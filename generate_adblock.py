#!/usr/bin/env python3
"""Generate a compact SmartDNS domain-set blocklist safely.

The script downloads several blocklists, normalizes common formats, applies an
allowlist, removes only wildcard redundancies that are safe under SmartDNS
wildcard semantics, and atomically writes the result plus a metadata file.

Python 3.8+; standard library only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import gzip
import hashlib
import ipaddress
import os
import re
import ssl
import sys
import tempfile
import time
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse


DEFAULT_SOURCES = (
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/popupads-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt",
    )

DEFAULT_ALLOWLIST = (
    "imoulife.com",
    "lechange.com",
    "easy4ip.com",
    "dahuasecurity.com",
    "tailscale.com",
    "cloudflare-dns.com",
    "dns.google",
    "ellekit.space",
    "amazonaws.com",
)

LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
SMARTDNS_RULE_RE = re.compile(
    r"^(?:\*\.)?(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def log(message: str) -> None:
    print(message, flush=True)


def is_valid_domain(domain: str) -> bool:
    if not 4 <= len(domain) <= 253 or "." not in domain:
        return False
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass
    labels = domain.split(".")
    return (
        2 <= len(labels[-1]) <= 63
        and labels[-1].isalpha()
        and all(LABEL_RE.fullmatch(label) for label in labels)
    )


def normalize_domain(value: str) -> Optional[str]:
    value = value.strip().lower().rstrip(".")
    if value.startswith("."):
        value = "*" + value
    while value.startswith("*.*."):
        value = value[2:]
    wildcard = value.startswith("*.")
    base = value[2:] if wildcard else value
    if "*" in base or ":" in base or not is_valid_domain(base):
        return None
    return "*." + base if wildcard else base


def extract_domain(line: str) -> Optional[str]:
    raw = line.strip().lower()
    if not raw or raw[0] in "#!/;[":
        return None

    # Remove inline comments without breaking adblock's ||domain^ form.
    raw = re.split(r"\s[#!;]", raw, maxsplit=1)[0].strip()
    if raw.startswith("||"):
        return normalize_domain(re.split(r"[\^$/]", raw[2:], maxsplit=1)[0])

    match = re.match(r"^(?:address|server)=/([^/]+)/", raw)
    if match:
        return normalize_domain(match.group(1))
    match = re.match(r"^address\s+/([^/]+)/", raw)
    if match:
        return normalize_domain(match.group(1))

    parts = raw.split()
    if len(parts) >= 2:
        try:
            ipaddress.ip_address(parts[0])
            return normalize_domain(parts[1])
        except ValueError:
            pass

    token = parts[0].rstrip("^$") if parts else ""
    return normalize_domain(token)


def parse_text(text: str) -> Set[str]:
    return {domain for line in text.splitlines() if (domain := extract_domain(line))}


def allowlisted(rule: str, allowed_suffixes: Sequence[str]) -> bool:
    base = rule[2:] if rule.startswith("*.") else rule
    return any(base == suffix or base.endswith("." + suffix) for suffix in allowed_suffixes)


class WildcardTrie:
    __slots__ = ("children", "terminal")

    def __init__(self) -> None:
        self.children = {}
        self.terminal = False

    def covered(self, base: str, include_self: bool) -> bool:
        node = self
        for label in reversed(base.split(".")):
            if node.terminal:
                return True
            node = node.children.get(label)
            if node is None:
                return False
        return include_self and node.terminal

    def add(self, base: str) -> None:
        node = self
        for label in reversed(base.split(".")):
            node = node.children.setdefault(label, WildcardTrie())
        node.terminal = True


@dataclass(frozen=True)
class CompactStats:
    input_unique: int
    output_rules: int
    wildcard_input: int
    wildcard_output: int
    exact_input: int
    exact_output: int
    redundant_wildcards_removed: int
    exacts_covered_by_wildcard_removed: int


def compact_domains(domains: Iterable[str]) -> Tuple[list[str], CompactStats]:
    unique = set(domains)
    wildcard_bases = {item[2:] for item in unique if item.startswith("*.")}
    exacts = {item for item in unique if not item.startswith("*.")}

    trie = WildcardTrie()
    kept_wildcards = []
    for base in sorted(wildcard_bases, key=lambda item: (item.count("."), item)):
        if not trie.covered(base, include_self=True):
            trie.add(base)
            kept_wildcards.append(base)

    # A wildcard does not cover its own apex, so example.com is retained when
    # only *.example.com exists. Descendants such as a.example.com are removed.
    kept_exacts = sorted(
        domain for domain in exacts if not trie.covered(domain, include_self=False)
    )
    rules = sorted(["*." + base for base in kept_wildcards] + kept_exacts)
    invalid = [rule for rule in rules if not SMARTDNS_RULE_RE.fullmatch(rule)]
    if invalid:
        raise ValueError(f"Internal validation failed for {len(invalid)} rules")

    stats = CompactStats(
        input_unique=len(unique),
        output_rules=len(rules),
        wildcard_input=len(wildcard_bases),
        wildcard_output=len(kept_wildcards),
        exact_input=len(exacts),
        exact_output=len(kept_exacts),
        redundant_wildcards_removed=len(wildcard_bases) - len(kept_wildcards),
        exacts_covered_by_wildcard_removed=len(exacts) - len(kept_exacts),
    )
    return rules, stats


def download(url: str, timeout: int, retries: int, insecure: bool) -> Tuple[str, str]:
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    error = None
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "smartdns-blocklist-generator/5.0",
                    "Accept-Encoding": "gzip",
                },
            )
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                data = response.read()
                if response.headers.get("Content-Encoding", "").lower() == "gzip" or data[:2] == b"\x1f\x8b":
                    data = gzip.decompress(data)
                text = data.decode("utf-8", errors="replace")
                if "<html" in text[:1024].lower():
                    raise ValueError("server returned HTML instead of a blocklist")
                return url, text
        except Exception as exc:  # network errors vary by Python/OpenSSL version
            error = exc
            if attempt < retries:
                time.sleep(min(2 ** attempt, 8))
    raise RuntimeError(f"{url}: {error}")


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_lines(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-o", "--output", default="adblock_merged.txt")
    parser.add_argument("--meta", help="default: OUTPUT.meta")
    parser.add_argument("--source", action="append", dest="sources", help="repeatable; replaces defaults")
    parser.add_argument("--sources-file", type=Path, help="one URL per line; replaces defaults")
    parser.add_argument("--allow", action="append", default=[], help="allow domain and all its subdomains")
    parser.add_argument("--allowlist-file", type=Path, help="one allowed domain per line")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--allow-partial", action="store_true", help="write output even if a source fails")
    parser.add_argument("--min-rules", type=int, default=1000, help="refuse suspiciously small output")
    parser.add_argument("--insecure", action="store_true", help="disable TLS verification (not recommended)")
    parser.add_argument("--check-only", action="store_true", help="validate and report; do not write")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.workers < 1 or args.timeout < 1 or args.retries < 0 or args.min_rules < 1:
        raise SystemExit("workers, timeout and min-rules must be positive; retries cannot be negative")

    if args.sources_file:
        sources = load_lines(args.sources_file)
    elif args.sources:
        sources = args.sources
    else:
        sources = list(DEFAULT_SOURCES)
    if not sources:
        raise SystemExit("no sources configured")

    allowed = list(DEFAULT_ALLOWLIST) + args.allow
    if args.allowlist_file:
        allowed.extend(load_lines(args.allowlist_file))
    normalized_allowlist = sorted(
        {
            value[2:] if value.startswith("*.") else value
            for item in allowed
            if (value := normalize_domain(item))
        }
    )

    started = time.time()
    all_domains: Set[str] = set()
    source_results = []
    failures = []
    log(f"Downloading {len(sources)} sources with {args.workers} workers...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(download, url, args.timeout, args.retries, args.insecure): url for url in sources}
        for future in concurrent.futures.as_completed(futures):
            url = futures[future]
            name = os.path.basename(urlparse(url).path) or urlparse(url).netloc
            try:
                _, text = future.result()
                parsed = parse_text(text)
                filtered = {rule for rule in parsed if not allowlisted(rule, normalized_allowlist)}
                before = len(all_domains)
                all_domains.update(filtered)
                source_results.append({"url": url, "parsed": len(parsed), "accepted": len(filtered)})
                log(f"OK   {name}: parsed={len(parsed):,}, new={len(all_domains)-before:,}")
            except Exception as exc:
                failures.append({"url": url, "error": str(exc)})
                log(f"FAIL {name}: {exc}")

    if failures and not args.allow_partial:
        log("Refusing to publish a weakened partial blocklist. Re-run with --allow-partial to override.")
        return 2
    if not all_domains:
        log("No valid domains were collected; output was not changed.")
        return 3

    rules, stats = compact_domains(all_domains)
    if len(rules) < args.min_rules:
        log(f"Output has only {len(rules):,} rules (< --min-rules {args.min_rules:,}); output was not changed.")
        return 4

    output_text = "\n".join(rules) + "\n"
    digest = hashlib.sha256(output_text.encode("utf-8")).hexdigest()
    duration = round(time.time() - started, 3)
    metadata = {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_seconds": duration,
        "sha256": digest,
        "output_bytes": len(output_text.encode("utf-8")),
        "allowlist": normalized_allowlist,
        "stats": asdict(stats),
        "sources": sorted(source_results, key=lambda item: item["url"]),
        "failures": failures,
    }

    removed = stats.input_unique - stats.output_rules
    reduction = removed * 100.0 / stats.input_unique
    log(f"Input unique : {stats.input_unique:,}")
    log(f"Output rules : {stats.output_rules:,}")
    log(f"Removed      : {removed:,} ({reduction:.2f}%)")
    log(f"SHA-256      : {digest}")

    if not args.check_only:
        output_path = Path(args.output).resolve()
        meta_path = Path(args.meta).resolve() if args.meta else Path(str(output_path) + ".meta")
        atomic_write(output_path, output_text)
        # Keep the same simple sidecar style as the original generator so a
        # GitHub Actions workflow can publish both files directly.
        meta_lines = [
            "# SmartDNS Blocklist metadata",
            f"# Generated: {metadata['generated_utc']}",
            f"# Raw unique: {stats.input_unique:,}",
            f"# Final rules: {stats.output_rules:,}",
            f"# Wildcard: {stats.wildcard_output:,}",
            f"# Exact: {stats.exact_output:,}",
            f"# Removed: {removed:,} ({reduction:.2f}%)",
            f"# SHA256: {digest}",
            f"# Duration: {duration:.3f}s",
            f"# Sources OK: {len(source_results)}/{len(sources)}",
            f"# Sources failed: {len(failures)}",
        ]
        atomic_write(meta_path, "\n".join(meta_lines) + "\n")
        log(f"Output       : {output_path}")
        log(f"Metadata     : {meta_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        log("Interrupted; output was not changed.")
        raise SystemExit(130)
