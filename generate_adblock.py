#!/usr/bin/env python3
"""Generate an ultra-compact blocklist for both SmartDNS (OpenWrt) and Cloudflare Worker.

- Outputs clean, bare base domains (no '*.' prefix) so it works natively with:
  1. SmartDNS `domain-set` (which automatically suffix-matches apex + subdomains).
  2. Cloudflare Worker BloomFilter + R2 Partition Trie (`getSuffixesInOrder`).
- Removes redundant subdomains covered by parent domains (~45-50% size reduction).
- Does NOT hardcode anti-revoke blocks (delegated to Cloudflare Worker).

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
import tempfile
import time
import urllib.request
from dataclasses import dataclass
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
    # Infrastructure, Smart Home & Custom services
    "imoulife.com",
    "lechange.com",
    "easy4ip.com",
    "dahuasecurity.com",
    "tailscale.com",
    "cloudflare-dns.com",
    "dns.google",
    "ellekit.space",
    "amazonaws.com",
    "rethinkdns.com",

    # iOS Wi-Fi Stability, Captive Portal & Core System Services
    # (Scoped to specific subdomains so anti-revoke domains are never whitelisted here)
    "captive.apple.com",
    "www.apple.com",
    "push.apple.com",
    "courier.push.apple.com",
    "time.apple.com",
    "time-ios.apple.com",
    "mesu.apple.com",
    "gdmf.apple.com",
    "appldnld.apple.com",
    "swscan.apple.com",
    "albert.apple.com",
    "gs.apple.com",
    "configuration.apple.com",
    "icloud.com",
    "apple-cloudkit.com",
    "mzstatic.com",
)

LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def log(message: str) -> None:
    print(message, flush=True)


def is_valid_domain(domain: str) -> bool:
    if not 4 <= len(domain) <= 253 or "." not in domain:
        return False
    labels = domain.split(".")
    tld = labels[-1]
    if not (2 <= len(tld) <= 63 and tld.isalpha()):
        return False
    return all(LABEL_RE.fullmatch(label) for label in labels)


def normalize_base_domain(value: str) -> Optional[str]:
    """Normalize any domain/wildcard rule down to its clean bare base domain."""
    value = value.strip().lower().rstrip(".")
    while value.startswith("*.") or value.startswith("."):
        value = value[2:] if value.startswith("*.") else value[1:]
    if not value or "*" in value or ":" in value or not is_valid_domain(value):
        return None
    return value


def extract_domain(line: str) -> Optional[str]:
    raw = line.strip().lower()
    if not raw or raw[0] in "#!/;[":
        return None

    if " #" in raw or "\t#" in raw or " !" in raw or " ;" in raw:
        raw = re.split(r"\s[#!;]", raw, maxsplit=1)[0].strip()

    if raw.startswith("||"):
        token = raw[2:].split("^", 1)[0].split("$", 1)[0].split("/", 1)[0]
        return normalize_base_domain(token)

    if raw.startswith(("address=", "server=", "address ")):
        match = re.match(r"^(?:address|server)=/([^/]+)/|^address\s+/([^/]+)/", raw)
        if match:
            return normalize_base_domain(match.group(1) or match.group(2))

    parts = raw.split()
    if len(parts) >= 2:
        try:
            ipaddress.ip_address(parts[0])
            return normalize_base_domain(parts[1])
        except ValueError:
            pass

    token = parts[0].rstrip("^$") if parts else ""
    return normalize_base_domain(token)


def has_parent_in_set(domain: str, domain_set: Set[str], include_self: bool = True) -> bool:
    """O(k) lookup checking if domain or any of its parent domains exist in domain_set."""
    if include_self and domain in domain_set:
        return True
    idx = domain.find(".")
    while idx != -1:
        if domain[idx + 1 :] in domain_set:
            return True
        idx = domain.find(".", idx + 1)
    return False


def parse_and_filter(text: str, allow_set: Set[str]) -> Set[str]:
    result: Set[str] = set()
    for line in text.splitlines():
        domain = extract_domain(line)
        if domain and not has_parent_in_set(domain, allow_set, include_self=True):
            result.add(domain)
    return result


@dataclass(frozen=True)
class CompactStats:
    raw_lines_parsed: int
    unique_before_compact: int
    output_rules: int
    subdomains_pruned: int


def compact_domains(domains: Iterable[str], raw_parsed_count: int) -> Tuple[list[str], CompactStats]:
    """Remove any subdomain whose parent domain is already present in the set."""
    unique = set(domains)
    kept: Set[str] = {
        d for d in unique if not has_parent_in_set(d, unique, include_self=False)
    }
    rules = sorted(kept)

    stats = CompactStats(
        raw_lines_parsed=raw_parsed_count,
        unique_before_compact=len(unique),
        output_rules=len(rules),
        subdomains_pruned=len(unique) - len(rules),
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
                    "User-Agent": "smartdns-blocklist-generator/6.1",
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
        except Exception as exc:
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
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


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

    raw_allowed = list(DEFAULT_ALLOWLIST) + args.allow
    if args.allowlist_file:
        raw_allowed.extend(load_lines(args.allowlist_file))
    allow_set: Set[str] = {
        norm for item in raw_allowed if (norm := normalize_base_domain(item))
    }

    started = time.time()
    all_domains: Set[str] = set()
    total_raw_parsed = 0
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
                filtered = parse_and_filter(text, allow_set)
                total_raw_parsed += len(filtered)
                before = len(all_domains)
                all_domains.update(filtered)
                source_results.append({"url": url, "accepted": len(filtered)})
                log(f"OK   {name}: accepted={len(filtered):,}, new_unique={len(all_domains)-before:,}")
            except Exception as exc:
                failures.append({"url": url, "error": str(exc)})
                log(f"FAIL {name}: {exc}")

    if failures and not args.allow_partial:
        log("Refusing to publish a weakened partial blocklist. Re-run with --allow-partial to override.")
        return 2
    if not all_domains:
        log("No valid domains were collected; output was not changed.")
        return 3

    rules, stats = compact_domains(all_domains, total_raw_parsed)
    if len(rules) < args.min_rules:
        log(f"Output has only {len(rules):,} rules (< --min-rules {args.min_rules:,}); output was not changed.")
        return 4

    output_text = "\n".join(rules) + "\n"
    output_bytes = len(output_text.encode("utf-8"))
    digest = hashlib.sha256(output_text.encode("utf-8")).hexdigest()
    duration = round(time.time() - started, 3)

    removed_total = stats.raw_lines_parsed - stats.output_rules
    reduction = (removed_total * 100.0 / stats.raw_lines_parsed) if stats.raw_lines_parsed else 0.0
    log(f"Raw accepted : {stats.raw_lines_parsed:,}")
    log(f"Unique base  : {stats.unique_before_compact:,}")
    log(f"Output rules : {stats.output_rules:,} ({output_bytes / 1024 / 1024:.2f} MB)")
    log(f"Pruned sub   : {stats.subdomains_pruned:,} (Total reduction: {reduction:.2f}%)")
    log(f"SHA-256      : {digest}")

    if not args.check_only:
        output_path = Path(args.output).resolve()
        meta_path = Path(args.meta).resolve() if args.meta else Path(str(output_path) + ".meta")
        atomic_write(output_path, output_text)
        meta_lines = [
            "# SmartDNS & Cloudflare Worker Blocklist Metadata",
            f"# Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
            f"# Raw accepted: {stats.raw_lines_parsed:,}",
            f"# Unique base: {stats.unique_before_compact:,}",
            f"# Final rules: {stats.output_rules:,}",
            f"# Subdomains pruned: {stats.subdomains_pruned:,}",
            f"# Size bytes: {output_bytes:,}",
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
