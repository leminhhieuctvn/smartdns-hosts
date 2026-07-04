#!/usr/bin/env python3
import gzip
import ipaddress
import os
import re
import ssl
import sys
import time
import urllib.request
from urllib.parse import urlparse

SOURCES = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.mini-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/popupads-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dyndns-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling.mini-onlydomains.txt",
    "https://big.oisd.nl/domainswild",
    "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/wildcards.txt",
]

OUTPUT_FILE = "adblock_merged.txt"

ALLOWLIST = {
    "imoulife.com",
    "*.imoulife.com",
    "lechange.com",
    "*.lechange.com",
    "easy4ip.com",
    "*.easy4ip.com",
    "dahuasecurity.com",
    "*.dahuasecurity.com",
    "tailscale.com",
    "*.tailscale.com",
    "cloudflare-dns.com",
    "dns.google",
    "google.com",
    "*.google.com",
    "gstatic.com",
    "*.gstatic.com",
    "googleapis.com",
    "*.googleapis.com",
}

DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def normalize_domain(d: str):
    d = d.strip().lower()
    d = d.replace("\r", "")
    d = d.rstrip(".")

    if not d:
        return None

    if d.startswith("."):
        d = "*" + d

    d = d.replace(".*.", ".")
    d = d.replace("*.*.", "*.")

    if d.startswith("*."):
        base = d[2:]
        if is_ip(base):
            return None
        if not DOMAIN_RE.match(d):
            return None
        return d

    if "*" in d:
        return None

    if is_ip(d):
        return None

    if not DOMAIN_RE.match(d):
        return None

    return d

def extract_from_line(line: str):
    raw = line.strip().lower()
    if not raw or raw.startswith(("#", "!", "//", ";", "[", "/!")):
        return None

    raw = raw.split("#", 1)[0].strip()
    raw = raw.split(";", 1)[0].strip()
    if not raw:
        return None

    # hosts: 0.0.0.0 domain.com
    parts = raw.split()
    if len(parts) >= 2 and is_ip(parts[0]):
        return normalize_domain(parts[1])

    # AdGuard / ABP: ||domain.com^
    if raw.startswith("||"):
        d = raw[2:]
        d = re.split(r"[\^/$]", d, 1)[0]
        return normalize_domain(d)

    # dnsmasq: address=/domain.com/0.0.0.0
    m = re.match(r"^(?:address|server)=/([^/]+)/", raw)
    if m:
        return normalize_domain(m.group(1))

    # smartdns: address /domain.com/#
    m = re.match(r"^address\s+/([^/]+)/", raw)
    if m:
        return normalize_domain(m.group(1))

    # domain-set line, wildcard line, plain domain
    token = re.split(r"[\s,\t]", raw, 1)[0]
    token = token.split("^", 1)[0]
    token = token.split("$", 1)[0]
    token = token.strip()

    return normalize_domain(token)

def is_allowlisted(domain: str) -> bool:
    if domain in ALLOWLIST:
        return True

    base = domain[2:] if domain.startswith("*.") else domain

    for allow in ALLOWLIST:
        allow_base = allow[2:] if allow.startswith("*.") else allow
        if base == allow_base or base.endswith("." + allow_base):
            return True

    return False

def wildcard_covers_exact(wildcard: str, exact: str) -> bool:
    if not wildcard.startswith("*."):
        return False
    base = wildcard[2:]
    return exact.endswith("." + base)

def wildcard_covers_wildcard(parent: str, child: str) -> bool:
    if not parent.startswith("*.") or not child.startswith("*."):
        return False
    p = parent[2:]
    c = child[2:]
    return c.endswith("." + p)

def optimize_domains(domains):
    domains = {d for d in domains if d and not is_allowlisted(d)}

    wildcards = sorted({d for d in domains if d.startswith("*.")})
    exacts = sorted({d for d in domains if not d.startswith("*.")})

    # Loại wildcard con nếu bị wildcard cha bao phủ.
    kept_wildcards = []
    for w in sorted(wildcards, key=lambda x: (x.count("."), x)):
        if any(wildcard_covers_wildcard(parent, w) for parent in kept_wildcards):
            continue
        kept_wildcards.append(w)

    # Loại exact nếu bị wildcard bao phủ.
    kept_exacts = []
    for d in exacts:
        if any(wildcard_covers_exact(w, d) for w in kept_wildcards):
            continue
        kept_exacts.append(d)

    return sorted(kept_wildcards, key=lambda x: (x.count("."), x)), sorted(kept_exacts)

def download(url):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "smartdns-blocklist-generator/2.0",
            "Accept-Encoding": "gzip",
        },
    )

    for i in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
                data = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                return data.decode("utf-8", errors="ignore")
        except Exception as e:
            print(f"  retry {i + 1}/3 failed: {e}", file=sys.stderr)
            time.sleep(2)

    return ""

def main():
    all_domains = set()
    per_source = []

    print("SmartDNS blocklist merge")
    print("=" * 60)

    for url in SOURCES:
        name = os.path.basename(urlparse(url).path) or url
        print(f"Downloading: {name}")

        content = download(url)
        if not content:
            print("  failed or empty")
            continue

        before = len(all_domains)
        parsed = set()

        for line in content.splitlines():
            d = extract_from_line(line)
            if d:
                parsed.add(d)

        all_domains.update(parsed)
        added = len(all_domains) - before

        wc = sum(1 for d in parsed if d.startswith("*."))
        ex = len(parsed) - wc

        per_source.append((name, len(parsed), wc, ex, added))
        print(f"  parsed={len(parsed):,}, wildcard={wc:,}, exact={ex:,}, new={added:,}")

    raw_total = len(all_domains)
    wildcards, exacts = optimize_domains(all_domains)
    final_total = len(wildcards) + len(exacts)

    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write("# SmartDNS optimized blocklist\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
        f.write("# Format: domain-set file, one domain per line\n")
        f.write("# Rule: keep upstream suffix/wildcard, do not synthesize new suffix\n")
        f.write(f"# Raw unique: {raw_total:,}\n")
        f.write(f"# Final: {final_total:,}\n")
        f.write(f"# Wildcards: {len(wildcards):,}\n")
        f.write(f"# Exact: {len(exacts):,}\n")
        f.write("#" + "=" * 60 + "\n\n")

        for d in wildcards:
            f.write(d + "\n")
        for d in exacts:
            f.write(d + "\n")

    print()
    print("Summary")
    print("=" * 60)
    for name, total, wc, ex, added in per_source:
        print(f"{name[:40]:40s} total={total:8,} wc={wc:8,} exact={ex:8,} new={added:8,}")

    print("-" * 60)
    print(f"Raw unique : {raw_total:,}")
    print(f"Final      : {final_total:,}")
    print(f"Removed    : {raw_total - final_total:,}")
    print(f"Wildcards  : {len(wildcards):,}")
    print(f"Exact      : {len(exacts):,}")
    print(f"Output     : {OUTPUT_FILE} ({os.path.getsize(OUTPUT_FILE) / 1024:.1f} KiB)")

if __name__ == "__main__":
    main()