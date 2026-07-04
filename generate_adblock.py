#!/usr/bin/env python3
import gzip
import ipaddress
import os
import re
import ssl
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

SOURCES = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/popupads-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dyndns-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt",
    "https://big.oisd.nl/domainswild",
    "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/wildcards.txt",
]

OUTPUT_FILE = "adblock_merged.txt"
MAX_WORKERS = 8
TIMEOUT = 25
RETRIES = 2

ALLOWLIST = {
    "imoulife.com", "*.imoulife.com",
    "lechange.com", "*.lechange.com",
    "easy4ip.com", "*.easy4ip.com",
    "dahuasecurity.com", "*.dahuasecurity.com",
    "tailscale.com", "*.tailscale.com",
    "cloudflare-dns.com",
    "dns.google",
}

DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

def log(msg):
    print(msg, flush=True)

def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def normalize_domain(d):
    d = d.strip().lower().rstrip(".")
    if not d:
        return None

    if d.startswith("."):
        d = "*" + d

    if d.startswith("*."):
        base = d[2:]
        if is_ip(base) or not DOMAIN_RE.match(d):
            return None
        return d

    if "*" in d or is_ip(d):
        return None

    if not DOMAIN_RE.match(d):
        return None

    return d

def extract_from_line(line):
    raw = line.strip().lower()
    if not raw or raw.startswith(("#", "!", "//", ";", "[")):
        return None

    raw = raw.split("#", 1)[0].split(";", 1)[0].strip()
    if not raw:
        return None

    parts = raw.split()

    # hosts format: 0.0.0.0 domain.com / 127.0.0.1 domain.com
    if len(parts) >= 2 and is_ip(parts[0]):
        return normalize_domain(parts[1])

    # AdGuard/ABP: ||domain.com^
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

    token = re.split(r"[\s,\t]", raw, 1)[0]
    token = token.split("^", 1)[0].split("$", 1)[0].strip()
    return normalize_domain(token)

def is_allowlisted(domain):
    base = domain[2:] if domain.startswith("*.") else domain

    for allow in ALLOWLIST:
        allow_base = allow[2:] if allow.startswith("*.") else allow
        if base == allow_base or base.endswith("." + allow_base):
            return True

    return False

def download_one(url):
    name = os.path.basename(urlparse(url).path) or urlparse(url).netloc
    ctx = ssl.create_default_context()

    last_error = None
    for attempt in range(1, RETRIES + 1):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "smartdns-blocklist-generator/3.0",
                    "Accept-Encoding": "gzip",
                    "Connection": "close",
                },
            )
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
                data = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                text = data.decode("utf-8", errors="ignore")
                return name, url, text, None
        except Exception as e:
            last_error = e
            time.sleep(1)

    return name, url, "", str(last_error)

def parse_content(text):
    domains = set()
    for line in text.splitlines():
        d = extract_from_line(line)
        if d and not is_allowlisted(d):
            domains.add(d)
    return domains

def wildcard_covers_exact(wildcard, exact):
    return wildcard.startswith("*.") and exact.endswith("." + wildcard[2:])

def wildcard_covers_wildcard(parent, child):
    return (
        parent.startswith("*.")
        and child.startswith("*.")
        and child[2:].endswith("." + parent[2:])
    )

def optimize(domains):
    wildcards = sorted(d for d in domains if d.startswith("*."))
    exacts = sorted(d for d in domains if not d.startswith("*."))

    kept_wildcards = []
    for w in sorted(wildcards, key=lambda x: (x.count("."), x)):
        if any(wildcard_covers_wildcard(parent, w) for parent in kept_wildcards):
            continue
        kept_wildcards.append(w)

    kept_exacts = []
    for d in exacts:
        if any(wildcard_covers_exact(w, d) for w in kept_wildcards):
            continue
        kept_exacts.append(d)

    return kept_wildcards, kept_exacts

def main():
    start = time.time()
    all_domains = set()

    log("=== SmartDNS blocklist generator ===")
    log(f"Sources: {len(SOURCES)}")
    log(f"Workers: {MAX_WORKERS}, timeout: {TIMEOUT}s, retries: {RETRIES}")
    log("")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(download_one, url) for url in SOURCES]

        for future in as_completed(futures):
            name, url, text, error = future.result()

            if error:
                log(f"FAIL {name}: {error}")
                continue

            domains = parse_content(text)
            before = len(all_domains)
            all_domains.update(domains)
            added = len(all_domains) - before

            wc = sum(1 for d in domains if d.startswith("*."))
            ex = len(domains) - wc
            log(f"OK   {name}: parsed={len(domains):,}, wildcard={wc:,}, exact={ex:,}, new={added:,}")

    raw_count = len(all_domains)
    wildcards, exacts = optimize(all_domains)
    final_count = len(wildcards) + len(exacts)

    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write("# SmartDNS optimized blocklist\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
        f.write("# Format: domain-set file, one domain per line\n")
        f.write("# Rule: keep upstream wildcard/suffix only, do not synthesize new suffix\n")
        f.write(f"# Raw unique: {raw_count:,}\n")
        f.write(f"# Final: {final_count:,}\n")
        f.write(f"# Wildcards: {len(wildcards):,}\n")
        f.write(f"# Exact: {len(exacts):,}\n")
        f.write("#" + "=" * 60 + "\n\n")

        for d in wildcards:
            f.write(d + "\n")
        for d in exacts:
            f.write(d + "\n")

    log("")
    log("=== Final Statistics ===")
    log(f"Raw unique : {raw_count:,}")
    log(f"Final      : {final_count:,}")
    log(f"Removed    : {raw_count - final_count:,}")
    log(f"Wildcards  : {len(wildcards):,}")
    log(f"Exact      : {len(exacts):,}")
    log(f"File       : {OUTPUT_FILE}")
    log(f"Size       : {os.path.getsize(OUTPUT_FILE) / 1024:.1f} KiB")
    log(f"Duration   : {time.time() - start:.1f}s")

if __name__ == "__main__":
    main()