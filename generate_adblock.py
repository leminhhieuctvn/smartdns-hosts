#!/usr/bin/env python3
"""
SmartDNS Blocklist Generator
Tạo blocklist tối ưu cho SmartDNS với domain-set format
"""

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
from functools import lru_cache

# Configuration
SOURCES = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/popupads-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dyndns-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt",
    "https://big.oisd.nl/domainswild",
    "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/wildcards.txt",
]

OUTPUT_FILE = "adblock_merged.txt"
META_FILE = OUTPUT_FILE + ".meta"
DOMAIN_SET_NAME = "adblock"
MAX_WORKERS = 8
TIMEOUT = 30
RETRIES = 3

ALLOWLIST = {
    "imoulife.com", "lechange.com", "easy4ip.com", 
    "dahuasecurity.com", "tailscale.com",
    "cloudflare-dns.com", "dns.google","ellekit.space",
}

DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
SMARTDNS_DOMAIN_RE = re.compile(
    r"^(?:\*\.|-\.)?(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
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
    d = d.strip().lower()
    if not d:
        return None
    
    if d.endswith('.'):
        d = d[:-1]
    d = d.replace('\r', '').replace('\n', '')
    
    if not d:
        return None

    if d.startswith("."):
        d = "*" + d

    if "*.*." in d:
        d = d.replace("*.*.", "*.", 1)

    if d.startswith("*."):
        base = d[2:]
        if ':' in base or (base.replace('.', '').isdigit() and base.count('.') == 3):
            return None
        if not DOMAIN_RE.match(base):
            return None
        return d

    if '*' in d:
        return None
    
    if ':' in d or (d.replace('.', '').isdigit() and d.count('.') == 3):
        return None

    if not DOMAIN_RE.match(d):
        return None

    return d

def extract_from_line(line):
    raw = line.strip().lower()
    if not raw or raw[0] in ('#', '!', '/', ';', '['):
        return None

    comment_pos = raw.find('#')
    if comment_pos == -1:
        comment_pos = len(raw)
    comment_pos2 = raw.find(';')
    if comment_pos2 != -1 and comment_pos2 < comment_pos:
        comment_pos = comment_pos2
    
    if comment_pos != len(raw):
        raw = raw[:comment_pos].strip()
        if not raw:
            return None

    if raw.startswith("||"):
        d = raw[2:]
        end = d.find('^')
        if end == -1:
            end = len(d)
        end2 = d.find('$')
        if end2 != -1 and end2 < end:
            end = end2
        end3 = d.find('/')
        if end3 != -1 and end3 < end:
            end = end3
        return normalize_domain(d[:end])

    parts = raw.split(None, 2)
    if len(parts) >= 2:
        first = parts[0]
        if first.count('.') == 3 and all(p.isdigit() for p in first.split('.')):
            return normalize_domain(parts[1])
        if first == '127.0.0.1':
            return normalize_domain(parts[1])

    if raw.startswith('address=/') or raw.startswith('server=/'):
        m = re.match(r"^(?:address|server)=/([^/]+)/", raw)
        if m:
            return normalize_domain(m.group(1))

    if raw.startswith('address /'):
        m = re.match(r"^address\s+/([^/]+)/", raw)
        if m:
            return normalize_domain(m.group(1))

    space_pos = raw.find(' ')
    if space_pos != -1:
        raw = raw[:space_pos]
    
    tab_pos = raw.find('\t')
    if tab_pos != -1:
        raw = raw[:tab_pos]
    
    raw = raw.rstrip('^$')
    
    return normalize_domain(raw)

def download_one(url):
    name = os.path.basename(urlparse(url).path) or urlparse(url).netloc
    
    for attempt in range(RETRIES + 1):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; smartdns-blocklist/4.0)",
                    "Accept-Encoding": "gzip",
                    "Connection": "close",
                },
            )
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                data = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                text = data.decode("utf-8", errors="ignore")
                return name, url, text, None

        except Exception as e:
            if attempt == RETRIES:
                return name, url, "", str(e)
            time.sleep(2)

    return name, url, "", "Max retries exceeded"

@lru_cache(maxsize=10000)
def is_allowlisted_cached(domain):
    base = domain[2:] if domain.startswith("*.") else domain
    
    if domain in ALLOWLIST or base in ALLOWLIST:
        return True
    
    for allow in ALLOWLIST:
        if allow.startswith("*."):
            allow_base = allow[2:]
            if base == allow_base or base.endswith("." + allow_base):
                return True
    
    return False

def parse_content(text):
    domains = set()
    
    for line in text.splitlines():
        d = extract_from_line(line)
        if d and not is_allowlisted_cached(d):
            domains.add(d)
    
    return domains

class DomainTrie:
    """Trie đảo ngược để kiểm tra wildcard cha/con nhanh."""
    def __init__(self):
        self.children = {}
        self.is_wildcard = False

    def mark_wildcard(self, domain_parts):
        """Đánh dấu wildcard cho một suffix, ví dụ example.com."""
        node = self
        for part in reversed(domain_parts):
            node = node.children.setdefault(part, DomainTrie())
        node.is_wildcard = True

    def has_covering_wildcard(self, domain_parts, include_self=True):
        """Kiểm tra domain có wildcard cha bao phủ không.

        SmartDNS 46.1+ hiểu `*.example.com` là chỉ match subdomain,
        không match chính `example.com`. Vì vậy exact `example.com` không
        bị xóa bởi wildcard `*.example.com` khi include_self=False.
        """
        node = self
        for part in reversed(domain_parts):
            if node.is_wildcard:
                return True
            if part not in node.children:
                return False
            node = node.children[part]
        return include_self and node.is_wildcard

def optimize_domains(domains):
    """Tối ưu domains cho SmartDNS domain-set list format."""
    log("  Phân loại domains...")

    wildcard_bases = []
    exacts = []

    for d in domains:
        if d.startswith("*."):
            wildcard_bases.append(d[2:])
        else:
            exacts.append(d)

    log(f"  Wildcards: {len(wildcard_bases):,}, Exacts: {len(exacts):,}")

    # Tối ưu wildcard: nếu đã có *.example.com thì bỏ *.a.example.com.
    log("  Tối ưu wildcard rules...")
    trie = DomainTrie()
    minimal_wildcards = []

    for base in sorted(set(wildcard_bases), key=lambda x: (x.count('.'), x)):
        parts = base.split(".")
        if trie.has_covering_wildcard(parts, include_self=True):
            continue
        trie.mark_wildcard(parts)
        minimal_wildcards.append(base)

    log(
        f"  Wildcard rules: {len(minimal_wildcards):,} "
        f"(removed {len(set(wildcard_bases)) - len(minimal_wildcards):,} redundant)"
    )

    # Tối ưu exact: chỉ bỏ exact subdomain nếu có wildcard cha.
    # Không bỏ chính example.com khi có *.example.com vì SmartDNS chỉ match subdomain.
    log("  Tối ưu exact domains...")
    kept_exacts = []
    removed = 0

    for i, d in enumerate(sorted(set(exacts))):
        if i % 100000 == 0:
            log(f"    Processing {i:,}/{len(set(exacts)):,}...")

        parts = d.split(".")
        if trie.has_covering_wildcard(parts, include_self=False):
            removed += 1
        else:
            kept_exacts.append(d)

    log(f"  Exact domains: {len(kept_exacts):,} (removed {removed:,})")

    # SmartDNS domain-set file: mỗi dòng là pattern domain hợp lệ.
    # `*.example.com` = chỉ subdomain; `example.com` = chính domain.
    smartdns_rules = [f"*.{base}" for base in minimal_wildcards] + kept_exacts
    smartdns_rules = [r for r in smartdns_rules if SMARTDNS_DOMAIN_RE.match(r)]

    return sorted(smartdns_rules), len(minimal_wildcards), len(kept_exacts)

def write_smartdns_output(rules, wildcard_count, exact_count, raw_count, duration):
    """Ghi file domain-set đúng cú pháp SmartDNS 46.1+."""
    final_count = len(rules)

    # File domain-set nên là danh sách domain/pattern thuần, mỗi dòng một rule.
    # Tránh ghi `suffix:`/`domain:` vì đó không phải cú pháp domain-set của SmartDNS.
    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="\n") as f:
        for rule in rules:
            f.write(rule + "\n")

    # Metadata tách riêng để file chính luôn sạch và dễ nạp vào SmartDNS.
    with open(META_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write("# SmartDNS Blocklist metadata\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
        f.write(f"# Raw unique: {raw_count:,}\n")
        f.write(f"# Final rules: {final_count:,}\n")
        f.write(f"# Wildcard: {wildcard_count:,}\n")
        f.write(f"# Exact: {exact_count:,}\n")
        f.write(f"# Duration: {duration:.1f}s\n")

def main():
    start = time.time()
    all_domains = set()

    log("=== SmartDNS Blocklist Generator ===")
    log(f"Sources: {len(SOURCES)}")
    log(f"Workers: {MAX_WORKERS}, Timeout: {TIMEOUT}s, Retries: {RETRIES}")
    log("")
    
    # Download và parse
    completed = 0
    failed = 0
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(download_one, url): url for url in SOURCES}

        for future in as_completed(futures):
            name, url, text, error = future.result()
            completed += 1

            if error:
                failed += 1
                log(f"FAIL [{completed}/{len(SOURCES)}] {name}: {error}")
                continue

            domains = parse_content(text)
            before = len(all_domains)
            all_domains.update(domains)
            added = len(all_domains) - before

            wc = sum(1 for d in domains if d.startswith("*."))
            ex = len(domains) - wc

            log(
                f"OK   [{completed}/{len(SOURCES)}] {name}: "
                f"parsed={len(domains):,} (wc:{wc:,} ex:{ex:,}) new={added:,}"
            )

    raw_count = len(all_domains)
    
    log(f"\nDownload: {completed}/{len(SOURCES)} successful, {failed} failed")
    log(f"Total raw domains: {raw_count:,}")
    log("")
    
    # Tối ưu
    log("Optimizing...")
    rules, wildcard_count, exact_count = optimize_domains(all_domains)

    duration = time.time() - start
    
    # Ghi output
    write_smartdns_output(rules, wildcard_count, exact_count, raw_count, duration)

    final_count = len(rules)

    log("")
    log("=== Results ===")
    log(f"Raw unique : {raw_count:,}")
    log(f"Final rules: {final_count:,}")
    log(f"  Wildcard : {wildcard_count:,}")
    log(f"  Exact    : {exact_count:,}")
    log(f"Saved      : {raw_count - final_count:,}")
    log(f"Duration   : {duration:.1f}s")
    log(f"Output     : {OUTPUT_FILE}")
    log(f"Meta       : {META_FILE}")
    log(f"Size       : {os.path.getsize(OUTPUT_FILE) / 1024:.1f} KiB")
    
    abs_output = os.path.abspath(OUTPUT_FILE)
    log("\nUsage in SmartDNS 46.1+:")
    log(f"  domain-set -name {DOMAIN_SET_NAME} -type list -file {abs_output}")
    log(f"  domain-rules /domain-set:{DOMAIN_SET_NAME}/ -address #")
    log("  # hoặc: address /domain-set:{}/#".format(DOMAIN_SET_NAME))

if __name__ == "__main__":
    main()
