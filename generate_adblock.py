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
MAX_WORKERS = 8
TIMEOUT = 30
RETRIES = 3

ALLOWLIST = {
    "imoulife.com", "lechange.com", "easy4ip.com", 
    "dahuasecurity.com", "tailscale.com",
    "cloudflare-dns.com", "dns.google",
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
        if not DOMAIN_RE.match(d):
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
    """Trie structure để tối ưu domains"""
    def __init__(self):
        self.children = {}
        self.is_wildcard = False
        self.has_wildcard_child = False
    
    def insert_reversed(self, domain_parts):
        """Chèn domain với các phần đảo ngược (com -> example -> sub)"""
        node = self
        for part in reversed(domain_parts):
            if part not in node.children:
                node.children[part] = DomainTrie()
            node = node.children[part]
    
    def mark_wildcard(self, domain_parts):
        """Đánh dấu wildcard tại vị trí cụ thể"""
        node = self
        for part in reversed(domain_parts):
            if part not in node.children:
                node.children[part] = DomainTrie()
            node = node.children[part]
        node.is_wildcard = True
    
    def propagate_wildcards(self):
        """Lan truyền trạng thái wildcard lên cây"""
        if self.is_wildcard:
            self.has_wildcard_child = True
        
        for child in self.children.values():
            child.propagate_wildcards()
            if child.has_wildcard_child:
                self.has_wildcard_child = True
    
    def get_minimal_suffixes(self, current_path=None):
        """Lấy các suffix rules tối thiểu"""
        if current_path is None:
            current_path = []
        
        suffixes = []
        
        # Nếu node này là wildcard và không có wildcard cha
        if self.is_wildcard:
            # Kiểm tra ancestors
            if not self._has_wildcard_ancestor(current_path):
                suffixes.append(".".join(reversed(current_path)))
        
        # Duyệt các children có chứa wildcard
        for part, child in self.children.items():
            if child.has_wildcard_child:
                suffixes.extend(child.get_minimal_suffixes(current_path + [part]))
        
        return suffixes
    
    def _has_wildcard_ancestor(self, path):
        """Kiểm tra xem có wildcard ancestor không"""
        node = self
        for part in reversed(path):
            if part in node.children:
                node = node.children[part]
                if node.is_wildcard and node != self:
                    return True
        return False
    
    def is_covered_by_suffix(self, domain_parts):
        """Kiểm tra domain có bị suffix nào bao phủ không"""
        node = self
        for part in reversed(domain_parts):
            if node.is_wildcard:
                return True
            if part not in node.children:
                return False
            node = node.children[part]
        return node.is_wildcard

def optimize_domains(domains):
    """Tối ưu domains cho SmartDNS"""
    log("  Phân loại domains...")
    
    wildcards = []
    exacts = []
    
    for d in domains:
        if d.startswith("*."):
            wildcards.append(d[2:])  # Bỏ prefix *.
        else:
            exacts.append(d)
    
    log(f"  Wildcards: {len(wildcards):,}, Exacts: {len(exacts):,}")
    
    # Xây dựng Trie cho wildcards
    log("  Tối ưu suffix rules...")
    trie = DomainTrie()
    
    for w in wildcards:
        parts = w.split(".")
        trie.mark_wildcard(parts)
    
    trie.propagate_wildcards()
    minimal_suffixes = trie.get_minimal_suffixes()
    
    log(f"  Suffix rules: {len(minimal_suffixes):,} (removed {len(wildcards) - len(minimal_suffixes):,} redundant)")
    
    # Tối ưu exact domains
    log("  Tối ưu exact domains...")
    kept_exacts = []
    removed = 0
    
    for i, d in enumerate(exacts):
        if i % 100000 == 0:
            log(f"    Processing {i:,}/{len(exacts):,}...")
        
        parts = d.split(".")
        if not trie.is_covered_by_suffix(parts):
            kept_exacts.append(d)
        else:
            removed += 1
    
    log(f"  Exact domains: {len(kept_exacts):,} (removed {removed:,})")
    
    return sorted(minimal_suffixes), sorted(kept_exacts)

def write_smartdns_output(suffixes, exacts, raw_count, duration):
    """Ghi file blocklist format cho SmartDNS"""
    final_count = len(suffixes) + len(exacts)
    
    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="\n") as f:
        f.write("# SmartDNS Blocklist\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
        f.write(f"# Raw unique: {raw_count:,}\n")
        f.write(f"# Final rules: {final_count:,}\n")
        f.write(f"# Suffix: {len(suffixes):,}\n")
        f.write(f"# Exact: {len(exacts):,}\n")
        f.write(f"# Duration: {duration:.1f}s\n")
        f.write("#" + "=" * 60 + "\n\n")
        
        if suffixes:
            f.write("# Suffix rules (match domain and all subdomains)\n")
            for suffix in suffixes:
                f.write(f"suffix:{suffix}\n")
            f.write("\n")
        
        if exacts:
            f.write("# Exact domain rules\n")
            for domain in exacts:
                f.write(f"domain:{domain}\n")

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
    suffixes, exacts = optimize_domains(all_domains)

    duration = time.time() - start
    
    # Ghi output
    write_smartdns_output(suffixes, exacts, raw_count, duration)

    final_count = len(suffixes) + len(exacts)

    log("")
    log("=== Results ===")
    log(f"Raw unique : {raw_count:,}")
    log(f"Final rules: {final_count:,}")
    log(f"  Suffix   : {len(suffixes):,}")
    log(f"  Exact    : {len(exacts):,}")
    log(f"Saved      : {raw_count - final_count:,}")
    log(f"Duration   : {duration:.1f}s")
    log(f"Output     : {OUTPUT_FILE}")
    log(f"Size       : {os.path.getsize(OUTPUT_FILE) / 1024:.1f} KiB")
    
    log("\nUsage in SmartDNS:")
    log(f"  conf-file {os.path.abspath(OUTPUT_FILE)}")

if __name__ == "__main__":
    main()