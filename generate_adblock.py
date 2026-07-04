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
from functools import lru_cache
from collections import defaultdict

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
MAX_WORKERS = 8  # Giảm xuống để tránh rate limiting
TIMEOUT = 30  # Tăng timeout
RETRIES = 3  # Tăng retries

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
    ctx = ssl.create_default_context()
    
    log(f"  Downloading {name}...")
    
    for attempt in range(RETRIES + 1):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; smartdns-blocklist-generator/3.1)",
                    "Accept-Encoding": "gzip",
                    "Connection": "close",
                },
            )
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
                data = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                text = data.decode("utf-8", errors="ignore")
                log(f"  ✓ {name}: {len(text):,} bytes")
                return name, url, text, None

        except Exception as e:
            log(f"  ✗ {name} attempt {attempt+1}: {str(e)[:100]}")
            if attempt < RETRIES:
                time.sleep(2)
            else:
                return name, url, "", str(e)

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
    """Trie để lưu trữ và tối ưu domains"""
    def __init__(self):
        self.children = {}
        self.is_wildcard = False
        self.has_wildcard_child = False
    
    def insert_reversed(self, domain_parts, is_wildcard=False):
        """Chèn domain với các phần đảo ngược (com -> example -> *)"""
        node = self
        for part in reversed(domain_parts):
            if part not in node.children:
                node.children[part] = DomainTrie()
            node = node.children[part]
        if is_wildcard:
            node.is_wildcard = True
    
    def mark_wildcard_path(self):
        """Đánh dấu các node có wildcard trong cây con"""
        if self.is_wildcard:
            self.has_wildcard_child = True
        
        for child in self.children.values():
            child.mark_wildcard_path()
            if child.has_wildcard_child:
                self.has_wildcard_child = True
    
    def collect_minimal_wildcards(self, current_path=None):
        """Thu thập các wildcard tối thiểu"""
        if current_path is None:
            current_path = []
        
        wildcards = []
        
        if self.is_wildcard:
            if not any(node.is_wildcard for node in self._get_path_nodes(current_path)):
                wildcards.append(".".join(reversed(current_path)))
        
        for part, child in self.children.items():
            if child.has_wildcard_child:
                wildcards.extend(child.collect_minimal_wildcards(current_path + [part]))
        
        return wildcards
    
    def _get_path_nodes(self, path):
        """Lấy tất cả nodes trên đường dẫn"""
        nodes = []
        node = self
        for part in reversed(path):
            if part in node.children:
                node = node.children[part]
                nodes.append(node)
        return nodes
    
    def is_covered_by_wildcard(self, domain_parts):
        """Kiểm tra domain có bị wildcard nào bao phủ không"""
        node = self
        for part in reversed(domain_parts):
            if node.is_wildcard:
                return True
            if part not in node.children:
                return False
            node = node.children[part]
        return node.is_wildcard

def optimize_trie(domains):
    """Tối ưu hóa sử dụng Trie - O(N)"""
    log("  Phân loại domains...")
    
    wildcards = []
    exacts = []
    
    for d in domains:
        if d.startswith("*."):
            wildcards.append(d[2:])  # Bỏ "*."
        else:
            exacts.append(d)
    
    log(f"  Wildcards: {len(wildcards):,}, Exacts: {len(exacts):,}")
    
    # Xây dựng Trie cho wildcards
    log("  Xây dựng Trie cho wildcards...")
    trie = DomainTrie()
    for w in wildcards:
        parts = w.split(".")
        trie.insert_reversed(parts, is_wildcard=True)
    
    # Đánh dấu các wildcard paths
    log("  Tối ưu wildcards...")
    trie.mark_wildcard_path()
    
    # Lấy wildcards tối thiểu
    minimal_wildcards = trie.collect_minimal_wildcards()
    log(f"  Giữ lại {len(minimal_wildcards):,} wildcards (loại bỏ {len(wildcards) - len(minimal_wildcards):,})")
    
    # Kiểm tra exact domains bị wildcards bao phủ
    log("  Kiểm tra exact domains...")
    kept_exacts = []
    removed_exacts = 0
    
    for i, d in enumerate(exacts):
        if i % 100000 == 0:
            log(f"    Processing exact domain {i:,}/{len(exacts):,}...")
        parts = d.split(".")
        if not trie.is_covered_by_wildcard(parts):
            kept_exacts.append(d)
        else:
            removed_exacts += 1
    
    log(f"  Giữ lại {len(kept_exacts):,} exact domains (loại bỏ {removed_exacts:,})")
    
    # Format lại wildcards
    formatted_wildcards = ["*." + w for w in minimal_wildcards]
    
    return sorted(formatted_wildcards), sorted(kept_exacts)

def write_output(wildcards, exacts, raw_count, duration):
    final_count = len(wildcards) + len(exacts)
    
    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="\n") as f:
        lines = [
            "# SmartDNS optimized blocklist",
            f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            "# Format: domain-set file, one domain per line",
            "# Rule: keep upstream wildcard/suffix only, do not synthesize new suffix",
            f"# Raw unique: {raw_count:,}",
            f"# Final: {final_count:,}",
            f"# Wildcards: {len(wildcards):,}",
            f"# Exact: {len(exacts):,}",
            f"# Duration: {duration:.1f}s",
            "#" + "=" * 60,
            "",
        ]
        f.write("\n".join(lines))
        
        if wildcards:
            f.write("\n".join(wildcards) + "\n")
        if exacts:
            f.write("\n".join(exacts) + "\n")

def main():
    start = time.time()
    all_domains = set()

    log("=== SmartDNS blocklist generator ===")
    log(f"Sources: {len(SOURCES)}")
    log(f"Workers: {MAX_WORKERS}, timeout: {TIMEOUT}s, retries: {RETRIES}")
    log("")

    # Download và parse song song
    log("Downloading sources...")
    log("=" * 60)
    
    completed = 0
    failed = 0
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(download_one, url): url for url in SOURCES}

        for future in as_completed(futures):
            name, url, text, error = future.result()
            completed += 1

            if error:
                failed += 1
                log(f"\nFAIL [{completed}/{len(SOURCES)}] {name}: {error}")
                continue

            domains = parse_content(text)
            before = len(all_domains)
            all_domains.update(domains)
            added = len(all_domains) - before

            wc = sum(1 for d in domains if d.startswith("*."))
            ex = len(domains) - wc

            log(
                f"OK   [{completed}/{len(SOURCES)}] {name}: "
                f"parsed={len(domains):,}, "
                f"wildcard={wc:,}, "
                f"exact={ex:,}, "
                f"new={added:,}"
            )

    log("=" * 60)
    log(f"Completed: {completed}/{len(SOURCES)}, Failed: {failed}/{len(SOURCES)}")
    
    if failed > 0:
        log("WARNING: Some sources failed to download!")
    
    raw_count = len(all_domains)

    log("")
    log("Optimizing...")
    log("=" * 60)
    wildcards, exacts = optimize_trie(all_domains)

    duration = time.time() - start
    write_output(wildcards, exacts, raw_count, duration)

    final_count = len(wildcards) + len(exacts)

    log("=" * 60)
    log("")
    log("=== Final Statistics ===")
    log(f"Raw unique : {raw_count:,}")
    log(f"Final      : {final_count:,}")
    log(f"Removed    : {raw_count - final_count:,}")
    log(f"Wildcards  : {len(wildcards):,}")
    log(f"Exact      : {len(exacts):,}")
    log(f"File       : {OUTPUT_FILE}")
    log(f"Size       : {os.path.getsize(OUTPUT_FILE) / 1024:.1f} KiB")
    log(f"Duration   : {duration:.1f}s")

if __name__ == "__main__":
    main()