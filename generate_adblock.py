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
MAX_WORKERS = 16  # Tăng workers vì phần lớn thời gian là I/O
TIMEOUT = 15  # Giảm timeout
RETRIES = 1  # Giảm retries

ALLOWLIST = {
    "imoulife.com", "lechange.com", "easy4ip.com", 
    "dahuasecurity.com", "tailscale.com",
    "cloudflare-dns.com", "dns.google",
}

# Pre-compile patterns và tối ưu regex
DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

# Cache cho allowlist checking
@lru_cache(maxsize=10000)
def is_allowlisted_cached(domain):
    base = domain[2:] if domain.startswith("*.") else domain
    
    # Tối ưu: kiểm tra trực tiếp trước
    if domain in ALLOWLIST or base in ALLOWLIST:
        return True
    
    for allow in ALLOWLIST:
        if allow.startswith("*."):
            allow_base = allow[2:]
            if base == allow_base or base.endswith("." + allow_base):
                return True
    
    return False

def log(msg):
    print(msg, flush=True)

def is_ip(s):
    # Tối ưu: kiểm tra nhanh hơn
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def normalize_domain(d):
    # Tối ưu: xử lý nhanh hơn với string operations
    d = d.strip().lower()
    if not d:
        return None
    
    # Remove trailing dot và carriage return
    if d.endswith('.'):
        d = d[:-1]
    d = d.replace('\r', '').replace('\n', '')
    
    if not d:
        return None

    if d.startswith("."):
        d = "*" + d

    # Fix double wildcard pattern
    if "*.*." in d:
        d = d.replace("*.*.", "*.", 1)

    # Tối ưu: kiểm tra pattern sớm
    if d.startswith("*."):
        base = d[2:]
        # Fast check cho IP
        if ':' in base or (base.replace('.', '').isdigit() and base.count('.') == 3):
            return None
        if not DOMAIN_RE.match(d):
            return None
        return d

    # Nếu có * hoặc là IP, bỏ qua
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

    # Tối ưu: xử lý comment nhanh hơn
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

    # Tối ưu: Kiểm tra các format phổ biến
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

    # Hosts format
    parts = raw.split(None, 2)
    if len(parts) >= 2:
        first = parts[0]
        # Check if first part is IP
        if first.count('.') == 3 and all(p.isdigit() for p in first.split('.')):
            return normalize_domain(parts[1])
        if first == '127.0.0.1':
            return normalize_domain(parts[1])

    # dnsmasq format
    if raw.startswith('address=/') or raw.startswith('server=/'):
        m = re.match(r"^(?:address|server)=/([^/]+)/", raw)
        if m:
            return normalize_domain(m.group(1))

    # smartdns format
    if raw.startswith('address /'):
        m = re.match(r"^address\s+/([^/]+)/", raw)
        if m:
            return normalize_domain(m.group(1))

    # Plain domain - chỉ lấy token đầu tiên
    space_pos = raw.find(' ')
    if space_pos != -1:
        raw = raw[:space_pos]
    
    tab_pos = raw.find('\t')
    if tab_pos != -1:
        raw = raw[:tab_pos]
    
    # Remove AdGuard modifiers
    raw = raw.rstrip('^$')
    
    return normalize_domain(raw)

def download_one(url):
    name = os.path.basename(urlparse(url).path) or urlparse(url).netloc
    ctx = ssl.create_default_context()
    
    for attempt in range(RETRIES + 1):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "smartdns-blocklist-generator/3.1",
                    "Accept-Encoding": "gzip",
                    "Connection": "close",
                    "Cache-Control": "no-cache",
                },
            )
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
                data = r.read()
                if r.headers.get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                text = data.decode("utf-8", errors="ignore")
                return name, url, text, None

        except Exception as e:
            if attempt == RETRIES:
                return name, url, "", str(e)
            time.sleep(0.5)  # Giảm delay

    return name, url, "", "Max retries exceeded"

def parse_content(text):
    domains = set()
    
    # Tối ưu: xử lý từng dòng một cách hiệu quả
    for line in text.splitlines():
        d = extract_from_line(line)
        if d and not is_allowlisted_cached(d):
            domains.add(d)
    
    return domains

def optimize(domains):
    # Phân loại nhanh
    wildcards = []
    exacts = []
    
    for d in domains:
        if d.startswith("*."):
            wildcards.append(d)
        else:
            exacts.append(d)
    
    # Sắp xếp wildcards theo độ dài (ngắn nhất trước = domain cha)
    wildcards.sort(key=lambda x: (x.count("."), len(x)))
    
    # Loại bỏ wildcards bị bao phủ
    kept_wildcards = []
    wildcard_bases = set()
    
    for w in wildcards:
        base = w[2:]  # Bỏ "*."
        if not any(base.endswith("." + parent_base) for parent_base in wildcard_bases):
            kept_wildcards.append(w)
            wildcard_bases.add(base)
    
    # Kiểm tra exact domains bị wildcards bao phủ
    kept_exacts = []
    for d in exacts:
        # Kiểm tra nhanh xem có bị wildcard nào bao phủ không
        covered = False
        for w_base in wildcard_bases:
            if d.endswith("." + w_base):
                covered = True
                break
        if not covered:
            kept_exacts.append(d)
    
    return kept_wildcards, kept_exacts

def write_output(wildcards, exacts, raw_count, duration):
    final_count = len(wildcards) + len(exacts)
    
    # Tối ưu: ghi file nhanh hơn với join
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
        
        # Ghi domains
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
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(download_one, url): url for url in SOURCES}

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

            log(
                f"OK   {name}: "
                f"parsed={len(domains):,}, "
                f"wildcard={wc:,}, "
                f"exact={ex:,}, "
                f"new={added:,}"
            )

    raw_count = len(all_domains)

    log("")
    log("Optimizing...")
    wildcards, exacts = optimize(all_domains)

    duration = time.time() - start
    write_output(wildcards, exacts, raw_count, duration)

    final_count = len(wildcards) + len(exacts)

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