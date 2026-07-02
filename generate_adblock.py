#!/usr/bin/env python3
"""
SmartDNS Blocklist Generator - SIMPLE & SAFE
Chỉ dùng nguồn có sẵn wildcard format (*.domain.com)
Không tự sinh wildcard → không lo false positive!
"""

import urllib.request
import ssl
import gzip
import re
import time
import os

# ===== NGUỒN WILDCARD FORMAT (đã được maintainer xử lý an toàn) =====
SOURCES = [
    # Hagezi - Các list đã được optimize wildcard sẵn
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.mini-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/popupads-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dyndns-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling.mini-onlydomains.txt",
    
    # OISD - Big list với wildcard sẵn
    "https://big.oisd.nl/domainswild",
    
    # 1Hosts - Wildcard format
    "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/wildcards.txt"
]

OUTPUT_FILE = "adblock_merged.txt"

def download_content(url):
    """Download với retry"""
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    for attempt in range(3):
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0", "Accept-Encoding": "gzip, deflate"}
            )
            with urllib.request.urlopen(req, timeout=60, context=ssl_context) as res:
                data = res.read()
                if res.info().get('Content-Encoding') == 'gzip':
                    data = gzip.decompress(data)
                return data.decode('utf-8', errors='ignore')
        except Exception as e:
            if attempt < 2:
                time.sleep(2)
    return ""

def extract_wildcard_domains(content):
    """
    Chỉ extract domains từ wildcard format
    Giữ nguyên wildcard (*.domain) hoặc domain đơn
    """
    domains = set()
    
    for line in content.splitlines():
        line = line.strip().lower()
        
        # Skip comments, empty, metadata
        if not line or line.startswith(('#', '!', '//', ';', '[', '/')):
            continue
        
        # Clean: bỏ port, path, regex, comment
        domain = line.split('#')[0].split('^')[0].split('$')[0].split(' ')[0]
        domain = domain.strip().rstrip('.')
        
        # Validate cơ bản
        if not domain or len(domain) < 4:
            continue
        if '..' in domain:
            continue
        
        # Chấp nhận:
        # - *.domain.com (wildcard)
        # - domain.com (exact)
        # - sub.domain.com (exact subdomain)
        if '*' in domain:
            # Wildcard format: *.domain.com
            if domain.startswith('*.') and domain.count('*') == 1:
                clean = domain[2:]  # Bỏ *.
                if '.' in clean and len(clean) >= 8:
                    domains.add(domain)
        else:
            # Regular domain
            if '.' in domain and not domain.startswith('-') and not domain.endswith('-'):
                if re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,}$', domain):
                    domains.add(domain)
    
    return domains

def extract_hosts_domains(content):
    """
    Extract từ hosts file (không có wildcard)
    """
    domains = set()
    
    for line in content.splitlines():
        line = line.strip().lower()
        
        if not line or line.startswith(('#', '!', '//')):
            continue
        
        # Hosts format: 0.0.0.0 domain.com
        if '127.0.0.1' in line or '0.0.0.0' in line:
            parts = line.split()
            if len(parts) >= 2:
                domain = parts[1].split('#')[0].strip().rstrip('.')
                if '.' in domain and len(domain) >= 4:
                    if re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,}$', domain):
                        domains.add(domain)
    
    return domains

def main():
    print("=" * 60)
    print("📋 SMARTDNS BLOCKLIST - SIMPLE & SAFE")
    print("=" * 60)
    print("Strategy: Use pre-made wildcards from trusted sources")
    print("         No auto-generation → No false positives!")
    print("-" * 60)
    
    all_domains = set()
    stats = {}
    
    for url in SOURCES:
        name = url.split('/')[-1][:50]
        print(f"↓ {name}...")
        
        content = download_content(url)
        if not content:
            continue
        
        if 'hosts' in url.lower() or 'hostsvn' in url.lower():
            domains = extract_hosts_domains(content)
        else:
            domains = extract_wildcard_domains(content)
        
        # Đếm wildcards và regular
        wildcards = sum(1 for d in domains if d.startswith('*.'))
        regular = len(domains) - wildcards
        
        stats[name] = len(domains)
        all_domains.update(domains)
        
        print(f"  ✓ {len(domains):,} domains ({wildcards:,} wildcards + {regular:,} exact)")
    
    # Deduplicate
    print(f"\n📊 RESULTS:")
    total_before = sum(stats.values())
    total_after = len(all_domains)
    duplicates = total_before - total_after
    
    for name, count in stats.items():
        print(f"  {name:50s} {count:>8,}")
    print(f"  {'─'*60}")
    print(f"  {'TOTAL (raw)':50s} {total_before:>8,}")
    print(f"  {'DUPLICATES':50s} {duplicates:>8,}")
    print(f"  {'FINAL':50s} {total_after:>8,}")
    
    # Phân loại
    wildcards = sorted([d for d in all_domains if d.startswith('*.')], key=lambda x: (len(x), x))
    regular = sorted([d for d in all_domains if not d.startswith('*.')])
    
    print(f"\n  Wildcards: {len(wildcards):,}")
    print(f"  Exact domains: {len(regular):,}")
    
    # Kiểm tra wildcard an toàn
    print(f"\n🔍 SAFETY CHECK:")
    dangerous = []
    for w in wildcards:
        clean = w[2:]  # Bỏ *.
        parts = clean.split('.')
        # Wildcard an toàn: ít nhất 3 parts (sub.domain.tld)
        if len(parts) < 3:
            dangerous.append(w)
    
    if dangerous:
        print(f"  ⚠️  POTENTIALLY DANGEROUS WILDCARDS ({len(dangerous)}):")
        for w in dangerous[:10]:
            print(f"    {w}")
        print(f"  ℹ️  These come from upstream sources, check if intentional")
    else:
        print(f"  ✅ All {len(wildcards)} wildcards have ≥3 levels (safe)")
    
    # Show sample
    print(f"\n📋 SAMPLE WILDCARDS:")
    for w in wildcards[:10]:
        print(f"  {w}")
    if len(wildcards) > 10:
        print(f"  ... and {len(wildcards)-10} more")
    
    print(f"\n📋 SAMPLE EXACT DOMAINS:")
    for d in regular[:10]:
        print(f"  {d}")
    if len(regular) > 10:
        print(f"  ... and {len(regular)-10} more")
    
    # Write output
    print(f"\n💾 Writing {OUTPUT_FILE}...")
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8', newline='\n') as f:
        f.write(f"# SmartDNS Blocklist - Safe Pre-made Wildcards\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"# Sources: {len(SOURCES)} trusted wildcard lists\n")
        f.write(f"# Total: {len(all_domains):,} rules\n")
        f.write(f"# Wildcards: {len(wildcards):,}\n")
        f.write(f"# Exact: {len(regular):,}\n")
        f.write(f"# Strategy: Only use pre-made wildcards from maintainers\n")
        f.write("#" + "="*60 + "\n\n")
        
        for domain in wildcards:
            f.write(f"{domain}\n")
        for domain in regular:
            f.write(f"{domain}\n")
    
    file_size = os.path.getsize(OUTPUT_FILE) / 1024
    print(f"  ✓ {OUTPUT_FILE}: {file_size:.1f} KB")
    print(f"  ✓ {len(all_domains):,} rules")
    
    print(f"\n{'='*60}")
    print(f"✅ DONE! Safe to use with SmartDNS")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()