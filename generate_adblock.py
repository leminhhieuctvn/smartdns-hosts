#!/usr/bin/env python3
"""
SmartDNS Blocklist Generator - Maximum Optimization
Aggregates and optimizes from 12 blocklist sources
Output: adblock_merged.txt (for smartdns domain-set)
"""

import re
import urllib.request
import gzip
import time
import os
from collections import defaultdict
import ssl

# ===== CONFIGURATION =====
SOURCES = [
    # Hagezi Lists (high quality, regularly updated)
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/popupads-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dyndns-onlydomains.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt",
    # Hosts-based lists
    "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts",
    # Big aggregated lists
    "https://big.oisd.nl/domainswild2",
    "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.wildcards",
]

OUTPUT_FILE = "adblock_merged.txt"

# Optimization settings
MIN_DOMAIN_LENGTH = 5
MAX_DOMAIN_LENGTH = 255
WILDCARD_THRESHOLD = 3  # Create wildcard if >= 3 subdomains

def download_with_retry(url, retries=3):
    """Download file with retry logic and gzip support"""
    # Create SSL context that doesn't verify (for problematic servers)
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; SmartDNS-Blocklist/1.0)",
                    "Accept-Encoding": "gzip, deflate"
                }
            )
            with urllib.request.urlopen(req, timeout=60, context=ssl_context) as response:
                data = response.read()
                # Decompress gzip if needed
                if response.info().get('Content-Encoding') == 'gzip':
                    data = gzip.decompress(data)
                return data.decode("utf-8", errors="ignore")
        except Exception as e:
            if attempt < retries - 1:
                print(f"    Retry {attempt + 1}/{retries}: {url.split('/')[-1][:40]}")
                time.sleep(2)
            else:
                print(f"    ✗ Failed: {url.split('/')[-1][:40]} - {str(e)[:50]}")
                return ""
    return ""

def validate_domain(domain):
    """Validate domain name according to RFC 1035"""
    if not domain or len(domain) < MIN_DOMAIN_LENGTH:
        return False
    if len(domain) > MAX_DOMAIN_LENGTH:
        return False
    if '..' in domain:  # No double dots
        return False
    
    # Regex pattern for valid domain
    pattern = r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,}$'
    if not re.match(pattern, domain):
        return False
    
    # Skip numeric-only domains (usually IPs or invalid)
    if re.match(r'^[\d\.]+$', domain):
        return False
    
    return True

def extract_domains_from_wildcard(content):
    """Extract domains from wildcard format (*.domain.com)"""
    domains = set()
    for line in content.splitlines():
        line = line.strip().lower()
        
        # Skip comments and empty lines
        if not line or line.startswith(('#', '!', '//', ';', '[')):
            continue
        
        # Handle wildcard format: *.domain.com
        if line.startswith('*.'):
            domain = line[2:]  # Remove *.
        elif line.startswith('.'):
            domain = line[1:]  # Remove .
        else:
            domain = line
        
        # Clean up: remove port, path, comments
        domain = domain.split('#')[0].split(' ')[0].split('^')[0].split('$')[0]
        domain = domain.strip().rstrip('.')
        
        if validate_domain(domain):
            domains.add(domain)
    
    return domains

def extract_domains_from_hosts(content):
    """Extract domains from hosts file format"""
    domains = set()
    for line in content.splitlines():
        line = line.strip().lower()
        
        # Skip comments and non-hosts lines
        if not line or line.startswith(('#', '!', '//')):
            continue
        
        # Hosts format: IP domain
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1].split('#')[0].strip().rstrip('.')
            if validate_domain(domain):
                domains.add(domain)
    
    return domains

def extract_domains_from_oisd(content):
    """Extract from OISD format (with wildcard and regex)"""
    domains = set()
    for line in content.splitlines():
        line = line.strip().lower()
        
        # Skip comments, regex, empty lines
        if not line or line.startswith(('#', '!', '//', ';', '[', '/', '|')):
            continue
        
        # Only take wildcard or simple domains
        if '*' in line:
            domain = line.replace('*.', '').strip()
        elif '^' in line or '$' in line:
            continue  # Skip regex patterns
        else:
            domain = line.split('#')[0].strip()
        
        domain = domain.rstrip('.')
        if validate_domain(domain):
            domains.add(domain)
    
    return domains

def optimize_wildcards(domains):
    """
    Optimize by grouping subdomains into wildcards
    
    If many subdomains share the same parent domain,
    merge them into *.parent.com to reduce rule count
    """
    print(f"\n🔧 Wildcard optimization (threshold: {WILDCARD_THRESHOLD})...")
    
    # Group subdomains by parent domain
    parent_map = defaultdict(set)
    
    for domain in domains:
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if len(parts[:i]) >= 1:  # Has at least 1 subdomain
                parent_map[parent].add(domain)
    
    # Create wildcards for parents with >= threshold subdomains
    wildcards = set()
    removed = set()
    
    for parent, subs in parent_map.items():
        if len(subs) >= WILDCARD_THRESHOLD:
            # Don't wildcard if parent itself is in the list (avoid overblocking)
            if parent not in domains:
                wildcards.add(f"*.{parent}")
                removed.update(subs)
    
    # Merge: add wildcards, remove grouped subdomains
    optimized = (domains - removed) | wildcards
    
    reduction = len(domains) - len(optimized)
    if len(domains) > 0:
        pct = (reduction / len(domains)) * 100
    else:
        pct = 0
    
    print(f"  ✓ Created {len(wildcards):,} wildcards")
    print(f"  ✓ Reduced {reduction:,} rules ({pct:.1f}%)")
    print(f"  ✓ Remaining: {len(optimized):,} rules")
    
    return optimized

def deduplicate_subdomains(domains):
    """
    Remove subdomains already covered by wildcards
    
    If *.example.com exists, remove a.example.com, b.example.com, etc.
    """
    print(f"\n🔧 Deduplicating subdomains...")
    
    wildcards = {d.replace('*.', '') for d in domains if d.startswith('*.')}
    regular = {d for d in domains if not d.startswith('*.')}
    
    # Remove subdomains covered by wildcard parents
    filtered = set()
    for domain in regular:
        parts = domain.split('.')
        is_covered = False
        
        # Check all parent domains
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in wildcards:
                is_covered = True
                break
        
        if not is_covered:
            filtered.add(domain)
    
    result = {f"*.{w}" for w in wildcards} | filtered
    reduction = len(domains) - len(result)
    print(f"  ✓ Removed {reduction:,} covered subdomains")
    
    return result

def sort_domains_efficiently(domains):
    """
    Smart sorting for better smartdns performance
    
    - Wildcards first (smartdns processes them first)
    - Sort by TLD then domain (better cache hit rate)
    """
    print(f"\n🔧 Efficient sorting...")
    
    wildcards = sorted([d for d in domains if d.startswith('*.')])
    regular = sorted([d for d in domains if not d.startswith('*.')])
    
    # Sort wildcards by length (shorter first - faster match)
    wildcards.sort(key=lambda x: (len(x), x))
    
    # Sort regular: TLD first, then domain
    regular.sort(key=lambda x: (x.split('.')[-1], '.'.join(x.split('.')[:-1])))
    
    return wildcards + regular

def main():
    print("=" * 60)
    print("🚀 SMARTDNS BLOCKLIST GENERATOR - MAXIMUM OPTIMIZATION")
    print("=" * 60)
    print(f"📥 Sources: {len(SOURCES)} lists")
    print(f"⚙️  Settings: Wildcard threshold={WILDCARD_THRESHOLD}")
    print("-" * 60)
    
    all_domains = set()
    stats = {}
    
    # Phase 1: Download and extract
    for url in SOURCES:
        name = url.split('/')[-1].split('?')[0]
        print(f"↓ {name[:50]}...")
        
        content = download_with_retry(url)
        if not content:
            stats[name] = 0
            continue
        
        # Choose appropriate parser
        if 'oisd' in url.lower():
            domains = extract_domains_from_oisd(content)
        elif 'hosts' in url.lower() or 'hostsvn' in url.lower():
            domains = extract_domains_from_hosts(content)
        else:
            domains = extract_domains_from_wildcard(content)
        
        stats[name] = len(domains)
        all_domains.update(domains)
        print(f"  ✓ {len(domains):,} domains")
    
    # Statistics
    print("\n" + "=" * 60)
    print("📊 SOURCE STATISTICS:")
    max_count = max(stats.values()) if stats else 1
    for name, count in stats.items():
        bar_length = min(int(count / max_count * 20), 20) if max_count > 0 else 0
        bar = "█" * bar_length
        print(f"  {name[:40]:40s} {count:>8,} {bar}")
    print(f"  {'TOTAL RAW':40s} {len(all_domains):>8,}")
    
    # Phase 2: Optimization
    print("\n" + "=" * 60)
    print("⚡ OPTIMIZATION:")
    
    initial_count = len(all_domains)
    
    # Optimization 1: Wildcard grouping
    all_domains = optimize_wildcards(all_domains)
    
    # Optimization 2: Deduplicate covered subdomains
    all_domains = deduplicate_subdomains(all_domains)
    
    # Optimization 3: Smart sorting
    final_domains = sort_domains_efficiently(all_domains)
    
    # Final statistics
    reduction = initial_count - len(final_domains)
    reduction_pct = (reduction / initial_count * 100) if initial_count > 0 else 0
    
    print(f"\n{'='*60}")
    print(f"📈 FINAL RESULTS:")
    print(f"  Raw domains:    {initial_count:>10,}")
    print(f"  Final rules:    {len(final_domains):>10,}")
    print(f"  Reduced:        {reduction:>10,} ({reduction_pct:.1f}%)")
    
    # Estimate RAM usage
    if final_domains:
        avg_len = sum(len(d) for d in final_domains) / len(final_domains)
        estimated_ram = (len(final_domains) * (avg_len + 64)) / 1024  # KB
        print(f"  Est. RAM usage: {estimated_ram:>10.1f} KB")
    
    # Phase 3: Write output file
    print(f"\n💾 Writing {OUTPUT_FILE}...")
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8', newline='\n') as f:
        f.write("# SmartDNS Adblock Domain Set\n")
        f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"# Sources: {len(SOURCES)} blocklists\n")
        f.write(f"# Total rules: {len(final_domains):,}\n")
        f.write(f"# Optimization: Wildcard grouping, dedup, efficient sorting\n")
        f.write("#" + "="*60 + "\n\n")
        
        for domain in final_domains:
            f.write(f"{domain}\n")
    
    # File size check
    file_size = os.path.getsize(OUTPUT_FILE) / 1024  # KB
    print(f"  ✓ File size: {file_size:.1f} KB")
    print(f"  ✓ Rules: {len(final_domains):,}")
    
    print("\n" + "="*60)
    print("✅ COMPLETED SUCCESSFULLY!")
    print(f"Output: {OUTPUT_FILE}")
    print("="*60)

if __name__ == "__main__":
    main()