#!/usr/bin/env python3
"""
consolidate.py — Download, parse, deduplicate, and consolidate
multiple threat intelligence IP feeds into a single blocklist.

Designed for firewall use (OPNsense, pfSense, iptables, etc.)
"""

import re
import sys
import time
import ipaddress
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml
import requests

# --- Configuration ---
MAX_WORKERS = 6
REQUEST_TIMEOUT = 60
RETRY_COUNT = 3
RETRY_DELAY = 3

# Paths
ROOT_DIR = Path(__file__).parent.parent
FEEDS_FILE = ROOT_DIR / "feeds.yaml"
BLOCKLIST_FILE = ROOT_DIR / "blocklist.txt"
STATS_FILE = ROOT_DIR / "stats.txt"
WHITELIST_FILE = ROOT_DIR / "whitelist.txt"
CUSTOM_BLOCKLIST_FILE = ROOT_DIR / "custom_blocklist.txt"

# Regex
IPV4_RE = re.compile(
    r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)'
)
IPV6_RE = re.compile(
    r'^([0-9a-fA-F:]+(?:/\d{1,3})?)\s'
)

session = requests.Session()
session.headers.update({
    "User-Agent": "threat-intel-block/1.0",
    "Accept": "text/plain, text/csv, */*",
})


def errprint(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr, flush=True)


def load_feeds():
    """Load feed definitions from YAML config."""
    with open(FEEDS_FILE) as f:
        config = yaml.safe_load(f)
    feeds = [fd for fd in config.get("feeds", []) if fd.get("enabled", True)]
    errprint(f"Loaded {len(feeds)} enabled feeds from {FEEDS_FILE.name}")
    return feeds


def load_whitelist():
    """Load IPs/CIDRs to exclude from the blocklist."""
    whitelist = set()
    if not WHITELIST_FILE.exists():
        return whitelist
    with open(WHITELIST_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                # Handle both single IPs and CIDR ranges
                if "/" in line:
                    net = ipaddress.ip_network(line, strict=False)
                    whitelist.add(str(net))
                else:
                    whitelist.add(str(ipaddress.ip_address(line)))
            except ValueError:
                errprint(f"  Whitelist: skipping invalid entry: {line}")
    return whitelist


def load_custom_blocklist():
    """Load manually added IPs/CIDRs from custom_blocklist.txt."""
    entries = set()
    if not CUSTOM_BLOCKLIST_FILE.exists():
        return entries
    with open(CUSTOM_BLOCKLIST_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                if "/" in line:
                    net = ipaddress.ip_network(line, strict=False)
                    if not net.is_private and not net.is_loopback:
                        entries.add(str(net))
                else:
                    ip = ipaddress.ip_address(line)
                    if ip.is_global and not ip.is_multicast:
                        entries.add(str(ip))
            except ValueError:
                errprint(f"  Custom blocklist: skipping invalid entry: {line}")
    return entries


def download_feed(feed):
    """Download a single feed with retries."""
    name = feed["name"]
    url = feed["url"]
    for attempt in range(1, RETRY_COUNT + 1):
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            return feed, resp.text, None
        except requests.RequestException as e:
            if attempt < RETRY_COUNT:
                time.sleep(RETRY_DELAY * attempt)
            else:
                return feed, None, str(e)
    return feed, None, "max retries exceeded"


def parse_entry(raw):
    """Try to parse a single line as an IP or CIDR. Returns str or None."""
    raw = raw.strip()
    if not raw:
        return None

    # Try IPv4 with optional CIDR
    m = IPV4_RE.match(raw)
    if m:
        candidate = m.group(1)
        try:
            if "/" in candidate:
                net = ipaddress.ip_network(candidate, strict=False)
                if not net.is_private and not net.is_loopback:
                    return str(net)
            else:
                ip = ipaddress.ip_address(candidate)
                if ip.is_global and not ip.is_multicast:
                    return str(ip)
        except ValueError:
            pass

    # Try IPv6 with optional CIDR
    try:
        if ":" in raw:
            part = raw.split()[0].split(";")[0].split("#")[0].strip()
            if "/" in part:
                net = ipaddress.ip_network(part, strict=False)
                if not net.is_private and not net.is_loopback:
                    return str(net)
            else:
                ip = ipaddress.ip_address(part)
                if ip.is_global and not ip.is_multicast:
                    return str(ip)
    except ValueError:
        pass

    return None


def parse_plain(text):
    """Parse a plain text feed (one IP/CIDR per line, # or ; comments)."""
    entries = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        # Strip inline comments
        for sep in [" #", " ;", "\t#", "\t;"]:
            if sep in line:
                line = line[:line.index(sep)]
        entry = parse_entry(line)
        if entry:
            entries.add(entry)
    return entries


def parse_spamhaus(text):
    """Parse Spamhaus DROP format: CIDR ; SBL-ID."""
    entries = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        part = line.split(";")[0].strip()
        entry = parse_entry(part)
        if entry:
            entries.add(entry)
    return entries


def parse_dshield(text):
    """Parse DShield block.txt format: Start\tEnd\tNetmask."""
    entries = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 3:
            start_ip = parts[0].strip()
            netmask = parts[2].strip()
            try:
                # Convert start IP + netmask to CIDR
                net = ipaddress.ip_network(f"{start_ip}/{netmask}", strict=False)
                if not net.is_private:
                    entries.add(str(net))
            except ValueError:
                # Try just the IP
                entry = parse_entry(start_ip)
                if entry:
                    entries.add(entry)
        else:
            entry = parse_entry(line)
            if entry:
                entries.add(entry)
    return entries


def parse_stamparm(text):
    """Parse stamparm/ipsum format: IP\\tcount (with # comments)."""
    entries = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        entry = parse_entry(parts[0])
        if entry:
            entries.add(entry)
    return entries


PARSERS = {
    "plain": parse_plain,
    "cidr": parse_plain,
    "spamhaus": parse_spamhaus,
    "dshield": parse_dshield,
    "stamparm": parse_stamparm,
    "csv_ip": parse_plain,
    "auto": parse_plain,
}


def parse_feed(feed, text):
    """Parse a feed using the appropriate parser."""
    fmt = feed.get("format", "auto")
    parser = PARSERS.get(fmt, parse_plain)
    return parser(text)


def is_whitelisted(entry, whitelist, whitelist_networks):
    """Check if an entry should be excluded."""
    if entry in whitelist:
        return True
    try:
        if "/" in entry:
            # Entry is a network — check if it's contained in any whitelist network
            net = ipaddress.ip_network(entry, strict=False)
            for wl_net in whitelist_networks:
                if net.subnet_of(wl_net):
                    return True
        else:
            # Entry is an IP — check if it's in any whitelist network
            ip = ipaddress.ip_address(entry)
            for wl_net in whitelist_networks:
                if ip in wl_net:
                    return True
    except (ValueError, TypeError):
        pass
    return False


def sort_key(entry):
    """Sort entries: IPv4 first, then IPv6, numerically."""
    try:
        if "/" in entry:
            net = ipaddress.ip_network(entry, strict=False)
            return (net.version, net.network_address.packed, net.prefixlen)
        else:
            ip = ipaddress.ip_address(entry)
            return (ip.version, ip.packed, 128)
    except ValueError:
        return (99, b"", 0)


def main():
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    errprint("=" * 60)
    errprint("threat-intel-block: Consolidated Blocklist Generator")
    errprint(f"Run: {now}")
    errprint("=" * 60)

    # Load config
    feeds = load_feeds()
    whitelist_raw = load_whitelist()

    # Pre-parse whitelist networks for containment checks
    whitelist_networks = []
    for entry in whitelist_raw:
        try:
            if "/" in entry:
                whitelist_networks.append(
                    ipaddress.ip_network(entry, strict=False))
        except ValueError:
            pass

    # Download all feeds in parallel
    errprint(f"\nDownloading {len(feeds)} feeds...")
    feed_results = {}
    feed_entries = {}
    feed_errors = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(download_feed, fd): fd for fd in feeds}
        for future in as_completed(futures):
            feed, text, error = future.result()
            name = feed["name"]
            if error:
                errprint(f"  FAILED: {name}: {error}")
                feed_errors[name] = error
                feed_entries[name] = set()
            else:
                entries = parse_feed(feed, text)
                feed_entries[name] = entries
                errprint(f"  OK: {name}: {len(entries)} entries")

    # Consolidate
    all_entries = set()
    provenance = defaultdict(set)  # entry -> set of feed names

    for feed in feeds:
        name = feed["name"]
        for entry in feed_entries.get(name, set()):
            all_entries.add(entry)
            provenance[entry].add(name)

    errprint(f"\nTotal raw entries: {len(all_entries)}")

    # Merge custom blocklist
    custom_entries = load_custom_blocklist()
    if custom_entries:
        custom_new = custom_entries - all_entries
        for entry in custom_entries:
            all_entries.add(entry)
            provenance[entry].add("Custom blocklist")
        errprint(f"Custom blocklist: {len(custom_entries)} entries "
                 f"({len(custom_new)} new)")

    # Apply whitelist
    whitelisted_count = 0
    final_entries = set()
    for entry in all_entries:
        if is_whitelisted(entry, whitelist_raw, whitelist_networks):
            whitelisted_count += 1
        else:
            final_entries.add(entry)

    if whitelisted_count:
        errprint(f"Whitelisted (excluded): {whitelisted_count}")

    errprint(f"Final entries: {len(final_entries)}")

    # Safety check
    if len(final_entries) < 100:
        errprint("WARNING: Suspiciously low count — possible issue")
        errprint("NOT overwriting existing files")
        sys.exit(1)

    # Sort and write blocklist
    sorted_entries = sorted(final_entries, key=sort_key)
    with open(BLOCKLIST_FILE, "w") as f:
        f.write(f"# Consolidated Threat Intelligence Blocklist\n")
        f.write(f"# Generated: {now}\n")
        f.write(f"# Entries: {len(sorted_entries)}\n")
        f.write(f"# Feeds: {len(feeds)}\n")
        f.write(f"# Source: github.com/pls-chris/threat-intel-block\n")
        f.write(f"#\n")
        for entry in sorted_entries:
            f.write(f"{entry}\n")

    errprint(f"Wrote {len(sorted_entries)} entries to {BLOCKLIST_FILE.name}")

    # Compute overlap stats
    overlap_counts = defaultdict(int)
    for entry, sources in provenance.items():
        if len(sources) > 1:
            for src in sources:
                overlap_counts[src] += 1

    # Write stats
    with open(STATS_FILE, "w") as f:
        f.write(f"Consolidated Threat Intelligence Blocklist — Stats\n")
        f.write(f"Generated: {now}\n")
        f.write(f"{'=' * 55}\n\n")

        f.write(f"Total unique entries: {len(final_entries)}\n")
        f.write(f"Whitelisted (excluded): {whitelisted_count}\n")
        f.write(f"Feeds downloaded: {len(feeds) - len(feed_errors)}/{len(feeds)}\n")
        if feed_errors:
            f.write(f"Feeds failed: {', '.join(feed_errors.keys())}\n")
        f.write(f"Custom blocklist: {len(custom_entries)} entries\n")
        f.write(f"\n")

        f.write(f"{'Feed':<30} {'Entries':>8} {'Unique':>8} {'Overlap':>8}  Category\n")
        f.write(f"{'-'*30} {'-'*8} {'-'*8} {'-'*8}  {'-'*12}\n")

        for feed in feeds:
            name = feed["name"]
            entries = feed_entries.get(name, set())
            # "Unique" = entries only found in this feed
            unique = sum(1 for e in entries if len(provenance.get(e, set())) == 1)
            overlap = overlap_counts.get(name, 0)
            category = feed.get("category", "")
            status = f"{len(entries):>8}" if name not in feed_errors else "  FAILED"
            f.write(f"{name:<30} {status} {unique:>8} {overlap:>8}  {category}\n")

        # Custom blocklist stats
        if custom_entries:
            custom_unique = sum(1 for e in custom_entries
                                if e in final_entries
                                and len(provenance.get(e, set())) == 1)
            custom_overlap = overlap_counts.get("Custom blocklist", 0)
            f.write(f"{'Custom blocklist':<30} {len(custom_entries):>8} "
                    f"{custom_unique:>8} {custom_overlap:>8}  manual\n")

        f.write(f"\n{'=' * 55}\n")
        f.write(f"Overlap = entries also found in other feeds\n")
        f.write(f"Unique = entries found ONLY in this feed\n")

    errprint(f"Wrote stats to {STATS_FILE.name}")
    errprint("\nDone!")


if __name__ == "__main__":
    main()
