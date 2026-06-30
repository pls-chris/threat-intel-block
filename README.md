# threat-intel-block

A daily-updated **consolidated threat intelligence IP blocklist** built from multiple high-quality open source feeds. Single file, deduplicated, ready for firewall import.

## How it works

A CI/CD pipeline downloads all feeds defined in `feeds.yaml`, parses IPs and CIDR ranges across multiple formats, merges manually added IOCs from `custom_blocklist.txt`, deduplicates, applies a whitelist for false positive exclusions, and outputs a single `blocklist.txt`.

Stats track per-feed health: entry counts, unique contributions, and overlap — so you can see which feeds are pulling their weight and catch any that go stale.

## Files

- `blocklist.txt` — Consolidated blocklist. One IP or CIDR per line. Point your firewall here.
- `feeds.yaml` — Feed definitions. Add, remove, or disable feeds without touching code.
- `custom_blocklist.txt` — Manually added IPs/CIDRs (incident IOCs, CERT advisories, internal threat hunting).
- `whitelist.txt` — IPs/CIDRs to exclude (false positives, your own infrastructure).
- `stats.txt` — Per-feed breakdown with unique/overlap analysis.

## Included feeds

| Feed | Category | What it tracks |
|---|---|---|
| Spamhaus DROP / DROPv6 | Hijacked networks | Worst-of-the-worst netblocks |
| abuse.ch Feodo Tracker | Botnet C2 | Feodo/Dridex/TrickBot/QakBot C2 servers |
| abuse.ch SSL Blacklist | Malware | Malicious SSL connections |
| C2-Tracker (JMousqueton) | C2 infrastructure | Cobalt Strike, Sliver, Metasploit, Brute Ratel |
| CINS Army | Attacks | Sentinel-detected attackers |
| DShield / DShield 30d | Attacks | Top attackers (SANS ISC) |
| Blocklist.de | Attacks | Community-reported attackers |
| GreenSnow | Attacks | Aggressive attacker IPs |
| Emerging Threats | Attacks | Compromised IPs |
| OpenDBL Bruteforce | Attacks | Brute force attackers |
| OpenDBL ET Known | Attacks | Known bad IPs |
| Stamparm ipsum L3 | Aggregated | Multi-feed scored (≥3 sources) |
| OpenDBL Tor Exit | Anonymizers | Tor exit nodes |

## Firewall configuration

Import `blocklist.txt` as a URL-based IP list/alias in your firewall, pointed at:

```
https://raw.githubusercontent.com/pls-chris/threat-intel-block/main/blocklist.txt
```

Set it to refresh daily to match the update schedule.

Create a rule blocking all inbound traffic from the alias to your network. For outbound blocking as well (prevents compromised internal hosts from reaching C2), add a second rule blocking LAN → alias. If you have multiple internal interfaces (VLANs, guest networks, IoT segments), use a floating/global rule to apply it across all of them at once.

## Managing feeds

### Adding a feed

Edit `feeds.yaml` and add an entry:

```yaml
  - name: My New Feed
    url: https://example.com/blocklist.txt
    category: attacks
    format: auto
    enabled: true
```

Supported formats: `plain` (most feeds), `spamhaus`, `dshield`, `stamparm`, `auto` (tries plain).

### Disabling a feed

Set `enabled: false` — the feed stays in config but is skipped during scraping.

## Adding manual IOCs

For incident-specific indicators not covered by automated feeds — such as IOCs from CERT/CSIRT advisories, NIS2 coordination groups, vendor security bulletins, or internal threat hunting — add them to `custom_blocklist.txt`:

```
# --- FortiBleed C2 infrastructure (SOCRadar STRU, June 2026) ---
85.11.187.8
193.8.187.42
194.113.39.71

# --- CERT-XX advisory 2026-042 ---
203.0.113.50
```

Use comment headers to document the source and date for each group. These entries are merged into `blocklist.txt` on every run and tracked separately as "Custom blocklist" in `stats.txt`.

Commit and push — the workflow triggers automatically and merges them into the consolidated blocklist on the next run.

## Handling false positives

If a legitimate IP appears in the blocklist, add it to `whitelist.txt`:

```
# CDN edge server wrongly flagged
203.0.113.50
```

Supports both single IPs and CIDR ranges.

## Update schedule

The workflow runs **daily at 04:00 UTC** via GitHub Actions, plus on any push that changes the scraper code, feed config, custom blocklist, or whitelist. Manual trigger available via the Actions tab.

## Running locally

```bash
pip install requests pyyaml
python scraper/consolidate.py
```

## License

GPL-3.0
