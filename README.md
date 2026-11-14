# IP Blocklist

Public, continuously updated list of malicious IP addresses.

## Files

| File | Description | Entries | Format |
|---|---|---|---|
| [`blocklist-ips-all-lite.txt`](blocklist-ips-all-lite.txt) | Lite version (10% sample) of the full malicious-IP list | 855,129 | Plain text, one IP per line |

## Format

The list is plain text — one IPv4 address per line. Lines beginning with `#` are comments:

```
# IsMalicious.com Blocklist - IPs (All Levels)
# Format: Plain
# Generated: 2026-11-14T11:31:57.792015311+00:00
# Total entries: 855,129 (Lite Version - 10% of 8,551,298)
# Update frequency: every 12 hours
```

## Usage

**Firewall / IP set**

```bash
# ufw
sudo ufw deny -F < blocklist-ips-all-lite.txt

# plain iptables
while read -r ip; do [[ "$ip" == \#* ]] || iptables -A INPUT -s "$ip" -j DROP; done < blocklist-ips-all-lite.txt
```

**Python**

```python
with open("blocklist-ips-all-lite.txt") as f:
    blocked = {line.strip() for line in f if line.strip() and not line.startswith("#")}
```

## Notes

- Entries reflect sources classified as malicious at generation time; always verify against your own threat model before blocking at scale.
- The list refreshes every 12 hours. Pull to get the newest snapshot.
- The full (non-lite) list contains 8,551,298 entries.

## License

MIT — see [LICENSE](LICENSE).
