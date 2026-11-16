# Blocklist

IP blocklists for defensive use: cloud compute space that gets tunnelled
through, commercial bulk hosts that get abused for the same, malware / C2 /
stalkerware infrastructure, and the CDN and enterprise routes that must stay
reachable while all of that is blocked.

Every file under [`lists/`](lists) is **pure CIDR, one prefix per line, no
comments** — ready to feed straight into `ufw`, `iptables`, `nftables`,
`pf` or any set-file consumer.

> [!IMPORTANT]
> The cloud-provider lists (AWS EC2, Azure, GCP) cover entire public clouds.
> Deploy them as **egress** rules, not inbound ones, and expect them to break
> your own services if those services run in the same cloud. Start with
> `lists/blocklist-default.txt`.

## Lists

| File | Prefixes | What it covers |
|---|---:|---|
| [`lists/blocklist-default.txt`](lists/blocklist-default.txt) | 203,787 | Malware / C2 / stalkerware + commonly abused bulk hosts. Safe default. |
| [`lists/blocklist-egress.txt`](lists/blocklist-egress.txt) | 191,680 | Everything above **plus** cloud compute space and Tor exits. Egress control. |
| [`lists/aws-ec2.txt`](lists/aws-ec2.txt) | 4,758 | AWS EC2 compute ranges (official `ip-ranges.amazonaws.com`). |
| [`lists/azure-compute.txt`](lists/azure-compute.txt) | 4,833 | Azure compute space (`AzureCloud` service tag). |
| [`lists/gcp-cloud.txt`](lists/gcp-cloud.txt) | 495 | Google Cloud customer ranges. |
| [`lists/cloud-compute.txt`](lists/cloud-compute.txt) | 10,086 | AWS EC2 + Azure + GCP merged. |
| [`lists/commercial-vps-abused.txt`](lists/commercial-vps-abused.txt) | 12,216 | Bulk hosts repeatedly used for tunnelling: Hetzner, OVH, Contabo, LeaseWeb, ColoCrossing, DigitalOcean, Vultr, Linode, Oracle Cloud, Alibaba, Tencent, M247, Datacamp, Psychz, BuyVM, Scaleway. |
| [`lists/malware-c2-stalkerware.txt`](lists/malware-c2-stalkerware.txt) | 224,972 | Malware hosts, C2, botnet and stalkerware/spyware routes. |
| [`lists/tor-exit-nodes.txt`](lists/tor-exit-nodes.txt) | 686 | Current Tor exit nodes. |
| [`lists/open-proxies.txt.gz`](lists/open-proxies.txt.gz) | 2,594,177 | Open proxies / anonymizers. Gzipped (~8 MB) because it is huge. |
| [`lists/preserve-enterprise.txt`](lists/preserve-enterprise.txt) | 8,729 | CDN and enterprise routes that are **never** blocked. Reference only. |

[`lists/manifest.json`](lists/manifest.json) carries the entry counts and
SHA-256 of every generated file.

## The safeguard rule

Every block category is computed as `category − preserve`. The preserve set
holds the routes registered to large enterprises for common applications and
non-risky software:

- **Akamai** (AS20940 edge space), **Fastly** (official published list),
  **Cloudflare** (official `ips-v4` / `ips-v6`)
- **Google Frontend** (Google's own app-delivery list, `goog.json`)
- **AWS** CloudFront / S3 / Route53
- **Azure Front Door**, **Entra ID (Azure Active Directory)**, Microsoft 365
  app and Defender service tags, Microsoft corporate ASNs
- **GitHub** (AS36459)

Because Google Frontend and the Microsoft ASNs both overlap their own cloud
ranges, the cloud block space is subtracted from the preserve set before it is
applied — so a CDN route can never be swallowed by a cloud prefix, and a cloud
prefix can never be hollowed out by a CDN prefix.

`scripts/verify_blocklists.py` asserts these invariants on every build:

```bash
python3 scripts/verify_blocklists.py lists
```

It fails the build if any preserve range appears inside a block list, if
Cloudflare / Fastly / Akamai / Google / GitHub / Entra / M365 probes are
blocked, or if a combined list stops covering one of its parts.

## Usage

```bash
# ufw
sudo ufw deny -F < lists/blocklist-default.txt

# nftables
sudo nft add set blocklist '{ type ipv4_addr; flags interval; }'
sudo nft add element inet filter blocklist '{ ' +
  awk '{print $1}' lists/blocklist-default.txt + join(", ") +
  '}'

# iptables (one rule per prefix)
while read -r cidr; do
  [[ "$cidr" == \#* ]] || sudo iptables -A INPUT -s "$cidr" -j DROP
done < lists/blocklist-default.txt
```

```python
import ipaddress

def load(path):
    with open(path) as fh:
        return {ipaddress.ip_network(l.strip()) for l in fh if l.strip()}

blocked = load("lists/blocklist-default.txt")
```

## Regenerating

```bash
scripts/fetch_sources.sh sources      # download every upstream feed
python3 scripts/build_blocklists.py sources lists
python3 scripts/verify_blocklists.py lists
```

`scripts/publish_github.sh` publishes a refresh as a single commit through
the GitHub Git Data API.

A GitHub Action ([`.github/workflows/update-blocklists.yml`](.github/workflows/update-blocklists.yml))
runs the same pipeline every 12 hours and commits the result.

### Your own carve-outs

Drop a file at `sources/microsoft365_preserve.txt` (one CIDR per line) and
it is subtracted from the Azure block set and added to the preserve set. Use
it for Microsoft 365 ranges your environment depends on, or for your own
SaaS estate.

## Sources

| Category | Upstream |
|---|---|
| AWS | [`ip-ranges.amazonaws.com/ip-ranges.json`](https://ip-ranges.amazonaws.com/ip-ranges.json) |
| GCP / Google | [`gstatic.com/ipranges/cloud.json`](https://www.gstatic.com/ipranges/cloud.json), [`goog.json`](https://www.gstatic.com/ipranges/goog.json) |
| Azure / Microsoft | [`ServiceTags_Public.json`](https://github.com/jensihnow/AzurePublicIPAddressRanges) (official Azure Service Tags file), [Azure Service Tags API](https://azservicetags.azurewebsites.net/) |
| CDN keeps | [`cloudflare.com/ips`](https://www.cloudflare.com/ips/), [`api.fastly.com/public-ip-list`](https://api.fastly.com/public-ip-list), AS20940 (RIPEstat / [ipverse/as-ip-blocks](https://github.com/ipverse/as-ip-blocks)) |
| ASN ranges | [ipverse/as-ip-blocks](https://github.com/ipverse/as-ip-blocks), fallback RIPEstat `announced-prefixes` |
| Malware / C2 | [FireHOL](https://github.com/firehol/blocklist-ipsets) levels 1–4 + webserver, [Spamhaus DROP](https://www.spamhaus.org/drop/), [Emerging Threats](https://rules.emergingthreats.net/blockrules/compromised-ips.txt), [CINSscore](https://cinsscore.com/list/ci-badguys.txt), [blocklist.de](https://lists.blocklist.de/), [Block List Project](https://github.com/blocklistproject/Lists), [Feodo Tracker](https://feodotracker.abuse.ch/), [botvrij](http://www.botvrij.eu/) |
| Tor | [check.torproject.org/exit-addresses](https://check.torproject.org/exit-addresses) |

## Caveats

- **Azure compute space contains some Microsoft 365 endpoints.** Microsoft
  publishes no feed that separates them from tenant compute, so a strict
  `AzureCloud` block touches some Exchange Online and SharePoint Online
  space. Use `sources/microsoft365_preserve.txt` to carve them out.
- **Tor exits and open proxies** are shipped as separate, opt-in files. They
  are legitimate for some users (anonymity, geo-testing) and produce false
  positives if applied blindly.
- **Bulk-host lists are coarse.** A whole provider's address space is
  blocked, not just the offending instances. Use them for egress control.
- **Everything refreshes.** These lists change daily; treat them as a
  generated artefact, not a static policy.

## Also in this repo

[`blocklist-ips-all-lite.txt`](blocklist-ips-all-lite.txt) — the
IsMalicious.com malicious-IP list (lite, 855,129 entries, refreshed every
12 hours), in the same plain-text format.

## License

MIT — see [LICENSE](LICENSE).
