#!/usr/bin/env python3
"""
build_blocklists.py - turn the raw feeds in sources/ into category blocklists.

Design rules
------------
1. Every output is pure CIDR (one per line, no comments) so it can be fed
   straight to ufw / iptables / pf / nftables set files.
2. "preserve" ranges (CDN and enterprise app-delivery routes) are subtracted
   from every block category, so a category can never accidentally blackhole
   a route that large enterprises use for normal software.
3. Output covers exactly the same IP space as the sources: everything is
   handled as (version, start, end) integer ranges, merged and then written
   back out as the minimal set of CIDR blocks.

Usage: scripts/build_blocklists.py [sources_dir] [out_dir]
"""

import gzip
import hashlib
import json
import os
import sys
from bisect import bisect_left, bisect_right
from datetime import datetime, timezone

SRC = sys.argv[1] if len(sys.argv) > 1 else "sources"
OUT = sys.argv[2] if len(sys.argv) > 2 else "lists"

os.makedirs(OUT, exist_ok=True)
BITS = {4: 32, 6: 128}


def p(*parts):
    return os.path.join(SRC, *parts)


def out(*parts):
    return os.path.join(OUT, *parts)


def read(name):
    path = p(name)
    if not os.path.exists(path):
        return ""
    with open(path, "r", errors="replace") as fh:
        return fh.read()


# ------------------------------------------------------------ range plumbing
def _v6_int(addr):
    """Parse an IPv6 address (with optional :: and embedded IPv4) to an int."""
    if "." in addr:
        head, _, v4 = addr.rpartition(":")
        parts = v4.split(".")
        v4val = (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
        addr = (head + ":" if head else "") + "%x:%x" % (v4val >> 16, v4val & 0xFFFF)
    if "::" in addr:
        head, _, tail = addr.partition("::")
        h = [g for g in head.split(":") if g]
        t = [g for g in tail.split(":") if g]
        groups = h + ["0"] * (8 - len(h) - len(t)) + t
    else:
        groups = addr.split(":")
    value = 0
    for g in groups:
        value = (value << 16) | int(g, 16)
    return value


def to_range(token):
    """'1.2.3.0/24' or '1.2.3.4' -> (version, start_int, end_int)."""
    token = token.strip()
    if not token or token.startswith("#"):
        return None
    try:
        if "/" in token:
            addr, plen_s = token.rsplit("/", 1)
            plen = int(plen_s)
        else:
            addr, plen = token, None
        if ":" in addr:
            version, bits = 6, 128
            base = _v6_int(addr)
        else:
            version, bits = 4, 32
            octets = addr.split(".")
            if len(octets) != 4:
                return None
            base = ((int(octets[0]) << 24) | (int(octets[1]) << 16) |
                    (int(octets[2]) << 8) | int(octets[3]))
        if plen is None:
            plen = bits
        if plen < 0 or plen > bits:
            return None
        mask = ((1 << plen) - 1) << (bits - plen)
        start = base & mask
        return (version, start, start | ((1 << (bits - plen)) - 1))
    except (ValueError, IndexError):
        return None


def merge(ranges):
    """Merge overlapping/adjacent ranges, per version. -> sorted list."""
    merged = []
    for version in (4, 6):
        items = sorted(r for r in ranges if r[0] == version)
        if not items:
            continue
        cur_v, cur_s, cur_e = items[0]
        for v, s, e in items[1:]:
            if s <= cur_e + 1:
                if e > cur_e:
                    cur_e = e
            else:
                merged.append((cur_v, cur_s, cur_e))
                cur_v, cur_s, cur_e = v, s, e
        merged.append((cur_v, cur_s, cur_e))
    return merged


def subtract(block, keep):
    """Remove every IP covered by keep from block. Exact, keeps remaining IPs.

    keep is merged first, so its ranges are disjoint and sorted: a bisect
    finds the only ranges that can overlap a given block range.
    """
    if not keep:
        return merge(block)
    keep_v = {4: [], 6: []}
    for v, s, e in merge(keep):
        keep_v[v].append((s, e))
    starts = {v: [k[0] for k in keep_v[v]] for v in keep_v}
    ends = {v: [k[1] for k in keep_v[v]] for v in keep_v}

    result = []
    for v, s, e in merge(block):
        lo = bisect_left(ends[v], s)
        hi = bisect_right(starts[v], e)
        pieces = [(s, e)]
        for idx in range(lo, hi):
            ks, ke = keep_v[v][idx]
            if not pieces:
                break
            nxt = []
            for ps, pe in pieces:
                if ke < ps or ks > pe:
                    nxt.append((ps, pe))
                    continue
                if ps < ks:
                    nxt.append((ps, ks - 1))
                if pe > ke:
                    nxt.append((ke + 1, pe))
            pieces = nxt
        for ps, pe in pieces:
            result.append((v, ps, pe))
    return merge(result)


def to_cidrs(version, start, end):
    """Minimal CIDR cover of an integer range."""
    bits = BITS[version]
    lines = []
    cur = start
    while cur <= end:
        size = 1
        while cur % (size << 1) == 0 and cur + (size << 1) - 1 <= end:
            size <<= 1
        lines.append("%s/%d" % (format_ip(version, cur), bits - (size.bit_length() - 1)))
        cur += size
    return lines


def format_ip(version, value):
    if version == 4:
        return "%d.%d.%d.%d" % ((value >> 24) & 255, (value >> 16) & 255,
                               (value >> 8) & 255, value & 255)
    groups = [(value >> (112 - 16 * i)) & 0xFFFF for i in range(8)]
    return ":".join("%x" % g for g in groups)


def ranges_to_lines(ranges):
    lines = []
    for v, s, e in ranges:
        lines.extend(to_cidrs(v, s, e))
    return lines


# ------------------------------------------------------------------ loaders
def read_cidr_file(name):
    ranges = []
    for line in read(name).splitlines():
        r = to_range(line)
        if r:
            ranges.append(r)
    return ranges


def read_asn(asn):
    """ASN prefix ranges: sources/asn_<AS>.txt (ipverse), else ripe_<AS>.json."""
    plain = read("asn_%s.txt" % asn)
    if plain:
        ranges = []
        for line in plain.splitlines():
            r = to_range(line)
            if r:
                ranges.append(r)
        return ranges
    raw = read("ripe_%s.json" % asn)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        print("warn: sources/ripe_%s.json invalid - skipped" % asn)
        return []
    ranges = []
    for entry in data.get("data", {}).get("prefixes", []):
        r = to_range(entry.get("prefix", ""))
        if r:
            ranges.append(r)
    return ranges


# ------------------------------------------------------------------ AWS
# Routing services that are preserved wherever AWS tags them: CDN and DNS.
AWS_PROTECT_ALL = ("CLOUDFRONT", "CLOUDFRONT_ORIGIN_FACING", "GLOBALACCELERATOR",
                   "ROUTE53", "ROUTE53_HEALTHCHECKS",
                   "ROUTE53_HEALTHCHECKS_PUBLISHING", "ROUTE53_RESOLVER")
# Application services preserved only where AWS tags them exclusively, i.e.
# where they do NOT overlap the compute space (S3, Route 53).
AWS_PROTECT_EXCLUSIVE = ("S3",)


def build_aws():
    """AWS compute space (EC2 + the legacy AMAZON service tag) and the
    routes that must stay reachable.

    AWS tags many prefixes with several services at once: a prefix can be
    EC2 *and* S3 at the same time. CDN and DNS routes are preserved
    wherever they appear, because they carry ordinary web and mail traffic.
    S3 is preserved only where AWS tags it exclusively - the overlapping
    prefixes are compute space and are blocked. Other AWS services
    (API Gateway, EBS, Workspaces gateways, instance connect, ...) are
    tunnelling-friendly and stay blocked.
    """
    raw = json.loads(read("aws_ip_ranges.json") or "{}")
    compute, protect_all, protect_excl = [], [], []
    for key in ("prefixes", "ipv6_prefixes"):
        for pfx in raw.get(key, []):
            token = pfx.get("ip_prefix") or pfx.get("ipv6_prefix") or ""
            r = to_range(token)
            if not r:
                continue
            service = (pfx.get("service") or "").upper()
            if service in ("EC2", "AMAZON"):
                compute.append(r)
            elif service in AWS_PROTECT_ALL:
                protect_all.append(r)
            elif service in AWS_PROTECT_EXCLUSIVE:
                protect_excl.append(r)
    keep = merge(protect_all + subtract(protect_excl, compute))
    return compute, keep


# ---------------------------------------------------------------- Azure
# Azure compute space (the "AzureCloud" service tag).
AZURE_BLOCK_PREFIX = ("AzureCloud",)

# Microsoft / enterprise application routes that live INSIDE the AzureCloud
# tag and must stay reachable: Entra ID (SSO), Microsoft 365 apps, Defender,
# Front Door. These are the service tags Microsoft publishes that identify
# common enterprise applications rather than tenant compute.
AZURE_KEEP_TAGS = (
    "AzureActiveDirectory",
    "AzureActiveDirectoryDomainServices",
    "AzureFrontDoor",
    "EOPExternalPublishedIPs",
    "SCCservice",
    "Scuba",
    "OneDsCollector",
    "GuestAndHybridManagement",
    "PowerBI",
    "PowerPlatformInfra",
    "PowerQueryOnline",
    "Dynamics365BusinessCentral",
    "Dynamics365ForMarketingEmail",
    "M365LighthouseProd",
    "M365ManagementActivityApi",
    "M365ManagementActivityApiWebhook",
    "Windows365",
    "SecurityCopilot",
    "MicrosoftDefenderForEndpoint",
    "MicrosoftCloudAppSecurity",
    "MicrosoftPurviewPolicyDistribution",
    "MicrosoftContainerRegistry",
    "MicrosoftAzureFluidRelay",
    "AzureDevOps",
    "AzureContainerRegistry",
)


def _tag_prefixes(tag):
    return tag.get("properties", {}).get("addressPrefixes", [])


def build_azure():
    """Azure compute ranges and Microsoft enterprise carve-outs."""
    block, keep = [], []
    raw = json.loads(read("microsoft_servicetags.json") or "{}")
    if raw.get("values"):
        for tag in raw["values"]:
            name = tag.get("name", "")
            target = None
            if name.startswith(AZURE_BLOCK_PREFIX):
                target = block
            elif any(name == t or name.startswith(t + ".") for t in AZURE_KEEP_TAGS):
                target = keep
            if target is None:
                continue
            for addr in _tag_prefixes(tag):
                r = to_range(addr)
                if r:
                    target.append(r)
        if block:
            return block, keep
    # fallback: the service-tag API (AzureCloud + Front Door only)
    for fname in sorted(os.listdir(SRC)):
        if not fname.startswith("azure_") or not fname.endswith(".json"):
            continue
        name = fname[len("azure_"):-len(".json")]
        target = None
        if name.startswith(AZURE_BLOCK_PREFIX):
            target = block
        elif name.startswith("AzureFrontDoor"):
            target = keep
        if target is None:
            continue
        payload = json.loads(read(fname) or "[]")
        for entry in payload:
            tag = entry.get("serviceTag", entry)
            for addr in tag.get("properties", {}).get("addressPrefixes", []):
                r = to_range(addr)
                if r:
                    target.append(r)
    return block, keep


def build_local_carveout():
    """Optional user-supplied carve-out (e.g. Microsoft 365 IP ranges)."""
    return read_cidr_file("microsoft365_preserve.txt")


# ------------------------------------------------------------------ GCP
def build_gcp():
    raw = json.loads(read("gcp_cloud.json") or "{}")
    ranges = []
    for pfx in raw.get("prefixes", []):
        r = to_range(pfx.get("ipv4Prefix") or pfx.get("ipv6Prefix") or "")
        if r:
            ranges.append(r)
    return ranges


def build_goog():
    raw = json.loads(read("gcp_goog.json") or "{}")
    ranges = []
    for pfx in raw.get("prefixes", []):
        r = to_range(pfx.get("ipv4Prefix") or pfx.get("ipv6Prefix") or "")
        if r:
            ranges.append(r)
    return ranges


# -------------------------------------------------------------- CDN keeps
def build_cdn_keeps():
    keep = []
    keep += read_cidr_file("cloudflare_ips_v4.txt")
    keep += read_cidr_file("cloudflare_ips_v6.txt")
    fastly = json.loads(read("fastly_ips.json") or "{}")
    addresses = fastly.get("addresses", []) if isinstance(fastly, dict) else fastly
    for addr in addresses:
        r = to_range(addr)
        if r:
            keep.append(r)
    keep += read_asn("AS20940")    # Akamai International (edge / CDN)
    keep += read_asn("AS36459")    # GitHub
    return keep


# ------------------------------------------------------- abused bulk hosts
ABUSED_ASNS = {
    "AS24940": "Hetzner Online",
    "AS200019": "Hetzner Online (2nd net)",
    "AS16276": "OVH SAS",
    "AS51167": "Contabo",
    "AS60781": "LeaseWeb",
    "AS36352": "ColoCrossing / HostPapa",
    "AS14061": "DigitalOcean",
    "AS20473": "Choopa / Vultr",
    "AS63949": "Linode (Akamai)",
    "AS31898": "Oracle Cloud Infrastructure",
    "AS31899": "Oracle Cloud Infrastructure",
    "AS45102": "Alibaba Cloud (intl)",
    "AS37963": "Alibaba Cloud (CN)",
    "AS45090": "Tencent Cloud",
    "AS132203": "Tencent Cloud",
    "AS9009": "M247",
    "AS60068": "Datacamp / CDN77",
    "AS212238": "Datacamp",
    "AS60558": "Psychz",
    "AS53667": "BuyVM / FranTech",
    "AS33655": "Scaleway",
}


def build_abused_vps():
    ranges = []
    for asn in ABUSED_ASNS:
        ranges += read_asn(asn)
    return ranges


# --------------------------------------------------------- malware / C2
def build_malware():
    ranges = []
    for name in ("firehol_level1.netset", "firehol_level2.netset",
                 "firehol_level3.netset", "firehol_level4.netset",
                 "firehol_webserver.netset", "et_compromised.txt",
                 "cins_badguys.txt", "blocklistde_all.txt", "blp_malware.ip",
                 "blp_abuse.ip", "feodo_ipblocklist.txt", "botvrij_ioc_dst.raw"):
        ranges += read_cidr_file(name)
    # Spamhaus DROP ships JSON Lines.
    for line in read("spamhaus_drop.json").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        cidr = obj.get("cidr") if isinstance(obj, dict) else obj
        r = to_range(cidr or "")
        if r:
            ranges.append(r)
    return ranges


def build_tor():
    ranges = []
    for line in read("tor_exit_addresses.txt").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("ExitAddress", "ExitNode"):
            r = to_range(parts[1])
            if r:
                ranges.append(r)
    return ranges


def build_proxies():
    return read_cidr_file("firehol_proxies.netset")


# ------------------------------------------------------------------ output
def write_list(name, ranges, title):
    lines = ranges_to_lines(ranges)
    path = out(name)
    with open(path, "w") as fh:
        for line in lines:
            fh.write(line + "\n")
    data = open(path, "rb").read()
    return {
        "file": name,
        "title": title,
        "entries": len(lines),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "ipv4": sum(1 for line in lines if ":" not in line),
        "ipv6": sum(1 for line in lines if ":" in line),
    }


def main():
    aws_raw, aws_keep = build_aws()
    az_raw, az_keep = build_azure()
    gcp_raw = build_gcp()
    goog_all = build_goog()
    cdn_keep = build_cdn_keeps()
    abused = build_abused_vps()
    malware = build_malware()
    tor = build_tor()
    proxies = build_proxies()

    # Microsoft ASN space (AS8075 ...) also carries the Azure compute space,
    # so the raw Azure space is removed from it: what is left is Office 365 /
    # Entra and other non-Azure Microsoft routes we want to keep reachable.
    microsoft_asn = []
    for asn in ("AS8075", "AS8068", "AS8069", "AS35908"):
        microsoft_asn += read_asn(asn)
    microsoft_keep = subtract(microsoft_asn, az_raw)

    # Google's published front-end list covers Google's WHOLE public space,
    # including the Google Cloud customer space, so only the part of it that
    # is NOT cloud space can be protected.
    goog_keep = subtract(goog_all, gcp_raw)

    # An optional locally supplied carve-out (Microsoft 365 IP ranges, your
    # own SaaS routes) is honoured as well: it is removed from the block
    # spaces and added to the preserve set.
    local_carveout = build_local_carveout()

    # The preserve set: CDN and enterprise routes that must stay reachable.
    preserve = merge(aws_keep + az_keep + goog_keep + cdn_keep + microsoft_keep
                     + local_carveout)

    # Every block space is the raw provider space minus the preserve set, so
    # a preserved route can never be blackholed by a cloud prefix.
    aws_ec2 = subtract(aws_raw, preserve)
    az_block = subtract(az_raw, preserve)
    gcp_block = subtract(gcp_raw, preserve)

    categories = [
        ("aws-ec2.txt", "AWS EC2 (compute) ranges", aws_ec2),
        ("azure-compute.txt", "Azure compute (AzureCloud) ranges", az_block),
        ("gcp-cloud.txt", "Google Cloud customer ranges", gcp_block),
        ("cloud-compute.txt", "Cloud compute (AWS EC2 + Azure + GCP)",
         aws_ec2 + az_block + gcp_block),
        ("commercial-vps-abused.txt",
         "Commonly abused commercial VPS / reseller ranges", abused),
        ("malware-c2-stalkerware.txt",
         "Malware, C2, stalkerware and known-bad routes", malware),
        ("tor-exit-nodes.txt", "Tor exit nodes", tor),
    ]

    stats = []
    for name, title, ranges in categories:
        stats.append(write_list(name, subtract(ranges, preserve), title))

    # proxies are ~2.6M prefixes: ship gzipped only
    proxy_ranges = subtract(proxies, preserve)
    gz_path = out("open-proxies.txt.gz")
    with gzip.open(gz_path, "wb", compresslevel=9) as fh:
        for line in ranges_to_lines(proxy_ranges):
            fh.write((line + "\n").encode())
    gz_data = open(gz_path, "rb").read()
    stats.append({
        "file": "open-proxies.txt.gz",
        "title": "Open proxies / anonymizers (gzip)",
        "entries": len(proxy_ranges),
        "bytes": len(gz_data),
        "sha256": hashlib.sha256(gz_data).hexdigest(),
    })

    stats.append(write_list("preserve-enterprise.txt", preserve,
                             "CDN / enterprise routes that must stay reachable"))

    default = subtract(malware + abused, preserve)
    stats.append(write_list("blocklist-default.txt", default,
                             "Default blocklist: malware/C2/stalkerware + abused bulk hosts"))
    egress = subtract(default + aws_ec2 + az_block + gcp_block + tor, preserve)
    stats.append(write_list("blocklist-egress.txt", egress,
                             "Egress-control list: everything above incl. cloud compute + Tor"))

    manifest = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "preserve_entries": len(preserve),
        "lists": stats,
    }
    with open(out("manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)

    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
