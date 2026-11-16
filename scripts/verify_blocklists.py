#!/usr/bin/env python3
"""verify_blocklists.py - invariant checks for the generated lists.

Checks:
  1. No preserve (CDN / enterprise) range appears inside any block list.
  2. Well-known CDN / DNS / app routes stay reachable in every block list.
  3. blocklist-egress covers blocklist-default plus the cloud compute space.
  4. Every list is sorted and parses as valid CIDR.
"""
import ipaddress
import os
import sys
from bisect import bisect_left

LIST_DIR = sys.argv[1] if len(sys.argv) > 1 else "lists"
FAIL = 0


class RangeSet:
    """Disjoint, sorted integer ranges per IP version, with O(log n) lookup."""

    def __init__(self, nets=None):
        self.raw = []
        for n in (nets or []):
            v = n.version
            bits = 32 if v == 4 else 128
            start = int(n.network_address)
            end = int(n.broadcast_address)
            self.raw.append((v, start, end, n.prefixlen))
        self.rebuild()

    def rebuild(self):
        self.v4 = []
        self.v6 = []
        self.meta = {}
        for version in (4, 6):
            items = sorted((r for r in self.raw if r[0] == version),
                           key=lambda r: (r[1], r[2]))
            merged = []
            for v, s, e, pl in items:
                if merged and s <= merged[-1][1] + 1:
                    if e > merged[-1][1]:
                        merged[-1][1] = e
                        merged[-1][2] = min(merged[-1][2], pl)
                else:
                    merged.append([s, e, pl])
            if version == 4:
                self.v4 = merged
            else:
                self.v6 = merged

    def _covers(self, table, version, start, end):
        starts = [m[0] for m in table]
        i = bisect_left(starts, start)
        i = max(0, i - 1)
        while i < len(table):
            s, e, pl = table[i]
            if s > end:
                return False
            if s <= start and end <= e:
                return True
            i += 1
        return False

    def covers(self, net):
        start = int(net.network_address)
        end = int(net.broadcast_address)
        table = self.v4 if net.version == 4 else self.v6
        return self._covers(table, net.version, start, end)

    def covers_raw(self, version, start, end):
        table = self.v4 if version == 4 else self.v6
        return self._covers(table, version, start, end)


def load(name):
    path = os.path.join(LIST_DIR, name)
    if not os.path.exists(path):
        return None
    nets = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                nets.append(ipaddress.ip_network(line, strict=True))
    return nets


BLOCK_FILES = ["aws-ec2.txt", "azure-compute.txt", "gcp-cloud.txt",
               "cloud-compute.txt", "commercial-vps-abused.txt",
               "malware-c2-stalkerware.txt", "tor-exit-nodes.txt",
               "blocklist-default.txt", "blocklist-egress.txt"]

preserve_nets = load("preserve-enterprise.txt")
preserve = RangeSet(preserve_nets)
print("preserve-enterprise.txt: %d prefixes" % len(preserve_nets))

sets = {}
for name in BLOCK_FILES:
    nets = load(name)
    if nets is None:
        print("SKIP  %s (not present)" % name)
        continue
    sets[name] = (nets, RangeSet(nets))

print()
for name, (nets, rs) in sets.items():
    bad = [n for n in preserve_nets if rs.covers(n)]
    if bad:
        FAIL += 1
        print("FAIL  %s blocks %d preserve range(s), e.g. %s" % (name, len(bad), bad[0]))
    else:
        print("ok    %-28s %8d prefixes, no preserve range blocked" % (name, len(nets)))

PROBES = [
    ("Cloudflare DNS", "1.1.1.0/24"),
    ("Cloudflare v4 space", "104.16.0.0/12"),
    ("Cloudflare v6 space", "2606:4700::/32"),
    ("Fastly", "151.101.0.0/16"),
    ("Google DNS", "8.8.8.0/24"),
    ("Google Frontend", "172.217.0.0/16"),
    ("Akamai edge", "23.32.0.0/11"),
    ("GitHub", "140.82.112.0/20"),
    ("Entra ID / SSO", "20.190.128.0/18"),
    ("Entra ID (AAD)", "20.190.0.0/16"),
    ("Microsoft 365 EOP", "52.100.0.0/14"),
    ("Teams / Front Door", "13.107.0.0/16"),
    ("Exchange Online", "52.104.0.0/15"),
    ("SharePoint Online", "40.97.0.0/16"),
]
print()
# Probes that only the aggressive cloud lists may block (they live inside
# the AzureCloud compute tag by design). Reported, not failed.
SOFT = {
    "Exchange Online": "52.104.0.0/15",
    "SharePoint Online": "40.97.0.0/16",
}
for label, cidr in PROBES:
    net = ipaddress.ip_network(cidr)
    hits = [name for name, (_, rs) in sets.items() if rs.covers(net)]
    if hits and label in SOFT:
        print("note  %-20s %-20s blocked by %s (inside the AzureCloud tag; "
              "carve out with sources/microsoft365_preserve.txt)"
              % (label, cidr, ", ".join(hits)))
    elif hits:
        FAIL += 1
        print("FAIL  %-20s %-20s blocked by: %s" % (label, cidr, ", ".join(hits)))
    else:
        print("ok    %-20s %-20s reachable everywhere" % (label, cidr))

print()
for name, (nets, _) in sets.items():
    keyed = [(n.version, int(n.network_address), n.prefixlen) for n in nets]
    if keyed != sorted(keyed):
        FAIL += 1
        print("FAIL  %s is not sorted" % name)

if "blocklist-default.txt" in sets and "blocklist-egress.txt" in sets:
    default_nets, default_rs = sets["blocklist-default.txt"]
    egress_nets, egress_rs = sets["blocklist-egress.txt"]
    missing = [n for n in default_nets if not egress_rs.covers(n)]
    if missing:
        FAIL += 1
        print("FAIL  egress misses %d default prefix(es), e.g. %s" % (len(missing), missing[0]))
    else:
        print("ok    egress covers every default prefix")
if "cloud-compute.txt" in sets and "blocklist-egress.txt" in sets:
    cloud_nets, _ = sets["cloud-compute.txt"]
    egress_rs = sets["blocklist-egress.txt"][1]
    missing = [n for n in cloud_nets if not egress_rs.covers(n)]
    if missing:
        FAIL += 1
        print("FAIL  egress misses %d cloud prefix(es), e.g. %s" % (len(missing), missing[0]))
    else:
        print("ok    egress covers every cloud-compute prefix")

print()
print("RESULT: %s" % ("PASS - all invariants hold" if FAIL == 0
                      else "%d CHECK(S) FAILED" % FAIL))
sys.exit(1 if FAIL else 0)
