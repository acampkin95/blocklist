#!/usr/bin/env bash
# fetch_sources.sh - download every upstream feed used by build_blocklists.py
#
# Only curl is used for network I/O on purpose: on some hardened machines
# (including this one) git/gh/node cannot open outbound sockets while curl
# can, so the whole pipeline is driven through curl.
#
# Usage: scripts/fetch_sources.sh [output_dir]   (default: sources/)

set -uo pipefail

OUT="${1:-sources}"
mkdir -p "$OUT"

UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

# portable sha256 (macOS has shasum, Linux has sha256sum)
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}
FETCHED="$OUT/FETCHED.txt"
: > "$FETCHED"

# fetch <local-name> <url> [url-fallback...]
fetch() {
  local name="$1"; shift
  local url
  for url in "$@"; do
    local tmp="$OUT/.$name.tmp"
    local code
    code=$(curl -sSL --max-time 300 --connect-timeout 20 --retry 4 --retry-all-errors \
            --retry-delay 3 -A "$UA" -o "$tmp" -w '%{http_code}' "$url")
    if [ "$code" = "200" ] && [ -s "$tmp" ]; then
      mv "$tmp" "$OUT/$name"
      local bytes sum
      bytes=$(wc -c < "$OUT/$name" | tr -d ' ')
      sum=$(sha256_of "$OUT/$name")
      printf '%s\t%s\t%s\t%s\n' "$name" "$bytes" "$sum" "$url" >> "$FETCHED"
      echo "[ok]   $name  ($bytes bytes)  <- $url"
      return 0
    fi
    rm -f "$tmp"
    echo "[warn] $name failed at $url (http $code)" >&2
  done
  echo "[FAIL] $name - no source succeeded" >&2
  return 1
}

# ------------------------------------------------------- ASN prefix ranges
# Primary source: ipverse/as-ip-blocks (aggregated prefixes per ASN, on GitHub).
# Fallback: RIPEstat announced-prefixes. Both can be unreachable from time to
# time on restricted networks, so each ASN is tried against both.
fetch_asn() {
  local asn="$1"
  local num="${asn#AS}"
  local outfile="$OUT/asn_$asn.txt"
  local tmp="$OUT/.asn_$asn.tmp"
  local code

  # 1) ipverse/as-ip-blocks
  local v4url="https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as/$num/ipv4-aggregated.txt"
  local v6url="https://raw.githubusercontent.com/ipverse/as-ip-blocks/master/as/$num/ipv6-aggregated.txt"
  code=$(curl -sSL --max-time 60 --connect-timeout 15 --retry 2 --retry-all-errors \
          -A "$UA" -o "$tmp.v4" -w '%{http_code}' "$v4url")
  if [ "$code" = "200" ] && [ -s "$tmp.v4" ]; then
    cp "$tmp.v4" "$tmp"
    curl -sSL --max-time 60 --connect-timeout 15 --retry 2 --retry-all-errors \
         -A "$UA" -o "$tmp.v6" -w '%{http_code}' "$v6url" >/dev/null 2>&1 || true
    if [ -s "$tmp.v6" ]; then cat "$tmp.v6" >> "$tmp"; fi
    mv "$tmp" "$outfile"
    rm -f "$tmp.v4" "$tmp.v6"
    local bytes sum
    bytes=$(wc -c < "$outfile" | tr -d ' ')
    sum=$(sha256_of "$outfile")
    printf 'asn_%s.txt\t%s\t%s\tipverse as-ip-blocks AS%s\n' "$asn" "$bytes" "$sum" "$asn" >> "$FETCHED"
    echo "[ok]   asn_$asn.txt  ($bytes bytes)  <- ipverse"
    return 0
  fi
  rm -f "$tmp.v4" "$tmp.v6"

  # 2) RIPEstat fallback
  for attempt in 1 2 3 4 5 6; do
    code=$(curl -sSL --max-time 120 --connect-timeout 15 -A "$UA" \
            -o "$tmp.json" -w '%{http_code}' \
            "https://stat.ripe.net/data/announced-prefixes/data.json?resource=$asn")
    if [ "$code" = "200" ] && [ -s "$tmp.json" ] && \
       python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$tmp.json" 2>/dev/null; then
      python3 - "$tmp.json" > "$tmp" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
for entry in data.get("data", {}).get("prefixes", []):
    print(entry.get("prefix", ""))
PY
      mv "$tmp" "$outfile"
      rm -f "$tmp.json"
      local bytes sum
      bytes=$(wc -c < "$outfile" | tr -d ' ')
      sum=$(sha256_of "$outfile")
      printf 'asn_%s.txt\t%s\t%s\tRIPEstat announced-prefixes %s\n' "$asn" "$bytes" "$sum" "$asn" >> "$FETCHED"
      echo "[ok]   asn_$asn.txt  ($bytes bytes)  <- RIPEstat"
      return 0
    fi
    rm -f "$tmp.json"
    sleep 3
  done
  rm -f "$tmp"
  echo "[warn] asn_$asn.txt - no ASN source succeeded" >&2
  return 1
}

# ---------------------------------------------------------------- provider ranges
fetch aws_ip_ranges.json      "https://ip-ranges.amazonaws.com/ip-ranges.json"
fetch gcp_cloud.json          "https://www.gstatic.com/ipranges/cloud.json"
fetch gcp_goog.json           "https://www.gstatic.com/ipranges/goog.json" \
                             "https://www.gstatic.com/ipranges/google.json"

# Azure / Microsoft service tags.
#
# Preferred: the full ServiceTags_Public file (it carries the AzureCloud
# compute tag AND the Microsoft 365 / Entra tags the public API does not
# expose). Served by the official Azure Service Tags site, and mirrored by
# jensihnow/AzurePublicIPAddressRanges.
fetch microsoft_servicetags.json \
  "https://raw.githubusercontent.com/jensihnow/AzurePublicIPAddressRanges/master/ServiceTags_Public.json" \
  "https://azservicetags.azurewebsites.net/api/ServiceTag/AzureCloud?cloudId=Public"

# Official service-tag API (works when the file above is unavailable).
for tag in AzureCloud AzureFrontDoor.Backend AzureFrontDoor.Frontend; do
  fetch "azure_${tag}.json" \
        "https://azservicetags.azurewebsites.net/api/ServiceTag/${tag}?cloudId=Public"
done

# Optional: drop your own Microsoft 365 / enterprise carve-out list here and
# it will be subtracted from the Azure block set.
#   sources/microsoft365_preserve.txt

# ------------------------------------------------------- CDN / enterprise (keep)
fetch cloudflare_ips_v4.txt   "https://www.cloudflare.com/ips-v4"
fetch cloudflare_ips_v6.txt   "https://www.cloudflare.com/ips-v6"
fetch fastly_ips.json         "https://api.fastly.com/public-ip-list"

# ------------------------------------------------- malware / C2 / stalkerware
fetch firehol_level1.netset   "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
fetch firehol_level2.netset   "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset"
fetch firehol_level3.netset   "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset"
fetch firehol_level4.netset   "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level4.netset"
fetch firehol_webserver.netset "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_webserver.netset"
fetch spamhaus_drop.json      "https://www.spamhaus.org/drop/drop_v4.json"
fetch et_compromised.txt      "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
fetch cins_badguys.txt        "https://cinsscore.com/list/ci-badguys.txt"
fetch blocklistde_all.txt     "https://lists.blocklist.de/lists/all.txt"
fetch blp_malware.ip          "https://raw.githubusercontent.com/blocklistproject/Lists/main/malware.ip"
fetch blp_abuse.ip            "https://raw.githubusercontent.com/blocklistproject/Lists/main/abuse.ip"
fetch feodo_ipblocklist.txt   "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
fetch botvrij_ioc_dst.raw     "http://www.botvrij.eu/data/ioclist.ip-dst.raw"

# ------------------------------------------------------ anonymous / proxy nets
fetch tor_exit_addresses.txt  "https://check.torproject.org/exit-addresses"
fetch firehol_proxies.netset  "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_proxies.netset"

# ------------------------------------------------------------------ ASN ranges
# CDN / enterprise routes that must stay reachable.
fetch_asn AS20940   # Akamai International (edge / CDN)
fetch_asn AS36459   # GitHub
# Microsoft app routes (Office 365 / Entra / corporate). AS8075 also carries the
# Azure compute space - build_blocklists.py subtracts AzureCloud from it.
fetch_asn AS8075
fetch_asn AS8068
fetch_asn AS8069
fetch_asn AS35908
# Commonly abused bulk-host networks (cheap VPS, reseller, cloud telco).
for asn in AS24940 AS200019 AS16276 AS51167 AS60781 AS36352 AS14061 AS20473 \
           AS63949 AS31898 AS31899 AS45102 AS37963 AS45090 AS132203 AS9009 \
           AS60068 AS212238 AS60558 AS53667 AS33655; do
  fetch_asn "$asn"
done

echo
echo "sources written to $OUT (manifest: $FETCHED)"
