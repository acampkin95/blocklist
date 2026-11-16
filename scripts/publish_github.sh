#!/usr/bin/env bash
# publish_github.sh - publish the generated lists and scripts to GitHub.
#
# Uses the GitHub Git Data API (blobs -> tree -> commit -> ref) so that a
# whole refresh lands as ONE commit. curl is used for every request because
# git/gh cannot open outbound sockets on some hardened machines.
#
# Usage:
#   scripts/publish_github.sh [owner/repo] [branch]
# Env: GH_TOKEN (or a working 'gh auth token')

set -uo pipefail

OWNER_REPO="${1:-acampkin95/blocklist}"
BRANCH="${2:-main}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API="https://api.github.com/repos/$OWNER_REPO"

TOKEN="${GH_TOKEN:-}"
if [ -z "$TOKEN" ]; then
  TOKEN="$(gh auth token 2>/dev/null)"
fi
if [ -z "$TOKEN" ]; then
  echo "no token: set GH_TOKEN or install gh and run 'gh auth login'" >&2
  exit 1
fi

AUTH=(-H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.github+json")

# Files to publish: "<repo path>|<local path>"
FILES=(
  "lists/aws-ec2.txt|lists/aws-ec2.txt"
  "lists/azure-compute.txt|lists/azure-compute.txt"
  "lists/gcp-cloud.txt|lists/gcp-cloud.txt"
  "lists/cloud-compute.txt|lists/cloud-compute.txt"
  "lists/commercial-vps-abused.txt|lists/commercial-vps-abused.txt"
  "lists/malware-c2-stalkerware.txt|lists/malware-c2-stalkerware.txt"
  "lists/tor-exit-nodes.txt|lists/tor-exit-nodes.txt"
  "lists/open-proxies.txt.gz|lists/open-proxies.txt.gz"
  "lists/preserve-enterprise.txt|lists/preserve-enterprise.txt"
  "lists/blocklist-default.txt|lists/blocklist-default.txt"
  "lists/blocklist-egress.txt|lists/blocklist-egress.txt"
  "lists/manifest.json|lists/manifest.json"
  "scripts/fetch_sources.sh|scripts/fetch_sources.sh"
  "scripts/build_blocklists.py|scripts/build_blocklists.py"
  "scripts/verify_blocklists.py|scripts/verify_blocklists.py"
  "scripts/publish_github.sh|scripts/publish_github.sh"
  ".github/workflows/update-blocklists.yml|.github/workflows/update-blocklists.yml"
  "README.md|README_GITHUB.md"
)

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

jget() { python3 -c "import json,sys;d=json.load(sys.stdin);print(d$1)"; }

HEAD_SHA=$(curl -s "${AUTH[@]}" "$API/git/ref/heads/$BRANCH" | jget '["object"]["sha"]')
BASE_TREE=$(curl -s "${AUTH[@]}" "$API/git/commits/$HEAD_SHA" | jget '["tree"]["sha"]')
echo "head=$HEAD_SHA base_tree=$BASE_TREE"

ENTRIES=""
for pair in "${FILES[@]}"; do
  repo_path="${pair%%|*}"
  local_path="$ROOT/${pair#*|}"
  [ -f "$local_path" ] || { echo "skip (missing): $repo_path" >&2; continue; }
  b64="$TMP/b.b64"
  base64 < "$local_path" | tr -d '\n' > "$b64"
  body="$TMP/blob.json"
  printf '{"content":"' > "$body"
  cat "$b64" >> "$body"
  printf '","encoding":"base64"}' >> "$body"
  blob_sha=$(curl -s -X POST "${AUTH[@]}" "$API/git/blobs" --data-binary "@$body" | jget '["sha"]')
  [ -n "$blob_sha" ] || { echo "blob failed: $repo_path" >&2; exit 1; }
  ENTRIES="$ENTRIES{\"path\":\"$repo_path\",\"mode\":\"100644\",\"type\":\"blob\",\"sha\":\"$blob_sha\"},"
  echo "  staged $repo_path -> $blob_sha"
done

ENTRIES="${ENTRIES%,}"
tree_body="$TMP/tree.json"
printf '{"base_tree":"%s","tree":[%s]}' "$BASE_TREE" "$ENTRIES" > "$tree_body"
TREE_SHA=$(curl -s -X POST "${AUTH[@]}" "$API/git/trees" --data-binary "@$tree_body" | jget '["sha"]')
[ -n "$TREE_SHA" ] || { echo "tree failed" >&2; exit 1; }

MSG="chore: refresh blocklists $(date -u +%Y-%m-%dT%H:%M:%SZ)"
commit_body="$TMP/commit.json"
python3 - "$TREE_SHA" "$HEAD_SHA" "$MSG" > "$commit_body" <<'PY'
import json, sys
tree, parent, msg = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({"message": msg, "tree": tree, "parents": [parent]}))
PY
COMMIT_SHA=$(curl -s -X POST "${AUTH[@]}" "$API/git/commits" --data-binary "@$commit_body" | jget '["sha"]')
[ -n "$COMMIT_SHA" ] || { echo "commit failed" >&2; exit 1; }

ref_body="$TMP/ref.json"
printf '{"sha":"%s","force":false}' "$COMMIT_SHA" > "$ref_body"
curl -s -X PATCH "${AUTH[@]}" "$API/git/refs/heads/$BRANCH" --data-binary "@$ref_body" > /dev/null
echo "published commit $COMMIT_SHA to $OWNER_REPO@$BRANCH"
