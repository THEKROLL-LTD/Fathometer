#!/usr/bin/env bash
#
# secscan-register.sh
# -------------------
# Registers this server with the secscan backend and produces a server
# API key. The master key comes from the SECSCAN_MASTER_KEY env var or
# is read interactively (silent).
#
# Usage:
#   ./secscan-register.sh <server-url> <server-name> [scan-interval-h]
#
# Examples:
#   # Interactive:
#   ./secscan-register.sh https://secscan.example.com prod-web-01 24
#
#   # Non-interactive (e.g. in a provisioning script):
#   SECSCAN_MASTER_KEY="$(cat /root/.secscan-master-key)" \
#     ./secscan-register.sh https://secscan.example.com prod-web-01 24 \
#     > /etc/secscan/api-key
#   chmod 600 /etc/secscan/api-key
#
# Block N (ADR-0021): the preferred way to set up a fresh host is the
# bootstrap installer one-liner:
#
#   curl -fsSL https://secscan.example.com/install.sh | sudo bash
#
# That wizard runs this script internally after fetching it from the
# backend. Use this script directly only when you want fine-grained
# control or are scripting your own provisioning.
#
# Prints the generated server key to stdout (nothing else), so piping
# works cleanly. Diagnostic messages go to stderr.
#
# Caution: server keys are printed ONCE. Whoever loses the key has to
# rotate it via the web UI. This is intentional.
#
# Exit codes:
#   0  success
#   1  missing requirements or arguments
#   2  HTTP error or unexpected server response
#

set -euo pipefail

log() { printf '[secscan-register] %s\n' "$*" >&2; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 \
    || { log "Error: '$1' not found in PATH"; exit 1; }
}
require_cmd curl
require_cmd jq

if [[ $# -lt 2 || $# -gt 3 ]]; then
  cat >&2 <<EOF
Usage: $0 <server-url> <server-name> [scan-interval-h]

  server-url        e.g. https://secscan.example.com
  server-name       unique name (a-z, 0-9, ._- and spaces)
  scan-interval-h   expected scan interval in hours (default: 24)

Tip: for fresh hosts, prefer the bootstrap installer:
  curl -fsSL <server-url>/install.sh | sudo bash
EOF
  exit 1
fi

server_url="${1%/}"
server_name="$2"
interval_h="${3:-24}"

if [[ -z "${SECSCAN_MASTER_KEY:-}" ]]; then
  # silent read — input does not show up in the shell history
  read -srp "Master key: " SECSCAN_MASTER_KEY
  echo >&2
fi

if [[ -z "$SECSCAN_MASTER_KEY" ]]; then
  log "Error: master key is empty"
  exit 1
fi

request="$(jq -n \
  --arg master_key "$SECSCAN_MASTER_KEY" \
  --arg name       "$server_name" \
  --argjson interval "$interval_h" \
  '{
    master_key: $master_key,
    name: $name,
    expected_scan_interval_h: $interval
  }')"

response_body="$(mktemp -t secscan-reg.XXXXXX)"
trap 'rm -f "$response_body"' EXIT

http_status="$(curl -sS \
  --max-time 30 \
  --post301 --post302 --post303 -L \
  -o "$response_body" -w '%{http_code}' \
  -X POST "${server_url}/api/register" \
  -H "Content-Type: application/json" \
  --data-binary "$request" || echo "000")"

if [[ "$http_status" != "200" && "$http_status" != "201" ]]; then
  log "Error: registration failed (HTTP ${http_status})"
  log "Server response:"
  cat "$response_body" >&2 || true
  exit 2
fi

api_key="$(jq -r '.api_key // empty' < "$response_body")"
server_id="$(jq -r '.server_id // empty' < "$response_body")"

if [[ -z "$api_key" ]]; then
  log "Error: server response does not contain api_key"
  cat "$response_body" >&2
  exit 2
fi

log "Server registered (id=${server_id}, name=${server_name})"
log "Server key printed to stdout — store it and protect it with chmod 600."
printf '%s\n' "$api_key"
