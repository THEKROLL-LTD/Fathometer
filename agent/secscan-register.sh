#!/usr/bin/env bash
#
# secscan-register.sh
# -------------------
# Registriert diesen Server beim secscan-Backend und erzeugt einen
# Server-API-Key. Master-Key kommt aus SECSCAN_MASTER_KEY env oder
# wird interaktiv (silent) abgefragt.
#
# Aufruf:
#   ./secscan-register.sh <server-url> <server-name> [scan-interval-h]
#
# Beispiele:
#   # Interaktiv:
#   ./secscan-register.sh https://secscan.example.com prod-web-01 24
#
#   # Nicht-interaktiv (z.B. in einem Provisioning-Skript):
#   SECSCAN_MASTER_KEY="$(cat /root/.secscan-master-key)" \
#     ./secscan-register.sh https://secscan.example.com prod-web-01 24 \
#     > /etc/secscan/api-key
#   chmod 600 /etc/secscan/api-key
#
# Druckt den generierten Server-Key auf stdout (sonst nichts), damit
# Pipelining sauber funktioniert. Diagnostische Meldungen gehen nach stderr.
#
# Achtung: Server-Keys werden NUR EINMAL ausgegeben. Wer den Key verliert,
# muss in der Web-UI rotieren. Das ist Absicht.
#
# Exit-Codes:
#   0  Erfolg
#   1  fehlende Voraussetzungen oder Argumente
#   2  HTTP-Fehler oder unerwartete Server-Antwort
#

set -euo pipefail

log() { printf '[secscan-register] %s\n' "$*" >&2; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 \
    || { log "Fehler: '$1' nicht im PATH gefunden"; exit 1; }
}
require_cmd curl
require_cmd jq

if [[ $# -lt 2 || $# -gt 3 ]]; then
  cat >&2 <<EOF
Aufruf: $0 <server-url> <server-name> [scan-interval-h]

  server-url        z.B. https://secscan.example.com
  server-name       eindeutiger Name (a-z, 0-9, ._- und Leerzeichen)
  scan-interval-h   erwartetes Scan-Intervall in Stunden (Default: 24)
EOF
  exit 1
fi

server_url="${1%/}"
server_name="$2"
interval_h="${3:-24}"

if [[ -z "${SECSCAN_MASTER_KEY:-}" ]]; then
  # silent read, Eingabe erscheint nicht in der Shell-History
  read -srp "Master-Key: " SECSCAN_MASTER_KEY
  echo >&2
fi

if [[ -z "$SECSCAN_MASTER_KEY" ]]; then
  log "Fehler: Master-Key ist leer"
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
  -o "$response_body" -w '%{http_code}' \
  -X POST "${server_url}/api/register" \
  -H "Content-Type: application/json" \
  --data-binary "$request" || echo "000")"

if [[ "$http_status" != "200" && "$http_status" != "201" ]]; then
  log "Fehler: Registrierung fehlgeschlagen (HTTP ${http_status})"
  log "Server-Response:"
  cat "$response_body" >&2 || true
  exit 2
fi

api_key="$(jq -r '.api_key // empty' < "$response_body")"
server_id="$(jq -r '.server_id // empty' < "$response_body")"

if [[ -z "$api_key" ]]; then
  log "Fehler: Server-Antwort enthält keinen api_key"
  cat "$response_body" >&2
  exit 2
fi

log "Server registriert (id=${server_id}, name=${server_name})"
log "Server-Key wird auf stdout gedruckt — speichern und mit chmod 600 schützen."
printf '%s\n' "$api_key"
