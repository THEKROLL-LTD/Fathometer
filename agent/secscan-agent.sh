#!/usr/bin/env bash
#
# secscan-agent.sh
# ----------------
# Sammelt OS-/Kernel-Info, läuft `trivy rootfs /` und sendet das Resultat
# als Wrapper-Envelope an einen secscan-Server.
#
# Subcommand-Wahl: `rootfs` (NICHT `fs`). Begruendung:
#   - `trivy fs <dir>` ist fuer Source-Repos/vendored Deps gedacht und
#     scannt auf einem Live-System nur die OS-Package-DB (apt/dpkg) —
#     Go-Binaries unter /usr/local/bin, /var/lib/rancher etc. werden
#     uebersprungen. Auf einem k3s-Node hiessen das praktisch alle
#     HIGH/CRITICAL aus den Cluster-Komponenten fehlen.
#   - `trivy rootfs <dir>` ist explizit fuer Live-Root-Filesystems und
#     fuehrt zusaetzlich `gobinary`/`jar`/etc-Analyzer aus.
# Siehe https://trivy.dev/docs/v0.70/coverage/others/standalone/
#
# Voraussetzungen: bash >= 4, curl, jq, gzip, trivy (>= 0.70.0)
#                  (https://aquasecurity.github.io/trivy/)
#
# Pflicht-ENV:
#   SECSCAN_URL       z.B. https://secscan.example.com
#   SECSCAN_API_KEY   Server-Key, der per ./secscan-register.sh erzeugt wurde
#
# Optional ENV:
#   SECSCAN_TRIVY_PATH    Pfad zur Trivy-Binary (Default: aus $PATH)
#   SECSCAN_SCAN_PATH     Was gescannt wird (Default: /)
#   SECSCAN_TIMEOUT_SEC   Upload-Timeout (Default: 60)
#
# Aufruf als root, typisch via cron oder systemd-Timer.
#
# Exit-Codes:
#   0  Erfolg
#   1  fehlende Voraussetzungen oder Konfiguration
#   2  Trivy-Scan fehlgeschlagen
#   3  Upload fehlgeschlagen
#

set -euo pipefail

readonly AGENT_VERSION="0.1.0"
readonly TRIVY_BIN="${SECSCAN_TRIVY_PATH:-trivy}"
readonly SCAN_PATH="${SECSCAN_SCAN_PATH:-/}"
readonly TIMEOUT_SEC="${SECSCAN_TIMEOUT_SEC:-60}"

log() { printf '[secscan-agent] %s\n' "$*" >&2; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 \
    || { log "Fehler: '$1' nicht im PATH gefunden"; exit 1; }
}

# ----- Voraussetzungen ---------------------------------------------------
require_cmd curl
require_cmd jq
require_cmd gzip
require_cmd "$TRIVY_BIN"

: "${SECSCAN_URL:?SECSCAN_URL ist nicht gesetzt}"
: "${SECSCAN_API_KEY:?SECSCAN_API_KEY ist nicht gesetzt}"

# ----- Host-Info sammeln -------------------------------------------------
if [[ -r /etc/os-release ]]; then
  # /etc/os-release ist von freedesktop.org standardisiert (ID, VERSION_ID, …)
  # shellcheck disable=SC1091
  . /etc/os-release
  os_family="${ID:-unknown}"
  os_version="${VERSION_ID:-unknown}"
  os_pretty="${PRETTY_NAME:-${NAME:-unknown}}"
else
  # Non-Linux (z.B. macOS, FreeBSD): kein /etc/os-release. Wir mappen
  # `uname -s` auf eine sinnvolle os_family.
  uname_s="$(uname -s)"
  case "$uname_s" in
    Darwin)      os_family="darwin" ;;
    FreeBSD)     os_family="freebsd" ;;
    OpenBSD)     os_family="openbsd" ;;
    NetBSD)      os_family="netbsd" ;;
    *)           os_family="$(printf '%s' "$uname_s" | tr '[:upper:]' '[:lower:]')" ;;
  esac
  os_version="$(uname -r)"
  if [[ "$uname_s" == "Darwin" ]] && command -v sw_vers >/dev/null 2>&1; then
    os_pretty="macOS $(sw_vers -productVersion 2>/dev/null) ($uname_s $os_version)"
  else
    os_pretty="$uname_s $os_version"
  fi
fi
kernel_version="$(uname -r)"
arch="$(uname -m)"
# Backend normalisiert `arm64`/`amd64`/`x86`/`i386` automatisch zu den
# Linux-Canonical-Formen; keine Client-seitige Normalisierung noetig.

log "Host: ${os_pretty} (kernel ${kernel_version}, ${arch})"

# ----- Trivy-Scan --------------------------------------------------------
trivy_out="$(mktemp -t secscan-trivy.XXXXXX.json)"
trap 'rm -f "$trivy_out"' EXIT

log "Starte Trivy-Scan auf ${SCAN_PATH} ..."
if ! "$TRIVY_BIN" rootfs "$SCAN_PATH" \
       --format json \
       --quiet \
       --scanners vuln \
       --output "$trivy_out"; then
  log "Fehler: Trivy-Scan fehlgeschlagen"
  exit 2
fi

# Trivy schreibt selbst bei "keine Findings" valides JSON. Falls die Datei
# leer ist, ist etwas grob schiefgelaufen.
if [[ ! -s "$trivy_out" ]]; then
  log "Fehler: Trivy-Output ist leer"
  exit 2
fi

# ----- Envelope bauen ----------------------------------------------------
payload="$(jq -n \
  --arg agent_version "$AGENT_VERSION" \
  --arg os_family     "$os_family" \
  --arg os_version    "$os_version" \
  --arg os_pretty     "$os_pretty" \
  --arg kernel        "$kernel_version" \
  --arg arch          "$arch" \
  --slurpfile scan    "$trivy_out" \
  '{
    agent_version: $agent_version,
    host: {
      os_family:      $os_family,
      os_version:     $os_version,
      os_pretty_name: $os_pretty,
      kernel_version: $kernel,
      architecture:   $arch
    },
    scan: $scan[0]
  }')"

# ----- Senden (gzipped) --------------------------------------------------
# Komprimiert typisch 8-10x. Server akzeptiert Content-Encoding: gzip
# und dekomprimiert mit Streaming-Limit (siehe ARCHITECTURE.md, Sektion 9).
response_body="$(mktemp -t secscan-resp.XXXXXX)"
trap 'rm -f "$trivy_out" "$response_body"' EXIT

http_status="$(printf '%s' "$payload" | gzip -c | curl -sS \
  --max-time "$TIMEOUT_SEC" \
  -o "$response_body" -w '%{http_code}' \
  -X POST "${SECSCAN_URL%/}/api/scans" \
  -H "Authorization: Bearer ${SECSCAN_API_KEY}" \
  -H "Content-Type: application/json" \
  -H "Content-Encoding: gzip" \
  --data-binary @- || echo "000")"

if [[ "$http_status" != "200" && "$http_status" != "202" ]]; then
  log "Fehler: Upload fehlgeschlagen (HTTP ${http_status})"
  log "Server-Response:"
  cat "$response_body" >&2 || true
  exit 3
fi

log "Scan erfolgreich übertragen (HTTP ${http_status})"
