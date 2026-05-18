#!/usr/bin/env bash
#
# secscan-agent.sh
# ----------------
# Collects OS/kernel info, runs `trivy rootfs /` and uploads the result
# as a wrapper envelope to a secscan backend.
#
# Subcommand: `rootfs` (NOT `fs`). Rationale:
#   - `trivy fs <dir>` is meant for source repos / vendored deps and on a
#     live system only inspects the OS package DB (apt/dpkg) — Go binaries
#     under /usr/local/bin, /var/lib/rancher etc. are skipped. On a k3s
#     node that effectively misses every HIGH/CRITICAL from the cluster
#     components.
#   - `trivy rootfs <dir>` is explicitly for live root filesystems and
#     additionally runs the gobinary/jar/etc analyzers.
# See https://trivy.dev/docs/v0.70/coverage/others/standalone/
#
# Block N (ADR-0021) — v0.2.0 changes:
#   - `host.trivy_version` is collected from `trivy --version` and added
#     to the envelope. Optional in the backend schema (older backends
#     ignore it via `extra="ignore"`).
#   - `Results[].Packages` is stripped via `jq` before the upload to
#     reduce bandwidth by 80-90% (the inventory block is unused by the
#     backend). Falls back to the raw output if `jq` cannot apply the
#     filter — backend handles both shapes identically.
#
# Requirements: bash >= 4, curl, jq, gzip, trivy (>= 0.70.0)
#               (https://aquasecurity.github.io/trivy/)
#
# Required env:
#   SECSCAN_URL       e.g. https://secscan.example.com
#   SECSCAN_API_KEY   server key produced by ./secscan-register.sh
#
# Optional env:
#   SECSCAN_TRIVY_PATH    path to the trivy binary (default: from $PATH)
#   SECSCAN_SCAN_PATH     what to scan (default: /)
#   SECSCAN_TIMEOUT_SEC   upload timeout (default: 60)
#
# Run as root, typically via cron or a systemd timer.
#
# Exit codes:
#   0  success
#   1  missing requirements or configuration
#   2  trivy scan failed
#   3  upload failed
#

set -euo pipefail

readonly AGENT_VERSION="0.2.0"
readonly TRIVY_BIN="${SECSCAN_TRIVY_PATH:-trivy}"
readonly SCAN_PATH="${SECSCAN_SCAN_PATH:-/}"
readonly TIMEOUT_SEC="${SECSCAN_TIMEOUT_SEC:-60}"

log() { printf '[secscan-agent] %s\n' "$*" >&2; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 \
    || { log "Error: '$1' not found in PATH"; exit 1; }
}

# ----- Prerequisites -----------------------------------------------------
require_cmd curl
require_cmd jq
require_cmd gzip
require_cmd "$TRIVY_BIN"

: "${SECSCAN_URL:?SECSCAN_URL is not set}"
: "${SECSCAN_API_KEY:?SECSCAN_API_KEY is not set}"

# ----- Host info ---------------------------------------------------------
if [[ -r /etc/os-release ]]; then
  # /etc/os-release is standardized by freedesktop.org (ID, VERSION_ID, …)
  # shellcheck disable=SC1091
  . /etc/os-release
  os_family="${ID:-unknown}"
  os_version="${VERSION_ID:-unknown}"
  os_pretty="${PRETTY_NAME:-${NAME:-unknown}}"
else
  # Non-Linux (e.g. macOS, FreeBSD): no /etc/os-release. We map
  # `uname -s` to a sensible os_family.
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
# Backend normalizes `arm64`/`amd64`/`x86`/`i386` to the Linux canonical
# forms; no client-side normalization needed.

# Block N (ADR-0021) — capture the trivy CLI version for the envelope.
trivy_version="$("$TRIVY_BIN" --version 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")"

log "Host: ${os_pretty} (kernel ${kernel_version}, ${arch}, trivy ${trivy_version})"

# ----- Trivy scan + Packages[] strip -------------------------------------
trivy_raw="$(mktemp -t secscan-trivy-raw.XXXXXX.json)"
trivy_out="$(mktemp -t secscan-trivy.XXXXXX.json)"
response_body="$(mktemp -t secscan-resp.XXXXXX)"
trap 'rm -f "$trivy_raw" "$trivy_out" "$response_body"' EXIT

log "Starting trivy scan on ${SCAN_PATH} ..."
if ! "$TRIVY_BIN" rootfs "$SCAN_PATH" \
       --format json \
       --quiet \
       --scanners vuln \
       --output "$trivy_raw"; then
  log "Error: trivy scan failed"
  exit 2
fi

# Trivy writes valid JSON even when there are no findings. An empty file
# means something went badly wrong.
if [[ ! -s "$trivy_raw" ]]; then
  log "Error: trivy output is empty"
  exit 2
fi

# Block N (ADR-0021) — strip the `Results[].Packages` inventory block.
# It contributes 80-90% of the JSON bytes and is unused by the backend.
# `PkgIdentifier`/`SeveritySource`/`VendorIDs` are duplicated per
# Vulnerability so the strip does not lose information used downstream.
# Fallback: if `jq` cannot apply the filter (old jq, unexpected schema),
# send the raw output — the backend tolerates both shapes.
if jq 'del(.Results[].Packages)' "$trivy_raw" > "$trivy_out" 2>/dev/null; then
  raw_size="$(wc -c < "$trivy_raw")"
  stripped_size="$(wc -c < "$trivy_out")"
  log "Stripped Packages[] block (${raw_size} -> ${stripped_size} bytes)"
else
  log "Warning: jq strip failed, sending raw trivy output"
  cp "$trivy_raw" "$trivy_out"
fi

# ----- Build envelope ----------------------------------------------------
payload="$(jq -n \
  --arg agent_version "$AGENT_VERSION" \
  --arg os_family     "$os_family" \
  --arg os_version    "$os_version" \
  --arg os_pretty     "$os_pretty" \
  --arg kernel        "$kernel_version" \
  --arg arch          "$arch" \
  --arg trivy_ver     "$trivy_version" \
  --slurpfile scan    "$trivy_out" \
  '{
    agent_version: $agent_version,
    host: {
      os_family:      $os_family,
      os_version:     $os_version,
      os_pretty_name: $os_pretty,
      kernel_version: $kernel,
      architecture:   $arch,
      trivy_version:  $trivy_ver
    },
    scan: $scan[0]
  }')"

# ----- Upload (gzipped) --------------------------------------------------
# Compresses typically 8-10x. Backend accepts Content-Encoding: gzip and
# decompresses with a streaming limit (see ARCHITECTURE.md §9).
http_status="$(printf '%s' "$payload" | gzip -c | curl -sS \
  --max-time "$TIMEOUT_SEC" \
  --post301 --post302 --post303 -L \
  -o "$response_body" -w '%{http_code}' \
  -X POST "${SECSCAN_URL%/}/api/scans" \
  -H "Authorization: Bearer ${SECSCAN_API_KEY}" \
  -H "Content-Type: application/json" \
  -H "Content-Encoding: gzip" \
  --data-binary @- || echo "000")"

if [[ "$http_status" != "200" && "$http_status" != "202" ]]; then
  log "Error: upload failed (HTTP ${http_status})"
  log "Server response:"
  cat "$response_body" >&2 || true
  exit 3
fi

log "Scan uploaded successfully (HTTP ${http_status})"
