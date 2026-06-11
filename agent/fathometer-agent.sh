#!/usr/bin/env bash
#
# fathometer-agent.sh
# ----------------
# Collects OS/kernel info, runs `trivy rootfs /` and uploads the result
# as a wrapper envelope to a fathometer backend.
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
# Block O (ADR-0022) — v0.3.0 changes:
#   - Optional `host_state` block is added to the envelope. Collects
#     `ss`-listeners, `ps`-processes, `lsmod`-kernel-modules and
#     `systemctl`-services. Each block has its own fallback path
#     (`netstat` for `ss`, gap-flag for the others). Adds ~10-30 KB
#     gzipped per scan on a typical Ubuntu host.
#   - Collectors live in `agent/lib_host_state.sh` (sourcable for tests
#     and Block-P reuse).
#
# TICKET-001 — v0.3.1 changes:
#   - Auto-update check before every scan. The agent downloads a newer
#     `fathometer-agent.sh` from the backend, keeps a `.bak` copy for operator
#     rollback, then re-execs itself once.
#   - Adds top-level `trivy_db` metadata from `trivy version --format json`.
#
# TICKET-015 — v0.6.0 changes:
#   - Trivy auto-update before every scan (`auto_update_trivy`), run AFTER
#     the agent self-update and BEFORE the scan. Only the fathometer-managed
#     binary at /opt/fathometer/bin/trivy is touched; a system trivy (apt,
#     /usr/bin) is never replaced. Mirrors the installer's vetted download:
#     tarball + `trivy_<v>_checksums.txt`, MANDATORY SHA256 verification,
#     atomic `install` with a `.bak` backup and post-replace re-verify +
#     rollback. Fail-soft throughout: any error keeps the current trivy and
#     never fails the scan. Opt out via `FM_TRIVY_AUTO_UPDATE=0` (air-gap).
#
# Requirements: bash >= 4, curl, jq, gzip, trivy (>= 0.70.0)
#               (trivy auto-update additionally uses tar + sha256sum;
#                both are optional — the update is skipped if either is absent)
#               (https://aquasecurity.github.io/trivy/)
#
# Required env:
#   FM_URL       e.g. https://fathometer.example.com
#   FM_API_KEY   server key produced by ./fathometer-register.sh
#
# Optional env:
#   FM_TRIVY_PATH          path to the trivy binary (default: from $PATH)
#   FM_SCAN_PATH           what to scan (default: /)
#   FM_TIMEOUT_SEC         upload timeout (default: 60)
#   FM_TRIVY_AUTO_UPDATE   1 (default) = keep the managed trivy on the
#                          recommended version; 0 = never touch trivy
#                          (set on air-gapped hosts without GitHub outbound)
#   FM_TRIVY_MANAGED_DIR   directory of the fathometer-managed trivy binary
#                          (default: /opt/fathometer/bin). Advanced/testing
#                          seam; trivy outside this dir is never replaced.
#
# Run as root, typically via cron or a systemd timer.
#
# Block R (ADR-0026) — async fast-path:
#   - `POST /api/scans` returns 202 + job_id.
#   - The agent exits immediately after acceptance; the server processes
#     the scan asynchronously. No polling.
#
# Exit codes:
#   0  success (scan accepted by server)
#   1  missing requirements or configuration
#   2  trivy scan failed
#   3  upload failed (HTTP-layer)
#

set -euo pipefail

readonly AGENT_VERSION="0.6.0"
readonly REQUIRED_LIB_HOST_STATE_VERSION="0.3.1"
readonly TRIVY_BIN="${FM_TRIVY_PATH:-trivy}"
readonly SCAN_PATH="${FM_SCAN_PATH:-/}"
readonly TIMEOUT_SEC="${FM_TIMEOUT_SEC:-60}"

log() { printf '[fathometer-agent] %s\n' "$*" >&2; }

version_lt() {
  local semver_re='^([0-9]+)\.([0-9]+)\.([0-9]+)(-rc\.?([0-9]+))?([.+-][A-Za-z0-9._-]+)?$'
  [[ "$1" =~ $semver_re ]] || return 1
  local a_major="${BASH_REMATCH[1]}" a_minor="${BASH_REMATCH[2]}" a_patch="${BASH_REMATCH[3]}" a_rc="${BASH_REMATCH[5]:-}"
  [[ "$2" =~ $semver_re ]] || return 1
  local b_major="${BASH_REMATCH[1]}" b_minor="${BASH_REMATCH[2]}" b_patch="${BASH_REMATCH[3]}" b_rc="${BASH_REMATCH[5]:-}"
  [[ "$1" = "$2" ]] && return 1

  if ((10#$a_major != 10#$b_major)); then
    ((10#$a_major < 10#$b_major))
    return $?
  fi
  if ((10#$a_minor != 10#$b_minor)); then
    ((10#$a_minor < 10#$b_minor))
    return $?
  fi
  if ((10#$a_patch != 10#$b_patch)); then
    ((10#$a_patch < 10#$b_patch))
    return $?
  fi

  # Bei gleicher Basisversion gilt: rc < final. Zwei rc-Versionen werden
  # numerisch verglichen. Andere Suffixe sind nach Regex erlaubt, triggern
  # aber kein Update gegen dieselbe Basisversion.
  if [[ -n "$a_rc" && -z "$b_rc" ]]; then
    return 0
  fi
  if [[ -z "$a_rc" && -n "$b_rc" ]]; then
    return 1
  fi
  if [[ -n "$a_rc" && -n "$b_rc" ]]; then
    ((10#$a_rc < 10#$b_rc))
    return $?
  fi
  return 1
}

resolve_self_path() {
  if self_path="$(readlink -f "$0" 2>/dev/null)" && [[ -n "$self_path" ]]; then
    printf '%s\n' "$self_path"
    return 0
  fi

  local self_dir self_base
  self_dir="$(cd "$(dirname "$0")" && pwd)"
  self_base="$(basename "$0")"
  printf '%s/%s\n' "$self_dir" "$self_base"
}

auto_update_self() {
  if [[ "${FM_AGENT_UPDATED:-0}" = "1" ]]; then
    return 0
  fi
  if [[ -z "${FM_URL:-}" ]]; then
    return 0
  fi

  local ver_json server_version
  ver_json="$(curl -fsS --max-time 5 "${FM_URL%/}/agent/version" 2>/dev/null || true)"
  if [[ -z "$ver_json" ]]; then
    log "Auto-Update: server unreachable, skipping"
    return 0
  fi

  server_version="$(printf '%s' "$ver_json" | jq -r '.current_agent_version // empty' 2>/dev/null)"
  if [[ -z "$server_version" ]] || [[ "$server_version" = "$AGENT_VERSION" ]]; then
    return 0
  fi
  if ! version_lt "$AGENT_VERSION" "$server_version"; then
    log "Auto-Update: server version $server_version is not newer than local $AGENT_VERSION, skipping"
    return 0
  fi

  log "Auto-Update: server version $server_version, local $AGENT_VERSION; updating"

  local tmpfile self_path self_dir lib_path
  self_path="$(resolve_self_path)"
  self_dir="$(dirname "$self_path")"
  lib_path="$self_dir/lib_host_state.sh"
  tmpfile="$(mktemp -t fathometer-agent.XXXXXX.sh)"

  # Authorization-Header beim Download: das `/agent/files/...`-Endpoint ist
  # heute by-design un-authenticated (Bootstrap-Installer-Konvention), wir
  # senden den API-Key trotzdem mit. Der Server akzeptiert ihn als optionalen
  # Header und kann ihn fuer Audit/Rate-Limits nutzen; spaetere Endpoint-
  # Hardening (Auth-Pflicht) bricht den Agent nicht.
  local auth_header=()
  if [[ -n "${FM_API_KEY:-}" ]]; then
    auth_header=(-H "Authorization: Bearer ${FM_API_KEY}")
  fi

  if ! curl -fsS --max-time 30 "${auth_header[@]+"${auth_header[@]}"}" -o "$tmpfile" "${FM_URL%/}/agent/files/fathometer-agent.sh"; then
    log "Auto-Update: download failed, keeping current version"
    rm -f "$tmpfile"
    return 0
  fi
  if ! head -1 "$tmpfile" | grep -q '^#!/'; then
    log "Auto-Update: downloaded script has no shebang, keeping current version"
    rm -f "$tmpfile"
    return 0
  fi
  if ! grep -q "AGENT_VERSION=\"$server_version\"" "$tmpfile"; then
    log "Auto-Update: downloaded script does not declare version $server_version, keeping current version"
    rm -f "$tmpfile"
    return 0
  fi

  local lib_tmp=""
  if [[ -f "$lib_path" ]]; then
    lib_tmp="$(mktemp -t lib_host_state.XXXXXX.sh)"
    if ! curl -fsS --max-time 30 "${auth_header[@]+"${auth_header[@]}"}" -o "$lib_tmp" "${FM_URL%/}/agent/files/lib_host_state.sh" 2>/dev/null; then
      log "Auto-Update: helper download failed, skipping helper replace"
      rm -f "$lib_tmp"
      lib_tmp=""
    elif ! head -1 "$lib_tmp" | grep -q '^#!/'; then
      log "Auto-Update: helper has no shebang, skipping helper replace"
      rm -f "$lib_tmp"
      lib_tmp=""
    fi
  fi

  cp -p "$self_path" "$self_path.bak" 2>/dev/null || true
  if [[ -n "$lib_tmp" ]]; then
    cp -p "$lib_path" "$lib_path.bak" 2>/dev/null || true
    chmod +x "$lib_tmp"
    if ! mv "$lib_tmp" "$lib_path"; then
      log "Auto-Update: helper replace failed, continuing with agent replace"
      rm -f "$lib_tmp"
    fi
  fi

  chmod +x "$tmpfile"
  if ! mv "$tmpfile" "$self_path"; then
    log "Auto-Update: agent replace failed, keeping current version"
    rm -f "$tmpfile"
    return 0
  fi

  log "Auto-Update: updated to $server_version, re-exec"
  export FM_AGENT_UPDATED=1
  exec "$self_path" "$@"
}

auto_update_trivy() {
  # TICKET-015 — hebt die fathometer-managed Trivy-Binary auf
  # `recommended_trivy_version`. Laeuft NACH `auto_update_self` (also im
  # bereits selbst-aktualisierten Skript) und VOR `require_cmd "$TRIVY_BIN"`.
  #
  # Fail-soft-Vertrag: JEDER Fehler (Download, Checksum, tar, Replace,
  # Re-Verify) endet in `log` + `return 0` mit der vorhandenen Trivy-Version.
  # Der Scan darf an einem fehlgeschlagenen Update NIE scheitern.

  # (1) Opt-out / Air-Gap-Guard. Default an; `0` deaktiviert komplett.
  if [[ "${FM_TRIVY_AUTO_UPDATE:-1}" = "0" ]]; then
    return 0
  fi
  if [[ -z "${FM_URL:-}" ]]; then
    return 0
  fi

  # (4) Nur die fathometer-managed Binary anfassen. Zeigt $TRIVY_BIN auf ein
  # System-Trivy (apt -> /usr/bin/trivy o.ae.), NICHT ersetzen — sonst Kampf
  # mit dem Paketmanager. Die UI-Pill deckt diesen Fall ohnehin ab.
  local trivy_resolved
  trivy_resolved="$(command -v "$TRIVY_BIN" 2>/dev/null || true)"
  if [[ -z "$trivy_resolved" ]]; then
    # Kein Trivy auffindbar — `require_cmd "$TRIVY_BIN"` faengt das gleich
    # mit Exit 1 ab; hier nichts zu aktualisieren.
    return 0
  fi
  trivy_resolved="$(readlink -f "$trivy_resolved" 2>/dev/null || printf '%s' "$trivy_resolved")"
  # `FM_TRIVY_MANAGED_DIR` ist der vom Installer gepinnte bin-Pfad; der Default
  # ist hart `/opt/fathometer/bin` (Installer-Konvention). Der Override
  # existiert ausschliesslich als Test-Seam und fuer abweichende Installer-
  # Prefixe — er aendert NICHT, dass nur die fathometer-eigene Binary ersetzt
  # wird (ein System-Trivy unter /usr/bin bleibt unangetastet).
  local managed_dir="${FM_TRIVY_MANAGED_DIR:-/opt/fathometer/bin}"
  if [[ "$trivy_resolved" != "$managed_dir/trivy" ]]; then
    log "Trivy-Update: '$trivy_resolved' is not fathometer-managed ($managed_dir/trivy); skipping"
    return 0
  fi

  # (2) Ziel-Version + URL-Template aus dem Backend (derselbe Endpoint wie
  # der Selbst-Update). Server unerreichbar/unvollstaendig -> fail-soft skip.
  local ver_json recommended url_template
  ver_json="$(curl -fsS --max-time 5 "${FM_URL%/}/agent/version" 2>/dev/null || true)"
  if [[ -z "$ver_json" ]]; then
    log "Trivy-Update: server unreachable, skipping"
    return 0
  fi
  recommended="$(printf '%s' "$ver_json" | jq -r '.recommended_trivy_version // empty' 2>/dev/null)"
  url_template="$(printf '%s' "$ver_json" | jq -r '.trivy_release_url_template // empty' 2>/dev/null)"
  if [[ -z "$recommended" || -z "$url_template" ]]; then
    log "Trivy-Update: server response missing recommended_trivy_version/url_template, skipping"
    return 0
  fi

  # (3) Trigger nur wenn installiert < recommended (version_lt, Z. 78).
  local installed
  installed="$("$TRIVY_BIN" --version 2>/dev/null | head -1 | awk '{print $2}' || true)"
  if [[ -z "$installed" ]]; then
    log "Trivy-Update: could not read installed trivy version, skipping"
    return 0
  fi
  if ! version_lt "$installed" "$recommended"; then
    log "Trivy-Update: installed $installed >= recommended $recommended, skipping"
    return 0
  fi

  # `tar`/`sha256sum` sind nur fuer den Update-Pfad noetig (neue Soft-Deps).
  # Fehlt eine -> Update skip statt Abbruch.
  if ! command -v tar >/dev/null 2>&1; then
    log "Trivy-Update: 'tar' not available, skipping update (keeping $installed)"
    return 0
  fi
  if ! command -v sha256sum >/dev/null 2>&1; then
    log "Trivy-Update: 'sha256sum' not available, skipping update (keeping $installed)"
    return 0
  fi

  # (5) Arch-Map wie `download_pinned_trivy` (im Recurring-Agent ergaenzt).
  local arch_raw arch
  arch_raw="$(uname -m)"
  case "$arch_raw" in
    x86_64|amd64) arch="64bit" ;;
    aarch64|arm64) arch="ARM64" ;;
    *)
      log "Trivy-Update: unsupported architecture '$arch_raw', skipping"
      return 0
      ;;
  esac

  local url checksums_url
  url="$url_template"
  url="${url//\{version\}/$recommended}"
  url="${url//\{arch\}/$arch}"
  checksums_url="$(printf '%s' "$url" | sed -E "s#trivy_${recommended}_Linux-${arch}\\.tar\\.gz#trivy_${recommended}_checksums.txt#")"

  log "Trivy-Update: installed $installed < recommended $recommended; updating from $url"

  local tmp
  tmp="$(mktemp -d -t fathometer-trivy.XXXXXX)" || {
    log "Trivy-Update: mktemp failed, keeping $installed"
    return 0
  }
  local tarball="${tmp}/trivy.tar.gz"
  local checksums="${tmp}/checksums.txt"

  # (5) Download Tarball + Checksums.
  if ! curl -fsSL --max-time 120 -o "$tarball" "$url"; then
    log "Trivy-Update: tarball download failed, keeping $installed"
    rm -rf "$tmp"
    return 0
  fi
  if ! curl -fsSL --max-time 30 -o "$checksums" "$checksums_url"; then
    log "Trivy-Update: checksums download failed, keeping $installed"
    rm -rf "$tmp"
    return 0
  fi

  # (5) SHA256-Verifikation ist PFLICHT — kein ungeprueftes Binaer-Replace.
  local expected actual
  expected="$(grep -F "trivy_${recommended}_Linux-${arch}.tar.gz" "$checksums" | awk '{print $1}' | head -1)"
  if [[ -z "$expected" ]]; then
    log "Trivy-Update: no checksum entry for trivy_${recommended}_Linux-${arch}.tar.gz, keeping $installed"
    rm -rf "$tmp"
    return 0
  fi
  actual="$(sha256sum "$tarball" | awk '{print $1}')"
  if [[ "$expected" != "$actual" ]]; then
    log "Trivy-Update: sha256 mismatch (expected $expected, got $actual), keeping $installed"
    rm -rf "$tmp"
    return 0
  fi

  if ! tar -xzf "$tarball" -C "$tmp" trivy; then
    log "Trivy-Update: failed to extract trivy from tarball, keeping $installed"
    rm -rf "$tmp"
    return 0
  fi

  # (6) Atomar ersetzen mit Backup. Backup zuerst, damit ein Rollback
  # moeglich bleibt falls die Re-Verifikation scheitert.
  cp -p "$trivy_resolved" "$trivy_resolved.bak" 2>/dev/null || true
  if ! install -m 0755 -o root -g root "$tmp/trivy" "$trivy_resolved"; then
    log "Trivy-Update: install/replace failed, keeping $installed"
    rm -rf "$tmp"
    return 0
  fi

  # (6) Re-Verifikation: meldet die neue Binary nicht >= recommended,
  # Rollback aus `.bak` und fail-soft weiter mit der alten Version.
  local new_version
  new_version="$("$TRIVY_BIN" --version 2>/dev/null | head -1 | awk '{print $2}' || true)"
  if [[ -z "$new_version" ]] || version_lt "$new_version" "$recommended"; then
    log "Trivy-Update: post-replace check failed (got '${new_version:-unknown}', want >= $recommended), rolling back"
    if [[ -f "$trivy_resolved.bak" ]]; then
      install -m 0755 -o root -g root "$trivy_resolved.bak" "$trivy_resolved" 2>/dev/null \
        || cp -p "$trivy_resolved.bak" "$trivy_resolved" 2>/dev/null || true
    fi
    rm -rf "$tmp"
    return 0
  fi

  log "Trivy-Update: updated to $new_version (was $installed); backup at $trivy_resolved.bak"
  rm -rf "$tmp"
  return 0
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 \
    || { log "Error: '$1' not found in PATH"; exit 1; }
}

if [[ "${FM_AGENT_SOURCE_ONLY:-0}" = "1" ]]; then
  # shellcheck disable=SC2317
  return 0 2>/dev/null || exit 0
fi

# ----- Prerequisites -----------------------------------------------------
require_cmd curl
require_cmd jq
require_cmd gzip

: "${FM_URL:?FM_URL is not set}"
: "${FM_API_KEY:?FM_API_KEY is not set}"

auto_update_self "$@"

# TICKET-015: nach dem (ggf. re-exec'ten) Selbst-Update die managed
# Trivy-Binary auf die empfohlene Version heben — fail-soft, vor dem Scan.
auto_update_trivy

require_cmd "$TRIVY_BIN"

# ----- Host-state collectors (Block O, v0.3.0) ---------------------------
# Sourcable companion library next to this script. We resolve the path via
# `BASH_SOURCE` so the script works when invoked via an absolute path,
# from a symlink, or from `$PATH`.
_agent_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib_host_state.sh
if [[ -r "${_agent_dir}/lib_host_state.sh" ]]; then
  # shellcheck disable=SC1091
  . "${_agent_dir}/lib_host_state.sh"
  _has_host_state_lib=1
  if [[ -z "${LIB_HOST_STATE_VERSION:-}" ]] || [[ "$LIB_HOST_STATE_VERSION" != "$REQUIRED_LIB_HOST_STATE_VERSION" ]]; then
    log "Warning: lib_host_state.sh version mismatch (need=${REQUIRED_LIB_HOST_STATE_VERSION}, found=${LIB_HOST_STATE_VERSION:-missing}); host_state will be omitted"
    _has_host_state_lib=0
  fi
else
  log "Warning: lib_host_state.sh not found next to agent; host_state will be omitted"
  _has_host_state_lib=0
fi

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

# `trivy version --format json` ist normalerweise <1s. Hard-Cap auf 10s
# damit ein haengender DB-Update-Lock o.ae. den Scan nicht blockiert.
# `timeout` ist GNU-coreutils; falls nicht verfuegbar (sehr alte BusyBox)
# faellt der Aufruf zurueck ohne Cap — kein Showstopper.
if command -v timeout >/dev/null 2>&1; then
  trivy_db_meta_raw="$(timeout 10 "$TRIVY_BIN" version --format json 2>/dev/null || echo '')"
else
  trivy_db_meta_raw="$("$TRIVY_BIN" version --format json 2>/dev/null || echo '')"
fi
trivy_db_block="null"
if [[ -n "$trivy_db_meta_raw" ]] && printf '%s' "$trivy_db_meta_raw" | jq -e '.VulnerabilityDB' >/dev/null 2>&1; then
  trivy_db_block="$(printf '%s' "$trivy_db_meta_raw" | jq -c '{
    version: (.VulnerabilityDB.Version | tostring),
    updated_at: .VulnerabilityDB.UpdatedAt,
    next_update_at: .VulnerabilityDB.NextUpdate,
    downloaded_at: .VulnerabilityDB.DownloadedAt
  }')"
  log "Trivy-DB meta: version=$(printf '%s' "$trivy_db_block" | jq -r .version) updated_at=$(printf '%s' "$trivy_db_block" | jq -r .updated_at)"
else
  log "Warning: trivy version --format json returned no VulnerabilityDB data; sending trivy_db=null"
fi

log "Host: ${os_pretty} (kernel ${kernel_version}, ${arch}, trivy ${trivy_version})"

# ----- Trivy scan + Packages[] strip -------------------------------------
trivy_raw="$(mktemp -t fathometer-trivy-raw.XXXXXX.json)"
trivy_out="$(mktemp -t fathometer-trivy.XXXXXX.json)"
response_body="$(mktemp -t fathometer-resp.XXXXXX)"
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

# ----- Host-state snapshot (Block O, v0.3.0) -----------------------------
# Sammelt Listener/Prozesse/Module/Services. Im Fehlerfall (Lib fehlt oder
# Build wirft) lassen wir den Block weg — Backend toleriert via
# `host_state: HostStateBlock | None = None`.
host_state_json="null"
if [[ "$_has_host_state_lib" -eq 1 ]]; then
  if hs_tmp="$(build_host_state_json 2>/dev/null)" && [[ -n "$hs_tmp" ]]; then
    # Validate via jq — falls Bash-Quirk doch invalid JSON erzeugt, fallback null.
    if printf '%s' "$hs_tmp" | jq -e '.' >/dev/null 2>&1; then
      host_state_json="$hs_tmp"
      log "Host-state collected (tools_available=$(printf '%s' "$hs_tmp" | jq -rc '.tools_available | join(",")'); gaps=$(printf '%s' "$hs_tmp" | jq -rc '.gaps | join(",")'))"
    else
      log "Warning: host_state build produced invalid JSON, omitting"
    fi
  else
    log "Warning: host_state build failed, omitting"
  fi
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
  --argjson host_state "$host_state_json" \
  --argjson trivy_db "$trivy_db_block" \
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
    scan: $scan[0],
    trivy_db: $trivy_db
  }
  + (if $host_state == null then {} else {host_state: $host_state} end)')"

# ----- Upload (gzipped) --------------------------------------------------
# Compresses typically 8-10x. Backend accepts Content-Encoding: gzip and
# decompresses with a streaming limit (see ARCHITECTURE.md §9).
# Block R (ADR-0026): POST now returns 202 + job_id (async fast-path).
http_status="$(printf '%s' "$payload" | gzip -c | curl -sS \
  --max-time "$TIMEOUT_SEC" \
  --post301 --post302 --post303 -L \
  -o "$response_body" -w '%{http_code}' \
  -X POST "${FM_URL%/}/api/scans" \
  -H "Authorization: Bearer ${FM_API_KEY}" \
  -H "Content-Type: application/json" \
  -H "Content-Encoding: gzip" \
  --data-binary @- || echo "000")"

case "$http_status" in
  202) ;;
  400|413|422|429)
    log "Error: upload rejected (HTTP ${http_status})"
    cat "$response_body" >&2 || true
    exit 3
    ;;
  *)
    log "Error: upload failed (HTTP ${http_status})"
    cat "$response_body" >&2 || true
    exit 3
    ;;
esac

job_id="$(jq -r '.job_id' < "$response_body")"
if [[ -z "$job_id" || "$job_id" = "null" ]]; then
  log "Error: response missing job_id"
  cat "$response_body" >&2 || true
  exit 3
fi
# Upload accepted (202). The server processes the scan asynchronously;
# the agent does not wait for the result and exits successfully here.
log "Scan accepted (job_id=${job_id})"
exit 0
