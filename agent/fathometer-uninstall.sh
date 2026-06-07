#!/usr/bin/env bash
#
# fathometer-agent uninstaller
#
#   Local:  sudo /opt/fathometer/bin/fathometer-uninstall.sh
#   Remote: sudo bash <(curl -fsSL https://fathometer.example.com/uninstall.sh)
#
# Removes every artifact the installer placed on this host: the agent +
# trivy under /opt/fathometer, the config + API key under /etc/fathometer,
# the systemd timer/service (or the cron entry), and the trivy cache.
#
# This is PURELY LOCAL. The server record in the backend is NOT deleted —
# delete it from the dashboard if you no longer want this host listed.
#
# Flags:
#   -y, --yes      skip the confirmation prompt (also honoured: FM_UNATTENDED=1)
#   --keep-cache   preserve the trivy vulnerability DB cache
#   -h, --help     show this help and exit
#
set -euo pipefail

readonly FM_PREFIX="/opt/fathometer"
readonly FM_CONF_DIR="/etc/fathometer"
readonly FM_ENV_FILE="${FM_CONF_DIR}/agent.env"
readonly SVC="/etc/systemd/system/fathometer-agent.service"
readonly TMR="/etc/systemd/system/fathometer-agent.timer"
readonly CRON_FILE="/etc/cron.d/fathometer-agent"

# --- Output helpers (same palette as the installer) ----------------------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_OK=$'\033[32m'
  C_WARN=$'\033[33m'
  C_FAIL=$'\033[31m'
  C_INFO=$'\033[36m'
else
  C_RESET=""
  C_BOLD=""
  C_OK=""
  C_WARN=""
  C_FAIL=""
  C_INFO=""
fi
ok()   { printf "  %s[ok]%s    %s\n" "${C_OK}"   "${C_RESET}" "$*"; }
info() { printf "  %s[..]%s    %s\n" "${C_INFO}" "${C_RESET}" "$*"; }
warn() { printf "  %s[warn]%s  %s\n" "${C_WARN}" "${C_RESET}" "$*" >&2; }
fail() { printf "  %s[fail]%s  %s\n" "${C_FAIL}" "${C_RESET}" "$*" >&2; }
abort() { fail "$*"; exit 1; }

# --- Argument parsing ----------------------------------------------------
ASSUME_YES="${FM_UNATTENDED:-0}"
KEEP_CACHE=0
for arg in "$@"; do
  case "$arg" in
    -y|--yes)     ASSUME_YES=1 ;;
    --keep-cache) KEEP_CACHE=1 ;;
    -h|--help)
      printf 'usage: fathometer-uninstall.sh [-y|--yes] [--keep-cache]\n'
      exit 0
      ;;
    *) warn "ignoring unknown argument: ${arg}" ;;
  esac
done

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  abort "this uninstaller must run as root (sudo)"
fi

# --- Self-relocation guard ----------------------------------------------
# When run locally from inside $FM_PREFIX, `rm -rf $FM_PREFIX` would delete
# this very script while bash may still be reading later lines from it.
# Copy ourselves to a tmp file and re-exec from there. When run via
# curl-pipe / process-substitution, BASH_SOURCE is /dev/fd/* (not under
# $FM_PREFIX) and this branch is skipped — no relocation needed.
self="$(readlink -f "${BASH_SOURCE[0]:-$0}" 2>/dev/null || true)"
if [[ "$self" == "$FM_PREFIX"/* && -z "${FM_UNINSTALL_RELOCATED:-}" ]]; then
  tmp_self="$(mktemp -t fathometer-uninstall.XXXXXX)"
  cat "$self" > "$tmp_self"
  chmod +x "$tmp_self"
  FM_UNINSTALL_RELOCATED=1 exec bash "$tmp_self" "$@"
fi

# --- Read the dashboard URL before we delete the env file ---------------
FM_URL=""
if [[ -r "$FM_ENV_FILE" ]]; then
  FM_URL="$(sed -n 's/^FM_URL=//p' "$FM_ENV_FILE" | head -1)"
fi

# --- Confirmation --------------------------------------------------------
if [[ "$ASSUME_YES" != "1" ]]; then
  printf "\n%sThis removes the fathometer agent from this host:%s\n" "${C_BOLD}" "${C_RESET}"
  printf "  - %s (agent, trivy, uninstaller)\n" "$FM_PREFIX"
  printf "  - %s (config + API key)\n" "$FM_CONF_DIR"
  printf "  - the systemd timer/service or cron entry\n"
  if [[ "$KEEP_CACHE" != "1" ]]; then
    printf "  - the trivy vulnerability DB cache\n"
  fi
  answer=""
  if [[ -r /dev/tty ]]; then
    read -rp "  Continue? [y/N] " answer < /dev/tty || answer=""
  else
    abort "no TTY for confirmation; re-run with --yes (or FM_UNATTENDED=1)"
  fi
  case "$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')" in
    y|yes) ;;
    *) abort "aborted by user" ;;
  esac
fi

# --- 1) Scheduler --------------------------------------------------------
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now fathometer-agent.timer   2>/dev/null || true
  systemctl stop          fathometer-agent.service 2>/dev/null || true
  if [[ -f "$SVC" || -f "$TMR" ]]; then
    rm -f "$SVC" "$TMR"
    systemctl daemon-reload                        2>/dev/null || true
    systemctl reset-failed fathometer-agent.service 2>/dev/null || true
    ok "systemd timer/service removed"
  fi
fi
if [[ -f "$CRON_FILE" ]]; then
  rm -f "$CRON_FILE"
  ok "cron entry removed"
fi

# --- 2) Files + secrets --------------------------------------------------
rm -rf "$FM_PREFIX" "$FM_CONF_DIR"
ok "removed ${FM_PREFIX} and ${FM_CONF_DIR}"

# --- 3) Trivy cache (best-effort) ---------------------------------------
if [[ "$KEEP_CACHE" != "1" ]]; then
  rm -rf "${XDG_CACHE_HOME:-/root/.cache}/trivy" /root/.cache/trivy 2>/dev/null || true
  ok "trivy cache removed"
else
  info "trivy cache preserved (--keep-cache)"
fi

# --- Done ----------------------------------------------------------------
printf "\n%sfathometer agent uninstalled.%s\n" "${C_BOLD}" "${C_RESET}"
if [[ -n "$FM_URL" ]]; then
  printf "  Note: this host may still be listed in the dashboard at %s/ —\n" "${FM_URL%/}"
  printf "  delete it there if you no longer want it shown.\n"
fi
