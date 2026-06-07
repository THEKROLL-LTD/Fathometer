#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

make_runner() {
  local dir="$1"
  mkdir -p "$dir"
  cat >"$dir/fathometer-agent.sh" <<SH
#!/usr/bin/env bash
set -euo pipefail
export FM_AGENT_SOURCE_ONLY=1
. "$repo_root/agent/fathometer-agent.sh"
auto_update_self "\$@"
printf 'NO_UPDATE\\n'
SH
  chmod +x "$dir/fathometer-agent.sh"
  cat >"$dir/lib_host_state.sh" <<'SH'
#!/usr/bin/env bash
readonly LIB_HOST_STATE_VERSION="0.3.1"
SH
  chmod +x "$dir/lib_host_state.sh"
}

make_stubs() {
  mkdir -p "$tmpdir/bin"
  cat >"$tmpdir/bin/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
out=""
url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    --max-time|-w) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done

case "${AUTO_UPDATE_SCENARIO:-same}" in
  http_error)
    exit 22
    ;;
  same)
    printf '{"current_agent_version":"0.3.1"}\n'
    ;;
  older)
    printf '{"current_agent_version":"0.3.0"}\n'
    ;;
  download_fail)
    if [[ "$url" == */agent/version ]]; then
      printf '{"current_agent_version":"0.3.2"}\n'
    else
      exit 22
    fi
    ;;
  no_shebang)
    if [[ "$url" == */agent/version ]]; then
      printf '{"current_agent_version":"0.3.2"}\n'
    else
      printf 'readonly AGENT_VERSION="0.3.2"\n' >"$out"
    fi
    ;;
  wrong_version)
    if [[ "$url" == */agent/version ]]; then
      printf '{"current_agent_version":"0.3.2"}\n'
    else
      printf '#!/usr/bin/env bash\nreadonly AGENT_VERSION="9.9.9"\n' >"$out"
    fi
    ;;
  helper_fail|agent_replace_fail|happy)
    if [[ "$url" == */agent/version ]]; then
      printf '{"current_agent_version":"0.3.2"}\n'
    elif [[ "$url" == */lib_host_state.sh ]]; then
      if [[ "${AUTO_UPDATE_SCENARIO:-}" = "helper_fail" ]]; then
        exit 22
      fi
      printf '#!/usr/bin/env bash\nreadonly LIB_HOST_STATE_VERSION="0.3.2"\n' >"$out"
    else
      cat >"$out" <<'AGENT'
#!/usr/bin/env bash
readonly AGENT_VERSION="0.3.2"
if [[ "${FM_AGENT_UPDATED:-0}" = "1" ]]; then
  printf 'UPDATED\n'
else
  printf 'MISSING_GUARD\n'
fi
AGENT
    fi
    ;;
esac
SH
  chmod +x "$tmpdir/bin/curl"

  # `mv`-Wrapper: agent_replace_fail-Szenario simuliert ein
  # Permission-Problem beim Agent-Replace. Wir kapseln den echten `mv`
  # ueber `command -v` damit der Test auf Linux UND macOS laeuft
  # (Linux: /bin/mv, macOS: /usr/bin/mv).
  cat >"$tmpdir/bin/mv" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${AUTO_UPDATE_SCENARIO:-}" = "agent_replace_fail" && "${2:-}" == */fathometer-agent.sh ]]; then
  exit 1
fi
real_mv=""
for c in /usr/bin/mv /bin/mv; do
  [[ -x "$c" ]] && { real_mv="$c"; break; }
done
[[ -z "$real_mv" ]] && { echo "no real mv found" >&2; exit 127; }
exec "$real_mv" "$@"
SH
  chmod +x "$tmpdir/bin/mv"
}

run_case() {
  local scenario="$1"
  local dir="$tmpdir/$scenario"
  make_runner "$dir"
  AUTO_UPDATE_SCENARIO="$scenario" \
    FM_URL="https://fathometer.example.test" \
    PATH="$tmpdir/bin:$PATH" \
    bash "$dir/fathometer-agent.sh"
}

make_stubs

out="$(FM_AGENT_UPDATED=1 run_case happy)"
[[ "$out" = "NO_UPDATE" ]]

dir="$tmpdir/no_url"
make_runner "$dir"
out="$(AUTO_UPDATE_SCENARIO=happy PATH="$tmpdir/bin:$PATH" bash "$dir/fathometer-agent.sh")"
[[ "$out" = "NO_UPDATE" ]]

for scenario in http_error same older download_fail no_shebang wrong_version; do
  out="$(run_case "$scenario")"
  [[ "$out" = "NO_UPDATE" ]] || { printf '%s produced %s\n' "$scenario" "$out" >&2; exit 1; }
done

dir="$tmpdir/happy_direct"
make_runner "$dir"
out="$(AUTO_UPDATE_SCENARIO=happy FM_URL="https://fathometer.example.test" PATH="$tmpdir/bin:$PATH" bash "$dir/fathometer-agent.sh")"
[[ "$out" = "UPDATED" ]]
[[ -f "$dir/fathometer-agent.sh.bak" ]]
[[ -f "$dir/lib_host_state.sh.bak" ]]
grep -q 'AGENT_VERSION="0.3.2"' "$dir/fathometer-agent.sh"

dir="$tmpdir/helper_fail_direct"
make_runner "$dir"
out="$(AUTO_UPDATE_SCENARIO=helper_fail FM_URL="https://fathometer.example.test" PATH="$tmpdir/bin:$PATH" bash "$dir/fathometer-agent.sh")"
[[ "$out" = "UPDATED" ]]
[[ -f "$dir/fathometer-agent.sh.bak" ]]

dir="$tmpdir/agent_replace_fail_direct"
make_runner "$dir"
out="$(AUTO_UPDATE_SCENARIO=agent_replace_fail FM_URL="https://fathometer.example.test" PATH="$tmpdir/bin:$PATH" bash "$dir/fathometer-agent.sh")"
[[ "$out" = "NO_UPDATE" ]]
[[ -f "$dir/fathometer-agent.sh.bak" ]]
[[ -f "$dir/lib_host_state.sh.bak" ]]

printf 'auto_update tests passed\n'
