#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

make_common_stubs() {
  mkdir -p "$tmpdir/bin"
  cat >"$tmpdir/bin/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -w) shift 2 ;;
    --data-binary) gzip -dc >"$FM_PAYLOAD_CAPTURE"; shift 2 ;;
    *) shift ;;
  esac
done
if [[ -n "$out" ]]; then : >"$out"; fi
printf '202'
SH
  chmod +x "$tmpdir/bin/curl"
  cat >"$tmpdir/bin/trivy" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  --version) printf 'Version: 0.70.0\n' ;;
  version) printf '{"Version":"0.70.0"}\n' ;;
  rootfs)
    out=""
    while [[ $# -gt 0 ]]; do
      if [[ "$1" = "--output" ]]; then out="$2"; shift 2; else shift; fi
    done
    printf '{"SchemaVersion":2,"Results":[]}\n' >"$out"
    ;;
esac
SH
  chmod +x "$tmpdir/bin/trivy"
}

run_case() {
  local lib_body="$1"
  local name="$2"
  local dir="$tmpdir/$name"
  mkdir -p "$dir"
  cp "$repo_root/agent/fathometer-agent.sh" "$dir/fathometer-agent.sh"
  chmod +x "$dir/fathometer-agent.sh"
  if [[ "$lib_body" != "missing" ]]; then
    printf '%s\n' "$lib_body" >"$dir/lib_host_state.sh"
    chmod +x "$dir/lib_host_state.sh"
  fi
  local payload="$tmpdir/$name.json"
  FM_AGENT_UPDATED=1 \
    FM_URL="https://fathometer.example.test" \
    FM_API_KEY="test-key" \
    FM_PAYLOAD_CAPTURE="$payload" \
    PATH="$tmpdir/bin:$PATH" \
    bash "$dir/fathometer-agent.sh" >/dev/null 2>"$tmpdir/$name.log"
  printf '%s\n' "$payload"
}

make_common_stubs

payload="$(run_case missing missing)"
jq -e 'has("host_state") | not' "$payload" >/dev/null

payload="$(run_case '#!/usr/bin/env bash
readonly LIB_HOST_STATE_VERSION="0.3.1"
build_host_state_json() { printf '\''{"snapshot_at":"2026-05-21T00:00:00Z","tools_available":[],"gaps":[],"listeners":[],"processes":[],"kernel_modules":[],"services":[]}\n'\''; }' matching)"
jq -e '.host_state != null' "$payload" >/dev/null

payload="$(run_case '#!/usr/bin/env bash
build_host_state_json() { printf '\''{}\n'\''; }' missing_version)"
jq -e 'has("host_state") | not' "$payload" >/dev/null

payload="$(run_case '#!/usr/bin/env bash
readonly LIB_HOST_STATE_VERSION="0.2.9"
build_host_state_json() { printf '\''{}\n'\''; }' mismatch)"
jq -e 'has("host_state") | not' "$payload" >/dev/null

printf 'lib_host_state compat tests passed\n'
