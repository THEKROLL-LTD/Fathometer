#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

make_stubs() {
  local mode="$1"
  mkdir -p "$tmpdir/bin"
  cat >"$tmpdir/bin/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -w) shift 2 ;;
    --data-binary) gzip -dc >"$SECSCAN_PAYLOAD_CAPTURE"; shift 2 ;;
    *) shift ;;
  esac
done
if [[ -n "$out" ]]; then
  : >"$out"
fi
printf '202'
SH
  chmod +x "$tmpdir/bin/curl"

  cat >"$tmpdir/bin/trivy" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  --version)
    printf 'Version: 0.70.0\n'
    ;;
  version)
    case "${TRIVY_DB_MODE:-happy}" in
      happy)
        cat <<'JSON'
{"Version":"0.70.0","VulnerabilityDB":{"Version":2,"UpdatedAt":"2026-05-21T01:03:33Z","NextUpdate":"2026-05-22T01:03:33Z","DownloadedAt":"2026-05-21T06:24:41Z"}}
JSON
        ;;
      empty)
        exit 0
        ;;
      no_db)
        printf '{"Version":"0.70.0"}\n'
        ;;
      fail)
        exit 1
        ;;
    esac
    ;;
  rootfs)
    out=""
    while [[ $# -gt 0 ]]; do
      if [[ "$1" = "--output" ]]; then
        out="$2"
        shift 2
      else
        shift
      fi
    done
    cat >"$out" <<'JSON'
{"SchemaVersion":2,"Trivy":{"Version":"0.70.0"},"Results":[]}
JSON
    ;;
  *)
    exit 1
    ;;
esac
SH
  chmod +x "$tmpdir/bin/trivy"
  export TRIVY_DB_MODE="$mode"
}

run_agent() {
  local mode="$1"
  local payload="$tmpdir/payload-$mode.json"
  make_stubs "$mode"
  SECSCAN_AGENT_UPDATED=1 \
    SECSCAN_URL="https://secscan.example.test" \
    SECSCAN_API_KEY="test-key" \
    SECSCAN_SCAN_PATH="/" \
    SECSCAN_PAYLOAD_CAPTURE="$payload" \
    PATH="$tmpdir/bin:$PATH" \
    bash "$repo_root/agent/secscan-agent.sh" >/dev/null 2>"$tmpdir/$mode.log"
  printf '%s\n' "$payload"
}

payload="$(run_agent happy)"
jq -e '.trivy_db.version == "2"' "$payload" >/dev/null
jq -e '.trivy_db.updated_at == "2026-05-21T01:03:33Z"' "$payload" >/dev/null
jq -e '.trivy_db.next_update_at == "2026-05-22T01:03:33Z"' "$payload" >/dev/null
jq -e '.trivy_db.downloaded_at == "2026-05-21T06:24:41Z"' "$payload" >/dev/null

for mode in empty no_db fail; do
  payload="$(run_agent "$mode")"
  jq -e '.trivy_db == null' "$payload" >/dev/null
  jq -e '.agent_version == "0.3.1"' "$payload" >/dev/null
  jq -e '.scan.SchemaVersion == 2' "$payload" >/dev/null
done

printf 'trivy_db meta tests passed\n'
