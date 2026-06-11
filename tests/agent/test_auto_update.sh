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
    printf '{"current_agent_version":"0.6.0"}\n'
    ;;
  older)
    printf '{"current_agent_version":"0.5.0"}\n'
    ;;
  download_fail)
    if [[ "$url" == */agent/version ]]; then
      printf '{"current_agent_version":"0.6.1"}\n'
    else
      exit 22
    fi
    ;;
  no_shebang)
    if [[ "$url" == */agent/version ]]; then
      printf '{"current_agent_version":"0.6.1"}\n'
    else
      printf 'readonly AGENT_VERSION="0.6.1"\n' >"$out"
    fi
    ;;
  wrong_version)
    if [[ "$url" == */agent/version ]]; then
      printf '{"current_agent_version":"0.6.1"}\n'
    else
      printf '#!/usr/bin/env bash\nreadonly AGENT_VERSION="9.9.9"\n' >"$out"
    fi
    ;;
  helper_fail|agent_replace_fail|happy)
    if [[ "$url" == */agent/version ]]; then
      printf '{"current_agent_version":"0.6.1"}\n'
    elif [[ "$url" == */lib_host_state.sh ]]; then
      if [[ "${AUTO_UPDATE_SCENARIO:-}" = "helper_fail" ]]; then
        exit 22
      fi
      printf '#!/usr/bin/env bash\nreadonly LIB_HOST_STATE_VERSION="0.3.2"\n' >"$out"
    else
      cat >"$out" <<'AGENT'
#!/usr/bin/env bash
readonly AGENT_VERSION="0.6.1"
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
grep -q 'AGENT_VERSION="0.6.1"' "$dir/fathometer-agent.sh"

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

printf 'auto_update_self tests passed\n'

# ===========================================================================
# auto_update_trivy (TICKET-015)
# ===========================================================================
#
# Hermetischer Stub-Harness: `curl`, `install`, `tar`, `sha256sum` und `uname`
# werden gemockt (kein Netz, kein root, keine echte Trivy-Binary). Der Guard
# "nur die fathometer-managed Binary" wird ueber `FM_TRIVY_MANAGED_DIR` auf ein
# Sandbox-bin-Dir gezeigt; der Default `/opt/fathometer/bin` bleibt im Code.

setup_trivy_stubs() {
  local bindir="$1"
  mkdir -p "$bindir"

  # curl: /agent/version -> JSON (stdout); Tarball/Checksums -> Datei (-o).
  cat >"$bindir/curl" <<'SH'
#!/usr/bin/env bash
out=""; url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    --max-time) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
rec="${TRIVY_RECOMMENDED:-0.71.0}"
case "$url" in
  */agent/version)
    [[ "${TRIVY_SCENARIO:-}" = "server_unreachable" ]] && exit 22
    printf '{"recommended_trivy_version":"%s","trivy_release_url_template":"https://example.test/trivy_{version}_Linux-{arch}.tar.gz"}\n' "$rec"
    ;;
  *.tar.gz)
    [[ "${TRIVY_SCENARIO:-}" = "download_fail" ]] && exit 22
    printf 'TARBALL\n' >"$out"
    ;;
  *checksums.txt)
    printf 'aaaaaaaaaaaaaaaa  trivy_%s_Linux-64bit.tar.gz\n' "$rec" >"$out"
    ;;
  *) exit 22 ;;
esac
SH
  chmod +x "$bindir/curl"

  # sha256sum: 'match' -> erwarteter Hash, sonst abweichend (Mismatch-Fall).
  cat >"$bindir/sha256sum" <<'SH'
#!/usr/bin/env bash
f="$1"
if [[ "${TRIVY_SCENARIO:-}" = "checksum_mismatch" ]]; then
  printf 'deadbeefdeadbeef  %s\n' "$f"
else
  printf 'aaaaaaaaaaaaaaaa  %s\n' "$f"
fi
SH
  chmod +x "$bindir/sha256sum"

  # tar: 'extrahiert' eine trivy-Binary die TRIVY_NEW_VERSION meldet.
  cat >"$bindir/tar" <<'SH'
#!/usr/bin/env bash
destdir=""
while [[ $# -gt 0 ]]; do
  case "$1" in -C) destdir="$2"; shift 2 ;; *) shift ;; esac
done
newver="${TRIVY_NEW_VERSION:-${TRIVY_RECOMMENDED:-0.71.0}}"
printf '#!/usr/bin/env bash\necho "Version: %s"\n' "$newver" >"$destdir/trivy"
chmod +x "$destdir/trivy"
SH
  chmod +x "$bindir/tar"

  # install: ignoriert -m/-o/-g (kein root noetig), kopiert SRC -> DEST.
  cat >"$bindir/install" <<'SH'
#!/usr/bin/env bash
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in -m|-o|-g) shift 2 ;; -d) shift ;; *) args+=("$1"); shift ;; esac
done
src="${args[0]:-}"; dest="${args[1]:-}"
cp "$src" "$dest"
chmod +x "$dest" 2>/dev/null || true
SH
  chmod +x "$bindir/install"

  # uname -m -> deterministische Arch (64bit-Asset).
  cat >"$bindir/uname" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" = "-m" ]]; then echo "x86_64"; else echo "Linux"; fi
SH
  chmod +x "$bindir/uname"
}

# Fuehrt auto_update_trivy in der Sandbox aus. Echo: Pfad des Case-Dirs.
run_trivy_case() {
  local scenario="$1" installed="$2"
  local dir="$tmpdir/trivy_$scenario"
  mkdir -p "$dir/managed" "$dir/bin"
  printf '#!/usr/bin/env bash\necho "Version: %s"\n' "$installed" >"$dir/managed/trivy"
  chmod +x "$dir/managed/trivy"
  setup_trivy_stubs "$dir/bin"

  # Kanonisierter Pfad: der Agent macht `readlink -f` auf die Binary; auf
  # macOS ist /var -> /private/var ein Symlink, daher muss FM_TRIVY_MANAGED_DIR
  # bereits der aufgeloeste Pfad sein, sonst schlaegt der Guard faelschlich an.
  local managed_dir
  managed_dir="$(readlink -f "$dir/managed" 2>/dev/null || printf '%s' "$dir/managed")"
  # Szenario "system_binary": Guard soll greifen -> managed_dir auf den
  # Default zeigen lassen (Sandbox-Pfad != /opt/fathometer/bin/trivy).
  local managed_env=("FM_TRIVY_MANAGED_DIR=$managed_dir")
  [[ "$scenario" = "system_binary" ]] && managed_env=("FM_TRIVY_MANAGED_DIR=/opt/fathometer/bin")

  local auto_env=("FM_TRIVY_AUTO_UPDATE=1")
  [[ "$scenario" = "auto_update_off" ]] && auto_env=("FM_TRIVY_AUTO_UPDATE=0")

  env -i HOME="$HOME" \
    TRIVY_SCENARIO="$scenario" \
    TRIVY_RECOMMENDED="0.71.0" \
    TRIVY_NEW_VERSION="${TRIVY_NEW_VERSION:-}" \
    FM_URL="https://fathometer.example.test" \
    FM_TRIVY_PATH="$dir/managed/trivy" \
    "${managed_env[@]}" "${auto_env[@]}" \
    PATH="$dir/bin:/usr/bin:/bin" \
    bash -c "export FM_AGENT_SOURCE_ONLY=1; . '$repo_root/agent/fathometer-agent.sh'; auto_update_trivy" \
    >"$dir/out" 2>"$dir/log" || true
  printf '%s\n' "$dir"
}

trivy_version_of() {
  bash "$1/managed/trivy" --version 2>/dev/null | head -1 | awk '{print $2}'
}

# (a) installed < recommended + managed -> Download/Verify/Replace.
d="$(run_trivy_case happy "0.70.0")"
[[ "$(trivy_version_of "$d")" = "0.71.0" ]] || { echo "happy: trivy not updated" >&2; cat "$d/log" >&2; exit 1; }
[[ -f "$d/managed/trivy.bak" ]] || { echo "happy: no .bak backup" >&2; exit 1; }
grep -q "updated to 0.71.0" "$d/log" || { echo "happy: missing update log" >&2; cat "$d/log" >&2; exit 1; }

# (b) installed >= recommended -> skip.
d="$(run_trivy_case skip_up_to_date "0.71.0")"
[[ "$(trivy_version_of "$d")" = "0.71.0" ]]
[[ ! -f "$d/managed/trivy.bak" ]] || { echo "skip: unexpected .bak" >&2; exit 1; }
grep -q "skipping" "$d/log" || { echo "skip: missing skip log" >&2; cat "$d/log" >&2; exit 1; }

# (c) System-Binary (nicht unter managed dir) -> kein Replace.
d="$(run_trivy_case system_binary "0.70.0")"
[[ "$(trivy_version_of "$d")" = "0.70.0" ]] || { echo "system: unexpectedly replaced" >&2; exit 1; }
[[ ! -f "$d/managed/trivy.bak" ]] || { echo "system: unexpected .bak" >&2; exit 1; }
grep -q "not fathometer-managed" "$d/log" || { echo "system: missing guard log" >&2; cat "$d/log" >&2; exit 1; }

# (d) Checksum-Mismatch -> kein Replace, alte Binary bleibt.
d="$(run_trivy_case checksum_mismatch "0.70.0")"
[[ "$(trivy_version_of "$d")" = "0.70.0" ]] || { echo "mismatch: replaced despite bad checksum" >&2; exit 1; }
[[ ! -f "$d/managed/trivy.bak" ]] || { echo "mismatch: unexpected .bak (replace started)" >&2; exit 1; }
grep -q "sha256 mismatch" "$d/log" || { echo "mismatch: missing mismatch log" >&2; cat "$d/log" >&2; exit 1; }

# (e) FM_TRIVY_AUTO_UPDATE=0 -> skip.
d="$(run_trivy_case auto_update_off "0.70.0")"
[[ "$(trivy_version_of "$d")" = "0.70.0" ]]
[[ ! -f "$d/managed/trivy.bak" ]] || { echo "off: unexpected .bak" >&2; exit 1; }

# (f) Download-Fail -> fail-soft, alte Binary bleibt.
d="$(run_trivy_case download_fail "0.70.0")"
[[ "$(trivy_version_of "$d")" = "0.70.0" ]] || { echo "download_fail: unexpectedly changed" >&2; exit 1; }
[[ ! -f "$d/managed/trivy.bak" ]] || { echo "download_fail: unexpected .bak" >&2; exit 1; }
grep -q "download failed" "$d/log" || { echo "download_fail: missing log" >&2; cat "$d/log" >&2; exit 1; }

# (g) Post-Replace-Reverify scheitert (neue Binary meldet alte Version)
#     -> Rollback aus .bak, alte Version laeuft weiter.
TRIVY_NEW_VERSION="0.70.0" d="$(run_trivy_case rollback "0.70.0")"
[[ "$(trivy_version_of "$d")" = "0.70.0" ]] || { echo "rollback: not rolled back" >&2; exit 1; }
grep -q "rolling back" "$d/log" || { echo "rollback: missing rollback log" >&2; cat "$d/log" >&2; exit 1; }

printf 'auto_update_trivy tests passed\n'
printf 'auto_update tests passed\n'
