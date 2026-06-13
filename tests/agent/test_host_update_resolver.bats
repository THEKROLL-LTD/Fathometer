#!/usr/bin/env bats
#
# test_host_update_resolver.bats — Block AH (ADR-0062)
# ----------------------------------------------------
# Unit-Tests fuer die reinen Resolver-Output-Parser in
# `agent/lib_host_state.sh` (rpm/dpkg/dnf/apt) sowie den `collect_host_updates`-
# Leerlauf. Die Parser sind stdin->stdout-Funktionen und werden mit
# captured-output String-Fixtures geprueft — kein echter Paketmanager-Aufruf,
# kein State-Change.
#
# On-Demand-Suite (NICHT im Default-pytest). Ausfuehren:
#   bats tests/agent/test_host_update_resolver.bats
# Benoetigt `bats` (bats-core) im Dev-/CI-Environment, nicht auf dem Host.
#
# Erlaubt per expliziter User-Genehmigung fuer Block AH (CLAUDE.md
# Test-Konvention — .bats normalerweise genehmigungspflichtig).

setup() {
  LIB="${BATS_TEST_DIRNAME}/../../agent/lib_host_state.sh"
  [ -r "$LIB" ] || { echo "lib_host_state.sh nicht gefunden: $LIB"; return 1; }
}

# Hilfsfunktion: Fixture via stdin durch eine Lib-Funktion jagen.
_pipe() {
  local fn="$1" fixture="$2"
  run bash -c "source '$LIB'; printf '%s' \"\$1\" | $fn" _ "$fixture"
}

# ---------------------------------------------------------------------------
# _parse_rpm_qf — `rpm -qf --qf '%{NAME}\n' <path>`
# ---------------------------------------------------------------------------

@test "rpm_qf: clean package name" {
  _pipe _parse_rpm_qf $'tailscale\n'
  [ "$status" -eq 0 ]
  [ "$output" = "tailscale" ]
}

@test "rpm_qf: 'not owned' error yields empty" {
  _pipe _parse_rpm_qf $'error: file /opt/x: is not owned by any package\n'
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "rpm_qf: no-such-file error yields empty" {
  _pipe _parse_rpm_qf $'error: file /opt/x: No such file or directory\n'
  [ -z "$output" ]
}

@test "rpm_qf: takes first valid line, ignores junk prefix" {
  _pipe _parse_rpm_qf $'error: file /opt/x: is not owned by any package\ncontainerd\n'
  [ "$output" = "containerd" ]
}

@test "rpm_qf: name with dots/plus/dash allowed" {
  _pipe _parse_rpm_qf $'gcc-c++\n'
  [ "$output" = "gcc-c++" ]
}

# ---------------------------------------------------------------------------
# _parse_dpkg_search — `dpkg -S <path>`
# ---------------------------------------------------------------------------

@test "dpkg_search: simple 'pkg: /path' line" {
  _pipe _parse_dpkg_search $'tailscale: /usr/sbin/tailscaled\n'
  [ "$output" = "tailscale" ]
}

@test "dpkg_search: 'no path found' yields empty" {
  _pipe _parse_dpkg_search $'dpkg-query: no path found matching pattern /opt/x\n'
  [ -z "$output" ]
}

@test "dpkg_search: diversion preamble is skipped, real owner line wins" {
  _pipe _parse_dpkg_search $'diversion by libc6 from: /lib/x\ndiversion by libc6 to: /lib/x.usr\nlibc6: /lib/x\n'
  [ "$output" = "libc6" ]
}

# ---------------------------------------------------------------------------
# _parse_dnf_check_update — `dnf|yum check-update`
# ---------------------------------------------------------------------------

@test "dnf_check_update: package lines -> name<TAB>version, arch stripped" {
  fixture=$'Last metadata expiration check: 0:10:00 ago.\n\ntailscale.x86_64    1.98.5-1    tailscale-stable\ncurl.x86_64    7.88.1-2.el9    baseos\n'
  _pipe _parse_dnf_check_update "$fixture"
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = $'tailscale\t1.98.5-1' ]
  [ "${lines[1]}" = $'curl\t7.88.1-2.el9' ]
}

@test "dnf_check_update: Obsoleting Packages block is ignored" {
  fixture=$'\ntailscale.x86_64    1.98.5-1    stable\n\nObsoleting Packages\noldpkg.noarch    2.0    repo\n'
  _pipe _parse_dnf_check_update "$fixture"
  [ "${#lines[@]}" -eq 1 ]
  [ "${lines[0]}" = $'tailscale\t1.98.5-1' ]
}

@test "dnf_check_update: header-only output yields nothing" {
  _pipe _parse_dnf_check_update $'Last metadata expiration check: 0:00:01 ago.\n'
  [ -z "$output" ]
}

# ---------------------------------------------------------------------------
# _parse_apt_upgrade_sim — `apt-get -s upgrade`
# ---------------------------------------------------------------------------

@test "apt_upgrade_sim: Inst line with old+new version" {
  _pipe _parse_apt_upgrade_sim $'Inst tailscale [1.98.4] (1.98.5 stable:amd64 [amd64])\n'
  [ "$output" = $'tailscale\t1.98.5' ]
}

@test "apt_upgrade_sim: Inst line without old version" {
  _pipe _parse_apt_upgrade_sim $'Inst curl (7.88.1 jammy [amd64])\n'
  [ "$output" = $'curl\t7.88.1' ]
}

@test "apt_upgrade_sim: ignores Conf/Remv lines" {
  fixture=$'Inst tailscale [1.98.4] (1.98.5 stable [amd64])\nConf tailscale (1.98.5 stable [amd64])\nRemv oldpkg [1.0]\n'
  _pipe _parse_apt_upgrade_sim "$fixture"
  [ "${#lines[@]}" -eq 1 ]
  [ "${lines[0]}" = $'tailscale\t1.98.5' ]
}

# ---------------------------------------------------------------------------
# collect_host_updates — Leerlauf (kein Trivy-Target -> [])
# ---------------------------------------------------------------------------

@test "collect_host_updates: empty trivy results -> []" {
  tmp="$(mktemp)"
  printf '%s' '{"Results":[]}' > "$tmp"
  run bash -c "source '$LIB'; collect_host_updates '$tmp' /"
  rm -f "$tmp"
  [ "$status" -eq 0 ]
  [ "$output" = "[]" ]
}

@test "collect_host_updates: no lang-pkgs class -> []" {
  tmp="$(mktemp)"
  printf '%s' '{"Results":[{"Class":"os-pkgs","Target":"debian","Vulnerabilities":[]}]}' > "$tmp"
  run bash -c "source '$LIB'; collect_host_updates '$tmp' /"
  rm -f "$tmp"
  [ "$status" -eq 0 ]
  [ "$output" = "[]" ]
}
