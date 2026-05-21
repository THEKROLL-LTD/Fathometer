#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

export SECSCAN_AGENT_SOURCE_ONLY=1
# shellcheck source=agent/secscan-agent.sh
. "$repo_root/agent/secscan-agent.sh"

assert_true() {
  if ! version_lt "$1" "$2"; then
    printf 'expected %s < %s\n' "$1" "$2" >&2
    exit 1
  fi
}

assert_false() {
  if version_lt "$1" "$2"; then
    printf 'expected not (%s < %s)\n' "$1" "$2" >&2
    exit 1
  fi
}

assert_true "0.3.0" "0.3.1"
assert_false "0.3.1" "0.3.0"
assert_false "0.3.1" "0.3.1"
assert_true "0.3.1-rc.1" "0.3.1"
assert_true "0.3.99" "0.4.0"
assert_false "branch-name" "0.3.1"
assert_false "0.3.1" "branch-name"
assert_false "" "0.3.1"

printf 'version_lt tests passed\n'
