#!/usr/bin/env bash
# The only way to merge a Renovate PR in the dependency workflow.
# Usage: [DRY_RUN=1] [RENOVATE_APP_SLUG=<slug>] merge-dependency-pr.sh <pr> <approved-head-sha>
set -euo pipefail

pr="${1:?pr number required}"
sha="${2:?approved head sha required}"
script_dir="$(cd "$(dirname "$0")" && pwd)"

die() { echo "REFUSED: $1" >&2; exit 1; }

identity="$("$script_dir/renovate-identity.sh")" || die "renovate identity unknown"
renovate_login="$(sed -n 's/^login=//p' <<<"$identity")"
renovate_email="$(sed -n 's/^email=//p' <<<"$identity")"

json="$(gh pr view "$pr" --json author,headRefName,headRefOid,baseRefName,state,isDraft,labels)"
jqr() { jq -r "$1" <<<"$json"; }

[[ "$(jqr .state)" == "OPEN" ]] || die "PR is not open"
[[ "$(jqr .isDraft)" == "false" ]] || die "PR is a draft"
[[ "$(jqr .baseRefName)" == "main" ]] || die "base is not main"
[[ "$(jqr .headRefName)" == renovate/* ]] || die "head branch is not renovate/*"
[[ "$(jqr .author.is_bot)" == "true" ]] || die "PR author is not a bot"
[[ "$(jqr .author.login)" == "$renovate_login" ]] || die "PR author is not Renovate: $(jqr .author.login)"
[[ "$(jqr .headRefOid)" == "$sha" ]] || die "head moved: $(jqr .headRefOid) != $sha"

if jq -e '.labels[].name | select(. == "needs-human")' <<<"$json" >/dev/null; then
  die "label needs-human is set"
fi

gh pr view "$pr" --json comments -q '.comments[].body' \
  | grep -qx "dependency-review: APPROVE $sha" || die "no review marker for $sha"

checks="$(gh pr checks "$pr" --json name,bucket)"
bad="$(jq -r '.[] | select(.bucket != "pass" and .bucket != "skipping") | "\(.name)=\(.bucket)"' <<<"$checks")"
[[ -z "$bad" ]] || die "checks not green: $bad"
[[ "$(jq length <<<"$checks")" -gt 0 ]] || die "no checks reported"

# Renovate head = newest commit by Renovate on the branch.
renovate_head="$(git log --format='%H %ae' "origin/main..$sha" \
  | awk -v email="$renovate_email" '$2 == email {print $1; exit}')"
[[ -n "$renovate_head" ]] || die "no Renovate commit found"
"$script_dir/check-dependency-fix.sh" "$renovate_head" || die "dependency fix rules violated"

if [[ "${DRY_RUN:-0}" == "1" ]]; then
  echo "WOULD_MERGE: PR #$pr at $sha"
  exit 0
fi

gh pr merge "$pr" --squash --delete-branch --match-head-commit "$sha"
echo "MERGED: PR #$pr at $sha"
