#!/usr/bin/env bash
# Derive the Renovate GitHub App identity from its slug.
# Usage: [RENOVATE_APP_SLUG=<slug>] renovate-identity.sh
# Output: two lines, login=<pr author login> and email=<git author email>.
# Valid as long as the Renovate runner sets no custom gitAuthor.
set -euo pipefail

slug="${RENOVATE_APP_SLUG:-thekroll-renovate}"

user="$(gh api "/users/${slug}%5Bbot%5D" --jq '"\(.id) \(.type)"')"
read -r bot_id bot_type <<<"$user"
[[ "$bot_type" == "Bot" ]] || { echo "not a bot account: ${slug}[bot]" >&2; exit 1; }
[[ "$bot_id" =~ ^[0-9]+$ ]] || { echo "invalid bot id: $bot_id" >&2; exit 1; }

echo "login=app/${slug}"
echo "email=${bot_id}+${slug}[bot]@users.noreply.github.com"
