#!/usr/bin/env bash
#
# run_adversarial.sh
# ------------------
# Schickt eine Reihe von Bad-Inputs gegen einen lokal laufenden secscan-Server
# und verifiziert, dass jeder mit dem erwarteten Fehler-Status abgewiesen wird.
#
# Pflicht-ENV:
#   SECSCAN_URL        z.B. http://localhost:8000 (Default)
#   SECSCAN_API_KEY    Server-Key fuer Tests die einen brauchen (optional fuer
#                      die meisten Cases — wir wollen nur 401/413/422 sehen).
#
# Aufruf (manuell):
#   docker compose up -d backend  # auf einem laufenden Server, ggf. .env
#   tests/adversarial/run_adversarial.sh
#
# Exit-Codes:
#   0   alle Bad-Inputs wurden vom Server KORREKT abgelehnt
#   1   mindestens eines wurde NICHT abgelehnt (Spec-Verletzung)
#   2   Server nicht erreichbar
#
# Hinweis: das Skript ist nicht Teil der pytest-Suite — es ist eine optionale
# Verhaltens-Pruefung gegen einen laufenden Server. Die pytest-Adversarial-
# Tests decken denselben Pfad In-Process ab.

set -uo pipefail

readonly URL="${SECSCAN_URL:-http://localhost:8000}"
readonly KEY="${SECSCAN_API_KEY:-not-a-real-key}"

pass=0
fail=0

check_status() {
  local description="$1"
  local expected_code="$2"
  local actual_code="$3"

  if [[ "$actual_code" == "$expected_code" ]]; then
    printf '  [ OK ] %s -> %s\n' "$description" "$actual_code"
    pass=$((pass + 1))
  else
    printf '  [FAIL] %s -> got %s, expected %s\n' \
      "$description" "$actual_code" "$expected_code" >&2
    fail=$((fail + 1))
  fi
}

# ---- Reachability ---------------------------------------------------------

if ! curl -sf -o /dev/null --max-time 3 "${URL}/healthz"; then
  echo "Server unter ${URL} nicht erreichbar." >&2
  exit 2
fi

echo "Server erreichbar unter ${URL}, starte Adversarial-Suite ..."

# ---- 1. 401 ohne Auth ----------------------------------------------------

code=$(curl -sS -o /dev/null -w '%{http_code}' \
       -X POST "${URL}/api/scans" --data '{}' --max-time 5)
check_status "POST /api/scans ohne Auth" 401 "$code"

# ---- 2. 401 mit grossem Body ohne Auth (Auth-vor-Body-Parse) -------------

bigbody=$(mktemp)
trap 'rm -f "$bigbody"' EXIT
head -c $((5 * 1024 * 1024)) /dev/urandom > "$bigbody"

code=$(curl -sS -o /dev/null -w '%{http_code}' \
       -X POST "${URL}/api/scans" \
       -H "Authorization: Bearer wrong-token" \
       --data-binary "@${bigbody}" \
       --max-time 10)
check_status "POST /api/scans (5 MB Body, falscher Bearer)" 401 "$code"

# ---- 3. 413 gzip-Bomb -----------------------------------------------------

bombfile=$(mktemp)
python3 -c "
import gzip, sys
sys.stdout.buffer.write(gzip.compress(b'A' * (200 * 1024 * 1024)))
" > "$bombfile"

code=$(curl -sS -o /dev/null -w '%{http_code}' \
       -X POST "${URL}/api/scans" \
       -H "Authorization: Bearer ${KEY}" \
       -H "Content-Encoding: gzip" \
       --data-binary "@${bombfile}" \
       --max-time 30)
rm -f "$bombfile"
# Erwartet: 413 (Server kennt den Key idR nicht -> 401; egal — wichtig ist
# dass kein 500/200 zurueckkommt). Wir akzeptieren 401 oder 413.
case "$code" in
  401|413) printf '  [ OK ] gzip-Bomb -> %s\n' "$code"; pass=$((pass + 1)) ;;
  *)       printf '  [FAIL] gzip-Bomb -> got %s, expected 401 oder 413\n' "$code" >&2
           fail=$((fail + 1)) ;;
esac

# ---- 4. 422 mit manipuliertem Envelope (ohne valid scan) -----------------

# Hier brauchen wir einen echten Bearer-Token — ohne wuerde der Test bei 401
# stehen. Wenn KEY unset, ueberspringen.
if [[ "$KEY" != "not-a-real-key" ]]; then
  code=$(curl -sS -o /dev/null -w '%{http_code}' \
         -X POST "${URL}/api/scans" \
         -H "Authorization: Bearer ${KEY}" \
         -H "Content-Type: application/json" \
         -H "Content-Encoding: gzip" \
         --data-binary "$(echo '{"foo":"bar"}' | gzip -c)" \
         --max-time 10)
  check_status "POST /api/scans (kein 'host'-Feld, gueltiger Bearer)" 422 "$code"
fi

# ---- 5. Path-Traversal in Server-Name bei /api/register -------------------

code=$(curl -sS -o /dev/null -w '%{http_code}' \
       -X POST "${URL}/api/register" \
       -H "Content-Type: application/json" \
       --data '{"master_key":"wrong","name":"../../etc/passwd","expected_scan_interval_h":24}' \
       --max-time 5)
# 422 (Pattern-Mismatch greift VOR Master-Key-Check). Aber: einige Implementer
# pruefen den Key zuerst -> 401. Beides akzeptieren.
case "$code" in
  401|422) printf '  [ OK ] /api/register mit Path-Traversal -> %s\n' "$code"
           pass=$((pass + 1)) ;;
  *)       printf '  [FAIL] /api/register mit Path-Traversal -> got %s\n' "$code" >&2
           fail=$((fail + 1)) ;;
esac

# ---- Summary --------------------------------------------------------------

echo
echo "Ergebnis: ${pass} OK, ${fail} FAIL"
[[ $fail -eq 0 ]] && exit 0 || exit 1
