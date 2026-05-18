#!/usr/bin/env bash
#
# lib_host_state.sh
# -----------------
# Sourcable bash-Library mit den vier Host-Snapshot-Collectors fuer den
# Agent ab v0.3.0 (Block O, ADR-0022).
#
# Exportiert vier Funktionen, die das JSON in eine globale Variable
# schreiben statt auf stdout, weil Bash bei `$(subshell)`-Capture die
# globalen Tracking-Arrays (TOOLS_AVAILABLE/GAPS) verliert. Konvention:
# pro Collector setzt die jeweilige Funktion eine `COLLECTED_<NAME>`-Var
# auf das JSON-Array. Plus eine `*_json_on_stdout`-Variante fuer Tests
# (die nur das JSON brauchen, kein Tool-Tracking).
#
#   collect_listeners        --  setzt COLLECTED_LISTENERS
#   collect_processes        --  setzt COLLECTED_PROCESSES
#   collect_kernel_modules   --  setzt COLLECTED_KERNEL_MODULES
#   collect_services         --  setzt COLLECTED_SERVICES
#
# Plus eine Aggregator-Funktion `build_host_state_json`, die alle vier
# Collectors aufruft und den finalen `host_state`-Block als JSON-Object
# auf stdout schreibt.
#
# Tool-Verfuegbarkeit wird in den globalen Bash-Arrays `TOOLS_AVAILABLE`
# und `GAPS` getrackt. Beide werden von `build_host_state_json` resettet
# bevor die Collectors laufen.
#
# Sicherheits-Eigenschaften:
#   - `LC_ALL=C` in jedem Collector — keine Locale-induzierten Surprise-Bytes.
#   - JSON wird ausschliesslich ueber `jq @json`/`jq --arg/--argjson`
#     gebaut, kein String-Concat von User-Input (Process-args koennen
#     Sonderzeichen enthalten).
#   - Non-ASCII-Bytes werden in den Roh-Outputs vor dem JSON-Bau weggefiltert
#     (`tr -d` auf den 0x80-0xFF-Bereich). Das Backend rejected non-ASCII
#     ohnehin per Pydantic-Validator; der Agent verwirft pre-emptiv, damit
#     der ganze Snapshot nicht wegen einer Junk-Zeile durchfaellt.
#   - Limits aus ADR-0022 (Backend-Validator):
#       Listener:       max 4096 Eintraege
#       Processes:      max 4096 Eintraege
#       Kernel-Modules: max 1024
#       Services:       max 1024
#       tools/gaps:     max 32 Items je
#     Pro `args`-Feld: max 4096 Chars (Backend rejected laenger).
#     Pro Module-Name: max 64 Chars.
#     Pro Service-Name: max 128 Chars.
#
# Portabilitaet: nur POSIX-awk verwendet (kein `match(s, re, arr)` —
# das ist gawk-only und faellt auf BSD/Alpine-mawk durch). Regex-Capture
# laeuft ueber sed -E im umgebenden Shell-Wrapper.
#
# Requirements: bash >= 4, jq, awk, sed, tr, head, tail.
#

# Konstanten (read-only). Nur deklarieren wenn noch nicht gesetzt — damit
# die Library mehrfach sourcebar bleibt (z.B. in pytest-Subshells).
if [[ -z "${_LIB_HOST_STATE_LOADED:-}" ]]; then
  readonly _LIB_HOST_STATE_LOADED=1
  readonly LISTENERS_CAP=4096
  readonly PROCESSES_CAP=4096
  readonly KERNEL_MODULES_CAP=1024
  readonly SERVICES_CAP=1024
  readonly ARGS_MAX_LEN=4096
  readonly MODULE_NAME_MAX_LEN=64
  readonly SERVICE_NAME_MAX_LEN=128
fi

# ---------------------------------------------------------------------------
# Helper: ASCII-Filter (stdin -> stdout, Bytes >= 0x80 entfernen).
# ---------------------------------------------------------------------------
_strip_non_ascii() {
  LC_ALL=C tr -d '\200-\377'
}

# ---------------------------------------------------------------------------
# Helper: parse_addr_port
#
# Eingabe via stdin: eine Zeile mit `addr:port`-Token (IPv4, IPv6 mit/ohne
# eckigen Klammern, `*:port`). Ausgabe: `addr<TAB>port` auf stdout.
# Liefert leere Strings wenn nicht parsebar.
# ---------------------------------------------------------------------------
_parse_addr_port() {
  local token="$1"
  local addr="" port=""

  # IPv6 mit Klammern: [::]:22  -> addr=::  port=22
  if [[ "$token" =~ ^\[(.*)\]:([0-9]+)$ ]]; then
    addr="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
  else
    # Last ':' als Trenner — funktioniert fuer IPv4 (1.2.3.4:80) und fuer
    # bare-IPv6 wie ss-Output `::ffff:127.0.0.1:443` (selten, aber moeglich).
    port="${token##*:}"
    addr="${token%:*}"
    # `*` oder leer -> 0.0.0.0
    [[ "$addr" == "*" || -z "$addr" ]] && addr="0.0.0.0"
    # Interface-Suffix `%lo` etc. entfernen
    addr="${addr%%%*}"
  fi

  # Validate
  [[ "$port" =~ ^[0-9]+$ ]] || { printf ''; return; }
  (( port > 65535 )) && { printf ''; return; }
  printf '%s\t%s' "$addr" "$port"
}

# ---------------------------------------------------------------------------
# collect_listeners
#
# Bevorzugt `ss -tulnpH` (header-frei). Fallback: `netstat -tulnp`.
# Wenn weder vorhanden: leeres Array + Gap `listeners`.
#
# Output: JSON-Array `[{proto, addr, port, process, pid}]`.
# ---------------------------------------------------------------------------
collect_listeners() {
  COLLECTED_LISTENERS="[]"
  local raw=""
  local source=""

  if command -v ss >/dev/null 2>&1; then
    raw="$(LC_ALL=C ss -tulnpH 2>/dev/null || true)"
    [[ -n "$raw" ]] && source="ss"
  fi

  if [[ -z "$source" ]] && command -v netstat >/dev/null 2>&1; then
    raw="$(LC_ALL=C netstat -tulnp 2>/dev/null | awk 'NR>2 {print}' || true)"
    [[ -n "$raw" ]] && source="netstat"
  fi

  if [[ -z "$source" ]]; then
    GAPS+=("listeners")
    return 0
  fi

  TOOLS_AVAILABLE+=("$source")

  # Zwischenformat: pro Zeile 5 TAB-getrennte Felder
  #   proto<TAB>addr<TAB>port<TAB>process<TAB>pid
  # process/pid koennen leer sein. `jq -Rsc` baut daraus das finale JSON.
  local tsv=""
  local count=0
  local line
  while IFS= read -r line; do
    (( count >= LISTENERS_CAP )) && break
    # Strip non-ASCII per line
    line="$(printf '%s' "$line" | _strip_non_ascii)"
    [[ -z "$line" ]] && continue

    local proto="" local_token="" proc_name="" proc_pid=""

    if [[ "$source" == "ss" ]]; then
      # ss-Format (mit -H header-frei):
      #   "tcp  LISTEN 0 128 0.0.0.0:22  0.0.0.0:*  users:((...))"
      # oder ohne State-Spalte je nach iproute2-Version:
      #   "tcp  0 128 ..."  -- selten, aber moeglich.
      # Robust: erstes Token = proto; erstes Token das `:Ziffer` oder `:*` enthaelt = local-addr.
      # shellcheck disable=SC2206
      local fields=( $line )
      proto="${fields[0]}"
      local i
      for ((i = 0; i < ${#fields[@]}; i++)); do
        if [[ "${fields[i]}" =~ :[0-9]+$ ]] || [[ "${fields[i]}" =~ :\*$ ]]; then
          local_token="${fields[i]}"
          break
        fi
      done
      # `users:(("sshd",pid=1234,...))` extrahieren
      if [[ "$line" == *"users:"* ]]; then
        local extracted
        extracted="$(printf '%s' "$line" \
          | sed -nE 's/.*users:\(\("([^"]+)",pid=([0-9]+).*/\1|\2/p' \
          | head -1)"
        if [[ -n "$extracted" ]]; then
          proc_name="${extracted%%|*}"
          proc_pid="${extracted##*|}"
        fi
      fi
    else
      # netstat-Format:
      #   "tcp  0  0 0.0.0.0:22  0.0.0.0:*  LISTEN  1234/sshd"
      # shellcheck disable=SC2206
      local fields=( $line )
      proto="${fields[0]}"
      local_token="${fields[3]}"
      # Letztes Feld kann `pid/name` oder `-` sein
      local last="${fields[${#fields[@]}-1]}"
      if [[ "$last" =~ ^([0-9]+)/(.+)$ ]]; then
        proc_pid="${BASH_REMATCH[1]}"
        proc_name="${BASH_REMATCH[2]}"
      fi
    fi

    # Proto-Whitelist
    case "$proto" in
      tcp|udp|tcp6|udp6) ;;
      *) continue ;;
    esac

    [[ -z "$local_token" ]] && continue

    local addr_port addr port
    addr_port="$(_parse_addr_port "$local_token")"
    [[ -z "$addr_port" ]] && continue
    addr="${addr_port%%	*}"
    port="${addr_port##*	}"
    [[ -z "$addr" || -z "$port" ]] && continue

    # Process-Name auf 64 Chars trimmen
    [[ ${#proc_name} -gt 64 ]] && proc_name="${proc_name:0:64}"

    # Non-ASCII-Schutz: `line` ist bereits ASCII-gefiltert oben im Loop,
    # damit ist `addr` per Konstruktion ASCII. IP-Literal-Validierung
    # erfolgt im Backend-Pydantic-Validator — der Agent waere nicht
    # zustaendig, hier ipaddress.ip_address-aequivalent zu implementieren.

    printf -v tsv_line '%s\t%s\t%s\t%s\t%s' "$proto" "$addr" "$port" "$proc_name" "$proc_pid"
    tsv+="${tsv_line}"$'\n'
    count=$((count + 1))
  done <<< "$raw"

  if [[ -z "$tsv" ]]; then
    return 0
  fi

  # jq baut das finale JSON aus dem TSV. `--raw-input --slurp` liest alles
  # ein, dann `split` + `map` mit pro-Feld JSON-Bau ueber das Objekt-Literal.
  local result
  result="$(printf '%s' "$tsv" | jq -Rsc '
    split("\n")
    | map(select(length > 0))
    | map(split("\t"))
    | map({
        proto: .[0],
        addr: .[1],
        port: (.[2] | tonumber),
        process: (if (.[3] // "") == "" then null else .[3] end),
        pid: (if (.[4] // "") == "" then null else (.[4] | tonumber) end)
      })
  ' 2>/dev/null)" || result="[]"
  [[ -n "$result" ]] && COLLECTED_LISTENERS="$result"
}

# ---------------------------------------------------------------------------
# collect_processes
#
# Quelle: `ps -eo pid=,user=,comm=,args=`. Die `=`-Form unterdrueckt den
# Header. Fallback: Long-Form mit `awk NR>1`-Header-Filter (BusyBox-ps).
# Wenn `ps` komplett fehlt: leeres Array + Gap `processes`.
# ---------------------------------------------------------------------------
collect_processes() {
  COLLECTED_PROCESSES="[]"
  if ! command -v ps >/dev/null 2>&1; then
    GAPS+=("processes")
    return 0
  fi

  local raw
  raw="$(LC_ALL=C ps -eo pid=,user=,comm=,args= 2>/dev/null || true)"
  if [[ -z "$raw" ]]; then
    raw="$(LC_ALL=C ps -e -o pid,user,comm,args 2>/dev/null \
      | awk 'NR>1 {print}' || true)"
  fi

  if [[ -z "$raw" ]]; then
    GAPS+=("processes")
    return 0
  fi

  TOOLS_AVAILABLE+=("ps")

  # Parser: erstes Token = pid, zweites = user, drittes = comm, Rest = args.
  # Wir filtern Non-ASCII per Zeile und cappen Laengen. Ausgabe als
  # TAB-getrennte Felder; jq baut JSON.
  local tsv
  tsv="$(printf '%s\n' "$raw" \
    | _strip_non_ascii \
    | awk -v cap="$PROCESSES_CAP" -v argmax="$ARGS_MAX_LEN" '
        BEGIN { n = 0 }
        {
          if (NF == 0) next
          if ($1 !~ /^[0-9]+$/) next
          pid = $1
          user = $2
          comm = $3
          args = ""
          for (i = 4; i <= NF; i++) {
            if (i == 4) args = $i
            else args = args " " $i
          }

          # Trim
          gsub(/^[ \t]+|[ \t]+$/, "", user)
          gsub(/^[ \t]+|[ \t]+$/, "", comm)
          gsub(/^[ \t]+|[ \t]+$/, "", args)

          # Length-Caps (Backend-Limits)
          if (length(user) > 32) user = substr(user, 1, 32)
          if (length(comm) > 64) comm = substr(comm, 1, 64)
          if (length(args) > argmax) args = substr(args, 1, argmax)

          if (n >= cap) next
          # TAB als Feld-Trenner, NL als Zeilen-Trenner. Wenn args selbst
          # ein TAB enthielte, wuerde der Split bei jq schiefgehen — wir
          # entfernen TABs aus args pre-emptiv (selten in cmdlines).
          gsub(/\t/, " ", args)
          printf "%d\t%s\t%s\t%s\n", pid, user, comm, args
          n++
        }
      ')"

  if [[ -z "$tsv" ]]; then
    return 0
  fi

  local result
  result="$(printf '%s' "$tsv" | jq -Rsc '
    split("\n")
    | map(select(length > 0))
    | map(split("\t"))
    | map({
        pid:  (.[0] | tonumber),
        user: (if (.[1] // "") == "" then null else .[1] end),
        comm: (if (.[2] // "") == "" then null else .[2] end),
        args: (if (.[3] // "") == "" then null else .[3] end)
      })
  ' 2>/dev/null)" || result="[]"
  [[ -n "$result" ]] && COLLECTED_PROCESSES="$result"
}

# ---------------------------------------------------------------------------
# collect_kernel_modules
#
# Quelle: `lsmod`. Erste Zeile ist Header (`Module Size Used by`) — wird
# via `tail -n +2` uebersprungen. Wenn `lsmod` fehlt: leeres Array + Gap.
# ---------------------------------------------------------------------------
collect_kernel_modules() {
  COLLECTED_KERNEL_MODULES="[]"
  if ! command -v lsmod >/dev/null 2>&1; then
    GAPS+=("kernel_modules")
    return 0
  fi

  local raw
  raw="$(LC_ALL=C lsmod 2>/dev/null | tail -n +2 || true)"

  if [[ -z "$raw" ]]; then
    GAPS+=("kernel_modules")
    return 0
  fi

  TOOLS_AVAILABLE+=("lsmod")

  local result
  result="$(printf '%s\n' "$raw" \
    | _strip_non_ascii \
    | awk -v cap="$KERNEL_MODULES_CAP" -v maxlen="$MODULE_NAME_MAX_LEN" '
        BEGIN { n = 0 }
        {
          if (NF == 0) next
          name = $1
          if (length(name) == 0) next
          if (length(name) > maxlen) next
          if (n >= cap) next
          print name
          n++
        }
      ' \
    | jq -Rsc 'split("\n") | map(select(length > 0))' 2>/dev/null)" || result="[]"
  [[ -n "$result" ]] && COLLECTED_KERNEL_MODULES="$result"
}

# ---------------------------------------------------------------------------
# collect_services
#
# Quelle: `systemctl list-units --type=service --state=active --no-legend
# --no-pager --plain`. Erste Spalte = Unit-Name. Wenn `systemctl` fehlt:
# leeres Array + Gap.
# ---------------------------------------------------------------------------
collect_services() {
  COLLECTED_SERVICES="[]"
  if ! command -v systemctl >/dev/null 2>&1; then
    GAPS+=("services")
    return 0
  fi

  local raw
  raw="$(LC_ALL=C systemctl list-units --type=service --state=active \
    --no-legend --no-pager --plain 2>/dev/null || true)"

  TOOLS_AVAILABLE+=("systemctl")

  if [[ -z "$raw" ]]; then
    # systemctl da, aber keine aktiven Services (Container-Edge-Case).
    # Tool ist verfuegbar, kein Gap, Liste leer.
    return 0
  fi

  local result
  result="$(printf '%s\n' "$raw" \
    | _strip_non_ascii \
    | awk -v cap="$SERVICES_CAP" -v maxlen="$SERVICE_NAME_MAX_LEN" '
        BEGIN { n = 0 }
        {
          if (NF == 0) next
          name = $1
          if (length(name) == 0) next
          if (length(name) > maxlen) next
          if (n >= cap) next
          print name
          n++
        }
      ' \
    | jq -Rsc 'split("\n") | map(select(length > 0))' 2>/dev/null)" || result="[]"
  [[ -n "$result" ]] && COLLECTED_SERVICES="$result"
}

# ---------------------------------------------------------------------------
# build_host_state_json
#
# Setzt `TOOLS_AVAILABLE`/`GAPS` zurueck, ruft alle vier Collectors und
# baut das finale `host_state`-JSON-Object auf stdout.
# ---------------------------------------------------------------------------
build_host_state_json() {
  TOOLS_AVAILABLE=()
  GAPS=()
  COLLECTED_LISTENERS="[]"
  COLLECTED_PROCESSES="[]"
  COLLECTED_KERNEL_MODULES="[]"
  COLLECTED_SERVICES="[]"

  # Direkt-Aufruf, kein `$(...)` — Collectors muessen die globalen
  # TOOLS_AVAILABLE/GAPS-Arrays mutieren koennen (Subshells haetten
  # ihre eigenen Kopien).
  collect_listeners
  collect_processes
  collect_kernel_modules
  collect_services

  local snapshot_at
  snapshot_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  local tools_json gaps_json
  if [[ ${#TOOLS_AVAILABLE[@]} -eq 0 ]]; then
    tools_json="[]"
  else
    tools_json="$(printf '%s\n' "${TOOLS_AVAILABLE[@]}" \
      | jq -Rsc 'split("\n") | map(select(length > 0))')"
  fi

  if [[ ${#GAPS[@]} -eq 0 ]]; then
    gaps_json="[]"
  else
    gaps_json="$(printf '%s\n' "${GAPS[@]}" \
      | jq -Rsc 'split("\n") | map(select(length > 0))')"
  fi

  jq -nc \
    --arg snapshot_at "$snapshot_at" \
    --argjson tools_available "$tools_json" \
    --argjson gaps "$gaps_json" \
    --argjson listeners "$COLLECTED_LISTENERS" \
    --argjson processes "$COLLECTED_PROCESSES" \
    --argjson kernel_modules "$COLLECTED_KERNEL_MODULES" \
    --argjson services "$COLLECTED_SERVICES" \
    '{
      snapshot_at: $snapshot_at,
      tools_available: $tools_available,
      gaps: $gaps,
      listeners: $listeners,
      processes: $processes,
      kernel_modules: $kernel_modules,
      services: $services
    }'
}
