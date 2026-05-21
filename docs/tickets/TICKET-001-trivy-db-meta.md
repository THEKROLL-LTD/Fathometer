# TICKET-001 — Trivy-DB-Metadaten persistieren + Agent-Auto-Update

**Status:** Offen
**Komponenten:** ``agent/secscan-agent.sh`` + ``app/schemas/scan_envelope.py`` + ``app/services/findings_ingest.py``
**Umfang:** End-to-End. Drei Themen in einem Ticket weil sie alle den Agent betreffen und gemeinsam ausgerollt werden muessen (sonst kann der Trivy-DB-Fix die alten Agents nie erreichen).

## Problem

Production-Bug 2026-05-21: Server-Detail-Seite zeigt "trivy-db stale", obwohl die Trivy-DB auf dem Agent-Host frisch ist (lt. ``trivy version`` lokal: ``UpdatedAt: 2026-05-21 01:03:33 UTC``, ~6h alt).

Ursache: Trivy 0.70 schreibt ``DataSource``/``UpdatedAt`` nur **pro Vulnerability** im Scan-JSON, nicht im Top-Level ``scan.Metadata``. Der Ingest-Pfad (``app/services/findings_ingest.py:447-454``) liest aber genau nur Top-Level — bleibt NULL → ``servers.trivy_db_version`` / ``trivy_db_updated_at`` NULL → UI-Stale-Check triggert false-positive.

Verifiziert in der DB: beide Spalten sind ``NULL``, obwohl ``trivy_version`` (CLI-Version, nicht DB-Version) korrekt mit ``0.70.0`` persistiert ist.

## Loesung — Schnittstelle

Neuer Top-Level-Envelope-Block, vom Agent aus ``trivy version --format json`` gebaut:

```json
{
  "agent_version": "0.3.1",
  "host": { ... },
  "scan": { ... },
  "host_state": { ... },
  "trivy_db": {
    "version": "2",
    "updated_at": "2026-05-21T01:03:33Z",
    "next_update_at": "2026-05-22T01:03:33Z",
    "downloaded_at": "2026-05-21T06:24:41Z"
  }
}
```

``trivy_db`` darf fehlen / ``null`` sein (alte Agents <0.3.1, oder Trivy ohne ``version --format json``-Support). Alle vier Felder einzeln nullable.

## Implementierungs-Plan

### 0. Agent — Auto-Update (NEU, lauft als erstes vor jedem Scan)

**Motivation:** Damit der Trivy-DB-Meta-Fix (Schritt 1) auch bei bestehenden
Deployments wirksam wird ohne Operator-Interaktion. Ab dieser Version
checkt der Agent bei jedem Run ob es eine neuere Version gibt und
ersetzt sich selbst.

**Rollout-Entscheidung 2026-05-21:** Bestehende Agents <0.3.1 haben noch
keinen Auto-Update-Code und koennen sich daher nicht selbst auf 0.3.1 heben.
Der Operator aktualisiert alle bestehenden Hosts einmalig manuell auf 0.3.1.
Ab 0.3.1 gilt dann: zukuenftige Agent-Versionen werden automatisch gezogen.

**Vorhandene Server-Endpunkte** (kein Backend-Aufwand noetig):

- ``GET $SECSCAN_URL/agent/version`` → JSON mit ``current_agent_version``,
  ``min_agent_version`` (siehe ``app/views/agent_install.py:50``).
- ``GET $SECSCAN_URL/agent/files/secscan-agent.sh`` → liefert den
  aktuellen Skript-Text (siehe ``app/views/agent_install.py:66``).
- ``GET $SECSCAN_URL/agent/files/lib_host_state.sh`` → analog fuer den
  Block-O-Helfer (falls Agent ihn nutzt).

**Pseudo-Code** (ans Ende der Variablen-Definitionen, vor dem ``trivy``-
Aufruf in ``secscan-agent.sh``):

```bash
# ---- Auto-Update-Check (Block N+ / TICKET-001) ----------------------------
# Lauft VOR dem Scan. Bei Failure (Netz weg, Server down, Hash mismatch)
# laeuft der bestehende Agent unveraendert weiter — Update wird beim
# naechsten Cron-Run nochmal versucht.
#
# Re-Exec-Guard: ``SECSCAN_AGENT_UPDATED=1`` wird vor exec gesetzt;
# beim Re-Exec ueberspringen wir den Check (kein Endlos-Loop wenn ein
# Bug zu unstoppbarer Re-Exec-Schleife fuehren wuerde).
auto_update_self() {
  if [[ "${SECSCAN_AGENT_UPDATED:-0}" = "1" ]]; then
    return 0  # bereits in dieser Run-Chain aktualisiert
  fi
  if [[ -z "${SECSCAN_URL:-}" ]]; then
    return 0  # kein Server konfiguriert
  fi

  local ver_json server_version
  ver_json="$(curl -fsS --max-time 5 "$SECSCAN_URL/agent/version" 2>/dev/null || true)"
  if [[ -z "$ver_json" ]]; then
    log "Auto-Update: server unreachable, skipping (laufe mit aktueller Version)"
    return 0
  fi

  server_version="$(printf '%s' "$ver_json" | jq -r '.current_agent_version // empty' 2>/dev/null)"
  if [[ -z "$server_version" ]] || [[ "$server_version" = "$AGENT_VERSION" ]]; then
    return 0  # gleicher Stand oder Server liefert keine Version
  fi
  if ! version_lt "$AGENT_VERSION" "$server_version"; then
    log "Auto-Update: Server-Version $server_version ist nicht neuer als lokal $AGENT_VERSION, skipping"
    return 0
  fi

  log "Auto-Update: Server-Version $server_version, lokal $AGENT_VERSION → update"

  local tmpfile self_path self_dir lib_path
  self_path="$(readlink -f "$0")"
  self_dir="$(dirname "$self_path")"
  lib_path="$self_dir/lib_host_state.sh"
  tmpfile="$(mktemp -t secscan-agent.XXXXXX.sh)"

  if ! curl -fsS --max-time 30 -o "$tmpfile" "$SECSCAN_URL/agent/files/secscan-agent.sh"; then
    log "Auto-Update: Download failed, halte aktuelle Version"
    rm -f "$tmpfile"
    return 0
  fi

  # Sanity: heruntergeladene Datei beginnt mit Shebang und traegt die erwartete Version.
  if ! head -1 "$tmpfile" | grep -q '^#!/'; then
    log "Auto-Update: ungueltige Skript-Datei (kein Shebang), halte aktuelle Version"
    rm -f "$tmpfile"
    return 0
  fi
  if ! grep -q "AGENT_VERSION=\"$server_version\"" "$tmpfile"; then
    log "Auto-Update: heruntergeladene Datei meldet nicht Version $server_version, halte aktuelle Version"
    rm -f "$tmpfile"
    return 0
  fi

  # Helper-Datei (lib_host_state.sh) parallel ziehen + validieren.
  # Wichtig: ein partieller Replace ist NICHT scan-brechend, weil der
  # Agent beim Sourcen die Helper-Version gegen REQUIRED_LIB_HOST_STATE_VERSION
  # prueft und bei Mismatch host_state einfach omit'et (siehe §"Helper-
  # Compatibility-Check"). Deshalb reicht "best effort"-Replace ohne
  # Rollback-Choreographie.
  local lib_tmp=""
  if [[ -f "$lib_path" ]]; then
    lib_tmp="$(mktemp -t lib_host_state.XXXXXX.sh)"
    if ! curl -fsS --max-time 30 -o "$lib_tmp" "$SECSCAN_URL/agent/files/lib_host_state.sh" 2>/dev/null; then
      log "Auto-Update: Helper-Download failed, ueberspringe Helper-Replace"
      rm -f "$lib_tmp"
      lib_tmp=""
    elif ! head -1 "$lib_tmp" | grep -q '^#!/'; then
      log "Auto-Update: ungueltige Helper-Datei (kein Shebang), ueberspringe Helper-Replace"
      rm -f "$lib_tmp"
      lib_tmp=""
    fi
  fi

  # Backup vor Replace (Operator-Recovery via *.bak-Files).
  cp -p "$self_path" "$self_path.bak" 2>/dev/null || true
  if [[ -n "$lib_tmp" ]]; then
    cp -p "$lib_path" "$lib_path.bak" 2>/dev/null || true
    chmod +x "$lib_tmp"
    if ! mv "$lib_tmp" "$lib_path"; then
      log "Auto-Update: Helper-Replace failed, fahre nur mit Agent-Replace fort"
      rm -f "$lib_tmp"
    fi
  fi

  chmod +x "$tmpfile"
  if ! mv "$tmpfile" "$self_path"; then
    log "Auto-Update: atomic-replace failed (Permissions?), halte aktuelle Version"
    rm -f "$tmpfile"
    return 0
  fi

  log "Auto-Update: erfolgreich auf $server_version, re-exec"
  export SECSCAN_AGENT_UPDATED=1
  exec "$self_path" "$@"
}

auto_update_self "$@"
```

**Bash-Helper ``version_lt``** — strikter SemVer-Compare, fail-safe gegen unerwartetes Server-Format:

```bash
# Returns 0 if $1 < $2, else 1. Strikt SemVer-Form (major.minor.patch mit
# optionalem rc-Pre-Release/Build), unbekanntes Format -> nicht-kleiner (=
# kein Update). Pure Bash, damit der Agent keine Python-Abhaengigkeit bekommt
# und auf macOS nicht an fehlendem `sort -V` scheitert.
version_lt() {
  local semver_re='^([0-9]+)\.([0-9]+)\.([0-9]+)(-rc\.?([0-9]+))?([.+-][A-Za-z0-9._-]+)?$'
  [[ "$1" =~ $semver_re ]] || return 1
  local a_major="${BASH_REMATCH[1]}" a_minor="${BASH_REMATCH[2]}" a_patch="${BASH_REMATCH[3]}" a_rc="${BASH_REMATCH[5]:-}"
  [[ "$2" =~ $semver_re ]] || return 1
  local b_major="${BASH_REMATCH[1]}" b_minor="${BASH_REMATCH[2]}" b_patch="${BASH_REMATCH[3]}" b_rc="${BASH_REMATCH[5]:-}"
  [[ "$1" = "$2" ]] && return 1
  # Danach: major/minor/patch numerisch vergleichen; bei gleicher Basis gilt rc < final.
  # Vollstaendige Implementierung im Skript.
}
```

Whitelist-Regex schuetzt gegen Server-Output-Drift (z.B. wenn jemand
``current_agent_version`` auf einen Branch-Namen setzt). Der Helper deckt
unsere Agent-Versionen ab: ``major.minor.patch``, optional ``-rc.N`` und
Build-/Suffix-Text, wobei bei gleicher Basisversion nur ``rc`` eine
Update-Entscheidung beeinflusst.

**Wo aufrufen:** direkt nach den ``require_cmd``-Checks und nach dem
``trivy_version="$(...)"``-Block, **vor** dem Scan. ``exec`` ersetzt den
aktuellen Process — alles danach laeuft erst nach dem Re-Exec im neuen
Skript-Inhalt mit ``SECSCAN_AGENT_UPDATED=1``.

**Version-Vergleich:** Der Agent aktualisiert nur wenn
``AGENT_VERSION < current_agent_version``. Unterschiedliche, aber nicht
neuere Server-Versionen (Rollback, falsche Deploy-Konstante, Pre-Release-
Drift) duerfen kein Downgrade/Replace ausloesen. Dafuer bekommt das
Agent-Skript einen kleinen Bash-Helper ``version_lt`` analog zur Backend-
SemVer-Logik in ``app/services/agent_version.py``.

**Pfad-Aufloesung:** Linux-Produktion kann ``readlink -f`` nutzen. Fuer
lokale Tests auf macOS/Darwin braucht die Implementierung einen Fallback
ueber ``cd "$(dirname "$0")" && pwd`` + ``basename "$0"``.

**Sicherheit / Beschraenkungen:**

- HTTPS via ``$SECSCAN_URL`` (existierende Variable, vom Operator beim
  Initial-Install gesetzt). Kein zusaetzlicher TLS-Pin im MVP.
- Kein Server-Auth fuer den Download (``/agent/files/...`` ist heute
  un-authenticated — das ist Block-N-Designentscheidung weil der
  Bootstrap-Installer auch ohne Auth den Agent ziehen muss).
- Kein Hash-Verify im MVP. Falls spaeter gewuenscht: Server liefert
  ``X-Content-SHA256``-Header im ``/agent/files/...``-Response,
  Agent vergleicht. Nicht in diesem Ticket.
- Failure-Modes: jede Stufe (Netz / Download / Sanity-Check / Helper-
  Replace / Agent-Replace / Re-Exec)
  schluckt Fehler und laeuft mit der alten Version weiter. Idempotent
  — naechster Cron-Run versucht's nochmal.
- Reihenfolge beim Replace: erst ``lib_host_state.sh``-Replace (best
  effort, kein Abort wenn das failt), dann ``secscan-agent.sh``-
  Replace. Partieller Replace (neuer Agent + alter Helper, oder umgekehrt)
  ist nicht scan-brechend weil der Agent beim Sourcen die Helper-Version
  prueft (siehe §"Helper-Compatibility-Check") und bei Mismatch
  ``host_state`` einfach omit'et.

**Self-Re-Exec funktioniert** weil ``exec`` den aktuellen Prozess
ersetzt; Bash hat das alte Skript bereits in den Speicher geladen,
``mv`` aendert nur den Pfad-Eintrag (Inode-Replace), der Re-Exec liest
den neuen Inhalt vom Pfad. Falls Re-Exec aus einem Grund nicht laeuft
(z.B. Skript ist nicht executable nach Replace), bleibt die alte Version
im RAM und schreibt den Update beim naechsten Cron-Run.

### 0.1 Helper-Compatibility-Check (``lib_host_state.sh``)

Damit partielle Replaces im Auto-Update keine scan-brechende Inkompatibilitaet
ausloesen, fuehren wir ein expliziter Versions-Pakt zwischen Agent und Helper-
Lib ein:

- ``agent/lib_host_state.sh`` deklariert oben: ``readonly LIB_HOST_STATE_VERSION="0.3.1"``.
  Bei jedem semantik-relevanten Aenderung der Helper-API muss dieser Wert
  gebumpt werden (Konvention: synchron mit ``AGENT_VERSION``, kann aber
  zurueckbleiben falls Helper unveraendert).
- ``secscan-agent.sh`` deklariert oben: ``readonly REQUIRED_LIB_HOST_STATE_VERSION="0.3.1"``.
- Nach dem ``source``/``.`` der Lib (oder vor dem Aufruf der ersten Helper-
  Funktion) pruefen:

  ```bash
  if [[ "$_has_host_state_lib" -eq 1 ]]; then
    if [[ -z "${LIB_HOST_STATE_VERSION:-}" ]] || [[ "$LIB_HOST_STATE_VERSION" != "$REQUIRED_LIB_HOST_STATE_VERSION" ]]; then
      log "Warning: lib_host_state.sh version mismatch (need=$REQUIRED_LIB_HOST_STATE_VERSION, found=${LIB_HOST_STATE_VERSION:-missing}); host_state wird omit'et"
      _has_host_state_lib=0
    fi
  fi
  ```

Drei Faelle:

| Lib-Status | Verhalten |
|---|---|
| nicht vorhanden | wie heute: ``_has_host_state_lib=0``, ``host_state`` omit |
| vorhanden, Version stimmt | normal nutzen |
| vorhanden, Version fehlt oder mismatch | Warning-Log, ``_has_host_state_lib=0``, ``host_state`` omit (nicht fatal) |

Vorteil: Auto-Update darf Helper und Agent in beliebiger Reihenfolge ersetzen.
Wenn nur eins der beiden Files erfolgreich gewechselt wurde, faellt der Scan
nicht aus — er liefert lediglich kein ``host_state``-Block bis beim naechsten
Cron-Run der Replace komplett ist.

### 1. Agent (``agent/secscan-agent.sh``)

Nach dem bestehenden ``trivy --version``-Aufruf (Zeile ~127) zusaetzlich:

```bash
trivy_db_meta_raw="$("$TRIVY_BIN" version --format json 2>/dev/null || echo '')"
trivy_db_block="null"
if [[ -n "$trivy_db_meta_raw" ]] && printf '%s' "$trivy_db_meta_raw" | jq -e '.VulnerabilityDB' >/dev/null 2>&1; then
  trivy_db_block="$(printf '%s' "$trivy_db_meta_raw" | jq -c '{
    version: (.VulnerabilityDB.Version | tostring),
    updated_at: .VulnerabilityDB.UpdatedAt,
    next_update_at: .VulnerabilityDB.NextUpdate,
    downloaded_at: .VulnerabilityDB.DownloadedAt
  }')"
  log "Trivy-DB meta: version=$(jq -r .version <<<"$trivy_db_block") updated_at=$(jq -r .updated_at <<<"$trivy_db_block")"
else
  log "Warning: trivy version --format json lieferte keine VulnerabilityDB-Daten, trivy_db wird als null gesendet"
fi
```

Im bestehenden ``jq -n``-Envelope-Build (Zeile ~189):

```bash
payload="$(jq -n \
  ...
  --argjson trivy_db "$trivy_db_block" \
  '{
    agent_version: $agent_version,
    host: { ... },
    scan: $scan[0],
    host_state: $host_state,
    trivy_db: $trivy_db
  }')"
```

Agent-Version-Bump: ``readonly AGENT_VERSION="0.3.1"`` oben in der Datei.

### 1a. Backend — Agent-Version-Konstante

In ``app/config.py`` muss die Server-seitig ausgelieferte Version im selben
Commit mitgezogen werden:

```python
CURRENT_AGENT_VERSION: ClassVar[str] = "0.3.1"
```

``MIN_AGENT_VERSION`` bleibt unveraendert bei ``0.1.0``. Alte Agents werden
nicht serverseitig ausgesperrt; der Operator aktualisiert sie fuer dieses
Ticket sofort manuell auf 0.3.1.

### 2. Backend — Pydantic-Schema (``app/schemas/scan_envelope.py``)

Vor der ``Envelope``-Klasse neu:

```python
class TrivyDbBlock(BaseModel):
    """Top-Level ``trivy_db``-Block aus dem Envelope (Agent >= 0.3.1).

    Trivy schreibt ``DataSource``/``UpdatedAt`` nur pro Vulnerability in
    ``Results[].Vulnerabilities[]``, nicht im Top-Level ``scan.Metadata``.
    Der Agent extrahiert die echten DB-Metadaten aus
    ``trivy version --format json`` und sendet sie als separater
    Top-Level-Block.
    """

    model_config = ConfigDict(extra="ignore")

    version: str | None = Field(default=None, max_length=32)
    updated_at: datetime | None = None
    next_update_at: datetime | None = None
    downloaded_at: datetime | None = None
```

In der ``Envelope``-Klasse:

```python
class Envelope(BaseModel):
    ...
    trivy_db: TrivyDbBlock | None = Field(default=None)
```

``__all__`` um ``"TrivyDbBlock"`` erweitern.

### 3. Backend — Ingest-Pfad (``app/services/findings_ingest.py``)

In ``ingest_scan`` (Zeile ~442-470), vor dem bestehenden ``metadata.data_source``-Fallback:

```python
trivy_db_version: str | None = None
trivy_db_updated_at: datetime | None = None

# Phase 1: bevorzugt Top-Level trivy_db-Block (Agent >= 0.3.1).
if envelope.trivy_db is not None:
    if envelope.trivy_db.version:
        trivy_db_version = envelope.trivy_db.version
    if envelope.trivy_db.updated_at:
        trivy_db_updated_at = envelope.trivy_db.updated_at

# Phase 2: Fallback auf scan.Metadata.DataSource (alte Agents <0.3.1).
# Wenn der neue Block schon Werte geliefert hat, NICHT ueberschreiben.
if trivy_db_version is None or trivy_db_updated_at is None:
    metadata = envelope.scan.metadata
    if metadata is not None:
        if trivy_db_version is None and metadata.data_source is not None:
            trivy_db_version = metadata.data_source.name or metadata.data_source.id
        if trivy_db_updated_at is None and metadata.updated_at is not None:
            trivy_db_updated_at = metadata.updated_at
```

### 4. Tests

**Agent (Bash-Unit-Tests):** vier neue Test-Files (Bash-Skripte mit ``set -e`` + Asserts, Stub-Binaries per ``PATH``-Manipulation):

``tests/agent/test_trivy_db_meta_extraction.sh``:

1. Happy: ``trivy version --format json`` liefert vollstaendigen Output → ``trivy_db_block`` enthaelt alle 4 Felder.
2. Trivy-Binary fehlt → ``trivy_db_block=null``, Scan laeuft trotzdem.
3. ``trivy version --format json`` liefert leeren String → ``trivy_db_block=null``.
4. ``trivy version --format json`` liefert JSON OHNE ``VulnerabilityDB``-Key → ``trivy_db_block=null``.
5. Envelope-Build mit ``trivy_db_block=null`` produziert valides JSON.
6. Envelope-Build mit gefuelltem ``trivy_db_block`` produziert valides JSON.

``tests/agent/test_auto_update.sh``:

1. ``SECSCAN_AGENT_UPDATED=1`` → Update-Check wird sofort uebersprungen.
2. ``SECSCAN_URL`` unset → Check wird uebersprungen ohne Fehler.
3. ``$SECSCAN_URL/agent/version`` liefert HTTP-Error → kein Update, kein Crash, Log-Eintrag.
4. ``$SECSCAN_URL/agent/version`` liefert ``current_agent_version`` gleich ``AGENT_VERSION`` → kein Update.
5. ``$SECSCAN_URL/agent/version`` liefert aeltere/nicht-neuere Version → kein Downgrade/Replace.
6. ``$SECSCAN_URL/agent/version`` liefert neuere Version, Download failed → kein Replace, Log-Eintrag.
7. ``$SECSCAN_URL/agent/version`` liefert neuere Version, Download ohne Shebang → kein Replace.
8. ``$SECSCAN_URL/agent/version`` liefert neuere Version, Download hat falsche ``AGENT_VERSION`` → kein Replace.
9. Happy mit Helper: neue Version, Helper-Download OK, beide Replaces OK, Backup-Files (``.bak``) angelegt, ``exec`` mit ``SECSCAN_AGENT_UPDATED=1``.
10. Helper-Download failed, Agent-Download OK → nur Agent ersetzt, ``host_state`` beim naechsten Run omit (Compat-Check).
11. Helper-Replace OK, Agent-Replace failed → Helper neu, Agent alt, ``.bak``-Files vorhanden, return ohne Re-Exec (alter Agent laeuft weiter).
12. Backup-File-Check: nach Replace existieren ``$self_path.bak`` und ggf. ``$lib_path.bak`` mit dem alten Inhalt (Operator-Recovery moeglich).

Mock-Strategie: lokaler HTTP-Server (Python ``http.server``) der gewuenschte Antworten liefert; ``SECSCAN_URL`` auf ``http://localhost:<port>`` setzen. ``exec``-Test via Stub-Self-Skript das ``echo "UPDATED"`` macht und exit. Replace-Failure simulieren via ``chmod -w "$self_dir"`` zwischen Helper- und Agent-Replace.

``tests/agent/test_version_lt.sh``:

1. ``version_lt "0.3.0" "0.3.1"`` → 0 (true).
2. ``version_lt "0.3.1" "0.3.0"`` → 1 (false).
3. ``version_lt "0.3.1" "0.3.1"`` → 1 (gleich → nicht-kleiner).
4. ``version_lt "0.3.1-rc.1" "0.3.1"`` → 0 (Pre-Release < Release).
5. ``version_lt "0.3.99" "0.4.0"`` → 0.
6. ``version_lt "branch-name" "0.3.1"`` → 1 (whitelist-reject → nicht-kleiner, kein Update).
7. ``version_lt "0.3.1" "branch-name"`` → 1 (analog).
8. ``version_lt "" "0.3.1"`` → 1 (leerer String reject).

``tests/agent/test_lib_host_state_compat.sh``:

1. Helper fehlt → ``_has_host_state_lib=0``, ``host_state`` omit, kein Warning-Log.
2. Helper vorhanden mit passender ``LIB_HOST_STATE_VERSION`` → normal genutzt.
3. Helper vorhanden, ``LIB_HOST_STATE_VERSION`` fehlt → Warning-Log, ``_has_host_state_lib=0``, Scan laeuft weiter.
4. Helper vorhanden, ``LIB_HOST_STATE_VERSION="0.2.9"`` (alt) und Agent erwartet ``0.3.1`` → Warning-Log, ``_has_host_state_lib=0``, Scan laeuft weiter.
5. Envelope nach Mismatch-Fall hat ``host_state=null``, ist valides JSON.

**Backend (Pure-Unit, kein DB):** neue Tests in ``tests/services/test_findings_ingest.py`` (schon im ``_MOCKED_UNIT_FILES``):

1. ``trivy_db``-Block voll → ``trivy_db_version``, ``trivy_db_updated_at`` korrekt extrahiert.
2. ``trivy_db=None`` + ``scan.Metadata.DataSource`` voll → Fallback greift.
3. ``trivy_db=None`` + ``scan.Metadata=None`` → beide Werte NULL.
4. ``trivy_db.updated_at=None`` + ``Metadata.updated_at`` voll → Mischung (Fallback nur fuer fehlende Felder).
5. ``Envelope.model_validate({"trivy_db": {...}})`` haengt nicht.
6. Adversarial: ``trivy_db`` mit unbekannten Extra-Feldern → ``extra="ignore"`` schluckt sie.

### 5. Doku

- ``CHANGELOG.md``: Eintrag unter ``[Unreleased]``: "Trivy-DB-Metadaten ab Agent 0.3.1 korrekt persistiert. Alte Agents (≤0.3.0) bleiben funktional; deren ``trivy_db_*``-Spalten bleiben NULL."
- ``docs/operations.md``: kurzer Hinweis im Agent-Update-Block.

## Definition-of-Done

1. Agent-Code (Auto-Update + Trivy-DB-Meta-Build) + Envelope-Schema + Ingest-Pfad implementiert.
2. ``AGENT_VERSION=0.3.1``.
3. ``Settings.CURRENT_AGENT_VERSION=0.3.1``.
4. ``MIN_AGENT_VERSION`` bleibt ``0.1.0``.
5. Bash-Unit-Tests gruen (Trivy-DB-Meta + Auto-Update + version_lt + lib_host_state-Compat).
6. 6 neue Backend-Unit-Tests gruen.
7. Bestehende Pure-Unit-Suite (``pytest -m "not todo_mock and not acceptance and not bench and not integration" -q``) bleibt gruen.
8. ``ruff check . && ruff format --check .`` clean.
9. ``mypy --strict app/services/findings_ingest.py app/schemas/scan_envelope.py`` keine neuen Errors.
10. CHANGELOG + operations.md (inkl. Hinweis: bestehende Agents werden einmalig manuell auf 0.3.1 aktualisiert; ab 0.3.1 self-updating, kein manuelles Reinstall fuer Folgeversionen mehr noetig).

## NICHT in diesem Ticket

- ``stale_trivy_db_threshold_h``-Tuning (bleibt 30h Default).
- UI-Aenderung an der Stale-Pill (zeigt automatisch korrekt sobald Spalten gefuellt sind).
- ``next_update_at`` / ``downloaded_at`` als eigene DB-Spalten (Schema-Migration). Beide Felder sind im Envelope fuer Forward-Compat enthalten, MVP persistiert nur ``version`` + ``updated_at``.
