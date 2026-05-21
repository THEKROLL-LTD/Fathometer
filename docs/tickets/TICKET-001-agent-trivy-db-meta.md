# TICKET-001 — Agent: Trivy-DB-Metadaten in den Envelope einbauen

**Status:** Offen
**Komponente:** `agent/secscan-agent.sh`
**Abhaengigkeit:** parallel zu TICKET-002 (Server-Seite). Beide muessen sich auf das gleiche Envelope-Schema einigen — siehe §"Schnittstelle".

## Problem

Production-Bug 2026-05-21: Server-Detail-Seite zeigt "trivy-db stale", obwohl die Trivy-DB auf dem Agent-Host aktuell ist (lt. ``trivy version`` lokal: ``UpdatedAt: 2026-05-21 01:03:33 UTC``).

Ursache: Trivy 0.70 schreibt ``DataSource``/``UpdatedAt`` nur **pro Vulnerability** im Scan-JSON, nicht im Top-Level ``scan.Metadata``. Der bestehende Ingest-Pfad (``app/services/findings_ingest.py:447-454``) liest aber genau nur das Top-Level — bleibt NULL, wird so in ``servers.trivy_db_version`` / ``trivy_db_updated_at`` persistiert. UI prueft Alter dieser NULL-Spalte → stale-Pill triggert.

Sehe ``docs/techdebt.md`` (kein TD-Eintrag dazu — direkt als Ticket).

## Aufgabe

Agent erweitern um die echten Trivy-DB-Metadaten **aus ``trivy version --format json``** zu lesen und als neuen Top-Level-Block in den Envelope zu packen. Server (TICKET-002) liest sie von dort.

## Schnittstelle (verbindlich, abgestimmt mit TICKET-002)

Top-Level-JSON-Feld im Envelope:

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

- **``version``**: String (Trivy schreibt es als Integer ``2``, wir wandeln zu String — Forward-Compat fuer Schema-V3).
- **``updated_at``** / **``next_update_at``** / **``downloaded_at``**: ISO-8601 mit ``Z``-Suffix (UTC). Trivy liefert Nano-Sekunden-Precision; auf Sekunde abrunden ist OK.
- **``trivy_db`` darf fehlen** (``null``/abwesend) wenn ``trivy version --format json`` failt oder unparsable ist — Server-Schema akzeptiert das (siehe TICKET-002).

## Implementierungs-Plan

### Phase 1 — Agent-Code

In ``agent/secscan-agent.sh``:

1. **Nach dem bestehenden ``trivy --version``-Aufruf** (Zeile ~127) zusaetzlich:

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

2. **Im bestehenden ``jq -n``-Envelope-Build** (Zeile ~189) als neues Feld einfuegen:

   ```bash
   payload="$(jq -n \
     ...
     --argjson trivy_db "$trivy_db_block" \
     '{
       agent_version: $agent_version,
       host: { ... },
       scan: $scan[0],
       host_state: $host_state,
       trivy_db: $trivy_db        # <-- neu
     }')"
   ```

3. **Agent-Version Bump:** ``readonly AGENT_VERSION="0.3.1"`` (oben in der Datei). Im ``app/config.py`` ``CURRENT_AGENT_VERSION`` und ggf. ``MIN_AGENT_VERSION`` parallel anpassen — aber das ist Server-Job, hier nur Agent-Wert hochziehen.

### Phase 2 — Fehlerbehandlung

- **Trivy <0.70** kennt ``--format json`` fuer ``version`` evtl nicht oder hat anderes Schema. Pattern: ``|| echo ''`` als Fallback, dann ``jq -e`` test, dann ``trivy_db=null``.
- **JSON-Parse-Fehler**: gleiche null-Fallback-Logik.
- **NIE den Scan blockieren** wenn ``trivy version`` failt — Pull-Pfad ist optional.

### Phase 3 — Tests

Agent-Shell-Tests laufen heute via ``scripts/e2e_smoke.sh`` und ``tests/integration/test_installer_e2e.py`` — beides Acceptance-Niveau, NICHT in der Unit-Suite.

Stattdessen: **Bash-Unit-Test als neuer File** ``tests/agent/test_trivy_db_meta_extraction.sh`` (Bats-Syntax oder reines Bash mit ``set -e`` + Asserts). Tests:

1. Happy: ``trivy version --format json`` liefert vollstaendigen Output → ``trivy_db_block`` enthaelt alle 4 Felder.
2. Trivy-Binary fehlt → ``trivy_db_block=null``, Scan laeuft trotzdem.
3. ``trivy version --format json`` liefert leeren String → ``trivy_db_block=null``.
4. ``trivy version --format json`` liefert JSON OHNE ``VulnerabilityDB``-Key (z.B. nur ``{"Version": "..."}``) → ``trivy_db_block=null``.
5. Envelope-Build mit ``trivy_db_block=null`` produziert valides JSON (``jq -e '.' <<<"$payload"``).
6. Envelope-Build mit gefuelltem ``trivy_db_block`` produziert valides JSON.

Mock-Strategie: ``TRIVY_BIN`` per Env-Var auf ein Stub-Script setzen das je nach Test-Case unterschiedliche Outputs liefert (analog wie ``test_outdated_agent_rejected.py`` Mocks macht).

### Phase 4 — Doku

- ``docs/operations.md``: Hinweis dass ab Agent 0.3.1 die Trivy-DB-Metadaten korrekt persistiert werden — alte Agents (0.3.0) bleiben funktional, nur die ``trivy_db_*``-Spalten bleiben dort NULL.
- ``CHANGELOG.md``: neuer Eintrag unter ``[Unreleased]``.

## Definition-of-Done

1. ``agent/secscan-agent.sh`` enthaelt den ``trivy_db``-Block-Build + Envelope-Integration.
2. ``AGENT_VERSION=0.3.1``.
3. Bash-Unit-Tests gruen (manuell laufbar via ``bash tests/agent/test_trivy_db_meta_extraction.sh``).
4. ``shellcheck agent/secscan-agent.sh`` clean (falls schon CI-tooling-installiert; sonst best-effort).
5. CHANGELOG + operations.md updated.

## NICHT in diesem Ticket

- Server-Schema-Aenderung (TICKET-002).
- Migration von ``stale_trivy_db_threshold_h`` (Threshold bleibt 30h Default).
- UI-Aenderung an der Stale-Pill (UI-Logik wird automatisch korrekt sobald die Spalten gefuellt sind).
