# TICKET-001 — Trivy-DB-Metadaten persistieren (Agent + Backend)

**Status:** Offen
**Komponenten:** ``agent/secscan-agent.sh`` + ``app/schemas/scan_envelope.py`` + ``app/services/findings_ingest.py``
**Umfang:** End-to-End, beide Seiten in einem Ticket.

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

**Agent (Bash-Unit-Test):** ``tests/agent/test_trivy_db_meta_extraction.sh`` (neu, Bash-Skript mit ``set -e`` + Asserts, Stub-TRIVY_BIN per Env-Var):

1. Happy: ``trivy version --format json`` liefert vollstaendigen Output → ``trivy_db_block`` enthaelt alle 4 Felder.
2. Trivy-Binary fehlt → ``trivy_db_block=null``, Scan laeuft trotzdem.
3. ``trivy version --format json`` liefert leeren String → ``trivy_db_block=null``.
4. ``trivy version --format json`` liefert JSON OHNE ``VulnerabilityDB``-Key → ``trivy_db_block=null``.
5. Envelope-Build mit ``trivy_db_block=null`` produziert valides JSON.
6. Envelope-Build mit gefuelltem ``trivy_db_block`` produziert valides JSON.

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

1. Agent-Code + Envelope-Schema + Ingest-Pfad implementiert.
2. ``AGENT_VERSION=0.3.1``.
3. Bash-Unit-Tests gruen.
4. 6 neue Backend-Unit-Tests gruen.
5. Bestehende Pure-Unit-Suite (``pytest -m "not todo_mock and not acceptance and not bench and not integration" -q``) bleibt gruen.
6. ``ruff check . && ruff format --check .`` clean.
7. ``mypy --strict app/services/findings_ingest.py app/schemas/scan_envelope.py`` keine neuen Errors.
8. CHANGELOG + operations.md.

## NICHT in diesem Ticket

- ``stale_trivy_db_threshold_h``-Tuning (bleibt 30h Default).
- UI-Aenderung an der Stale-Pill (zeigt automatisch korrekt sobald Spalten gefuellt sind).
- ``next_update_at`` / ``downloaded_at`` als eigene DB-Spalten (Schema-Migration). Beide Felder sind im Envelope fuer Forward-Compat enthalten, MVP persistiert nur ``version`` + ``updated_at``.
