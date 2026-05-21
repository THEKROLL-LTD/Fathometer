# TICKET-002 — Server: Envelope-Schema + Ingest fuer Trivy-DB-Metadaten

**Status:** Offen
**Komponente:** ``app/schemas/scan_envelope.py``, ``app/services/findings_ingest.py``
**Abhaengigkeit:** parallel zu TICKET-001 (Agent-Seite). Beide muessen sich auf das gleiche Envelope-Schema einigen — siehe §"Schnittstelle".

## Problem

Production-Bug 2026-05-21: Server-Detail-Seite zeigt "trivy-db stale", obwohl die Trivy-DB auf dem Agent-Host aktuell ist.

Ursache: Trivy 0.70 schreibt ``DataSource``/``UpdatedAt`` nur **pro Vulnerability** im Scan-JSON, nicht im Top-Level ``scan.Metadata``. Unser Ingest (``app/services/findings_ingest.py:447-454``) liest genau nur Top-Level — bleibt NULL → ``servers.trivy_db_version`` / ``trivy_db_updated_at`` NULL → UI-Stale-Check triggert false-positive.

TICKET-001 erweitert den Agent um einen neuen Top-Level-Envelope-Block ``trivy_db``. Dieses Ticket erweitert das Server-Schema dafuer und priorisiert die neuen Werte vor dem alten ``Metadata.DataSource``-Pfad.

## Schnittstelle (verbindlich, abgestimmt mit TICKET-001)

Neuer Top-Level-Envelope-Block:

```json
{
  ...
  "trivy_db": {
    "version": "2",
    "updated_at": "2026-05-21T01:03:33Z",
    "next_update_at": "2026-05-22T01:03:33Z",
    "downloaded_at": "2026-05-21T06:24:41Z"
  }
}
```

- ``trivy_db`` darf fehlen / ``null`` sein (alte Agents <0.3.1, oder Trivy ohne ``version --format json``-Support).
- Alle 4 Felder einzeln nullable (defensive parsing).
- ``updated_at`` / ``next_update_at`` / ``downloaded_at``: ISO-8601 UTC, Pydantic ``datetime``.
- ``version``: String. Trivy schreibt es als Integer; Agent serialisiert als String.

## Implementierungs-Plan

### Phase 1 — Pydantic-Schema

In ``app/schemas/scan_envelope.py`` (vor der ``Envelope``-Klasse):

```python
class TrivyDbBlock(BaseModel):
    """Top-Level ``trivy_db``-Block aus dem Envelope (Agent ≥ 0.3.1).

    Trivy schreibt ``DataSource``/``UpdatedAt`` nur pro Vulnerability in
    ``Results[].Vulnerabilities[]``, nicht im Top-Level ``scan.Metadata``.
    Damit der Server die echten DB-Metadaten persistieren kann, schickt
    der Agent sie aus ``trivy version --format json`` als separater
    Top-Level-Block.

    Alle Felder defensiv nullable — ein Agent mit Trivy <0.70 oder
    fehlgeschlagenem ``version``-Call sendet hier ``null``-Block.
    """

    model_config = ConfigDict(extra="ignore")

    version: str | None = Field(default=None, max_length=32)
    updated_at: datetime | None = None
    next_update_at: datetime | None = None
    downloaded_at: datetime | None = None
```

In der ``Envelope``-Klasse als neues Feld:

```python
class Envelope(BaseModel):
    ...
    trivy_db: TrivyDbBlock | None = Field(default=None)
```

``__all__``-Liste erweitern um ``"TrivyDbBlock"``.

### Phase 2 — Ingest-Pfad anpassen

In ``app/services/findings_ingest.py`` (ca. Zeile 442-470, ``ingest_scan``):

Vor dem bestehenden ``metadata.data_source``-Fallback:

```python
trivy_db_version: str | None = None
trivy_db_updated_at: datetime | None = None

# Phase 1: bevorzugt Top-Level trivy_db-Block (Agent ≥ 0.3.1).
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

Das Persistieren auf ``server.trivy_db_version`` / ``trivy_db_updated_at`` bleibt unveraendert.

### Phase 3 — Tests (Unit, kein DB)

Bestehendes Test-File ``tests/services/test_findings_ingest.py`` ist bereits in ``_MOCKED_UNIT_FILES`` (LOW-refactored). Neue Tests dort hinzufuegen oder in eigenes File ``tests/services/test_findings_ingest_trivy_db_meta.py``:

Test-Faelle (alle pure Unit mit MagicMock-Session):

1. **Happy: ``trivy_db``-Block voll** → ``trivy_db_version``, ``trivy_db_updated_at`` korrekt extrahiert.
2. **``trivy_db`` ist None** + ``scan.Metadata.DataSource`` voll → Fallback greift, Werte aus Metadata.
3. **``trivy_db`` ist None** + ``scan.Metadata`` ist None → beide Werte NULL.
4. **``trivy_db`` hat nur ``version``, ``updated_at=null``** + ``Metadata.DataSource.updated_at`` voll → Mischung: version aus trivy_db, updated_at aus metadata (Fallback nur fuer fehlende Felder).
5. **``trivy_db.version``-Format**: String "2" vs. Integer 2. Pydantic ``str | None`` muss tolerieren wenn Agent doch mal Integer schickt — oder striktes Reject mit ValidationError. Empfehlung: Pydantic-default-validation (String pflicht), Agent muss korrekt serialisieren.
6. **Adversarial: ``trivy_db`` enthaelt unbekannte Extra-Felder** (z.B. ``java_db``) → ``extra="ignore"`` schluckt sie, keine ValidationError.

Plus Envelope-Schema-Smoke-Tests in ``tests/schemas/test_host_state_envelope.py`` (oder neu): ``Envelope.model_validate({"trivy_db": {...}})`` haengt nicht.

### Phase 4 — Doku + Migration

- ``CHANGELOG.md``: Eintrag unter ``[Unreleased]``: "Trivy-DB-Metadaten werden ab Agent 0.3.1 korrekt persistiert. Alte Agents (≤0.3.0) bleiben funktional; ihre ``trivy_db_version``/``trivy_db_updated_at`` bleiben NULL."
- ``docs/decisions/``: kein neuer ADR noetig — es ist eine Bug-Fix-Implementierung der bestehenden ARCHITECTURE-§5-Anforderung. Verweis als Kommentar im Code reicht.
- ``app/config.py``: ``MIN_AGENT_VERSION`` bleibt unveraendert (alte Agents akzeptiert, neue Feature ist optional). ``CURRENT_AGENT_VERSION`` auf ``"0.3.1"`` ziehen sobald TICKET-001 deployed.

### Phase 5 — Backward-Compat-Check

Mit den vorhandenen Trivy-Fixtures (``tests/fixtures/trivy/ubuntu-22.04-rke2.json``) bleibt der Envelope ohne ``trivy_db``-Block valide — verifizieren via existierenden ``test_envelope_cause_fields.py``-Suite.

## Definition-of-Done

1. ``TrivyDbBlock``-Pydantic-Modell + ``Envelope.trivy_db``-Feld.
2. Ingest-Pfad bevorzugt Top-Level-Block, faellt sauber auf alte ``Metadata.DataSource``-Logik zurueck.
3. 6+ neue Unit-Tests mit MagicMock-Session, alle gruen.
4. Bestehende Pure-Unit-Suite (``pytest -m "not todo_mock and not acceptance and not bench and not integration" -q``) bleibt gruen (heute 756).
5. ``ruff check . && ruff format --check .`` clean.
6. ``mypy --strict app/services/findings_ingest.py app/schemas/scan_envelope.py`` keine neuen Errors.
7. CHANGELOG-Eintrag.

## NICHT in diesem Ticket

- Agent-Code (TICKET-001).
- ``stale_trivy_db_threshold_h``-Tuning (Threshold bleibt 30h Default — wenn die Werte jetzt korrekt persistiert werden, ist die Pill informativ ehrlich).
- UI-Aenderung an der Stale-Pill (zeigt automatisch korrekt sobald Spalten gefuellt sind).
- ``next_update_at`` / ``downloaded_at`` persistieren — beide Felder sind im Envelope-Schema enthalten fuer Forward-Compat, werden im MVP aber NICHT in eigene DB-Spalten gespeichert. Wenn spaeter benoetigt: separates Ticket + Migration.
