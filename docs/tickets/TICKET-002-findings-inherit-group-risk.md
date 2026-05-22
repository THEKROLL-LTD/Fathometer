# TICKET-002 — Findings erben Risk-Band von ApplicationGroup

**Status:** Erledigt durch Block T (ADR-0028, 2026-05-22). Inheritance-Service liegt in `app/services/finding_group_inheritance.py`; jointet seit Block T auf `application_group_evaluations` mit Composite-Match `(group_id, server_id)` — kein Cross-Server-Leak mehr. Inhaltliches Ziel (Findings tragen den von Pass-2 ermittelten Band) ist erreicht; das urspruenglich skizzierte Schema (Direkt-Set auf `ApplicationGroup.risk_band`) wurde durch die Junction abgeloest.
**Komponenten:** ``app/services/llm_risk_reviewer.py``, ``app/services/findings_ingest.py``, ``app/services/group_matcher.py``, ggf. ``app/workers/llm_worker.py``
**Umfang:** Daten-Vererbung + Re-Ingest-Pfad

## Problem

Production-Bug 2026-05-21: Server-Detail-Seite zeigt "Action needed — **2845 pending**" obwohl alle LLM-Pass-1 und -Pass-2 erfolgreich durchgelaufen sind. Bei 5067 OPEN-Findings sind das ~56% — viel zu viel fuer einen Server der erfolgreich klassifiziert wurde.

Ursache: ``Finding.risk_band`` und ``ApplicationGroup.risk_band`` sind **zwei separate Spalten ohne Vererbung**.

- Block O (Pre-Triage) setzt ``Finding.risk_band`` auf ``escalate``/``act``/``mitigate``/``monitor``/``noise`` ODER ``pending``/``unknown`` wenn die deterministische Pre-Triage-Heuristik keine eindeutige Klassifikation hinkriegt.
- Block P (LLM Pass-2) setzt ``ApplicationGroup.risk_band`` auf das finale Verdict (``escalate``/``act``/``monitor``/``noise``).
- **Es gibt aktuell keinen Schritt der das Group-Verdict auf die Member-Findings vererbt.** Findings die in eine Group zugeordnet sind und deren Group ein finales Pass-2-Verdict hat, behalten ihren Pre-Triage-Status (oft ``pending``).

Resultat: die UI-Pill ``_load_action_required_counts`` (``app/views/server_detail.py:483``) zaehlt ``Finding.risk_band='pending'`` und kommt auf 2845 obwohl die zugehoerigen Groups laengst bewertet sind.

## Loesung — User-Anforderung

> *"Es sollen nur noch Findings angezeigt werden die wirklich nicht einer Gruppe zugeordnet worden sind und unbewertet sind."*

Konkret: ein Finding ist "wirklich pending" nur wenn

1. ``application_group_id IS NULL`` (kein Group-Match), UND
2. ``risk_band IN (NULL, 'pending', 'unknown')`` (kein Pre-Triage-Verdict, kein LLM-Verdict).

Alle anderen Findings ueberschreiben ihren ``risk_band`` mit dem ``risk_band`` ihrer Group (Quelle der Wahrheit ist das LLM-Verdict, nicht die deterministische Pre-Triage).

### Schema-Pruefung (vorab verifiziert 2026-05-21)

- **``Finding.action_type`` existiert NICHT.** Nur ``ApplicationGroup.action_type`` und ``LlmRiskCache.action_type`` haben das Feld. Die Vererbung kopiert daher **nur** ``risk_band`` + ``risk_band_reason`` + ``risk_band_source`` + ``risk_band_computed_at`` auf das Finding. Den ``action_type`` zeigt die UI ueber den Join ``Finding -> ApplicationGroup`` an (bestehender Pfad). Keine Schema-Migration noetig.
- **``risk_band_source = "llm"``** (nicht ``"llm_group"``). Drei Gruende:
  1. Semantisch korrekt — es ist ein LLM-Verdict, nur eben Group-vererbt statt direkt.
  2. Die bestehende Re-Ingest-Skip-Logik in ``app/api/scans.py:337``
     (``if finding.risk_band_source == "llm": continue``) greift damit
     automatisch — vererbte Findings werden bei der naechsten Pre-Triage
     nicht ueberschrieben. Ein neuer Wert ``"llm_group"`` wuerde die
     Skip-Logik umgehen und einen separaten Patch in ``scans.py``
     erfordern (oder gleich einen DB-CheckConstraint-Bump, wenn
     ``risk_band_source`` mal restriktiv wird).
  3. Bestehende ADR-0022/0023-Whitelist (``engine``/``llm``/``manual``)
     bleibt unveraendert.

## Designentscheidung — wo passiert die Vererbung?

Zwei Optionen:

| Option | Speicherort | Trigger | Vorteil | Nachteil |
|---|---|---|---|---|
| **A — Lazy/View-Pfad** | nicht persistiert | ``_load_action_required_counts``-Query joint Finding + ApplicationGroup und nimmt ``COALESCE(group.risk_band, finding.risk_band)`` | Keine zusaetzliche Persistenz, Live-Konsistenz | Jede View-Query muss joinen, evtl. teurer; andere Pfade die ``Finding.risk_band`` direkt lesen sehen die alten Werte |
| **B — Eager/Persistiert** | ``Finding.risk_band``-Spalte wird ueberschrieben | Pass-2-Erfolg + neuer Ingest + Backfill | Alle bestehenden Queries arbeiten unveraendert; UI/Filter/Counter sind sofort konsistent | Dreifacher Trigger (Pass-2, Ingest, Backfill) — etwas mehr Code, dafuer kein Schema-Drift |

**Empfehlung: Option B (Eager)**, analog zum Block-Q-Backfill-Pattern. Reasons:
- ``Finding.risk_band`` ist von vielen Stellen gelesen (CSV-Export, ``findings_query.py``, Dashboard-KPIs, Server-Detail-Pill). Single-Source-of-Truth in der Spalte ist robuster als Join-Magic an allen Lese-Stellen.
- Pattern existiert bereits (``app/services/feed_backfill.py:backfill_epss/backfill_kev`` — idempotentes ``UPDATE ... FROM`` mit ``IS DISTINCT FROM``-Filter).

## Implementierungs-Plan

### 1. Neue Service-Funktion ``inherit_group_risk_to_findings``

In ``app/services/group_matcher.py`` (existierender Group-Matcher-Service) oder neuem ``app/services/finding_group_inheritance.py``:

```python
def inherit_group_risk_to_findings(
    session: Session,
    *,
    group_ids: Sequence[int] | None = None,
    server_id: int | None = None,
) -> int:
    """Setzt ``Finding.risk_band`` auf den Wert der zugeordneten ApplicationGroup.

    Idempotent (``IS DISTINCT FROM``-Filter), analog zum Feed-Backfill.
    ``action_type`` wird NICHT kopiert — das Feld existiert nicht auf
    ``Finding`` (nur auf ``ApplicationGroup``). UI rendert es ueber den
    Join ``Finding -> ApplicationGroup``.

    Args:
        group_ids: optional Filter — nur Findings dieser Gruppen aktualisieren.
            Wird vom Pass-2-Hook verwendet (nur frisch bewertete Groups).
        server_id: optional Filter — nur Findings dieses Servers aktualisieren.
            Wird vom Re-Ingest-Pfad verwendet.

    Returns:
        Anzahl der tatsaechlich aktualisierten Findings-Rows.
    """
    stmt = (
        update(Finding)
        .where(Finding.application_group_id == ApplicationGroup.id)
        .where(ApplicationGroup.risk_band.is_not(None))
        .where(
            (Finding.risk_band.is_distinct_from(ApplicationGroup.risk_band))
            | (Finding.risk_band_source.is_distinct_from("llm"))
        )
        .values(
            risk_band=ApplicationGroup.risk_band,
            risk_band_source="llm",
            risk_band_computed_at=func.now(),
            risk_band_reason=ApplicationGroup.risk_band_reason,
        )
        .execution_options(synchronize_session=False)
    )
    if group_ids is not None:
        stmt = stmt.where(ApplicationGroup.id.in_(list(group_ids)))
    if server_id is not None:
        stmt = stmt.where(Finding.server_id == server_id)
    result = session.execute(stmt)
    session.commit()
    return int(result.rowcount or 0)
```

Schema-Aspekt: ``risk_band_source`` ist heute ein einfacher ``String(16)`` ohne CheckConstraint (siehe ``app/models.py:347``). Kein Migration-Bedarf. Mit ``"llm"`` greift ausserdem die bestehende Re-Ingest-Skip-Logik in ``app/api/scans.py:337`` automatisch.

### 2. Hook nach Pass-2-Erfolg

In ``app/services/llm_risk_reviewer.py`` (oder direkt im LLM-Worker, je nachdem wo das ``ApplicationGroup.risk_band`` persistiert wird — ggf. ``app/workers/llm_worker.py::_do_pass2``):

Nach dem ``session.commit()`` der Pass-2-Persistierung:

```python
inherited = inherit_group_risk_to_findings(
    session, group_ids=[ev.application_group_id for ev in result.evaluations]
)
log.info("pass2.findings_inherited", count=inherited)
```

### 3. Hook nach Ingest (neue Findings die zu bestehenden Groups gematcht werden)

In ``app/services/findings_ingest.py::ingest_scan``, nach dem Bulk-Upsert + Group-Matching (vermutlich Block N/O-Logik im ingest_scan):

```python
# Frische Vererbung fuer Findings dieses Servers — falls neue Findings
# zu bestehenden Groups gematcht wurden, sollen sie sofort den
# Group-risk_band uebernehmen statt auf den naechsten Pass-2-Lauf zu warten.
inherit_group_risk_to_findings(session, server_id=server_id)
```

Group-Matching passiert heute in ``app/services/group_matcher.py``. Pruefen ob das im Ingest-Pfad aufgerufen wird oder asynchron im Worker. Wenn asynchron, dann den Hook dort einbauen.

### 4. Initial-Backfill nach Deploy

Einmaliger ``inherit_group_risk_to_findings(session)`` (ohne Filter — alle Findings aller Server) nach dem ersten Pass-2-Lauf bzw. nach Deploy. Optional via Worker-Sub-Tick (alle 60min als Sicherheitsnetz fuer Drift).

**Empfehlung:** nicht als Worker-Tick, sondern als einmaliger CLI-Befehl ``python -m app.cli.inherit_group_risk_backfill`` den der Operator nach dem ersten Deploy einmal laufen laesst. Idempotent — kann beliebig oft wiederholt werden. Verhindert dass die Vererbung bei jedem Worker-Tick neu drueber laeuft (sinnlos wenn nichts neues gepasst hat).

### 5. UI-Pill semantisch unveraendert

Nach Vererbung zaehlt ``_load_action_required_counts`` automatisch korrekt:
- Findings mit Group + Pass-2-Verdict → haben jetzt das Group-``risk_band`` → fallen in den richtigen Bucket (escalate/act/monitor/noise).
- Findings ohne Group → behalten ihren Pre-Triage-``risk_band`` (kann ``pending`` sein wenn Pre-Triage nicht klassifizieren konnte).
- "Action needed" zaehlt nur noch echte orphan-pending-Findings.

Sanity-Check via SQL nach Deploy:

```sql
SELECT
  f.risk_band,
  COUNT(*) FILTER (WHERE f.application_group_id IS NULL) AS ungrouped,
  COUNT(*) FILTER (WHERE f.application_group_id IS NOT NULL) AS in_group
FROM findings f
WHERE f.status = 'open' AND f.server_id = <SERVER_ID>
GROUP BY f.risk_band
ORDER BY ungrouped + in_group DESC;
```

Erwartet nach Vererbung: ``in_group`` ist 0 fuer Band ``pending``/``unknown``; ``ungrouped`` kann fuer ``pending`` weiterhin > 0 sein.

### 6. Tests (Pure-Unit, kein DB)

In ``tests/services/test_finding_group_inheritance.py`` (neu), MagicMock-Session:

1. Happy: Finding mit Group, Group hat ``risk_band='act'`` → Finding bekommt ``risk_band='act'``, ``risk_band_source='llm'``, ``risk_band_reason``-Kopie. ``Finding.action_type`` wird NICHT gesetzt (existiert nicht auf dem Model).
2. Group hat ``risk_band=NULL`` (Pass-2 noch nicht durch) → Finding bleibt unveraendert.
3. Finding hat ``application_group_id=NULL`` → wird nicht angefasst.
4. Finding hat schon korrekten ``risk_band`` + ``risk_band_source='llm'`` (idempotent) → kein UPDATE.
5. ``group_ids``-Filter beschraenkt UPDATE auf die genannten Groups.
6. ``server_id``-Filter beschraenkt UPDATE auf den genannten Server.
7. ``rowcount=None`` → normalisiert auf 0.
8. SQL-Shape-Check: rendered SQL enthaelt ``Finding.application_group_id = ApplicationGroup.id`` + ``IS DISTINCT FROM``-Filter + SET-Klausel.
9. Re-Ingest-Skip-Smoke: nach Vererbung hat Finding ``risk_band_source='llm'``; ein simulierter Pre-Triage-Lauf via ``app/api/scans.py``-Codepfad skippt das Finding (Test verifiziert dass die Skip-Logik fuer ``"llm"`` bestehende Group-Vererbung schuetzt).

Plus 2 Integrations-Smoke-Tests (mocked, kein DB):
- Pass-2-Hook ruft ``inherit_group_risk_to_findings`` mit den ``group_ids`` aus dem Pass-2-Result.
- Ingest-Hook ruft ``inherit_group_risk_to_findings`` mit ``server_id``.

### 7. Doku

- ``CHANGELOG.md``: "Findings erben jetzt das Risk-Band ihrer ApplicationGroup nach Pass-2-Erfolg und bei jedem Re-Ingest. UI-Pill ``Action needed`` zaehlt nur noch wirklich-orphan-Findings."
- ``docs/operations.md``: kurzer Hinweis dass nach Deploy einmal ``python -m app.cli.inherit_group_risk_backfill`` laufen soll.

## Definition-of-Done

1. ``inherit_group_risk_to_findings``-Service-Funktion implementiert + 8+ Unit-Tests.
2. Pass-2-Hook (in ``_do_pass2`` oder ``llm_risk_reviewer``).
3. Ingest-Hook (in ``ingest_scan``).
4. CLI-Befehl ``app/cli/inherit_group_risk_backfill.py`` fuer Initial-Backfill.
5. Pure-Unit-Suite bleibt gruen.
6. ``ruff check . && ruff format --check .`` clean.
7. ``mypy --strict app/services/group_matcher.py`` oder neues Modul keine neuen Errors.
8. CHANGELOG + operations.md.

## NICHT in diesem Ticket

- Migration auf neuen ``risk_band_source``-Constraint-Wert wenn schon String-only (nur falls Constraint die Werte einschraenkt — vor Implementation pruefen via ``\d findings``).
- UI-Aenderung — die Pill funktioniert nach Vererbung automatisch.
- Schema-Aenderung an ``ApplicationGroup``.
- Rueckwirkende Korrektur historischer ``risk_band_computed_at``-Timestamps.

## Sanity-Checks vorab (vor Implementation auszufuehren)

```bash
PGPASS='<...>'
# (a) Bestaetige Vererbungs-Luecke
kubectl -n secscan exec secscan-db-1 -- env PGPASSWORD="$PGPASS" \
  psql -h secscan-db-rw -U secscan -d secscan -c "
SELECT
  f.risk_band, ag.risk_band AS group_band,
  COUNT(*) AS n
FROM findings f
LEFT JOIN application_groups ag ON ag.id = f.application_group_id
WHERE f.status = 'open'
GROUP BY f.risk_band, ag.risk_band
ORDER BY n DESC LIMIT 20;"

# (b) Bestaetige risk_band_source ist nicht constraint-eingeschraenkt
kubectl -n secscan exec secscan-db-1 -- env PGPASSWORD="$PGPASS" \
  psql -h secscan-db-rw -U secscan -d secscan -c "\d findings" | grep -i 'risk_band'
```

Erwartung (a): viele Rows mit ``f.risk_band='pending'`` + ``group_band='act'`` o.ae. — das ist die Vererbungs-Luecke. Erwartung (b): ``risk_band_source`` ist freier String ohne CheckConstraint (verifiziert 2026-05-21 via ``app/models.py:347`` — keine Migration noetig fuer den neuen Inheritance-Pfad mit ``"llm"``).
