# Block T — Application-Group-Evaluations als Junction

**Spec-Quelle:** [ADR-0028](../decisions/0028-application-group-evaluations-junction.md)
**Branch:** `feat/block-t-eval-junction`
**Vorgänger-Block:** Block Q (v0.10.0). Block R (Async-Ingest) und Block S (Perf-Konsolidierung) sind unabhängig und können vor oder nach Block T landen.
**Status:** Geplant

## Ziel

`application_groups` wird auf fleet-weite Identität + Patterns reduziert. Sieben server-abhängige Eval-Spalten wandern in eine neue Junction-Tabelle `application_group_evaluations` mit Composite-PK `(group_id, server_id)`. Bestehende Eval-Daten werden _nicht_ migriert (drop & rebuild) — Pass-2 läuft beim nächsten regulären Scan jedes Servers via Cache-Hit nahezu kostenlos neu.

## Spec-Referenzen (Pflicht-Lektüre)

1. ADR-0028 §Entscheidung — Schema der Junction, CheckConstraints, Indizes.
2. ADR-0028 §Pass-2-Trigger-Adaptation — wie der Block-P-Hook auf fehlende Junction-Rows triggert.
3. ADR-0028 §Pass-2-Persistierung — UPSERT-Statement.
4. ADR-0028 §UI-bei-Eval-Lücke — Render-Verhalten bei fehlender Junction-Row.
5. ADR-0023 + `app/workers/llm_worker.py:1035-1353` — heutige Pass-2-Persistierung.
6. TICKET-002 + `app/services/finding_group_inheritance.py` — Inheritance-Logik die mit umzieht.
7. ADR-0025 + `app/views/server_detail.py::_load_application_groups_for_server` — Block-Q-Lazy-Load-Pfad.

## Modell

Tabelle `application_group_evaluations` — siehe ADR-0028 §Schema-Schnitt. Drei Indizes:

- Composite-PK auf `(group_id, server_id)`.
- `ix_app_group_evals_server` auf `(server_id, risk_band)` — Server-Detail- und Aggregate-Pfade.
- `ix_app_group_evals_worst_finding` partial auf `worst_finding_id WHERE worst_finding_id IS NOT NULL`.

Drei CheckConstraints: Band, Source, Action-Type.

## Phasen

### Phase A — Schema + Model

**Dateien:** `alembic/versions/00XX_application_group_evaluations.py` (Nummer = nächste freie nach Block-R/S-Stand), `app/models.py`.

Upgrade/Downgrade-Pseudocode siehe ADR-0028 §Migration. SQLAlchemy-Modell `ApplicationGroupEvaluation` parallel angelegt. Sieben Spalten und zwei CheckConstraints aus `ApplicationGroup` entfernen.

**Tests:**
- `tests/alembic/test_00XX_application_group_evaluations.py` — Schema-Properties via Reflection (alle Spalten, Constraints, Indizes), Upgrade → Downgrade → Upgrade Roundtrip leer von Daten beim Upgrade.

**DoD-A:**
1. Migration-File commit-bar, Upgrade/Downgrade beide implementiert.
2. `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` PASS gegen Test-Postgres.
3. `ApplicationGroupEvaluation`-Modell in `app/models.py`.
4. `ApplicationGroup` hat keine der sieben gelöschten Spalten mehr.
5. `mypy --strict app/models.py` ohne Errors.

### Phase B — Pass-2-Persistierung auf Junction-UPSERT

**Dateien:** `app/workers/llm_worker.py` Pass-2-Pfad.

Vier Stellen umstellen:

1. Cache-Hit-Pfad (~Zeilen 1035-1063): `group.risk_band = cached.risk_band; …` → UPSERT auf `application_group_evaluations`.
2. Live-LLM-Pfad (~Zeilen 1190-1216): `group.risk_band = evaluation.risk_band; …` → UPSERT.
3. Helper `_apply_pass2_to_group` (~Zeilen 1346-1353): umbenennen auf `_upsert_evaluation(session, group_id, server_id, evaluation, gf_fp)`, gibt die Junction-Row zurück.
4. Audit-Event-Metadata-Builder (~Zeilen 1046, 1217): falls `group_id` und `server_id` als Identifier verwendet werden, beide explizit ausgeben (heute meist nur `group_id`).

UPSERT-Statement-Skelett aus ADR-0028 §Pass-2-Persistierung verwenden.

**Tests:**
- `tests/workers/test_pass2_persistence_junction.py`:
  1. Cache-Hit: Pass-2-Job mit existierender `llm_risk_cache`-Row → UPSERT in Junction, kein LLM-Call.
  2. Live-LLM: Cache-Miss → LLM-Call, UPSERT in Junction.
  3. Idempotenz: zweiter Lauf für dieselbe `(group, server)` mit identischem Fingerprint → UPSERT überschreibt mit denselben Werten, kein Side-Effect.
  4. Parallelität: zwei UPSERTs für dieselbe `(group, server)` via `pg_insert ... on_conflict_do_update` atomar.
  5. `worst_finding_id` ohne FK: gelöschtes Finding → Junction-Row bleibt mit stale-Pointer.

**DoD-B:**
1. Vier Persist-Sites umgestellt.
2. Pass-2-Job-Result-JSONB enthält weiter `risk_band` und `action_type` für Debug-Log (semantisch unverändert).
3. `pytest tests/workers/test_pass2_persistence_junction.py -v` PASS, mindestens 5 Test-Fälle.
4. `mypy --strict app/workers/llm_worker.py` ohne neue Errors.

### Phase C — Pass-2-Trigger-Adaptation

**Dateien:** `app/api/scans.py:436-487`.

Heutige Skip-Logik:

```python
if grp.group_findings_fingerprint == new_fp and grp.risk_band is not None:
    continue
```

Neu:

```python
existing_eval = sess.execute(
    select(ApplicationGroupEvaluation)
    .where(
        ApplicationGroupEvaluation.group_id == grp.id,
        ApplicationGroupEvaluation.server_id == server.id,
    )
).scalar_one_or_none()
if existing_eval and existing_eval.group_findings_fingerprint == new_fp:
    continue
```

Batch-Optimierung: ein einzelner SELECT lädt alle Junction-Rows für `(server_id=server.id, group_id IN (affected_group_ids))` vor und baut ein Dict — vermeidet N+1.

**Tests:**
- `tests/api/test_scans_block_p_queueing_junction.py` (oder erweitere bestehende):
  1. Server-mit-bewerteter-Group: Junction-Row existiert mit gleichem Fingerprint → Pass-2 NICHT enqueued.
  2. Server-mit-bewerteter-Group + Fingerprint-Drift: Pass-2 enqueued.
  3. Server-ohne-Junction-Row für eine Group: Pass-2 enqueued (Backfill-Auslöser nach Deploy).
  4. Zwei Server, derselben Group: jeder triggert eigenen Pass-2-Job, kein Cross-Server-Skip.

**DoD-C:**
1. Block-P-Hook in `scans.py` umgestellt.
2. Batch-Lookup (ein SELECT statt N).
3. `pytest tests/api/test_scans_block_p_queueing_junction.py -v` PASS, mindestens 4 Test-Fälle.

### Phase D — `inherit_group_risk_to_findings` auf Junction

**Datei:** `app/services/finding_group_inheritance.py`.

Heutiges Statement (UPDATE-FROM mit `ApplicationGroup`) auf Junction-Join umstellen — Pseudo-Code siehe ADR-0028 §`inherit_group_risk_to_findings`. Composite-Match `(Finding.application_group_id == Junction.group_id AND Finding.server_id == Junction.server_id)`.

`server_id`-Kwarg (heute existierend für den Per-Scan-Pfad in `scans.py:393`) passt mit dem neuen Join zusammen.

**Tests:**
- `tests/services/test_finding_inheritance_junction.py`:
  1. Finding-A auf Server-A in Group-X, Junction `(X, A)` mit `act` → Finding-A erbt `act`.
  2. Finding-B auf Server-B in Group-X, Junction `(X, B)` mit `monitor` → Finding-B erbt `monitor`, Finding-A bleibt `act` (kein Cross-Server-Leak).
  3. Junction-Row fehlt für `(X, A)` → Finding-A unberührt.
  4. Idempotent: zweiter Lauf mit gleichen Werten → kein UPDATE.
  5. `server_id`-Kwarg-Filter funktioniert (nur Server X's Findings angefasst).

**DoD-D:**
1. Service-Funktion umgestellt.
2. `pytest tests/services/test_finding_inheritance_junction.py -v` PASS, mindestens 5 Test-Fälle.
3. `mypy --strict app/services/finding_group_inheritance.py` ohne neue Errors.

### Phase E — Server-Detail-Lazy-Load + Template-Rendering

**Dateien:** `app/views/server_detail.py::_load_application_groups_for_server`, `app/templates/_partials/application_group_card.html`, `app/templates/_partials/group_evaluating_card.html`, `app/templates/servers/_view_groups.html`.

Block-Q hat heute drei feste SELECTs (Count-Aggregat, Group-Metadaten-Batch, Worst-Finding-Batch). Neu: vierter Batch-SELECT für Junction-Daten:

```python
evaluations = {
    row.group_id: row
    for row in sess.execute(
        select(ApplicationGroupEvaluation)
        .where(
            ApplicationGroupEvaluation.server_id == server_id,
            ApplicationGroupEvaluation.group_id.in_(group_ids),
        )
    ).scalars().all()
}
```

Im Template wird `group.risk_band` durch `evaluation.risk_band if evaluation else None` ersetzt — der Loop-Context bekommt eine `evaluation`-Variable.

**„Nicht bewertet"-Pille:** `_partials/group_evaluating_card.html` rendert wenn `evaluation is None`. Heute existiert dieser Pfad bereits für `group.risk_band IS NULL` — Verallgemeinerung auf „Junction-Row fehlt".

`worst_finding_id` kommt jetzt aus der Junction-Row statt aus Group — der Worst-Finding-Batch-SELECT in `_load_application_groups_for_server` wechselt seine Quelle.

**Tests:**
- `tests/views/test_server_detail_evaluation_lookup.py`:
  1. Server-Detail rendert für eine Group mit Junction-Row die korrekte Pille (Band, Reason).
  2. Server-Detail rendert für eine Group ohne Junction-Row die „Nicht bewertet"-Pille.
  3. Zwei Server, dieselbe Group: jeder sieht seine Junction-Werte.
  4. Block-Q-Query-Count bleibt konstant (jetzt vier SELECTs statt drei; Regression-Test der `_load_application_groups_for_server` nicht in N+1 verfällt).
- Snapshot-Test der `application_group_card.html`-Render-Output (HTMX-Fragment).

**DoD-E:**
1. Vier SELECTs in `_load_application_groups_for_server`.
2. Template-Renaming abgeschlossen, kein `group.risk_band`-Referenz mehr in Templates.
3. `pytest tests/views/test_server_detail_evaluation_lookup.py -v` PASS, mindestens 5 Test-Fälle.

### Phase F — Bestehende Tests migrieren + Quer-Verweise

**Surface-Identifikation:**

```
grep -rn 'ApplicationGroup\.risk_band\|grp\.risk_band\|group\.risk_band' app/ tests/
```

Erwartete betroffene Test-Files (Schätzung, bei Implementation verifizieren):

- `tests/workers/test_llm_worker_pass2.py`
- `tests/services/test_finding_group_inheritance.py` (Migrieren oder durch `test_finding_inheritance_junction.py` ersetzen)
- `tests/api/test_scans_block_p_queueing.py` (umsteigen auf Junction-Asserts)
- `tests/views/test_server_detail_lazy_groups.py`
- `tests/api/test_scans_risk_pretriage.py` (wenn Pre-Triage-Tests Group-Band asserten — Pre-Triage ist semantisch nicht betroffen, aber Setup-Code könnte Group-Band setzen)

Pro Test-File: entweder
- Setup-Code von „set `group.risk_band = …`" auf „insert `ApplicationGroupEvaluation(group_id=…, server_id=…, risk_band=…)`" umstellen, oder
- Test entfernt wenn er Verhalten testet das jetzt durch Junction-Tests in Phase B/D abgedeckt ist.

**ARCHITECTURE.md §5** (Datenmodell): neue Tabelle aufnehmen, `application_groups` verliert sieben Spalten.

**`docs/decisions/0023-llm-risk-reviewer-and-application-grouping.md`** (Spec-Drift-Schutz): Hinweis-Block am Anfang dass `ApplicationGroup` heute keine Eval-Spalten mehr trägt, Verweis auf ADR-0028.

**`docs/decisions/0022-risk-based-prioritization.md`**: gleicher Hinweis bei §"Re-Evaluation"-Abschnitt.

**Block-Q-Doku** (`docs/blocks/Q-slim-down.md`): falls Group-Card-Render dort beschrieben ist, Junction-Kontext nachziehen.

**TICKET-002**: setzen auf `Status: Erledigt durch Block T` — die Inheritance-Logik wird hier mit umgebaut. Kein separater Cleanup nötig.

**DoD-F:**
1. `grep -rn 'application_groups\.risk_band\|ApplicationGroup\.risk_band\|group\.risk_band' app/` ist leer (kein Code-Pfad mehr).
2. `grep -rn 'group\.risk_band' tests/` ist leer (alle Tests migriert).
3. ARCHITECTURE.md §5 angeglichen.
4. ADR-0022/0023 mit Hinweis-Block ergänzt.
5. Block-Q-Doku angeglichen.
6. TICKET-002 als „Erledigt durch Block T" markiert.

### Phase G — Cutover

**Cutover-Plan:**

1. Feature-Flag `SCAN_INGEST_ASYNC`-Pattern aus Block R übernehmen wir hier _nicht_ — der Junction-Cut ist schema-bestimmend (Spalten weg), kein Hybrid-Modus möglich.
2. Migration ist atomar: nach `alembic upgrade` ist die Junction-Tabelle leer, `ApplicationGroup` hat keine Eval-Spalten mehr.
3. UI zeigt sofort nach Deploy für alle Groups auf allen Server-Detail-Seiten „Nicht bewertet" (bis der nächste Scan jedes Servers Pass-2 triggert).
4. Operator-Awareness: `docs/operations.md`-Hinweis „Nach Deploy: 24h erwartete UI-Lücke (Group-Cards in `Nicht bewertet`-Zustand), automatischer Re-Eval beim nächsten Agent-Scan. Bei Bedarf manueller Force-Scan möglich via …".
5. CHANGELOG-Eintrag v0.11.x.

**DoD-G:**
1. `docs/operations.md`-Hinweis ergänzt.
2. CHANGELOG-Eintrag.
3. Operator-Smoketest: Migration ausgeführt → Server-Detail-Seite zeigt „Nicht bewertet"-Pillen → Force-Scan via Agent → nach Pass-2-Worker-Lauf zeigen Cards korrekte Bänder.

## Risiken & Mitigation

| Risiko | Mitigation |
|---|---|
| **UI-Lücke nach Deploy** (Groups zeigen „Nicht bewertet" bis nächster Scan) | In Kauf genommen. Mitigation: Operator weiß über `docs/operations.md`-Hinweis Bescheid, Force-Scan ist via Cron- oder manuellem Trigger jederzeit möglich. Cache-Hit-Rate aus `llm_risk_cache` macht den Re-Eval-Lauf nahezu kostenlos. |
| **Pass-2-Backlog** wenn N×M `(group, server)`-Pairs auf einmal getriggert werden | Worker-Concurrency wie heute (single Pass-2 pro Tick). Bei 200 Groups × 100 Servern = 20k Pass-2-Jobs, davon ~95% Cache-Hits (sub-Sekunden-Persistierung). Backlog läuft typischerweise in <30min ab. Falls schmerzhaft: separater `secscan-pass2-worker`-Pod als Folge-ADR. |
| **`worst_finding_id` stale-Pointer** | Heutiges Verhalten unverändert. UI-Fallback auf „Worst-Finding nicht mehr vorhanden". |
| **Doppel-Pass-2 für `(group, server)` durch konkurrente Worker** | UPSERT mit `ON CONFLICT (group_id, server_id) DO UPDATE` ist atomar. Akzeptiert: letzter Worker gewinnt. Pass-2-Sibling-Wait-Pattern aus ADR-0023 verhindert das auf Worker-Pickup-Ebene heute schon. |
| **Test-Surface-Migration unterschätzt** | Phase F hat einen Grep-Schritt als DoD-Punkt 1+2; alle Treffer müssen adressiert werden bevor Phase F als abgeschlossen gilt. Erfahrung aus Block Q: Test-Migration ist die größte Einzelkomponente eines Schema-Cut-Blocks. |
| **Block-R-Coupling** wenn Pass-2-Persistierung in Block R in den Worker wandert (statt aus dem Web-Container) | Geringes Risiko: Pass-2 läuft heute schon im Worker, Block R verschiebt nur den Ingest. Pass-2-Persist-Code in `llm_worker.py` ist von Block R nicht angefasst. |
| **Konkurrierende ADR-Numerierung mit TICKET-003** | Geklärt 2026-05-22: TICKET-003 ist bereits umgesetzt (Commit `7867220`) und belegt ADR-0027. Block R hat 0026. Block T rückt deshalb auf ADR-0028. |

## NICHT in Block T

- **Fleet-Aggregat-Spalte auf `application_groups`** (Variante D aus ADR-0028). Nicht in MVP — wenn Dashboard-Performance-Befund eigene ADR rechtfertigt.
- **Manual-Override-Pfad** (Operator setzt Junction-Row mit `risk_band_source='manual'`). Schema sieht es vor (`source IN ('llm','manual')`), Endpoint kommt in Folge-ADR.
- **Worker-Backfill-Sub-Tick.** Pass-2-Trigger im Block-P-Hook reicht (siehe ADR-0028 §Begründung).
- **Cross-Server-Pass-1-Dedup.** Pass-1-Optimierung steht in der Designdiskussion als separater Hebel zur Verfügung — nicht jetzt gewählt.
- **Cache-Konsolidierung** (Junction-Rows mit semantisch gleicher Bewertung über Server zusammenführen). Re-Open-Trigger in ADR-0028.
- **Audit-Event `risk.band_changed`-Anpassung auf Junction-Granularität.** TICKET-003 (ADR-0027) ist vor Block T gelandet; das Event ist ersatzlos entfernt. Nichts mehr zu tun in Block T Phase F.
- **Permission-Modell für Junction-Reads** (z.B. Server-X-Operator darf nur Junction-Rows mit `server_id=X` lesen). MVP ist Single-User — out of scope.

## Definition-of-Done (Block-Übergreifend)

1. Alle Phasen-DoDs (A–G) PASS.
2. `ruff check . && ruff format --check . && mypy app/` PASS.
3. `pytest -v` Gesamt-Suite PASS.
4. `pytest tests/adversarial/ -v` PASS.
5. `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` PASS.
6. `docker compose up -d --build && curl -fsSL http://localhost:8000/healthz` PASS.
7. ADR-0028 commit-bar, ADR-0022/0023 mit Hinweis-Block.
8. ARCHITECTURE.md §5 angeglichen.
9. CHANGELOG-Eintrag v0.11.x.
10. STATE.md Block-T-Abschluss dokumentiert.
11. Operator-Smoketest (siehe Phase G DoD #3).
