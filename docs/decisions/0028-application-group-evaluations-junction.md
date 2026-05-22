# ADR-0028 — Application-Group-Evaluations als Junction-Tabelle

**Status:** Akzeptiert
**Datum:** 2026-05-22
**Block:** T (Implementation, siehe `docs/blocks/T-eval-junction.md`)
**Vorgänger:** ADR-0023 (LLM-Risk-Reviewer + Pass-2-Logik), TICKET-002 (Findings erben Risk-Band von ApplicationGroup), ADR-0022 (host_state als Eval-Input). **Tangiert** ADR-0026 (Async-Ingest, komplementär) und ADR-0025 (Server-Detail-Slim-Down — Group-Card-Render).

## Kontext

`application_groups` modelliert heute zwei semantisch unterschiedliche Konzepte auf einer einzigen Zeile pro Group:

1. **Fleet-weite Identität** — `label` (UNIQUE), `explanation`, `path_prefixes`, `pkg_name_exact`, `pkg_name_glob`, `pkg_purl_pattern`, `group_kind`, `source`, `detected_at`, `last_used_at`. Das ist die Pattern-Library die Pass-1 aufbaut und `GroupMatcher` zum Routing nutzt.

2. **Server-abhängige Bewertung** — `risk_band`, `risk_band_reason`, `risk_band_source`, `risk_band_computed_at`, `worst_finding_id`, `group_findings_fingerprint`, `action_type`. Diese Werte werden in Pass-2 _pro `(group, server-context)`_ vom LLM berechnet (Prompt sieht `host_state`, `cve_data`, Server-Listener etc.), aber auf die _eine_ Group-Zeile geschrieben.

Konsequenz: **Last-write-wins zwischen Servern.** Server A scant 08:00 → Group `libc6` bekommt `risk_band='monitor'` (kein externer Listener). Server B scant 08:15 → dieselbe Zeile wird auf `risk_band='act'` umgeschrieben (Port 22 offen). Über `inherit_group_risk_to_findings` aus TICKET-002 erben alle Findings beider Server B's Band. A's Operator sieht `act` für ein Paket das auf seinem Server kein Risiko ist.

Das ist ein 2NF/3NF-Verstoß: server-spezifische Attribute leben auf einer Zeile die fleet-weit identitäts-skopiert ist.

Bemerkenswerter Hinweis: der LLM-Cache (`llm_risk_cache.cache_key = SHA256(group_id|group_findings_fp|cve_data_fp|server_context_fp)`) ist _bereits_ per-`(group, server-context)` geschnitten. Die Cache-Ebene weiß seit ADR-0023, dass die Bewertung pro Server unterschiedlich ist — die Persistenz hinkt hinterher.

## Entscheidung

`application_groups` wird auf reine **fleet-weite Identität + Patterns** reduziert. Die sieben server-abhängigen Eval-Spalten wandern in eine neue Junction-Tabelle `application_group_evaluations` mit Composite-PK `(group_id, server_id)`.

### Neue Tabelle `application_group_evaluations`

| Spalte | Typ | Constraints | Quelle |
|---|---|---|---|
| `group_id` | `BIGINT` | `FK application_groups.id ON DELETE CASCADE`, Composite-PK | aus Pass-2-Job-Payload |
| `server_id` | `INT` | `FK servers.id ON DELETE CASCADE`, Composite-PK | aus Pass-2-Job-Payload |
| `risk_band` | `VARCHAR(16)` | NOT NULL, CHECK `IN ('escalate','act','mitigate','monitor','noise')` | LLM-Output Pass-2 |
| `risk_band_reason` | `VARCHAR(256)` | NULL | LLM-Output Pass-2, host_state-spezifisch |
| `risk_band_source` | `VARCHAR(16)` | NOT NULL, CHECK `IN ('llm','manual')` | „llm" beim Pass-2-Persist, „manual" für zukünftige Operator-Overrides |
| `risk_band_computed_at` | `TIMESTAMPTZ` | NOT NULL DEFAULT `now()` | Pass-2-Lauf |
| `worst_finding_id` | `BIGINT` | NULL, _kein_ FK (analog zu heutiger Group-Logik — Group überlebt Finding-Deletes) | LLM-Output Pass-2 |
| `group_findings_fingerprint` | `VARCHAR(16)` | NULL | für Pass-2-Skip-Logik (`grp.group_findings_fingerprint == new_fp` → kein neuer Job) |
| `action_type` | `VARCHAR(16)` | NULL, CHECK `IN ('patch','mitigate','watch','none','investigate')` | LLM-Output Pass-2 |

Indizes:

- Composite-PK auf `(group_id, server_id)` — primärer Lookup-Pfad.
- `ix_app_group_evals_server` auf `(server_id, risk_band)` — für Server-Detail-Seite und Fleet-Aggregate.
- `ix_app_group_evals_worst_finding` auf `worst_finding_id WHERE worst_finding_id IS NOT NULL` (partial) — UI-Render-Pfad für „Worst-Finding-Vorschau".

### `application_groups` verliert sieben Spalten

`risk_band`, `risk_band_reason`, `risk_band_source`, `risk_band_computed_at`, `worst_finding_id`, `group_findings_fingerprint`, `action_type` werden ersatzlos aus `application_groups` entfernt. Die zwei CheckConstraints `ck_application_groups_band` und `ck_application_groups_action_type` wandern in die neue Tabelle.

### Migration ist Drop & Rebuild — kein Daten-Backfill

Operator-Entscheidung 2026-05-22: **bestehende Eval-Daten werden _nicht_ in die Junction übertragen.** Begründung:

- Die Werte sind semantisch falsch (last-server-wins) — eine Migration die sie pro Server repliziert würde den Fehler in N Zeilen vervielfältigen statt zu beheben.
- Pass-2 läuft auf dem nächsten regulären Scan jedes Servers automatisch neu — siehe „Pass-2-Trigger-Adaptation" unten — und füllt die Junction frisch.
- Cache-Hits via `llm_risk_cache` sorgen dafür dass der Re-Eval-Lauf nahezu kostenlos ist: die _Bewertung_ pro `(group_id, group_findings_fp, cve_data_fp, server_context_fp)` ist schon im Cache. Pass-2 muss nur die Junction-Row schreiben.

Alembic-Migration:

```python
def upgrade():
    # Neue Tabelle anlegen
    op.create_table(
        "application_group_evaluations",
        sa.Column("group_id", sa.BigInteger, sa.ForeignKey("application_groups.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("server_id", sa.Integer, sa.ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("risk_band", sa.String(16), nullable=False),
        # … weitere Spalten
    )
    op.create_index("ix_app_group_evals_server", "application_group_evaluations", ["server_id", "risk_band"])
    op.create_index("ix_app_group_evals_worst_finding", "application_group_evaluations", ["worst_finding_id"], postgresql_where=sa.text("worst_finding_id IS NOT NULL"))
    # CheckConstraints auf der neuen Tabelle
    op.create_check_constraint("ck_app_group_evals_band", "application_group_evaluations", "risk_band IN ('escalate','act','mitigate','monitor','noise')")
    op.create_check_constraint("ck_app_group_evals_source", "application_group_evaluations", "risk_band_source IN ('llm','manual')")
    op.create_check_constraint("ck_app_group_evals_action_type", "application_group_evaluations", "action_type IS NULL OR action_type IN ('patch','mitigate','watch','none','investigate')")
    # Alte Constraints und Spalten weg
    op.drop_constraint("ck_application_groups_band", "application_groups")
    op.drop_constraint("ck_application_groups_action_type", "application_groups")
    op.drop_column("application_groups", "risk_band")
    op.drop_column("application_groups", "risk_band_reason")
    op.drop_column("application_groups", "risk_band_source")
    op.drop_column("application_groups", "risk_band_computed_at")
    op.drop_column("application_groups", "worst_finding_id")
    op.drop_column("application_groups", "group_findings_fingerprint")
    op.drop_column("application_groups", "action_type")

def downgrade():
    # Eval-Spalten zurück auf application_groups, Daten LEER (Cut akzeptiert).
    op.add_column("application_groups", sa.Column("risk_band", sa.String(16), nullable=True))
    # … alle sieben Spalten zurück
    op.create_check_constraint("ck_application_groups_band", "application_groups", "risk_band IS NULL OR risk_band IN ('escalate','act','mitigate','monitor','noise')")
    op.create_check_constraint("ck_application_groups_action_type", "application_groups", "action_type IS NULL OR action_type IN ('patch','mitigate','watch','none','investigate')")
    op.drop_table("application_group_evaluations")
```

Downgrade lässt die Eval-Spalten leer — der Cut wird beim Upgrade hingenommen, ein Rollback erlaubt aber das Schema zurückzubauen. Ein etwaiges erneutes Upgrade nach Rollback startet wieder mit leerer Junction und Pass-2 füllt sie neu.

### Pass-2-Trigger-Adaptation

Heutige Pass-2-Enqueue-Logik in `app/api/scans.py:460-478` schaut auf `grp.group_findings_fingerprint == new_fp and grp.risk_band is not None` und skippt wenn beides gilt. Nach Block T:

```python
# Junction-Lookup pro (group, server)
existing_eval = sess.execute(
    select(ApplicationGroupEvaluation)
    .where(
        ApplicationGroupEvaluation.group_id == grp.id,
        ApplicationGroupEvaluation.server_id == server.id,
    )
).scalar_one_or_none()

new_fp = group_findings_fingerprint(findings_in_group)
if existing_eval and existing_eval.group_findings_fingerprint == new_fp:
    continue  # nichts zu tun
# Pass-2-Job queuen
```

Damit triggert der nächste Scan jedes Servers automatisch Pass-2 für jede Group ohne Junction-Row. Der Re-Build der Junction nach Deploy passiert organisch über das natürliche Scan-Intervall (Cron-Schedule des Agents — typisch alle 24h, oft alle 1-6h). Kein dedizierter Backfill-Sub-Tick im Worker nötig.

### Pass-2-Persistierung schreibt in die Junction

`app/workers/llm_worker.py` Zeilen ~1190 und ~1346 (`group.risk_band = risk_band; group.risk_band_reason = reason; …`) werden ersetzt durch `UPSERT` in `application_group_evaluations`:

```python
stmt = pg_insert(ApplicationGroupEvaluation).values(
    group_id=group.id,
    server_id=server.id,
    risk_band=evaluation.risk_band,
    risk_band_reason=evaluation.reason,
    risk_band_source="llm",
    risk_band_computed_at=datetime.now(UTC),
    worst_finding_id=evaluation.worst_finding_id,
    group_findings_fingerprint=gf_fp,
    action_type=evaluation.action_type,
)
stmt = stmt.on_conflict_do_update(
    index_elements=["group_id", "server_id"],
    set_={
        "risk_band": stmt.excluded.risk_band,
        "risk_band_reason": stmt.excluded.risk_band_reason,
        "risk_band_source": stmt.excluded.risk_band_source,
        "risk_band_computed_at": stmt.excluded.risk_band_computed_at,
        "worst_finding_id": stmt.excluded.worst_finding_id,
        "group_findings_fingerprint": stmt.excluded.group_findings_fingerprint,
        "action_type": stmt.excluded.action_type,
    },
)
session.execute(stmt)
```

UPSERT statt INSERT, weil dieselbe `(group, server)`-Kombination bei mehrfachen Scans des Servers immer wieder neu bewertet wird (Fingerprint-Drift, neue Findings in der Group).

### `inherit_group_risk_to_findings` (TICKET-002) joint auf Junction

Heute (`app/services/finding_group_inheritance.py`):

```python
stmt = (
    update(Finding)
    .where(Finding.application_group_id == ApplicationGroup.id)
    .where(ApplicationGroup.risk_band.is_not(None))
    .values(
        risk_band=ApplicationGroup.risk_band,
        risk_band_reason=ApplicationGroup.risk_band_reason,
        ...
    )
)
```

Nach Block T:

```python
stmt = (
    update(Finding)
    .where(Finding.application_group_id == ApplicationGroupEvaluation.group_id)
    .where(Finding.server_id == ApplicationGroupEvaluation.server_id)
    .where(ApplicationGroupEvaluation.risk_band.is_not(None))
    .values(
        risk_band=ApplicationGroupEvaluation.risk_band,
        risk_band_reason=ApplicationGroupEvaluation.risk_band_reason,
        risk_band_source="llm",
        risk_band_computed_at=ApplicationGroupEvaluation.risk_band_computed_at,
    )
)
```

Der Composite-Match (`Finding.application_group_id == Junction.group_id AND Finding.server_id == Junction.server_id`) ist der saubere 3NF-Join. Server-A-Findings erben aus `(group, A)`-Junction, B-Findings aus `(group, B)`-Junction — kein Cross-Server-Leak mehr.

### UI bei Eval-Lücke

Wenn auf der Server-Detail-Seite eine Group sichtbar ist (Findings dieses Servers sind in der Group), für die noch keine Junction-Row existiert: die Group-Card rendert mit einer **„Nicht bewertet"-Pille** und einem Hinweis-Text *„Diese Group wird beim nächsten Scan ausgewertet."*. Kein Band, keine Aktion, kein Sortier-Schlüssel — die Group landet in einer eigenen Sortier-Bucket unter den bewerteten Cards.

Konkret in `app/templates/_partials/application_group_card.html`: die heute existierende Logik die `group.risk_band IS NULL` als „evaluating"-Zustand rendert (siehe `_partials/group_evaluating_card.html`) wird verallgemeinert auf „keine Junction-Row für diesen Server". Variable-Renaming `group.risk_band` → `evaluation.risk_band` (mit Fallback auf `None` wenn `evaluation IS NULL`).

## Begründung

**Warum Junction statt Drop-Eval-komplett (Variante C aus Designdiskussion)?**

- Junction wäre semantisch das Minimum. „Drop-Eval-komplett" würde bedeuten: Group hat keine `worst_finding_id`-Spalte mehr, kein `risk_band_computed_at`. UI müsste „Worst-Finding pro Group pro Server" als `max(Finding.risk_band, Finding.severity_priority, …)` rechnen — ein deutlicher Query-Komplexitätssprung an mehreren Read-Sites.
- Die Junction ist semantisch derselbe Datenraum wie heute auf Group, nur korrekt aufgeschlüsselt. Schreib-Pfade ändern sich minimal (Pass-2 schreibt UPSERT statt direkten Set), Read-Pfade bekommen ein Join.

**Warum Drop & Rebuild statt Daten-Migration (Variante (b)/(c) aus Designdiskussion)?**

- Bestehende Eval-Werte sind last-write-wins-falsch. Eine Migration die sie pro Server repliziert würde den Fehler in N Zeilen vervielfältigen statt zu beheben — Operator-Entscheidung explizit gegen Datenerhalt.
- Der LLM-Cache trägt die echten per-`(group, server-context)`-Bewertungen. Sie liegen in `llm_risk_cache` mit dem korrekten Key. Pass-2-Re-Run trifft den Cache, schreibt die Junction-Row, kein LLM-Token-Aufwand.
- UI-Lücke „Nicht bewertet" wird über die ohnehin nötige Pille kommuniziert (`_partials/group_evaluating_card.html`-Pfad).

**Warum kein dedizierter Worker-Backfill-Sub-Tick?**

- Pass-2 wird im Block-P-Hook (`app/api/scans.py:436-487`) ohnehin bei jedem Scan eines Servers für jede Group des Servers geprüft (Fingerprint-Diff oder fehlende Bewertung). Mit der Junction-Adaption oben triggert das automatisch für jede `(group, server)`-Kombination ohne Junction-Row.
- Ein zusätzlicher Sub-Tick wäre Code- und Test-Aufwand für einen Pfad der nach dem ersten kompletten Flottenscan-Zyklus dauerhaft leerläuft.
- _Trade-off:_ ein Server der nach Deploy nicht innerhalb von 24h scannt zeigt seine Groups als „Nicht bewertet". Akzeptiert — der Operator sieht das in der UI, kann manuell einen Scan triggern wenn nötig.

**Warum `worst_finding_id` ohne FK?**

- Konsistent mit der heutigen Logik (siehe `app/models.py:793` Kommentar). Findings können gelöscht werden (Status `resolved`, Retention-Sweep), Junction-Row soll überleben mit stale-Pointer. UI fängt das ab.

**Warum CheckConstraint auf `risk_band NOT NULL`?**

- Heute ist `application_groups.risk_band` nullable, um „Group erkannt, aber noch nicht bewertet" zu modellieren. Mit Junction ist das anders: eine Junction-Row existiert nur _nachdem_ Pass-2 gelaufen ist. „Nicht bewertet" wird durch _das Fehlen der Row_ ausgedrückt, nicht durch `risk_band IS NULL`. NOT-NULL macht das Modell präziser.

**Warum keine Group-Aggregat-Spalte für Fleet-Sicht (Variante D)?**

- Nicht in MVP-Scope. Wenn das Dashboard mal ein „Groups in `act` fleet-wide"-Widget braucht, ein `SELECT group_id, max(severity_priority) FROM application_group_evaluations GROUP BY group_id` läuft auf dem Composite-Index in <ms. Eine denormalisierte Spalte wäre eine zweite Wahrheits-Quelle die wir konsistent halten müssten — nicht jetzt.

## Konsequenzen

**Schema-Änderungen**:

- Migration `0009_application_group_evaluations.py` oder `0010_*` je nach Block-Reihenfolge.
- `ApplicationGroup` verliert sieben Spalten plus zwei Constraints.
- Neue `ApplicationGroupEvaluation` mit drei Constraints, drei Indizes.

**Worker-Änderungen**:

- `app/workers/llm_worker.py` Pass-2-Persistierung — UPSERT statt direkter Field-Set. Betroffene Zeilen heute: ~1035-1063 (Cache-Hit-Pfad), ~1190-1216 (Live-LLM-Pfad), 1346-1353 (`_apply_pass2_to_group`-Helper). Helper-Funktion neu: `_upsert_evaluation(session, group_id, server_id, evaluation, gf_fp)`.

**Service-Layer-Änderungen**:

- `app/services/finding_group_inheritance.py::inherit_group_risk_to_findings` — Update-Statement joint auf Junction, Composite-Match `(group_id, server_id)`. `server_id`-Filter heute existiert als Kwarg — passt mit dem neuen Join zusammen.

**View-Layer-Änderungen**:

- `app/views/server_detail.py::_load_application_groups_for_server` — der Block-Q-optimierte „Group-Meta-Batch" (drei feste SELECTs) bekommt ein viertes SELECT für Junction-Daten (`WHERE server_id = ? AND group_id IN (...)`). Render-Pfad joint im Template via Python-Dict.
- `app/views/findings.py` Cross-Server-View — Findings tragen Band weiter via `Finding.risk_band` (inherited), transparent.
- `app/views/settings.py` LLM-Reviewer-Seite — falls Group-Eval-Stats angezeigt werden, Lookups auf Junction.

**Template-Änderungen**:

- `app/templates/_partials/application_group_card.html` — Variable-Renaming `group.risk_band` → `evaluation.risk_band` (mit None-Fallback).
- `app/templates/_partials/group_evaluating_card.html` — Logik die „Nicht bewertet" anzeigt wird verallgemeinert auf „keine Junction-Row".
- `app/templates/servers/_view_groups.html` — Render-Loop joint pro Group die zugehörige Eval-Row.

**Cache-Layer**:

- `app/services/llm_cache.py` unverändert. Cache-Key war schon per-(group, server-context) — der Persist-Pfad richtet sich nur jetzt mit der Cache-Granularität aus.

**Audit-Events**:

- `risk.band_changed` ist durch TICKET-003 (ADR-0027) bereits ersatzlos entfernt — Block T fügt diesem Event nichts hinzu. Aggregat `risk.pretriage_evaluated` deckt Audit-Bedarf für Band-Bewegungen ab.

**Tests**:

- Neue Tests: `tests/services/test_application_group_evaluations.py`, `tests/workers/test_pass2_persistence_junction.py`, `tests/views/test_server_detail_evaluation_lookup.py`, `tests/services/test_finding_inheritance_junction.py`.
- Geänderte Tests: alle die `ApplicationGroup.risk_band` direkt assert'en. Massen-Refactor analog zu Block Q.

**ARCHITECTURE.md**:

- §5 (Datenmodell) — neue Tabelle aufnehmen, `application_groups` verliert sieben Spalten.

**TICKET-002** (Inheritance) bleibt semantisch unverändert: Findings erben ihren Band aus der für ihren Server zuständigen Eval. Die Code-Anpassung läuft im Block T mit.

## Re-Open-Trigger

- **Wenn Fleet-Aggregate (Dashboard-KPI „N Groups in `act` fleet-wide") schmerzhaft langsam werden**, denormalisierte `risk_band_fleet_max`-Spalte auf `application_groups` (Variante D) als Folge-ADR.
- **Wenn das LLM-Cache-Hit-Rate-Profil zeigt dass per-(group, server)-Bewertungen nahezu deterministisch identisch sind** (z.B. weil host_state-Differenzen zwischen Servern in 95% der Fälle die Bewertung nicht beeinflussen), Junction-Rows konsolidieren über einen „Eval-Equivalence-Hash" — nicht in v1.
- **Wenn Operator-Override-Feature kommt** (Manual-Override eines Bands), pro-`(group, server)`-Override-Pfad mit `risk_band_source='manual'` und eigenem Override-Mechanismus. Diese ADR sieht das Schema schon vor (`source IN ('llm','manual')`).

## Abgewogene Alternativen

| Alternative | Ablehnung |
|---|---|
| **Status quo** | Last-write-wins-Bug bleibt. Operator sieht falsche Bands cross-server. Verworfen. |
| **Eval-Spalten komplett weg, alles auf `Finding.risk_band`** (Variante C) | Sauber, aber UI-Queries werden teurer (`max(Finding.risk_band) GROUP BY (server_id, group_id)` an mehreren Stellen statt direkter Junction-Read). Auch `worst_finding_id` und `risk_band_computed_at` als „aggregate über Finding-Set" zu rekonstruieren ist Aufwand. Junction ist semantisch dasselbe mit billigeren Reads. |
| **Hybrid: Junction + Fleet-Aggregat-Spalte auf Group** (Variante D) | Zwei Wahrheits-Quellen, müssen konsistent gehalten werden. Nicht in MVP-Scope — als Folge-ADR möglich wenn Fleet-Aggregate Performance-Probleme machen. |
| **Daten-Migration: bestehende Eval-Werte auf alle aktiven Server der Group replizieren** | Würde semantisch falsche Daten (last-server-wins) per Server konservieren statt korrigieren. Verworfen. |
| **`server_id=NULL` als Legacy-Fleet-Default in der Junction** | Modell wird hybrid, Read-Sites müssen sich entscheiden ob sie Server-spezifisch oder Fleet-Fallback rendern. Macht den Bug stabiler statt zu beheben. Verworfen. |
| **Dedizierter Worker-Backfill-Sub-Tick** | Wäre Code- und Test-Aufwand für einen Pfad der nach <1 Scan-Zyklus dauerhaft leerläuft. Pass-2-Trigger im Block-P-Hook (`app/api/scans.py`) macht den Backfill organisch. |

## Bedrohungsmodell-Implikationen

- **Cross-Server-Eval-Leak.** Mit Junction unmöglich: Composite-PK trennt physisch. Server-A's Read auf `WHERE server_id = A` sieht nie B's Bewertung.
- **ON DELETE CASCADE.** Wenn ein Server retired/deleted wird, fallen alle seine Junction-Rows mit (`ON DELETE CASCADE`). Wenn eine Group deleted wird, fallen alle ihre Junction-Rows. Beides gewollt. Audit-Spur der Server-Lifecycle-Events bleibt in `audit_events` erhalten.
- **`worst_finding_id` ohne FK.** Stale-Pointer wenn das referenzierte Finding deleted wird. UI-Code fällt auf „nicht mehr vorhanden" zurück (heutige Logik, unverändert).
- **Pass-2-Race auf UPSERT.** Zwei parallele Pass-2-Jobs für dieselbe `(group, server)` (sollte durch das Pass-2-Sibling-Wait-Pattern in `app/workers/llm_worker.py::_pick_next_job_id` nicht passieren, aber als Schutz): UPSERT mit `ON CONFLICT (group_id, server_id) DO UPDATE` ist atomar, letzte Schreiber-Version gewinnt. Akzeptabel — beide Worker hatten zum Pickup-Zeitpunkt dieselbe Datengrundlage.
- **DoS via Junction-Wachstum.** Worst-Case: `O(groups × servers)` Junction-Rows. Bei 200 Groups × 100 Servern = 20k Rows. Kein Storage-Problem (jede Row ~200 Bytes = ~4MB total).

## Quellen / Verweise

- `app/models.py:755-838` — heutige `ApplicationGroup`-Definition.
- `app/workers/llm_worker.py:826-892` — `_persist_pass1_groups` (unverändert für Block T).
- `app/workers/llm_worker.py:1035-1353` — Pass-2-Persistierung (Hauptänderung).
- `app/services/finding_group_inheritance.py` — TICKET-002-Inheritance (Junction-Anpassung).
- `app/api/scans.py:436-487` — Pass-2-Enqueue-Logik (Trigger-Adaption).
- `app/services/llm_cache.py` + `app/services/llm_fingerprints.py:179` — Cache-Key (unverändert, war schon korrekt geschnitten).
- ADR-0022 (Pre-Triage + host_state), ADR-0023 (Pass-1/Pass-2 + Cache-Key), TICKET-002 (Inheritance), ADR-0025 (Block-Q Lazy-Load — Render-Pfad), ADR-0026 (Async-Ingest — komplementär, Worker-Pfad wo Pass-2-Persistierung lebt).
- TICKET-003 (Audit-Noise) — wenn vor Block T merged, einer der Audit-Event-Querverweise hier entfällt.
