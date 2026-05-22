# TICKET-003 — `risk.band_changed`-Audit-Events ersatzlos entfernen

**Status:** Abgeschlossen 2026-05-22 (Commit `7867220 fix(ticket-003): remove risk.band_changed audit events`)
**Komponenten:** ``app/api/scans.py``, ``tests/api/test_scans_risk_pretriage.py``, ``tests/adversarial/test_pretriage_no_llm_override.py``, ``docs/decisions/0022-risk-based-prioritization.md`` (§Audit-Events + §Bedrohungsmodell #6), ``docs/blocks/O-risk-engine.md`` (§Tests + §Definition of Done), neue ``docs/decisions/0027-no-per-finding-risk-band-audit.md`` (ADR-Nummer 0026 war beim Implementierungs-Commit bereits von Block R belegt; daher 0027).
**Umfang:** Code + Tests + Spec-Supersession (ADR-0027). Keine Schema-Migration, keine UI-Änderung.

**Verifikation:** `grep -rn risk\\.band_changed app/ tests/` ist leer; CHANGELOG-Eintrag und ADR-Index angeglichen.

## Problem

Production-Befund 2026-05-22: ``audit_events``-Tabelle ist mit ``risk.band_changed``-Zeilen geflutet. Allein bei einem einzigen `rke2-sv-0`-Scan (id-Range 49601–49616+) werden pro betroffenem Finding eine Zeile geschrieben — ``actor='rke2-sv-0'``, ``actor_user_id=NULL``, ``comment=NULL``, ``metadata={"to": "pending"/"monitor"/…}``. Bei ~5000 OPEN-Findings pro Server und mehreren Servern × jedem Re-Ingest entstehen ~10000–50000 Zeilen pro Tag.

Bewertungsmodell-Wechsel zwischen Pre-Triage-Heuristik (Block O) und LLM-Vererbung (Block P / TICKET-002) erzeugt nach jedem Scan kaskadenhafte Band-Übergänge — die einzelnen Events sind **operationell wertlos**: kein Operator liest sie ab, sie sind hochfrequent, der Aggregat-Snapshot ``risk.pretriage_evaluated`` (counters: {pending: N, monitor: N, noise: N, unknown: N}) deckt den Information-Bedarf bereits ab.

Konsequenz heute:
- Audit-Log-UI (``/audit``) ist unbenutzbar — relevante Events (auth.login, server.revoke, settings.changed, …) verschwinden im Noise.
- ``audit_events``-Tabelle wächst unbegrenzt; Backup-Größe + Query-Zeit auf Audit-Filter degradieren.
- Operator-Investigations beginnen damit ``risk.band_changed`` im SQL-Filter rauszuwerfen.

## Lösung — User-Anforderung (2026-05-22)

> *"risk.band_changed soll kein audit log eintrag erzeugen. Das ist nur noise."*

Konkret: das Event wird **ersatzlos** entfernt — aus allen Quellen, nicht nur aus dem Pre-Triage-Loop. Heute gibt es genau eine Emit-Stelle (``app/api/scans.py:346-358``), aber die Spec (ADR-0022 §Bedrohungsmodell #6: *"Jede Band-Bewegung produziert `risk.band_changed`. Test verifiziert."*) ist als allgemeine Invariante formuliert und gilt auch für zukünftige LLM-/Manual-Override-Pfade. Die Invariante wird durch ADR-0026 explizit zurückgenommen.

Bestehende ~49000 Zeilen bleiben unangetastet — keine Cleanup-Migration. Begründung: historische Forensik-Wert ≥ Storage-Kosten, und ein ``DELETE`` ohne Downgrade-Pfad in einer Alembic-Migration wäre semantisch unsauber (Audit-Daten sind per Definition append-only).

## Designentscheidung — warum komplette Entfernung, nicht "nur Pre-Triage"

Drei Alternativen wurden erwogen:

| Option | Bewertung |
|---|---|
| **A — Nur Pre-Triage-Loop schweigt, LLM-/Manual-Pfade behalten Event** | Verworfen. Es gibt heute keinen LLM- oder Manual-Emit-Pfad (Grep ``risk\.band_changed`` in ``app/`` zeigt 1 Treffer). Eine selektive Beibehaltung wäre Spec-Krypsis ohne aktuellen Nutzen — die Operator-UI würde nie ein "echtes" ``risk.band_changed`` zu Gesicht bekommen. |
| **B — Pro-Finding-Detail in structlog (``app/workers/llm_worker.py``-Pattern), nur Aggregat ins Audit-Log** | Verworfen. ``risk.pretriage_evaluated`` ist bereits das Aggregat. Der zusätzliche structlog-Eintrag pro Finding würde den Application-Log fluten (analog zum ursprünglichen Problem, nur in einem anderen Sink). Operator-Wert weiterhin null. |
| **C — Ersatzlos entfernen, ADR-Invariante zurücknehmen** | **Empfohlen.** Aggregat (``risk.pretriage_evaluated``) bleibt erhalten — pro Scan ein Event mit Counter-Dict. Wenn in Zukunft Per-Finding-Audit nötig wird, kommt er via neuer ADR mit Trigger-Begründung zurück. |

## Implementierungs-Plan

### 1. Code-Patch — `app/api/scans.py`

Aktueller Block (Zeilen 345–358):

```python
if finding.risk_band != new_band:
    log_event(
        "risk.band_changed",
        target_type="finding",
        target_id=str(finding.id),
        metadata={
            "from": finding.risk_band,
            "to": new_band,
            "source": "engine",
            "reason": evaluation.reason,
        },
        actor=server.name,
        session=sess,
    )

finding.risk_band = new_band
finding.risk_band_reason = evaluation.reason
finding.risk_band_source = "engine"
finding.risk_band_computed_at = evaluation.computed_at
band_counters[new_band] += 1
```

Neu:

```python
finding.risk_band = new_band
finding.risk_band_reason = evaluation.reason
finding.risk_band_source = "engine"
finding.risk_band_computed_at = evaluation.computed_at
band_counters[new_band] += 1
```

Der ``if finding.risk_band != new_band:``-Block entfällt komplett. ``risk.pretriage_evaluated`` (Zeilen 366–373) bleibt unverändert — das Aggregat ist die einzige verbleibende Audit-Spur.

Wenn in einem zukünftigen Block ein LLM- oder Manual-Override-Pfad implementiert wird (heute noch nicht vorhanden), darf er **keinen** ``risk.band_changed``-Audit emittieren. ADR-0026 dokumentiert die Invariante.

### 2. Tests anpassen — pro betroffenes Test-Modul ein präziser Edit

**`tests/api/test_scans_risk_pretriage.py`** — fünf Stellen:

- Docstring (Zeilen 6–14): Aufzählungspunkte zu ``risk.band_changed`` rauswerfen, ersetzen durch *"Bands ändern sich bei Re-Ingest deterministisch, `risk.pretriage_evaluated`-Aggregat wird pro Scan geschrieben."*
- Zeile 201–203 (``changes_1 = _audit_events(... action="risk.band_changed")`` + ``assert len(changes_1) == 1``): kompletter Block entfernt.
- Zeile 212–213 (Idempotenz-Check): kompletter Block entfernt.
- Zeile 254–256 (KEV-Übergangstest erwartet zwei Events): umformuliert auf den ``risk.pretriage_evaluated``-Aggregat-Counter — der KEV-Übergang zeigt sich jetzt darin dass das Aggregat nach dem zweiten Scan einen ``pending``-Counter > 0 hat während es nach dem ersten 0 war.
- Zeile 287–335 (LLM-Override-Adversarial): die ``_audit_events(... action="risk.band_changed")``-Asserts fallen weg; der zentrale Invariant-Check bleibt (``finding.risk_band_source == "llm"`` und ``finding.risk_band == "act"`` nach Re-Ingest unverändert). **Field-Level-Asserts sind die robustere Spec-Verankerung als das Audit-Event.**

**`tests/adversarial/test_pretriage_no_llm_override.py`** — zwei Stellen:

- Docstring (Zeile 14–15): Aufzählungspunkt *"Kein neues `risk.band_changed`-Audit-Event für diese Finding-ID"* streichen, ersetzen durch *"`risk_band_source` und `risk_band_computed_at` bleiben unverändert (Field-Level-Invariante)."*
- Helper ``_band_changed_events_for`` (Zeilen 103–115): komplett entfernt.
- Test-Body (Zeilen 211–217): Audit-Assert raus, Field-Level-Assert bleibt (``finding.risk_band == "act" and finding.risk_band_source == "llm" and finding.risk_band_computed_at == original_ts``).

Anschließend ``grep -r risk\.band_changed tests/`` muss leer sein.

### 3. Spec-Updates

**`docs/decisions/0022-risk-based-prioritization.md`** — drei chirurgische Edits:

- §Audit-Events (Zeile 326): Bullet *"`risk.band_changed` — pro Finding wenn der Band sich ändert. Body enthält alt + neu + Source (engine/llm/manual) + Reason. Deckt sowohl Pre-Triage-Klassifikation als auch zukünftige LLM-Updates und Demote-Events ab."* → ersatzlos streichen. Erläuternde Fußnote: *"`risk.band_changed` wurde durch ADR-0026 ersatzlos entfernt (Noise-Reduktion 2026-05-22). Aggregat `risk.pretriage_evaluated` deckt den Audit-Bedarf ab."*
- §Bedrohungsmodell #6 (Zeile 673): *"Audit-Events sind vollständig. Jede Band-Bewegung produziert `risk.band_changed`. Test verifiziert."* → *"Audit-Events sind aggregiert. Pro Scan wird `risk.pretriage_evaluated` mit Band-Counter-Dict geschrieben (Field-Level-Invarianten in den Tests verankert; siehe ADR-0026)."*
- Header-Status auf *"Akzeptiert (Spec §Audit-Events teilweise abgelöst durch ADR-0026)"*.

**`docs/blocks/O-risk-engine.md`** — zwei Edits:

- §Tests (Zeile 473–476): Bullet *"Re-Ingest mit gleichem Snapshot + gleichen Findings → Bands unverändert, **keine `risk.band_changed`-Audits**"* → *"Re-Ingest mit gleichem Snapshot + gleichen Findings → Bands unverändert, `risk.pretriage_evaluated`-Counter identisch."*
- Pseudo-Code (Zeile 455–457): den ``audit_event("risk.band_changed", ...)``-Block aus dem Skizzen-Snippet entfernen.

**Neue ADR `docs/decisions/0026-no-per-finding-risk-band-audit.md`** (Skelett):

```markdown
# ADR-0026 — `risk.band_changed`-Audit-Events ersatzlos entfernt

**Status:** Akzeptiert
**Datum:** 2026-05-22
**Vorgänger:** ADR-0022 §Audit-Events (teilweise abgelöst)

## Kontext

ADR-0022 hatte pro Band-Wechsel einen `risk.band_changed`-Audit-Event vorgesehen.
In Produktion (2026-05-22) entstehen pro Scan ~5000+ Events. Audit-UI unbenutzbar,
Tabelle wächst unbegrenzt, kein Operator-Mehrwert.

## Entscheidung

`risk.band_changed` wird in keinem Codepfad mehr geschrieben (Pre-Triage, LLM-Pass-2,
zukünftige Manual-Overrides). Aggregat `risk.pretriage_evaluated` bleibt einzige
Audit-Spur für Band-Übergänge.

## Begründung

- Per-Finding-Detail ist im `audit_events`-Sink wertlos — kein Read-Pfad nutzt es.
- Aggregat-Counter deckt den Compliance-Bedarf ("haben sich Bands seit letztem Scan
  bewegt?").
- Field-Level-Invarianten (`risk_band_source`, `risk_band_computed_at`) bleiben in
  Tests verankert — Spec-Coverage wandert von Audit-Event-Existenz auf direkten
  Field-Read.

## Konsequenzen

- Bestehende `risk.band_changed`-Zeilen bleiben als Historie unangetastet —
  kein DELETE, kein Migration. Operator-Filter im Audit-UI: `WHERE action !=
  'risk.band_changed'`.
- Adversarial-Tests in `tests/adversarial/test_pretriage_no_llm_override.py`
  prüfen Field-Level-Invarianten statt Audit-Event-Absenz.

## Re-Open-Trigger

- Wenn Compliance einen pro-Finding-Audit verlangt (z.B. für regulierte Branchen).
  Dann mit Severity-Filter (`escalate`/`act` only) oder strukturiertem Worker-Log
  als Alternative.
- Wenn Manual-Override-Feature (Operator setzt `risk_band` per Hand) implementiert
  wird — dann separate Event-Action `risk.manual_override` (NICHT `risk.band_changed`),
  weil semantisch anders (User-driven, einmalig, geringer Volume).
```

**`docs/decisions/README.md`** — Tabellenzeile für ADR-0026 ergänzen, ADR-0022-Status auf *"Akzeptiert (§Audit-Events teilweise abgelöst durch 0026)"*.

### 4. CHANGELOG

Eintrag unter dem nächsten Version-Tag (vermutlich v0.10.1 oder v0.11.0):

```
- `risk.band_changed`-Audit-Events ersatzlos entfernt (ADR-0026). Aggregat
  `risk.pretriage_evaluated` bleibt einzige Audit-Spur für Band-Übergänge.
  Bestehende historische Events bleiben in der Tabelle erhalten.
```

### 5. Operator-Hinweis (optional)

Falls ein Audit-UI-Filter empfohlen werden soll: `docs/operations.md`-Snippet *"Audit-Log-Filter — bestehende `risk.band_changed`-Zeilen ausblenden"* mit der SQL-WHERE-Klausel. Nur als Komfort, kein Pflichtbestandteil des Tickets.

## Definition-of-Done

1. ``app/api/scans.py``: ``if finding.risk_band != new_band:``-Block (Zeilen 345–358) entfernt; Pre-Triage-Logik schreibt nur noch die vier Felder + Counter.
2. ``tests/api/test_scans_risk_pretriage.py``: alle fünf ``risk.band_changed``-Asserts ersetzt durch Field-Level-Checks oder ``risk.pretriage_evaluated``-Counter-Checks.
3. ``tests/adversarial/test_pretriage_no_llm_override.py``: Helper + Asserts entfernt, Field-Level-Invariante bleibt.
4. ``grep -rn risk\.band_changed app/ tests/`` ist leer (kein Code-/Test-Treffer).
5. ADR-0026 angelegt, ADR-0022 + Block-O-Spec angepasst, ADR-Index aktualisiert.
6. CHANGELOG-Eintrag.
7. Lint/Type-Gates grün: ``ruff check . && ruff format --check . && mypy app/``.
8. Test-Suite grün: ``pytest -v`` (Erwartung: kein Test-Count-Delta nach Anpassung, weil pro entferntem Event-Assert ein Field-Level-Assert dazukommt).
9. Alembic-Roundtrip grün (keine Migration in diesem Ticket, aber Gate bleibt aus CI-Konsistenz).

## NICHT in diesem Ticket

- **Cleanup bestehender ``risk.band_changed``-Zeilen** in der Produktion. Explizite Operator-Entscheidung 2026-05-22: stehen lassen.
- **Andere Audit-Events** anfassen (``risk.pretriage_evaluated`` bleibt, ``host_state.snapshot_received`` bleibt, etc.).
- **Audit-UI-Filter-Default** auf "alles außer risk.band_changed" setzen — wenn überhaupt, dann in separater UI-Iteration.
- **Pro-Finding-Audit als structlog-Eintrag** ins Application-Log — explizit verworfen (Option B in §Designentscheidung).
- **`risk.manual_override`-Event** für ein zukünftiges Manual-Override-Feature — wenn dieses Feature kommt, kriegt es eine eigene ADR und ein eigenes Event mit anderem Action-Namen (siehe ADR-0026 §Re-Open-Trigger).
- **CheckConstraint/Trigger** der `risk.band_changed` als Action-String verbietet — nicht nötig, Code-Review und das fehlende Emit-Site reichen.

## Sanity-Checks vorab (vor Implementation auszuführen)

```bash
# (a) Bestätige: es gibt genau eine Emit-Stelle
grep -rn "risk\.band_changed" /Users/skroll/code_local/secscan/app/

# Erwartung: genau eine Zeile in app/api/scans.py:347.

# (b) Bestätige: keine andere Aktion heißt ähnlich (Schutz vor Verwechslung)
grep -rn 'log_event("risk\.' /Users/skroll/code_local/secscan/app/

# Erwartung: nur risk.pretriage_evaluated bleibt.

# (c) Bestätige Volume in Produktion (für CHANGELOG-Zahl)
kubectl -n secscan exec secscan-db-1 -- env PGPASSWORD="$PGPASS" \
  psql -h secscan-db-rw -U secscan -d secscan -c "
SELECT action, COUNT(*) FROM audit_events
WHERE ts > now() - interval '7 days'
GROUP BY action ORDER BY 2 DESC LIMIT 10;"

# Erwartung: risk.band_changed dominiert die Top-10 mit ~Faktor 100× über dem
# zweitgrößten Event.
```
