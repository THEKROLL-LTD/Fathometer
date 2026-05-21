# ADR-0027 — `risk.band_changed`-Audit-Events ersatzlos entfernt

**Status:** Akzeptiert
**Datum:** 2026-05-22
**Vorgaenger:** ADR-0022 §Audit-Events (teilweise abgeloest)

## Kontext

ADR-0022 hatte pro Band-Wechsel einen `risk.band_changed`-Audit-Event vorgesehen.
In Produktion entstehen dadurch pro Scan tausende Events. Die Audit-UI wird durch
Noise unbenutzbar, die Tabelle waechst schnell, und es gibt keinen operativen
Read-Pfad fuer diese per-Finding-Zeilen.

Das bestehende Aggregat `risk.pretriage_evaluated` schreibt pro Scan ein Counter-
Dict fuer die Band-Verteilung und deckt den tatsaechlichen Audit-Bedarf ab.

## Entscheidung

`risk.band_changed` wird in keinem Codepfad mehr geschrieben. Das gilt fuer den
heutigen Pre-Triage-Ingest und fuer zukuenftige LLM- oder Manual-Override-Pfade.
Das Aggregat `risk.pretriage_evaluated` bleibt die einzige Audit-Spur fuer
Band-Bewegungen.

## Begruendung

- Per-Finding-Detail ist im `audit_events`-Sink wertlos: kein Operator-Workflow
  nutzt diese Zeilen.
- Das Aggregat pro Scan reduziert Volume drastisch und beantwortet die relevante
  Frage, wie viele Findings in welchem Band gelandet sind.
- Tests sichern die fachlichen Invarianten direkt auf den Feldern ab
  (`risk_band`, `risk_band_source`, `risk_band_computed_at`) statt indirekt ueber
  Audit-Event-Existenz.

## Konsequenzen

- Bestehende `risk.band_changed`-Zeilen bleiben als Historie unangetastet. Es
  gibt kein `DELETE` und keine Alembic-Migration fuer Cleanup.
- Adversarial-Tests pruefen Field-Level-Invarianten fuer LLM-gesetzte Bands.
- Neue Codepfade duerfen fuer Band-Wechsel keinen `risk.band_changed`-Event
  einfuehren. Falls ein Operator-gesteuerter Override kommt, braucht er eine
  semantisch eigene Action, z.B. `risk.manual_override`.

## Re-Open-Trigger

- Compliance verlangt einen pro-Finding-Audit fuer regulierte Umgebungen. Dann
  braucht es eine neue ADR mit Trigger-Begruendung und Volume-Begrenzung.
- Ein Manual-Override-Feature wird implementiert. Dann sollte ein eigener,
  user-getriebener Event wie `risk.manual_override` entstehen, nicht
  `risk.band_changed`.
