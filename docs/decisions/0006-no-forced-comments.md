# ADR-0006 — Niemals Pflicht-Kommentare in der UI

**Status:** Akzeptiert · **Datum:** 2026-05-14

## Kontext

Bei Acknowledge-, Re-Open-, Bulk- und Retire-Aktionen könnte ein Pflicht-Kommentar (`required="true"`) den Audit-Trail aussagekräftiger machen. Standard-Vulnerability-Management-Tools (DefectDojo etc.) erzwingen das oft.

## Entscheidung

Kein Feld in der gesamten UI ist als Pflicht-Kommentar markiert. Acknowledge, Re-Open, Bulk-Acknowledge, Server-Retire, Notes — Kommentar-Felder sind immer optional. Wenn ein Kommentar mitgegeben wird, landet er als `finding_note` mit Author `system-ack`/`system-reopen`. Ohne Kommentar bleibt nur der Audit-Event als Beleg.

## Begründung

Erzwungene Kommentare produzieren in der Praxis "asdf", ".", "ok" — und reduzieren damit die Audit-Qualität eher als sie zu erhöhen. Der Audit-Event allein dokumentiert Wer/Wann/Was zuverlässig. Wer Kontext liefern will, kann es freiwillig tun.

## Konsequenzen

- Pydantic-Schema und WTForms haben `comment: Optional[str]`, niemals `required=True`.
- DB-Spalten für Kommentar-Felder sind NULL erlaubt.
- Tests müssen den ohne-Kommentar-Pfad mittesten.
- Audit-View muss mit leeren Kommentar-Spalten klar umgehen können.

## Re-Open-Trigger

Wenn ein konkretes Compliance-Mandat einen Pflicht-Kommentar verlangt — dann nur für genau die betroffene Aktion und nur mit explizitem Opt-in in den Settings.
