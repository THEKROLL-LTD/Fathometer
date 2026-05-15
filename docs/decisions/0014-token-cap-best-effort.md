# ADR-0014 — Token-Cap ist Best-Effort, keine Pre-Reservation

**Status:** Akzeptiert · **Datum:** 2026-05-15

## Kontext

Der Tages-Token-Cap aus `Setting.llm_daily_token_cap` (Default
1.000.000) ist als **Cost-Cap** gedacht — er soll runaway-Loops und
hängende Stream-Schleifen budgetär begrenzen.

Der aktuelle Mechanismus (`app/services/llm_token_tracker.py`):

1. Vor jedem Stream-Start: `get_today_usage()` summiert `prompt_tokens`
   und `completion_tokens` aller heutigen `LlmMessage`-Zeilen.
2. Wenn `used >= cap`: 429.
3. Nach Stream-Ende: Assistant-Message mit Provider-`usage` persistieren.

**Race**: zwei parallele Streams können beide den Check passieren
(beide sehen `used < cap`), beide laufen los, beide schreiben am Ende
ihre Token-Counts. Im Worst-Case überschreitet die Tages-Summe den
Cap um `n × max_completion_tokens`, wobei `n` die Anzahl gleichzeitig
streamender Conversations ist.

Der Block-G-Security-Auditor hat das als CONCERN markiert (Cost-Cap,
nicht Security-Cap).

## Entscheidung

Wir **akzeptieren das Race-Verhalten als Best-Effort-Cap** und
implementieren *keine* Pre-Reservation-Mechanik im MVP.

## Begründung

- **Skala**: secscan ist Single-User. Realistisch sind ein bis zwei
  gleichzeitig offene Chat-Tabs, also `n ≤ 2`. Die Mehrkosten im
  Worst-Case sind ≤ 2 × `max_completion_tokens` (typisch
  ≤ 8.000 Tokens) und damit deutlich unter 1% des Default-Caps von
  1.000.000.
- **Token-Cap-Charakter**: der Cap ist eine Kosten-Bremse, kein
  Sicherheits-Mechanismus. Hartes Limit-Enforcement würde
  Pre-Reservation, Lock-Tabellen oder eine Counter-Row mit
  `SELECT ... FOR UPDATE` bedeuten — das wäre messbare zusätzliche
  Latenz auf dem Stream-Start-Pfad für einen marginalen
  Risiko-Reduktions-Effekt.
- **Reset-Verhalten**: der Cap setzt sich täglich um 00:00 UTC
  zurück. Auch wenn ein Tag um wenige Prozent überschritten wird,
  fängt der nächste Tag den Operator wieder ein.

## Konsequenzen

- Operator-Hinweis im Settings-UI: "Tages-Token-Cap ist eine
  Best-Effort-Kostenbremse. Parallele Streams können sie geringfügig
  überschreiten."
- Cap-Check bleibt auf `is_blocked()` mit Snapshot-Logik.
- Keine zusätzlichen Locks, keine Counter-Tabelle.

## Re-Open-Trigger

- Wenn secscan ein Multi-User-Auth-Modell bekommt (siehe ADR-0004),
  steigt `n` deutlich (jeder User kann parallel chatten) und das Race
  wird signifikant.
- Wenn höhere Concurrency-Profile erwartet werden (z.B. Auto-Triage-
  Workflows die N Findings parallel an das LLM schicken).
- Wenn der Default-Cap drastisch sinkt (z.B. 10.000 Tokens/Tag für
  einen Cost-Sensitive-Setup), wird die relative Überschreitung
  groß genug um auf Pre-Reservation umzubauen.
