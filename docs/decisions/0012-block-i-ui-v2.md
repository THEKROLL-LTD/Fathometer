# ADR-0012 — Block I bringt UI v2 als separate Phase nach MVP-Abschluss

**Status:** Akzeptiert · **Datum:** 2026-05-15

## Kontext

Während der Implementierung der MVP-Blöcke A–F wurde das UI gegen die Spec aus §7 (Multi-Page-Layout, Card-Grid auf dem Dashboard) gebaut und durch den `reviewer`-Agent abgenommen. Beim Vergleich mit uptime-kuma und anderen modernen Ops-Tools (Linear, Tailscale Admin, Vercel) wurde sichtbar dass das UI funktional vollständig ist, aber visuell und in der Information-Density deutlich hinter dem zurück was Anwender heute von einem Self-Hosted-Ops-Dashboard erwarten.

Drei Optionen zur Bewertung:

1. UI v2 in Block H einbauen (zusammen mit SSE-Live-Updates und Production-Polish).
2. UI v2 als eigenen Block I nach H aufsetzen.
3. UI v2 in v2 zurückstellen (nach erstem Release).

## Entscheidung

**Option 2: UI v2 als eigener Block I nach Block H.** §7 bleibt als Spec-Referenz für die MVP-UI bestehen — Blöcke D, E, F sind reviewer-approved gegen §7 implementiert und werden nicht retroaktiv geändert. Die neue Spec für UI v2 lebt in §7a (Single-Page-Layout, Heartbeat-Bars, Density-Regeln, Inline-Actions, Status-Icons, Empty-States). Block-I-Plan in `docs/blocks/I-ui-modernization.md` mit ausführbarer DoD-Checkliste.

Funktional ändert Block I nichts: alle Endpoints, Routen, Daten-Verträge aus §6 und §7 bleiben gültig. Das ist explizit Layout-/Visual-Refactor ohne neue Features.

## Begründung

Gegen Option 1 (in Block H einbauen): Block H ist als Polish + Live-Updates spezifiziert. Aufgeblähter H wird zur Mülltonne, der `reviewer`-Agent wird unscharf, "fertig"-Meldungen werden unzuverlässig. Ein UI-Refactor mit Single-Page-Layout, Heartbeat-Aggregation und Density-Pass ist mit ~7–10 Tagen Aufwand kein "Polish"-Add-on, sondern braucht eigene Spec, eigene DoD, eigenen Reviewer-Lauf.

Gegen Option 3 (in v2 zurückstellen): die UI ist das Erste was ein Anwender beim ersten Login sieht. Wenn die App nach den 8 MVP-Blöcken funktional perfekt ist, aber wie ein 2018er Bootstrap-Dashboard aussieht, leidet die Adoption — gerade in der Zielgruppe (Operator die zwischen "Cron-Plugin mailt Updates" und "vollwertiges SIEM" suchen) ist die UX ein wesentlicher Differenzierer gegen die aufgeführten Alternativen (DefectDojo, Enterprise-Scanner). Block I direkt nach Block H schließt dieses Lücken-Risiko.

Für Option 2 (separater Block): erlaubt sauberen Reviewer-Lauf mit eigener Checkliste (Heartbeat-Bars wie spec, Sidebar-Layout, Density). MVP nach Block H ist released-fähig und kann notfalls auch ohne Block I als v0.1.0 ausgeliefert werden — Block I ist v0.2.0. Die existierenden Implementierungen aus D/E/F bleiben Reviewer-approved und müssen nicht retroaktiv reauditiert werden.

## Konsequenzen

- §7 bleibt unverändert als Referenz für die MVP-UI. Implementer in Block G und H referenzieren weiter §7 für UI-Belange (Settings-Provider-Block, Dashboard-SSE-Hooks).
- §7a beschreibt die UI-v2-Spec. Block-I-Implementer referenziert §7a plus diesen ADR.
- Block I taucht im STATE.md-Backlog auf, wartet auf Block-H-Abschluss.
- Tests aus Block D, E, F die Markup-spezifisch sind (z.B. "Card mit Klasse `.card`") werden in Block I aktualisiert. Funktionale Tests (View-Logik, Aggregationen) bleiben unverändert.
- Bei späterem Block J ("Power-User-Features": Cmd-K-Palette, Vim-Style-Shortcuts, Optimistic-Updates, Loading-Skeletons) baut der wiederum auf §7a auf.

## Re-Open-Trigger

Niemals. Block I ist als separater Block geplant und wird so umgesetzt. Wenn nach Block H Erkenntnisse aufkommen die das Layout grundsätzlich anders verlangen (z.B. echter Mobile-Bedarf), wird das als Block J/K nachgezogen — nicht durch Re-Öffnung dieses ADRs.
