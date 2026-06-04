# ADR-0046 — Sidebar-Group-Aufklapp-Zustand: Cookie + Server-Render

**Status:** Akzeptiert · **Datum:** 2026-06-04 · **Block:** AC — Sidebar Group State

Bezug: [ADR-0034](0034-host-group-data-model.md) §Sidebar-Verhalten (Default collapsed — bleibt der Fallback ohne Cookie), [ADR-0019](0019-dashboard-polling-not-sse.md)/[ADR-0030](0030-server-detail-performance.md) (Sidebar-Polling-Endpoint, 60s-`outerHTML`-Swap), CLAUDE.md §HTMX-OOB-Single-Source-Pattern (ein Partial, beide Pfade).

## Kontext

Sidebar-Gruppen (`sidebar/_group_section.html`) sind `<details>` ohne `open`-Attribut — Default eingeklappt (ADR-0034). Die gesamte Server-Liste wird per HTMX ersetzt: beim Initial-Load (`hx-trigger="load"`) und alle 60 s durch den Polling-Endpoint (`GET /_partials/sidebar`, `outerHTML`-Swap). Folge: Jede vom Operator aufgeklappte Gruppe klappt spätestens nach 60 s wieder zu; Reload, Navigation und Rückkehr nach Tagen verlieren den Zustand ebenfalls.

Anforderung (User, 2026-06-04): Aufgeklappte Gruppen bleiben aufgeklappt — über HTMX-Swaps, Seiten-Reloads, Polling-Intervalle und Browser-Sessions hinweg.

## Entscheidung

**Cookie + Server-Render.** Der Client schreibt den Aufklapp-Zustand in ein langlebiges Cookie; der Server liest es und rendert das `open`-Attribut direkt ins Partial. Damit ist der Zustand auf **jedem** Render-Pfad automatisch korrekt — Initial-Render, Polling-Swap, Reload, Rückkehr nach Wochen — ohne Client-seitiges Re-Apply nach Swaps.

1. **Cookie:** `sidebar_open_groups`, Wert = kommaseparierte Group-IDs (z. B. `1,5,12`). `Max-Age` 1 Jahr, `Path=/`, `SameSite=Lax`, **kein** `HttpOnly` (JS muss schreiben), `Secure` analog zur Session-Cookie-Config. Kein personenbezogener oder sicherheitsrelevanter Inhalt — nur ganzzahlige Group-IDs.
2. **Schreiben (JS, `sidebar.js`):** Delegierter `toggle`-Listener (Capture-Phase — `toggle` bubbelt nicht) auf dem Sidebar-Container. Bei jedem Toggle wird der Zustand **aus dem DOM** neu eingesammelt (alle `details.hostgroup[open]`-IDs) und das Cookie komplett neu geschrieben — kein inkrementelles Add/Remove, damit Cookie und DOM nie divergieren. Stale IDs (gelöschte Gruppen) heilen sich beim nächsten Toggle selbst.
3. **Lesen (Server, `build_sidebar_context()`):** Cookie parsen → `sidebar_open_group_ids: set[int]`. Defensive Validierung: nur Ints, Nicht-Parsebares verwerfen, Längen-Cap (max. 64 Einträge / 512 Zeichen, Rest ignorieren). Da `build_sidebar_context()` von beiden Render-Pfaden (Context-Processor + Polling-Endpoint) genutzt wird, ist der Zustand automatisch single-source.
4. **Rendern (`_group_section.html`):** `open`-Attribut + `aria-expanded` conditional aus `sidebar_open_group_ids`. Der JS-Toggle-Handler zieht `aria-expanded` auf dem `<summary>` nach (heute hartes `"false"` — Drive-by-Fix im selben Block).

## Begründung

- **Strukturell statt Reparatur-JS:** localStorage hätte nach jedem Swap einen Re-Apply-Hook gebraucht — ein zweiter Zustands-Pfad neben dem Server-Render, exakt die Drift-Klasse aus dem Block-W-Heartbeat-Bug. Cookie macht den Server-Render selbst korrekt.
- **Kein Backend-Schema:** Eine DB-Lösung (Spalte/Prefs-Tabelle + POST-Endpoint + CSRF) wäre für ein Single-User-Tool überdimensioniert und würde UI-Zustand in Domänen-Tabellen tragen.
- **Kein Request pro Klick:** Toggle schreibt nur das Cookie; der Zustand fährt beim nächsten ohnehin stattfindenden Request mit.

## Konsequenzen

- Zustand gilt **pro Browser/Gerät** (bewusst akzeptiert, Single-User-Tool an einem Arbeitsplatz).
- Cookie fährt bei jedem Request mit (< 100 Bytes bei realistischen Gruppen-Zahlen — irrelevant).
- `build_sidebar_context()` bekommt eine Request-Abhängigkeit (Cookie-Read). Lesender Zugriff via `flask.request` ist in beiden Pfaden vorhanden; Pure-Unit-Tests setzen das Cookie im Test-Client.
- Der Filter-/Suchpfad (`sidebarSearch`) bleibt unberührt: Suche versteckt Server-Rows via CSS-Klasse, ändert aber keinen `open`-Zustand und schreibt **kein** Cookie. Ein Auto-Expand bei aktiver Suche bleibt Out of Scope (siehe unten).

## Verworfen

- **localStorage + Re-Apply nach jedem Swap:** zweiter Zustands-Pfad gegen das Server-Render-Modell, Collapsed-Flash beim Initial-Paint, jeder künftige Sidebar-Umbau muss an den Hook denken.
- **DB-Persistenz (Spalte an `server_groups` oder Prefs-Tabelle):** Migration + Endpoint + Request pro Klick ohne Mehrwert für Single-User; Schema-Verschmutzung.
- **`hx-preserve` auf den `<details>`-Elementen:** konserviert den kompletten alten DOM-Teilbaum — die Heartbeat-/Count-Updates aus dem Polling kämen in offenen Gruppen nicht mehr an.

## Re-Open-Trigger

- Wenn geräteübergreifende Persistenz gewünscht wird (Zweit-Arbeitsplatz): DB-Prefs-Lösung als neue ADR, Cookie bleibt dann Read-Through-Cache oder entfällt.
- Wenn Auto-Expand bei aktiver Sidebar-Suche gewünscht wird: separater kleiner Block; muss die Cookie-Schreib-Logik explizit aussparen (transienter Zustand).
