# ADR-0009 — Mobile-responsive Layout out of scope

**Status:** Akzeptiert · **Datum:** 2026-05-14

## Kontext

Sollen wir explizit für mobile Viewports optimieren? Tailwind/DaisyUI-Defaults skalieren grundsätzlich, aber echte Mobile-First-Optimierung (Touch-Targets, Off-Canvas-Nav, kompakte Tabellen) ist Aufwand.

## Entscheidung

Kein expliziter Mobile-Support. App ist desktop-first. Tailwind-Defaults werden nicht aktiv kaputt gemacht, aber wir testen nicht auf kleinen Viewports und optimieren nichts dafür.

## Begründung

Use-Case ist Triage-Sessions: Operator schauen einmal pro Tag/Woche am Desktop drauf, arbeiten Findings ab, machen Acknowledge in Bulk. Das sind keine Mobile-Workflows. Mobile-Optimierung würde substantiellen UI-Aufwand bedeuten (verschachtelte Tabellen funktionieren auf Phones nicht, Modals müssen anders, Touch-Targets > 44px etc.) ohne echten Nutzen.

## Konsequenzen

- DaisyUI-Komponenten ohne explizite responsive-Klassen verwenden ist OK.
- Keine Mobile-Test-Cases.
- Wer auf dem Phone schaut, sieht eine zusammenstauende Desktop-Variante — funktional aber unschön.

## Re-Open-Trigger

Wenn Anwender das aktiv anfragen und ein konkreter Mobile-Workflow definierbar ist (z.B. "Bereitschaft hat KEV-Alert auf dem Handy gesehen, will ein-Klick-Acknowledge"). Dann gezielt für die ein bis zwei wichtigen Mobile-Flows optimieren, nicht das ganze UI.
