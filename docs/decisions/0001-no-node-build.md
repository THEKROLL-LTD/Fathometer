# ADR-0001 — Kein Node-Build im MVP

**Status:** Akzeptiert · **Datum:** 2026-05-14

## Kontext

Modernes UI braucht heute oft Node-Toolchain (Vite/Webpack, Tailwind-JIT, Bundler). Für secscan ist die Frage: bauen wir gegen die Bundle-Pipeline oder kommen wir ohne aus?

## Entscheidung

Kein Node-Build im MVP. Tailwind CDN, HTMX und Alpine.js als `<script>`-Tags, DaisyUI als Tailwind-Plugin via CDN.

## Begründung

Self-Hosting-Spirit (siehe Vision in §1) verlangt minimale Setup-Reibung. Eine zweite Build-Pipeline neben Python erhöht Container-Image-Größe, Build-Zeit und kognitive Last für Operator die das Image selbst bauen wollen. Die Performance-Kosten von CDN-Tailwind sind für einen Single-User-Admin-Dashboard vernachlässigbar.

## Konsequenzen

- Container-Image bleibt schlank (geschätzt ~150 MB).
- Frontend-Iteration ohne `npm install`-Hürde.
- Bei Performance-Problemen oder Air-Gap-Anforderungen kann Tailwind später als Build-Step nachgezogen werden — Code-Änderungen wären minimal.

## Re-Open-Trigger

Wenn das Repo so groß wird dass Tailwind-CDN-Größe (~3 MB) wirklich stört, oder wenn ein Air-Gap-Deploy gefordert ist.
