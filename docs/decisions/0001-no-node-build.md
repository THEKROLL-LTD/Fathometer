# ADR-0001 — Kein Node-Build im MVP

**Status:** Superseded by [ADR-0032](0032-frontend-build-plain-css.md) (2026-05-23) · **Datum:** 2026-05-14

> **Hinweis (2026-05-23):** Block W führt einen esbuild-Node-Build ein.
> Das ursprüngliche „CDN-only"-Modell mit Tailwind/DaisyUI/Alpine/HTMX
> via Script-Tags ist abgelöst. Plain-CSS-Bundle + esbuild-JS-Bundle
> kommen aus `frontend/`, Multi-Stage-Dockerfile mit `node:20-alpine`
> als Build-Stage 1 und Python-Slim als Stage 2. Siehe ADR-0032 für
> die volle Begründung, die Trade-Offs und das Phase-2-Addendum (in
> dem Tailwind/DaisyUI auch endgültig aus dem Dual-Stack rausgeflogen
> sind). Das Original unten bleibt als historischer Kontext stehen.

---

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
