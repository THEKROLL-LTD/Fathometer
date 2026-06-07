# ADR-0051 — Lizenzierung unter Apache License 2.0

**Status:** Akzeptiert · **Datum:** 2026-06-07 · **Block:** kein eigener Block (Projekt-/Lizenz-Entscheidung)

Bezug: [ADR-0048](0048-rebrand-secscan-to-fathometer.md) (Rebrand secscan → Fathometer — Projektname „Fathometer" wird im Copyright-/NOTICE-Eintrag verwendet).

## Kontext

Das Projekt war bisher nicht öffentlich lizenziert: `pyproject.toml` trug `license = { text = "Proprietary" }`, eine `LICENSE`-Datei existierte nicht. Für die geplante Veröffentlichung auf GitHub muss eine eindeutige Open-Source-Lizenz gewählt und konsistent im Repo hinterlegt werden — ohne Lizenz gilt rechtlich „all rights reserved", d.h. niemand darf den Code legal nutzen, forken oder weitergeben.

Abgewogen wurden eine permissive Lizenz (Apache 2.0) und ein Copyleft-Modell, das bei Web-Apps tatsächlich greift (AGPLv3). Entschieden wurde für **Apache 2.0**: Ziel ist maximale, reibungslose Verbreitung und Nachnutzbarkeit (auch kommerziell/proprietär) gegenüber erzwungener Offenlegung von Forks/Betreibern. Apache 2.0 enthält zudem einen expliziten Patent-Grant (§3) und ist mit dem gesamten Dependency-Stack vereinbar.

Rechteinhaber ist **THEKROLL LTD**.

## Entscheidung

Fathometer wird unter der **Apache License, Version 2.0** veröffentlicht. Konkret:

- **`LICENSE`** im Repo-Root mit dem vollständigen, unveränderten Apache-2.0-Text.
- **`NOTICE`** im Repo-Root mit dem Attribution-Eintrag (`Fathometer · Copyright 2026 THEKROLL LTD`) gemäß Apache 2.0 §4(d).
- **`pyproject.toml`**: `license = { text = "Apache-2.0" }`, `authors = [{ name = "THEKROLL LTD" }]` (vorher `"Proprietary"` / `"fathometer maintainers"`). Die Table-Form (`{ text = … }`) wird beibehalten, weil `build-system.requires = setuptools>=68` die PEP-639-String-Form (`license = "Apache-2.0"`, ab setuptools 77) noch nicht garantiert.
- **SPDX-Header** in allen `app/**/*.py` (Zweizeiler `# SPDX-License-Identifier: Apache-2.0` + `# Copyright 2026 THEKROLL LTD`), eingefügt nach evtl. Shebang/Encoding-Cookie.
- **README**: Abschnitt `## License` mit Verweis auf `LICENSE`/`NOTICE` und Copyright-Zeile.

### Dependency-Kompatibilität

Alle Runtime-Dependencies sind mit Apache-2.0-Distribution vereinbar (überwiegend BSD/MIT/Apache-2.0). Einzige Copyleft-Dependency: **`psycopg[binary]` (LGPL-3.0)** — kompatibel, solange psycopg als separate Bibliothek genutzt/verteilt wird (keine statische Einbettung in einen Derivative Work). Bei Weitergabe des Docker-Images ist die LGPL-Pflicht (Quellzugang zu psycopg, Austauschbarkeit) zu beachten; dies ändert die Apache-2.0-Lizenz des eigenen Codes nicht.

## Begründung

- **Verbreitung vor Copyleft:** ein self-hosted Security-Tool profitiert von breiter, unkomplizierter Nachnutzung; AGPL hätte kommerzielle Mitnutzer und Firmen mit No-AGPL-Policy ausgeschlossen.
- **Patent-Schutz:** Apache 2.0 §3 liefert einen ausdrücklichen Patent-Grant, anders als MIT/BSD.
- **Stack-Verträglichkeit:** v3-Linie der Dependencies und Apache-2.0 vertragen sich; GPLv2 wäre wegen Apache-2.0-Deps (`cryptography`, `structlog`) inkompatibel gewesen — kein Thema mehr durch die Apache-Wahl.

## Konsequenzen

- Externe Beiträge fallen ohne gegenteilige Erklärung unter Apache 2.0 §5 (inbound = outbound). Ein formales CLA/DCO ist **nicht** eingeführt; falls später nötig → eigene ADR + `CONTRIBUTING.md`.
- Neue Source-Dateien sollen den SPDX-Header tragen (Konsistenz); kein automatischer Lint-Zwang dafür eingeführt.
- Modifizierte Dateien müssen bei Weitergabe gemäß §4(b) einen „changed"-Hinweis tragen — relevant erst für Downstream-Distributoren, nicht für das Upstream-Repo.
- `NOTICE` muss bei künftigen Drittkomponenten mit eigener Attribution-Pflicht ergänzt werden.

## Re-Open-Trigger

- Wechsel des Lizenzmodells (z.B. zu AGPLv3 oder Dual-Licensing) — erfordert Zustimmung aller Copyright-Inhaber und eine neue ADR.
- Aufnahme einer Dependency mit strengerem Copyleft (GPL/AGPL) in den eigenen Code (nicht nur als separate Bibliothek), die mit Apache-2.0-Distribution kollidiert.
- Einführung eines formalen Contribution-Agreements (CLA/DCO).
