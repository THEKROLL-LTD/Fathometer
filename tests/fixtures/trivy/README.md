# Trivy-Test-Fixtures

Realistische und adversariale Trivy-JSON-Outputs für Tests aller Blöcke.
Pflicht-Lektüre für `backend-implementer` und `test-writer` bevor sie das
Pydantic-Schema in `app/schemas/scan_envelope.py` schreiben oder verändern.

## Fixtures

### `ubuntu-22.04-rke2.json` (~5 MB, 306 Vulnerabilities)

Echter Trivy-Filesystem-Scan eines Ubuntu-22.04-Servers mit installiertem
RKE2/k3s. Zeigt die reale Schema-Variante von Trivy >= 0.70.0 inkl. CVSS-,
EPSS-, KEV- und CWE-Feldern. Verteilung der Findings:

- **Class `os-pkgs`**: 10 Findings (kernel-modules etc.)
- **Class `lang-pkgs`**: 296 Findings (eingebettete Go-Binaries: tailscale,
  k3s, runc, longhorn, coredns, metrics-server, …)

Diese Fixture ist die Grundlage für:

- Pydantic-Schema-Entwicklung — alle Felder die hier vorkommen müssen sauber
  geparst werden
- Performance-Tests (4.95 MB roh → ~0.56 MB gzipped)
- Coverage-Tests der Findings-Extraktion mit `finding_class`-Differenzierung
- E2E-Smoke gegen den echten Ingest-Flow

### `adversarial.json` (klein, 10 Vulnerabilities)

Synthetische Bad-Inputs. Jede Vulnerability enthält im `_attack`-Feld eine
Beschreibung des Angriffsvektors. Ingest-Logik muss alle ablehnen oder die
schädlichen Werte verwerfen, ohne 500-Crash und ohne Persistierung von
unsicheren Daten.

| ID | Bad-Input | Erwartete Ingest-Reaktion |
|----|-----------|---------------------------|
| CVE-2026-00001 | NUL-Byte-Marker im Title (Test ersetzt vor Push durch echtes `\x00`) | 422 oder Title gestrippt |
| CVE-2026-00002 | `<script>` in Title | Persistiert, aber im Render mit Jinja-Autoescape |
| CVE-2026-00003 | EPSS=1.5 (außerhalb 0–1) | 422 |
| CVE-2026-00004 | CVE-ID `CVE-foo-bar` | 422 |
| CVE-2026-00005 | Severity `ULTRA_CRITICAL` | 422 |
| CVE-2026-00006 | PkgName mit Path-Traversal | 422 (Whitelist-Regex) |
| CVE-2026-00007 | CVSS-Score 11.5 | 422 |
| CVE-2026-00008 | Attack-Vector `Q` (ungültig) | 422 oder auf `unknown` gemappt |
| CVE-2026-00009 | CWE `NOT-A-CWE` und `CWE-12345678` (zu viele Stellen) | 422 oder ungültige Items gestrippt |
| CVE-2026-00010 | Reference mit `javascript:` und `file://` | 422 oder auf nur https-URLs gestrippt |

Plus diese Test-Cases die der `test-writer` programmatisch ergänzt:

- **Gzip-Bomb**: 1 KB hochrepetitiver Bytes komprimiert, decompressed > 100 MB
  → Server muss bei `FM_MAX_DECOMPRESSED_MB` mit 413 abbrechen.
- **Body ohne Auth über 10 MB**: muss mit 401 in <50 ms abgelehnt werden
  (Auth-vor-Body-Parse aus §9).
- **JSON-Tiefe > 32**: muss mit 422 abgelehnt werden.
- **Übergroßes String-Feld** (Description > 64 KB): muss mit 422 abgelehnt
  werden.
- **Übergroße References-Liste** (> 50 URLs pro Finding): muss mit 422
  abgelehnt werden oder auf 50 limitiert.

## Wann diese Fixtures aktualisieren

- Wenn Trivy ein Schema-Update macht das wir supporten (neue Felder in CVSS,
  EPSS-Format-Wechsel etc.) → neue Fixture mit Versions-Suffix erstellen,
  alte beibehalten für Kompatibilitäts-Tests.
- Wenn ein neuer Adversarial-Pfad gefunden wird (z.B. via Security-Auditor) →
  Eintrag in `adversarial.json` ergänzen mit `_attack`-Beschreibung.

## Wann diese Fixtures NICHT verwenden

- Für Unit-Tests einzelner Pydantic-Modelle — dort sind handgeschriebene
  Mini-JSONs (5-10 Zeilen) lesbarer und schneller.
- Für UI-Snapshot-Tests die deterministische Render-Outputs brauchen — dort
  eine kleinere kuratierte Fixture mit z.B. 5 Findings (eines mit KEV, eines
  acknowledged, eines resolved) statt 306.
