# ADR-0005 — Roh-Trivy-JSON wird nicht persistiert

**Status:** Akzeptiert · **Datum:** 2026-05-14

## Kontext

Beim Scan-Empfang haben wir die Wahl: das volle Trivy-JSON in `scans.raw_json` (jsonb) langfristig speichern, eine Retention-Policy fahren (z.B. 30 Tage), oder gar nicht speichern. Reale Scans sind 1-5 MB groß, bei großen Flotten wächst das schnell.

## Entscheidung

Das Roh-JSON wird nach dem Pydantic-Parse und der Findings-Extraktion verworfen. Die `scans`-Tabelle hält nur Metadaten: `received_at`, `server_id`, Host-Snapshot, Trivy-DB-Version. Die `findings`-Tabelle enthält alle relevanten Daten und bleibt forever.

## Begründung

Datenmessung am realen Scan: 4.95 MB Roh-JSON pro Scan auf einem k8s-Server. Bei 50 Servern täglich = 250 MB/Tag = ~7 GB/Monat in der DB nur für Roh-Scans. Forensik-Wert ist gering, weil:
- Die extrahierten `findings` enthalten alle Triage-relevanten Felder (CVSS, EPSS, KEV, CWE, References).
- Audit-Log dokumentiert wann was passiert ist.
- Wenn nachträglich ein neues Feld extrahiert werden soll, kommt das mit dem nächsten Scan rein (üblicherweise innerhalb 24h).

## Konsequenzen

- DB-Wachstum bleibt linear in den Findings, nicht in den Scan-Bodies.
- Wer doch ein Feld nachziehen will das wir heute nicht extrahieren, muss auf den nächsten Scan warten.
- `scans`-Tabelle ist eine reine Empfangs-Buchhaltung — Anzahl Zeilen wächst aber jede Zeile ist klein (~500 Bytes).

## Re-Open-Trigger

Wenn Forensik-Bedarf nachweislich auftaucht (z.B. Compliance-Audit verlangt "vollständiger Originalbeleg pro Scan"), führen wir ein optionales jsonb-Feld mit konfigurierbarer Retention ein.
