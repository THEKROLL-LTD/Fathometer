# ADR-0008 — Secret-Scanning out of MVP

**Status:** Akzeptiert · **Datum:** 2026-05-14

## Kontext

Trivy unterstützt zusätzlich zu Vulnerability-Scans auch Secret-Detection (`--scanners secret` findet AWS-Keys, SSH-Keys, generische API-Token im Filesystem). Wäre für Root-Server hochrelevant.

## Entscheidung

Secret-Scanning ist im MVP **nicht aktiv**. Agent läuft ausschließlich `--scanners vuln`. Datenmodell ist via `finding_type`-Enum (`vulnerability`/`secret`/`misconfig`) vorbereitet, aber nur `vulnerability` wird produziert. Secrets sind v2.

## Begründung

Workflow-Schritte für Secrets sind komplett anders (Key rotieren, aus Source entfernen, Git-History bereinigen) — KEV/EPSS/CVSS sind irrelevant. UI-Design braucht eigene Aufmerksamkeit (Redaction der Werte, der secscan-Server darf selbst nicht zum Secret-Tresor werden). Im MVP fokussieren wir auf den CVE-Triage-Flow, sonst dehnt sich der Scope.

## Konsequenzen

- Agent hat `--scanners vuln` hardcoded.
- DB-Schema enthält bereits `finding_type`-Enum, sodass Secrets ohne Migration in v2 dazukommen können.
- UI hat keinen Secrets-Tab im MVP.
- Wer Secrets jetzt schon scannen will, kann sich den Agent selbst anpassen — der Server würde sie auch annehmen, würde aber im UI nichts damit anfangen.

## Re-Open-Trigger

v2 nach erfolgreichem MVP-Launch und sobald die ersten Anwender konkret nach Secret-Scanning fragen.
