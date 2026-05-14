# ADR-0003 — Push statt Pull, keine Server-Credentials

**Status:** Akzeptiert · **Datum:** 2026-05-14

## Kontext

Wie kommen Trivy-Scan-Resultate vom Server zur secscan-App? Optionen: (a) secscan zieht aktiv per SSH/HTTP von den Servern, (b) Server pushen aktiv an secscan über cron oder systemd-Timer.

## Entscheidung

Push-Modell. secscan hat keinen Zugriff auf die überwachten Server. Server pushen Scans aktiv über `POST /api/scans` mit pro-Server-API-Key. Im gesamten System gibt es keine SSH-Keys, Sudo-Credentials oder Inbound-Verbindungen vom secscan-Server zur Flotte.

## Begründung

Klasse von Angriffen, die in der Praxis regelmäßig auftritt: zentrales Management-Tool sammelt Credentials für viele Server an einem Ort und wird zum bevorzugten Angriffsziel. Bei Pull-Architektur würde ein secscan-Kompromiss direkten Zugang zur gesamten Flotte verschaffen. Bei Push gilt: wer secscan kompromittiert, sieht nur die Schwachstellen-Liste der Server (unangenehm, aber kein direkter Zugang) — der Angreifer muss jede Schwachstelle separat ausnutzen.

## Konsequenzen

- Operator muss auf jedem Server selbst einen Cron- oder systemd-Timer einrichten (Referenz-Skript unter `agent/`).
- "Scan jetzt anstoßen"-Knopf in der UI ist nicht möglich — der Server entscheidet selbst wann er scannt.
- Notifications sind aus dem MVP draußen, weil jeder Notification-Channel ein zusätzlicher Credential auf secscan wäre — siehe ADR-008.
- Master-Key und Server-Keys sind unabhängig rotierbar; ein Master-Key-Leak erlaubt nur die Registrierung neuer Phantom-Server (auditierbar), nicht den Zugriff auf existierende.

## Re-Open-Trigger

Niemals. Diese Entscheidung definiert das Sicherheits-Modell und ist nicht verhandelbar.
