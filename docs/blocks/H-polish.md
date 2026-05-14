# Block H — Live-Updates, Tests, Production-Smoke

## Ziel

SSE-Live-Updates auf dem Dashboard (neue Scans triggern Card-Refresh ohne Reload), animierte Card-Updates, vollständige Test-Coverage über alle Blöcke, Docker-Image-Build verifiziert, Compose-Up auf einem Server-ähnlichen Setup gegen die echte Trivy-Fixture als E2E-Smoke. Nach Block H ist die App für ersten Self-Hosting-Use ready.

## Vorbereitung — zu lesende Sektionen

- `ARCHITECTURE.md` §6 (`GET /events` SSE-Stream)
- `ARCHITECTURE.md` §7 (Dashboard-Live-Update-Verhalten)
- `ARCHITECTURE.md` §13 (Audit-Log — Action `scan.received` triggert Event)
- `ARCHITECTURE.md` §14 (Stale-Hervorhebung muss live aktualisieren)

## Aufgaben

1. `app/services/event_bus.py`: einfacher in-process-Dispatcher (Python `queue` plus Background-Thread). Multi-Subscriber pro App-Worker (typisch 1 Subscriber = aktiver Browser-Tab).
2. `app/api/events.py`: `GET /events` als SSE-Stream mit Heartbeat alle 30s, Subscribe an event_bus, Auth via Session.
3. Dashboard-JS: HTMX `hx-sse` auf den Server-Karten, Animation beim Update-Empfang (DaisyUI-Highlight-Klasse für 1s).
4. `findings_ingest.py`-Hook: nach erfolgreichem Scan-Ingest event_bus publish mit `{server_id, new_finding_count, resolved_count}`.
5. Stale-Detection: client-seitiger Re-Render alle 60s im Dashboard (Alpine-Timer), damit Stale-Badges live aufpoppen ohne neuen Scan.
6. Vollständiger Test-Run: `pytest -v --cov=app --cov-fail-under=85`.
7. Docker-Image-Build mit `docker build -t secscan:latest .` und Größen-Check (`docker images secscan` < 200 MB).
8. End-to-End-Smoke: `docker compose up`, Setup durchklicken, Server registrieren, real-Fixture als Trivy-Mock pushen, Dashboard-Update beobachten, Triage durchklicken, LLM-Anfrage absetzen (mit Mock-Provider), CSV-Export, Logout. Als Skript: `scripts/e2e_smoke.sh`.
9. Production-README aktualisieren mit allen Deploy-Hinweisen (Reverse-Proxy-Config-Snippets für nginx und Caddy als Anhang, IP-Allowlist-Empfehlung für `/api/scans`).
10. Release-Tag `v0.1.0` mit Changelog.

## Was NICHT in diesem Block

- Keine neuen Features. Nur Polish, Live-Updates und Tests.
- Keine Performance-Optimierungen außer offensichtlichen Wins (z.B. Index-Hints).

## Definition of Done

### Datei-Existenz

- [ ] `app/services/event_bus.py`, `app/api/events.py`
- [ ] `static/js/sse.js` mit HTMX-Integration
- [ ] `scripts/e2e_smoke.sh` als ausführbares Bash-Skript

### Statische Checks

- [ ] cmd: `ruff check . && ruff format --check . && mypy app/` → exit 0
- [ ] cmd: `pytest -v --cov=app --cov-fail-under=85` → exit 0
- [ ] cmd: `pytest tests/adversarial/ -v` → alle grün

### Build und Image

- [ ] cmd: `docker build -t secscan:latest .` → exit 0
- [ ] cmd: `docker images secscan:latest --format '{{.Size}}'` → < 200 MB
- [ ] cmd: `docker compose up -d --build` → alle Container healthy
- [ ] cmd: `docker compose logs app | grep -i error` → keine Errors

### E2E-Smoke

- [ ] cmd: `bash scripts/e2e_smoke.sh` → exit 0 mit Zwischen-Logs für jede Phase
- [ ] manual: SSE-Live-Update beobachten — neuer Scan-Push triggert Card-Animation ohne Reload
- [ ] manual: Stale-Badge erscheint nach Ablauf der konfigurierten Zeit ohne Page-Reload
- [ ] Screenshots der Live-Update-Animation und finalen Dashboard-Status unter `docs/blocks/H-evidence/`

### Production-Readiness

- [ ] README enthält Reverse-Proxy-Config-Snippets für nginx UND Caddy
- [ ] README enthält Empfehlung "IP-Allowlist auf /api/scans" mit Beispiel
- [ ] CHANGELOG.md für `v0.1.0` mit allen 8 Block-Achievements
- [ ] Git-Tag `v0.1.0` gesetzt

### Final-Audit (durch `security-auditor`-Agent über alle Blöcke)

- [ ] Auth-Reihenfolge auf `/api/scans` final verifiziert (compare_digest VOR Body-Parse)
- [ ] Rate-Limits greifen unter Last (Test mit 100 Parallel-Requests)
- [ ] gzip-Bomb (200 MB Decompress aus 1 KB) wird abgelehnt mit 413
- [ ] Pflicht-Kommentare gibt es nirgendwo (final-grep nach `required` auf Comment-Feldern)
- [ ] LLM-Output enthält in keinem Test-Pfad ungefilterte HTML-Tags

### Dokumentation

- [ ] `STATE.md` aktualisiert: Block H → completed, Status "MVP ready for first deployment"
