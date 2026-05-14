# ADR-0007 — Gzip-Kompression auf der Wire

**Status:** Akzeptiert · **Datum:** 2026-05-14

## Kontext

Trivy-JSON-Bodies sind groß (gemessen: 4.95 MB für einen typischen k8s-Server). Mehrere Optionen: nichts tun, gzip auf der Leitung, Wechsel zu kompakterem Format (CycloneDX, SARIF, Custom-Slim), serverseitiges Strippen.

## Entscheidung

Der Agent komprimiert das JSON mit gzip vor dem Senden (`Content-Encoding: gzip`). Server dekomprimiert mit Streaming-Decompress und hartem Decompress-Bound von 100 MB als Gzip-Bomb-Schutz. Format bleibt Trivy-JSON.

## Begründung

Gemessenes Kompressions-Verhältnis am realen Scan: 4.95 MB → 0.56 MB (8.9×). Bei 50 Servern täglich: 250 MB/Tag → 28 MB/Tag. Aufwand: eine Zeile Bash im Agent, ein Streaming-Decompress-Wrapper im Server. Kein Schema-Wechsel, kein Forensik-Verlust, kein Lock-in.

CycloneDX-VEX und SARIF wurden geprüft und verworfen: für OS-Paket-Vulns sind sie verbose, eher größer als Trivy-JSON, und mappen schlecht auf den Use-Case. Custom-Slim-Format würde Agent und Server eng koppeln.

## Konsequenzen

- Agent braucht zusätzlich `gzip` als Dependency (auf jeder Distro Standard).
- Server hat Streaming-Decompress-Logik mit Bytes-Counter und Hard-Stop bei `SECSCAN_MAX_DECOMPRESSED_MB` (Default 100 MB).
- `MAX_CONTENT_LENGTH` bleibt 10 MB on the wire — entspricht ~80-100 MB Roh-JSON, mehr als ausreichend.
- Ungezippte Bodies werden weiterhin akzeptiert (Header optional) — `curl -d @scan.json` zum Debuggen funktioniert ohne Setup.

## Re-Open-Trigger

Wenn jemand einen Air-Gap-Setup mit ressourcenbeschränktem Server hat und 30% mehr Kompression durch zstd echte Wirkung hätten — dann zusätzlich `Content-Encoding: zstd` akzeptieren.
