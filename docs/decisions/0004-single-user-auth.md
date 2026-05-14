# ADR-0004 — Single-User Admin-Auth im MVP

**Status:** Akzeptiert · **Datum:** 2026-05-14

## Kontext

Welches Auth-Modell? Optionen: Single-User mit Passwort (uptime-kuma-Style), Multi-User mit lokalen Accounts und Rollen, OIDC/SSO.

## Entscheidung

Single-User Admin-Account. Beim ersten Boot wird ein Admin-User über den Setup-Wizard angelegt. Mehr User gibt es nicht.

## Begründung

Zielgruppe sind kleinere Setups (5-50 Server, Solo-Operator oder kleine Teams die geteilten Account akzeptieren). Multi-User-Komplexität (RBAC, Account-Recovery, Email-Verifikation, Session-Management pro User) ist disproportional zum Use-Case. Datenmodell ist trotzdem so ausgelegt dass Multi-User später ohne Migration nachgezogen werden kann (`users`-Tabelle existiert, Audit-Events haben `actor`-Feld).

## Konsequenzen

- Kein Account-Recovery-Flow nötig (Admin-Reset-Befehl per `docker compose exec`).
- Audit-Events haben immer entweder den Admin-Username, einen Server-Namen (für API-Calls) oder `system` als Actor.
- Acknowledge-Notes werden alle vom Admin geschrieben — kein Multi-Author-Konflikt.
- OIDC/SSO ist v3, falls jemand danach fragt.

## Re-Open-Trigger

Wenn ein Team mit echtem Multi-Author-Bedarf danach fragt und der Use-Case substantiell ist (nicht "wir hätten gerne separate Logins").
