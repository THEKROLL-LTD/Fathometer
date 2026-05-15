# ADR-0013 — Fernet-KDF: Beibehalten ohne Salt/Iterations für MVP

**Status:** Akzeptiert · **Datum:** 2026-05-15

## Kontext

Block-G ingest verschlüsselt `Setting.llm_api_key_encrypted` mit Fernet
(`cryptography`-Library). Der Fernet-Key wird aus
`SECSCAN_ENCRYPTION_KEY` deterministisch abgeleitet:

```python
key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
```

Das ist effektiv `sha256(secret)[:32]` — **kein Salt, keine
Iterations, kein dedizierter KDF**. Bei einer schwachen Passphrase
(z.B. `"changeme"` oder `"password" * 4`) wäre ein Offline-
Dictionary-Angriff trivial: pro Kandidat-Passphrase eine SHA-256-
Berechnung, dann ein Fernet-Decrypt-Versuch. Auf moderner Hardware
sind das mehrere hundert Millionen Versuche pro Sekunde.

Der Block-G-Security-Auditor hat das als CONCERN markiert.

## Entscheidung

Wir **behalten den aktuellen KDF für den MVP** und kompensieren das
Risiko durch zwei nicht-kryptographische Mitigationen:

1. **README-/Wizard-Pflicht-Empfehlung**: die README und der
   First-Boot-Wizard weisen den Operator explizit auf die Verwendung
   eines hochentropischen Keys hin. Empfohlen:

   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   # ODER
   openssl rand -base64 48
   ```

   Beide Generatoren liefern ≥ 256 Bit Entropie, was einen Offline-
   Brute-Force gegen SHA-256 unmöglich macht.

2. **Entropie-Warnung beim App-Start**: ein Settings-Validator
   in `app.config` zählt die Anzahl distinkter Byte-Werte in
   `SECSCAN_ENCRYPTION_KEY`. Bei weniger als 16 distinkten Bytes
   loggt die App-Factory ein `secscan.weak_encryption_key`-Warning,
   bricht aber nicht ab. Das fängt offensichtlich schwache Keys ab
   (`aaaaaaaaaaaaaaaa…`, `1234567890` * 4) ohne legitime Keys zu
   blockieren.

## Begründung

- **Bedrohungsmodell**: secscan ist Single-User-Self-Hosted. Der
  einzige Operator generiert den Key. Wenn der Operator das
  README-Snippet einmal kopiert, ist die Mitigation effektiv.
- **API-Key-Wert**: DeepInfra-/OpenAI-API-Keys sind moderate-Cost-
  Secrets (Rate-Limited beim Provider, deutlich unter "Massen-
  Geheimnis"). Ein kompromittierter LLM-Key kostet im
  Worst-Case einen begrenzten Token-Betrag — kein Lateral-Movement,
  kein Datenleak über Trivy-Findings hinaus.
- **Migrations-Kosten**: Wechsel auf `argon2id` oder `scrypt` als
  KDF erzwingt eine Re-Encrypt-Migration (alte Cipher-Texts können
  nicht mit neuem KDF entschlüsselt werden). Das wäre Downtime plus
  Rollback-Komplexität und liegt außerhalb des MVP-Scopes.
- **Alternativen Mitigations**: ein KDF auf Argon2id würde
  Brute-Force-Angriffe verteuern, aber ändert nichts daran, dass
  ein 8-Zeichen-Passwort auch mit Argon2id in Reichweite eines
  ernsthaften Angreifers bleibt. Die einzige robuste Mitigation ist
  Entropie an der Quelle — und genau das stellen Mitigations 1 und 2
  sicher.

## Konsequenzen

- README erhält eine prominente "SECSCAN_ENCRYPTION_KEY generieren"-
  Sektion.
- `app/config.py` enthält einen Validator, der niedrige Entropie
  erkennt und beim App-Start eine WARN-Zeile loggt.
- Operator, die das README ignorieren und einen Trivial-Key setzen,
  bekommen einen sichtbaren Warning-Log — ohne dass die App startet
  oder Schein-Sicherheit suggeriert.

## Re-Open-Trigger

- Wenn secscan ein Multi-User-Auth-Modell bekommt (siehe ADR-0004),
  ist der Encryption-Key plötzlich nicht mehr unter alleiniger
  Kontrolle des Operators — dann muss auf einen echten KDF
  (Argon2id) migriert werden, inklusive Re-Encrypt-Migration.
- Wenn Provider-API-Keys höhere Cost-Profile bekommen (z.B. dedizierte
  Hardware-Allokationen, große Pre-Paid-Budgets), steigt das
  Risiko und der Re-Open ist angezeigt.
- Wenn aus Operations Bedarf für robustere KDF entsteht (z.B. ein
  Compliance-Audit verlangt PBKDF2/Argon2-Mindest-Anforderungen).
