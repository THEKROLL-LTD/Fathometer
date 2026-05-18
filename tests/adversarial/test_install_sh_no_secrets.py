"""Block N (ADR-0021) — Adversarial: `/install.sh` enthaelt keine Geheimnisse.

ADR-0021 §"Warum keine Auth auf /install.sh" begruendet das so: der Inhalt
ist kein Geheimnis. Dieser Test verifiziert die Aussage maschinell, damit
ein versehentliches `{{ master_key }}`-Einsetzen im Template sofort
auffliegt.

Patterns:
* `SECSCAN_MASTER_KEY=` mit einem Wert dahinter (kein Beispiel-Token).
* `Authorization: Bearer <hex/base64-token>`.
* `SECSCAN_API_KEY=<value>` (das schreibt der Wizard ZUR LAUFZEIT, nicht ins
  Template).
* LLM-API-Key-Pattern (`sk-` plus 40+ Hex-Zeichen — OpenAI-Format).
* DB-URL-Pattern (`postgresql://user:pass@host`).
"""

from __future__ import annotations

import re

from flask import Flask

_FORBIDDEN_PATTERNS = [
    # Master-Key oder API-Key MIT Wert (`KEY="..."` mit min. 16 Chars).
    re.compile(r'SECSCAN_MASTER_KEY=["\'][A-Za-z0-9_\-+/=]{16,}', re.IGNORECASE),
    re.compile(r'SECSCAN_API_KEY=["\'][A-Za-z0-9_\-+/=]{16,}', re.IGNORECASE),
    # Authorization-Header mit echtem Token (Hex/Base64, >= 24 Chars).
    re.compile(r"Authorization:\s*Bearer\s+[A-Za-z0-9._\-+/=]{24,}", re.IGNORECASE),
    # OpenAI/DeepInfra-API-Key-Format.
    re.compile(r"\bsk-[A-Za-z0-9]{32,}"),
    # Postgres-URL mit eingebettetem Passwort.
    re.compile(r"postgres(?:ql)?://[^:]+:[^@/\s]+@"),
]


def test_install_sh_contains_no_secret_patterns(db_app: Flask) -> None:
    client = db_app.test_client()
    body = client.get("/install.sh").get_data(as_text=True)
    for pattern in _FORBIDDEN_PATTERNS:
        match = pattern.search(body)
        assert match is None, (
            f"Forbidden secret pattern matched in /install.sh: "
            f"pattern={pattern.pattern!r} match={match.group(0)!r}"
        )


def test_install_sh_master_key_only_referenced_as_env_var_name(db_app: Flask) -> None:
    """`SECSCAN_MASTER_KEY` als Bash-Variablen-Name darf vorkommen (Unattended-
    Mode liest die Var), aber nie mit einem konkreten Wert assigned."""
    client = db_app.test_client()
    body = client.get("/install.sh").get_data(as_text=True)
    # Mindestens eine Erwaehnung (Wizard liest ENV).
    assert "SECSCAN_MASTER_KEY" in body
    # Aber NIE als `SECSCAN_MASTER_KEY="<token>"` mit konkretem Token-Wert.
    forbidden = re.compile(r'SECSCAN_MASTER_KEY\s*=\s*["\'][A-Za-z0-9_\-+/=]{8,}')
    assert forbidden.search(body) is None
