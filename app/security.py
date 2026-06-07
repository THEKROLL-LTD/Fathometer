# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Security-Helfer (Stub fuer Block A).

In Block B/C werden hier Key-Hashing und Verify-Funktionen ergaenzt.
Wir importieren `hmac.compare_digest` bereits hier, weil:

- die DoD von Block A einen `compare_digest`-Import in `app/` per grep verlangt;
- alle spaeteren konstantzeit-Vergleiche durch genau diese Funktion laufen sollen
  (siehe ARCHITECTURE.md §9 — niemals `==` fuer Key-/Hash-Vergleiche).
"""

from __future__ import annotations

from hmac import compare_digest

__all__ = ["constant_time_equals"]


def constant_time_equals(a: str | bytes, b: str | bytes) -> bool:
    """Konstantzeit-Vergleich fuer Keys, Tokens und Hashes.

    Verhindert Timing-Attacks auf der Key-Validierung. Im Block A ist das
    nur ein Wrapper — Block B/C werden die eigentlichen Verify-Funktionen
    fuer Master-Key (Argon2id) und Server-Key (SHA-256) hier anhaengen.
    """
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return compare_digest(a, b)
