# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Pydantic-Schemas fuer `POST /api/findings/bulk-acknowledge`.

ARCHITECTURE.md §6 und Block F-Plan: drei Flavors.

- **Flavor A** — `finding_ids: list[int]` (explizite Auswahl, z.B. aus
  Checkbox-Selection im Server-Detail-View).
- **Flavor B** — `match: BulkAckMatchCriterion` mit `cve_id` und/oder
  `package_name`, optionalem Tag- und Status-Filter (genutzt von der
  globalen Suche fuer "Alle Vorkommen abhaken").
- **Flavor C** — `server_scope: BulkAckServerScope` mit `server_id` und
  `risk_band` (server-scoped Per-Band-Bulk-Ack, ADR-0044). Der Server
  resolved die Findings selbst, kein ID-Transport durch den Client.

`dry_run` ist Pflicht-Bool mit Default `True` — der Caller muss explizit
`false` setzen um die Aktion wirklich auszufuehren.

Sicherheits-Whitelists (siehe §10):
- `cve_id` matcht `^CVE-\\d{4}-\\d{4,7}$` (gleicher RE wie im Ingest).
- `package_name` matcht das gleiche Package-Charset wie beim Ingest.
- `tag` matcht das Tag-Name-Pattern aus `app.forms`.
- `status` ist eine Whitelist aus `{open, acknowledged, resolved}`.

Genau **einer** der Flavors muss befuellt sein — ein Body, der beide oder
keinen liefert, faellt mit 422 raus.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.forms import TAG_NAME_REGEX

# Wiederverwendung der Whitelist-Patterns aus dem Ingest — bewusst lokal
# kopiert um Zirkel zwischen `app.schemas.bulk_request` und
# `app.schemas.scan_envelope` zu vermeiden.
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
# Package-Names wie im Envelope-Schema. `@` bleibt zugelassen wegen der
# `package_name@target`-Disambiguation aus ADR-0011.
_PKG_NAME_RE = re.compile(r"^[a-zA-Z0-9._+\-:/@]+$")

# Max-Laenge fuer den optionalen Kommentar (gleiche Regel wie bei
# Acknowledge-Forms).
_COMMENT_MAX_LEN = 8 * 1024
# Hartes Cap fuer die explizite ID-Liste — verhindert dass eine fehlerhafte
# UI hunderttausend IDs in einen Request schreibt.
_MAX_FINDING_IDS = 10_000


BulkAckStatusFilter = Literal["open", "acknowledged", "resolved"]

# Single Source der bulk-abhakbaren Risk-Bands (ADR-0044 §Entscheidung (1)).
# `pending`/`unknown` fehlen bewusst — ein Bulk-Ack auf nicht bewertete
# Findings waere ein Urteil ohne Grundlage (ADR-0044 §Kontext). Diese Konstante
# wird von Tests und Template als Whitelist konsumiert; das `Literal` in
# `BulkAckServerScope.risk_band` muss literal bleiben (Pydantic kann es nicht
# aus der Konstante ableiten) und ist daher eine getrennte, deckungsgleiche
# Aufzaehlung.
BULK_ACK_BANDS: tuple[str, ...] = ("escalate", "act", "mitigate", "monitor", "noise")


class BulkAckMatchCriterion(BaseModel):
    """Match-Kriterium fuer Flavor B."""

    model_config = ConfigDict(extra="ignore")

    cve_id: str | None = Field(default=None, max_length=64)
    package_name: str | None = Field(default=None, max_length=256)
    tag: str | None = Field(default=None, max_length=32)
    status: BulkAckStatusFilter = "open"

    @model_validator(mode="after")
    def _must_have_cve_or_package(self) -> BulkAckMatchCriterion:
        """Mindestens `cve_id` oder `package_name` muss gesetzt sein.

        Sonst wuerde das Match-Kriterium "alle offenen Findings der Flotte"
        bedeuten — das ist zu offen und wuerde gefaehrliche Mass-Ack
        ermoeglichen.
        """
        if not self.cve_id and not self.package_name:
            raise ValueError("match braucht mindestens cve_id oder package_name")
        if self.cve_id is not None and not _CVE_ID_RE.match(self.cve_id):
            raise ValueError("cve_id matcht nicht CVE-YYYY-NNNN[..]")
        if self.package_name is not None:
            pkg = self.package_name.strip()
            if not pkg or not _PKG_NAME_RE.match(pkg):
                raise ValueError("package_name enthaelt unerlaubte Zeichen")
        if self.tag is not None:
            tag = self.tag.strip().lower()
            if not tag or not TAG_NAME_REGEX.match(tag):
                raise ValueError("tag matcht nicht das Tag-Name-Pattern")
        return self


class BulkAckServerScope(BaseModel):
    """Scope-Kriterium fuer Flavor C (server-scoped Per-Band-Bulk-Ack).

    Der Endpoint resolved die betroffenen Findings server-seitig anhand von
    `(server_id, risk_band)` — es wird **keine** ID-Liste durch den Client
    transportiert (ADR-0044 §Entscheidung (1)). `risk_band` ist auf die
    Whitelist :data:`BULK_ACK_BANDS` beschraenkt; `pending`/`unknown`
    scheitern damit bereits an Pydantic (422).
    """

    model_config = ConfigDict(extra="ignore")

    server_id: int
    risk_band: Literal["escalate", "act", "mitigate", "monitor", "noise"]

    @field_validator("server_id")
    @classmethod
    def _server_id_positive(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("server_id muss eine positive Ganzzahl sein")
        return value


class BulkAckRequest(BaseModel):
    """Request-Body fuer `POST /api/findings/bulk-acknowledge`.

    Drei Flavors, von denen genau **einer** befuellt sein muss:

    - **Flavor A** — `finding_ids` (explizite Auswahl).
    - **Flavor B** — `match` (Flotten-Match per CVE/Package).
    - **Flavor C** — `server_scope` (server-scoped Per-Band, ADR-0044).
    """

    model_config = ConfigDict(extra="ignore")

    finding_ids: list[int] | None = None
    match: BulkAckMatchCriterion | None = None
    server_scope: BulkAckServerScope | None = None
    dry_run: bool = True
    comment: str | None = Field(default=None, max_length=_COMMENT_MAX_LEN)

    @model_validator(mode="after")
    def _exactly_one_flavor(self) -> BulkAckRequest:
        """Genau einer von `finding_ids`/`match`/`server_scope` (XOR)."""
        has_ids = self.finding_ids is not None and len(self.finding_ids) > 0
        has_match = self.match is not None
        has_scope = self.server_scope is not None
        flavor_count = sum((has_ids, has_match, has_scope))
        if flavor_count > 1:
            raise ValueError("genau einer von finding_ids/match/server_scope darf gesetzt sein")
        if flavor_count == 0:
            raise ValueError("einer von finding_ids/match/server_scope ist Pflicht")
        if has_ids:
            assert self.finding_ids is not None
            if len(self.finding_ids) > _MAX_FINDING_IDS:
                raise ValueError(f"finding_ids: maximal {_MAX_FINDING_IDS} pro Request")
            for fid in self.finding_ids:
                if fid <= 0:
                    raise ValueError("finding_ids muessen positive Ganzzahlen sein")
        return self

    @property
    def has_comment(self) -> bool:
        return bool(self.comment and self.comment.strip())

    def clean_comment(self) -> str | None:
        if not self.has_comment:
            return None
        assert self.comment is not None
        return self.comment.strip()


__all__ = [
    "BULK_ACK_BANDS",
    "BulkAckMatchCriterion",
    "BulkAckRequest",
    "BulkAckServerScope",
    "BulkAckStatusFilter",
]
