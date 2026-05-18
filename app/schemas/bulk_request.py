"""Pydantic-Schemas fuer `POST /api/findings/bulk-acknowledge`.

ARCHITECTURE.md §6 und Block F-Plan: zwei Flavors.

- **Flavor A** — `finding_ids: list[int]` (explizite Auswahl, z.B. aus
  Checkbox-Selection im Server-Detail-View).
- **Flavor B** — `match: BulkAckMatchCriterion` mit `cve_id` und/oder
  `package_name`, optionalem Tag- und Status-Filter (genutzt von der
  globalen Suche fuer "Alle Vorkommen abhaken").

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

from pydantic import BaseModel, ConfigDict, Field, model_validator

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


class BulkAckRequest(BaseModel):
    """Request-Body fuer `POST /api/findings/bulk-acknowledge`.

    Block O (ADR-0022) erweitert das Schema um `risk_band_filter`. Wenn
    gesetzt, filtert der Endpoint **server-side** hart auf den genannten
    Band — eingeschleuste IDs anderer Baender werden gedropped und in
    `skipped_non_noise_ids` reportet. Aktuell nur `"noise"` zugelassen
    (Bulk-Ack-Noise-Workflow, siehe ADR-0022 §UI-Redesign).
    """

    model_config = ConfigDict(extra="ignore")

    finding_ids: list[int] | None = None
    match: BulkAckMatchCriterion | None = None
    dry_run: bool = True
    comment: str | None = Field(default=None, max_length=_COMMENT_MAX_LEN)
    risk_band_filter: Literal["noise"] | None = None

    @model_validator(mode="after")
    def _xor_finding_ids_and_match(self) -> BulkAckRequest:
        """Entweder `finding_ids` ODER `match` — nicht beide, nicht keiner."""
        has_ids = self.finding_ids is not None and len(self.finding_ids) > 0
        has_match = self.match is not None
        if has_ids and has_match:
            raise ValueError("finding_ids und match duerfen nicht zusammen gesetzt sein")
        if not has_ids and not has_match:
            raise ValueError("Entweder finding_ids oder match ist Pflicht")
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
    "BulkAckMatchCriterion",
    "BulkAckRequest",
    "BulkAckStatusFilter",
]
