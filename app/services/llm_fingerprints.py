# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Fingerprint-Helper fuer Block P (ADR-0023) — Two-Level-Cache.

Drei Eingangs-Fingerprints plus ein abgeleiteter Cache-Key:

* :func:`group_findings_fingerprint` — SHA256[:16] ueber sortierte
  ``(identifier_key, package_purl)``-Tuple. Input ist das **OPEN-Set**
  der Group auf dem Server (TICKET-010/ADR-0052): Enqueue
  (``pass2_enqueue``) und Worker (``llm_worker._do_pass2``) MUESSEN
  dieselbe Domaene fingerprinten, sonst konvergiert der Fingerprint-Gate
  nie. Aendert sich genau wenn Findings der Group offen werden oder
  aufhoeren offen zu sein (neu, resolved, acknowledged, reopened).

* :func:`cve_data_fingerprint` — SHA256[:16] ueber
  ``(identifier_key, severity, severity_by_provider_normalized, epss_score,
  is_kev, vendor_status, title, attack_vector)``. Aendert sich wenn
  EPSS/KEV/Vendor-Status-Daten fuer enthaltene Findings driften —
  title/attack_vector sind seit TICKET-011 Teil des Pass-2-Prompts und
  muessen daher mit-invalidieren (z.B. Title-Update durch CVE-Enrichment).

* :func:`server_context_fingerprint` — SHA256[:16] ueber kanonisch-
  serialisierte Host-Felder. PIDs, args, snapshot_at und das User-Feld
  der Prozesse fliessen bewusst NICHT ein (siehe ADR-0023
  §"Two-Level-Caching").

* :func:`make_cache_key` — voller SHA256-hex (64 chars) ueber die vier
  Inputs (group_id + die drei 16-char-Fingerprints) plus den
  Versions-Salt :data:`app.services.llm_prompts.PASS2_PROMPT_VERSION`
  (TICKET-011: materielle Prompt-Semantik-Aenderungen invalidieren den
  Cache einmalig), passt 1:1 in die PK-Spalte ``llm_risk_cache.cache_key``.

Die Snapshot-Daten fuer den Server-Context werden hier aus den vier
Block-O-Snapshot-Tabellen geladen (``server_listeners``, ``server_processes``,
``server_kernel_modules``, ``server_services``). ``host_state_gaps`` ist
keine Modell-Spalte — wir lesen sie defensiv ueber ``getattr`` und
defaulten auf ``[]``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    Finding,
    Server,
    ServerKernelModule,
    ServerListener,
    ServerProcess,
    ServerService,
)
from app.services.llm_prompts import PASS2_PROMPT_VERSION


def group_findings_fingerprint(findings: list[Finding]) -> str:
    """SHA256[:16] ueber sortierte ``(identifier_key, package_purl or "")``-Tuple.

    Kanonische Sortierung garantiert Sortier-Unabhaengigkeit beim Caller.

    Erwarteter Input ist das **OPEN-Set** der Group auf dem Server
    (``status == FindingStatus.OPEN``) — siehe TICKET-010/ADR-0052.
    Enqueue (``pass2_enqueue.enqueue_pass2_for_server``) und Worker
    (``llm_worker._do_pass2``) MUESSEN ueber dieselbe Domaene
    fingerprinten; andernfalls matchen gespeicherter Eval-Fingerprint
    und Enqueue-Fingerprint nie und jede Group mit non-open Findings
    wird bei jedem Ingest erneut enqueued.
    """
    tuples = sorted((f.identifier_key, f.package_purl or "") for f in findings)
    payload = json.dumps(tuples, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def cve_data_fingerprint(findings: list[Finding]) -> str:
    """SHA256[:16] ueber CVE-Daten-Tuple.

    Felder pro Finding:

    * ``identifier_key``
    * ``severity.value`` (lowercase Severity-Enum)
    * ``json.dumps(severity_by_provider or {}, sort_keys=True)`` —
      Provider-Map normalisiert
    * ``round(epss_score, 4) if epss_score is not None else None``
    * ``is_kev``
    * ``vendor_status``
    * ``title`` (TICKET-011: Teil der Pass-2-Prompt-Zeile)
    * ``attack_vector.value`` (TICKET-011: dito)
    """
    tuples = sorted(
        (
            f.identifier_key,
            f.severity.value,
            json.dumps(f.severity_by_provider or {}, sort_keys=True),
            round(f.epss_score, 4) if f.epss_score is not None else None,
            f.is_kev,
            f.vendor_status,
            f.title or "",
            f.attack_vector.value,
        )
        for f in findings
    )
    payload = json.dumps(tuples, separators=(",", ":"), default=str, sort_keys=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _load_server_snapshot_for_fingerprint(session: Session, server_id: int) -> dict[str, Any]:
    """Laedt die vier Snapshot-Tabellen sortiert fuer ``server_context_fingerprint``.

    Rueckgabe ist ein Dict mit den Schluesseln ``listeners``,
    ``process_comms``, ``modules``, ``services`` (alle bereits sortiert).
    PIDs, args, snapshot_at und User-Feld fliessen NICHT ein.
    """
    listener_rows = session.execute(
        select(
            ServerListener.proto,
            ServerListener.addr,
            ServerListener.port,
            ServerListener.process,
        ).where(ServerListener.server_id == server_id)
    ).all()
    listeners = sorted((row[0], row[1], row[2], row[3] or "") for row in listener_rows)

    comm_rows = session.execute(
        select(ServerProcess.comm)
        .where(ServerProcess.server_id == server_id)
        .where(ServerProcess.comm.isnot(None))
    ).all()
    process_comms = sorted({row[0] for row in comm_rows if row[0]})

    module_rows = session.execute(
        select(ServerKernelModule.name).where(ServerKernelModule.server_id == server_id)
    ).all()
    modules = sorted(row[0] for row in module_rows)

    service_rows = session.execute(
        select(ServerService.name).where(ServerService.server_id == server_id)
    ).all()
    services = sorted(row[0] for row in service_rows)

    return {
        "listeners": listeners,
        "process_comms": process_comms,
        "modules": modules,
        "services": services,
    }


def server_context_fingerprint(server: Server, session: Session | None = None) -> str:
    """SHA256[:16] ueber semantisch-stabile Host-Felder.

    Wenn ``session`` uebergeben wird, werden die Snapshot-Tabellen frisch
    abgefragt. Andernfalls fallen wir auf ``getattr(server, "listeners", [])``
    etc. zurueck — das deckt In-Memory-Tests mit auf-dem-ORM-Objekt
    gesetzten Listen ab.

    PID, args, snapshot_at, User-Feld fliessen bewusst NICHT ein.
    """
    if session is not None:
        snap = _load_server_snapshot_for_fingerprint(session, server.id)
        listeners = snap["listeners"]
        process_comms = snap["process_comms"]
        modules = snap["modules"]
        services = snap["services"]
    else:
        raw_listeners = getattr(server, "listeners", []) or []
        listeners = sorted((li.proto, li.addr, li.port, li.process or "") for li in raw_listeners)
        raw_procs = getattr(server, "processes", []) or []
        process_comms = sorted({p.comm for p in raw_procs if p.comm})
        raw_modules = getattr(server, "kernel_modules", []) or []
        modules = sorted(m.name for m in raw_modules)
        raw_services = getattr(server, "services", []) or []
        services = sorted(s.name for s in raw_services)

    tag_links = getattr(server, "tag_links", []) or []
    tags = sorted(link.tag.name for link in tag_links if getattr(link, "tag", None))

    raw_gaps = getattr(server, "host_state_gaps", None) or []
    gaps = sorted(raw_gaps)

    payload = json.dumps(
        {
            "os_family": server.os_family,
            "os_version": server.os_version,
            "tags": tags,
            "listeners": listeners,
            "process_comms": process_comms,
            "kernel_modules": modules,
            "services": services,
            "gaps": gaps,
        },
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def make_cache_key(
    group_id: int,
    group_findings_fp: str,
    cve_data_fp: str,
    server_context_fp: str,
) -> str:
    """Voller SHA256-hex (64 chars) ueber die vier Inputs plus Versions-Salt.

    Format des serialisierten Payloads: pipe-getrennte Strings, damit der
    Key in Debug-Logs visuell trennbar bleibt (der Hash selbst ist
    deterministisch unabhaengig vom Payload-Format).

    Der Versions-Salt (:data:`PASS2_PROMPT_VERSION`, TICKET-011) sorgt
    dafuer, dass eine materielle Aenderung der Prompt-Semantik den Cache
    einmalig invalidiert — sonst blieben Bestands-Reasons aus alter
    Semantik bis zur naechsten OPEN-Set-Aenderung stehen.
    """
    payload = (
        f"{group_id}|{group_findings_fp}|{cve_data_fp}|{server_context_fp}|v{PASS2_PROMPT_VERSION}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


__all__ = [
    "cve_data_fingerprint",
    "group_findings_fingerprint",
    "make_cache_key",
    "server_context_fingerprint",
]
