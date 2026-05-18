"""Host-Snapshot-Persistenz (Block O Phase C Task #7, ADR-0022).

Persistiert den vom Agent gelieferten `envelope.host_state`-Block in die vier
Snapshot-Tabellen `server_listeners`, `server_processes`,
`server_kernel_modules`, `server_services`.

Persistenz-Strategie: **truncate + insert in einer Transaktion** pro Server
(nicht global). Wir wollen den vollstaendigen aktuellen State, kein Merge
mit alten Daten. Single-Source-of-Truth ist der aktuelle Scan.

Dedup-Strategie pro Tabelle (Agent koennte doppelte Eintraege melden, z.B.
bei `ss`-Output-Race-Conditions):

* Listener: Natural-Key `(proto, addr, port)` — erster Eintrag gewinnt.
* Process: Natural-Key `pid` — erster gewinnt.
* Module / Service: Natural-Key `name` — erster gewinnt.

Fehlerbehandlung: keine. Errors propagieren an den Caller
(`app/api/scans.py` Task #8 faengt `SQLAlchemyError`/`ValueError` ab und
faellt auf `snapshot_available=False` zurueck).
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models import (
    Server,
    ServerKernelModule,
    ServerListener,
    ServerProcess,
    ServerService,
)
from app.schemas.scan_envelope import HostStateBlock


def persist_host_state(session: Session, server: Server, block: HostStateBlock) -> None:
    """Truncate-and-insert der vier Snapshot-Tabellen fuer `server`.

    Alle Operationen laufen in der vom Caller gefuehrten Transaktion;
    `session.commit()` ist Sache des Callers (Flask-Per-Request-Session).

    Setzt `server.host_state_snapshot_at` auf `block.snapshot_at` oder
    `now(UTC)` wenn das Feld fehlt.
    """

    # ---- 1. Alte Snapshot-Daten fuer diesen Server entfernen -----------
    # `synchronize_session=False` ist sicher, weil wir die Tabellen direkt
    # danach neu befuellen und keine ORM-Identity-Map-Konflikte erwarten.
    session.query(ServerListener).filter_by(server_id=server.id).delete(synchronize_session=False)
    session.query(ServerProcess).filter_by(server_id=server.id).delete(synchronize_session=False)
    session.query(ServerKernelModule).filter_by(server_id=server.id).delete(
        synchronize_session=False
    )
    session.query(ServerService).filter_by(server_id=server.id).delete(synchronize_session=False)

    # ---- 2. Listener-Insert mit Natural-Key-Dedup ----------------------
    listener_seen: set[tuple[str, str, int]] = set()
    for entry in block.listeners:
        key = (entry.proto, entry.addr, entry.port)
        if key in listener_seen:
            continue
        listener_seen.add(key)
        session.add(
            ServerListener(
                server_id=server.id,
                proto=entry.proto,
                addr=entry.addr,
                port=entry.port,
                process=entry.process,
                pid=entry.pid,
            )
        )

    # ---- 3. Process-Insert mit PID-Dedup -------------------------------
    process_seen: set[int] = set()
    for proc in block.processes:
        if proc.pid in process_seen:
            continue
        process_seen.add(proc.pid)
        session.add(
            ServerProcess(
                server_id=server.id,
                pid=proc.pid,
                user=proc.user,
                comm=proc.comm,
                args=proc.args,
            )
        )

    # ---- 4. Kernel-Module-Insert mit Name-Dedup ------------------------
    module_seen: set[str] = set()
    for module_name in block.kernel_modules:
        if module_name in module_seen:
            continue
        module_seen.add(module_name)
        session.add(ServerKernelModule(server_id=server.id, name=module_name))

    # ---- 5. Services-Insert mit Name-Dedup -----------------------------
    service_seen: set[str] = set()
    for service_name in block.services:
        if service_name in service_seen:
            continue
        service_seen.add(service_name)
        session.add(ServerService(server_id=server.id, name=service_name))

    # ---- 6. Tracking-Spalte am Server ----------------------------------
    server.host_state_snapshot_at = block.snapshot_at or datetime.now(tz=UTC)

    # Sicherstellen, dass die DELETE+INSERTs vor weiteren Reads sichtbar sind
    # (z.B. Pre-Triage-Pass im selben Ingest).
    session.flush()


__all__ = ["persist_host_state"]
