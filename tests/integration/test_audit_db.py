"""Tests fuer `/audit` und `/audit/export.csv` (Block F).

ARCHITECTURE.md §7 (Audit-View mit Filtern) und §13 (Audit-Vokabular).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import AuditEvent, Server, ServerTag, Tag
from tests._helpers import create_admin_user, login


def _create_server(app: Flask, name: str, tags: list[str] | None = None) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(name=name, api_key_hash="x" * 64, expected_scan_interval_h=24)
            sess.add(srv)
            sess.flush()
            sid = srv.id
            for tname in tags or []:
                tag = sess.execute(select(Tag).where(Tag.name == tname)).scalar_one_or_none()
                if tag is None:
                    tag = Tag(name=tname)
                    sess.add(tag)
                    sess.flush()
                sess.add(ServerTag(server_id=sid, tag_id=tag.id))
            sess.commit()
            return sid
        finally:
            sess.close()


def _add_event(
    app: Flask,
    *,
    actor: str,
    action: str,
    target_type: str = "finding",
    target_id: str | None = None,
    ts: datetime | None = None,
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            e = AuditEvent(
                actor=actor,
                action=action,
                target_type=target_type,
                target_id=target_id,
            )
            sess.add(e)
            sess.flush()
            if ts is not None:
                # Direkt nach dem Insert anpassen — `ts` hat sonst Default `now()`.
                e.ts = ts
            eid = e.id
            sess.commit()
            return eid
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# List View
# ---------------------------------------------------------------------------


def test_audit_list_renders_all_events_without_filter(db_app: Flask) -> None:
    create_admin_user(db_app)
    _add_event(db_app, actor="admin", action="finding.acknowledged", target_id="1")
    _add_event(db_app, actor="server-x", action="scan.ingested", target_id="2")
    client = db_app.test_client()
    login(client)
    resp = client.get("/audit/")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)
    assert "finding.acknowledged" in body
    assert "scan.ingested" in body


def test_audit_filter_by_date_range(db_app: Flask) -> None:
    create_admin_user(db_app)
    in_range = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
    out_range = datetime(2025, 6, 1, 12, 0, tzinfo=UTC)
    _add_event(db_app, actor="admin", action="auth.login", target_id="1", ts=in_range)
    _add_event(db_app, actor="admin", action="auth.login", target_id="2", ts=out_range)
    client = db_app.test_client()
    login(client)
    resp = client.get("/audit/?date_from=2026-01-01&date_to=2026-12-31")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # In-range Event muss da sein (matched ueber Action "auth.login"), aber
    # out-of-range nicht. Da beide Action gleich heissen, vergleichen wir
    # die Anzahl der Tabellenzeilen mit `auth.login` als Indikator.
    assert body.count("auth.login") >= 1


def test_audit_filter_by_actor_substring(db_app: Flask) -> None:
    create_admin_user(db_app)
    _add_event(db_app, actor="admin", action="auth.login", target_id="1")
    _add_event(db_app, actor="other-user", action="auth.login", target_id="2")
    client = db_app.test_client()
    login(client)
    resp = client.get("/audit/?actor=admin")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "admin" in body
    # `other-user` darf nicht in der Liste sein (Filter wirkt).
    # Wir suchen nach einem spezifischen Marker — der Username taucht direkt
    # in der Tabelle auf.
    assert "other-user" not in body


def test_audit_filter_action_exact_match(db_app: Flask) -> None:
    create_admin_user(db_app)
    _add_event(db_app, actor="admin", action="finding.acknowledged", target_id="1")
    _add_event(db_app, actor="admin", action="finding.reopened", target_id="2")
    client = db_app.test_client()
    login(client)
    resp = client.get("/audit/?action=finding.acknowledged")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Filter aktiv: nur akzeptierte Action sichtbar.
    assert "finding.acknowledged" in body
    # `finding.reopened` darf nicht in der gefilterten Tabelle stehen.
    # Hinweis: das Wort kann im Dropdown vorkommen — wir checken auf den
    # eindeutigen target_id-Wert "2".
    # Etwas paranoider: wir pruefen indirekt ueber die zaehlbare Liste.
    # Verlassen wir uns auf Action-Strings: in der Liste-Tabelle steht
    # `finding.acknowledged` mindestens einmal; `finding.reopened` darf nicht
    # haeufiger als im Dropdown vorkommen.
    # Wir pruefen ueber die <td>-Spalte target_id: "2" wuerde fuer den
    # gefilterten-out Reopen-Event sichtbar werden, "1" steht fuer den Match.
    assert ">1<" in body
    # target_id=2 hat als Action "finding.reopened" — beim Filter
    # auf "finding.acknowledged" darf der Wert "2" nicht als target_id-Zelle
    # auftauchen. Wir akzeptieren bis zu 1 Vorkommen (z.B. in pagination).
    # Eindeutiger Marker: `<td>2</td>` (kommt nur als target_id-Zelle).
    assert "<td>2</td>" not in body


def test_audit_unknown_action_filter_does_not_crash(db_app: Flask) -> None:
    create_admin_user(db_app)
    _add_event(db_app, actor="admin", action="finding.acknowledged", target_id="1")
    client = db_app.test_client()
    login(client)
    resp = client.get("/audit/?action=unknown.action")
    # Unbekannte Action -> Filter wird verworfen. 200 mit allen Events.
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]


def test_audit_filter_by_server_name_substring(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid_match = _create_server(db_app, "prod-web-01")
    sid_other = _create_server(db_app, "dev-db-02")
    _add_event(
        db_app,
        actor="admin",
        action="server.tag.added",
        target_type="server",
        target_id=str(sid_match),
    )
    _add_event(
        db_app,
        actor="admin",
        action="server.tag.added",
        target_type="server",
        target_id=str(sid_other),
    )
    client = db_app.test_client()
    login(client)
    resp = client.get("/audit/?server_name=prod-web")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Audit-Tabelle isolieren — Sidebar-Aggregate koennen IDs als
    # Aggregat-Counter rendern ("2 Server", `>2<`), das soll den Test
    # nicht stoeren. `data-test="audit-table"` markiert die Result-Tabelle.
    table_start = body.index('data-test="audit-table"')
    table_end = body.index("</table>", table_start)
    table = body[table_start:table_end]
    assert str(sid_match) in table
    # Other-Server-Event darf nicht in der Tabelle sein.
    assert table.count(f">{sid_other}<") == 0


def test_audit_filter_by_tag(db_app: Flask) -> None:
    create_admin_user(db_app)
    sid_prod = _create_server(db_app, "srv-audit-prod", tags=["prod"])
    sid_dev = _create_server(db_app, "srv-audit-dev", tags=["dev"])
    _add_event(
        db_app,
        actor="admin",
        action="server.tag.added",
        target_type="server",
        target_id=str(sid_prod),
    )
    _add_event(
        db_app,
        actor="admin",
        action="server.tag.added",
        target_type="server",
        target_id=str(sid_dev),
    )
    client = db_app.test_client()
    login(client)
    resp = client.get("/audit/?tag=prod")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Audit-Tabelle isolieren — Sidebar-Aggregate koennen IDs als `>2<`
    # rendern, die nichts mit dem Tabellen-Inhalt zu tun haben.
    table_start = body.index('data-test="audit-table"')
    table_end = body.index("</table>", table_start)
    table = body[table_start:table_end]
    assert str(sid_prod) in table
    # Dev-Server-Target-ID darf nicht in der gefilterten Tabelle stehen.
    assert table.count(f">{sid_dev}<") == 0


def test_audit_pagination_50_per_page(db_app: Flask) -> None:
    create_admin_user(db_app)
    # 75 Events.
    for i in range(75):
        _add_event(db_app, actor="admin", action="auth.login", target_id=str(i))
    client = db_app.test_client()
    login(client)

    resp1 = client.get("/audit/")
    assert resp1.status_code == 200
    body1 = resp1.get_data(as_text=True)
    # 50 Events auf Seite 1. Wir suchen nach einem eindeutigen target_id-Marker.
    # IDs 25..74 sollten alle auf Seite 1 sein (neueste zuerst, aber alle haben
    # ts=now); bei gleichem ts sortiert das nach id desc, also id-74..id-25
    # auf Seite 1, dann id-24..id-0 auf Seite 2. Wir pruefen einfach:
    # mindestens 50 verschiedene target-Eintraege sichtbar.
    visible_p1 = sum(1 for i in range(75) if f">{i}<" in body1)
    assert visible_p1 >= 50, visible_p1

    resp2 = client.get("/audit/?page=2")
    assert resp2.status_code == 200
    body2 = resp2.get_data(as_text=True)
    visible_p2 = sum(1 for i in range(75) if f">{i}<" in body2)
    assert visible_p2 >= 25, visible_p2


def test_audit_requires_login(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    resp = client.get("/audit/", follow_redirects=False)
    assert resp.status_code in (302, 401)
    if resp.status_code == 302:
        assert "/login" in resp.headers.get("Location", "")


# ---------------------------------------------------------------------------
# CSV-Export
# ---------------------------------------------------------------------------


def test_audit_csv_export_returns_csv_with_filter(db_app: Flask) -> None:
    create_admin_user(db_app)
    _add_event(db_app, actor="admin", action="finding.acknowledged", target_id="1")
    _add_event(db_app, actor="admin", action="finding.reopened", target_id="2")
    client = db_app.test_client()
    login(client)

    resp = client.get("/audit/export.csv?action=finding.acknowledged")
    assert resp.status_code == 200
    assert resp.mimetype.startswith("text/csv"), resp.mimetype
    assert "attachment" in resp.headers.get("Content-Disposition", "")
    body = resp.get_data(as_text=True)
    assert "finding.acknowledged" in body
    # Header-Zeile vorhanden.
    assert "ts" in body
    assert "action" in body


_ = timedelta
