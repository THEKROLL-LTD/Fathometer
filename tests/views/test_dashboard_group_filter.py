"""Findings-Group-Filter und Group-Spalte (Block P, Task #14 / Block Q, ADR-0025).

DoD:
  - `?application_group=<id>` filtert die Findings-Tabelle.
  - Sort-Header "Group" sortiert alphabetisch nach Group.label asc/desc.
  - Findings ohne Group zeigen `—` in der Group-Spalte.

Block Q (ADR-0025) hat den Cross-Server-Filter vom Dashboard `/` auf die
dedizierte `/findings`-Seite verlagert — alle Tests hier laufen jetzt
gegen `/findings`.
"""

from __future__ import annotations

from datetime import UTC, datetime

from flask import Flask

from app.db import get_session_factory
from app.models import (
    ApplicationGroup,
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Server,
    Severity,
)
from tests._helpers import create_admin_user, login


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _seed(db_app: Flask) -> dict[str, int]:
    """Legt Server, 2 Groups und 4 Findings (2 in g1, 1 in g2, 1 ungrouped) an.

    Liefert ein Mapping mit `srv_id`, `g1_id`, `g2_id` und den Finding-IDs.
    """
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            srv = Server(name="srv-dash", api_key_hash="x" * 64)
            sess.add(srv)
            sess.flush()

            g_alpha = ApplicationGroup(
                label="alpha-app",
                path_prefixes=[],
                pkg_name_exact=[],
                pkg_name_glob=[],
                pkg_purl_pattern=[],
                risk_band="act",
            )
            g_zulu = ApplicationGroup(
                label="zulu-app",
                path_prefixes=[],
                pkg_name_exact=[],
                pkg_name_glob=[],
                pkg_purl_pattern=[],
                risk_band="monitor",
            )
            sess.add_all([g_alpha, g_zulu])
            sess.flush()

            def _mk(idx: int, grp_id: int | None) -> Finding:
                return Finding(
                    server_id=srv.id,
                    finding_type=FindingType.VULNERABILITY,
                    finding_class=FindingClass.OS_PKGS,
                    identifier_key=f"CVE-DASH-{idx}",
                    package_name=f"pkg-{idx}",
                    severity=Severity.HIGH,
                    status=FindingStatus.OPEN,
                    attack_vector=AttackVector.UNKNOWN,
                    first_seen_at=_now(),
                    last_seen_at=_now(),
                    application_group_id=grp_id,
                    risk_band="act" if grp_id is not None else "pending",
                )

            f1 = _mk(1, g_alpha.id)
            f2 = _mk(2, g_alpha.id)
            f3 = _mk(3, g_zulu.id)
            f4 = _mk(4, None)
            sess.add_all([f1, f2, f3, f4])
            sess.flush()
            sess.commit()
            return {
                "srv_id": srv.id,
                "g_alpha": g_alpha.id,
                "g_zulu": g_zulu.id,
                "f1": f1.id,
                "f2": f2.id,
                "f3": f3.id,
                "f4": f4.id,
            }
        finally:
            sess.close()


def test_dashboard_filter_by_application_group(db_app: Flask) -> None:
    """`?application_group=<id>` filtert auf Findings dieser Group."""
    create_admin_user(db_app)
    ids = _seed(db_app)
    client = db_app.test_client()
    login(client)

    resp = client.get(f"/findings?application_group={ids['g_alpha']}&status=open")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Findings aus alpha-Group muessen drin sein.
    assert "CVE-DASH-1" in body
    assert "CVE-DASH-2" in body
    # Finding aus zulu-Group oder ungrouped: NICHT in der Tabelle.
    # (Wir checken eine Zeilen-Markierung, nicht das Wort allein — der
    # Filter-Bar-Select kann das Group-Label trotzdem enthalten.)
    assert "CVE-DASH-3" not in body
    assert "CVE-DASH-4" not in body


def test_dashboard_filter_invalid_application_group_falls_back_to_none(
    db_app: Flask,
) -> None:
    """Ungueltige `application_group`-Werte werden still ignoriert.

    Wir setzen zusaetzlich `?q=CVE-DASH` damit `is_filtered=True` und die
    Findings-Tabelle gerendert wird — sonst zeigt /findings den Empty-State.
    """
    create_admin_user(db_app)
    _seed(db_app)
    client = db_app.test_client()
    login(client)

    # `0` ist nicht erlaubt (ge=1) und ein String erst recht nicht.
    for bad in ("0", "-1", "abc", "9999999"):
        resp = client.get(f"/findings?application_group={bad}&status=open&q=CVE-DASH")
        assert resp.status_code == 200, resp.status_code
        body = resp.get_data(as_text=True)
        # Bei "0/-1/abc" wird der application_group-Filter ignoriert -> alle
        # 4 Findings (durch q=CVE-DASH gematcht) da.
        # Bei "9999999" wird der Filter aktiv (gueltige ID-Form), die Tabelle
        # bleibt leer. Beide Verhalten sind ok — wir verlangen nur "kein
        # 422-Crash".
        if bad in ("0", "-1", "abc"):
            assert "CVE-DASH-1" in body, f"bad={bad}: Findings nicht gerendert"


def test_dashboard_group_column_shows_label_or_dash(db_app: Flask) -> None:
    """Findings mit Group zeigen Label, ohne Group zeigen Em-Dash.

    `?q=CVE-DASH` aktiviert die Tabelle (sonst Empty-State auf /findings).
    """
    create_admin_user(db_app)
    _seed(db_app)
    client = db_app.test_client()
    login(client)

    body = client.get("/findings?q=CVE-DASH&status=open").get_data(as_text=True)

    # Group-Spalte ist im Markup vorhanden.
    assert 'data-test="finding-group-cell"' in body
    # Mindestens eine Cell mit Group-Link.
    assert 'data-test="finding-group-link"' in body
    # alpha-app + zulu-app als Group-Labels.
    assert "alpha-app" in body
    assert "zulu-app" in body
    # Ungrouped-Finding (#4) hat die "empty"-Variante.
    assert 'data-test="finding-group-empty"' in body


def test_dashboard_sort_by_group_label(db_app: Flask) -> None:
    """`?sort=group&dir=asc` sortiert Findings nach Group.label asc.

    Wir pruefen nur die relative Position der zwei Findings aus alpha-app
    gegenueber dem einen aus zulu-app — alpha kommt vor zulu.
    """
    create_admin_user(db_app)
    _seed(db_app)
    client = db_app.test_client()
    login(client)

    body_asc = client.get("/findings?sort=group&dir=asc&status=open").get_data(as_text=True)
    # Mindestens einer der alpha-Findings muss VOR dem zulu-Finding stehen.
    p_alpha = body_asc.find("CVE-DASH-1")
    p_zulu = body_asc.find("CVE-DASH-3")
    assert p_alpha != -1 and p_zulu != -1
    assert p_alpha < p_zulu, (p_alpha, p_zulu)

    body_desc = client.get("/findings?sort=group&dir=desc&status=open").get_data(as_text=True)
    p_alpha_d = body_desc.find("CVE-DASH-1")
    p_zulu_d = body_desc.find("CVE-DASH-3")
    assert p_zulu_d < p_alpha_d, (p_zulu_d, p_alpha_d)


def test_dashboard_group_filter_select_renders(db_app: Flask) -> None:
    """Filter-Bar enthaelt `<select name="application_group">` mit Library-
    Options."""
    create_admin_user(db_app)
    _seed(db_app)
    client = db_app.test_client()
    login(client)

    body = client.get("/findings").get_data(as_text=True)
    assert 'data-test="filter-application-group"' in body
    assert 'name="application_group"' in body
    # Beide Group-Labels als Options.
    assert "alpha-app" in body
    assert "zulu-app" in body
