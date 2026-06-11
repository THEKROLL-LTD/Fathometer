"""Pure-Unit-Tests fuer den Triage-Queue-Fragment-Endpoint (Block Y Phase C,
ADR-0039 §3).

Prueft `GET /servers/<id>/triage/<band>` in `app/views/server_detail.py`:

  - Happy-Path: Page 1 von N liefert max 10 Findings + Pager-Footer.
  - Pagination: Seiten-Ersatz via Vor/Zurueck-Buttons (Seite N von M).
  - Whitelist: ungueltiges Band -> 400.
  - 404 bei unbekanntem/revoked/retired Server.
  - Leere Band-Response (kein Crash).
  - Projektion enthaelt die 13 erwarteten Spalten.
  - Sort-Reihenfolge: KEV DESC, Severity ASC (CRITICAL=0), EPSS DESC NULLS LAST.
  - Auth-Guard (302 ohne Login).
  - Page-Parameter-Edge-Cases: 0 -> Page 1, "abc" -> 400.
  - Template-Smoke: risk_band_section.html hat hx-get/hx-trigger korrekt.

Pattern: Flask-Testclient + Mock-Session + direkter `__wrapped__`-Aufruf
fuer Content-Tests, um `@login_required` zu umgehen. Keine DB.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from flask import Flask
from flask.testing import FlaskClient
from werkzeug.exceptions import HTTPException

from app.models import FindingClass, FindingStatus, Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_server(
    server_id: int = 1,
    *,
    revoked_at: datetime | None = None,
    retired_at: datetime | None = None,
) -> MagicMock:
    srv = MagicMock()
    srv.id = server_id
    srv.name = f"host-{server_id}"
    srv.revoked_at = revoked_at
    srv.retired_at = retired_at
    srv.tag_links = []
    return srv


def _make_row(
    *,
    fid: int,
    identifier_key: str = "CVE-2024-0001",
    title: str | None = "Boom",
    package_name: str = "openssl",
    installed_version: str | None = "1.0.0",
    fixed_version: str | None = "1.0.1",
    epss_score: float | None = 0.5,
    cvss_v3_score: float | None = 7.5,
    severity: Severity = Severity.HIGH,
    is_kev: bool = False,
    status: FindingStatus = FindingStatus.OPEN,
    finding_class: FindingClass = FindingClass.OS_PKGS,
    description: str | None = None,
    references: list[str] | None = None,
    primary_url: str | None = None,
    notes: list[Any] | None = None,
) -> SimpleNamespace:
    """Imitiert ein ORM-`Finding`-Objekt mit Attribut-Zugriff.

    Block AA (ADR-0041): triage_band_fragment hydratisiert volle ORM-Findings,
    der Inline-Body greift auf `description`/`references`/`primary_url`/`notes`
    zu — daher hier mitmodelliert.
    """
    return SimpleNamespace(
        id=fid,
        identifier_key=identifier_key,
        title=title,
        package_name=package_name,
        installed_version=installed_version,
        fixed_version=fixed_version,
        epss_score=epss_score,
        cvss_v3_score=cvss_v3_score,
        severity=severity,
        is_kev=is_kev,
        status=status,
        finding_class=finding_class,
        description=description,
        references=references,
        primary_url=primary_url,
        notes=notes if notes is not None else [],
    )


def _stub_load_server(monkeypatch: pytest.MonkeyPatch, server: MagicMock | None) -> None:
    monkeypatch.setattr(
        "app.views.server_detail._load_server_with_tags",
        lambda _sid: server,
    )


def _patch_session_returning(
    monkeypatch: pytest.MonkeyPatch, rows: list[Any], *, total: int | None = None
) -> tuple[MagicMock, list[Any]]:
    """Patcht get_session fuer den Triage-Endpoint.

    Two-Step-Hydration (Perf-Refactor 2026-06-07): der Endpoint feuert DREI
    Queries (bei nicht-leerem Ergebnis):
      [0] COUNT (`.scalar()` -> `total`) fuer die Pagination-Metadaten,
      [1] schlanke ID-Query (`.scalars()` #1 -> IDs) fuer Sort+LIMIT,
      [-1] volle ORM-Hydration (`.scalars()` #2 -> `rows`) der <=10 IDs.
    Bei leerem Ergebnis entfaellt [-1] (page_ids leer -> keine Hydration),
    dann ist `captured` 2 Eintraege lang. Alle Statement-Ausdruecke landen
    in `captured`.
    """
    sess = MagicMock()
    captured: list[Any] = []
    _total = total if total is not None else len(rows)
    ids = [r.id for r in rows]
    state = {"scalars_calls": 0}

    def _execute(stmt: Any) -> Any:
        captured.append(stmt)
        result = MagicMock()
        result.scalar.return_value = _total

        def _scalars() -> Any:
            state["scalars_calls"] += 1
            sc = MagicMock()
            sc.all.return_value = list(ids) if state["scalars_calls"] == 1 else list(rows)
            return sc

        result.scalars.side_effect = _scalars
        return result

    sess.execute.side_effect = _execute
    monkeypatch.setattr("app.views.server_detail.get_session", lambda: sess)
    return sess, captured


def _call_inner(
    app: Flask,
    url: str,
    server_id: int,
    band: str,
) -> Any:
    """Ruft `triage_band_fragment.__wrapped__` im Request-Context auf."""
    from app.views import server_detail

    view = server_detail.triage_band_fragment
    inner = getattr(view, "__wrapped__", view)
    with app.test_request_context(url, method="GET"):
        try:
            return inner(server_id, band)
        except HTTPException as exc:
            return exc


# ---------------------------------------------------------------------------
# Route-Registrierung
# ---------------------------------------------------------------------------


def test_triage_route_registered(app: Flask) -> None:
    rules = {r.rule: list(r.methods or []) for r in app.url_map.iter_rules()}
    rule = "/servers/<int:server_id>/triage/<string:band>"
    assert rule in rules, f"Route {rule!r} fehlt. Vorhanden: {sorted(rules)}"
    assert "GET" in rules[rule]


# ---------------------------------------------------------------------------
# Auth-Guard
# ---------------------------------------------------------------------------


def test_triage_band_fragment_auth_guard(client: FlaskClient) -> None:
    response = client.get("/servers/1/triage/escalate")
    assert response.status_code == 302
    location = response.headers.get("Location", "")
    assert "login" in location.lower()


# ---------------------------------------------------------------------------
# Whitelist + 404-Guards
# ---------------------------------------------------------------------------


def test_triage_band_fragment_invalid_band_400(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    # Auch wenn der Server existiert: ungueltiges Band MUSS 400 liefern, bevor
    # _load_active_server_or_404 ueberhaupt aufgerufen wird (Whitelist first).
    _stub_load_server(monkeypatch, _make_server(1))
    result = _call_inner(app, "/servers/1/triage/bogus", 1, "bogus")
    assert isinstance(result, HTTPException), f"Erwartet HTTPException, erhalten: {result!r}"
    assert result.code == 400


def test_triage_band_fragment_unknown_server_404(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_load_server(monkeypatch, None)
    result = _call_inner(app, "/servers/999/triage/escalate", 999, "escalate")
    assert isinstance(result, HTTPException) and result.code == 404


def test_triage_band_fragment_revoked_server_404(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_load_server(monkeypatch, _make_server(1, revoked_at=datetime.now(UTC)))
    result = _call_inner(app, "/servers/1/triage/escalate", 1, "escalate")
    assert isinstance(result, HTTPException) and result.code == 404


def test_triage_band_fragment_retired_server_404(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_load_server(monkeypatch, _make_server(1, retired_at=datetime.now(UTC)))
    result = _call_inner(app, "/servers/1/triage/escalate", 1, "escalate")
    assert isinstance(result, HTTPException) and result.code == 404


# ---------------------------------------------------------------------------
# Page-Parameter Edge-Cases
# ---------------------------------------------------------------------------


def test_triage_band_fragment_page_string_400(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Nicht-numerisches page="abc" -> 400 statt 500."""
    _stub_load_server(monkeypatch, _make_server(1))
    _patch_session_returning(monkeypatch, [])
    result = _call_inner(app, "/servers/1/triage/escalate?page=abc", 1, "escalate")
    assert isinstance(result, HTTPException), f"Erwartet HTTPException, erhalten: {result!r}"
    assert result.code == 400


def test_triage_band_fragment_page_zero_clamps_to_one(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """page=0 wird auf 1 geklemmt — kein 400, normales Rendering."""
    _stub_load_server(monkeypatch, _make_server(1))
    _patch_session_returning(monkeypatch, [])
    html = _call_inner(app, "/servers/1/triage/escalate?page=0", 1, "escalate")
    assert isinstance(html, str), f"Erwartet HTML, erhalten: {html!r}"


def test_triage_band_fragment_page_negative_clamps_to_one(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_load_server(monkeypatch, _make_server(1))
    _patch_session_returning(monkeypatch, [])
    html = _call_inner(app, "/servers/1/triage/escalate?page=-3", 1, "escalate")
    assert isinstance(html, str), f"Erwartet HTML, erhalten: {html!r}"


# ---------------------------------------------------------------------------
# Happy-Path + Pagination
# ---------------------------------------------------------------------------


def test_triage_band_fragment_page_1_of_many(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Page 1 von 3 (total=30, Page-Size 10): 10 Rows, Kopf, aktiver Next-Button."""
    _stub_load_server(monkeypatch, _make_server(1))
    rows = [_make_row(fid=i, identifier_key=f"CVE-2024-{i:04d}") for i in range(1, 11)]
    _patch_session_returning(monkeypatch, rows, total=30)
    html = _call_inner(app, "/servers/1/triage/escalate?page=1", 1, "escalate")
    assert isinstance(html, str)
    # 10 Finding-Rows
    assert html.count('data-test="triage-finding-row-') == 10, (
        f"Erwartet 10 Finding-Rows, gefunden: {html.count('data-test="triage-finding-row-')}"
    )
    # Spalten-Kopf rendert auf jeder Seite (Seiten-Ersatz, nicht Append)
    assert "sd-findings-head" in html
    # Pager-Footer mit korrektem Seiten-/Total-Text
    assert 'data-test="triage-pager-escalate"' in html
    assert "Page 1 of 3" in html
    assert "30 findings" in html
    # Next-Button aktiv (zeigt auf page=2), Prev-Button disabled (page=1)
    assert 'data-test="triage-pager-next-escalate"' in html
    assert "page=2" in html
    assert 'data-test="triage-pager-prev-escalate"' in html
    # Prev ist auf Seite 1 disabled — kein hx-get fuer page=0
    assert "page=0" not in html


def test_triage_band_fragment_last_page_next_disabled(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Letzte Seite (page 3 von 3, total=26, Page-Size 10): Prev aktiv, Next disabled."""
    _stub_load_server(monkeypatch, _make_server(1))
    rows = [_make_row(fid=i, identifier_key=f"CVE-2024-{i:04d}") for i in range(21, 27)]
    _patch_session_returning(monkeypatch, rows, total=26)
    html = _call_inner(app, "/servers/1/triage/escalate?page=3", 1, "escalate")
    assert isinstance(html, str)
    assert html.count('data-test="triage-finding-row-') == 6
    # Kopf rendert auf jeder Seite
    assert "sd-findings-head" in html
    assert "Page 3 of 3" in html
    # Prev aktiv -> page=2, Next disabled -> kein page=4
    assert "page=2" in html
    assert "page=4" not in html


def test_triage_band_fragment_single_page_both_disabled(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine einzige Seite (Seite 1 von 1, total=8 <= Page-Size 10): beide disabled."""
    _stub_load_server(monkeypatch, _make_server(1))
    rows = [_make_row(fid=i, identifier_key=f"CVE-2024-{i:04d}") for i in range(1, 9)]
    _patch_session_returning(monkeypatch, rows, total=8)
    html = _call_inner(app, "/servers/1/triage/escalate?page=1", 1, "escalate")
    assert isinstance(html, str)
    assert "Page 1 of 1 · 8 findings" in html
    # Keine Navigation moeglich -> weder page=0 noch page=2 als hx-get
    assert "page=0" not in html
    assert "page=2" not in html


def test_triage_band_fragment_empty_band(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Leere Band-Response -> 200 mit Empty-Hint, kein Pager, kein Crash."""
    _stub_load_server(monkeypatch, _make_server(1))
    _patch_session_returning(monkeypatch, [], total=0)
    html = _call_inner(app, "/servers/1/triage/monitor?page=1", 1, "monitor")
    assert isinstance(html, str)
    assert 'data-test="triage-empty-monitor"' in html
    assert 'data-test="triage-finding-row-' not in html
    assert 'data-test="triage-pager-' not in html


# ---------------------------------------------------------------------------
# ORM-Hydration (Block AA, ADR-0041) — ersetzt die ADR-0039-Spalten-Projektion
# ---------------------------------------------------------------------------


def test_triage_band_fragment_orm_hydration_columns(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Block AA (ADR-0041): die Hydration-Query ist ein volles `select(Finding)`
    — die Inline-Body-Felder description/references/primary_url sind als
    Spalten Teil der Selektion.

    Perf-Refactor 2026-06-07 (Two-Step): Step 1 projiziert NUR `id` (schlanker
    Index-Only-Scan ueber ix_findings_server_open_triage), Step 2 hydratisiert
    die <=10 sichtbaren IDs voll. Wir verifizieren beide Vertraege."""
    _stub_load_server(monkeypatch, _make_server(1))
    rows = [_make_row(fid=1)]
    _sess, captured = _patch_session_returning(monkeypatch, rows)
    _call_inner(app, "/servers/1/triage/escalate?page=1", 1, "escalate")
    # Drei Statements: [0] COUNT, [1] schlanke ID-Query, [-1] ORM-Hydration.
    assert len(captured) == 3, (
        f"Erwartet 3 SQL-Statements (COUNT + ID-Query + Hydration), captured: {len(captured)}"
    )
    # Step 1 darf NUR `id` projizieren — sonst materialisiert der Sort wieder
    # fette Rows (das ist genau der Bug, den dieser Refactor behebt).
    id_cols = {c.name for c in captured[1].selected_columns}
    assert id_cols == {"id"}, f"Step-1-Query soll nur `id` projizieren, hat: {sorted(id_cols)}"
    # Step 2: volle ORM-Hydration mit den Inline-Body-Spalten.
    col_names = {c.name for c in captured[-1].selected_columns}
    for needed in ("id", "description", "references", "primary_url"):
        assert needed in col_names, (
            f"ORM-Hydration unvollstaendig — {needed!r} fehlt in {sorted(col_names)}"
        )


def test_triage_band_fragment_eager_loads_notes(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """selectinload(Finding.notes) ist als Loader-Option der Hydration-Query
    gesetzt (kein N+1). Bei nicht-leerem Ergebnis ist die Hydration-Query
    `captured[-1]` (Step 2 des Two-Step-Refactors)."""
    _stub_load_server(monkeypatch, _make_server(1))
    rows = [_make_row(fid=1)]
    _sess, captured = _patch_session_returning(monkeypatch, rows)
    _call_inner(app, "/servers/1/triage/escalate?page=1", 1, "escalate")
    stmt = captured[-1]
    # Loader-Optionen tragen das Ziel-Attribut im `path`-Repr.
    opts_repr = " ".join(str(getattr(o, "path", o)) for o in stmt._with_options)
    assert "Finding.notes" in opts_repr, (
        f"selectinload(Finding.notes) fehlt in Loader-Optionen: {opts_repr}"
    )


# ---------------------------------------------------------------------------
# Sort-Reihenfolge
# ---------------------------------------------------------------------------


def test_triage_band_fragment_sort_order_clause(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SQL-ORDER-BY enthaelt is_kev DESC, severity-CASE ASC, epss_score DESC NULLS LAST."""
    _stub_load_server(monkeypatch, _make_server(1))
    _sess, captured = _patch_session_returning(monkeypatch, [])
    _call_inner(app, "/servers/1/triage/escalate?page=1", 1, "escalate")
    stmt = captured[-1]
    # Stmt-Compile inspektion: ORDER-BY-Klauseln.
    compiled = str(stmt.compile(compile_kwargs={"literal_binds": False}))
    # Reihenfolge der ORDER-BY-Tokens.
    order_pos_kev = compiled.find("findings.is_kev DESC")
    order_pos_epss = compiled.find("findings.epss_score DESC NULLS LAST")
    assert order_pos_kev > 0, f"is_kev DESC fehlt im SQL: {compiled}"
    assert order_pos_epss > 0, f"epss_score DESC NULLS LAST fehlt im SQL: {compiled}"
    # KEV muss vor EPSS im ORDER-BY stehen.
    assert order_pos_kev < order_pos_epss, (
        f"Sort-Reihenfolge falsch: KEV pos={order_pos_kev}, EPSS pos={order_pos_epss}"
    )
    # CASE-Expression fuer severity-Rank muss zwischen KEV und EPSS stehen.
    # Postgres-CASE wird als "CASE WHEN ... THEN ... END" gerendert.
    order_pos_case = compiled.find("CASE", order_pos_kev)
    assert 0 < order_pos_case < order_pos_epss, (
        f"Severity-CASE muss zwischen KEV und EPSS stehen, gefunden bei pos={order_pos_case}"
    )


def test_triage_severity_sort_expr_mapping() -> None:
    """Unit-Test der Pure-Function `_triage_severity_sort_expr`: CASE-Mapping
    weist CRITICAL den niedrigsten Rank zu (0), UNKNOWN den hoechsten (4)."""
    from app.views.server_detail import _triage_severity_sort_expr

    expr = _triage_severity_sort_expr()
    compiled = str(expr.compile(compile_kwargs={"literal_binds": True}))
    # Wir verifizieren, dass die literal-Werte CRITICAL=0 ... UNKNOWN=4 in der
    # erwarteten Reihenfolge in der CASE-Expression vorkommen.
    assert "'critical'" in compiled
    assert "'high'" in compiled
    assert "'medium'" in compiled
    assert "'low'" in compiled
    assert "'unknown'" in compiled
    # CRITICAL muss vor HIGH stehen (durchsuchbare Reihenfolge).
    crit_pos = compiled.find("'critical'")
    high_pos = compiled.find("'high'")
    med_pos = compiled.find("'medium'")
    low_pos = compiled.find("'low'")
    unk_pos = compiled.find("'unknown'")
    assert crit_pos < high_pos < med_pos < low_pos < unk_pos, (
        f"CASE-Reihenfolge falsch: critical={crit_pos}, high={high_pos}, "
        f"medium={med_pos}, low={low_pos}, unknown={unk_pos}"
    )


# ---------------------------------------------------------------------------
# Limit / Offset
# ---------------------------------------------------------------------------


def test_triage_band_fragment_limit_offset(app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Page 3 (total=100, Page-Size 10) -> LIMIT 10 OFFSET 20."""
    _stub_load_server(monkeypatch, _make_server(1))
    _sess, captured = _patch_session_returning(monkeypatch, [], total=100)
    _call_inner(app, "/servers/1/triage/escalate?page=3", 1, "escalate")
    stmt = captured[-1]
    compiled = str(stmt.compile(compile_kwargs={"literal_binds": True}))
    assert "LIMIT 10" in compiled, f"LIMIT 10 fehlt: {compiled}"
    assert "OFFSET 20" in compiled, f"OFFSET 20 fehlt: {compiled}"


# ---------------------------------------------------------------------------
# Template-Smoke: risk_band_section.html hat hx-get / hx-trigger
# ---------------------------------------------------------------------------


def test_risk_band_section_default_open_hx_load(app: Flask) -> None:
    """Default-open-Band: `<details open>` + `hx-trigger="load"`."""
    from flask import render_template

    srv = SimpleNamespace(id=42)
    section = {
        "band": "escalate",
        "total_count": 5,
        "is_empty": False,
        "default_open": True,
    }
    with app.test_request_context("/"):
        html = render_template("_partials/risk_band_section.html", server=srv, section=section)
    assert "open" in html, "default_open=True muss `open`-Attr setzen"
    assert "/servers/42/triage/escalate" in html, "hx-get-URL fehlt"
    assert 'hx-trigger="load"' in html, "hx-trigger=load fehlt"
    assert 'data-test="risk-band-body-escalate"' in html


def test_risk_band_section_collapsed_hx_toggle(app: Flask) -> None:
    """Nicht-default-open-Band: `hx-trigger="toggle from:closest details once"`."""
    from flask import render_template

    srv = SimpleNamespace(id=42)
    section = {
        "band": "act",
        "total_count": 3,
        "is_empty": False,
        "default_open": False,
    }
    with app.test_request_context("/"):
        html = render_template("_partials/risk_band_section.html", server=srv, section=section)
    assert "/servers/42/triage/act" in html
    assert 'hx-trigger="toggle from:closest details once"' in html, (
        f"Lazy-toggle-trigger fehlt im Markup: {html}"
    )
    # Default-open-Attribute darf NICHT gerendert werden.
    assert "<details" in html
    assert ">\n" in html or "><" in html or "open" not in html.split(">", 1)[0]


def test_risk_band_section_empty_band_skipped(app: Flask) -> None:
    """is_empty=True -> Partial rendert leer (kein <details>)."""
    from flask import render_template

    srv = SimpleNamespace(id=42)
    section = {
        "band": "monitor",
        "total_count": 0,
        "is_empty": True,
        "default_open": False,
    }
    with app.test_request_context("/"):
        html = render_template("_partials/risk_band_section.html", server=srv, section=section)
    assert "<details" not in html
    assert html.strip() == ""
