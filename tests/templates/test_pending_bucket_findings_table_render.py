"""Pure-Unit Template-Render-Tests fuer ``_partials/pending_bucket_findings_table.html``.

Track Findings-Redesign (Style-/Markup-Replacement). Wie der regulaere
Bucket-Body, aber Cross-Server: zusaetzliche erste Daten-Spalte `Server`
(8-Spalten-Layout), OHNE `server_id`/`group_id` im Context, Pager auf
``findings.pending_fragment``.

Render-Pattern: ``jinja_env.get_template()`` + ``SimpleNamespace``-Mocks.
em-dash ist ``—`` (U+2014); Severity-Cell ist whitespace-umrandet.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from flask import Flask

_EM_DASH = "—"


def _make_finding(
    *,
    finding_id: int = 42,
    identifier_key: str = "CVE-2024-1234",
    risk_band_reason: str | None = None,
    is_kev: bool = False,
    title: str | None = "OpenSSL Buffer Overflow",
    package_name: str | None = "openssl",
    installed_version: str | None = "3.0.2-0ubuntu1.12",
    fixed_version: str | None = "3.0.2-0ubuntu1.13",
    epss_score: float | None = 0.12345,
    cvss_v3_score: float | None = 7.5,
    severity: str | None = "high",
    server_id: int = 5,
    server_name: str = "srv-prod-01",
    first_seen_at: datetime | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=finding_id,
        identifier_key=identifier_key,
        risk_band_reason=risk_band_reason,
        is_kev=is_kev,
        title=title,
        package_name=package_name,
        installed_version=installed_version,
        fixed_version=fixed_version,
        epss_score=epss_score,
        cvss_v3_score=cvss_v3_score,
        severity=severity,
        server=SimpleNamespace(id=server_id, name=server_name),
        first_seen_at=first_seen_at or datetime(2024, 5, 1, 12, 0, tzinfo=UTC),
    )


def _render(
    app: Flask,
    *,
    findings: list[SimpleNamespace],
    total: int | None = None,
    page: int = 1,
    per_page: int = 20,
    filter_qs: str = "",
) -> str:
    if total is None:
        total = len(findings)
    with app.test_request_context("/findings"):
        template = app.jinja_env.get_template("_partials/pending_bucket_findings_table.html")
        return template.render(
            findings=findings,
            total=total,
            page=page,
            per_page=per_page,
            filter_qs=filter_qs,
        )


# ---------------------------------------------------------------------------
# 8-Spalten-Header inkl. Server
# ---------------------------------------------------------------------------


def test_eight_column_header_includes_server(app: Flask) -> None:
    """8-Spalten-Header mit erster Daten-Spalte `Server`."""
    html = _render(app, findings=[_make_finding()])
    assert 'class="bucket-findings-head"' in html, html[:600]
    for col in ("Server", "CVE / Titel", "Paket", "EPSS", "CVSS", "Severity", "Erstmals"):
        assert col in html, f"Spaltenkopf '{col}' fehlt: {html[:800]}"
    assert ">Status<" not in html and "Status</span>" not in html, "Keine Status-Spalte"


# ---------------------------------------------------------------------------
# Server-Link
# ---------------------------------------------------------------------------


def test_server_link_contract(app: Flask) -> None:
    """Server-Link: data-test, class, @click.stop, href/hx-get auf server_detail.show."""
    html = _render(app, findings=[_make_finding(server_id=5, server_name="srv-prod-01")])
    assert 'data-test="pending-finding-server-link"' in html, html
    assert 'class="bucket-finding__server"' in html, html
    assert "@click.stop" in html, html
    assert "/servers/5" in html, f"server_detail.show-URL fehlt: {html}"
    assert "srv-prod-01" in html, html


def test_row_data_test_marker(app: Flask) -> None:
    """Zeile traegt data-test="pending-bucket-finding-row-<id>"."""
    html = _render(app, findings=[_make_finding(finding_id=88)])
    assert 'data-test="pending-bucket-finding-row-88"' in html, html


def test_empty_findings_renders_empty_marker(app: Flask) -> None:
    """findings=[] -> data-test="pending-bucket-findings-empty"."""
    html = _render(app, findings=[], total=0)
    assert 'data-test="pending-bucket-findings-empty"' in html, html
    assert "pending-bucket-finding-row-" not in html


# ---------------------------------------------------------------------------
# Pager auf pending_fragment
# ---------------------------------------------------------------------------


def test_pager_markers_and_pending_fragment_url(app: Flask) -> None:
    """Pager: pending-bucket-pager/-prev/-next; URL auf findings.pending_fragment."""
    html = _render(app, findings=[_make_finding()], total=60, per_page=20, page=2, filter_qs="q=x")
    assert 'data-test="pending-bucket-pager"' in html, html
    assert 'data-test="pending-bucket-pager-prev"' in html, html
    assert 'data-test="pending-bucket-pager-next"' in html, html
    assert "/findings/pending" in html, f"pending_fragment-URL fehlt: {html}"
    assert "q=x" in html, f"filter_qs im Pager-URL fehlt: {html}"


def test_pager_both_disabled_when_single_page(app: Flask) -> None:
    """total<=per_page -> prev und next disabled."""
    html = _render(app, findings=[_make_finding()], total=3, per_page=20, page=1)
    prev_idx = html.find('data-test="pending-bucket-pager-prev"')
    next_idx = html.find('data-test="pending-bucket-pager-next"')
    prev_tag = html[prev_idx : html.find(">", prev_idx)]
    next_tag = html[next_idx : html.find(">", next_idx)]
    assert "disabled" in prev_tag, prev_tag
    assert "disabled" in next_tag, next_tag


# ---------------------------------------------------------------------------
# sd-* / KEV / Severity / EPSS / XSS / Bulk (sinngemaess wie regulaerer Body)
# ---------------------------------------------------------------------------


def test_kev_badge_present_and_absent(app: Flask) -> None:
    html_kev = _render(app, findings=[_make_finding(is_kev=True)])
    html_no = _render(app, findings=[_make_finding(is_kev=False)])
    assert "sd-badge sd-badge--kev" in html_kev, html_kev
    assert "sd-badge--kev" not in html_no, html_no


def test_severity_critical_accent_high_neutral(app: Flask) -> None:
    html_crit = _render(app, findings=[_make_finding(severity="critical")])
    html_high = _render(app, findings=[_make_finding(severity="high")])
    assert "sd-cap--accent" in html_crit and "CRITICAL" in html_crit, html_crit
    assert "sd-cap--accent" not in html_high, html_high
    assert "HIGH" in html_high, html_high


def test_epss_cvss_em_dash_when_none(app: Flask) -> None:
    html = _render(app, findings=[_make_finding(epss_score=None, cvss_v3_score=None)])
    assert _EM_DASH in html, repr(html)


def test_inline_ai_reason_escaped(app: Flask) -> None:
    html = _render(app, findings=[_make_finding(risk_band_reason="<script>alert(1)</script>")])
    assert "<script>alert(1)</script>" not in html, html
    assert "&lt;script&gt;" in html, html
    assert "KI-Bewertung" in html and "sd-ai-text" in html, html


def test_checkbox_bulk_contract(app: Flask) -> None:
    html = _render(app, findings=[_make_finding(finding_id=77)])
    assert 'data-bulk-finding-id="77"' in html, html
    assert "toggleFinding(77, $event.target.checked)" in html, html
    assert "@click.stop" in html, html


def test_no_daisyui_classes(app: Flask) -> None:
    html = _render(app, findings=[_make_finding(is_kev=True, risk_band_reason="x")])
    for needle in ('class="badge ', " btn-", "table table", "link-hover", "checkbox checkbox"):
        assert needle not in html, f"DaisyUI-Rest gefunden: {needle!r}"


def test_no_quick_copy_clipboard_button(app: Flask) -> None:
    html = _render(app, findings=[_make_finding()])
    assert 'title="In Zwischenablage kopieren"' not in html, html
