"""Pure-Unit Template-Render-Tests fuer ``_partials/bucket_findings_table.html``.

Track Findings-Redesign (Style-/Markup-Replacement DaisyUI -> sd-*/ff-*).
Backend/Routes/Schemas unveraendert; getestet wird nur der Render-Vertrag des
umgebauten Partials.

Render-Pattern: Flask-App mit ``test_request_context`` +
``jinja_env.get_template()``; Finding-Mocks via ``SimpleNamespace`` (kein
DB-Zugriff). Fehlende Attribute werden defensiv aufgeloest — minimaler Mock
genuegt.

Hinweise:
  - Severity-Cell rendert mit Whitespace um den Text (``>\\n  HIGH\\n  <``) —
    ``HIGH`` wird als Substring geprueft, nicht ``>HIGH<``.
  - em-dash ist ``—`` (U+2014).
  - KEIN OOB-Drift-Test: der Pager re-rendert dasselbe Partial (Single-Source),
    es gibt keinen ``hx-swap-oob``-Pfad.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from flask import Flask

# em-dash (U+2014) — Platzhalter fuer None-Werte in EPSS/CVSS/Severity.
_EM_DASH = "—"


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


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
        first_seen_at=first_seen_at or datetime(2024, 5, 1, 12, 0, tzinfo=UTC),
    )


def _render(
    app: Flask,
    *,
    findings: list[SimpleNamespace],
    total: int | None = None,
    page: int = 1,
    per_page: int = 20,
    server_id: int = 42,
    group_id: int = 7,
    filter_qs: str = "",
) -> str:
    if total is None:
        total = len(findings)
    with app.test_request_context("/findings"):
        template = app.jinja_env.get_template("_partials/bucket_findings_table.html")
        return template.render(
            findings=findings,
            total=total,
            page=page,
            per_page=per_page,
            server_id=server_id,
            group_id=group_id,
            filter_qs=filter_qs,
        )


# ---------------------------------------------------------------------------
# Zeilen-Markup
# ---------------------------------------------------------------------------


def test_single_finding_renders_details_row(app: Flask) -> None:
    """1 Finding ergibt <details class="bucket-finding" mit id + data-test."""
    html = _render(app, findings=[_make_finding(finding_id=99)])

    assert '<details class="bucket-finding"' in html, html[:600]
    assert 'id="finding-99"' in html, html
    assert 'data-test="bucket-finding-row-99"' in html, html


def test_seven_column_header_without_status(app: Flask) -> None:
    """7-Spalten-Header `bucket-findings-head`; KEINE Status-Spalte."""
    html = _render(app, findings=[_make_finding()])

    assert 'class="bucket-findings-head"' in html, html[:600]
    for col in ("CVE / Titel", "Paket", "EPSS", "CVSS", "Severity", "Erstmals"):
        assert col in html, f"Spaltenkopf '{col}' fehlt: {html[:800]}"
    # Status-Spalte ist gedroppt (Design-Adoption analog Server-Detail-Triage).
    assert ">Status<" not in html, f"Status-Spaltenkopf darf NICHT auftauchen: {html}"
    assert "Status</span>" not in html, f"Status-Spaltenkopf darf NICHT auftauchen: {html}"


def test_empty_findings_renders_empty_marker(app: Flask) -> None:
    """findings=[] -> data-test="bucket-findings-empty", keine Zeile."""
    html = _render(app, findings=[], total=0)

    assert 'data-test="bucket-findings-empty"' in html, html
    assert "bucket-finding-row-" not in html, "Keine Finding-Zeile bei leerer Liste"


# ---------------------------------------------------------------------------
# KEV
# ---------------------------------------------------------------------------


def test_kev_badge_present_when_is_kev(app: Flask) -> None:
    """f.is_kev=True -> sd-badge sd-badge--kev im Output."""
    html = _render(app, findings=[_make_finding(is_kev=True)])
    assert "sd-badge sd-badge--kev" in html, html


def test_kev_badge_absent_when_not_kev(app: Flask) -> None:
    """f.is_kev=False -> KEINE KEV-Badge."""
    html = _render(app, findings=[_make_finding(is_kev=False)])
    assert "sd-badge--kev" not in html, html


# ---------------------------------------------------------------------------
# Severity-Cap (Accent nur CRITICAL)
# ---------------------------------------------------------------------------


def test_severity_critical_uses_accent_cap(app: Flask) -> None:
    """f.severity='critical' -> sd-cap--accent + Text CRITICAL."""
    html = _render(app, findings=[_make_finding(severity="critical")])
    assert "sd-cap--accent" in html, html
    assert "CRITICAL" in html, html


def test_severity_high_has_no_accent_cap(app: Flask) -> None:
    """f.severity='high' -> KEIN sd-cap--accent (nur neutral). Hard-Constraint."""
    html = _render(app, findings=[_make_finding(severity="high")])
    assert "sd-cap--accent" not in html, (
        f"Accent-Cap nur fuer CRITICAL erlaubt, NICHT fuer HIGH: {html}"
    )
    # Severity-Text steht mit Whitespace umrandet -> Substring pruefen.
    assert "HIGH" in html, html


# ---------------------------------------------------------------------------
# EPSS / CVSS Formatierung + None -> em-dash
# ---------------------------------------------------------------------------


def test_epss_cvss_formatted_when_set(app: Flask) -> None:
    """Gesetzte Werte -> %.3f (EPSS) / %.1f (CVSS)."""
    html = _render(app, findings=[_make_finding(epss_score=0.12345, cvss_v3_score=7.5)])
    assert "0.123" in html, f"EPSS %.3f fehlt: {html}"
    assert "7.5" in html, f"CVSS %.1f fehlt: {html}"


def test_epss_cvss_em_dash_when_none(app: Flask) -> None:
    """EPSS/CVSS None -> em-dash statt Zahl."""
    html = _render(app, findings=[_make_finding(epss_score=None, cvss_v3_score=None)])
    assert _EM_DASH in html, f"em-dash (U+2014) fehlt bei None-Werten: {html!r}"


# ---------------------------------------------------------------------------
# Inline-KI-Bewertung
# ---------------------------------------------------------------------------


def test_inline_ai_reason_rendered_when_set(app: Flask) -> None:
    """risk_band_reason gesetzt -> sd-ai-eyebrow + KI-Bewertung + sd-ai-text + Text."""
    reason = "vendor (redhat) severity HIGH"
    html = _render(app, findings=[_make_finding(risk_band_reason=reason)])
    assert "bucket-finding__body" in html, html
    assert "sd-ai-eyebrow" in html, html
    assert "KI-Bewertung" in html, html
    assert "sd-ai-text" in html, html
    assert reason in html, html


def test_inline_ai_reason_absent_when_none(app: Flask) -> None:
    """risk_band_reason None -> kein bucket-finding__body, kein KI-Bewertung."""
    html = _render(app, findings=[_make_finding(risk_band_reason=None)])
    assert "bucket-finding__body" not in html, html
    assert "KI-Bewertung" not in html, html


def test_inline_ai_reason_absent_when_empty(app: Flask) -> None:
    """risk_band_reason '' (falsy) -> kein Reason-Block."""
    html = _render(app, findings=[_make_finding(risk_band_reason="")])
    assert "bucket-finding__body" not in html, html
    assert "KI-Bewertung" not in html, html


def test_inline_ai_reason_is_html_escaped(app: Flask) -> None:
    """KRITISCH (XSS): risk_band_reason wird autoescaped, kein |safe."""
    html = _render(app, findings=[_make_finding(risk_band_reason="<script>alert(1)</script>")])
    assert "<script>alert(1)</script>" not in html, f"XSS unescaped im Output: {html}"
    assert "&lt;script&gt;" in html, f"Escaped-Version fehlt: {html}"


# ---------------------------------------------------------------------------
# Bulk-Checkbox-Vertrag (bucket_bulk_ack.js)
# ---------------------------------------------------------------------------


def test_checkbox_bulk_contract(app: Flask) -> None:
    """Checkbox traegt data-bulk-finding-id, @change=toggleFinding, @click.stop."""
    html = _render(app, findings=[_make_finding(finding_id=77)])
    assert 'data-bulk-finding-id="77"' in html, html
    assert "toggleFinding(77, $event.target.checked)" in html, html
    assert "@click.stop" in html, html


# ---------------------------------------------------------------------------
# Pager
# ---------------------------------------------------------------------------


def test_pager_present_with_markers(app: Flask) -> None:
    """Pager: bucket-card__footer + data-test bucket-pager/-prev/-next."""
    html = _render(app, findings=[_make_finding()])
    assert "bucket-card__footer" in html, html
    assert 'data-test="bucket-pager"' in html, html
    assert 'data-test="bucket-pager-prev"' in html, html
    assert 'data-test="bucket-pager-next"' in html, html


def test_pager_both_disabled_when_single_page(app: Flask) -> None:
    """total<=per_page -> prev und next sind disabled."""
    html = _render(app, findings=[_make_finding()], total=5, per_page=20, page=1)
    prev_idx = html.find('data-test="bucket-pager-prev"')
    next_idx = html.find('data-test="bucket-pager-next"')
    prev_tag = html[prev_idx : html.find(">", prev_idx)]
    next_tag = html[next_idx : html.find(">", next_idx)]
    assert "disabled" in prev_tag, f"prev muss disabled sein: {prev_tag!r}"
    assert "disabled" in next_tag, f"next muss disabled sein: {next_tag!r}"


def test_pager_prev_active_when_page_gt_1(app: Flask) -> None:
    """page>1 -> prev nicht disabled, enthaelt bucket_fragment-URL mit page-1 + filter_qs."""
    html = _render(
        app,
        findings=[_make_finding()],
        total=60,
        per_page=20,
        page=2,
        filter_qs="risk_band=escalate",
    )
    prev_idx = html.find('data-test="bucket-pager-prev"')
    prev_tag = html[prev_idx : html.find(">", prev_idx)]
    # Aktiver prev-Pfad rendert hx-get; das bare `disabled`-Attribut fehlt
    # (`hx-disabled-elt="this"` ist kein disabled-Zustand).
    assert "hx-get=" in prev_tag, (
        f"prev muss bei page=2 hx-get tragen (nicht disabled): {prev_tag!r}"
    )
    assert prev_tag.replace("hx-disabled-elt", "").find("disabled") == -1, (
        f"prev darf bei page=2 kein bare disabled-Attribut tragen: {prev_tag!r}"
    )
    assert "/findings/bucket" in html, f"bucket_fragment-URL fehlt: {html}"
    assert "page=1" in html, f"page=page-1 (=1) im prev-URL fehlt: {html}"
    assert "risk_band=escalate" in html, f"filter_qs im Pager-URL fehlt: {html}"


# ---------------------------------------------------------------------------
# KEIN DaisyUI / kein quick_copy
# ---------------------------------------------------------------------------


def test_no_daisyui_classes(app: Flask) -> None:
    """Kein DaisyUI-Markup mehr im umgebauten Partial."""
    html = _render(app, findings=[_make_finding(is_kev=True, risk_band_reason="x")])
    for needle in ('class="badge ', " btn-", "table table", "link-hover", "checkbox checkbox"):
        assert needle not in html, f"DaisyUI-Rest gefunden: {needle!r}"


def test_no_quick_copy_clipboard_button(app: Flask) -> None:
    """Kein quick_copy-Clipboard-Button (Marker title='In Zwischenablage kopieren')."""
    html = _render(app, findings=[_make_finding()])
    assert 'title="In Zwischenablage kopieren"' not in html, (
        f"quick_copy-Clipboard-Button darf nicht im Bucket-Body sein: {html}"
    )
