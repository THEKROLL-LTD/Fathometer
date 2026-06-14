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
from typing import Any

from flask import Flask

from app.forms import AcknowledgeForm, CSRFOnlyForm, NoteForm, ReopenForm
from app.models import FindingStatus

# em-dash (U+2014) — Platzhalter fuer None-Werte in EPSS/CVSS/Severity.
_EM_DASH = "—"


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    finding_id: int = 42,
    identifier_key: str = "CVE-2024-1234",
    is_kev: bool = False,
    title: str | None = "OpenSSL Buffer Overflow",
    package_name: str | None = "openssl",
    installed_version: str | None = "3.0.2-0ubuntu1.12",
    fixed_version: str | None = "3.0.2-0ubuntu1.13",
    epss_score: float | None = 0.12345,
    cvss_v3_score: float | None = 7.5,
    severity: str | None = "high",
    first_seen_at: datetime | None = None,
    status: FindingStatus = FindingStatus.OPEN,
    description: str | None = None,
    primary_url: str | None = None,
    references: list[str] | None = None,
    notes: list[Any] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=finding_id,
        identifier_key=identifier_key,
        is_kev=is_kev,
        title=title,
        package_name=package_name,
        installed_version=installed_version,
        fixed_version=fixed_version,
        epss_score=epss_score,
        cvss_v3_score=cvss_v3_score,
        severity=severity,
        first_seen_at=first_seen_at or datetime(2024, 5, 1, 12, 0, tzinfo=UTC),
        status=status,
        description=description,
        primary_url=primary_url,
        references=references,
        notes=notes if notes is not None else [],
    )


def _lane_group(
    *,
    fix_lane: str = "patch",
    risk_band: str = "pending",
    risk_band_reason: str | None = None,
    findings: list[SimpleNamespace],
) -> SimpleNamespace:
    """Baut einen `BucketLaneGroup`-kompatiblen Lane-Eintrag (TICKET-016 /
    ADR-0065). Jinja greift per Attribut zu — SimpleNamespace genuegt."""
    return SimpleNamespace(
        fix_lane=fix_lane,
        risk_band=risk_band,
        risk_band_reason=risk_band_reason,
        findings=findings,
    )


def _render(
    app: Flask,
    *,
    findings: list[SimpleNamespace],
    lane_groups: list[SimpleNamespace] | None = None,
    total: int | None = None,
    page: int = 1,
    per_page: int = 20,
    server_id: int = 42,
    group_id: int = 7,
    filter_qs: str = "",
) -> str:
    if total is None:
        total = len(findings)
    if lane_groups is None:
        # Default: alle Findings in einer einzigen patch-Lane ohne Reason-Header
        # (deckt die Zeilen-/Pager-/Bulk-Vertraege ab, ohne Lane-Logik zu testen).
        lane_groups = [_lane_group(findings=findings)] if findings else []
    with app.test_request_context("/findings"):
        template = app.jinja_env.get_template("_partials/bucket_findings_table.html")
        return template.render(
            findings=findings,
            lane_groups=lane_groups,
            total=total,
            page=page,
            per_page=per_page,
            server_id=server_id,
            group_id=group_id,
            filter_qs=filter_qs,
            note_form=NoteForm(),
            csrf_form=CSRFOnlyForm(),
            ack_form=AcknowledgeForm(),
            reopen_form=ReopenForm(),
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
    for col in ("CVE / Title", "Package", "EPSS", "CVSS", "Severity", "First seen"):
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
# Keine Per-Finding-AI-Box (TICKET-012)
# ---------------------------------------------------------------------------


def test_no_inline_ai_assessment_box(app: Flask) -> None:
    """TICKET-012: der aufgeklappte Body rendert KEINE Per-Finding-AI-Box mehr
    (weder Reason noch Pending-Fallback). Das Assessment lebt auf der
    Application-Group-Card."""
    html = _render(app, findings=[_make_finding()])
    assert "sd-finding__body" in html, html
    assert "AI assessment" not in html, html
    assert "sd-ai-text--pending" not in html, html
    assert "finding-reason-pending-" not in html, html


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


def test_no_daisyui_classes_in_summary(app: Flask) -> None:
    """Kein DaisyUI-Markup in der Bucket-Summary-Row.

    Block AA (ADR-0041): der gemeinsame Inline-Body includet das beibehaltene
    Ack-/Reopen-Modal + Notes-Thread, die noch Legacy-Shim-Klassen tragen
    ("migrate, not refactor"). Geprueft wird daher nur der Summary-Teil bis
    zum Body-Start.
    """
    html = _render(app, findings=[_make_finding(is_kev=True)])
    summary = html[: html.index('<div class="sd-finding__body"')]
    for needle in ('class="badge ', " btn-", "table table", "link-hover", "checkbox checkbox"):
        assert needle not in summary, f"DaisyUI-Rest in Summary gefunden: {needle!r}"


def test_no_quick_copy_clipboard_button(app: Flask) -> None:
    """Kein quick_copy-Clipboard-Button (Marker title='In Zwischenablage kopieren')."""
    html = _render(app, findings=[_make_finding()])
    assert 'title="In Zwischenablage kopieren"' not in html, (
        f"quick_copy-Clipboard-Button darf nicht im Bucket-Body sein: {html}"
    )


# ---------------------------------------------------------------------------
# Lane-Reason-Header (TICKET-016 / ADR-0065 Strategie a)
# ---------------------------------------------------------------------------


def test_single_lane_header_renders_tag_but_no_band_badge(app: Flask) -> None:
    """Single-Lane-Bucket: Lane-Tag (Patch/No patch) rendert, aber KEIN
    Band-Badge — das Band steht schon in der Bucket-Card-Row (sonst doppelt)."""
    f = _make_finding(finding_id=1)
    lanes = [_lane_group(fix_lane="patch", risk_band="act", findings=[f])]
    html = _render(app, findings=[f], lane_groups=lanes, group_id=7)
    assert 'data-test="bucket-lane-7-patch"' in html, html
    assert 'data-test="bucket-lane-label-7-patch"' in html
    assert "Patch" in html
    # Band-Badge unterdrueckt bei einer einzigen Lane.
    assert 'data-test="bucket-lane-band-7-patch"' not in html, (
        f"Single-Lane darf kein doppeltes Band-Badge zeigen:\n{html}"
    )


def test_lane_header_renders_above_column_header(app: Flask) -> None:
    """Der Lane-Kontext-Header (Tag + AI assessment) steht UEBER dem
    Spaltenkopf (CVE/Title …), nicht zwischen Spaltenkopf und Zeile 1."""
    f = _make_finding(finding_id=1)
    lanes = [
        _lane_group(fix_lane="patch", risk_band="act", risk_band_reason="why act", findings=[f])
    ]
    html = _render(app, findings=[f], lane_groups=lanes, group_id=7)
    lane_idx = html.index('data-test="bucket-lane-label-7-patch"')
    reason_idx = html.index('data-test="bucket-lane-reason-7-patch"')
    head_idx = html.index('class="bucket-findings-head"')
    assert lane_idx < reason_idx < head_idx, (
        f"Lane-Tag + AI assessment muessen ueber dem Spaltenkopf stehen:\n{html}"
    )


def test_lane_header_reason_uses_truncation_macro_for_monitor(app: Flask) -> None:
    """TD-020: monitor-Lane zeigt ihre Reason (vorher unsichtbar). Reason
    rendert ueber das reason_block-Macro (AI-assessment-Eyebrow + Text)."""
    f = _make_finding(finding_id=1)
    reason = "tailscaled MIME-decode flaw unlikely to be triggered by WireGuard."
    lanes = [
        _lane_group(fix_lane="mitigate", risk_band="monitor", risk_band_reason=reason, findings=[f])
    ]
    html = _render(app, findings=[f], lane_groups=lanes, group_id=7)
    assert 'data-test="bucket-lane-reason-7-mitigate"' in html, html
    assert "AI assessment" in html
    assert reason in html
    assert "No patch" in html


def test_lane_header_omitted_when_no_reason(app: Flask) -> None:
    """Lane ohne Reason -> Lane-Tag rendert, aber kein Reason-Block."""
    f = _make_finding(finding_id=1)
    lanes = [
        _lane_group(fix_lane="patch", risk_band="pending", risk_band_reason=None, findings=[f])
    ]
    html = _render(app, findings=[f], lane_groups=lanes, group_id=7)
    assert 'data-test="bucket-lane-label-7-patch"' in html
    assert 'data-test="bucket-lane-reason-7-patch"' not in html
    assert "AI assessment" not in html


def test_two_lanes_render_two_headers_with_band_badges(app: Flask) -> None:
    """Bucket mit patch + mitigate -> zwei Lane-Header, je eigene Findings UND
    je eigenes Band-Badge (bei >1 Lane stehen die Lane-Baender NICHT in der
    Bucket-Row, sind also nicht doppelt)."""
    fp = _make_finding(finding_id=1, identifier_key="CVE-PATCH")
    fm = _make_finding(finding_id=2, identifier_key="CVE-MIT")
    lanes = [
        _lane_group(fix_lane="patch", risk_band="act", risk_band_reason="r-patch", findings=[fp]),
        _lane_group(
            fix_lane="mitigate", risk_band="escalate", risk_band_reason="r-mit", findings=[fm]
        ),
    ]
    html = _render(app, findings=[fp, fm], lane_groups=lanes, group_id=7)
    assert 'data-test="bucket-lane-7-patch"' in html
    assert 'data-test="bucket-lane-7-mitigate"' in html
    # Bei >1 Lane werden die Band-Badges gezeigt.
    assert 'data-test="bucket-lane-band-7-patch"' in html
    assert 'data-test="bucket-lane-band-7-mitigate"' in html
    assert "ACT" in html
    assert "ESCALATE" in html
    assert "r-patch" in html
    assert "r-mit" in html
    assert "CVE-PATCH" in html
    assert "CVE-MIT" in html


def test_lane_reason_higher_truncation_limit_on_findings_page(app: Flask) -> None:
    """Findings-Page nutzt die volle Bucket-Breite -> grosszuegigeres Limit
    (~520 Zeichen): eine ~300-Zeichen-Reason rendert ganz OHNE 'Show all',
    eine ~700-Zeichen-Reason bekommt den Toggle."""
    f = _make_finding(finding_id=1)

    mid = "word " * 60  # ~300 Zeichen -> unter dem 520-Limit
    html_mid = _render(
        app,
        findings=[f],
        lane_groups=[_lane_group(risk_band_reason=mid, findings=[f])],
        group_id=7,
    )
    assert "reason-block__toggle" not in html_mid, (
        f"~300-Zeichen-Reason darf auf der Findings-Page keinen Toggle haben:\n{html_mid}"
    )

    long = "word " * 160  # ~800 Zeichen -> ueber dem 520-Limit
    html_long = _render(
        app,
        findings=[f],
        lane_groups=[_lane_group(risk_band_reason=long, findings=[f])],
        group_id=7,
    )
    assert "reason-block__toggle" in html_long, (
        f"~800-Zeichen-Reason muss den 'Show all'-Toggle zeigen:\n{html_long[:400]}"
    )
    assert "Show all" in html_long


def test_lane_reason_long_text_xss_escaped(app: Flask) -> None:
    """Lane-Reason ist LLM-Output -> autoescaped, kein |safe-Leak."""
    f = _make_finding(finding_id=1)
    payload = "<script>alert(9)</script> " + "filler " * 30
    lanes = [_lane_group(fix_lane="patch", risk_band="act", risk_band_reason=payload, findings=[f])]
    html = _render(app, findings=[f], lane_groups=lanes, group_id=7)
    assert "<script>alert(9)</script>" not in html, html
    assert "&lt;script&gt;" in html
