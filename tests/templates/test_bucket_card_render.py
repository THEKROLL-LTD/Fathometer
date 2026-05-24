"""Pure-Unit Template-Smoke-Tests fuer Bucket-Cards (ADR-0037, TICKET-006 Etappe 3).

Prueft:
  - `_partials/bucket_card.html` Render-Vertrag (Risk-Pille, Count-Badge,
    HTMX-URL, Server-Link, Group-Label, Bulk-Checkbox-data-Attribute).
  - `_partials/pending_bucket_card.html` Render-Vertrag (cross-server-Label,
    Pending-Risk-Band, Body-URL auf `findings.pending_fragment`).
  - Initial-Markup ist collapsed (kein `open`-Attribut).
  - Lazy-Slot-URL enthaelt `filter_qs` falls gesetzt.

Render-Pattern: Flask-App mit test_request_context + jinja_env.get_template().
BucketHeader wird direkt aus dem Service-Modul importiert — keine Mock-
Datenklasse, damit der Test bricht wenn Etappe 1 die Felder umbenennt.
"""

from __future__ import annotations

from flask import Flask

from app.services.findings_bucket_query import BucketHeader

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _render_bucket_card(app: Flask, bucket: BucketHeader, filter_qs: str = "") -> str:
    with app.test_request_context("/"):
        template = app.jinja_env.get_template("_partials/bucket_card.html")
        return template.render(bucket=bucket, filter_qs=filter_qs)


def _render_pending_bucket_card(app: Flask, bucket: BucketHeader, filter_qs: str = "") -> str:
    with app.test_request_context("/"):
        template = app.jinja_env.get_template("_partials/pending_bucket_card.html")
        return template.render(bucket=bucket, filter_qs=filter_qs)


# ---------------------------------------------------------------------------
# bucket_card.html
# ---------------------------------------------------------------------------


def test_bucket_card_renders_collapsed_details(app: Flask) -> None:
    """Bucket-Card rendert `<details>` OHNE `open`-Attribut (collapsed default)."""
    bucket = BucketHeader(
        server_id=42,
        group_id=7,
        server_name="srv-prod-01",
        group_label="nginx",
        risk_band="escalate",
        finding_count=12,
    )

    html = _render_bucket_card(app, bucket)

    assert "<details" in html, "Bucket-Card muss <details> rendern"
    details_start = html.find("<details")
    details_end = html.find(">", details_start)
    details_tag = html[details_start : details_end + 1]
    assert " open" not in details_tag, (
        f"`<details>` darf nicht initial open sein (collapsed default): {details_tag!r}"
    )


def test_bucket_card_renders_risk_band_pill_and_count(app: Flask) -> None:
    """Risk-Pille mit Band-Klasse + Count-Badge erscheinen im Header."""
    bucket = BucketHeader(
        server_id=1,
        group_id=2,
        server_name="srv-a",
        group_label="postgres",
        risk_band="escalate",
        finding_count=3,
    )

    html = _render_bucket_card(app, bucket)

    # Risk-Pille mit dem `escalate`-Marker (siehe risk_band_pill.html).
    assert 'data-test="risk-band-pill-escalate"' in html, (
        f"Risk-Pille fuer 'escalate' fehlt: {html[:600]}"
    )
    # Count-Badge.
    assert 'data-test="bucket-finding-count"' in html, "Count-Badge-Marker fehlt"
    assert "3 findings" in html, f"Count-Text '3 findings' fehlt: {html}"


def test_bucket_card_singular_finding_word(app: Flask) -> None:
    """Bei finding_count==1 wird die Einzahl gerendert."""
    bucket = BucketHeader(
        server_id=1,
        group_id=2,
        server_name="srv-a",
        group_label="redis",
        risk_band="act",
        finding_count=1,
    )

    html = _render_bucket_card(app, bucket)

    # Singular "1 finding" muss erscheinen — Whitespace zwischen Text und
    # schliessendem `</span>` kann variieren (Jinja-Indent), daher Substring-Check.
    assert "1 finding" in html, f"Singular 'finding' bei count=1 erwartet: {html}"
    assert "1 findings" not in html, "Plural darf bei count=1 nicht auftauchen"
    # Zusatz-Sanity: der Count-Badge enthaelt genau das Singular-Token.
    badge_start = html.find('data-test="bucket-finding-count"')
    badge_end = html.find("</span>", badge_start)
    badge_text = html[badge_start:badge_end]
    assert " finding" in badge_text and " findings" not in badge_text, (
        f"Count-Badge muss Singular 'finding' fuehren: {badge_text!r}"
    )


def test_bucket_card_lazy_slot_url_includes_filter_qs(app: Flask) -> None:
    """Der HTMX-Lazy-Slot enthaelt die `bucket_fragment`-URL plus filter_qs."""
    bucket = BucketHeader(
        server_id=42,
        group_id=7,
        server_name="srv-x",
        group_label="grp-x",
        risk_band="mitigate",
        finding_count=5,
    )

    html = _render_bucket_card(app, bucket, filter_qs="risk_band=mitigate&status=open")

    assert 'data-test="bucket-findings-lazy-slot"' in html, "Lazy-Slot-Marker fehlt"
    # URL: server_id, group_id, page=1, plus angehaengter filter_qs.
    assert "server_id=42" in html, f"server_id im URL fehlt: {html}"
    assert "group_id=7" in html, f"group_id im URL fehlt: {html}"
    assert "page=1" in html, "page=1 im URL fehlt"
    assert "risk_band=mitigate" in html, f"filter_qs (risk_band) im URL fehlt: {html}"
    assert "status=open" in html, "filter_qs (status) im URL fehlt"
    # Trigger: `toggle once from:closest details`.
    assert "toggle once from:closest details" in html, "HTMX-Trigger 'toggle once' fehlt"


def test_bucket_card_lazy_slot_url_without_filter_qs(app: Flask) -> None:
    """Wenn filter_qs leer ist, haengt kein '&' am URL-Ende."""
    bucket = BucketHeader(
        server_id=1,
        group_id=2,
        server_name="srv-a",
        group_label="grp-y",
        risk_band="pending",
        finding_count=2,
    )

    html = _render_bucket_card(app, bucket, filter_qs="")

    # `page=1` ohne folgendes `&` (Filter ist leer).
    assert 'page=1"' in html or "page=1'" in html, f"URL muss auf page=1 ohne Anhang enden: {html}"


def test_bucket_card_checkbox_has_data_attributes(app: Flask) -> None:
    """Bucket-Checkbox traegt data-bucket-server/-group/-filter/-count."""
    bucket = BucketHeader(
        server_id=11,
        group_id=22,
        server_name="srv-x",
        group_label="grp",
        risk_band="noise",
        finding_count=9,
    )

    html = _render_bucket_card(app, bucket, filter_qs="q=foo")

    assert 'data-bucket-server="11"' in html, "data-bucket-server fehlt"
    assert 'data-bucket-group="22"' in html, "data-bucket-group fehlt"
    assert 'data-bucket-filter="q=foo"' in html, "data-bucket-filter fehlt"
    assert 'data-bucket-count="9"' in html, "data-bucket-count fehlt"
    # Alpine-Handler liest aus dataset.* (KEINE String-Interpolation).
    assert "$event.target.dataset.bucketServer" in html, (
        "Alpine-Handler muss dataset.bucketServer lesen (sicherer Pfad)"
    )


def test_bucket_card_data_test_marker_uses_ids(app: Flask) -> None:
    """data-test enthaelt server_id und group_id im Marker."""
    bucket = BucketHeader(
        server_id=42,
        group_id=7,
        server_name="srv",
        group_label="grp",
        risk_band="act",
        finding_count=4,
    )

    html = _render_bucket_card(app, bucket)

    assert 'data-test="bucket-card-42-7"' in html, (
        f"data-test-Marker mit ids 42/7 erwartet: {html[:400]}"
    )


# ---------------------------------------------------------------------------
# pending_bucket_card.html
# ---------------------------------------------------------------------------


def test_pending_bucket_card_renders_cross_server_label(app: Flask) -> None:
    """Pending-Card zeigt 'cross-server' statt eines Server-Namens."""
    bucket = BucketHeader(
        server_id=0,
        group_id=0,
        server_name="",
        group_label="(ohne Group)",
        risk_band="pending",
        finding_count=42,
    )

    html = _render_pending_bucket_card(app, bucket)

    assert 'data-test="pending-bucket-cross-server"' in html, "cross-server-Marker fehlt"
    assert "cross-server" in html, f"'cross-server'-Text fehlt: {html[:600]}"
    assert 'data-test="pending-bucket-group-label"' in html, "Group-Label-Marker fehlt"
    assert "(ohne Group)" in html, "Group-Label '(ohne Group)' fehlt"


def test_pending_bucket_card_body_url_targets_pending_fragment(app: Flask) -> None:
    """Lazy-Slot der Pending-Card zeigt auf `findings.pending_fragment`."""
    bucket = BucketHeader(
        server_id=0,
        group_id=0,
        server_name="",
        group_label="(ohne Group)",
        risk_band="pending",
        finding_count=10,
    )

    html = _render_pending_bucket_card(app, bucket, filter_qs="q=baz")

    assert 'data-test="pending-bucket-findings-lazy-slot"' in html, "Pending-Lazy-Slot-Marker fehlt"
    # URL muss auf /findings/pending verweisen.
    assert "/findings/pending" in html, f"Pending-Fragment-URL fehlt: {html[:600]}"
    assert "page=1" in html, "page=1 in Pending-URL fehlt"
    assert "q=baz" in html, "filter_qs in Pending-URL fehlt"


def test_pending_bucket_card_uses_pending_risk_pill(app: Flask) -> None:
    """Pending-Card rendert IMMER die `pending`-Risk-Pille (auch wenn
    bucket.risk_band davon abweichen sollte)."""
    bucket = BucketHeader(
        server_id=0,
        group_id=0,
        server_name="",
        group_label="(ohne Group)",
        # Template ignoriert das absichtlich und nutzt 'pending' fix.
        risk_band="escalate",
        finding_count=5,
    )

    html = _render_pending_bucket_card(app, bucket)

    assert 'data-test="risk-band-pill-pending"' in html, (
        f"Pending-Card muss IMMER pending-Pille zeigen: {html[:600]}"
    )
    assert 'data-test="risk-band-pill-escalate"' not in html, (
        "Pending-Card darf KEINE escalate-Pille rendern (auch wenn das Bucket-Feld so waere)"
    )


def test_pending_bucket_card_checkbox_uses_zero_ids(app: Flask) -> None:
    """Pending-Checkbox hat data-bucket-server=0 und data-bucket-group=0."""
    bucket = BucketHeader(
        server_id=0,
        group_id=0,
        server_name="",
        group_label="(ohne Group)",
        risk_band="pending",
        finding_count=3,
    )

    html = _render_pending_bucket_card(app, bucket, filter_qs="status=open")

    assert 'data-bucket-server="0"' in html, "data-bucket-server=0 fehlt"
    assert 'data-bucket-group="0"' in html, "data-bucket-group=0 fehlt"
    assert 'data-bucket-filter="status=open"' in html, (
        "Pending-Card muss data-bucket-filter mit dem aktuellen QS tragen"
    )
