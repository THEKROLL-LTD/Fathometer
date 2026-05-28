"""Pure-Unit Template-Smoke-Tests fuer `findings/index.html` (ADR-0037, TICKET-006 Etappe 3).

Prueft:
  - Ohne Filter (`is_filtered=False`) zeigt das Template den Empty-State,
    KEINE Bucket-Cards, keinen Bulk-Toolbar-Block.
  - Mit Filter + 0 Buckets: "Kein Treffer"-Hinweis sichtbar, keine Cards.
  - Mit Filter + 2 Buckets: Bucket-Counter "2 Gruppen · N Findings",
    `<details>` collapsed (kein `open`), Bulk-Toolbar-Block existiert.
  - Mit Pending-Bucket: Pending-Card am Ende der Liste.
  - Sort-/Dir-Hidden-Inputs sind ENTFERNT (ADR-0037 §(5)).

Render-Pattern: Das Template extended `base_app.html` (volle App-Shell mit
Sidebar etc.). Damit wir nicht die ganze Shell mocken muessen, ueberschreiben
wir `base_app.html` zur Testzeit mit einem Minimal-Stub via `DictLoader` +
`ChoiceLoader`. Der `detail_pane`-Block des `findings/index.html`-Templates
wird im Stub gerendert; alles andere ist leer.

Die View-Context-Variablen sind das echte Etappe-2-Vertragsformat von
`findings.index` (BucketHeader-Dataclass, DashboardFilter usw.).
"""

from __future__ import annotations

from types import SimpleNamespace

from flask import Flask
from jinja2 import ChoiceLoader, DictLoader

from app.schemas.dashboard_filter import DashboardFilter
from app.services.findings_bucket_query import BucketHeader

# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

# Minimal-Stub fuer base_app.html: nur der `detail_pane`-Block wird gerendert.
# So muss der Test nicht die echte App-Shell (Sidebar, Topbar, Footer) mocken.
_BASE_APP_STUB = """<!doctype html>
<html><body>
{% block detail_pane %}{% endblock %}
</body></html>
"""


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _override_base_app(app: Flask) -> None:
    """Schiebt einen Minimal-Stub fuer `base_app.html` vor den File-Loader.

    `ChoiceLoader` versucht jeden Loader in Reihenfolge; der `DictLoader`
    deckt `base_app.html` ab, alle anderen Templates kommen weiter vom
    File-Loader. Wir muessen ausserdem den Template-Cache leeren, sonst
    bedient jinja den File-basierten Loader-Cache.
    """
    original = app.jinja_env.loader
    assert original is not None, "App muss einen Loader haben"
    app.jinja_env.loader = ChoiceLoader([DictLoader({"base_app.html": _BASE_APP_STUB}), original])
    app.jinja_env.cache.clear() if app.jinja_env.cache else None


def _render_findings_index(
    app: Flask,
    *,
    is_filtered: bool,
    buckets: list[BucketHeader],
    pending_bucket: BucketHeader | None,
    filt: DashboardFilter | None = None,
    total_findings: int = 0,
    visible_servers: int = 0,
    filter_qs: str = "",
) -> str:
    """Rendert das Index-Template mit gestubbter base_app.html-Shell."""
    _override_base_app(app)
    if filt is None:
        filt = DashboardFilter()
    total_buckets = len(buckets) + (1 if pending_bucket is not None else 0)
    total_findings_in_buckets = sum(b.finding_count for b in buckets) + (
        pending_bucket.finding_count if pending_bucket is not None else 0
    )

    # Available-Tags/Groups: leere Listen reichen, das Template iteriert nur.
    ctx = {
        "filt": filt,
        "view_filter": filt,
        "buckets": buckets,
        "pending_bucket": pending_bucket,
        "total_buckets": total_buckets,
        "total_findings_in_buckets": total_findings_in_buckets,
        "filter_qs": filter_qs,
        "is_filtered": is_filtered,
        "total_findings": total_findings,
        "visible_servers": visible_servers,
        "available_tags": [],
        "available_application_groups": [],
        "bulk_form": SimpleNamespace(),
        "csrf_form": SimpleNamespace(),
    }

    with app.test_request_context("/findings"):
        template = app.jinja_env.get_template("findings/index.html")
        return template.render(**ctx)


# ---------------------------------------------------------------------------
# Empty-State (kein Filter)
# ---------------------------------------------------------------------------


def test_index_empty_state_when_not_filtered(app: Flask) -> None:
    """Ohne Filter: Empty-State sichtbar, keine Bucket-Cards, keine Toolbar."""
    html = _render_findings_index(
        app,
        is_filtered=False,
        buckets=[],
        pending_bucket=None,
        total_findings=1234,
        visible_servers=5,
    )

    assert 'data-test="findings-empty-state"' in html, (
        "Empty-State-Marker fehlt bei is_filtered=False"
    )
    assert "1234" in html, "Empty-State zeigt total_findings"
    # Keine Bucket-Section in diesem Pfad.
    assert 'data-test="findings-buckets-section"' not in html, (
        "Bucket-Section darf bei is_filtered=False NICHT erscheinen"
    )
    # Kein Bulk-Toolbar.
    assert 'data-test="bucket-bulk-toolbar"' not in html, (
        "Bulk-Toolbar darf bei is_filtered=False NICHT erscheinen"
    )
    # Counter darf nicht erscheinen (kein Bucket-Result).
    assert 'data-test="findings-bucket-counter"' not in html, (
        "Counter darf ohne Filter nicht erscheinen"
    )


# ---------------------------------------------------------------------------
# Filter aktiv, aber 0 Buckets
# ---------------------------------------------------------------------------


def test_index_zero_buckets_shows_no_match_hint(app: Flask) -> None:
    """Mit Filter, aber 0 Buckets: 'Kein Treffer fuer diesen Filter.'-Hinweis."""
    filt = DashboardFilter(
        status="acknowledged"
    )  # is_filtered wird durch View bestimmt; hier explizit.
    html = _render_findings_index(
        app,
        is_filtered=True,
        buckets=[],
        pending_bucket=None,
        filt=filt,
    )

    assert "Kein Treffer" in html, f"Empty-Match-Text fehlt: {html[:600]}"
    # Bucket-Section bleibt weg in diesem Pfad.
    assert 'data-test="findings-buckets-section"' not in html


# ---------------------------------------------------------------------------
# Filter aktiv mit 2 Buckets
# ---------------------------------------------------------------------------


def test_index_two_buckets_render_counter_and_cards(app: Flask) -> None:
    """Mit Filter + 2 Buckets: Counter 'X Gruppen · Y Findings' + Cards."""
    buckets = [
        BucketHeader(
            server_id=1,
            group_id=10,
            server_name="srv-a",
            group_label="nginx",
            risk_band="escalate",
            finding_count=3,
        ),
        BucketHeader(
            server_id=2,
            group_id=11,
            server_name="srv-b",
            group_label="postgres",
            risk_band="act",
            finding_count=5,
        ),
    ]
    html = _render_findings_index(
        app,
        is_filtered=True,
        buckets=buckets,
        pending_bucket=None,
        filter_qs="risk_band=escalate",
    )

    # Counter mit Plural-Suffix (Werte sind im Design in <b> gewrappt).
    assert 'data-test="findings-bucket-counter"' in html, "Counter-Marker fehlt"
    assert "<b>2</b>" in html and "Gruppen" in html, f"'2 Gruppen' nicht im Counter: {html[:1000]}"
    assert "<b>8</b>" in html and "Findings" in html, (
        f"'8 Findings' (Summe) nicht im Counter: {html[:1000]}"
    )

    # Bucket-Cards.
    assert 'data-test="bucket-card-1-10"' in html, "Erste Bucket-Card fehlt"
    assert 'data-test="bucket-card-2-11"' in html, "Zweite Bucket-Card fehlt"

    # Bulk-Section sichtbar.
    assert 'data-test="findings-buckets-section"' in html
    assert 'data-test="bucket-bulk-toolbar"' in html, "Bulk-Toolbar-Block fehlt"


def test_index_buckets_render_collapsed_details(app: Flask) -> None:
    """Bucket-Cards rendern collapsed `<details>` (kein `open`-Attribut)."""
    bucket = BucketHeader(
        server_id=42,
        group_id=7,
        server_name="srv-42",
        group_label="grp",
        risk_band="escalate",
        finding_count=1,
    )
    html = _render_findings_index(
        app,
        is_filtered=True,
        buckets=[bucket],
        pending_bucket=None,
    )

    # Suche das spezifische details-Tag der Bucket-Card.
    marker = 'data-test="bucket-card-42-7"'
    idx = html.find(marker)
    assert idx != -1, "Bucket-Card-Marker nicht gefunden"
    # Das umschliessende <details ...>-Tag muss ohne `open`-Attribut sein.
    details_start = html.rfind("<details", 0, idx)
    assert details_start != -1, "<details vor Bucket-Marker erwartet"
    details_end = html.find(">", details_start)
    details_tag = html[details_start : details_end + 1]
    assert " open" not in details_tag, f"<details muss collapsed (kein open) sein: {details_tag!r}"


# ---------------------------------------------------------------------------
# Pending-Bucket
# ---------------------------------------------------------------------------


def test_index_pending_bucket_renders_after_buckets(app: Flask) -> None:
    """Pending-Card erscheint NACH den regulaeren Buckets in der Liste."""
    bucket = BucketHeader(
        server_id=1,
        group_id=10,
        server_name="srv-a",
        group_label="nginx",
        risk_band="act",
        finding_count=2,
    )
    pending = BucketHeader(
        server_id=0,
        group_id=0,
        server_name="",
        group_label="(ohne Group)",
        risk_band="pending",
        finding_count=4,
    )
    html = _render_findings_index(
        app,
        is_filtered=True,
        buckets=[bucket],
        pending_bucket=pending,
    )

    assert 'data-test="bucket-card-1-10"' in html, "Regulaere Card erwartet"
    assert 'data-test="pending-bucket-card"' in html, "Pending-Card fehlt"

    pos_bucket = html.find('data-test="bucket-card-1-10"')
    pos_pending = html.find('data-test="pending-bucket-card"')
    assert pos_bucket < pos_pending, (
        "Pending-Card muss NACH den regulaeren Bucket-Cards stehen "
        f"(bucket={pos_bucket}, pending={pos_pending})"
    )

    # Counter zaehlt Pending mit (1 + 1 = 2 Gruppen, 2 + 4 = 6 Findings).
    assert "<b>2</b>" in html and "Gruppen" in html, "Counter muss Pending mitzaehlen"
    assert "<b>6</b>" in html and "Findings" in html, "Counter-Summe inkl. Pending erwartet"


# ---------------------------------------------------------------------------
# Sort-/Dir-Hidden-Inputs sind weg
# ---------------------------------------------------------------------------


def test_index_has_no_sort_or_dir_hidden_inputs(app: Flask) -> None:
    """Sort/Dir-Hidden-Inputs entfallen (ADR-0037 §(5))."""
    html = _render_findings_index(
        app,
        is_filtered=True,
        buckets=[
            BucketHeader(
                server_id=1,
                group_id=2,
                server_name="srv",
                group_label="grp",
                risk_band="escalate",
                finding_count=1,
            ),
        ],
        pending_bucket=None,
    )

    assert 'name="sort"' not in html, (
        "Sort-Hidden-Input ist verboten in der Bucket-View (ADR-0037 §(5))"
    )
    assert 'name="dir"' not in html, (
        "Dir-Hidden-Input ist verboten in der Bucket-View (ADR-0037 §(5))"
    )


# ---------------------------------------------------------------------------
# Bulk-Toolbar + Modal-Hooks
# ---------------------------------------------------------------------------


def test_index_bucket_bulk_toolbar_present(app: Flask) -> None:
    """Bulk-Toolbar mit Counter und Clear-Button existiert in der Bucket-Section."""
    html = _render_findings_index(
        app,
        is_filtered=True,
        buckets=[
            BucketHeader(
                server_id=1,
                group_id=2,
                server_name="srv",
                group_label="grp",
                risk_band="escalate",
                finding_count=1,
            ),
        ],
        pending_bucket=None,
    )

    assert 'data-test="bucket-bulk-toolbar"' in html, "Bulk-Toolbar fehlt"
    assert 'data-test="bucket-bulk-bar"' in html, "Bulk-Counter-Bar fehlt"
    assert 'data-test="bucket-bulk-clear"' in html, "Bulk-Clear-Button fehlt"
    # Modal-Hook.
    assert 'data-test="bucket-bulk-ack-modal"' in html, "Bucket-Bulk-Ack-Modal fehlt"
    assert 'x-data="bucketBulkSelection()"' in html, (
        "Alpine-Scope `bucketBulkSelection()` fehlt auf der Bucket-Section"
    )


# ---------------------------------------------------------------------------
# CSV-Export-Link bleibt
# ---------------------------------------------------------------------------


def test_index_csv_export_link_still_present(app: Flask) -> None:
    """CSV-Export-Link bleibt unveraendert in der Filter-Bar."""
    html = _render_findings_index(
        app,
        is_filtered=False,
        buckets=[],
        pending_bucket=None,
    )

    assert 'data-test="findings-csv-export"' in html, "CSV-Export-Link fehlt"
    assert "/findings/export.csv" in html, "CSV-Export-URL fehlt"
