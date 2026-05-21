"""Lint fuer die Tailwind-CDN-Safelist in `app/templates/base_app.html`.

Hintergrund (TD-010): das Tailwind-CDN-Skript (`cdn.tailwindcss.com`) ist
ein im Browser laufender JIT-Compiler, der beim Page-Load den DOM scannt
und nur fuer dort gefundene Klassen CSS-Regeln generiert. Der eingebaute
MutationObserver soll dynamisch eingespielte Subtrees (HTMX-Swaps) erfassen
— in der Praxis bricht das bei `innerHTML`/`outerHTML`-Replacement fuer
Klassen, die noch nie im DOM waren (beobachtet 2026-05-21: `h-full` fehlt
nach Sidebar-Klick auf /servers/<id>, KPI-Sparkline-SVGs faellen auf
intrinsische 300 px Default-Hoehe).

Dieser Test prueft drei Invarianten:

1. Die Safelist in `base_app.html` ist syntaktisch parsebar und nicht leer.
2. Jeder Safelist-Eintrag wird in mindestens einem `*.html`-Template
   tatsaechlich verwendet (kein Drift durch stale Eintraege).
3. Alle als "high-risk" markierten Klassen (vertikale Layout-Klassen, die
   im Dashboard-Default-Render selten sind aber kritisch fuer Container-
   Hoehen auf Sub-Pages), die irgendwo in Templates benutzt werden, sind
   in der Safelist eingetragen.

Wenn ein Frontend-Implementer eine neue `h-full`/`h-screen`/`h-fit`-Klasse
in einem HTMX-Subtree-Template ergaenzt, schlaegt Test 3 fehl — Pflicht
ist dann: Safelist-Eintrag nachziehen ODER die Klasse durch eine bereits
im Initial-DOM bekannte Alternative ersetzen.

Langfristig (TD-010): Tailwind-CDN raus, Vite-Build mit Pre-Scan aller
Templates. Damit ist diese Safelist obsolet.
"""

from __future__ import annotations

import re
from pathlib import Path

# Templates-Wurzel relativ zur Repo-Wurzel.
_TEMPLATES_ROOT = Path(__file__).parent.parent.parent / "app" / "templates"
_BASE_APP = _TEMPLATES_ROOT / "base_app.html"

# Klassen-Patterns mit erhoehtem CDN-JIT-Race-Risiko:
# - Vertikale Layout-Klassen: im Dashboard-Default-Render selten benutzt,
#   aber auf Sub-Pages fuer Chart-/Pane-Hoehen kritisch.
# - Wenn Tailwind-CSS dafuer beim initialen JIT-Bootstrap fehlt, fallen
#   Container auf intrinsische Browser-Defaults.
_HIGH_RISK_CLASSES: tuple[str, ...] = (
    "h-full",
    "h-screen",
    "h-fit",
    "min-h-full",
    "min-h-screen",
)


# Templates, die als "Initial-DOM" gezaehlt werden — Klassen, die hier
# auftauchen, sieht der CDN-JIT-Scan beim Page-Load und generiert dafuer
# CSS. Kein Race moeglich.
#
# Pflicht-Lektuere: `base_app.html` (App-Shell fuer eingeloggte Routen),
# `base.html` (Pre-Login-Shell). Plus alles, was diese Shells _direkt_
# beim Initial-Render fuer JEDE Login-Route inkludieren:
# - `layout/_header.html` (Top-Bar, immer da)
# - `layout/_profile_dropdown.html` (im Header inkludiert)
# - `sidebar/_search.html` + `_server_list.html` + `_server_row.html`
# - `dashboard/index.html` + `_detail_pane.html` + `_kpi_cards.html`
#   plus deren Partials (`_partials/risk_band_pill.html`, etc.)
#
# Pragmatisch: wir whitelisten die Top-Level-Shells und Layout-/Sidebar-
# Verzeichnisse. Klassen, die ausschliesslich dort vorkommen, sind sicher.
_INITIAL_DOM_TEMPLATES: tuple[str, ...] = (
    "base.html",
    "base_app.html",
    "login.html",
    "layout/",
    "sidebar/",
    "dashboard/",
    # `_partials/` ist gemischt: einige Partials (Risk-Pill, Action-Card)
    # werden auf dem Dashboard inkludiert (Initial-DOM), andere
    # (group_findings_table, application_group_card) sind HTMX-only.
    # Pragmatisch zaehlen wir den ganzen Ordner als Initial-DOM — die im
    # Dashboard-Pfad gelesenen Partials decken die Klassen auch fuer die
    # Subtree-Partials ab (CDN-JIT generiert das CSS einmal pro Klasse).
    # Wenn ein zukuenftiges Partial _nur_ via HTMX rendert und eine neue
    # arbitrary-value-Klasse einfuehrt, faengt der Test sie nicht — dann
    # Eintrag manuell in Safelist nachziehen.
    "_partials/",
    "_empty/",
    "errors/",
)


def _extract_safelist() -> set[str]:
    """Liest das `safelist`-Array aus `base_app.html`.

    Bracket-Counting statt simpler Regex, weil die Safelist-Eintraege selbst
    eckige Klammern enthalten koennen (`w-[180px]`, `max-w-[44ch]`).
    """
    text = _BASE_APP.read_text(encoding="utf-8")
    anchor = text.find("safelist:")
    assert anchor != -1, (
        "Safelist-Block in base_app.html nicht gefunden — siehe TD-010 und das "
        "Inline-Skript vor dem CDN-`<script src=cdn.tailwindcss.com>`-Tag."
    )
    bracket_start = text.find("[", anchor)
    assert bracket_start != -1, "Safelist-Block ohne `[` nach `safelist:`"
    depth = 0
    bracket_end = -1
    for idx in range(bracket_start, len(text)):
        ch = text[idx]
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                bracket_end = idx
                break
    assert bracket_end != -1, "Safelist-Block hat unausbalancierte Klammern"
    raw = text[bracket_start + 1 : bracket_end]
    # Inline-Kommentare (`// ...`) ausblenden bevor wir am Komma splitten.
    raw_no_comments = re.sub(r"//[^\n]*", "", raw)
    out: set[str] = set()
    for entry in raw_no_comments.split(","):
        cleaned = entry.strip().strip('"').strip("'")
        if cleaned:
            out.add(cleaned)
    return out


def _scan_template_classes() -> dict[str, list[str]]:
    """Sammelt alle `class="..."`-Werte aus jedem `*.html` in `app/templates/`.

    Rueckgabe: dict[class_name -> list[relative_path]] — pro Klasse die
    Liste der Templates, die sie verwenden. Mehrfach-Vorkommen pro File
    werden dedupliziert.
    """
    class_re = re.compile(r'class="([^"]+)"')
    out: dict[str, set[str]] = {}
    for path in _TEMPLATES_ROOT.rglob("*.html"):
        text = path.read_text(encoding="utf-8")
        rel = str(path.relative_to(_TEMPLATES_ROOT))
        for match in class_re.finditer(text):
            for cls in match.group(1).split():
                out.setdefault(cls, set()).add(rel)
    return {k: sorted(v) for k, v in out.items()}


def test_safelist_block_parsable_and_non_empty() -> None:
    """Sicherheitsnetz: das Safelist-Array existiert und hat Inhalt."""
    safelist = _extract_safelist()
    assert safelist, (
        "Safelist in base_app.html ist leer — siehe TD-010. Mindestens "
        "`h-full` sollte vorhanden sein."
    )


def test_safelist_entries_used_in_templates() -> None:
    """Kein Drift durch stale Safelist-Eintraege.

    Wenn ein Eintrag in keinem Template mehr referenziert wird, kann er
    aus der Safelist raus — sonst wird die Liste mit der Zeit zu Lagerhaltung.
    """
    safelist = _extract_safelist()
    classes_in_use = _scan_template_classes()
    stale = sorted(entry for entry in safelist if entry not in classes_in_use)
    assert not stale, (
        f"Safelist-Eintraege werden in keinem Template benutzt: {stale}. "
        f"Entweder Eintrag entfernen oder Verwendung pruefen (z.B. ist der "
        f"Selektor exakt geschrieben?)."
    )


def _is_initial_dom_only(paths: list[str]) -> bool:
    """True wenn alle `paths` zum Initial-DOM-Set gehoeren (kein Race)."""
    return all(
        any(p == prefix or p.startswith(prefix) for prefix in _INITIAL_DOM_TEMPLATES) for p in paths
    )


def test_high_risk_classes_in_htmx_subtrees_are_safelisted() -> None:
    """Pflicht-Marker: jede high-risk-Klasse, die in einem HTMX-Subtree-
    Template benutzt wird (also nicht ausschliesslich im Initial-DOM),
    muss in der Safelist stehen.

    Verhindert dass ein Frontend-Implementer `h-full` in einem HTMX-Subtree-
    Template ergaenzt und das Layout-Problem aus TD-010 reproduziert.

    Klassen, die ausschliesslich in `base.html`, `base_app.html`, oder den
    `layout/`/`sidebar/`-Partials vorkommen, sind sicher: der CDN-JIT-Scan
    sieht sie beim Page-Load und generiert CSS dafuer.
    """
    safelist = _extract_safelist()
    classes_in_use = _scan_template_classes()
    missing: list[tuple[str, list[str]]] = []
    for risk_cls in _HIGH_RISK_CLASSES:
        if risk_cls not in classes_in_use:
            continue
        paths = classes_in_use[risk_cls]
        if _is_initial_dom_only(paths):
            continue  # nur im Initial-DOM, kein Race
        if risk_cls not in safelist:
            missing.append((risk_cls, paths))
    assert not missing, "\n".join(
        f"High-risk-Klasse {cls!r} in {paths} verwendet (HTMX-Subtree), "
        f"fehlt in Safelist (base_app.html). Siehe TD-010."
        for cls, paths in missing
    )


# Arbitrary-value-Klassen (Tailwind `[]`-Bracket-Notation): selbe Race-
# Anfaelligkeit wie die `_HIGH_RISK_CLASSES`, nur dass jede einzelne Auspraegung
# eine eigene Klasse ist — der CDN-JIT muss sie genau in dieser Form schon
# beim Page-Load gesehen haben.
#
# Matched: w-[..], h-[..], min-w-[..], max-w-[..], min-h-[..], max-h-[..],
# leading-[..], gap-[..], etc. Die Pattern-Familien sind eng — wir greifen
# defensiv die Sizing-/Spacing-Klassen, weil dort Layout-Brueche entstehen.
_ARBITRARY_VALUE_RE = re.compile(
    r"^(?:w|h|min-w|max-w|min-h|max-h|leading|gap|space-[xy])-\[[^\]]+\]$"
)


def test_arbitrary_value_classes_in_htmx_subtrees_are_safelisted() -> None:
    """Pflicht-Marker fuer arbitrary-value-Klassen (`w-[180px]`, `max-w-[44ch]`).

    Beobachtet 2026-05-22: `w-[180px]` auf der KPI-Card in `_kpi_card.html`
    wurde nach HTMX-Pane-Swap vom CDN-JIT nicht erfasst — Card-Breite
    kollabierte auf intrinsische Flex-Item-Breite. Pattern ist dasselbe
    wie bei `h-full` (TD-010); jede arbitrary-value-Klasse ist ihre
    eigene CSS-Regel und damit eigene Race-Anfaelligkeit.

    Eine Klasse, die ueberlappend ein Initial-DOM-Template und ein HTMX-
    Subtree-Template benutzt, ist sicher — Tailwind generiert das CSS aus
    dem Initial-DOM-Scan, der HTMX-Subtree erbt es.
    """
    safelist = _extract_safelist()
    classes_in_use = _scan_template_classes()
    missing: list[tuple[str, list[str]]] = []
    for cls, paths in classes_in_use.items():
        if not _ARBITRARY_VALUE_RE.match(cls):
            continue
        if _is_initial_dom_only(paths):
            continue  # nur im Initial-DOM, sicher
        # Klasse muss auch in mindestens einem Initial-DOM-Template stehen,
        # ODER in der Safelist eingetragen sein.
        initial_dom_paths = [
            p
            for p in paths
            if any(p == prefix or p.startswith(prefix) for prefix in _INITIAL_DOM_TEMPLATES)
        ]
        if initial_dom_paths:
            continue  # ueberlappende Verwendung → JIT scannt sie auf Initial-DOM
        if cls not in safelist:
            missing.append((cls, paths))
    assert not missing, "\n".join(
        f"Arbitrary-value-Klasse {cls!r} in {paths} verwendet (nur HTMX-Subtree), "
        f"fehlt in Safelist (base_app.html). Siehe TD-010."
        for cls, paths in missing
    )
