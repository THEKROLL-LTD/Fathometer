"""Sprach-Sweep: verhindert deutsche Strings in der operator-sichtbaren UI.

ADR-0045 (English-only UI, Block AB): die gesamte UI ist ausschliesslich
englisch. Dieser Pure-Unit-Test scannt die operator-sichtbaren Flaechen gegen
eine deutsche Marker-Wortliste (Umlaute + `ae/oe/ue`-Transliterationen + haeufige
deutsche Woerter) und schlaegt fehl, sobald ein neuer deutscher UI-String
hinzukommt.

Scope (was gescannt wird):
  - `app/templates/**/*.html`  — nach Abzug von `{# … #}` und `<!-- … -->`
  - `app/static/js/*.js`       — nach Abzug von `// …` und `/* … */`
  - `app/views/*.py`           — nur String-Literale (keine Docstrings/Kommentare)
  - `app/forms.py`             — nur String-Literale (keine Docstrings/Kommentare)
  - `app/services/trend.py`    — `Tendency.label` wird per `tendency_label`-Macro
                                 direkt in der UI gerendert (Jinja-Filter-Output,
                                 ADR-0045 §1). Andere `app/services/`-Module sind
                                 Maschinen-/Agent-/LLM-Worker-Flaechen (ADR-0021/
                                 0023/0043) und bewusst NICHT im Scan.

Bewusst NICHT gescannt (ADR-0045 §Scope — bleiben deutsch):
  - Code-Kommentare, Docstrings, Jinja-/HTML-Kommentare.
  - `app/static/js/`-Dateien aus dem esbuild-Bundle (`frontend/src/js/`) sind
    bereits englisch (Block W) und ausserhalb des Scans; hier wird nur das
    direkt ausgelieferte `app/static/js/` geprueft.
  - Test-Dateien, Doku, ADRs.

Erweiterung des Scans (neue Marker) ist erwuenscht; die `_ALLOWLIST` ist der
explizite Ausnahme-Mechanismus fuer dokumentierte False-Positives.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

# Projekt-Wurzel: dieser Test liegt in tests/, eine Ebene unter der Wurzel.
_ROOT = Path(__file__).resolve().parent.parent
_APP = _ROOT / "app"

# ---------------------------------------------------------------------------
# Marker-Wortliste
# ---------------------------------------------------------------------------
# Umlaute / ScharfesS — eindeutig deutsch.
_UMLAUT_RE = re.compile(r"[äöüßÄÖÜ]")

# Transliterierte und haeufige deutsche Woerter. Case-insensitive Substring-Match.
# WICHTIG: nur Tokens aufnehmen, die NICHT als Substring in legitimen englischen
# UI-Strings / Identifiern / CSS-Klassen vorkommen. Bei Bedarf erweitern.
_MARKER_WORDS: tuple[str, ...] = (
    # ae/oe/ue-Transliterationen
    "ungueltig",
    "gespeichert",
    "geloescht",
    "gewaehlt",
    "geaendert",
    "pruefen",
    "fuer ",
    "schluessel",
    "loeschen",
    "benutzername",
    "passwort",
    "bestaetig",
    "ueber",
    # haeufige deutsche Woerter / Floskeln
    "bitte",
    "wurde",
    "eingabe",
    "hinweis",
    "keine ",
    "nicht ",
    "noch nie",
    "gerade eben",
    "servern",
    "anlegen",
    "abbrechen",
    "vorschau",
    "einstellungen",
    "gruppen ",
    "abgehakt",
    "abhaken",
    "fehlgeschlagen",
    "widerrufen",
    "stillgelegt",
    "kopieren",
    "kopiert",
    "weiter",
    "schritt",
    "zwischenablage",
)

# Distinkte deutsche Inhalts-/Funktionswoerter, die als ganzes Wort gematcht
# werden (Wortgrenze), weil sie als Substring in legitimem Englisch vorkaemen
# (z.B. "ist" in "list"/"exist"). Bewusst nur kollisionsarme Tokens — kurze
# Artikel (der/die/das) sind absichtlich NICHT dabei, um Rauschen zu vermeiden.
# Diese Liste fing die Block-AB-Restfunde (patchen/einspielen/mitigieren/
# vergeben/falsch/Ganzzahl/oder/Tage …) die die reine Umlaut-/Translit-Suche
# verfehlt hat.
_MARKER_BOUNDARY_WORDS: tuple[str, ...] = (
    "und",
    "oder",
    "nicht",
    "kein",
    "keine",
    "ist",
    "sind",
    "wurde",
    "wird",
    "werden",
    "muss",
    "muessen",
    "bereits",
    "vergeben",
    "erlaubt",
    "vorhanden",
    "gesetzt",
    "falsch",
    "schalte",
    "patchen",
    "einspielen",
    "mitigieren",
    "naechste",
    "naechsten",
    "tage",
    "tagen",
    "stunden",
    "ganzzahl",
    "ganzzahlen",
    "wahrscheinlichkeit",
    "ausnutzung",
    "schluessel",
    "liegen",
    "zwischen",
)

_BOUNDARY_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(w) for w in _MARKER_BOUNDARY_WORDS) + r")\b",
    re.IGNORECASE,
)

# Explizite Allowlist fuer dokumentierte False-Positives.
# Eintragsform: (relativer_pfad, gematchtes_token_lowercase, kurze_begruendung).
# Der Match wird unterdrueckt, wenn Pfad UND Token uebereinstimmen.
_ALLOWLIST: tuple[tuple[str, str, str], ...] = ()


def _strip_template_comments(text: str) -> str:
    """Entferne Jinja- (`{# … #}`) und HTML- (`<!-- … -->`) Kommentare.

    Ersetzt durch gleichlange Whitespace-Bloecke (Newlines erhalten), damit die
    Zeilennummern fuer die Fehlermeldung stabil bleiben.
    """

    def _blank(m: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))

    text = re.sub(r"\{#.*?#\}", _blank, text, flags=re.DOTALL)
    text = re.sub(r"<!--.*?-->", _blank, text, flags=re.DOTALL)
    return text


def _strip_js_comments(text: str) -> str:
    """Entferne JS-Block- (`/* … */`) und Zeilen- (`// …`) Kommentare.

    Zeilennummern bleiben erhalten. Bewusst simpel (kein voller JS-Parser):
    `//` und `/* */` in String-Literalen sind in unseren 6 Dateien nicht
    vorhanden; sollte das mal vorkommen, deckt die Allowlist den Fall ab.
    """

    def _blank(m: re.Match[str]) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))

    text = re.sub(r"/\*.*?\*/", _blank, text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", _blank, text)
    return text


def _find_markers(text: str) -> list[tuple[int, str, str]]:
    """Finde deutsche Marker in `text`. Liefert (zeile, token, kontext)."""
    hits: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        low = line.lower()
        if _UMLAUT_RE.search(line):
            m = _UMLAUT_RE.search(line)
            assert m is not None
            hits.append((lineno, m.group(0), line.strip()[:120]))
            continue
        matched = False
        for token in _MARKER_WORDS:
            if token in low:
                hits.append((lineno, token, line.strip()[:120]))
                matched = True
                break
        if matched:
            continue
        bm = _BOUNDARY_RE.search(line)
        if bm is not None:
            hits.append((lineno, bm.group(0).lower(), line.strip()[:120]))
    return hits


def _python_string_literals(path: Path) -> list[tuple[int, str]]:
    """Extrahiere String-Literale aus einer Python-Datei, ohne Docstrings.

    f-String-Literal-Teile (die Konstanten zwischen den `{…}`-Feldern) werden
    mit erfasst, da sie als `ast.Constant` im `JoinedStr` liegen. Kommentare
    tauchen im AST nicht auf und werden damit automatisch ignoriert.
    """
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)

    # Docstring-Konstanten (Module/Class/Func) per Identitaet sammeln.
    doc_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                doc_ids.add(id(body[0].value))

    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in doc_ids
        ):
            out.append((node.lineno, node.value))
    return out


def _allowed(rel: str, token: str) -> bool:
    token = token.lower()
    return any(a_rel == rel and a_tok == token for a_rel, a_tok, _ in _ALLOWLIST)


def _violations() -> list[str]:
    violations: list[str] = []

    # Templates
    for path in sorted((_APP / "templates").rglob("*.html")):
        rel = str(path.relative_to(_ROOT))
        text = _strip_template_comments(path.read_text(encoding="utf-8"))
        for lineno, token, ctx in _find_markers(text):
            if _allowed(rel, token):
                continue
            violations.append(f"{rel}:{lineno}: marker {token!r} -> {ctx}")

    # Direkt ausgelieferte JS-Dateien
    js_dir = _APP / "static" / "js"
    for path in sorted(js_dir.glob("*.js")):
        rel = str(path.relative_to(_ROOT))
        text = _strip_js_comments(path.read_text(encoding="utf-8"))
        for lineno, token, ctx in _find_markers(text):
            if _allowed(rel, token):
                continue
            violations.append(f"{rel}:{lineno}: marker {token!r} -> {ctx}")

    # Python: nur String-Literale in views/* + forms.py + UI-Label-Quellen.
    # trend.py: `Tendency.label` wird via `tendency_label`-Macro in der UI
    # gerendert; uebrige services/* sind Maschinen-/LLM-Flaechen (siehe Modul-
    # Docstring) und absichtlich nicht im Scan.
    py_files = [
        *sorted((_APP / "views").glob("*.py")),
        _APP / "forms.py",
        _APP / "services" / "trend.py",
    ]
    for path in py_files:
        rel = str(path.relative_to(_ROOT))
        for lineno, literal in _python_string_literals(path):
            for hit_line, token, ctx in _find_markers(literal):
                del hit_line, ctx
                if _allowed(rel, token):
                    continue
                violations.append(f"{rel}:{lineno}: marker {token!r} -> {literal.strip()[:120]!r}")
                break
    return violations


def test_no_german_markers_in_ui() -> None:
    """Keine deutschen Marker in Templates / JS / View- und Form-String-Literalen."""
    violations = _violations()
    assert not violations, (
        "Deutsche UI-Strings gefunden (ADR-0045: UI ist ausschliesslich englisch).\n"
        "Kommentare/Docstrings sind ausgenommen; echte Ausnahmen in _ALLOWLIST "
        "dokumentieren.\n\n" + "\n".join(violations)
    )
