"""Tests fuer den `/`-Tastaturkurzbefehl der Sidebar-Suche (Block I, §7a).

Der Shortcut ist reine Browser-JS-Logik in `app/static/js/sidebar.js`.
Wir koennen ihn ohne JS-Runtime (JSDOM) nicht funktional triggern; ein
funktionaler Test bringt unverhaeltnismaessigen Aufwand fuer ein
Block-I-Polish-Feature. Stattdessen prueft diese Datei:

  1. `app/static/js/sidebar.js` wird von Flask ausgeliefert (200).
  2. Der ausgelieferte Inhalt enthaelt den `/`-Shortcut-Handler:
       - `keydown`-Listener registriert,
       - filtert `e.key !== "/"`,
       - ignoriert wenn ein editierbares Feld fokussiert ist
         (INPUT/TEXTAREA/SELECT/contentEditable),
       - fokussiert `#sidebar-search-input`.
  3. Der Sidebar-Search-Input traegt die richtige ID auf der Vollseite,
     damit der Shortcut auch tatsaechlich ein Ziel hat.

DoD-Begruendung: ARCHITECTURE.md §7a fordert das `/`-Shortcut-Verhalten,
das `sidebar.js`-Implementierung deckt es ab; der reine JS-Pfad ohne
DOM-Runtime ist nicht sinnvoll automatisch testbar. Manueller DoD-Eintrag
in `docs/blocks/I-ui-modernization.md` deckt die Live-Pruefung.
"""

from __future__ import annotations

from flask import Flask

from tests._helpers import create_admin_user, login


def test_sidebar_js_is_served(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    resp = client.get("/static/js/sidebar.js")
    assert resp.status_code == 200, resp.status_code
    assert (resp.mimetype or "").startswith("application/javascript") or (
        resp.mimetype or ""
    ).startswith("text/javascript"), resp.mimetype


def test_sidebar_js_registers_slash_shortcut(db_app: Flask) -> None:
    """Der ausgelieferte JS-Code enthaelt den Shortcut-Handler."""
    client = db_app.test_client()
    resp = client.get("/static/js/sidebar.js")
    body = resp.get_data(as_text=True)
    assert 'addEventListener("keydown"' in body, body[:600]
    assert 'e.key !== "/"' in body, "Kein '/'-Filter im keydown-Handler gefunden"
    # Editable-Guard.
    assert "INPUT" in body and "TEXTAREA" in body and "SELECT" in body, body[:600]
    # Ziel-Input wird ueber die richtige ID gefokussiert.
    assert "sidebar-search-input" in body


def test_sidebar_js_ignores_modifier_keys(db_app: Flask) -> None:
    """Der Handler darf bei Ctrl/Cmd/Alt + `/` nicht zuschnappen."""
    client = db_app.test_client()
    body = client.get("/static/js/sidebar.js").get_data(as_text=True)
    assert "ctrlKey" in body, "ctrlKey-Filter fehlt"
    assert "metaKey" in body, "metaKey-Filter fehlt"
    assert "altKey" in body, "altKey-Filter fehlt"


def test_sidebar_full_page_exposes_search_input_id(db_app: Flask) -> None:
    """Die Sidebar muss das Ziel-Input fuer den Shortcut ausliefern."""
    create_admin_user(db_app)
    client = db_app.test_client()
    login(client)
    resp = client.get("/")
    body = resp.get_data(as_text=True)
    assert 'id="sidebar-search-input"' in body
