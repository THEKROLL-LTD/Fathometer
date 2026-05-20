"""Block N (ADR-0021) — Agent-Bootstrap-Installer-Routes.

Drei Endpoints ohne Auth (CSRF-frei, login-frei):

- `GET /agent/version` — JSON mit aktuellen Min-/Recommended-Versionen
  fuer Agent und Trivy.
- `GET /agent/files/<name>` — liefert `secscan-agent.sh` und
  `secscan-register.sh` als statische Files (Whitelist).
- `GET /install.sh` — rendert das Bootstrap-Installer-Bash-Template mit
  eingebackener Backend-URL und Versions-Konstanten.

Begruendung fuer "kein Auth": der Inhalt ist kein Geheimnis (kein
Master-Key, kein API-Key), der Operator soll das Skript vor dem Pipen
in `bash` inspizieren koennen, und der Master-Key wird ohnehin spaeter
im Wizard-Lauf interaktiv abgefragt (Auth gegen `/api/register`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flask import Blueprint, abort, current_app, jsonify, render_template, request
from werkzeug.wrappers import Response

from app.config import Settings

if TYPE_CHECKING:
    from flask.wrappers import Response as FlaskResponse

agent_install_bp = Blueprint("agent_install", __name__)


# Whitelist der lieferbaren Agent-Files. `send_from_directory` schuetzt
# zusaetzlich gegen Path-Traversal, aber die Whitelist macht den Schutz
# explizit und auditbar.
#
# `lib_host_state.sh` (Block O, ADR-0022) wird vom `secscan-agent.sh` als
# Source-Library erwartet. Fehlt sie, kommt `host_state` nicht im Envelope
# an → Pre-Triage faellt auf `risk_band=unknown` → Block-P-LLM-Pipeline
# wird silently disabled. Daher zwingend mit ausliefern (v0.9.2).
_AGENT_FILE_WHITELIST: frozenset[str] = frozenset(
    {
        "secscan-agent.sh",
        "secscan-register.sh",
        "lib_host_state.sh",
    }
)


@agent_install_bp.route("/agent/version", methods=["GET"])
def agent_version() -> Response:
    """JSON mit Agent-/Trivy-Versions-Konstanten fuer den Installer."""
    payload = {
        "current_agent_version": Settings.CURRENT_AGENT_VERSION,
        "min_agent_version": Settings.MIN_AGENT_VERSION,
        "recommended_trivy_version": Settings.RECOMMENDED_TRIVY_VERSION,
        "min_trivy_version": Settings.MIN_TRIVY_VERSION,
        "trivy_release_url_template": Settings.TRIVY_RELEASE_URL_TEMPLATE,
    }
    response: Response = jsonify(payload)
    # Kurzes Caching — die Konstanten aendern sich nur mit einem Backend-Deploy.
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


@agent_install_bp.route("/agent/files/<name>", methods=["GET"])
def agent_file(name: str) -> Response:
    """Liefert ein Agent-Skript aus der Whitelist als `text/x-shellscript`."""
    if name not in _AGENT_FILE_WHITELIST:
        abort(404)
    agent_dir: str = current_app.config["AGENT_FILES_DIR"]
    # `send_from_directory` hardened gegen Path-Traversal — zusammen mit
    # der Whitelist oben ein doppelter Schutz.
    from flask import send_from_directory

    response = send_from_directory(
        agent_dir,
        name,
        mimetype="text/x-shellscript",
        max_age=300,
    )
    return response


@agent_install_bp.route("/install.sh", methods=["GET"])
def install_sh() -> Response:
    """Rendert das Bootstrap-Installer-Template als Bash-Skript.

    Das Template wird in einem separaten Implementer-Schritt (Task #8)
    voll ausgebaut — hier liegt vorerst nur ein Stub, der die Route
    funktionsfaehig haelt.

    `EXTERNAL_BASE_URL` ist die per Setup-Wizard konfigurierte oeffentliche
    Backend-URL. Solange das Feld nicht existiert, fallen wir auf
    `request.host_url` zurueck, damit `/install.sh` immer eine Antwort
    liefert (auch in Dev-Setups ohne explizite Konfiguration).
    """
    external_base_url = current_app.config.get("EXTERNAL_BASE_URL")
    if not external_base_url:
        external_base_url = request.host_url.rstrip("/")
    rendered = render_template(
        "agent/install.sh.j2",
        secscan_url=external_base_url,
        recommended_trivy_version=Settings.RECOMMENDED_TRIVY_VERSION,
        min_trivy_version=Settings.MIN_TRIVY_VERSION,
        trivy_release_url_template=Settings.TRIVY_RELEASE_URL_TEMPLATE,
        current_agent_version=Settings.CURRENT_AGENT_VERSION,
    )
    response: FlaskResponse = current_app.response_class(
        rendered,
        mimetype="text/x-shellscript",
    )
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


__all__ = ["agent_install_bp"]
