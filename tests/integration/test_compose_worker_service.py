"""Schema-Tests fuer den `secscan-llm-worker`-Service in `docker-compose.yml`.

Block P (ADR-0023) Phase F definiert einen zweiten Container neben `app`.
Wir verifizieren, dass der Service deklariert ist und die wichtigsten
Eigenschaften aus der DoD erfuellt:

* Entrypoint zeigt auf den Worker-Modulpfad.
* `depends_on` haengt auf `db` mit `service_healthy`-Bedingung.
* Healthcheck ruft `python -m app.workers.healthcheck` ohne HTTP auf.
* Keine `ports:`-Direktive — Worker hat keine eingehenden Ports
  (ARCHITECTURE.md §9).
* Restart-Policy `unless-stopped` analog zu `app`.

Der echte End-to-End-Test (Container hochfahren, Healthcheck abwarten)
gehoert nicht in den pytest-Lauf — Operator-Smoke per
`docker compose up -d --build` ist im Block-Brief beschrieben.

**Implementations-Hinweis:** wir parsen `docker-compose.yml` als Text und
extrahieren den Service-Block via Indentierungs-Slicing. PyYAML ist
bewusst KEINE Projekt-Dependency — siehe ADR-001 (kein Node-Build) und
das Prinzip „minimaler Dependency-Footprint im MVP". Ein robuster
String-Parser reicht fuer die DoD-Asserts hier vollkommen.
"""

from __future__ import annotations

from pathlib import Path


def _compose_text() -> str:
    repo_root = Path(__file__).resolve().parents[2]
    return (repo_root / "docker-compose.yml").read_text()


def _service_block(service_name: str) -> str:
    """Extrahiert den Text-Block eines benannten Services aus der Compose-Datei.

    Sucht die Zeile `  <name>:` (2-space-indent unter `services:`) und
    nimmt alle Folgezeilen bis zur naechsten Top-Level-Service-Definition
    (auch 2-space-indent) oder dem naechsten Top-Level-Key (`volumes:`).
    """
    text = _compose_text()
    lines = text.splitlines()
    start: int | None = None
    for idx, line in enumerate(lines):
        # Top-Level-Service hat Indent 2 und endet auf `:`.
        if line.rstrip() == f"  {service_name}:":
            start = idx + 1
            break
    if start is None:
        raise AssertionError(f"Service `{service_name}` nicht in docker-compose.yml gefunden")

    block: list[str] = []
    for line in lines[start:]:
        # Naechster Top-Level-Key (`volumes:`) oder naechster Service
        # (Indent 2, endet auf `:`) → Block-Ende.
        if line and not line.startswith(" "):
            break
        if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
            break
        block.append(line)
    return "\n".join(block)


def test_worker_service_is_declared() -> None:
    text = _compose_text()
    assert "  secscan-llm-worker:" in text, (
        "Service `secscan-llm-worker` fehlt im docker-compose.yml"
    )


def test_worker_entrypoint_points_to_worker_module() -> None:
    block = _service_block("secscan-llm-worker")
    # Wir akzeptieren beide Listen-Formate (Inline-Liste und Block-Liste).
    inline = '["python", "-m", "app.workers.llm_worker"]'
    has_inline = inline in block
    has_block_list = "- python" in block and "- app.workers.llm_worker" in block
    assert has_inline or has_block_list, (
        f"entrypoint zeigt nicht auf den Worker-Modulpfad. Block:\n{block}"
    )


def test_worker_depends_on_db_healthy() -> None:
    block = _service_block("secscan-llm-worker")
    assert "depends_on:" in block, "Worker muss auf `db` warten"
    assert "db:" in block, "depends_on.db fehlt"
    assert "condition: service_healthy" in block, (
        "depends_on.db.condition muss `service_healthy` sein"
    )


def test_worker_healthcheck_uses_python_module() -> None:
    block = _service_block("secscan-llm-worker")
    assert "healthcheck:" in block, "Worker-Healthcheck fehlt"
    expected = '["CMD", "python", "-m", "app.workers.healthcheck"]'
    assert expected in block, (
        f"healthcheck.test ruft nicht den Python-Healthcheck auf. Block:\n{block}"
    )
    # Cadence-Felder vorhanden.
    for key in ("interval:", "timeout:", "retries:", "start_period:"):
        assert key in block, f"healthcheck.{key} fehlt"


def test_worker_has_no_inbound_ports() -> None:
    """Worker hat KEINE `ports:`-Direktive (ARCHITECTURE.md §9)."""
    block = _service_block("secscan-llm-worker")
    assert "ports:" not in block, (
        "Worker darf keine eingehenden Ports exponieren — nur DB- und LLM-Provider-Egress."
    )


def test_worker_restart_policy_is_unless_stopped() -> None:
    block = _service_block("secscan-llm-worker")
    assert "restart: unless-stopped" in block


def test_worker_has_required_env_vars() -> None:
    """Worker braucht `SECSCAN_DATABASE_URL` und `SECSCAN_ENCRYPTION_KEY`."""
    block = _service_block("secscan-llm-worker")
    assert "SECSCAN_DATABASE_URL:" in block, (
        "SECSCAN_DATABASE_URL fehlt — Worker kann sonst keine DB-Engine bauen"
    )
    assert "SECSCAN_ENCRYPTION_KEY:" in block, (
        "SECSCAN_ENCRYPTION_KEY fehlt — load_settings() wuerde am Start ValidationError werfen"
    )


def test_worker_uses_same_build_context_as_app() -> None:
    """Worker nutzt das gleiche Image/Build-Setup wie `app`."""
    block = _service_block("secscan-llm-worker")
    assert "build:" in block, "Worker muss `build:` definieren (gleiches Image wie app)"
    assert "context: ." in block
    assert "dockerfile: Dockerfile" in block
