"""v0.7.1 — `SECSCAN_PUBLIC_URL` + ProxyFix-Verhalten fuer `/install.sh`.

Drei Pfade durch die Render-Logik im Block-N-Installer-Template:

1. Ohne ProxyFix-Header und ohne `SECSCAN_PUBLIC_URL` → Fallback auf
   `request.host_url`, in Tests `http://localhost`.
2. Mit `X-Forwarded-Proto: https` und ohne explizite Public-URL →
   `request.host_url` aufloesen ueber ProxyFix als `https://...`.
3. Mit explizit gesetzter `SECSCAN_PUBLIC_URL` → die Env-Var gewinnt
   gegen jeden Proxy-Header (deploy-eindeutige Quelle der Wahrheit).
"""

from __future__ import annotations

from pathlib import Path

from flask.testing import FlaskClient

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_install_sh_fallback_uses_request_host_url(client: FlaskClient) -> None:
    """Ohne Public-URL + ohne Proxy-Header rendert der Fallback http://localhost."""
    resp = client.get("/install.sh")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'SECSCAN_URL="http://localhost"' in body


def test_install_sh_honours_x_forwarded_proto(client: FlaskClient) -> None:
    """ProxyFix uebersetzt `X-Forwarded-Proto: https` in `request.scheme=https`."""
    resp = client.get(
        "/install.sh",
        headers={
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "secscan.example.com",
        },
    )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Der Box-Header und die `readonly SECSCAN_URL`-Zeile sehen jetzt HTTPS.
    assert 'SECSCAN_URL="https://secscan.example.com"' in body


def test_install_sh_public_url_env_overrides_request_host(
    client: FlaskClient,
) -> None:
    """`SECSCAN_PUBLIC_URL` wird im Render bevorzugt vor `request.host_url`.

    Dieser Test simuliert den Production-Setup: Operator hat in `.env`
    `SECSCAN_PUBLIC_URL=https://secscan.example.com` gesetzt; der Wizard
    soll diese URL einbacken — unabhaengig davon, was `request.host_url`
    in der laufenden App liefert.
    """
    # Test-Override ueber `app.config`, weil die App-Factory in `client`
    # bereits initialisiert ist. Aequivalent zu `SECSCAN_PUBLIC_URL`-Env.
    client.application.config["EXTERNAL_BASE_URL"] = "https://secscan.example.com"
    try:
        resp = client.get("/install.sh")
    finally:
        client.application.config["EXTERNAL_BASE_URL"] = ""

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'SECSCAN_URL="https://secscan.example.com"' in body


def test_install_sh_post_curl_uses_redirect_following() -> None:
    """Das Template benutzt `--post301 --post302 --post303 -L` fuer den
    Register-POST, damit ein HTTP->HTTPS-30x-Redirect den POST nicht
    eskamotiert.
    """
    template = _REPO_ROOT / "app" / "templates" / "agent" / "install.sh.j2"
    content = template.read_text(encoding="utf-8")
    # Genau eine `curl`-Stelle fuer den Register-POST. Sie muss die drei
    # `--post30x`-Flags plus `-L` enthalten, damit der Body bei einem
    # HTTP->HTTPS-Redirect wieder als POST gesendet wird.
    assert "--post301 --post302 --post303 -L" in content


def test_agent_scan_curl_uses_redirect_following() -> None:
    """`secscan-agent.sh` upload-POST folgt 30x-Redirects analog."""
    script = _REPO_ROOT / "agent" / "secscan-agent.sh"
    content = script.read_text(encoding="utf-8")
    assert "--post301 --post302 --post303 -L" in content


def test_register_script_uses_redirect_following() -> None:
    """`secscan-register.sh` register-POST folgt 30x-Redirects analog."""
    script = _REPO_ROOT / "agent" / "secscan-register.sh"
    content = script.read_text(encoding="utf-8")
    assert "--post301 --post302 --post303 -L" in content


def test_install_sh_does_not_make_secscan_url_readonly() -> None:
    """v0.7.2 — `SECSCAN_URL` darf nicht `readonly` sein.

    Phase 6 (probe scan) sourced `/etc/secscan/agent.env` in einer
    Subshell. Wenn das Wizard-Toplevel `readonly SECSCAN_URL=...`
    deklariert, erbt die Subshell das `readonly`-Flag, und das
    Re-Assignment aus `agent.env` schlaegt mit 'readonly variable'
    fehl — der probe-scan endet mit exit 1, obwohl die Werte
    identisch sind.

    Real beobachtet auf rke2-sv-0-1 (Ubuntu 22.04 aarch64) nach dem
    v0.7.1-Upgrade.
    """
    template = _REPO_ROOT / "app" / "templates" / "agent" / "install.sh.j2"
    content = template.read_text(encoding="utf-8")
    # Es darf keine `readonly SECSCAN_URL=`-Zeile geben — weder am
    # Zeilenanfang noch nach Whitespace.
    for line in content.splitlines():
        stripped = line.lstrip()
        assert not stripped.startswith("readonly SECSCAN_URL"), (
            f"SECSCAN_URL must not be readonly, found: {line!r}"
        )
    # Aber die Variable muss als normales Assignment vorhanden sein.
    assert 'SECSCAN_URL="{{ secscan_url }}"' in content
