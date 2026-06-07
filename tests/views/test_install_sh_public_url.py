"""v0.7.1 — `FM_PUBLIC_URL` + ProxyFix-Verhalten fuer `/install.sh`.

Drei Pfade durch die Render-Logik im Block-N-Installer-Template:

1. Ohne ProxyFix-Header und ohne `FM_PUBLIC_URL` → Fallback auf
   `request.host_url`, in Tests `http://localhost`.
2. Mit `X-Forwarded-Proto: https` und ohne explizite Public-URL →
   `request.host_url` aufloesen ueber ProxyFix als `https://...`.
3. Mit explizit gesetzter `FM_PUBLIC_URL` → die Env-Var gewinnt
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
    assert 'FM_URL="http://localhost"' in body


def test_install_sh_honours_x_forwarded_proto(client: FlaskClient) -> None:
    """ProxyFix uebersetzt `X-Forwarded-Proto: https` in `request.scheme=https`."""
    resp = client.get(
        "/install.sh",
        headers={
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "fathometer.example.com",
        },
    )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Der Box-Header und die `readonly FM_URL`-Zeile sehen jetzt HTTPS.
    assert 'FM_URL="https://fathometer.example.com"' in body


def test_install_sh_public_url_env_overrides_request_host(
    client: FlaskClient,
) -> None:
    """`FM_PUBLIC_URL` wird im Render bevorzugt vor `request.host_url`.

    Dieser Test simuliert den Production-Setup: Operator hat in `.env`
    `FM_PUBLIC_URL=https://fathometer.example.com` gesetzt; der Wizard
    soll diese URL einbacken — unabhaengig davon, was `request.host_url`
    in der laufenden App liefert.
    """
    # Test-Override ueber `app.config`, weil die App-Factory in `client`
    # bereits initialisiert ist. Aequivalent zu `FM_PUBLIC_URL`-Env.
    client.application.config["EXTERNAL_BASE_URL"] = "https://fathometer.example.com"
    try:
        resp = client.get("/install.sh")
    finally:
        client.application.config["EXTERNAL_BASE_URL"] = ""

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert 'FM_URL="https://fathometer.example.com"' in body


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
    """`fathometer-agent.sh` upload-POST folgt 30x-Redirects analog."""
    script = _REPO_ROOT / "agent" / "fathometer-agent.sh"
    content = script.read_text(encoding="utf-8")
    assert "--post301 --post302 --post303 -L" in content


def test_register_script_uses_redirect_following() -> None:
    """`fathometer-register.sh` register-POST folgt 30x-Redirects analog."""
    script = _REPO_ROOT / "agent" / "fathometer-register.sh"
    content = script.read_text(encoding="utf-8")
    assert "--post301 --post302 --post303 -L" in content


def test_install_sh_does_not_make_fathometer_url_readonly() -> None:
    """v0.7.2 — `FM_URL` darf nicht `readonly` sein.

    Phase 6 (probe scan) sourced `/etc/fathometer/agent.env` in einer
    Subshell. Wenn das Wizard-Toplevel `readonly FM_URL=...`
    deklariert, erbt die Subshell das `readonly`-Flag, und das
    Re-Assignment aus `agent.env` schlaegt mit 'readonly variable'
    fehl — der probe-scan endet mit exit 1, obwohl die Werte
    identisch sind.

    Real beobachtet auf rke2-sv-0-1 (Ubuntu 22.04 aarch64) nach dem
    v0.7.1-Upgrade.
    """
    template = _REPO_ROOT / "app" / "templates" / "agent" / "install.sh.j2"
    content = template.read_text(encoding="utf-8")
    # Es darf keine `readonly FM_URL=`-Zeile geben — weder am
    # Zeilenanfang noch nach Whitespace.
    for line in content.splitlines():
        stripped = line.lstrip()
        assert not stripped.startswith("readonly FM_URL"), (
            f"FM_URL must not be readonly, found: {line!r}"
        )
    # Aber die Variable muss als normales Assignment vorhanden sein.
    assert 'FM_URL="{{ fathometer_url }}"' in content
