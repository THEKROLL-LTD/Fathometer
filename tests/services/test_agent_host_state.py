"""Block O Phase E — Tests fuer den Host-Snapshot-Collector im Agent.

Strategie: das Skript `agent/lib_host_state.sh` ist sourcable und exportiert
die vier `collect_*`-Funktionen plus den `build_host_state_json`-Aggregator.
Wir bauen pro Test ein temporaeres `bin/`-Verzeichnis mit Stub-Skripten fuer
`ss`/`netstat`/`ps`/`lsmod`/`systemctl` und setzen `PATH=<tmpbin>:<real-tools>`
sodass die Lib die Stubs picked statt der echten System-Tools.

Die `real-tools` enthalten gezielt `jq`, `awk`, `sed`, `tr`, `head`, `tail`,
`date` — alles was die Lib intern braucht. `ss`/`netstat`/`ps`/`lsmod`/
`systemctl` sind absichtlich NUR in `tmpbin`, damit wir die Tool-Verfuegbar-
keit pro Test kontrollieren koennen.

Validierung: das resultierende JSON wird via Pydantic-Modell `HostStateBlock`
geparst — schlaegt der Parse fehl, ist das ein Agent/Schema-Drift-Bug.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from app.schemas.scan_envelope import HostStateBlock

LIB_PATH = Path(__file__).parent.parent.parent / "agent" / "lib_host_state.sh"

# Tools die die Lib intrinsisch braucht. Wir suchen sie auf dem CI-Host
# und linken sie in das Stub-bin/ ein. Wenn eines davon fehlt, werden die
# Tests geskippt (CI hat sie standardmaessig).
_REQUIRED_REAL_TOOLS = (
    "jq",
    "awk",
    "sed",
    "tr",
    "head",
    "tail",
    "date",
    "bash",
    "cat",
)


def _real_tool_paths() -> dict[str, str]:
    resolved: dict[str, str] = {}
    for name in _REQUIRED_REAL_TOOLS:
        path = shutil.which(name)
        if path is None:
            pytest.skip(f"required tool '{name}' not in PATH")
        resolved[name] = path
    return resolved


def _make_stub(bindir: Path, name: str, body: str) -> None:
    """Schreibt ein executable Stub-Skript nach `bindir/name`."""
    p = bindir / name
    p.write_text("#!/usr/bin/env bash\n" + body + "\n")
    p.chmod(0o755)


def _link_real(bindir: Path, real_paths: dict[str, str]) -> None:
    """Symlinkt die intrinsischen Tools in das Stub-bin-Verzeichnis."""
    for name, path in real_paths.items():
        link = bindir / name
        if not link.exists():
            link.symlink_to(path)


def _run_build(bindir: Path) -> str:
    """Ruft `build_host_state_json` in einer Subshell mit isoliertem PATH auf."""
    cmd = [
        "bash",
        "-c",
        f"set -e; PATH={bindir}; export PATH; "
        f"TOOLS_AVAILABLE=(); GAPS=(); "
        f"source '{LIB_PATH}'; build_host_state_json",
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env={"PATH": str(bindir), "LC_ALL": "C"},
        timeout=30,
    )
    assert proc.returncode == 0, (
        f"build_host_state_json failed: exit={proc.returncode}\n"
        f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}"
    )
    return proc.stdout.strip()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def stub_bin(tmp_path: Path) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _link_real(bindir, _real_tool_paths())
    return bindir


# ---------------------------------------------------------------------------
# Stub-Output-Konstanten — modellieren echtes Linux-Tool-Verhalten.
# ---------------------------------------------------------------------------

# `ss -tulnpH` Output: state-Spalte vorhanden, users:(("name",pid=N,fd=M)).
SS_TULNPH_OUTPUT = """\
tcp   LISTEN 0 128 0.0.0.0:22         0.0.0.0:* users:(("sshd",pid=1234,fd=3))
tcp   LISTEN 0 128 127.0.0.1:5432     0.0.0.0:* users:(("postgres",pid=5678,fd=7))
udp   UNCONN 0 0   0.0.0.0:53         0.0.0.0:* users:(("named",pid=901,fd=8))
tcp6  LISTEN 0 128 [::]:443           [::]:*    users:(("nginx",pid=2222,fd=6))
"""

# `ps -eo pid=,user=,comm=,args=` Output ohne Header.
PS_OUTPUT = """\
1234 root sshd /usr/sbin/sshd -D
5678 postgres postgres /usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main
901 root named /usr/sbin/named -f -u bind
2222 www-data nginx nginx: master process /usr/sbin/nginx
"""

# `lsmod` Output mit Header.
LSMOD_OUTPUT = """\
Module                  Size  Used by
ext4                  856064  1
nf_conntrack          135168  4 nf_nat,nft_ct,nf_conntrack_netlink,xt_conntrack
br_netfilter           28672  0
overlay               147456  3
bridge                311296  1 br_netfilter
"""

# `systemctl list-units ...` Output ohne Header (--no-legend).
SYSTEMCTL_OUTPUT = """\
sshd.service                       loaded active running OpenSSH server
postgresql.service                 loaded active running PostgreSQL RDBMS
nginx.service                      loaded active running nginx
cron.service                       loaded active running Regular background program processing daemon
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_all_four_tools_present(stub_bin: Path) -> None:
    """Volles Linux-Setup: alle vier Sub-Bloecke populated, gaps leer."""
    _make_stub(stub_bin, "ss", f'cat <<"EOF"\n{SS_TULNPH_OUTPUT}EOF')
    _make_stub(stub_bin, "ps", f'cat <<"EOF"\n{PS_OUTPUT}EOF')
    _make_stub(stub_bin, "lsmod", f'cat <<"EOF"\n{LSMOD_OUTPUT}EOF')
    _make_stub(stub_bin, "systemctl", f'cat <<"EOF"\n{SYSTEMCTL_OUTPUT}EOF')

    out = _run_build(stub_bin)
    data: dict[str, Any] = json.loads(out)

    assert data["gaps"] == []
    assert set(data["tools_available"]) == {"ss", "ps", "lsmod", "systemctl"}

    # Listeners
    listeners = data["listeners"]
    assert len(listeners) == 4
    procs = {entry["process"] for entry in listeners}
    assert procs == {"sshd", "postgres", "named", "nginx"}
    ssh_entry = next(entry for entry in listeners if entry["process"] == "sshd")
    # S104 false positive: das ist ein Test-Assert, kein bind() — wir
    # verifizieren dass der Parser die Wildcard-Adresse durchreicht.
    assert ssh_entry == {
        "proto": "tcp",
        "addr": "0.0.0.0",  # noqa: S104
        "port": 22,
        "process": "sshd",
        "pid": 1234,
    }
    # IPv6-Eintrag korrekt zerlegt
    nginx_entry = next(entry for entry in listeners if entry["process"] == "nginx")
    assert nginx_entry["proto"] == "tcp6"
    assert nginx_entry["addr"] == "::"
    assert nginx_entry["port"] == 443

    # Processes
    assert len(data["processes"]) == 4
    pid_to_user = {p["pid"]: p["user"] for p in data["processes"]}
    assert pid_to_user[1234] == "root"
    assert pid_to_user[5678] == "postgres"
    assert pid_to_user[2222] == "www-data"

    # Kernel modules
    assert set(data["kernel_modules"]) == {
        "ext4",
        "nf_conntrack",
        "br_netfilter",
        "overlay",
        "bridge",
    }

    # Services
    assert set(data["services"]) == {
        "sshd.service",
        "postgresql.service",
        "nginx.service",
        "cron.service",
    }

    # JSON ist gegen das Backend-Schema parsebar.
    HostStateBlock.model_validate(data)


def test_no_systemctl_gap_marked(stub_bin: Path) -> None:
    """Container ohne systemctl: services leer + gaps=['services']."""
    _make_stub(stub_bin, "ss", f'cat <<"EOF"\n{SS_TULNPH_OUTPUT}EOF')
    _make_stub(stub_bin, "ps", f'cat <<"EOF"\n{PS_OUTPUT}EOF')
    _make_stub(stub_bin, "lsmod", f'cat <<"EOF"\n{LSMOD_OUTPUT}EOF')
    # systemctl absichtlich NICHT angelegt

    out = _run_build(stub_bin)
    data = json.loads(out)

    assert data["services"] == []
    assert "services" in data["gaps"]
    assert "systemctl" not in data["tools_available"]
    # Andere Bloecke nicht beeintraechtigt
    assert len(data["listeners"]) == 4
    assert len(data["processes"]) == 4
    HostStateBlock.model_validate(data)


def test_no_lsmod_gap_marked(stub_bin: Path) -> None:
    """Container ohne lsmod: kernel_modules leer + gaps=['kernel_modules']."""
    _make_stub(stub_bin, "ss", f'cat <<"EOF"\n{SS_TULNPH_OUTPUT}EOF')
    _make_stub(stub_bin, "ps", f'cat <<"EOF"\n{PS_OUTPUT}EOF')
    _make_stub(stub_bin, "systemctl", f'cat <<"EOF"\n{SYSTEMCTL_OUTPUT}EOF')
    # lsmod absichtlich NICHT angelegt

    out = _run_build(stub_bin)
    data = json.loads(out)

    assert data["kernel_modules"] == []
    assert "kernel_modules" in data["gaps"]
    assert "lsmod" not in data["tools_available"]
    HostStateBlock.model_validate(data)


def test_netstat_fallback_when_ss_missing(stub_bin: Path) -> None:
    """Kein ss, aber netstat: netstat wird genutzt, Listeners populated."""
    netstat_output = (
        "Active Internet connections (only servers)\n"
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd\n"
        "tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      5678/postgres\n"
        "udp        0      0 0.0.0.0:53              0.0.0.0:*                           901/named\n"
    )
    _make_stub(stub_bin, "netstat", f'cat <<"EOF"\n{netstat_output}EOF')
    _make_stub(stub_bin, "ps", f'cat <<"EOF"\n{PS_OUTPUT}EOF')

    out = _run_build(stub_bin)
    data = json.loads(out)

    assert "netstat" in data["tools_available"]
    assert "ss" not in data["tools_available"]
    assert "listeners" not in data["gaps"]
    # Mindestens die TCP-Listeners gefunden
    procs = {entry["process"] for entry in data["listeners"]}
    assert "sshd" in procs
    assert "postgres" in procs
    HostStateBlock.model_validate(data)


def test_no_listener_tool_gap_marked(stub_bin: Path) -> None:
    """Weder ss noch netstat: listeners=[] + gaps=['listeners']."""
    _make_stub(stub_bin, "ps", f'cat <<"EOF"\n{PS_OUTPUT}EOF')

    out = _run_build(stub_bin)
    data = json.loads(out)

    assert data["listeners"] == []
    assert "listeners" in data["gaps"]
    assert "ss" not in data["tools_available"]
    assert "netstat" not in data["tools_available"]
    HostStateBlock.model_validate(data)


def test_non_ascii_dropped(stub_bin: Path) -> None:
    """Non-ASCII-Garbage in den Outputs wird gefiltert, JSON bleibt valid."""
    # `\xc3` ist UTF-8-Start-Byte ohne valide Continuation — non-ASCII byte.
    # Wir injecten ihn in einen Module-Namen; der ASCII-Filter sollte ihn
    # entfernen. Andere Eintraege muessen unbeschaedigt durchgehen.
    lsmod_with_garbage = (
        "Module                  Size  Used by\n"
        "ext4                  856064  1\n"
        # Non-ASCII-Byte in der Mitte des Modul-Namens — `tr -d 0x80-0xff`
        # entfernt das Byte und laesst den Rest stehen, sodass der Name
        # `nfconntrack` heisst (statt `nf\xc3\xa9_conntrack`).
        "nf\xc3\xa9_conntrack          135168  0\n"
        "overlay               147456  0\n"
    )
    lsmod_bin = stub_bin / "lsmod"
    # printf -- printable. Wir schreiben die Bytes direkt.
    lsmod_bin.write_bytes(
        b'#!/usr/bin/env bash\nprintf "%s" "' + lsmod_with_garbage.encode("latin-1") + b'"\n'
    )
    lsmod_bin.chmod(0o755)

    _make_stub(stub_bin, "ps", f'cat <<"EOF"\n{PS_OUTPUT}EOF')

    out = _run_build(stub_bin)
    data = json.loads(out)

    # JSON ist valid und gegen Schema parsebar
    HostStateBlock.model_validate(data)
    # ext4 + overlay muessen drin sein (waren rein ASCII)
    assert "ext4" in data["kernel_modules"]
    assert "overlay" in data["kernel_modules"]
    # Kein Modul-Eintrag enthaelt non-ASCII-Bytes (Pydantic-Validator wuerde
    # rejecten — wenn wir hier kommen, ist alles sauber gefiltert).
    for mod in data["kernel_modules"]:
        assert all(ord(c) < 128 for c in mod), f"non-ASCII byte ueberlebt in {mod!r}"


def test_envelope_compat(stub_bin: Path) -> None:
    """Der erzeugte `host_state`-Block parsed als Teil eines vollen Envelopes."""
    _make_stub(stub_bin, "ss", f'cat <<"EOF"\n{SS_TULNPH_OUTPUT}EOF')
    _make_stub(stub_bin, "ps", f'cat <<"EOF"\n{PS_OUTPUT}EOF')
    _make_stub(stub_bin, "lsmod", f'cat <<"EOF"\n{LSMOD_OUTPUT}EOF')
    _make_stub(stub_bin, "systemctl", f'cat <<"EOF"\n{SYSTEMCTL_OUTPUT}EOF')

    out = _run_build(stub_bin)
    host_state = json.loads(out)

    envelope_data = {
        "agent_version": "0.3.0",
        "host": {
            "os_family": "ubuntu",
            "os_version": "22.04",
            "os_pretty_name": "Ubuntu 22.04 LTS",
            "kernel_version": "6.1.0",
            "architecture": "amd64",
            "trivy_version": "0.70.0",
        },
        "scan": {"SchemaVersion": 2, "Results": []},
        "host_state": host_state,
    }
    from app.schemas.scan_envelope import Envelope

    env = Envelope.model_validate(envelope_data)
    assert env.host_state is not None
    assert len(env.host_state.listeners) == 4
    assert len(env.host_state.processes) == 4
    assert len(env.host_state.kernel_modules) == 5
    assert len(env.host_state.services) == 4


def test_agent_script_has_host_state_integration() -> None:
    """Sanity-Check: das Haupt-Skript traegt den aktuellen Versions-Bump und
    sourct die Lib (Block AL / ADR-0066 zieht Agent auf 0.8.0, Lib auf 0.5.0)."""
    agent_sh = Path(__file__).parent.parent.parent / "agent" / "fathometer-agent.sh"
    body = agent_sh.read_text()
    assert 'AGENT_VERSION="0.8.0"' in body, "Agent-Version-Bump auf 0.8.0 fehlt"
    assert 'REQUIRED_LIB_HOST_STATE_VERSION="0.5.0"' in body
    assert "lib_host_state.sh" in body, "Agent sourct lib_host_state.sh nicht"
    assert "host_state" in body, "Agent baut host_state nicht in Envelope ein"
    assert "collect_host_updates" in body, "Agent ruft den Host-Update-Resolver nicht auf"
    assert "host_updates" in body, "Agent baut host_updates nicht in Envelope ein"


def test_empty_systemctl_output_not_a_gap(stub_bin: Path) -> None:
    """systemctl vorhanden aber keine aktiven Services: kein gaps-Eintrag."""
    # systemctl gibt 0 Bytes aus (kein Service active, --no-legend ohne Header).
    _make_stub(stub_bin, "systemctl", "exit 0")
    _make_stub(stub_bin, "ps", f'cat <<"EOF"\n{PS_OUTPUT}EOF')

    out = _run_build(stub_bin)
    data = json.loads(out)

    assert data["services"] == []
    # systemctl WAR verfuegbar -> kein gap
    assert "services" not in data["gaps"]
    assert "systemctl" in data["tools_available"]


@pytest.mark.skipif(
    os.environ.get("SKIP_SHELLCHECK") == "1", reason="explicit skip via SKIP_SHELLCHECK"
)
def test_shellcheck_clean() -> None:
    """Beide Agent-Skripte sind shellcheck-clean."""
    shellcheck = shutil.which("shellcheck")
    if shellcheck is None:
        pytest.skip("shellcheck not installed")
    agent_dir = Path(__file__).parent.parent.parent / "agent"
    for script in ("fathometer-agent.sh", "lib_host_state.sh"):
        proc = subprocess.run(
            [shellcheck, str(agent_dir / script)],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, (
            f"shellcheck failed for {script}:\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )
