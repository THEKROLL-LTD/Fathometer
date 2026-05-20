"""Block P Phase D Task #11 — LLM-Job-Queueing im Scan-Ingest.

Diese Suite verifiziert dass der `/api/scans`-Endpoint nach erfolgreichem
Findings-UPSERT und Pre-Triage abhaengig vom `block_p_llm_mode`-Flag
Pass-1- und Pass-2-Jobs in der `llm_jobs`-Tabelle queued.

Cases:
* **Mode=off** → keine Jobs queued (egal welche Findings).
* **Mode=observation, keine pending Findings** → keine Jobs queued.
* **Mode=observation, pending Findings, leere Library** → 1 Pass-1-Job
  mit allen pending-Finding-IDs, 0 Pass-2-Jobs.
* **Mode=observation, pending Findings, Library matched alle** →
  0 Pass-1-Jobs, 1 Pass-2-Job ohne `depends_on`.
* **Mix** — einige Findings matchen Library, andere nicht → 1 Pass-1-Job
  fuer ungrouped + Pass-2-Job fuer gematcht Group, Pass-2.depends_on
  zeigt auf Pass-1-Job-ID.
* **Re-Ingest mit unveraendertem group_findings_fingerprint** → idempotent,
  keine neuen Pass-2-Jobs fuer bereits bewertete Group.
* **Re-Ingest nach KEV-DB-Update** (cve_data_fingerprint aendert sich,
  group_findings_fingerprint bleibt gleich) → kein zusaetzlicher Pass-2-Job
  vom Hook; Cache-Miss-Re-Eval ist Sache des Workers (siehe
  ADR-0023 §"Cache-Invalidation", MVP-Kompromiss).
* **GroupMatcher-Refresh** — neue Group nach erstem Ingest wird beim
  zweiten Ingest sofort gesehen, Findings werden korrekt gruppiert.
"""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import ApplicationGroup, AuditEvent, Finding, LLMJob
from app.services.group_matcher import GroupMatcher
from app.settings_service import ensure_settings_row
from tests._helpers import register_test_server

# ---------------------------------------------------------------------------
# Fixtures / Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singleton() -> None:
    """Vor und nach jedem Test den GroupMatcher-Singleton resetten."""
    GroupMatcher._reset_for_tests()
    yield
    GroupMatcher._reset_for_tests()


def _minimal_host_state() -> dict[str, Any]:
    return {
        "snapshot_at": "2026-05-18T03:14:22Z",
        "tools_available": ["ss", "ps", "lsmod", "systemctl"],
        "gaps": [],
        "listeners": [],
        "processes": [],
        "kernel_modules": [],
        "services": [],
    }


def _envelope(
    *,
    vulns: list[dict[str, Any]],
    host_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if host_state is None:
        host_state = _minimal_host_state()
    return {
        "agent_version": "0.3.0",
        "host": {
            "os_family": "ubuntu",
            "os_version": "22.04",
            "os_pretty_name": "Ubuntu 22.04",
            "kernel_version": "5.15.0",
            "architecture": "x86_64",
            "trivy_version": "0.70.2",
        },
        "scan": {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.70.2"},
            "Results": [
                {
                    "Target": "test-target",
                    "Class": "os-pkgs",
                    "Type": "ubuntu",
                    "Vulnerabilities": vulns,
                }
            ],
        },
        "host_state": host_state,
    }


def _post(client: Any, payload: dict[str, Any], *, bearer: str) -> Any:
    return client.post(
        "/api/scans",
        data=gzip.compress(json.dumps(payload).encode("utf-8")),
        headers={
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "Authorization": f"Bearer {bearer}",
        },
    )


def _set_mode(app: Flask, mode: str) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            row = ensure_settings_row(sess)
            row.block_p_llm_mode = mode
            sess.commit()
        finally:
            sess.close()


def _insert_group(
    app: Flask,
    label: str,
    *,
    pkg_name_exact: list[str] | None = None,
    path_prefixes: list[str] | None = None,
    risk_band: str | None = None,
    group_findings_fingerprint: str | None = None,
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            grp = ApplicationGroup(
                label=label,
                explanation=f"Test group {label}",
                path_prefixes=path_prefixes or [],
                pkg_name_exact=pkg_name_exact or [],
                pkg_name_glob=[],
                pkg_purl_pattern=[],
                source="llm",
                risk_band=risk_band,
                risk_band_source="llm" if risk_band else None,
                risk_band_computed_at=datetime.now(tz=UTC) if risk_band else None,
                group_findings_fingerprint=group_findings_fingerprint,
            )
            sess.add(grp)
            sess.flush()
            grp_id = grp.id
            sess.commit()
            return grp_id
        finally:
            sess.close()


def _all_jobs(app: Flask) -> list[LLMJob]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return list(sess.execute(select(LLMJob).order_by(LLMJob.id)).scalars().all())
        finally:
            sess.close()


def _findings(app: Flask, server_id: int) -> list[Finding]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return list(
                sess.execute(select(Finding).where(Finding.server_id == server_id)).scalars().all()
            )
        finally:
            sess.close()


def _audit_events(app: Flask, action: str) -> list[AuditEvent]:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return list(
                sess.execute(select(AuditEvent).where(AuditEvent.action == action)).scalars().all()
            )
        finally:
            sess.close()


# Vulns -------------------------------------------------------------------


def _pending_vuln(cve: str, pkg: str = "openssh-server") -> dict[str, Any]:
    """HIGH-Severity → Pre-Triage setzt `pending`."""
    return {
        "VulnerabilityID": cve,
        "PkgName": pkg,
        "InstalledVersion": "1.0",
        "Severity": "HIGH",
    }


def _noise_vuln(cve: str, pkg: str = "low-pkg") -> dict[str, Any]:
    """LOW-Severity ohne KEV/EPSS → Pre-Triage setzt `noise`."""
    return {
        "VulnerabilityID": cve,
        "PkgName": pkg,
        "InstalledVersion": "1.0",
        "Severity": "LOW",
    }


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


def test_mode_off_no_jobs_queued(db_app: Flask) -> None:
    """Mode=off: jeglicher Scan queued KEINE Jobs."""
    _set_mode(db_app, "off")
    _sid, key = register_test_server(db_app, name="srv-p-off")
    client = db_app.test_client()

    resp = _post(
        client,
        _envelope(vulns=[_pending_vuln("CVE-2024-50001")]),
        bearer=key,
    )
    assert resp.status_code == 202, resp.get_data(as_text=True)[:300]

    assert _all_jobs(db_app) == []
    assert _audit_events(db_app, "llm.jobs_queued") == []


def test_mode_observation_no_pending_findings_no_jobs(db_app: Flask) -> None:
    """Mode=observation + nur LOW-Findings (alle landen in `noise`) → keine Jobs."""
    _set_mode(db_app, "observation")
    _sid, key = register_test_server(db_app, name="srv-p-no-pending")
    client = db_app.test_client()

    resp = _post(
        client,
        _envelope(
            vulns=[_noise_vuln("CVE-2024-50010"), _noise_vuln("CVE-2024-50011", pkg="other")]
        ),
        bearer=key,
    )
    assert resp.status_code == 202

    findings = _findings(db_app, _sid)
    assert all(f.risk_band == "noise" for f in findings)

    jobs = _all_jobs(db_app)
    assert jobs == []

    # llm.jobs_queued-Audit muss aber existieren — der Hook lief, queue war leer.
    events = _audit_events(db_app, "llm.jobs_queued")
    assert len(events) == 1
    assert events[0].event_metadata is not None
    assert events[0].event_metadata["pass1_queued"] == 0
    assert events[0].event_metadata["pass2_queued"] == 0
    assert events[0].event_metadata["mode"] == "observation"


def test_mode_observation_pending_findings_empty_library_queues_pass1(
    db_app: Flask,
) -> None:
    """Mode=observation + pending Findings + leere Library → 1 Pass-1-Job."""
    _set_mode(db_app, "observation")
    _sid, key = register_test_server(db_app, name="srv-p-pass1")
    client = db_app.test_client()

    vulns = [
        _pending_vuln("CVE-2024-50020", pkg="pkg-a"),
        _pending_vuln("CVE-2024-50021", pkg="pkg-b"),
    ]
    resp = _post(client, _envelope(vulns=vulns), bearer=key)
    assert resp.status_code == 202

    findings = _findings(db_app, _sid)
    assert all(f.risk_band == "pending" for f in findings)
    assert all(f.application_group_id is None for f in findings)

    jobs = _all_jobs(db_app)
    assert len(jobs) == 1
    job = jobs[0]
    assert job.job_type == "group_detection"
    assert job.server_id == _sid
    assert job.status == "queued"
    assert job.depends_on is None
    assert set(job.payload["finding_ids"]) == {f.id for f in findings}

    events = _audit_events(db_app, "llm.jobs_queued")
    assert len(events) == 1
    assert events[0].event_metadata is not None
    assert events[0].event_metadata["pass1_queued"] == 1
    assert events[0].event_metadata["pass2_queued"] == 0


def test_mode_observation_full_library_match_queues_only_pass2(db_app: Flask) -> None:
    """Library matched alle Findings → 0 Pass-1, 1 Pass-2 ohne depends_on."""
    _set_mode(db_app, "observation")
    _insert_group(db_app, label="openssh-server", pkg_name_exact=["openssh-server"])
    _sid, key = register_test_server(db_app, name="srv-p-pass2-only")
    client = db_app.test_client()

    vulns = [
        _pending_vuln("CVE-2024-50030", pkg="openssh-server"),
        _pending_vuln("CVE-2024-50031", pkg="openssh-server"),
    ]
    resp = _post(client, _envelope(vulns=vulns), bearer=key)
    assert resp.status_code == 202

    findings = _findings(db_app, _sid)
    assert len(findings) == 2
    assert all(f.application_group_id is not None for f in findings)

    jobs = _all_jobs(db_app)
    assert len(jobs) == 1
    job = jobs[0]
    assert job.job_type == "risk_evaluation"
    assert job.server_id == _sid
    assert job.depends_on is None
    assert job.payload["server_id"] == _sid
    assert job.payload["group_id"] == findings[0].application_group_id

    events = _audit_events(db_app, "llm.jobs_queued")
    assert len(events) == 1
    assert events[0].event_metadata is not None
    assert events[0].event_metadata["pass1_queued"] == 0
    assert events[0].event_metadata["pass2_queued"] == 1


def test_mode_observation_mix_queues_pass1_and_pass2_with_dep(db_app: Flask) -> None:
    """Mix: ein Finding matcht Library, ein anderes nicht → Pass-1 + Pass-2 mit depends_on."""
    _set_mode(db_app, "observation")
    _insert_group(db_app, label="openssh-server", pkg_name_exact=["openssh-server"])
    _sid, key = register_test_server(db_app, name="srv-p-mix")
    client = db_app.test_client()

    vulns = [
        _pending_vuln("CVE-2024-50040", pkg="openssh-server"),  # → Group
        _pending_vuln("CVE-2024-50041", pkg="rare-lib"),  # → ungrouped
    ]
    resp = _post(client, _envelope(vulns=vulns), bearer=key)
    assert resp.status_code == 202

    jobs = _all_jobs(db_app)
    assert len(jobs) == 2

    pass1 = next(j for j in jobs if j.job_type == "group_detection")
    pass2 = next(j for j in jobs if j.job_type == "risk_evaluation")

    assert pass1.depends_on is None
    assert pass2.depends_on == pass1.id

    findings = _findings(db_app, _sid)
    ungrouped_ids = {f.id for f in findings if f.application_group_id is None}
    assert set(pass1.payload["finding_ids"]) == ungrouped_ids

    events = _audit_events(db_app, "llm.jobs_queued")
    assert len(events) == 1
    assert events[0].event_metadata is not None
    assert events[0].event_metadata["pass1_queued"] == 1
    assert events[0].event_metadata["pass2_queued"] == 1


def test_re_ingest_idempotent_when_group_findings_fingerprint_unchanged(
    db_app: Flask,
) -> None:
    """Group hat bereits Bewertung + stabilen Fingerprint → kein neuer Pass-2."""
    _set_mode(db_app, "observation")
    # Vorab-Setup: Group existiert, ist als `act` bewertet, hat einen
    # gespeicherten Fingerprint. Den echten Fingerprint berechnen wir nach
    # dem ersten Ingest und aktualisieren die Group entsprechend.
    grp_id = _insert_group(
        db_app,
        label="openssh-server",
        pkg_name_exact=["openssh-server"],
    )
    _sid, key = register_test_server(db_app, name="srv-p-idempotent")
    client = db_app.test_client()

    vulns = [_pending_vuln("CVE-2024-50050", pkg="openssh-server")]

    # Erster Ingest erzeugt 1 Pass-2-Job (Group hat noch keinen Fingerprint).
    resp1 = _post(client, _envelope(vulns=vulns), bearer=key)
    assert resp1.status_code == 202

    jobs_after_1 = _all_jobs(db_app)
    assert len(jobs_after_1) == 1
    assert jobs_after_1[0].job_type == "risk_evaluation"

    # Simuliere Worker-Resultat: Group bekommt risk_band + Fingerprint.
    from app.services.llm_fingerprints import group_findings_fingerprint

    findings = _findings(db_app, _sid)
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            grp = sess.get(ApplicationGroup, grp_id)
            assert grp is not None
            grp.risk_band = "act"
            grp.risk_band_source = "llm"
            grp.risk_band_computed_at = datetime.now(tz=UTC)
            grp.group_findings_fingerprint = group_findings_fingerprint(findings)
            sess.commit()
        finally:
            sess.close()

    # Zweiter Ingest mit IDENTISCHEN Findings → kein neuer Pass-2-Job.
    resp2 = _post(client, _envelope(vulns=vulns), bearer=key)
    assert resp2.status_code == 202

    jobs_after_2 = _all_jobs(db_app)
    assert len(jobs_after_2) == 1, "no new Pass-2 job expected"

    events = _audit_events(db_app, "llm.jobs_queued")
    assert len(events) == 2
    # Letztes Event: pass2_queued == 0
    last = events[-1]
    assert last.event_metadata is not None
    assert last.event_metadata["pass1_queued"] == 0
    assert last.event_metadata["pass2_queued"] == 0


def test_re_ingest_after_kev_update_does_not_requeue_pass2(db_app: Flask) -> None:
    """KEV-DB-Update aendert `cve_data_fingerprint`, aber `group_findings_fingerprint`
    bleibt stabil → Hook queued KEINEN neuen Pass-2.

    Re-Eval erfolgt im Worker via Cache-Miss (cve_data_fingerprint ist Teil
    des Cache-Keys). Dieser MVP-Kompromiss ist in ADR-0023 §"Cache-Invalidation"
    dokumentiert.
    """
    _set_mode(db_app, "observation")
    grp_id = _insert_group(
        db_app,
        label="kev-pkg",
        pkg_name_exact=["kev-pkg"],
    )
    _sid, key = register_test_server(db_app, name="srv-p-kev-update")
    client = db_app.test_client()

    base_vuln = _pending_vuln("CVE-2024-50060", pkg="kev-pkg")
    resp1 = _post(client, _envelope(vulns=[base_vuln]), bearer=key)
    assert resp1.status_code == 202

    # Simuliere Worker-Resultat → Group bewertet + Fingerprint gespeichert.
    from app.services.llm_fingerprints import group_findings_fingerprint

    findings = _findings(db_app, _sid)
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            grp = sess.get(ApplicationGroup, grp_id)
            assert grp is not None
            grp.risk_band = "act"
            grp.risk_band_source = "llm"
            grp.risk_band_computed_at = datetime.now(tz=UTC)
            grp.group_findings_fingerprint = group_findings_fingerprint(findings)
            sess.commit()
        finally:
            sess.close()

    initial_jobs = len(_all_jobs(db_app))

    # Zweiter Ingest: gleiches CVE, jetzt KEV-flagged.
    kev_vuln = dict(base_vuln)
    kev_vuln["IsKEV"] = True
    kev_vuln["CISAKEVDateAdded"] = "2024-06-01T00:00:00Z"

    resp2 = _post(client, _envelope(vulns=[kev_vuln]), bearer=key)
    assert resp2.status_code == 202

    findings2 = _findings(db_app, _sid)
    assert findings2[0].is_kev is True

    # `group_findings_fingerprint` bleibt stabil (selber identifier_key/purl),
    # daher KEIN neuer Pass-2-Job.
    jobs_after = _all_jobs(db_app)
    assert len(jobs_after) == initial_jobs

    events = _audit_events(db_app, "llm.jobs_queued")
    last = events[-1]
    assert last.event_metadata is not None
    assert last.event_metadata["pass2_queued"] == 0


def test_group_matcher_reload_picks_up_new_group_between_ingests(
    db_app: Flask,
) -> None:
    """Nach erstem Ingest legt der "Worker" (hier: direkter Insert) eine neue
    Group an. Der zweite Ingest sieht die Group sofort via `reload()` und
    gruppiert die Findings korrekt — neuer Server, sonst identische Findings.
    """
    _set_mode(db_app, "observation")
    _sid_a, key_a = register_test_server(db_app, name="srv-p-reload-a")
    _sid_b, key_b = register_test_server(db_app, name="srv-p-reload-b")
    client = db_app.test_client()

    vulns = [_pending_vuln("CVE-2024-50070", pkg="newgroup-pkg")]

    # Erster Ingest fuer Server A → keine Library, Pass-1 wird gequeued.
    resp1 = _post(client, _envelope(vulns=vulns), bearer=key_a)
    assert resp1.status_code == 202

    findings_a = _findings(db_app, _sid_a)
    assert all(f.application_group_id is None for f in findings_a)
    pass1_jobs = [j for j in _all_jobs(db_app) if j.job_type == "group_detection"]
    assert len(pass1_jobs) == 1

    # "Worker" legt die Group nachtraeglich an.
    grp_id = _insert_group(
        db_app,
        label="newgroup",
        pkg_name_exact=["newgroup-pkg"],
    )

    # Zweiter Ingest fuer Server B → `reload()` sieht die neue Group, das
    # neue Finding wird sofort gruppiert, kein Pass-1, dafuer ein Pass-2.
    resp2 = _post(client, _envelope(vulns=vulns), bearer=key_b)
    assert resp2.status_code == 202

    findings_b = _findings(db_app, _sid_b)
    assert all(f.application_group_id == grp_id for f in findings_b)

    # Server-B-Jobs: 0 Pass-1 (alle gematcht), 1 Pass-2.
    server_b_jobs = [j for j in _all_jobs(db_app) if j.server_id == _sid_b]
    assert len(server_b_jobs) == 1
    assert server_b_jobs[0].job_type == "risk_evaluation"
    assert server_b_jobs[0].payload["group_id"] == grp_id


# ---------------------------------------------------------------------------
# v0.9.4 — Pass-1-Batching mit Affinity-Sort
# ---------------------------------------------------------------------------


def _many_pending_vulns(count: int, *, pkg_prefix: str = "pkg") -> list[dict[str, Any]]:
    """Erzeugt ``count`` distinkte HIGH-Severity-Vulns mit verschiedenen Paketen."""
    return [
        _pending_vuln(f"CVE-2024-{50_000 + i:05d}", pkg=f"{pkg_prefix}-{i:03d}")
        for i in range(count)
    ]


def test_pass1_creates_single_job_when_under_batch_size(db_app: Flask) -> None:
    """50 ungrouped Findings + Default-Batch-Size=100 → genau 1 group_detection-Job."""
    _set_mode(db_app, "observation")
    _sid, key = register_test_server(db_app, name="srv-p-batch-small")
    client = db_app.test_client()

    resp = _post(client, _envelope(vulns=_many_pending_vulns(50)), bearer=key)
    assert resp.status_code == 202, resp.get_data(as_text=True)[:300]

    pass1_jobs = [j for j in _all_jobs(db_app) if j.job_type == "group_detection"]
    assert len(pass1_jobs) == 1
    assert len(pass1_jobs[0].payload["finding_ids"]) == 50

    events = _audit_events(db_app, "llm.jobs_queued")
    assert events[-1].event_metadata is not None
    assert events[-1].event_metadata["pass1_queued"] == 1
    assert events[-1].event_metadata["pass1_batch_size"] == 100


def test_pass1_splits_into_batches(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """250 Findings + Batch-Size=100 → 3 Jobs mit Groessen [100, 100, 50]."""
    _set_mode(db_app, "observation")
    _sid, key = register_test_server(db_app, name="srv-p-batch-split")
    client = db_app.test_client()

    resp = _post(client, _envelope(vulns=_many_pending_vulns(250)), bearer=key)
    assert resp.status_code == 202, resp.get_data(as_text=True)[:300]

    pass1_jobs = [
        j for j in _all_jobs(db_app) if j.job_type == "group_detection" and j.server_id == _sid
    ]
    pass1_jobs.sort(key=lambda j: j.id)
    sizes = [len(j.payload["finding_ids"]) for j in pass1_jobs]
    assert sizes == [100, 100, 50]

    # Keine Finding-ID landet in zwei Batches.
    all_ids: list[int] = []
    for job in pass1_jobs:
        all_ids.extend(job.payload["finding_ids"])
    assert len(all_ids) == len(set(all_ids)) == 250

    events = _audit_events(db_app, "llm.jobs_queued")
    assert events[-1].event_metadata is not None
    assert events[-1].event_metadata["pass1_queued"] == 3
    assert events[-1].event_metadata["pass1_batch_size"] == 100


def _set_batch_size(app: Flask, size: int) -> None:
    """Setzt llm_pass1_findings_per_batch im App-Settings-Singleton."""
    from app.config import Settings

    settings: Settings = app.config["SECSCAN_SETTINGS"]
    # Pydantic v2 BaseSettings: Field-Assign ist erlaubt mit model_copy oder
    # direkt via __dict__ — wir mutieren in-place fuer den Test.
    object.__setattr__(settings, "llm_pass1_findings_per_batch", size)


def test_pass1_affinity_sort_groups_by_path_prefix(db_app: Flask) -> None:
    """6 Findings mit zwei verschiedenen Top-3-Pfad-Prefixen, Batch-Size=3.

    Erwartung: Batch 1 enthaelt ausschliesslich Findings aus einem Pfad-Cluster,
    Batch 2 enthaelt ausschliesslich Findings des anderen.
    """
    _set_batch_size(db_app, 3)
    _set_mode(db_app, "observation")
    _sid, key = register_test_server(db_app, name="srv-p-affinity")
    client = db_app.test_client()

    # 3 Lang-Pkg-Findings unter /home/webapp/...
    # 3 OS-Pkg-Findings (kein target_path == "" → eigener Bucket)
    webapp_vulns = [
        {
            "VulnerabilityID": f"CVE-2024-60{i:03d}",
            "PkgName": f"flask-dep-{i}",
            "InstalledVersion": "1.0",
            "Severity": "HIGH",
            "PkgPath": f"/home/webapp/lib/dep{i}.py",
        }
        for i in range(3)
    ]
    # OS-Pkgs (kein PkgPath in Trivy-Output → target_path bleibt leer/parent).
    os_vulns = [_pending_vuln(f"CVE-2024-70{i:03d}", pkg=f"sys-pkg-{i}") for i in range(3)]

    # Trivy-Envelope mit zwei Results: einer lang-pkgs (mit Pfaden), einer os-pkgs.
    envelope = {
        "agent_version": "0.3.0",
        "host": {
            "os_family": "ubuntu",
            "os_version": "22.04",
            "os_pretty_name": "Ubuntu 22.04",
            "kernel_version": "5.15.0",
            "architecture": "x86_64",
            "trivy_version": "0.70.2",
        },
        "scan": {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.70.2"},
            "Results": [
                {
                    "Target": "/home/webapp/Pipfile.lock",
                    "Class": "lang-pkgs",
                    "Type": "pipenv",
                    "Vulnerabilities": webapp_vulns,
                },
                {
                    "Target": "ubuntu",
                    "Class": "os-pkgs",
                    "Type": "ubuntu",
                    "Vulnerabilities": os_vulns,
                },
            ],
        },
        "host_state": _minimal_host_state(),
    }
    resp = _post(client, envelope, bearer=key)
    assert resp.status_code == 202, resp.get_data(as_text=True)[:300]

    pass1_jobs = [
        j for j in _all_jobs(db_app) if j.job_type == "group_detection" and j.server_id == _sid
    ]
    pass1_jobs.sort(key=lambda j: j.id)
    assert len(pass1_jobs) == 2, [len(j.payload["finding_ids"]) for j in pass1_jobs]

    findings = _findings(db_app, _sid)
    by_id = {f.id: f for f in findings}

    def _cluster(finding_ids: list[int]) -> set[str]:
        clusters: set[str] = set()
        for fid in finding_ids:
            f = by_id[fid]
            tp = f.target_path or ""
            if tp.startswith("/home/webapp"):
                clusters.add("webapp")
            else:
                clusters.add("os")
        return clusters

    clusters_batch0 = _cluster(pass1_jobs[0].payload["finding_ids"])
    clusters_batch1 = _cluster(pass1_jobs[1].payload["finding_ids"])
    # Jeder Batch hat genau einen Cluster (keine Vermischung).
    assert len(clusters_batch0) == 1
    assert len(clusters_batch1) == 1
    # Die beiden Batches haben verschiedene Cluster.
    assert clusters_batch0 != clusters_batch1


def test_pass2_depends_on_last_pass1_job(db_app: Flask) -> None:
    """Bei mehreren Pass-1-Batches zeigt Pass-2.depends_on auf den HOECHSTEN
    Pass-1-Job (Worker verarbeitet ORDER BY created_at, der letzte ist erst
    `done` wenn alle vorherigen durch sind)."""
    _set_batch_size(db_app, 50)
    _set_mode(db_app, "observation")
    # Bestehende Library-Group, damit auch ein Pass-2-Job entsteht.
    _insert_group(db_app, label="grouped-pkg", pkg_name_exact=["grouped-pkg"])
    _sid, key = register_test_server(db_app, name="srv-p-batch-dep")
    client = db_app.test_client()

    # 120 ungrouped + 1 grouped (matched library).
    ungrouped = _many_pending_vulns(120, pkg_prefix="ungroup")
    grouped = [_pending_vuln("CVE-2024-99999", pkg="grouped-pkg")]
    resp = _post(client, _envelope(vulns=ungrouped + grouped), bearer=key)
    assert resp.status_code == 202

    server_jobs = [j for j in _all_jobs(db_app) if j.server_id == _sid]
    pass1_jobs = sorted(
        (j for j in server_jobs if j.job_type == "group_detection"),
        key=lambda j: j.id,
    )
    pass2_jobs = [j for j in server_jobs if j.job_type == "risk_evaluation"]

    assert len(pass1_jobs) == 3  # 120 / 50 → 50,50,20
    assert len(pass2_jobs) == 1
    assert pass2_jobs[0].depends_on == pass1_jobs[-1].id


def test_jobs_queued_audit_includes_batches_count(db_app: Flask) -> None:
    """Audit-Event ``llm.jobs_queued`` enthaelt ``pass1_queued=N`` und
    ``pass1_batch_size`` (= konfigurierte Cap)."""
    _set_batch_size(db_app, 50)
    _set_mode(db_app, "observation")
    _sid, key = register_test_server(db_app, name="srv-p-batch-audit")
    client = db_app.test_client()

    resp = _post(client, _envelope(vulns=_many_pending_vulns(120)), bearer=key)
    assert resp.status_code == 202

    events = _audit_events(db_app, "llm.jobs_queued")
    assert len(events) == 1
    meta = events[0].event_metadata
    assert meta is not None
    assert meta["pass1_queued"] == 3
    assert meta["pass1_batch_size"] == 50
