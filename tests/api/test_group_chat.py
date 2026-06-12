"""Pure-Unit-/Mock-Tests fuer das Per-Group-Chat-Blueprint (ADR-0055, Block AE).

Bewusst DB-FREI: statt der echten Per-Request-Session wird
``app.api.group_chat.get_session`` auf eine ``_FakeSession``-Spy gepatcht, die
``execute``-Aufrufe nach Statement-Form klassifiziert. Die aus
``server_detail`` importierten Loader (``_load_host_snapshot``,
``_load_application_groups_for_server``) werden im ``group_chat``-Modul-
Namespace gepatcht. Auth wird via ``LOGIN_DISABLED=True`` neutralisiert; CSRF
wird in einem eigenen ``WTF_CSRF_ENABLED=True``-App-Pfad geprueft.

So laufen 404-Guard-, Lazy-Create-, Resume-, Delete- und SSE-Generator-Asserts
ohne echtes Postgres. Die DB-Roundtrip-/Live-Provider-Tests (UNIQUE-Constraint,
CASCADE-Delete, SSE-E2E) stehen beim User an (db_integration/integration) und
sind hier NICHT dupliziert.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from flask import Flask

import app.api.group_chat as gc
from app.models import ChatMessageRole, Severity

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _ExecResult:
    """Minimaler Stand-in fuer das SQLAlchemy-`Result`-Objekt."""

    def __init__(self, *, rows: list[Any] | None = None) -> None:
        self._rows = rows or []

    def scalar_one_or_none(self) -> Any:
        return self._rows[0] if self._rows else None

    def scalar_one(self) -> Any:
        return self._rows[0]

    def scalars(self) -> _ExecResult:
        return self

    def all(self) -> list[Any]:
        return list(self._rows)


class _FakeFinding:
    """Stand-in fuer ein OPEN-Finding der Group (volles ORM-Objekt-Surrogat).

    Traegt genug Felder fuer ``select_pass2_findings`` (ADR-0058): Triage-Key
    (``is_kev``/``epss_score``/``cvss_v3_score``/``severity``/``first_seen_at``/
    ``identifier_key``/``id``) plus Pfad-/Fix-Felder fuer Quote und Aggregat.
    """

    def __init__(
        self,
        fid: int,
        *,
        severity: Severity = Severity.HIGH,
        is_kev: bool = False,
        epss: float = 0.1,
        fixed_version: str | None = "1.0.1",
    ) -> None:
        self.id = fid
        self.identifier_key = f"CVE-2026-{fid:04d}"
        self.title = "demo finding"
        self.severity = severity
        self.cvss_v3_score = 7.5
        self.epss_score = epss
        self.is_kev = is_kev
        self.attack_vector = "network"
        self.first_seen_at = datetime(2026, 5, 1, tzinfo=UTC)
        self.target_path = None
        self.package_name = f"pkg-{fid}"
        self.fixed_version = fixed_version


class _FakeServer:
    def __init__(self, sid: int, *, revoked: bool = False, retired: bool = False) -> None:
        self.id = sid
        self.name = f"host-{sid}"
        self.os_pretty_name = "Debian 12"
        self.kernel_version = "6.1.0"
        self.architecture = "x86_64"
        self.last_scan_at = None
        self.tag_links: list[Any] = []
        self.revoked_at = "X" if revoked else None
        self.retired_at = "X" if retired else None


class _FakeConversation:
    def __init__(self, cid: int = 1) -> None:
        self.id = cid
        self.server_id = 1
        self.application_group_id = 1
        self.model = "deepseek-ai/DeepSeek-V3"
        self.last_message_at: Any = None
        self.findings_snapshot_at: Any = None


class _FakeMessage:
    def __init__(self, role: ChatMessageRole, content: str, mid: int = 1) -> None:
        self.id = mid
        self.role = role
        self.content = content


class _FakeSettings:
    def __init__(self, *, configured: bool = True) -> None:
        self.llm_base_url = "https://api.example.com/v1" if configured else None
        self.llm_model = "deepseek-ai/DeepSeek-V3" if configured else None
        self.llm_api_key_encrypted = b"enc" if configured else None


class _FakeSession:
    """Spy-Session: klassifiziert `execute`-Calls anhand der SQL-Form.

    Konfigurierbar pro Test:
      - ``server``:        das Server-Surrogat (oder None -> 404).
      - ``open_findings``: OPEN-Findings der Group (leer -> 404).
      - ``conversation``:  bestehende Konversation (oder None).
      - ``messages``:      Verlauf der Konversation (chronologisch).
    """

    def __init__(
        self,
        *,
        server: _FakeServer | None = None,
        open_findings: list[Any] | None = None,
        conversation: _FakeConversation | None = None,
        messages: list[Any] | None = None,
    ) -> None:
        self.server = server
        self.open_findings = open_findings if open_findings is not None else []
        self.conversation = conversation
        self.messages = messages if messages is not None else []

        self.added: list[Any] = []
        self.deleted_statements: list[Any] = []
        self.flush_count = 0
        self.commit_count = 0
        self.flushed_ids = 0

    @staticmethod
    def _sql(stmt: Any) -> str:
        try:
            return str(stmt).lower()
        except Exception:  # pragma: no cover - defensiv
            return ""

    def execute(self, stmt: Any, params: Any = None) -> _ExecResult:
        sql = self._sql(stmt)
        if sql.startswith("delete"):
            self.deleted_statements.append(stmt)
            return _ExecResult()
        # Server-Guard-SELECT.
        if "from servers" in sql:
            return _ExecResult(rows=[self.server] if self.server is not None else [])
        # Group-OPEN-Findings-Guard.
        if "from findings" in sql:
            return _ExecResult(rows=list(self.open_findings))
        # Conversation-Lookup.
        if "from group_chat_conversations" in sql:
            return _ExecResult(rows=[self.conversation] if self.conversation else [])
        # Message-Verlauf.
        if "from group_chat_messages" in sql:
            return _ExecResult(rows=list(self.messages))
        return _ExecResult(rows=[])

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    def flush(self) -> None:
        self.flush_count += 1
        # Simuliere PK-Vergabe auf neu hinzugefuegten Konversationen.
        for obj in self.added:
            if isinstance(obj, gc.GroupChatConversation) and getattr(obj, "id", None) is None:
                self.flushed_ids += 1
                obj.id = 99

    def commit(self) -> None:
        self.commit_count += 1


# ---------------------------------------------------------------------------
# Fixtures + Patch-Helper
# ---------------------------------------------------------------------------


@pytest.fixture
def nodb_app(app: Flask) -> Flask:
    """App mit deaktiviertem Login + neutralisiertem Limiter — kein DB-Touch."""
    import contextlib

    from app import limiter

    app.config.update(TESTING=True, LOGIN_DISABLED=True, WTF_CSRF_ENABLED=False)
    with contextlib.suppress(Exception):
        limiter.reset()
    return app


@pytest.fixture
def csrf_app(app: Flask) -> Flask:
    """App mit aktiviertem CSRF + deaktiviertem Login (CSRF-Guard-Test)."""
    import contextlib

    from app import limiter

    app.config.update(TESTING=True, LOGIN_DISABLED=True, WTF_CSRF_ENABLED=True)
    with contextlib.suppress(Exception):
        limiter.reset()
    return app


def _patch(monkeypatch: pytest.MonkeyPatch, sess: _FakeSession, **over: Any) -> None:
    """Patcht Session + Settings + die importierten server_detail-Loader.

    Default-Stubs koennen pro Test ueberschrieben werden (``over``).
    """
    monkeypatch.setattr(gc, "get_session", lambda: sess)
    monkeypatch.setattr(
        gc, "get_settings_row", over.get("settings_row", lambda _s=None: _FakeSettings())
    )
    monkeypatch.setattr(
        gc,
        "_load_host_snapshot",
        over.get(
            "host_snapshot",
            lambda _s, _sid: {"listeners": [], "services": [], "processes": []},
        ),
    )
    monkeypatch.setattr(
        gc,
        "_load_application_groups_for_server",
        over.get("groups", lambda _s, _sid: _default_groups()),
    )
    # Template-Renderer stubs — wir pruefen Kontext-/Persistenz-Ebene, nicht
    # echtes Jinja-Rendering (Templates existieren erst in Phase 4).
    monkeypatch.setattr(gc, "_render_chat_view", over.get("render_view", _stub_render_view))
    monkeypatch.setattr(gc, "_user_bubble_partial", over.get("bubble", _stub_bubble))


def _default_groups() -> list[dict[str, Any]]:
    """Lane-Kontrakt-Surrogat fuer Group 1 (eine patch-Lane mit Eval)."""

    class _Grp:
        id = 1
        label = "openssl"
        group_kind = "os_package"
        explanation = ""

    class _Eval:
        risk_band = "escalate"
        risk_band_reason = "KEV exploited in the wild"

    class _Worst:
        identifier_key = "CVE-2026-0001"
        title = "demo worst"

    return [
        {
            "group": _Grp(),
            "count": 1,
            "lanes": [
                {
                    "fix_lane": "patch",
                    "evaluation": _Eval(),
                    "count": 1,
                    "worst_finding": _Worst(),
                    "worst_finding_drift": False,
                }
            ],
        }
    ]


def _stub_render_view(server: Any, sid: int, gid: int, conv: Any, findings: Any) -> str:
    return f"VIEW sid={sid} gid={gid} conv={'yes' if conv else 'none'} n={len(findings)}"


def _stub_bubble(message: Any, sid: int, gid: int) -> str:
    return f"BUBBLE {message.content}"


# ===========================================================================
# 404-Guards (IDOR)
# ===========================================================================


def test_404_cross_server_unknown_server(nodb_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Server existiert nicht -> 404 (Cross-Server-Probing)."""
    sess = _FakeSession(server=None, open_findings=[_FakeFinding(1)])
    _patch(monkeypatch, sess)
    resp = nodb_app.test_client().get("/servers/1/groups/1/chat")
    assert resp.status_code == 404


def test_404_revoked_server(nodb_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Revoked Server -> 404 (Chat nur fuer aktive Hosts)."""
    sess = _FakeSession(server=_FakeServer(1, revoked=True), open_findings=[_FakeFinding(1)])
    _patch(monkeypatch, sess)
    resp = nodb_app.test_client().get("/servers/1/groups/1/chat")
    assert resp.status_code == 404


def test_404_cross_group_no_open_findings(nodb_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Group hat keine OPEN-Findings auf diesem Server -> 404 (Cross-Group-Probing)."""
    sess = _FakeSession(server=_FakeServer(1), open_findings=[])
    _patch(monkeypatch, sess)
    resp = nodb_app.test_client().get("/servers/1/groups/9999/chat")
    assert resp.status_code == 404


def test_show_renders_when_guard_passes(nodb_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Aktiver Server + OPEN-Findings -> 200, rendert die Sub-View."""
    sess = _FakeSession(server=_FakeServer(1), open_findings=[_FakeFinding(1)], conversation=None)
    _patch(monkeypatch, sess)
    resp = nodb_app.test_client().get("/servers/1/groups/1/chat")
    assert resp.status_code == 200
    assert b"conv=none" in resp.data
    # GET legt nichts an.
    assert sess.commit_count == 0
    assert sess.added == []


# ===========================================================================
# POST /messages — llm_not_configured + Lazy-Create + Resume
# ===========================================================================


def test_post_message_llm_not_configured_400(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlender Provider -> 400 llm_not_configured (kein Snapshot gebaut)."""
    sess = _FakeSession(server=_FakeServer(1), open_findings=[_FakeFinding(1)])
    _patch(monkeypatch, sess, settings_row=lambda _s=None: _FakeSettings(configured=False))
    resp = nodb_app.test_client().post("/servers/1/groups/1/chat/messages", json={"content": "hi"})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "llm_not_configured"
    assert sess.added == []


def test_post_message_lazy_create_builds_snapshot(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Erster POST ohne Konversation -> Lazy-Create: Conversation + System + User.

    Prueft: System-Prompt persistiert, ``findings_snapshot_at``/``model`` gesetzt,
    Snapshot via ``build_group_system_prompt`` gebaut (host_snapshot konsumiert).
    """
    sess = _FakeSession(server=_FakeServer(1), open_findings=[_FakeFinding(1)], conversation=None)
    snapshot_calls: list[Any] = []

    def _spy_snapshot(_s: Any, _sid: int) -> dict[str, Any]:
        snapshot_calls.append((_s, _sid))
        return {"listeners": [], "services": ["nginx"], "processes": []}

    _patch(monkeypatch, sess, host_snapshot=_spy_snapshot)
    resp = nodb_app.test_client().post(
        "/servers/1/groups/1/chat/messages", json={"content": "explain"}
    )
    assert resp.status_code == 200
    # Snapshot-Loader wurde genutzt (Lazy-Create-Pfad).
    assert snapshot_calls == [(sess, 1)]

    convs = [o for o in sess.added if isinstance(o, gc.GroupChatConversation)]
    msgs = [o for o in sess.added if isinstance(o, gc.GroupChatMessage)]
    assert len(convs) == 1
    conv = convs[0]
    assert conv.model == "deepseek-ai/DeepSeek-V3"
    assert conv.findings_snapshot_at is not None
    # Genau eine System-Message (Snapshot-Prompt) + eine User-Message.
    roles = [m.role for m in msgs]
    assert roles.count(ChatMessageRole.SYSTEM) == 1
    assert roles.count(ChatMessageRole.USER) == 1
    system_msg = next(m for m in msgs if m.role == ChatMessageRole.SYSTEM)
    # Marker-Disziplin: der eingefrorene Prompt traegt den Daten-Marker.
    assert gc.build_group_system_prompt.__name__  # importiert
    assert "<<TRIVY_DATA_START>>" in system_msg.content
    assert sess.commit_count == 1
    body = resp.get_json()
    assert body["stream_url"].endswith("/servers/1/groups/1/chat/stream")
    assert "bubble_html" in body


def test_post_message_lazy_create_trims_findings_and_aggregates(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-0058: bei > Budget Findings traegt der Snapshot nur die wichtigsten
    ``GROUP_CHAT_FINDINGS_BUDGET`` Findings-Zeilen + eine Aggregat-Zeile."""
    from app.services.group_chat_prompt import GROUP_CHAT_FINDINGS_BUDGET

    findings = [_FakeFinding(i) for i in range(1, 31)]  # 30 > Budget (15)
    sess = _FakeSession(server=_FakeServer(1), open_findings=findings, conversation=None)
    _patch(monkeypatch, sess)
    resp = nodb_app.test_client().post(
        "/servers/1/groups/1/chat/messages", json={"content": "explain"}
    )
    assert resp.status_code == 200

    msgs = [o for o in sess.added if isinstance(o, gc.GroupChatMessage)]
    system_msg = next(m for m in msgs if m.role == ChatMessageRole.SYSTEM)
    content = system_msg.content
    # Genau Budget viele einzelne Findings-Zeilen (jede traegt "| sev=").
    assert content.count("| sev=") == GROUP_CHAT_FINDINGS_BUDGET
    # Aggregat-Zeile fuer den Rest (30 - 15 = 15).
    rest = len(findings) - GROUP_CHAT_FINDINGS_BUDGET
    assert f"{rest} more findings not shown" in content


def test_chat_findings_context_truncated() -> None:
    """Reiner Kontext-Helper (kein Flask): > Budget -> truncated + Zahlen."""
    from app.services.group_chat_prompt import GROUP_CHAT_FINDINGS_BUDGET

    ctx = gc._chat_findings_context([_FakeFinding(i) for i in range(1, 31)])
    assert ctx["findings_total"] == 30
    assert ctx["findings_shown"] == GROUP_CHAT_FINDINGS_BUDGET
    assert ctx["findings_truncated"] is True


def test_chat_findings_context_no_truncation() -> None:
    """<= Budget -> kein Trim, kein Hinweis."""
    ctx = gc._chat_findings_context([_FakeFinding(1), _FakeFinding(2)])
    assert ctx == {"findings_total": 2, "findings_shown": 2, "findings_truncated": False}


def test_post_message_resume_no_new_snapshot(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Zweiter POST mit bestehender Konversation -> KEIN neuer Snapshot.

    Prueft Resume vs. Create: keine neue Conversation, keine System-Message,
    der host_snapshot-Loader wird NICHT aufgerufen.
    """
    existing = _FakeConversation(cid=7)
    sess = _FakeSession(
        server=_FakeServer(1), open_findings=[_FakeFinding(1)], conversation=existing
    )
    snapshot_calls: list[Any] = []

    def _spy_snapshot(_s: Any, _sid: int) -> dict[str, Any]:
        snapshot_calls.append((_s, _sid))  # pragma: no cover — darf nicht laufen
        return {"listeners": [], "services": [], "processes": []}

    _patch(monkeypatch, sess, host_snapshot=_spy_snapshot)
    resp = nodb_app.test_client().post(
        "/servers/1/groups/1/chat/messages", json={"content": "follow up"}
    )
    assert resp.status_code == 200
    # Resume-Pfad: Snapshot-Loader nicht angefasst.
    assert snapshot_calls == []
    convs = [o for o in sess.added if isinstance(o, gc.GroupChatConversation)]
    msgs = [o for o in sess.added if isinstance(o, gc.GroupChatMessage)]
    assert convs == []
    assert len(msgs) == 1
    assert msgs[0].role == ChatMessageRole.USER
    assert msgs[0].conversation_id == 7
    # last_message_at der bestehenden Konversation aktualisiert.
    assert existing.last_message_at is not None


def test_post_message_rejects_empty_content(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Leerer Content -> 400 invalid_content."""
    sess = _FakeSession(server=_FakeServer(1), open_findings=[_FakeFinding(1)])
    _patch(monkeypatch, sess)
    resp = nodb_app.test_client().post("/servers/1/groups/1/chat/messages", json={"content": "   "})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_content"


# ===========================================================================
# CSRF
# ===========================================================================


def test_csrf_protects_post_messages(csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """POST ohne CSRF-Token -> 400 (Flask-WTF CSRFProtect)."""
    sess = _FakeSession(server=_FakeServer(1), open_findings=[_FakeFinding(1)])
    _patch(monkeypatch, sess)
    resp = csrf_app.test_client().post("/servers/1/groups/1/chat/messages", json={"content": "hi"})
    assert resp.status_code == 400


def test_csrf_protects_post_new(csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """POST /new ohne CSRF-Token -> 400."""
    sess = _FakeSession(server=_FakeServer(1), open_findings=[_FakeFinding(1)])
    _patch(monkeypatch, sess)
    resp = csrf_app.test_client().post("/servers/1/groups/1/chat/new")
    assert resp.status_code == 400


# ===========================================================================
# POST /new — Delete
# ===========================================================================


def test_new_chat_deletes_exactly_this_conversation(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """New-Chat -> DELETE-Statement trifft genau (server_id, group_id)."""
    sess = _FakeSession(
        server=_FakeServer(1),
        open_findings=[_FakeFinding(1)],
        conversation=_FakeConversation(),
    )
    _patch(monkeypatch, sess)
    resp = nodb_app.test_client().post("/servers/1/groups/1/chat/new")
    assert resp.status_code == 200
    assert len(sess.deleted_statements) == 1
    sql = str(sess.deleted_statements[0]).lower()
    assert sql.startswith("delete from group_chat_conversations")
    assert "server_id" in sql
    assert "application_group_id" in sql
    assert sess.commit_count == 1


# ===========================================================================
# SSE-Stream
# ===========================================================================


class _FakeUsage:
    prompt_tokens = 42
    completion_tokens = 7


class _FakeClient:
    """Mock-LlmClient: streamt vorgegebene Deltas, fuehrt last_usage."""

    def __init__(self, deltas: list[str]) -> None:
        self._deltas = deltas
        self.last_usage = _FakeUsage()
        self.closed = False

    async def stream_chat(self, _history: Any) -> Any:
        for d in self._deltas:
            yield d

    async def aclose(self) -> None:
        self.closed = True


def test_stream_no_conversation_404(nodb_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Stream ohne bestehende Konversation -> 404 no_conversation."""
    sess = _FakeSession(server=_FakeServer(1), open_findings=[_FakeFinding(1)], conversation=None)
    _patch(monkeypatch, sess)
    resp = nodb_app.test_client().get("/servers/1/groups/1/chat/stream")
    assert resp.status_code == 404
    assert resp.get_json()["error"] == "no_conversation"


def test_stream_emits_delta_and_done_frames_and_persists(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SSE-Generator: Delta-Frames im data:-Format + done-Frame.

    Zusaetzlich: Assistant-Message + Usage werden nach Stream-Ende persistiert.
    Die frische Worker-Session wird durch eine Spy ersetzt.
    """
    conv = _FakeConversation(cid=5)
    sess = _FakeSession(
        server=_FakeServer(1),
        open_findings=[_FakeFinding(1)],
        conversation=conv,
        messages=[
            _FakeMessage(ChatMessageRole.SYSTEM, "sysprompt", 1),
            _FakeMessage(ChatMessageRole.USER, "explain", 2),
        ],
    )
    _patch(monkeypatch, sess)

    # Mock-Client statt echtem Provider.
    fake_client = _FakeClient(["Hel", "lo"])
    monkeypatch.setattr(gc, "build_client_from_settings", lambda _s, **_k: fake_client)

    # Frische Persistenz-Session abfangen (kein echtes Engine-Bind).
    persisted: dict[str, Any] = {}

    def _spy_persist(conv_id: int, chunks: list[str], pt: int | None, ct: int | None) -> None:
        persisted["conv_id"] = conv_id
        persisted["text"] = "".join(chunks)
        persisted["prompt_tokens"] = pt
        persisted["completion_tokens"] = ct

    monkeypatch.setattr(gc, "_persist_assistant", _spy_persist)

    resp = nodb_app.test_client().get("/servers/1/groups/1/chat/stream")
    assert resp.status_code == 200
    assert resp.mimetype == "text/event-stream"
    assert resp.headers["Cache-Control"] == "no-cache"
    assert resp.headers["X-Accel-Buffering"] == "no"

    body = resp.get_data(as_text=True)
    # Delta-Frames im data:-Format.
    assert "data: Hel\n" in body
    assert "data: lo\n" in body
    # done-Frame mit Usage-JSON.
    assert "event: done\n" in body
    done_line = next(line for line in body.splitlines() if line.startswith("data: {"))
    payload = json.loads(done_line[len("data: ") :])
    assert payload["prompt_tokens"] == 42
    assert payload["completion_tokens"] == 7
    assert payload["conversation_id"] == 5

    # Assistant-Persistenz nach Stream-Ende.
    assert persisted["conv_id"] == 5
    assert persisted["text"] == "Hello"
    assert persisted["prompt_tokens"] == 42
    assert persisted["completion_tokens"] == 7
    assert fake_client.closed is True


def test_stream_provider_error_emits_generic_error_frame(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Provider-Fehler -> generischer error-Frame, kein Exception-/Key-Leak."""
    conv = _FakeConversation(cid=5)
    sess = _FakeSession(
        server=_FakeServer(1),
        open_findings=[_FakeFinding(1)],
        conversation=conv,
        messages=[_FakeMessage(ChatMessageRole.SYSTEM, "sysprompt", 1)],
    )
    _patch(monkeypatch, sess)

    class _BoomClient:
        last_usage = _FakeUsage()

        async def stream_chat(self, _history: Any) -> Any:
            raise RuntimeError("secret-key-abc123 leaked in message")
            yield  # pragma: no cover

        async def aclose(self) -> None:
            return None

    monkeypatch.setattr(gc, "build_client_from_settings", lambda _s, **_k: _BoomClient())
    monkeypatch.setattr(gc, "_persist_assistant", lambda *a, **k: None)

    resp = nodb_app.test_client().get("/servers/1/groups/1/chat/stream")
    body = resp.get_data(as_text=True)
    assert "event: error\n" in body
    assert "provider_error" in body
    # Kein Leak des Exception-Texts/Key-Fragments.
    assert "secret-key-abc123" not in body
