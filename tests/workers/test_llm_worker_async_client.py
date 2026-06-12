"""Pure-Unit-Tests fuer Block U Phase B — Persistenter Async-Client mit
Fingerprint-Cache (siehe ``docs/blocks/U-worker-concurrency.md``).

Getestet werden ausschliesslich die neuen Helper in
``app.workers.llm_worker``:

* :func:`_compute_client_fingerprint` (Determinismus + Sensitivitaet pro Feld).
* :func:`_get_or_build_async_client` (Build-on-first-call, Reuse,
  Rebuild bei Fingerprint-Mismatch, Aclose-auf-altem-Client).
* :func:`reset_client_cache_for_tests` (Modul-State sauber leeren).
* :func:`_aclose_reviewer_client` (defensiv ohne ``.client``-Attribut).

Alle Tests verwenden Mocks fuer ``build_client_from_settings`` und
``ensure_settings_row`` / ``decrypt_api_key`` / ``load_settings`` — kein
echter Postgres-Zugriff, keine echten ``AsyncOpenAI``-Instanzen.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.workers import llm_worker

# ---------------------------------------------------------------------------
# Setup-Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_client_cache() -> Iterator[None]:
    """Stellt sicher dass jeder Test mit leerem Client-Cache startet."""
    llm_worker.reset_client_cache_for_tests()
    # Test-Hook-Factory ebenfalls neutralisieren — manche Tests setzen sie.
    llm_worker.set_reviewer_factory_for_tests(None)
    yield
    llm_worker.reset_client_cache_for_tests()
    llm_worker.set_reviewer_factory_for_tests(None)


@pytest.fixture(autouse=True)
def _reset_worker_logger_state() -> Iterator[None]:
    """Defensive Logger-State-Reset gegen Test-Pollution.

    Vorhergehende Tests (insb. solche die ``configure_logging()`` / einen
    ``dictConfig``-Lauf triggern) hinterlassen den ``fathometer.llm_worker``-
    Logger gelegentlich mit ``disabled=True`` oder ``propagate=False``,
    wodurch ``caplog.set_level(...)`` allein nicht ausreicht. Wir setzen
    den Zustand vor jedem Test auf einen bekannten Default und stellen
    nach dem Test den Original-Zustand wieder her, damit andere Tests
    nicht beeinflusst werden.
    """
    worker_logger = logging.getLogger("fathometer.llm_worker")
    prev_disabled = worker_logger.disabled
    prev_propagate = worker_logger.propagate
    prev_level = worker_logger.level
    worker_logger.disabled = False
    worker_logger.propagate = True
    try:
        yield
    finally:
        worker_logger.disabled = prev_disabled
        worker_logger.propagate = prev_propagate
        worker_logger.level = prev_level


def _make_settings_row(
    *,
    base_url: str = "https://api.deepinfra.com/v1/openai",
    model: str = "deepseek-ai/DeepSeek-V3",
    chat_model: str = "deepseek-ai/DeepSeek-V4-Flash",
    api_key_encrypted: bytes | None = b"ciphertext-A",
) -> SimpleNamespace:
    """Leichtgewichtiger Stand-in fuer eine ``Setting``-Row.

    Traegt beide Modell-Felder (ADR-0057): der Reviewer-Pfad liest
    ``llm_reviewer_model``; ``llm_chat_model`` ist bewusst gesetzt um zu
    verifizieren, dass der Reviewer-Fingerprint es **nicht** mitfuehrt.
    """
    return SimpleNamespace(
        llm_base_url=base_url,
        llm_reviewer_model=model,
        llm_chat_model=chat_model,
        llm_api_key_encrypted=api_key_encrypted,
    )


def _make_fake_client(*, model: str = "deepseek-ai/DeepSeek-V3") -> MagicMock:
    """Mock-``LlmClient`` mit ``.model``-Property und ``aclose`` als AsyncMock."""
    client = MagicMock(spec_set=["model", "aclose"])
    client.model = model
    client.aclose = AsyncMock()
    return client


def _patch_settings_chain(
    monkeypatch: pytest.MonkeyPatch,
    *,
    settings_row: SimpleNamespace,
    plain_keys: list[str],
    fake_clients: list[MagicMock],
) -> dict[str, Any]:
    """Patcht ``ensure_settings_row``, ``decrypt_api_key``, ``load_settings``
    und ``build_client_from_settings`` im ``llm_worker``-Modul.

    ``plain_keys`` und ``fake_clients`` werden in der Reihenfolge der
    Aufrufe konsumiert. Returnt ein Dict mit den Mocks und einem
    ``build_calls``-Counter fuer Assertions.
    """
    cfg = SimpleNamespace(encryption_key=SimpleNamespace(get_secret_value=lambda: "k" * 32))

    monkeypatch.setattr(llm_worker, "ensure_settings_row", lambda _session: settings_row)
    monkeypatch.setattr(llm_worker, "load_settings", lambda: cfg)

    plain_key_iter = iter(plain_keys)

    def _fake_decrypt(_enc: bytes, _key: str) -> str:
        try:
            return next(plain_key_iter)
        except StopIteration:  # pragma: no cover — Test setzt genug Keys
            return ""

    # ``decrypt_api_key`` wird *innerhalb* von ``_get_or_build_async_client``
    # via ``from app.services.llm_client import decrypt_api_key`` importiert.
    # Wir patchen das Symbol direkt an der Quelle.
    import app.services.llm_client as llm_client_mod

    monkeypatch.setattr(llm_client_mod, "decrypt_api_key", _fake_decrypt)

    fake_client_iter = iter(fake_clients)
    build_calls: list[dict[str, Any]] = []

    def _fake_build(setting: Any, *, encryption_key: str, timeout: float = 240.0) -> MagicMock:
        build_calls.append(
            {
                "base_url": setting.llm_base_url,
                "model": setting.llm_reviewer_model,
                "api_key_encrypted": setting.llm_api_key_encrypted,
                "encryption_key": encryption_key,
            }
        )
        try:
            return next(fake_client_iter)
        except StopIteration:  # pragma: no cover — Test setzt genug Clients
            return _make_fake_client()

    monkeypatch.setattr(llm_worker, "build_client_from_settings", _fake_build)

    return {"build_calls": build_calls}


# ---------------------------------------------------------------------------
# 1) Fingerprint-Determinismus + Feld-Sensitivitaet (pure)
# ---------------------------------------------------------------------------


def test_fingerprint_deterministic_for_identical_inputs() -> None:
    """Zweimal mit denselben Inputs muss exakt dasselbe Tuple liefern."""
    a = llm_worker._compute_client_fingerprint(
        "https://api.deepinfra.com/v1/openai", "deepseek-ai/DeepSeek-V3", "secret-abc"
    )
    b = llm_worker._compute_client_fingerprint(
        "https://api.deepinfra.com/v1/openai", "deepseek-ai/DeepSeek-V3", "secret-abc"
    )
    assert a == b, f"Fingerprint nicht deterministisch: {a} != {b}"

    # SHA-256-Hex hat 64 Zeichen.
    base_url, model, digest = a
    assert base_url == "https://api.deepinfra.com/v1/openai"
    assert model == "deepseek-ai/DeepSeek-V3"
    assert len(digest) == 64, f"sha256-hex sollte 64 Zeichen sein, got {len(digest)}"
    assert all(c in "0123456789abcdef" for c in digest), f"non-hex Zeichen in {digest!r}"


def test_fingerprint_changes_when_api_key_differs() -> None:
    """Gleiche base_url + model, unterschiedlicher Key → anderes Tuple."""
    a = llm_worker._compute_client_fingerprint("https://x", "m", "key-A")
    b = llm_worker._compute_client_fingerprint("https://x", "m", "key-B")
    assert a != b, "Fingerprint sollte sich bei abweichendem Key aendern"
    assert a[0] == b[0] and a[1] == b[1], "base_url+model identisch erwartet"
    assert a[2] != b[2], "sha256-Hex muss differieren"


def test_fingerprint_changes_when_base_url_or_model_differs() -> None:
    """``base_url`` oder ``model`` allein muessen ebenfalls einen Mismatch erzeugen."""
    base = llm_worker._compute_client_fingerprint("https://x", "m", "k")
    other_url = llm_worker._compute_client_fingerprint("https://y", "m", "k")
    other_model = llm_worker._compute_client_fingerprint("https://x", "n", "k")
    assert base != other_url, "base_url-Wechsel muss Fingerprint aendern"
    assert base != other_model, "model-Wechsel muss Fingerprint aendern"


# ---------------------------------------------------------------------------
# 2) Erster Call → Client wird gebaut, Fingerprint gesetzt
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
async def test_first_call_builds_client_and_sets_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Beim ersten Aufruf wird ``build_client_from_settings`` genau einmal
    gerufen, das Modul-State enthaelt Client + Fingerprint, der zurueck-
    gegebene Client ist das Mock-Objekt."""
    settings_row = _make_settings_row()
    fake_client = _make_fake_client()
    state = _patch_settings_chain(
        monkeypatch,
        settings_row=settings_row,
        plain_keys=["plain-key-A"],
        fake_clients=[fake_client],
    )

    session = MagicMock()
    client, model_name = await llm_worker._get_or_build_async_client(session)

    assert client is fake_client, "Erster Call sollte den gebauten Mock-Client zurueckgeben"
    assert model_name == "deepseek-ai/DeepSeek-V3"
    assert llm_worker._cached_client is fake_client
    assert llm_worker._cached_client_fingerprint == (
        settings_row.llm_base_url,
        settings_row.llm_reviewer_model,
        # SHA-256 von "plain-key-A"
        llm_worker._compute_client_fingerprint(
            settings_row.llm_base_url,
            settings_row.llm_reviewer_model,
            "plain-key-A",
        )[2],
    )
    assert len(state["build_calls"]) == 1, "Build wurde nicht genau einmal aufgerufen"
    # aclose darf NICHT auf einem neuen Cache aufgerufen werden.
    fake_client.aclose.assert_not_awaited()


# ---------------------------------------------------------------------------
# 3) Zweiter Call mit unveraenderten Settings → derselbe Client
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
async def test_second_call_unchanged_returns_same_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Zwei Aufrufe mit identischer Settings-Row liefern dieselbe Client-
    Instanz; Build wird nur einmal gerufen, kein aclose."""
    settings_row = _make_settings_row()
    fake_client = _make_fake_client()
    # Zwei Plain-Key-Returns weil der Fingerprint zweimal berechnet wird
    # (jeder Async-Aufruf liest Settings neu).
    state = _patch_settings_chain(
        monkeypatch,
        settings_row=settings_row,
        plain_keys=["same-plain-key", "same-plain-key"],
        fake_clients=[fake_client],
    )

    session = MagicMock()
    client1, _ = await llm_worker._get_or_build_async_client(session)
    client2, _ = await llm_worker._get_or_build_async_client(session)

    assert client1 is client2, "Bei unveraenderten Settings selbe Client-Instanz erwartet"
    assert len(state["build_calls"]) == 1, "Build darf nur einmal laufen"
    fake_client.aclose.assert_not_awaited()


# ---------------------------------------------------------------------------
# 4) Settings-Change `base_url` → Rebuild + altes aclose()
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
async def test_base_url_change_triggers_rebuild_and_acloses_old(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``base_url``-Wechsel zwischen Aufrufen muss ``aclose`` auf dem alten
    Client triggern und einen neuen Client liefern. Log-Marker
    ``llm_worker.client_rebuilt`` muss im Worker-Logger erscheinen.

    Wir haengen einen eigenen Handler direkt an
    ``app.workers.llm_worker.log`` (statt ``caplog`` zu verwenden), weil
    bei voller Suite vorhergehende Tests den Logger-State so verschmutzen
    koennen, dass ``caplog`` keine Records mehr sieht. Der ``autouse``-
    Logger-Reset oben hilft bereits; der eigene Handler ist Belt-and-
    Suspenders gegen verbleibende ``dictConfig``-/Propagate-Quirks.
    """
    settings_row = _make_settings_row(base_url="https://api.deepinfra.com/v1/openai")
    fake_client_old = _make_fake_client(model="deepseek-ai/DeepSeek-V3")
    fake_client_new = _make_fake_client(model="deepseek-ai/DeepSeek-V3")

    state = _patch_settings_chain(
        monkeypatch,
        settings_row=settings_row,
        plain_keys=["plain-key", "plain-key"],
        fake_clients=[fake_client_old, fake_client_new],
    )

    captured: list[logging.LogRecord] = []

    class _Handler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    worker_logger = llm_worker.log
    prev_level = worker_logger.level
    worker_logger.setLevel(logging.DEBUG)
    handler = _Handler()
    handler.setLevel(logging.DEBUG)
    worker_logger.addHandler(handler)

    try:
        session = MagicMock()

        client1, _ = await llm_worker._get_or_build_async_client(session)
        assert client1 is fake_client_old

        # Zweiter Call: base_url aendern (mutiert dasselbe SimpleNamespace-Objekt).
        settings_row.llm_base_url = "https://api.openai.com/v1"

        client2, _ = await llm_worker._get_or_build_async_client(session)

        assert client2 is fake_client_new, "Neuer Client erwartet nach base_url-Wechsel"
        assert client2 is not fake_client_old
        fake_client_old.aclose.assert_awaited_once()
        fake_client_new.aclose.assert_not_awaited()
        assert len(state["build_calls"]) == 2

        rebuilt_records = [r for r in captured if "client_rebuilt" in r.getMessage()]
        assert rebuilt_records, (
            "Erwartet mindestens einen INFO-Log mit Marker 'llm_worker.client_rebuilt', "
            f"bekommen: {[r.getMessage() for r in captured]}"
        )
        # Key-Material darf nicht im Log auftauchen.
        for rec in rebuilt_records:
            msg = rec.getMessage()
            assert "plain-key" not in msg, f"plaintext key im Log: {msg!r}"
    finally:
        worker_logger.removeHandler(handler)
        worker_logger.setLevel(prev_level)


# ---------------------------------------------------------------------------
# 5) Settings-Change nur `api_key` → Rebuild
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
async def test_api_key_change_only_triggers_rebuild(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``base_url`` und ``model`` bleiben gleich, nur der API-Key-Klartext
    aendert sich (z.B. neuer Fernet-Ciphertext) → Rebuild + aclose alt."""
    settings_row = _make_settings_row(
        base_url="https://api.deepinfra.com/v1/openai",
        model="deepseek-ai/DeepSeek-V3",
        api_key_encrypted=b"cipher-A",
    )
    fake_client_old = _make_fake_client()
    fake_client_new = _make_fake_client()

    state = _patch_settings_chain(
        monkeypatch,
        settings_row=settings_row,
        plain_keys=["plain-A", "plain-B"],
        fake_clients=[fake_client_old, fake_client_new],
    )

    session = MagicMock()
    client1, _ = await llm_worker._get_or_build_async_client(session)

    # Cipher aendern (relevanten Settings-Wert) — wir lassen plain_keys
    # die Differenzierung erzeugen (zweiter Call liest "plain-B").
    settings_row.llm_api_key_encrypted = b"cipher-B"

    client2, _ = await llm_worker._get_or_build_async_client(session)

    assert client1 is not client2, "API-Key-Wechsel muss neuen Client erzwingen"
    fake_client_old.aclose.assert_awaited_once()
    assert len(state["build_calls"]) == 2

    # Fingerprint-Drittes-Element hat sich geaendert, base_url+model nicht.
    fp = llm_worker._cached_client_fingerprint
    assert fp is not None
    assert fp[0] == settings_row.llm_base_url
    assert fp[1] == settings_row.llm_reviewer_model
    # Aktueller Cached-Hash entspricht "plain-B".
    expected = llm_worker._compute_client_fingerprint(
        settings_row.llm_base_url, settings_row.llm_reviewer_model, "plain-B"
    )[2]
    assert fp[2] == expected


# ---------------------------------------------------------------------------
# 6) reset_client_cache_for_tests raeumt Modul-State
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
async def test_reset_client_cache_clears_module_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nach ``reset_client_cache_for_tests`` triggert der naechste Aufruf
    einen frischen Build (Cache war geleert) — auch wenn Settings
    unveraendert sind. Der alte Client wird *nicht* synchron geschlossen
    (kein Event-Loop in Pure-Unit-Tests).
    """
    settings_row = _make_settings_row()
    fake_client_first = _make_fake_client()
    fake_client_second = _make_fake_client()

    state = _patch_settings_chain(
        monkeypatch,
        settings_row=settings_row,
        plain_keys=["plain", "plain"],
        fake_clients=[fake_client_first, fake_client_second],
    )

    session = MagicMock()
    client1, _ = await llm_worker._get_or_build_async_client(session)
    assert client1 is fake_client_first
    assert llm_worker._cached_client is fake_client_first

    llm_worker.reset_client_cache_for_tests()
    assert llm_worker._cached_client is None
    assert llm_worker._cached_client_fingerprint is None
    assert llm_worker._cached_client_lock is None
    # Alter Client darf NICHT synchron geschlossen worden sein.
    fake_client_first.aclose.assert_not_awaited()

    client2, _ = await llm_worker._get_or_build_async_client(session)
    assert client2 is fake_client_second, (
        "Nach reset_client_cache_for_tests muss ein frischer Build laufen"
    )
    assert len(state["build_calls"]) == 2
    # Auch beim Rebuild-Pfad: der gecachte (jetzt None) Client wird nicht
    # aclose-d, weil kein alter Client da war.
    fake_client_first.aclose.assert_not_awaited()


# ---------------------------------------------------------------------------
# 7) Defensiver Mock-Reviewer ohne `client`-Attribut → no-op
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
async def test_aclose_reviewer_client_noop_for_reviewer_without_client_attr() -> None:
    """Test-Hooks (z.B. ``set_reviewer_factory_for_tests``) liefern oft
    Mock-Reviewer ohne ``.client``-Attribut. ``_aclose_reviewer_client``
    muss diesen Fall *ohne* Exception verarbeiten — Regression-Schutz
    fuer den Test-Hook-Pfad."""

    class _ReviewerWithoutClient:
        """Hat absichtlich kein ``client``-Attribut."""

    # Soll nicht werfen.
    await llm_worker._aclose_reviewer_client(_ReviewerWithoutClient())

    # Variante mit ``client = None``.
    none_reviewer = SimpleNamespace(client=None)
    await llm_worker._aclose_reviewer_client(none_reviewer)

    # Variante mit ``client`` ohne ``aclose``-Methode.
    no_aclose_reviewer = SimpleNamespace(client=SimpleNamespace())
    await llm_worker._aclose_reviewer_client(no_aclose_reviewer)


# ---------------------------------------------------------------------------
# 8) Empty-API-Key (Ollama-Pfad) bekommt konsistenten Fingerprint
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
async def test_empty_api_key_produces_consistent_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ohne konfigurierten API-Key (Ollama-Localhost) hasht der Helper
    den leeren String — der Fingerprint muss deterministisch sein und
    der Cache muss bei identischem Empty-Key-Setup nicht rebuilden."""
    settings_row = _make_settings_row(
        base_url="http://localhost:11434",
        model="llama3",
        api_key_encrypted=None,  # keine Cipher-Bytes → kein decrypt_api_key-Call
    )
    fake_client = _make_fake_client(model="llama3")

    state = _patch_settings_chain(
        monkeypatch,
        settings_row=settings_row,
        plain_keys=[],  # decrypt_api_key wird gar nicht aufgerufen
        fake_clients=[fake_client],
    )

    session = MagicMock()
    c1, _ = await llm_worker._get_or_build_async_client(session)
    c2, _ = await llm_worker._get_or_build_async_client(session)

    assert c1 is c2, "Zwei Empty-Key-Aufrufe mit gleicher Settings-Row → selber Client"
    assert len(state["build_calls"]) == 1
    fake_client.aclose.assert_not_awaited()
    fp = llm_worker._cached_client_fingerprint
    assert fp is not None
    # Empty-Key-Hash konsistent mit dem expliziten Compute.
    expected = llm_worker._compute_client_fingerprint(
        settings_row.llm_base_url, settings_row.llm_reviewer_model, ""
    )
    assert fp == expected


# ---------------------------------------------------------------------------
# 9) Reviewer-Fingerprint folgt ``llm_reviewer_model`` — NICHT ``llm_chat_model``
#    (ADR-0057: Chat-Modell ist kein Teil des Reviewer-Client-Fingerprints)
# ---------------------------------------------------------------------------


@pytest.mark.timeout(5)
async def test_reviewer_model_change_triggers_rebuild(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Aenderung von ``llm_reviewer_model`` zwischen Aufrufen -> Rebuild.

    Der Reviewer-Client liest ausschliesslich das Reviewer-Modell; ein Wechsel
    muss den Fingerprint aendern und einen neuen Client bauen.
    """
    settings_row = _make_settings_row(model="openai/gpt-oss-120b")
    fake_old = _make_fake_client(model="openai/gpt-oss-120b")
    fake_new = _make_fake_client(model="some/other-reviewer")

    state = _patch_settings_chain(
        monkeypatch,
        settings_row=settings_row,
        plain_keys=["plain", "plain"],
        fake_clients=[fake_old, fake_new],
    )

    session = MagicMock()
    c1, _ = await llm_worker._get_or_build_async_client(session)
    assert c1 is fake_old

    settings_row.llm_reviewer_model = "some/other-reviewer"
    c2, _ = await llm_worker._get_or_build_async_client(session)

    assert c2 is fake_new, "Reviewer-Modell-Wechsel muss neuen Client bauen"
    fake_old.aclose.assert_awaited_once()
    assert len(state["build_calls"]) == 2
    fp = llm_worker._cached_client_fingerprint
    assert fp is not None
    assert fp[1] == "some/other-reviewer", fp


@pytest.mark.timeout(5)
async def test_chat_model_change_does_not_rebuild_reviewer_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Aenderung von ``llm_chat_model`` allein -> KEIN Rebuild des Reviewer-
    Clients. Das Chat-Modell ist nicht Teil des Reviewer-Fingerprints
    (ADR-0057 §Entscheidung 3). Belegt, dass eine Chat-Modell-Umstellung im
    Provider-Tab den laufenden Reviewer-Client nicht unnoetig neu aufbaut.
    """
    settings_row = _make_settings_row(
        model="openai/gpt-oss-120b",
        chat_model="deepseek-ai/DeepSeek-V4-Flash",
    )
    fake_client = _make_fake_client(model="openai/gpt-oss-120b")

    state = _patch_settings_chain(
        monkeypatch,
        settings_row=settings_row,
        plain_keys=["plain", "plain"],
        fake_clients=[fake_client],
    )

    session = MagicMock()
    c1, _ = await llm_worker._get_or_build_async_client(session)
    fp_before = llm_worker._cached_client_fingerprint

    # Nur das Chat-Modell wechseln — der Reviewer-Pfad darf das ignorieren.
    settings_row.llm_chat_model = "some/other-chat-model"
    c2, _ = await llm_worker._get_or_build_async_client(session)

    assert c1 is c2, "Chat-Modell-Wechsel darf den Reviewer-Client NICHT rebuilden"
    assert len(state["build_calls"]) == 1, "Build darf nur einmal laufen"
    fake_client.aclose.assert_not_awaited()
    assert llm_worker._cached_client_fingerprint == fp_before


def test_reviewer_fingerprint_independent_of_chat_model() -> None:
    """Reiner Fingerprint-Compute: das Chat-Modell ist gar kein Eingang.

    Der Fingerprint-Helper kennt nur ``(base_url, model, api_key)`` — ein
    expliziter Beleg, dass das Chat-Modell strukturell ausserhalb des
    Reviewer-Fingerprints liegt.
    """
    fp = llm_worker._compute_client_fingerprint("https://x", "openai/gpt-oss-120b", "k")
    # Gleicher Reviewer-Input -> gleicher Fingerprint, egal welches Chat-Modell
    # der Operator setzt (das Chat-Modell flowt hier nirgends ein).
    fp_again = llm_worker._compute_client_fingerprint("https://x", "openai/gpt-oss-120b", "k")
    assert fp == fp_again
    assert fp[1] == "openai/gpt-oss-120b"
