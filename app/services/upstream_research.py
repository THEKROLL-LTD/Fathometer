# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Agentischer Upstream-Update-Such-Service (Block AI, ADR-0063, P4).

Produktionierung des Spikes ``scripts/spikes/test_agent_pydantic.py``: eine
duenne Pydantic-AI-Agenten-Schleife, bei der **wir die Tools besitzen**
(``web_search`` + ``fetch_url``). Das Modell plant -> sucht -> liest ->
schlussfolgert, bis ein getyptes :class:`Verdict` steht oder das
``request_limit`` greift; dann FINALIZE-Pfad -> sonst deterministischer
``none_yet``-Fallback. Am Ende ein deterministischer Konsistenz-Pass.

**Struktur fuer Testbarkeit (CLAUDE.md Test-Konvention):** die deterministischen
Bausteine sind je eigene reine Funktionen und pure-unit testbar **ohne**
Live-Netz/LLM:

* :func:`enforce_verdict_consistency` — Konsistenz-Pass (ADR-0063 §Output-Vertrag).
* :func:`web_search` — Such-Backend-Dispatch mit gemocktem ``httpx``.
* :func:`fetch_url` — Fetch via ``trafilatura`` (gemockt).
* :func:`build_instructions` — Instructions aus dem :class:`ResearchSeed`.
* :func:`is_upstream_check_configured` — Konfig-Gating.

Nur :func:`research_upstream` (der Agent-Loop) wird **nicht** proaktiv getestet
(Live-Netz/LLM -> beim User); seine Bausteine schon.

**Untrusted-Output-Haertung (ADR-0063 + group_chat-Doktrin):** Such-/Fetch-
Ergebnisse und Verdikt-Strings sind untrusted (Web/LLM). Dieser Service gibt
strukturierte Daten zurueck; die UI-Sanitization (nh3, kein ``|safe``) ist AI-2.
Scanner-Strings, die wir ins Prompt einbetten (Seed-Description), werden hier
ueber ``group_chat_prompt._safe`` (Marker-Neutralisierung + Control-Strip)
defensiv entschaerft.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlparse

import httpx
import structlog
import trafilatura
from pydantic import BaseModel, Field

from app.services.group_chat_prompt import _safe
from app.services.llm_client import decrypt_api_key
from app.services.upstream_seed import ResearchSeed
from app.views.llm_settings import DEFAULT_RESEARCH_MODEL

if TYPE_CHECKING:
    from app.models import Setting

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

#: Erlaubte Such-Backends (ADR-0063 §Such-/Fetch-Backend).
SEARCH_BACKENDS = ("searxng", "tavily", "firecrawl", "serper")

#: HTTP-Timeout fuer Such-Backend-Requests (Sekunden).
_SEARCH_TIMEOUT = 30.0
#: Max. Anzahl normalisierter Treffer pro Suche.
_MAX_RESULTS = 8
#: Fetch-Output-Cap (Zeichen) — wie im Spike.
_FETCH_CAP = 6000
#: Mindestlaenge fuer einen ``extract()``-Treffer; darunter Roh-Download nutzen.
_EXTRACT_MIN = 200
#: Default-Loop-Budget (Modell-Anfragen) wenn keins uebergeben wird.
DEFAULT_REQUEST_LIMIT = 20
#: Erlaubte URL-Schemes fuer ``fetch_url`` (SSRF-Allowlist, ADR-0063 §Leitplanke 2).
_ALLOWED_FETCH_SCHEMES = frozenset({"http", "https"})
#: Fetch-Timeout (Sekunden) fuer den eigenen httpx-Download.
_FETCH_TIMEOUT = 30.0


# ---------------------------------------------------------------------------
# Such-Backend-Konfiguration (entschluesselt, DB-frei) — Brueck zum Worker (P5)
# ---------------------------------------------------------------------------


class SearchBackendConfig(BaseModel):
    """Entschluesselte Such-Backend-Konfiguration fuer :func:`web_search`.

    Der Worker (P5) baut diese aus der ``Setting``-Zeile (Backend, base_url,
    entschluesselter API-Key + optionale SearXNG-Basic-Auth). DB-frei und ohne
    Geheimnis-Persistenz, damit :func:`web_search` pure-unit (gemockter httpx)
    testbar bleibt.
    """

    backend: Literal["searxng", "tavily", "firecrawl", "serper"]
    base_url: str | None = None
    api_key: str | None = None
    username: str | None = None
    password: str | None = None


# ---------------------------------------------------------------------------
# Verdikt (1:1 aus dem Spike, Z.101-112)
# ---------------------------------------------------------------------------


class Verdict(BaseModel):
    """Getyptes Verdikt des Research-Agenten (ADR-0063 §Output-Vertrag)."""

    fixing_component_version: str | None = Field(
        None,
        description="version of the affected component (runtime/stdlib/dependency) "
        "that first fixes the CVE",
    )
    latest_release_component_version: str | None = Field(
        None,
        description="version of the affected component the newest package release "
        "is built with or bundles",
    )
    latest_release_found: str | None = None
    fixed_build_release: str | None = Field(
        None,
        description="first package release built with a fixing component version, else null",
    )
    fixed_build_release_date: str | None = None
    delivery: Literal["fixed_release_exists", "none_yet"] | None = None
    operator_action: str = Field(
        description="one sentence: what the package operator should do now"
    )
    confidence: Literal["low", "medium", "high"]
    sources_used: list[str] = Field(default_factory=list, description="URLs actually relied on")
    reasoning: str


# ---------------------------------------------------------------------------
# Deterministischer Konsistenz-Pass (ADR-0063 §Output-Vertrag, Spike Z.242)
# ---------------------------------------------------------------------------


def enforce_verdict_consistency(verdict: Verdict) -> Verdict:
    """Erzwingt die deterministischen Invarianten ueber dem LLM-Verdikt.

    * ``fixed_build_release is None  <->  delivery == "none_yet"`` (Spike Z.242):
      gibt es kein gefixtes veroeffentlichtes Release, ist die Lieferung
      ``none_yet``; gibt es eins, ``fixed_release_exists``. Das LLM fudgt diese
      Kopplung selbst bei guter Instruktion gelegentlich.
    * ADR-0063 §Output-Vertrag-Invariante "build_version < fixing_version ->
      nicht gefixt": ist die Komponenten-Version des neuesten Releases identisch
      mit der bekannten verwundbaren installierten Version (deterministisch
      pruefbarer Teil-Fall), kann das neueste Release nicht gefixt sein -> wir
      raeumen ein vom Modell faelschlich gesetztes ``fixed_build_release``
      nicht generisch ab (Versions-Ordering ist ecosystem-spezifisch und nicht
      sicher deterministisch), aber die ``delivery``-Kopplung oben bleibt die
      harte Klammer.

    Reine Funktion ohne Seiteneffekte: gibt ein neues, konsistentes
    :class:`Verdict` zurueck (das Eingabe-Objekt bleibt unveraendert).
    """
    delivery: Literal["fixed_release_exists", "none_yet"] = (
        "none_yet" if verdict.fixed_build_release is None else "fixed_release_exists"
    )
    return verdict.model_copy(update={"delivery": delivery})


# ---------------------------------------------------------------------------
# Such-Backend-Dispatch (ADR-0063 §Such-/Fetch-Backend) — via httpx
# ---------------------------------------------------------------------------


def _normalize_hit(title: Any, url: Any, content: Any) -> dict[str, str]:
    """Normalisiert einen Roh-Treffer auf ``{title,url,content}`` (alle str)."""
    return {
        "title": str(title or ""),
        "url": str(url or ""),
        "content": str(content or ""),
    }


def _search_searxng(
    client: httpx.Client, query: str, cfg: SearchBackendConfig
) -> list[dict[str, str]]:
    base = (cfg.base_url or "").rstrip("/")
    auth = (cfg.username, cfg.password or "") if cfg.username else None
    resp = client.get(
        f"{base}/search",
        params={"q": query, "format": "json"},
        auth=auth,
        timeout=_SEARCH_TIMEOUT,
    )
    resp.raise_for_status()
    results = (resp.json().get("results") or [])[:_MAX_RESULTS]
    return [_normalize_hit(x.get("title"), x.get("url"), x.get("content")) for x in results]


def _search_tavily(
    client: httpx.Client, query: str, cfg: SearchBackendConfig
) -> list[dict[str, str]]:
    base = (cfg.base_url or "https://api.tavily.com").rstrip("/")
    resp = client.post(
        f"{base}/search",
        headers={"Authorization": f"Bearer {cfg.api_key or ''}"},
        json={"query": query, "max_results": _MAX_RESULTS},
        timeout=_SEARCH_TIMEOUT,
    )
    resp.raise_for_status()
    results = (resp.json().get("results") or [])[:_MAX_RESULTS]
    return [_normalize_hit(x.get("title"), x.get("url"), x.get("content")) for x in results]


def _search_serper(
    client: httpx.Client, query: str, cfg: SearchBackendConfig
) -> list[dict[str, str]]:
    base = (cfg.base_url or "https://google.serper.dev").rstrip("/")
    resp = client.post(
        f"{base}/search",
        headers={"X-API-KEY": cfg.api_key or "", "Content-Type": "application/json"},
        json={"q": query, "num": _MAX_RESULTS},
        timeout=_SEARCH_TIMEOUT,
    )
    resp.raise_for_status()
    organic = (resp.json().get("organic") or [])[:_MAX_RESULTS]
    return [_normalize_hit(x.get("title"), x.get("link"), x.get("snippet")) for x in organic]


def _search_firecrawl(
    client: httpx.Client, query: str, cfg: SearchBackendConfig
) -> list[dict[str, str]]:
    base = (cfg.base_url or "https://api.firecrawl.dev").rstrip("/")
    resp = client.post(
        f"{base}/v1/search",
        headers={"Authorization": f"Bearer {cfg.api_key or ''}"},
        json={"query": query, "limit": _MAX_RESULTS},
        timeout=_SEARCH_TIMEOUT,
    )
    resp.raise_for_status()
    data = (resp.json().get("data") or [])[:_MAX_RESULTS]
    return [_normalize_hit(x.get("title"), x.get("url"), x.get("description")) for x in data]


_BACKEND_DISPATCH = {
    "searxng": _search_searxng,
    "tavily": _search_tavily,
    "serper": _search_serper,
    "firecrawl": _search_firecrawl,
}


def web_search(query: str, *, backend_cfg: SearchBackendConfig) -> list[dict[str, str]]:
    """Such-Backend-Dispatch -> normalisierte ``[{title,url,content}]``.

    Baut pro Backend (``searxng``/``tavily``/``serper``/``firecrawl``) den
    passenden Request via ``httpx`` und normalisiert die Antwort. Defensiver
    Fehler-Pfad: jeder Netz-/Parse-Fehler liefert ``[{"error": ...}]`` statt zu
    werfen — der Agent-Loop soll an einer fehlgeschlagenen Suche nicht
    crashen. Pure-unit testbar mit gemocktem ``httpx`` (Request-Bau +
    Normalisierung pro Backend).
    """
    handler = _BACKEND_DISPATCH.get(backend_cfg.backend)
    if handler is None:  # pragma: no cover — Literal-Typ schliesst das aus
        return [{"error": f"unknown search backend: {backend_cfg.backend}"}]
    # Defensive Scheme-Pruefung auf der operator-konfigurierten base_url. KEINE
    # private-IP-Sperre: die base_url ist vertrauenswuerdig und darf bewusst auf
    # eine interne/RFC1918-SearXNG zeigen (ADR-0063 §Such-/Fetch-Backend). Der
    # SSRF-Vektor ist ``fetch_url`` (LLM-gewaehlte URL), nicht ``web_search``.
    if backend_cfg.base_url:
        scheme = urlparse(backend_cfg.base_url).scheme.lower()
        if scheme not in _ALLOWED_FETCH_SCHEMES:
            log.warning(
                "upstream_research.search_bad_scheme",
                backend=backend_cfg.backend,
                scheme=scheme,
            )
            return [{"error": "search misconfigured (disallowed base_url scheme)"}]
    try:
        with httpx.Client() as client:
            return handler(client, query, backend_cfg)
    except Exception as exc:
        log.warning(
            "upstream_research.search_failed",
            backend=backend_cfg.backend,
            error=f"{type(exc).__name__}: {str(exc)[:200]}",
        )
        return [{"error": f"search failed ({type(exc).__name__})"}]


# ---------------------------------------------------------------------------
# Fetch-Tool (Spike Z.83-97) — trafilatura mit Raw-Fallback
# ---------------------------------------------------------------------------


def _is_fetch_url_allowed(url: str) -> tuple[bool, str]:
    """SSRF-Allowlist fuer eine vom LLM gewaehlte (untrusted) Fetch-URL.

    Die URL stammt aus LLM-/Web-Suchergebnissen und ist damit
    angreifer-beeinflussbar (Prompt-Injection in einer gelesenen Seite kann
    ``fetch http://169.254.169.254/...`` o.ae. erzwingen). Der research-worker
    hat Netz-Egress neben ``db``/``app`` — ohne diese Pruefung waere das ein
    SSRF-Vektor auf Cloud-Metadaten / interne Services (ADR-0063 §Leitplanke 2).

    Fail-closed:

    * Scheme muss ``http``/``https`` sein (``file``/``gopher``/``ftp``/leer ab).
    * Hostname wird aufgeloest (``socket.getaddrinfo``); **jede** aufgeloeste IP
      muss oeffentlich-routbar sein — abgelehnt bei ``is_private`` /
      ``is_loopback`` / ``is_link_local`` (deckt ``169.254.169.254``) /
      ``is_reserved`` / ``is_multicast`` / ``is_unspecified``. IP-Literal-Hosts
      werden direkt geprueft.
    * DNS-Aufloesungsfehler -> abgelehnt.

    Reine (lese-only, abgesehen vom DNS-Lookup) Funktion -> ``(allowed, reason)``.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_FETCH_SCHEMES:
        return (False, "disallowed scheme")
    host = parsed.hostname
    if not host:
        return (False, "missing host")

    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError):
        # DNS-Fehler / kaputter Host -> fail-closed.
        return (False, "dns resolution failed")

    if not infos:  # pragma: no cover — getaddrinfo wirft bei Fehler bereits
        return (False, "dns resolution failed")

    for info in infos:
        sockaddr = info[4]
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:  # pragma: no cover — getaddrinfo liefert valide IPs
            return (False, "unresolvable address")
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return (False, "disallowed host (non-public address)")

    return (True, "ok")


def fetch_url(url: str) -> str:
    """Holt den lesbaren Text einer Web-Seite ODER Roh-Datei (Release/go.mod/SBOM).

    **SSRF-haertung (ADR-0063 §Leitplanke 2):** die ``url`` stammt aus
    LLM-/Web-Suchergebnissen und ist untrusted. Vor dem Request wird sie durch
    :func:`_is_fetch_url_allowed` geprueft (Scheme + alle aufgeloesten IPs
    oeffentlich). Der Download laeuft ueber **eigenen** ``httpx``-Client mit
    ``follow_redirects=False`` (trafilaturas interner Fetch folgt Redirects und
    waere ein SSRF-Bypass) und explizitem Timeout; ein ``30x``-Redirect wird
    abgelehnt (einfacher + sicher: keine Re-Validierung von Hops noetig).

    ``trafilatura.extract()`` ist ein HTML-Artikel-Extraktor — Roh-Dateien
    (go.mod, Lockfiles, SBOMs) haben keinen Artikel und liefern nichts. Dann
    den Roh-Download durchreichen statt ihn wegzuwerfen (sonst geht die
    maschinenlesbare Build-Quelle verloren). Output auf :data:`_FETCH_CAP`
    Zeichen gekappt. Defensiver Fehler-Pfad statt Exception — nie ein roher
    Host-/Exception-Text der ein Geheimnis leaken koennte.
    """
    allowed, _reason = _is_fetch_url_allowed(url)
    if not allowed:
        log.warning("upstream_research.fetch_blocked", reason=_reason)
        return "fetch blocked (disallowed host)"

    try:
        with httpx.Client(timeout=_FETCH_TIMEOUT, follow_redirects=False) as client:
            resp = client.get(url)
    except Exception as exc:
        log.warning(
            "upstream_research.fetch_failed",
            error=f"{type(exc).__name__}: {str(exc)[:200]}",
        )
        return "fetch failed (download error)"

    if 300 <= resp.status_code < 400:
        # Redirect -> nicht folgen (SSRF-Bypass-Schutz). Die Ziel-IP der
        # Location waere zwar erneut pruefbar, aber Ablehnen ist einfacher
        # und sicherer (ADR-0063 §Leitplanke 2).
        log.warning("upstream_research.fetch_blocked", reason="redirect")
        return "fetch blocked (redirect)"
    if resp.status_code >= 400:
        return f"fetch failed (http {resp.status_code})"

    downloaded = resp.text
    if not downloaded:
        return "fetch failed (empty body)"
    extracted = trafilatura.extract(downloaded, include_links=False) or ""
    raw = extracted if len(extracted) >= _EXTRACT_MIN else downloaded
    return raw[:_FETCH_CAP]


# ---------------------------------------------------------------------------
# Instructions-Builder (Spike-INSTRUCTIONS aus Seed-Feldern statt Konstanten)
# ---------------------------------------------------------------------------


FINALIZE = (
    "Your research budget is now exhausted — do NOT call any tools. Based ONLY on the "
    "information already gathered in this conversation, output the final verdict now. "
    "Policy: if by this point no fixed PUBLISHED release has been found, that means none "
    "exists yet — set fixed_build_release=null and delivery='none_yet'. Fill every field "
    "from what you gathered; use null only where nothing was found."
)


def build_instructions(seed: ResearchSeed) -> str:
    """Baut die Agent-Instructions aus dem :class:`ResearchSeed`.

    Portiert das Spike-``INSTRUCTIONS``-Template, aber aus Seed-Feldern statt
    den hartcodierten Konstanten. Untrusted Scanner-Strings (``description``,
    ``search_hint``) werden ueber ``_safe`` (Marker-Neutralisierung +
    Control-Strip) entschaerft, bevor sie ins Prompt eingebettet werden.
    """
    package = _safe(seed.artifact_module, max_len=128)
    installed = _safe(seed.installed_component_version, max_len=64)
    ecosystem = _safe(seed.ecosystem, max_len=64)
    binary = _safe(seed.binary_path, max_len=256)
    cve = _safe(seed.cve, max_len=64)
    vuln_component = _safe(seed.vulnerable_component, max_len=256)
    fixing = _safe(seed.fixing_component_version, max_len=128)
    vuln_desc = _safe(seed.description, max_len=600) if seed.description else "(no description)"
    hint_line = ""
    if seed.search_hint:
        hint_line = (
            f"\nSearch hint (owning OS package, may help locate the project): "
            f"{_safe(seed.search_hint, max_len=128)}."
        )

    return f"""You are a security-remediation researcher. A Linux host carries the artifact \
'{binary}' (ecosystem: {ecosystem}, named '{package}'). A scanner flags {cve} in the \
component '{vuln_component}' compiled or bundled INTO the artifact: {vuln_desc}. The flaw is \
only fixed once the artifact is REBUILT with a patched component version.{hint_line}

KNOWN FACTS from the scanner — do NOT re-research these:
- the installed artifact is built with component version '{installed}' — this is the vulnerable version.
- the flaw is fixed in component version '{fixing}'.

Your ONLY research question: does a NEWER published release of '{package}' built with a fixed \
component version (>= {fixing}) EXIST upstream yet — and if so, which release and when? Do NOT \
try to determine whether the host's package repo carries it: whether a fixed release has reached \
THIS host is decided locally by the host's own package manager, not by you.

Investigate with web_search and fetch_url, then conclude — do not loop:
1. Find the latest PUBLISHED release of '{package}' and its date, from the project's official \
releases page (or its package channels) — the version the project marks as its current release. \
CRUCIAL: a "release" is an officially published, installable release. A bare git TAG or unreleased \
branch — even if its build manifest (go.mod etc.) is already bumped — is NOT a release. \
Version-tracking sites that index git tags (e.g. FlakeHub, repology) may list tags that were never \
released; do NOT treat those as releases. Query the project's AUTHORITATIVE release listing ONCE — \
its release API, or the releases page's "latest" marker — and TRUST it as the single source of \
truth for the latest published release. Do not triangulate across search snippets, git-tag \
listings, or third-party trackers to second-guess which release is latest.
2. Determine the build component version of THAT latest published release. Find the authoritative \
source for THIS ecosystem ({ecosystem}) yourself (a build/toolchain manifest or lockfile in the \
repo at the RELEASE's tag, embedded build metadata, or a vendor SBOM). Consult it ONCE — human \
changelogs usually do NOT state it. (For a Go module: with no explicit 'toolchain' directive, the \
'go' directive in go.mod IS the build toolchain version.)
3. Decide and STOP:
   - If the latest published release is built with a fixed component version (>= {fixing}): \
fixed_build_release = that release, fixed_build_release_date = its date, \
delivery = "fixed_release_exists".
   - If the latest published release is still built with a vulnerable version: \
fixed_build_release = null, delivery = "none_yet". Do NOT chase unreleased git tags or pre-release \
branches hoping to find a fix.
   Do NOT investigate the host's dnf/yum/apt repo contents or which version is installable — that \
is OUT OF SCOPE for you (the host's package manager determines it locally).

Hard rules: base every field ONLY on sources you actually read; use null where a value is not \
established — never guess; after ~2 failed attempts at one fact, treat it as null and conclude (do \
not rephrase the same query repeatedly). The operator runs a package, not a build setup — \
operator_action is advice for them (install/await a fixed package or upstream binary), never \
'rebuild it yourself'. Put the URLs you relied on in sources_used."""


def build_user_prompt(seed: ResearchSeed) -> str:
    """Die initiale Recherche-Frage (Spike Z.191) aus dem Seed."""
    return (
        f"Is {_safe(seed.cve, max_len=64)} fixed in any installable "
        f"'{_safe(seed.artifact_module, max_len=128)}' build for this host yet?"
    )


# ---------------------------------------------------------------------------
# Konfig-Gating (pure-unit testbar) — vom Worker (P5) und UI (AI-2) genutzt
# ---------------------------------------------------------------------------


def is_upstream_check_configured(settings_row: Setting) -> bool:
    """``True`` wenn das Upstream-Check-Feature voll konfiguriert ist.

    Bedingungen (ADR-0063 §Opt-in & gated, §Gating & Sicherheit):

    * Feature-Flag ``upstream_check_enabled`` an,
    * Such-Backend gesetzt UND in der Whitelist UND eine Such-base_url
      gesetzt (SearXNG braucht die self-hosted URL; die paid-APIs nutzen
      ihre Default-URL, aber wir verlangen einen expliziten Backend-Pick),
    * LLM-Provider konfiguriert (geteilte ``llm_base_url`` wie Reviewer/Chat).

    Das Research-Modell faellt sonst auf :data:`DEFAULT_RESEARCH_MODEL` zurueck,
    ist also nie ein Blocker. Reine, lese-only Funktion.
    """
    if not getattr(settings_row, "upstream_check_enabled", False):
        return False
    backend = getattr(settings_row, "upstream_search_backend", None)
    if not backend or backend not in SEARCH_BACKENDS:
        return False
    if not getattr(settings_row, "upstream_search_base_url", None):
        return False
    return bool(getattr(settings_row, "llm_base_url", None))


def build_search_config(settings_row: Setting, *, encryption_key: str) -> SearchBackendConfig:
    """Baut die :class:`SearchBackendConfig` aus der ``Setting``-Zeile.

    Entschluesselt API-Key und SearXNG-Basic-Auth-Passwort ueber dieselbe
    Fernet-Pipeline wie ``llm_api_key_encrypted`` (``decrypt_api_key``). Wird
    vom Worker (P5) vor :func:`research_upstream` aufgerufen. Setzt voraus, dass
    :func:`is_upstream_check_configured` bereits ``True`` ergab.
    """
    backend = getattr(settings_row, "upstream_search_backend", None)
    if backend not in SEARCH_BACKENDS:  # pragma: no cover — Gating prueft das
        raise ValueError(f"invalid search backend: {backend!r}")

    api_key: str | None = None
    enc_key = getattr(settings_row, "upstream_search_api_key_encrypted", None)
    if enc_key:
        api_key = decrypt_api_key(enc_key, encryption_key)

    password: str | None = None
    enc_pw = getattr(settings_row, "upstream_search_password_encrypted", None)
    if enc_pw:
        password = decrypt_api_key(enc_pw, encryption_key)

    return SearchBackendConfig(
        backend=backend,  # durch Whitelist-Check oben gedeckt
        base_url=getattr(settings_row, "upstream_search_base_url", None),
        api_key=api_key,
        username=getattr(settings_row, "upstream_search_username", None),
        password=password,
    )


# ---------------------------------------------------------------------------
# Agent-Runner (NICHT proaktiv getestet — Live-Netz/LLM)
# ---------------------------------------------------------------------------


def _build_model(settings_row: Setting, *, encryption_key: str) -> Any:
    """Baut das ``OpenAIChatModel`` aus dem geteilten Provider + Research-Modell.

    Lazy-Import der pydantic_ai-OpenAI-Klassen (nur im Live-Pfad noetig) —
    haelt den Modul-Import schlank fuer die pure-unit-Bausteine.
    """
    from pydantic_ai.models.openai import OpenAIChatModel
    from pydantic_ai.profiles.openai import OpenAIModelProfile
    from pydantic_ai.providers.openai import OpenAIProvider

    base_url = getattr(settings_row, "llm_base_url", None)
    if not base_url:
        raise ValueError("LLM provider not configured (llm_base_url missing)")
    model_name = getattr(settings_row, "llm_research_model", None) or DEFAULT_RESEARCH_MODEL
    api_key = ""
    enc = getattr(settings_row, "llm_api_key_encrypted", None)
    if enc:
        api_key = decrypt_api_key(enc, encryption_key)
    return OpenAIChatModel(
        model_name,
        provider=OpenAIProvider(base_url=base_url, api_key=api_key or "ollama"),
        # Offene Modelle auf DeepInfra unterstuetzen oft kein strict-tool-schema.
        profile=OpenAIModelProfile(openai_supports_strict_tool_definition=False),
    )


async def research_upstream(
    seed: ResearchSeed,
    *,
    settings_row: Setting,
    encryption_key: str,
    search_cfg: SearchBackendConfig | None = None,
    request_limit: int = DEFAULT_REQUEST_LIMIT,
) -> Verdict:
    """Faehrt den agentischen Upstream-Check fuer einen :class:`ResearchSeed`.

    Baut das Modell aus dem geteilten Provider (``llm_base_url``/Key wie
    Reviewer/Chat, Modell ``llm_research_model`` oder
    :data:`DEFAULT_RESEARCH_MODEL`), die Tools (``web_search`` mit gebundener
    :class:`SearchBackendConfig`, ``fetch_url``), die Instructions aus dem Seed,
    und laeuft ``agent.iter`` mit ``UsageLimits(request_limit=...)``. Budget-Ende
    -> FINALIZE-Pfad -> sonst deterministischer ``none_yet``-Fallback. Am Ende
    :func:`enforce_verdict_consistency`.

    **Nicht proaktiv getestet** (Live-Netz/LLM -> beim User). Die deterministischen
    Bausteine (Konsistenz-Pass, Such-Dispatch, Verdict, Instructions-Builder)
    sind separat pure-unit testbar.
    """
    from pydantic_ai import Agent
    from pydantic_ai.exceptions import UsageLimitExceeded
    from pydantic_ai.usage import UsageLimits

    if search_cfg is None:
        search_cfg = build_search_config(settings_row, encryption_key=encryption_key)

    def _web_search(query: str) -> list[dict[str, str]]:
        """Search the web. Returns up to 8 results, each with title, url and a content snippet."""
        return web_search(query, backend_cfg=search_cfg)

    def _fetch_url(url: str) -> str:
        """Fetch the readable text of one web page OR raw file (release page, changelog, go.mod, lockfile, SBOM)."""
        return fetch_url(url)

    agent: Agent[None, Verdict] = Agent(
        _build_model(settings_row, encryption_key=encryption_key),
        output_type=Verdict,
        tools=[_web_search, _fetch_url],
        instructions=build_instructions(seed),
    )

    async def _run() -> Verdict:
        async with agent.iter(
            build_user_prompt(seed),
            usage_limits=UsageLimits(request_limit=request_limit),
        ) as run:
            try:
                async for _node in run:
                    pass
                result = run.result
                if result is None:  # pragma: no cover — defensiver Pfad
                    raise RuntimeError("agent run produced no result")
                return result.output
            except UsageLimitExceeded:
                # Budget leer -> bisherigen Stand ans LLM, finale Aussage erzwingen.
                log.info("upstream_research.budget_exhausted_finalizing")
                history = getattr(getattr(run, "ctx", None), "state", None)
                history = getattr(history, "message_history", None)
                if history:
                    try:
                        final = await agent.run(
                            FINALIZE,
                            message_history=history,
                            usage_limits=UsageLimits(request_limit=2),
                        )
                        return final.output
                    except Exception as exc:
                        log.warning(
                            "upstream_research.finalize_failed",
                            error=f"{type(exc).__name__}: {str(exc)[:200]}",
                        )
                # Fallback: nichts gefunden = kein Fix (Spike Z.231-237).
                return Verdict(
                    fixing_component_version=None,
                    latest_release_component_version=None,
                    latest_release_found=None,
                    fixed_build_release=None,
                    fixed_build_release_date=None,
                    delivery="none_yet",
                    operator_action="No fixed published release found within the research "
                    "budget; treat as not-yet-fixed and mitigate/monitor.",
                    confidence="low",
                    reasoning="Research budget exhausted without finding a fixed published "
                    "release; per policy, absence of a found fix means no fixed release exists yet.",
                )

    verdict = await _run()
    return enforce_verdict_consistency(verdict)


# Lokale Convenience fuer synchrone Aufrufer (Worker kann auch direkt awaiten).
def research_upstream_sync(
    seed: ResearchSeed,
    *,
    settings_row: Setting,
    encryption_key: str,
    search_cfg: SearchBackendConfig | None = None,
    request_limit: int = DEFAULT_REQUEST_LIMIT,
) -> Verdict:
    """Synchroner Wrapper um :func:`research_upstream` (eigener Event-Loop)."""
    return asyncio.run(
        research_upstream(
            seed,
            settings_row=settings_row,
            encryption_key=encryption_key,
            search_cfg=search_cfg,
            request_limit=request_limit,
        )
    )


__all__ = [
    "DEFAULT_REQUEST_LIMIT",
    "SEARCH_BACKENDS",
    "SearchBackendConfig",
    "Verdict",
    "_is_fetch_url_allowed",
    "build_instructions",
    "build_search_config",
    "build_user_prompt",
    "enforce_verdict_consistency",
    "fetch_url",
    "is_upstream_check_configured",
    "research_upstream",
    "research_upstream_sync",
    "web_search",
]
