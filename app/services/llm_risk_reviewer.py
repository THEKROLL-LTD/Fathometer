# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""LLM-Risk-Reviewer-Service fuer Block P (ADR-0023).

Zwei-Pass-LLM-Architektur:

* **Pass 1 — Group-Detection.** :meth:`LLMRiskReviewer.pass1_detect_groups`
  bekommt eine Liste von Findings (kompakt: ``finding_id``, ``package_name``,
  ``target_path``, ``package_purl``, ``result_type``) und liefert
  Application-Groups mit Match-Patterns plus ``finding_ids``-Zuordnung.

* **Pass 2 — Risk-Evaluation.** :meth:`pass2_evaluate_groups` bekommt
  Server-Kontext + Groups-mit-Findings und liefert pro Group ein
  ``risk_band`` aus ``{escalate, act, mitigate, monitor, noise}``,
  ``worst_finding_id`` und ``reason``.

Beide Passes validieren das LLM-Output strikt gegen Halluzinationen:

* Pass-1: jede ``finding_id`` muss im Input gewesen sein, jeder Input-
  Finding muss in genau einer Group oder im ``ungrouped``-Array landen,
  Label-Regex erzwungen, Pattern-Sanitization gegen NUL/Non-ASCII/
  Wildcard-only.
* Pass-2: ``group_label`` muss im Input gewesen sein, ``risk_band`` muss
  in der finalen Whitelist liegen (``pending``/``unknown`` SIND VERBOTEN
  — das sind reine Pre-Triage-Werte), ``worst_finding_id`` muss eines
  der im Prompt GEZEIGTEN Findings sein (TICKET-011: deterministische
  Worst-Selektion via :mod:`app.services.pass2_input_selection` statt
  zufaelligem ``fs[:32]``-Cap), ``reason`` <= 256 chars und NUL-frei.

Der LLM-Call selbst geht ueber einen duennen Helper :func:`chat_completion_json`,
der auf dem Block-G-:class:`app.services.llm_client.LlmClient` aufsetzt
(kein Refactoring an Block G).
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Literal, cast

import structlog
from pydantic import BaseModel, ConfigDict, Field

from app.config import load_settings
from app.models import ApplicationGroup, AttackVector, Finding, Server
from app.services.llm_prompts import PASS1_SYSTEM_PROMPT, PASS2_SYSTEM_PROMPT
from app.services.pass2_input_selection import SelectionResult, select_pass2_findings

if TYPE_CHECKING:
    from app.services.llm_client import LlmClient

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Konstanten / Regex / Schemas
# ---------------------------------------------------------------------------


# Label-Whitelist gemaess ADR-0023 §"Backend-Validierung": kleinbuchstaben,
# Ziffern, ``._-``. Erstes Zeichen alphanumerisch, max 64 chars.
# v0.9.5: Spec-Drift behoben — docs/blocks/P-evidence/prompt-pass1-final.md
# Z. 63 spezifiziert "^[a-z0-9][a-z0-9._-]{0,63}$" (mit Punkt). Der Punkt
# ist relevant fuer Distro-Pakete mit Version im Paketnamen
# (z.B. "linux-modules-5.15.0-177-generic", "libstdc++6.0.30").
LABEL_PATTERN: re.Pattern[str] = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

# Reason-Hardlimit pro ADR-0023 §"Backend-Validierung".
MAX_REASON_LEN: int = 256

# TICKET-011: Laengen-Cap fuer den Finding-Title in der Pass-2-Prompt-Zeile.
MAX_PROMPT_TITLE_LEN: int = 100


def _sanitize_prompt_title(raw: str) -> str:
    """Finding-Title fuer die Pass-2-Prompt-Zeile haerten (TICKET-011).

    Der Title ist Fremdtext (Trivy/CVE-Feed) und wird auf genau eine
    Zeile gezwungen: Steuerzeichen/Newlines raus, Whitespace kollabiert,
    Double-Quotes zu Single-Quotes (der Title steht im Prompt in
    ``title="..."``), Cap bei :data:`MAX_PROMPT_TITLE_LEN` Zeichen.
    """
    cleaned = "".join(ch if ch.isprintable() else " " for ch in raw)
    cleaned = " ".join(cleaned.split())
    cleaned = cleaned.replace('"', "'")
    if len(cleaned) > MAX_PROMPT_TITLE_LEN:
        cleaned = cleaned[: MAX_PROMPT_TITLE_LEN - 3].rstrip() + "..."
    return cleaned


# Final-LLM-Bands (Whitelist; pending/unknown bewusst NICHT zugelassen).
# Backward-Compat: ``mitigate`` bleibt akzeptiert (Iteration-5-Output, historische
# Bewertungen), wird aber im Validator auf ``escalate`` umgemappt (mit Warning).
VALID_RISK_BANDS: frozenset[str] = frozenset({"escalate", "act", "mitigate", "monitor", "noise"})

# v0.9.3: vier aktive Bands plus legacy ``mitigate``. Action-Types kommen
# strukturell als separates Feld.
VALID_ACTION_TYPES: frozenset[str] = frozenset({"patch", "mitigate", "watch", "none"})

# Erlaubte ``(risk_band, action_type)``-Kombinationen (Iteration 6, final).
# Jede andere Kombination wird vom Validator abgelehnt.
ALLOWED_BAND_ACTION_COMBOS: frozenset[tuple[str, str]] = frozenset(
    {
        ("escalate", "patch"),
        ("escalate", "mitigate"),
        ("act", "patch"),
        ("monitor", "watch"),
        ("noise", "none"),
    }
)

# Pattern-Sanitization-Limits (ASCII-only, NUL-frei, Laengen-Range).
_PATH_PREFIX_MIN: int = 1
_PATH_PREFIX_MAX: int = 256
_PKG_NAME_MAX: int = 256
_PKG_PURL_MAX: int = 512

# Generische Pattern die wir IMMER droppen (zu unspezifisch / gefaehrlich).
_FORBIDDEN_PATTERNS: frozenset[str] = frozenset({"/", "*", "**", ""})


PASS1_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["groups", "ungrouped"],
    "properties": {
        "groups": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["label", "finding_ids"],
                "properties": {
                    "label": {"type": "string", "maxLength": 64},
                    "explanation": {"type": ["string", "null"], "maxLength": 512},
                    "match_rules": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "path_prefixes": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "pkg_name_exact": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "pkg_name_glob": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                            "pkg_purl_pattern": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                        },
                    },
                    "finding_ids": {
                        "type": "array",
                        "items": {"type": "integer"},
                    },
                },
            },
        },
        "ungrouped": {
            "type": "array",
            "items": {"type": "integer"},
        },
    },
}


PASS2_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["evaluations"],
    "properties": {
        "evaluations": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["group_label", "risk_band", "action_type", "reason"],
                "properties": {
                    "group_label": {"type": "string", "maxLength": 64},
                    "risk_band": {
                        "type": "string",
                        "enum": ["escalate", "act", "mitigate", "monitor", "noise"],
                    },
                    "action_type": {
                        "type": "string",
                        "enum": ["patch", "mitigate", "watch", "none"],
                    },
                    "worst_finding_id": {"type": ["integer", "null"]},
                    "reason": {"type": "string", "maxLength": MAX_REASON_LEN},
                },
            },
        }
    },
}


# ---------------------------------------------------------------------------
# Pydantic-Output-Modelle
# ---------------------------------------------------------------------------


class Pass1Group(BaseModel):
    """Ein vom LLM in Pass 1 erkanntes Application-Group-Bundle.

    Pattern-Listen werden vom Validator nach defensiv-Sanitization gefiltert
    (siehe :func:`_sanitize_patterns`); leere Listen sind erlaubt.
    """

    model_config = ConfigDict(extra="ignore")

    label: str
    explanation: str | None = None
    path_prefixes: list[str] = Field(default_factory=list)
    pkg_name_exact: list[str] = Field(default_factory=list)
    pkg_name_glob: list[str] = Field(default_factory=list)
    pkg_purl_pattern: list[str] = Field(default_factory=list)
    finding_ids: list[int] = Field(default_factory=list)


class Pass1Result(BaseModel):
    """Validierter Pass-1-Output."""

    model_config = ConfigDict(extra="ignore")

    groups: list[Pass1Group] = Field(default_factory=list)
    ungrouped_finding_ids: list[int] = Field(default_factory=list)


class Pass2Evaluation(BaseModel):
    """Eine Group-Bewertung aus Pass 2.

    ``action_type`` ist ab v0.9.3 Pflicht-Output (vier zulaessige Werte:
    ``patch``/``mitigate``/``watch``/``none``). ``investigate`` ist
    Pre-Triage-only und wird vom LLM nie produziert; Pre-Triage-Groups
    haben ``ApplicationGroup.action_type IS NULL`` bis Pass 2 laeuft.
    """

    model_config = ConfigDict(extra="ignore")

    group_label: str
    risk_band: Literal["escalate", "act", "mitigate", "monitor", "noise"]
    action_type: Literal["patch", "mitigate", "watch", "none"]
    reason: str
    worst_finding_id: int | None = None


class Pass2Result(BaseModel):
    """Validierter Pass-2-Output."""

    model_config = ConfigDict(extra="ignore")

    evaluations: list[Pass2Evaluation] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Exception-Typen
# ---------------------------------------------------------------------------


class LLMInvalidResponseError(ValueError):
    """LLM-Output ist schema- oder semantik-invalid (Halluzination, falsches Band, ...).

    v0.9.5: optionales ``meta``-Attribut traegt das ``chat_completion_json_with_meta``-
    Meta-Dict (raw_content, extracted_json, reasoning_field, usage, duration_ms, ...)
    durch, damit der Worker es beim Debug-Log-Insert persistieren kann auch wenn
    der Backend-Validator wirft. ``None`` solange noch keine Response da ist
    (z.B. JSON-Parse-Error vor Schema-Validation).
    """

    def __init__(self, message: str, *, meta: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.meta: dict[str, Any] | None = meta


class LLMTimeoutError(RuntimeError):
    """LLM-Call hat das konfigurierte Timeout ueberschritten.

    v0.9.x: optionales ``meta``-Attribut analog :class:`LLMInvalidResponseError`
    damit der Worker beim Debug-Log-Insert auch im Timeout-Pfad die
    verfuegbaren Felder (model, max_tokens, duration_ms_until_timeout, plus
    system_prompt/user_prompt sobald der Reviewer-Wrapper sie anhaengt)
    persistieren kann. Vorher: Timeouts schrieben ``meta=None`` → Debug-Log
    leer, Operator-Blindheit.
    """

    def __init__(self, message: str, *, meta: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.meta: dict[str, Any] | None = meta


# ---------------------------------------------------------------------------
# System-Prompts werden aus :mod:`app.services.llm_prompts` re-exportiert.
# Quelle der Wahrheit sind die Evidenz-Files unter ``docs/blocks/P-evidence/``.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Reasoning-Block-Extraction (v0.9.3 — GPT-OSS-Harmony, DeepSeek-R1, etc.)
# ---------------------------------------------------------------------------


_REASONING_BLOCK_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<\|channel\|>analysis<\|message\|>.*?<\|end\|>", re.DOTALL),
    re.compile(r"<think>.*?</think>", re.DOTALL),
    re.compile(r"\[REASONING\].*?\[/REASONING\]", re.DOTALL),
)
_MARKDOWN_JSON_FENCE: re.Pattern[str] = re.compile(r"^```(?:json)?\s*\n(.*?)\n```\s*$", re.DOTALL)
_GREEDY_BRACES: re.Pattern[str] = re.compile(r"\{.*\}", re.DOTALL)


def _extract_json_from_response(content: str) -> str:
    """Strippt Reasoning-Wrapper, Markdown-Fences, faellt auf Greedy-Brace zurueck.

    Drei Schichten in Reihenfolge — vgl. ADR-0023 §"(d) Reasoning-Block-
    Handling":

    1. Bekannte Reasoning-Wrapper-Pattern strippen
       (Harmony-`<|channel|>analysis<|message|>...<|end|>`, `<think>...</think>`,
       `[REASONING]...[/REASONING]`).
    2. Markdown-Code-Fence (` ```json ... ``` `) abloesen falls vorhanden.
    3. Greedy-Brace-Fallback: vom ersten ``{`` bis zum letzten ``}`` — schuetzt
       gegen ``"Here is the JSON:\\n{...}\\nLet me know..."``-Begleittext.
    """
    s = content
    for pat in _REASONING_BLOCK_PATTERNS:
        s = pat.sub("", s)
    s = s.strip()
    m = _MARKDOWN_JSON_FENCE.match(s)
    if m:
        s = m.group(1).strip()
    if not s.startswith("{"):
        m2 = _GREEDY_BRACES.search(s)
        if m2:
            s = m2.group(0)
    return s.strip()


def _extract_reasoning(message: Any) -> str | None:
    """Liest Reasoning-Inhalt von verschiedenen Provider-Patterns:

    * OpenAI o1-Style: ``message.reasoning`` (Direct-Attribute).
    * DeepSeek-R1: ``message.reasoning_content`` (Direct-Attribute).
    * DeepInfra GPT-OSS via OpenAI-SDK: ``message.model_extra["reasoning_content"]``
      (Pydantic-V2-extra-Bucket — ``content`` selbst ist clean JSON).
    * Fallback: ``None``.
    """
    for attr in ("reasoning", "reasoning_content", "thinking"):
        val = getattr(message, attr, None)
        if val:
            return str(val)
    extra = getattr(message, "model_extra", None) or {}
    for key in ("reasoning_content", "reasoning", "thinking"):
        val = extra.get(key)
        if val:
            return str(val)
    return None


# ---------------------------------------------------------------------------
# Pattern-Sanitization
# ---------------------------------------------------------------------------


def _is_ascii_no_nul(s: str) -> bool:
    return "\x00" not in s and all(ord(c) < 128 for c in s)


def _sanitize_path_prefix(s: str) -> str | None:
    """Validiert und normalisiert einen LLM-emittierten Path-Prefix.

    Akzeptiert sowohl absolute (``/AdminLTE-master/``) als auch relative
    (``AdminLTE-master/``) Form vom LLM — der PASS1-Prompt verlangt zwar
    explizit „absolute path prefixes" mit Leading-Slash, in der Praxis liefert
    Trivy aber bei ``rootfs /``-Scans Pfade RELATIV zur Scan-Root (siehe
    ``agent/fathometer-agent.sh::SCAN_PATH``-Default ``"/"`` plus Trivy-Konvention
    Pfade ohne Leading-Slash zu reporten).

    Bugfix 2026-05-24: persistiere immer in normalisierter relativer Form
    (``lstrip("/")``), damit der Matcher in ``group_matcher.py`` deterministisch
    gegen Trivys Output vergleichen kann. Forbidden-Set und Min-/Max-Laenge
    werden NACH der Normalisierung geprueft, damit ``"/"`` allein nicht durch
    Strip zur leeren Zeichenkette wird und trotzdem als forbidden gilt.
    """
    if not isinstance(s, str):
        return None
    stripped = s.strip()
    if stripped in _FORBIDDEN_PATTERNS:
        return None
    if not _is_ascii_no_nul(stripped):
        return None
    normalized = stripped.lstrip("/")
    # Nach dem Strip nochmal pruefen — ein reines ``"/"`` oder ``"////"`` wird
    # zu leer.
    if not normalized or normalized in _FORBIDDEN_PATTERNS:
        return None
    if not (_PATH_PREFIX_MIN <= len(normalized) <= _PATH_PREFIX_MAX):
        return None
    return normalized


def _sanitize_pkg_name(s: str) -> str | None:
    if not isinstance(s, str):
        return None
    stripped = s.strip()
    if stripped in _FORBIDDEN_PATTERNS:
        return None
    if not (1 <= len(stripped) <= _PKG_NAME_MAX):
        return None
    if not _is_ascii_no_nul(stripped):
        return None
    return stripped


def _sanitize_pkg_glob(s: str) -> str | None:
    if not isinstance(s, str):
        return None
    stripped = s.strip()
    if stripped in _FORBIDDEN_PATTERNS:
        return None
    # Pure-`*`-only-Pattern verboten (zu generisch).
    if stripped.replace("*", "").strip() == "":
        return None
    if not (1 <= len(stripped) <= _PKG_NAME_MAX):
        return None
    if not _is_ascii_no_nul(stripped):
        return None
    return stripped


def _sanitize_purl_pattern(s: str) -> str | None:
    if not isinstance(s, str):
        return None
    stripped = s.strip()
    if stripped in _FORBIDDEN_PATTERNS:
        return None
    if not (1 <= len(stripped) <= _PKG_PURL_MAX):
        return None
    if not _is_ascii_no_nul(stripped):
        return None
    return stripped


# ---------------------------------------------------------------------------
# LLM-Call-Helper
# ---------------------------------------------------------------------------


async def chat_completion_json_with_meta(
    client: LlmClient,
    *,
    system_prompt: str,
    user_prompt: str,
    schema: dict[str, Any],
    max_tokens: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """LLM-Call mit Meta-Return-Tuple (parsed, meta).

    ``meta`` enthaelt:

    * ``raw_content`` — der unveraenderte ``message.content``-String (oder
      ``None`` falls leer).
    * ``extracted_json`` — der String nachdem
      :func:`_extract_json_from_response` Reasoning-Wrapper/Fences/etc.
      gestrippt hat. Identisch zu ``raw_content`` wenn der Provider
      bereits clean JSON liefert.
    * ``reasoning_field`` — Provider-Reasoning falls vorhanden (siehe
      :func:`_extract_reasoning`), sonst ``None``.
    * ``model`` — das angefragte Modell (``client.model``).
    * ``duration_ms`` — Wall-Clock-Dauer des SDK-Calls.
    * ``usage`` — ``response.usage``-Dict falls geliefert, sonst ``None``.

    Wirft :class:`LLMTimeoutError` bei Timeout,
    :class:`LLMInvalidResponseError` wenn die Response keinen gueltigen
    JSON-Block enthaelt.
    """
    sdk = client._sdk  # intentional Block-G-Reuse.
    started_at = time.monotonic()
    try:
        response = await sdk.chat.completions.create(
            model=client.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            stream=False,
            max_tokens=max_tokens,
            # v0.9.4: explizit temperature=0 wie in P-evidence/prompt-pass{1,2}-final.md
            # spezifiziert — wichtig fuer Idempotenz bei Pass-1-Group-Labels
            # (Batch-Merge-Logik braucht deterministische Outputs).
            temperature=0,
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "fathometer_risk_review",
                    "schema": schema,
                    "strict": False,
                },
            },
        )
    except TimeoutError as exc:
        # v0.9.x: meta-Dict an Timeout-Exception haengen (analog zum
        # LLMInvalidResponseError-Pfad) damit der Debug-Log nicht leer
        # bleibt. Reviewer-Wrapper (pass1/pass2) reichert um Prompts an.
        timeout_meta: dict[str, Any] = {
            "raw_content": None,
            "extracted_json": None,
            "reasoning_field": None,
            "model": client.model,
            "duration_ms": int((time.monotonic() - started_at) * 1000),
            "usage": None,
            "finish_reason": None,
            "max_tokens": max_tokens,
        }
        raise LLMTimeoutError(str(exc), meta=timeout_meta) from exc
    except Exception as exc:  # pragma: no cover — Provider-Quirks
        if type(exc).__name__.lower().find("timeout") >= 0:
            timeout_meta = {
                "raw_content": None,
                "extracted_json": None,
                "reasoning_field": None,
                "model": client.model,
                "duration_ms": int((time.monotonic() - started_at) * 1000),
                "usage": None,
                "finish_reason": None,
                "max_tokens": max_tokens,
            }
            raise LLMTimeoutError(str(exc), meta=timeout_meta) from exc
        raise
    duration_ms = int((time.monotonic() - started_at) * 1000)

    choices = getattr(response, "choices", None) or []
    if not choices:
        raise LLMInvalidResponseError("LLM response hat keine choices")
    # v0.9.7: finish_reason capturen — bei GPT-OSS-120B kann
    # finish_reason="length" mit content="" auftreten wenn das Modell
    # alle max_tokens fuers Reasoning verbraucht hat.
    finish_reason = getattr(choices[0], "finish_reason", None)
    message = choices[0].message
    raw_content = getattr(message, "content", None)
    reasoning_field = _extract_reasoning(message)

    usage_obj = getattr(response, "usage", None)
    usage: dict[str, Any] | None = None
    if usage_obj is not None:
        # Pydantic-Model oder Plain-Dict — beides unterstuetzen.
        if hasattr(usage_obj, "model_dump"):
            usage = dict(usage_obj.model_dump())
        elif isinstance(usage_obj, dict):
            usage = dict(usage_obj)
        else:
            usage = {
                k: getattr(usage_obj, k, None)
                for k in ("prompt_tokens", "completion_tokens", "total_tokens")
            }

    # Meta-Dict moeglichst frueh bauen damit Exception-Pfade es mit-werfen
    # koennen (siehe v0.9.5: LLMInvalidResponseError.meta).
    meta: dict[str, Any] = {
        "raw_content": raw_content,
        "extracted_json": None,
        "reasoning_field": reasoning_field,
        "model": client.model,
        "duration_ms": duration_ms,
        "usage": usage,
        "finish_reason": finish_reason,
    }

    if not raw_content or not isinstance(raw_content, str):
        # v0.9.7: bei finish_reason="length" + leerem content ist das fast
        # immer ein max_tokens-Cap-Hit waehrend des Reasonings. Praeziser
        # Error-Text damit Operator die Ursache sofort sieht.
        if finish_reason == "length":
            raise LLMInvalidResponseError(
                "LLM response hat leeren content (finish_reason=length — "
                "max_tokens-Cap waehrend Reasoning erreicht, kein JSON-Output)",
                meta=meta,
            )
        raise LLMInvalidResponseError(
            f"LLM response hat leeren content (finish_reason={finish_reason!r})",
            meta=meta,
        )

    extracted = _extract_json_from_response(raw_content)
    meta["extracted_json"] = extracted
    try:
        parsed = json.loads(extracted)
    except json.JSONDecodeError as exc:
        raise LLMInvalidResponseError(
            f"LLM response ist kein valides JSON: {exc}", meta=meta
        ) from exc
    if not isinstance(parsed, dict):
        raise LLMInvalidResponseError("LLM response ist kein JSON-Object", meta=meta)

    return parsed, meta


async def chat_completion_json(
    client: LlmClient,
    *,
    system_prompt: str,
    user_prompt: str,
    schema: dict[str, Any],
    max_tokens: int,
) -> dict[str, Any]:
    """Backward-Compat-Wrapper um :func:`chat_completion_json_with_meta`.

    Liefert nur das geparste Dict; Meta-Daten werden verworfen.
    """
    parsed, _meta = await chat_completion_json_with_meta(
        client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        schema=schema,
        max_tokens=max_tokens,
    )
    return parsed


# ---------------------------------------------------------------------------
# Reviewer-Service
# ---------------------------------------------------------------------------


class LLMRiskReviewer:
    """Zwei-Pass-LLM-Wrapper fuer Block-P-Risk-Assessment.

    Tests koennen ``client`` als Mock uebergeben. In Production wird der
    Client vom Worker-Loop erzeugt (Block-G-:func:`build_client_from_settings`)
    und pro Job-Batch wiederverwendet.
    """

    def __init__(self, client: LlmClient | None = None) -> None:
        if client is None:
            # Lazy: in Production baut der Worker den Client mit
            # `build_client_from_settings`. Wir vermeiden einen automatischen
            # Build hier, damit Tests die Klasse ohne DB instanziieren koennen.
            raise ValueError("LLMRiskReviewer requires an explicit client")
        self.client: LlmClient = client

    # ---- Pass 1 ----------------------------------------------------------

    async def pass1_detect_groups(
        self, findings: Sequence[Finding]
    ) -> tuple[Pass1Result, dict[str, Any]]:
        """LLM-Call mit kompakter Finding-Identitaet.

        Returns ``(validated_result, meta)``. ``meta`` enthaelt
        ``system_prompt``/``user_prompt``/``raw_content``/``extracted_json``/
        ``reasoning_field``/``model``/``duration_ms``/``usage`` fuer den
        :mod:`app.services.llm_debug_log`-Insert im Worker.
        """
        user_prompt = self._render_pass1_prompt(findings)
        cfg = load_settings()
        # v0.9.x: try/except um chat_completion_json_with_meta — bei Timeout
        # ODER frueh-wurf-Invalid-Response (leeren content / JSON-Parse-Fail)
        # haengt der Helper schon meta an die Exception, aber OHNE die
        # Prompts. Hier reichern wir um system_prompt/user_prompt an, damit
        # der Debug-Log im Worker komplett sichtbar ist.
        try:
            response, meta = await chat_completion_json_with_meta(
                self.client,
                system_prompt=PASS1_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                schema=PASS1_RESPONSE_SCHEMA,
                max_tokens=cfg.llm_pass1_max_tokens,
            )
        except (LLMInvalidResponseError, LLMTimeoutError) as exc:
            if exc.meta is None:
                exc.meta = {}
            exc.meta["system_prompt"] = PASS1_SYSTEM_PROMPT
            exc.meta["user_prompt"] = user_prompt
            exc.meta["max_tokens"] = cfg.llm_pass1_max_tokens
            raise
        meta = dict(meta)
        meta["system_prompt"] = PASS1_SYSTEM_PROMPT
        meta["user_prompt"] = user_prompt
        meta["max_tokens"] = cfg.llm_pass1_max_tokens
        # v0.9.5: bei Validation-Error meta an Exception anhaengen, damit der
        # Worker auch im Failure-Pfad raw_content/extracted_json/usage in den
        # llm_debug_log schreibt (vorher: leeres Debug-Log-Body, Operator
        # blind).
        try:
            validated = self._validate_pass1_response(response, list(findings))
        except LLMInvalidResponseError as exc:
            exc.meta = meta
            raise
        return validated, meta

    def _render_pass1_prompt(self, findings: Sequence[Finding]) -> str:
        """Findings als kompakte Tabelle mit den fuer Group-Detection
        relevanten Feldern. Keine CVE-Daten, kein Server-Kontext."""
        lines: list[str] = []
        lines.append("Hier sind die Findings, die du gruppieren sollst. Felder pro Zeile:")
        lines.append("finding_id | package_name | target_path | package_purl | result_type")
        lines.append("")
        for f in findings:
            pkg = (f.package_name or "")[:128]
            tp = (f.target_path or "-")[:256]
            purl = (f.package_purl or "-")[:256]
            rt = (f.result_type or "-")[:64]
            lines.append(f"{f.id} | {pkg} | {tp} | {purl} | {rt}")
        lines.append("")
        lines.append(
            "Antworte JSON nach Schema: groups[] mit label/explanation/match_rules/"
            "finding_ids und ungrouped[] fuer Findings ohne klare Owner-Application."
        )
        return "\n".join(lines)

    def _validate_pass1_response(
        self,
        response: dict[str, Any],
        findings: list[Finding],
    ) -> Pass1Result:
        input_ids: set[int] = {int(f.id) for f in findings}
        seen_in_groups: set[int] = set()

        groups_raw = response.get("groups")
        if not isinstance(groups_raw, list):
            raise LLMInvalidResponseError("Pass1: `groups` fehlt oder ist keine Liste")
        ungrouped_raw = response.get("ungrouped")
        if not isinstance(ungrouped_raw, list):
            raise LLMInvalidResponseError("Pass1: `ungrouped` fehlt oder ist keine Liste")

        validated_groups: list[Pass1Group] = []
        seen_labels: set[str] = set()
        for grp_raw in groups_raw:
            if not isinstance(grp_raw, dict):
                raise LLMInvalidResponseError("Pass1: Group-Eintrag ist kein Objekt")
            label = grp_raw.get("label")
            if not isinstance(label, str) or not LABEL_PATTERN.match(label):
                raise LLMInvalidResponseError(
                    f"Pass1: Label verletzt Regex {LABEL_PATTERN.pattern!r}: {label!r}"
                )
            if label in seen_labels:
                raise LLMInvalidResponseError(f"Pass1: doppeltes Group-Label {label!r}")
            seen_labels.add(label)

            explanation = grp_raw.get("explanation")
            if explanation is not None and not isinstance(explanation, str):
                raise LLMInvalidResponseError("Pass1: `explanation` muss string oder null sein")
            if isinstance(explanation, str) and "\x00" in explanation:
                raise LLMInvalidResponseError("Pass1: `explanation` enthaelt NUL-Byte")

            rules = grp_raw.get("match_rules") or {}
            if not isinstance(rules, dict):
                raise LLMInvalidResponseError("Pass1: `match_rules` ist kein Objekt")
            path_prefixes = self._sanitize_list(rules.get("path_prefixes"), _sanitize_path_prefix)
            pkg_name_exact = self._sanitize_list(rules.get("pkg_name_exact"), _sanitize_pkg_name)
            pkg_name_glob = self._sanitize_list(rules.get("pkg_name_glob"), _sanitize_pkg_glob)
            pkg_purl_pattern = self._sanitize_list(
                rules.get("pkg_purl_pattern"), _sanitize_purl_pattern
            )

            finding_ids_raw = grp_raw.get("finding_ids")
            if not isinstance(finding_ids_raw, list):
                raise LLMInvalidResponseError(
                    f"Pass1: Group {label!r} `finding_ids` ist keine Liste"
                )
            finding_ids: list[int] = []
            for fid in finding_ids_raw:
                if not isinstance(fid, int) or isinstance(fid, bool):
                    raise LLMInvalidResponseError(
                        f"Pass1: Group {label!r} hat nicht-Integer finding_id {fid!r}"
                    )
                if fid not in input_ids:
                    raise LLMInvalidResponseError(
                        f"Pass1: Group {label!r} hat halluzinierte "
                        f"finding_id {fid} (nicht im Input)"
                    )
                if fid in seen_in_groups:
                    raise LLMInvalidResponseError(f"Pass1: finding_id {fid} in mehreren Groups")
                seen_in_groups.add(fid)
                finding_ids.append(fid)

            validated_groups.append(
                Pass1Group(
                    label=label,
                    explanation=explanation,
                    path_prefixes=path_prefixes,
                    pkg_name_exact=pkg_name_exact,
                    pkg_name_glob=pkg_name_glob,
                    pkg_purl_pattern=pkg_purl_pattern,
                    finding_ids=finding_ids,
                )
            )

        ungrouped_ids: list[int] = []
        for fid in ungrouped_raw:
            if not isinstance(fid, int) or isinstance(fid, bool):
                raise LLMInvalidResponseError(f"Pass1: `ungrouped` hat nicht-Integer-Wert {fid!r}")
            if fid not in input_ids:
                raise LLMInvalidResponseError(
                    f"Pass1: halluzinierte ungrouped finding_id {fid} (nicht im Input)"
                )
            if fid in seen_in_groups:
                raise LLMInvalidResponseError(
                    f"Pass1: finding_id {fid} sowohl in einer Group als auch ungrouped"
                )
            ungrouped_ids.append(fid)

        # Vollstaendigkeits-Check: jeder Input-Finding muss abgedeckt sein.
        accounted = seen_in_groups | set(ungrouped_ids)
        missing = input_ids - accounted
        if missing:
            preview = sorted(missing)[:5]
            raise LLMInvalidResponseError(
                f"Pass1: {len(missing)} Findings nicht zugeordnet (z.B. {preview})"
            )

        return Pass1Result(groups=validated_groups, ungrouped_finding_ids=ungrouped_ids)

    @staticmethod
    def _sanitize_list(
        raw: Any,
        sanitizer: Any,
    ) -> list[str]:
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise LLMInvalidResponseError(
                f"Pass1: Pattern-Liste ist keine Liste, sondern {type(raw).__name__}"
            )
        out: list[str] = []
        for item in raw:
            cleaned = sanitizer(item)
            if cleaned is not None:
                out.append(cleaned)
        return out

    # ---- Pass 2 ----------------------------------------------------------

    async def pass2_evaluate_groups(
        self,
        server: Server,
        groups_with_findings: Sequence[tuple[ApplicationGroup, list[Finding]]],
    ) -> tuple[Pass2Result, dict[str, Any]]:
        """LLM-Call mit Server-Kontext + Groups.

        Returns ``(validated_result, meta)`` — siehe :meth:`pass1_detect_groups`
        fuer die Meta-Felder.
        """
        # TICKET-011: deterministische Worst-Selektion EINMAL berechnen und
        # an Render UND Validierung durchreichen — worst_finding_id wird
        # gegen die gezeigten IDs geprueft, nicht gegen die volle Group.
        selections = self._select_for_groups(groups_with_findings)
        user_prompt = self._render_pass2_prompt(server, groups_with_findings, selections)
        cfg = load_settings()
        # v0.9.x: try/except um chat_completion_json_with_meta — analog Pass-1.
        try:
            response, meta = await chat_completion_json_with_meta(
                self.client,
                system_prompt=PASS2_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                schema=PASS2_RESPONSE_SCHEMA,
                max_tokens=cfg.llm_pass2_max_tokens,
            )
        except (LLMInvalidResponseError, LLMTimeoutError) as exc:
            if exc.meta is None:
                exc.meta = {}
            exc.meta["system_prompt"] = PASS2_SYSTEM_PROMPT
            exc.meta["user_prompt"] = user_prompt
            exc.meta["max_tokens"] = cfg.llm_pass2_max_tokens
            raise
        meta = dict(meta)
        meta["system_prompt"] = PASS2_SYSTEM_PROMPT
        meta["user_prompt"] = user_prompt
        meta["max_tokens"] = cfg.llm_pass2_max_tokens
        # v0.9.5: bei Validation-Error meta an Exception anhaengen, damit der
        # Worker auch im Failure-Pfad raw_content/extracted_json/usage in den
        # llm_debug_log schreibt (vorher: leeres Debug-Log-Body, Operator
        # blind).
        try:
            validated = self._validate_pass2_response(
                response, list(groups_with_findings), selections
            )
        except LLMInvalidResponseError as exc:
            exc.meta = meta
            raise
        return validated, meta

    @staticmethod
    def _select_for_groups(
        groups_with_findings: Sequence[tuple[ApplicationGroup, list[Finding]]],
    ) -> dict[str, SelectionResult]:
        """Pass-2-Input-Selektion pro Group (TICKET-011)."""
        return {grp.label: select_pass2_findings(fs) for grp, fs in groups_with_findings}

    def _render_pass2_prompt(
        self,
        server: Server,
        groups_with_findings: Sequence[tuple[ApplicationGroup, list[Finding]]],
        selections: dict[str, SelectionResult] | None = None,
    ) -> str:
        if selections is None:
            selections = self._select_for_groups(groups_with_findings)
        lines: list[str] = []
        lines.append("host_context:")
        lines.append(
            f"  os: {server.os_pretty_name or server.os_family or '-'}"
            f" {server.os_version or ''}".strip()
        )
        # v0.9.3 (ADR-0023 §"Tags-Exclusion"): Tags werden NICHT mehr an das
        # LLM weitergereicht — sie sind User-Freitext-Labels ohne garantierte
        # Semantik. Exposure-Bewertung erfolgt ausschliesslich ueber Listener-
        # Adressen plus LLM-Reasoning (PUBLIC-EXPOSED/LOOPBACK-ONLY/NO-LISTENER).

        listeners = getattr(server, "listeners", []) or []
        if listeners:
            lines.append("  listeners (proto/addr:port -> process):")
            sorted_li = sorted(listeners, key=lambda li: (li.port, li.proto, li.addr or ""))
            for li in sorted_li[:64]:
                lines.append(f"    {li.proto} {li.addr}:{li.port} {li.process or '-'}")
        modules = sorted(
            (m.name for m in (getattr(server, "kernel_modules", []) or [])),
        )
        if modules:
            lines.append("  kernel_modules: " + ", ".join(modules[:80]))
        services = sorted(
            (s.name for s in (getattr(server, "services", []) or [])),
        )
        if services:
            lines.append("  active_services: " + ", ".join(services[:80]))
        comms = sorted({p.comm for p in (getattr(server, "processes", []) or []) if p.comm})
        if comms:
            lines.append("  process_commands (unique): " + ", ".join(comms[:80]))

        lines.append("")
        lines.append("groups_to_evaluate:")
        for grp, fs in groups_with_findings:
            lines.append(f"  group: {grp.label}")
            if grp.explanation:
                lines.append(f"    explanation: {grp.explanation[:256]}")
            lines.append(f"    findings_in_group ({len(fs)} total):")
            # Kompakte Zusammenfassung — deterministische Worst-Selektion
            # (TICKET-011, `pass2_input_selection`) statt des frueheren
            # zufaelligen ``fs[:32]``-Caps; der Rest wird aggregiert.
            # Per-Finding-Felder: cvss, epss, kev, fix sind explizit gelistet
            # damit das LLM bewerten kann (siehe PASS2_SYSTEM_PROMPT
            # "Severity / Exploit signal / Patch availability"-Sektion).
            # NULL-Werte werden als ``n/a`` bzw. ``none`` gerendert; der
            # System-Prompt sagt das Modell, "n/a" nicht als Eskalations-
            # Signal zu werten.
            sel = selections[grp.label]
            for f in sel.selected:
                vendor_map = f.severity_by_provider or {}
                vendor_str = ",".join(f"{k}={v}" for k, v in sorted(vendor_map.items()))[:80]
                cvss_str = (
                    f" cvss={f.cvss_v3_score:.1f}" if f.cvss_v3_score is not None else " cvss=n/a"
                )
                epss_str = f" epss={f.epss_score:.2f}" if f.epss_score is not None else " epss=n/a"
                fix_str = f" fix={f.fixed_version}" if f.fixed_version else " fix=none"
                kev_str = " kev=yes" if f.is_kev else " kev=no"
                # Bugfix 2026-05-24 (ADR-0023 Nachtrag): Per-Finding-Pfad mit
                # in den Prompt — siehe PASS2_SYSTEM_PROMPT-Block "Path-based
                # exposure judgment". Pfad wird auf 128 Chars gecappt (Token-
                # Budget); fehlt er, kommt der Marker `path=n/a` statt einer
                # leeren Stelle, damit das Modell explizit signalisiert wird
                # dass Pfad-Reasoning nicht moeglich ist.
                path_raw = (f.target_path or "").strip()
                path_str = f" path={path_raw[:128]}" if path_raw else " path=n/a"
                # TICKET-011 (User-Entscheidung 2): title (destillierte
                # Description) + av (CVSS-Attack-Vector) statt voller
                # CVE-Description. Title ist Fremdtext und bleibt via
                # `_sanitize_prompt_title` auf eine Zeile begrenzt.
                av_str = (
                    f" av={f.attack_vector.value}"
                    if f.attack_vector is not None and f.attack_vector != AttackVector.UNKNOWN
                    else " av=n/a"
                )
                title_str = (
                    f' title="{_sanitize_prompt_title(f.title)}"' if f.title else " title=n/a"
                )
                lines.append(
                    f"      {f.id} {f.identifier_key} {f.package_name} "
                    f"sev={f.severity.value}{cvss_str}{epss_str}{fix_str}{kev_str}{av_str}"
                    f"{path_str} "
                    f"{vendor_str}{title_str}"
                )
            if sel.rest_count:
                agg_parts = [f"{count} {sev}" for sev, count in sel.rest_severity_counts]
                agg_parts.append(
                    f"max_epss={sel.rest_max_epss:.2f}"
                    if sel.rest_max_epss is not None
                    else "max_epss=n/a"
                )
                agg_parts.append(f"{sel.rest_fixable_count} fixable")
                agg_parts.append(f"{sel.rest_kev_count} kev")
                lines.append(f"      ... ({sel.rest_count} more: {', '.join(agg_parts)})")
            lines.append("")

        lines.append(
            "Return per group: group_label (exactly as above), risk_band "
            "from {escalate, act, monitor, noise}, action_type from "
            "{patch, mitigate, watch, none}, worst_finding_id (MUST be one "
            "of the finding ids listed above for that group), reason <= 256 "
            "chars. The (risk_band, action_type) combination MUST come from "
            "the whitelist in the system prompt."
        )
        return "\n".join(lines)

    def _validate_pass2_response(
        self,
        response: dict[str, Any],
        groups_with_findings: list[tuple[ApplicationGroup, list[Finding]]],
        selections: dict[str, SelectionResult] | None = None,
    ) -> Pass2Result:
        if selections is None:
            selections = self._select_for_groups(groups_with_findings)
        # TICKET-011 (Bug C): worst_finding_id wird gegen die GEZEIGTEN
        # IDs (Selektion) validiert, nicht gegen die volle Group — das
        # LLM hat nur die selektierten Findings gesehen; Reason und
        # Worst-Finding duerfen nicht auseinanderfallen.
        input_labels: dict[str, frozenset[int]] = {
            grp.label: selections[grp.label].selected_ids for grp, _fs in groups_with_findings
        }

        evals_raw = response.get("evaluations")
        if not isinstance(evals_raw, list):
            raise LLMInvalidResponseError("Pass2: `evaluations` fehlt oder ist keine Liste")

        validated: list[Pass2Evaluation] = []
        seen_labels: set[str] = set()
        for ev_raw in evals_raw:
            if not isinstance(ev_raw, dict):
                raise LLMInvalidResponseError("Pass2: Eintrag ist kein Objekt")
            label = ev_raw.get("group_label")
            if not isinstance(label, str):
                raise LLMInvalidResponseError(f"Pass2: `group_label` ist kein String: {label!r}")
            if label not in input_labels:
                raise LLMInvalidResponseError(
                    f"Pass2: halluzinierter group_label {label!r} "
                    f"(nicht in Input {sorted(input_labels)})"
                )
            if label in seen_labels:
                raise LLMInvalidResponseError(f"Pass2: doppelter group_label {label!r}")
            seen_labels.add(label)

            band = ev_raw.get("risk_band")
            if band not in VALID_RISK_BANDS:
                raise LLMInvalidResponseError(
                    f"Pass2: Group {label!r} hat ungueltiges risk_band {band!r} "
                    f"(erlaubt: {sorted(VALID_RISK_BANDS)})"
                )
            # Legacy-Mapping (ADR-0023 §"Risk-Band-Reduktion auf 4 aktive
            # Werte"): wenn das LLM trotz neuem Prompt noch ``mitigate`` als
            # ``risk_band`` liefert (Backward-Compat / Provider-Drift),
            # mappen wir intern auf ``escalate`` und loggen das.
            if band == "mitigate":
                log.warning(
                    "llm.legacy_mitigate_band_observed",
                    group_label=label,
                )
                band = "escalate"

            action_type = ev_raw.get("action_type")
            if not isinstance(action_type, str) or action_type not in VALID_ACTION_TYPES:
                raise LLMInvalidResponseError(
                    f"Pass2: Group {label!r} hat ungueltiges action_type {action_type!r} "
                    f"(erlaubt: {sorted(VALID_ACTION_TYPES)})"
                )
            if (band, action_type) not in ALLOWED_BAND_ACTION_COMBOS:
                raise LLMInvalidResponseError(
                    f"Pass2: Group {label!r} hat unzulaessige (risk_band, action_type) "
                    f"Kombination ({band!r}, {action_type!r}); "
                    f"Whitelist: {sorted(ALLOWED_BAND_ACTION_COMBOS)}"
                )

            reason = ev_raw.get("reason")
            if not isinstance(reason, str):
                raise LLMInvalidResponseError(f"Pass2: Group {label!r} `reason` ist kein String")
            if "\x00" in reason:
                raise LLMInvalidResponseError(f"Pass2: Group {label!r} `reason` enthaelt NUL-Byte")
            if len(reason) > MAX_REASON_LEN:
                raise LLMInvalidResponseError(
                    f"Pass2: Group {label!r} `reason` ueberschreitet "
                    f"{MAX_REASON_LEN} chars ({len(reason)})"
                )

            worst_raw = ev_raw.get("worst_finding_id")
            worst_id: int | None
            if worst_raw is None:
                worst_id = None
            elif isinstance(worst_raw, int) and not isinstance(worst_raw, bool):
                if worst_raw not in input_labels[label]:
                    raise LLMInvalidResponseError(
                        f"Pass2: Group {label!r} worst_finding_id={worst_raw} "
                        f"ist nicht Mitglied der im Prompt gezeigten Findings"
                    )
                worst_id = worst_raw
            else:
                raise LLMInvalidResponseError(
                    f"Pass2: Group {label!r} worst_finding_id ist kein Integer: {worst_raw!r}"
                )

            validated.append(
                Pass2Evaluation(
                    group_label=label,
                    risk_band=cast(
                        Literal["escalate", "act", "mitigate", "monitor", "noise"],
                        band,
                    ),
                    action_type=cast(
                        Literal["patch", "mitigate", "watch", "none"],
                        action_type,
                    ),
                    reason=reason,
                    worst_finding_id=worst_id,
                )
            )

        return Pass2Result(evaluations=validated)


__all__ = [
    "ALLOWED_BAND_ACTION_COMBOS",
    "LABEL_PATTERN",
    "MAX_REASON_LEN",
    "PASS1_RESPONSE_SCHEMA",
    "PASS1_SYSTEM_PROMPT",
    "PASS2_RESPONSE_SCHEMA",
    "PASS2_SYSTEM_PROMPT",
    "VALID_ACTION_TYPES",
    "VALID_RISK_BANDS",
    "LLMInvalidResponseError",
    "LLMRiskReviewer",
    "LLMTimeoutError",
    "Pass1Group",
    "Pass1Result",
    "Pass2Evaluation",
    "Pass2Result",
    "chat_completion_json",
    "chat_completion_json_with_meta",
]
