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
  — das sind reine Pre-Triage-Werte), ``worst_finding_id`` muss Group-
  Mitglied sein, ``reason`` <= 256 chars und NUL-frei.

Der LLM-Call selbst geht ueber einen duennen Helper :func:`chat_completion_json`,
der auf dem Block-G-:class:`app.services.llm_client.LlmClient` aufsetzt
(kein Refactoring an Block G).
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.config import load_settings
from app.models import ApplicationGroup, Finding, Server

if TYPE_CHECKING:
    from app.services.llm_client import LlmClient


# ---------------------------------------------------------------------------
# Konstanten / Regex / Schemas
# ---------------------------------------------------------------------------


# Label-Whitelist gemaess ADR-0023 §"Backend-Validierung": kleinbuchstaben,
# Ziffern, ``_-``. Erstes Zeichen alphanumerisch, max 64 chars.
LABEL_PATTERN: re.Pattern[str] = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

# Reason-Hardlimit pro ADR-0023 §"Backend-Validierung".
MAX_REASON_LEN: int = 256

# Final-LLM-Bands (Whitelist; pending/unknown bewusst NICHT zugelassen).
VALID_RISK_BANDS: frozenset[str] = frozenset({"escalate", "act", "mitigate", "monitor", "noise"})

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
                "required": ["group_label", "risk_band", "reason"],
                "properties": {
                    "group_label": {"type": "string", "maxLength": 64},
                    "risk_band": {
                        "type": "string",
                        "enum": ["escalate", "act", "mitigate", "monitor", "noise"],
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
    """Eine Group-Bewertung aus Pass 2."""

    model_config = ConfigDict(extra="ignore")

    group_label: str
    risk_band: Literal["escalate", "act", "mitigate", "monitor", "noise"]
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
    """LLM-Output ist schema- oder semantik-invalid (Halluzination, falsches Band, ...)."""


class LLMTimeoutError(RuntimeError):
    """LLM-Call hat das konfigurierte Timeout ueberschritten."""


# ---------------------------------------------------------------------------
# System-Prompts (wortgetreu aus ADR-0023)
# ---------------------------------------------------------------------------


PASS1_SYSTEM_PROMPT: str = """\
Du gruppierst Vulnerability-Findings auf einem Linux-Host nach
Owner-Application. Eine Owner-Application ist die Software die der
Operator als Einheit installiert/updated (z.B. "k3s", "openssh-server",
"grafana"). Sub-Komponenten die mit der Owner-Application kommen
(containerd in k3s, coredns in k3s, kubelet in k3s) gehoeren in die
Owner-Group, NICHT in eigene Sub-Groups.

WICHTIG fuer die Group-Labels:
- Waehle Namen so generisch wie moeglich, damit Pfad-Aenderungen bei
  minor/patch-Updates derselben Application weiter matchen. Beispiel:
  "k3s", nicht "k3s-1.23".
- Verschiedene Major-Produkte sind verschiedene Groups: RKE und RKE2 ja,
  k3s und rke2 ja. Sub-Komponenten einer Application bleiben in derselben
  Group: kein "k3s-containerd", "k3s-coredns".
- Distro-OS-Pakete bekommen ihren package_name als Group-Label (z.B.
  "openssh-server", "openssl"), kein Sub-Splitting.
- Label-Regex: ^[a-z0-9][a-z0-9_-]{0,63}$ (kleinbuchstaben, Ziffern,
  _ oder -, max 64 chars, erstes Zeichen alphanumerisch).

Liefere fuer jede Group:
- label (kurz, kleinbuchstaben, max 64 chars)
- explanation (max 256 chars, was die Group ist)
- match_rules: path_prefixes[], pkg_name_exact[], pkg_name_glob[],
  pkg_purl_pattern[] — so dass zukuenftige aehnliche Findings ohne
  weiteren LLM-Call automatisch zugeordnet werden koennen
- finding_ids: Liste der zugeordneten IDs aus dem Input

Jedes Finding aus dem Input MUSS in genau einer Group ODER im
"ungrouped"-Array landen. Erfinde keine finding_ids die nicht im Input
sind. Antworte ausschliesslich mit gueltigem JSON nach dem Schema.
"""


PASS2_SYSTEM_PROMPT: str = """\
Du bist ein erfahrener IT-Sicherheits-Analyst. Du bewertest pro
Application-Group das Risiko auf einem konkreten Host.

Bewerte jede Group in eines von fuenf Risikobaendern:
- escalate: KEV-gelistet und Application ist auf diesem Host aktiv
  und/oder erreichbar (oder: kritisch ohne Patch-Pfad)
- act: Application aktiv/erreichbar, Patch verfuegbar oder erwartbar
  (Operator soll updaten)
- mitigate: Application aktiv/erreichbar, KEIN Patch verfuegbar oder
  will_not_fix (Operator muss anders eindaemmen)
- monitor: Application nicht klar aktiv ODER ohne klare Exposure,
  beobachten
- noise: Application erkennbar nicht aktiv (z.B. kein Bluetooth-Modul
  geladen, kein bluetoothd-Prozess)

Die Werte "pending" und "unknown" sind verboten — das sind reine
Pre-Triage-Werte aus einer frueheren Engine-Stufe.

WICHTIG fuer den Reason-Text:
- Sage NICHT konkret welche Application-Version den Patch mitbringt.
  Beispiel verboten: "Update auf k3s >= v1.30.4-rc1". Du kannst nicht
  zuverlaessig wissen welche k3s-Release welche Go-Toolchain mitzieht.
- Stattdessen formuliere ehrlich: "Patch in der zugrundeliegenden
  Library verfuegbar — Operator muss pruefen welche k3s-Release diese
  Library-Version enthaelt oder Mitigation einsetzen."
- Bei OS-Distro-Paketen (openssh-server, openssl, etc.) kannst du
  sagen "Patch verfuegbar im Distro-Repository" oder "Vendor markiert
  als will-not-fix", aber KEIN konkreter Befehl wie "apt-get install".
- Reason max 256 chars, ASCII bevorzugt, KEINE NUL-Bytes.

Liefere pro Group: group_label, risk_band, worst_finding_id (oder null),
reason. Antworte ausschliesslich mit gueltigem JSON nach dem Schema.
"""


# ---------------------------------------------------------------------------
# Pattern-Sanitization
# ---------------------------------------------------------------------------


def _is_ascii_no_nul(s: str) -> bool:
    return "\x00" not in s and all(ord(c) < 128 for c in s)


def _sanitize_path_prefix(s: str) -> str | None:
    if not isinstance(s, str):
        return None
    stripped = s.strip()
    if stripped in _FORBIDDEN_PATTERNS:
        return None
    if not stripped.startswith("/"):
        return None
    if not (_PATH_PREFIX_MIN <= len(stripped) <= _PATH_PREFIX_MAX):
        return None
    if not _is_ascii_no_nul(stripped):
        return None
    return stripped


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


async def chat_completion_json(
    client: LlmClient,
    *,
    system_prompt: str,
    user_prompt: str,
    schema: dict[str, Any],
    max_tokens: int,
) -> dict[str, Any]:
    """Duenner Helper um den Block-G-:class:`LlmClient` JSON-Mode-faehig zu machen.

    Wir geben das Schema als ``response_format`` mit Typ ``json_schema``
    durch — das OpenAI-SDK leitet das an Provider weiter, die
    Structured-Outputs unterstuetzen (DeepSeek-V3 und kompatible).

    Wirft :class:`LLMTimeoutError` bei Timeout, :class:`LLMInvalidResponseError`
    wenn die Response keinen gueltigen JSON-Block enthaelt.
    """
    # Wir nutzen das Low-Level-SDK direkt, damit wir non-stream JSON-Mode
    # bekommen — der Block-G-Wrapper kennt nur Stream.
    sdk = client._sdk  # intentional Block-G-Reuse.
    try:
        response = await sdk.chat.completions.create(
            model=client.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            stream=False,
            max_tokens=max_tokens,
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "secscan_risk_review",
                    "schema": schema,
                    "strict": False,
                },
            },
        )
    except TimeoutError as exc:
        raise LLMTimeoutError(str(exc)) from exc
    except Exception as exc:  # pragma: no cover — Provider-Quirks
        # Wir reichen den Block-G-Timeout-Begriff hoch wenn der SDK selbst
        # einen ``Timeout``-Subtyp wirft. Bei jeder anderen Exception
        # haengt der Worker den Job in retry mit backoff.
        if type(exc).__name__.lower().find("timeout") >= 0:
            raise LLMTimeoutError(str(exc)) from exc
        raise

    choices = getattr(response, "choices", None) or []
    if not choices:
        raise LLMInvalidResponseError("LLM response hat keine choices")
    content = getattr(choices[0].message, "content", None)
    if not content or not isinstance(content, str):
        raise LLMInvalidResponseError("LLM response hat leeren content")
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise LLMInvalidResponseError(f"LLM response ist kein valides JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise LLMInvalidResponseError("LLM response ist kein JSON-Object")
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

    async def pass1_detect_groups(self, findings: Sequence[Finding]) -> Pass1Result:
        """LLM-Call mit kompakter Finding-Identitaet, returns validierte Groups."""
        user_prompt = self._render_pass1_prompt(findings)
        cfg = load_settings()
        response = await chat_completion_json(
            self.client,
            system_prompt=PASS1_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            schema=PASS1_RESPONSE_SCHEMA,
            max_tokens=cfg.llm_pass1_max_tokens,
        )
        return self._validate_pass1_response(response, list(findings))

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
    ) -> Pass2Result:
        """LLM-Call mit Server-Kontext + Groups, returns validierte Bewertungen."""
        user_prompt = self._render_pass2_prompt(server, groups_with_findings)
        cfg = load_settings()
        response = await chat_completion_json(
            self.client,
            system_prompt=PASS2_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            schema=PASS2_RESPONSE_SCHEMA,
            max_tokens=cfg.llm_pass2_max_tokens,
        )
        return self._validate_pass2_response(response, list(groups_with_findings))

    def _render_pass2_prompt(
        self,
        server: Server,
        groups_with_findings: Sequence[tuple[ApplicationGroup, list[Finding]]],
    ) -> str:
        lines: list[str] = []
        lines.append("host_context:")
        lines.append(
            f"  os: {server.os_pretty_name or server.os_family or '-'}"
            f" {server.os_version or ''}".strip()
        )
        tag_links = getattr(server, "tag_links", []) or []
        tags = sorted(link.tag.name for link in tag_links if getattr(link, "tag", None))
        lines.append(f"  tags: {', '.join(tags) if tags else '-'}")

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
            # Kompakte Zusammenfassung — max 32 Findings, Rest summiert.
            for f in fs[:32]:
                vendor_map = f.severity_by_provider or {}
                vendor_str = ",".join(f"{k}={v}" for k, v in sorted(vendor_map.items()))[:80]
                kev_str = " kev=yes" if f.is_kev else ""
                lines.append(
                    f"      {f.id} {f.identifier_key} {f.package_name} "
                    f"sev={f.severity.value} {vendor_str}"
                    f"{kev_str}"
                )
            if len(fs) > 32:
                lines.append(f"      ... ({len(fs) - 32} weitere)")
            lines.append("")

        lines.append(
            "Liefere pro Group: group_label (exakt wie oben), risk_band aus "
            "{escalate, act, mitigate, monitor, noise}, worst_finding_id "
            "(MUSS in der Group enthalten sein oder null), reason <= 256 chars."
        )
        return "\n".join(lines)

    def _validate_pass2_response(
        self,
        response: dict[str, Any],
        groups_with_findings: list[tuple[ApplicationGroup, list[Finding]]],
    ) -> Pass2Result:
        input_labels: dict[str, set[int]] = {
            grp.label: {int(f.id) for f in fs} for grp, fs in groups_with_findings
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
                        f"ist nicht Mitglied der Group"
                    )
                worst_id = worst_raw
            else:
                raise LLMInvalidResponseError(
                    f"Pass2: Group {label!r} worst_finding_id ist kein Integer: {worst_raw!r}"
                )

            validated.append(
                Pass2Evaluation(
                    group_label=label,
                    risk_band=band,
                    reason=reason,
                    worst_finding_id=worst_id,
                )
            )

        return Pass2Result(evaluations=validated)


__all__ = [
    "LABEL_PATTERN",
    "MAX_REASON_LEN",
    "PASS1_RESPONSE_SCHEMA",
    "PASS1_SYSTEM_PROMPT",
    "PASS2_RESPONSE_SCHEMA",
    "PASS2_SYSTEM_PROMPT",
    "VALID_RISK_BANDS",
    "LLMInvalidResponseError",
    "LLMRiskReviewer",
    "LLMTimeoutError",
    "Pass1Group",
    "Pass1Result",
    "Pass2Evaluation",
    "Pass2Result",
    "chat_completion_json",
]
