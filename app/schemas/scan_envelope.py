"""Pydantic-Envelope und Trivy-Sub-Schema fuer `POST /api/scans`.

Strikte Validierung nach ARCHITECTURE.md §10 (Regex-Whitelists, Laengen- und
Range-Limits, NUL-Byte-Schutz, Listen-Bounds). `model_config = ConfigDict(
extra="ignore")` auf jedem Modell — neue Trivy-Felder duerfen einfach
mitkommen, ohne dass wir das Schema bumpen muessen (siehe CLAUDE.md und §10
"Forward-Compat").

Erkenntnisse aus den realen Fixtures (`tests/fixtures/trivy/`):

- `ubuntu-22.04-rke2.json` (Schema-Version 2, Trivy 0.70.0, 306 Vulns):
  - Top-Level: `SchemaVersion`, `Trivy` (Block mit `Version`), `ReportID`,
    `CreatedAt`, `ArtifactName`, `ArtifactType`, `Metadata`, `Results`.
  - `Metadata` in der Praxis schmal: hier nur `{"OS": {...}}`. `DataSource`
    und `UpdatedAt` auf Top-Level-Metadata sind in dieser Fixture **nicht
    vorhanden** — sind aber in `adversarial.json` gesetzt. Wir machen beide
    optional und ziehen alternativ den `DataSource`-Block pro Vulnerability
    heran, der in der echten Fixture pro Vuln vorkommt.
  - Vulnerability-Keys real beobachtet: `VulnerabilityID`, `PkgID`, `PkgName`,
    `PkgIdentifier`, `InstalledVersion`, `Status`, `SeveritySource`,
    `PrimaryURL`, `DataSource`, `Fingerprint`, `Title`, `Description`,
    `Severity`, `CweIDs`, `VendorSeverity`, `CVSS`, `References`,
    `PublishedDate`, `LastModifiedDate`, `VendorIDs`. Wir mappen nur die
    relevanten ab; unbekannte landen in `extra="ignore"`.
  - **EPSS und KEV (CISAKnownExploited)**: in der echten Fixture nicht
    enthalten (Trivy 0.70.0 schreibt EPSS/KEV erst wenn die DB die Daten
    fuehrt — in dieser Aufnahme nicht der Fall). Wir akzeptieren beide
    Varianten: `EPSS: {Score, Percentile}` (siehe `adversarial.json`) oder
    Top-Level `epss_score`/`epss_percentile`. Bei Abwesenheit bleiben die
    Felder None.
  - CVSS-Block ist ein Dict-of-Provider (`redhat`, `nvd`, `ghsa`, ...) mit
    jeweils `V3Vector`/`V3Score`. Wir whitelisten die Provider-Keys nicht
    (kommen vom Trivy-Provider-Schema), sondern validieren die Inner-Felder.
- `adversarial.json` (10 Vulns, jede mit `_attack`-Marker):
  - Testet alle Validierungs-Pfade (NUL-Byte, EPSS>1, CVE-foo-bar,
    Severity=ULTRA_CRITICAL, PkgName-Traversal, CVSS>10, Attack-Vector `Q`,
    CWE-Format, Reference-Scheme).
  - Wir lassen einzelne *Vulns* mit ungueltigen Whitelist-Werten verwerfen
    statt den ganzen Scan zu killen — der `ingest_scan`-Service entscheidet
    pro-Vuln (Pydantic gibt eine ValidationError, der Caller fasst per-Vuln-
    Versuche zusammen). Top-Level- und Strukturfehler dagegen → 422.

Pragmatische Defaults wo §10 unscharf war:
- max 100 References pro Finding — defensiv per Validator getrimmt, nicht
  hart abgelehnt. Trivy liefert fuer Distro-CVEs regelmaessig >50 Refs
  (NVD + Mailinglisten + Vendor-Advisories). Limit war historisch 50 +
  `Field(max_length=…)`, aber der Field-Constraint feuerte VOR dem
  Trim-Validator und produzierte HTTP 422 statt das beabsichtigte Trim
  (Fix v0.6.1).
- max 50 CweIDs pro Finding — analog defensiv getrimmt.
- max 32 VendorIDs pro Finding — Block N (ADR-0021).
- max 50.000 Vulnerabilities aggregiert ueber alle Results (§9).
- max 1.000 Results pro Scan (§10 "Listen-Bounds").
- max 64 KB pro einzelnem String-Feld (§9 "Trivy-JSON-Sanity-Checks") — wir
  reflektieren das per `max_length=65536` an Description.

Block N (ADR-0021): `PkgIdentifier`/`SeveritySource`/`VendorIDs` werden ab
v0.7.0 aktiv extrahiert und persistiert — frueher hat das Schema sie via
`extra="ignore"` weggeworfen. Zusaetzlich liefert der Agent ab v0.2.0
`host.trivy_version` und strippt den `Results[].Packages`-Inventarblock
vor dem Upload (`extra="ignore"` toleriert beide Faelle).
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    field_validator,
    model_validator,
)

# Trivy-internes Severity-Integer-Mapping — Single-Source-of-Truth in
# `app/services/risk_engine.py` (Block O Phase B Zentralisierung).
from app.services.risk_engine import (
    VENDOR_SEVERITY_INT_MAP as _VENDOR_SEVERITY_INT_MAP,
)

# ---------------------------------------------------------------------------
# Regex-Whitelists aus ARCHITECTURE.md §10
# ---------------------------------------------------------------------------

# CVE-IDs: `^CVE-\d{4}-\d{4,}$`
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
# GHSA-IDs (kommen in lang-pkgs auch vor; akzeptiert als zusaetzliche identifier_key).
_GHSA_ID_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")
# Package-Names: druckbares ASCII gemaess §10 — Alpine, Debian, RPM, plus
# typische Go-/Python-/Node-Module mit Pfad-aehnlichen Namen wie
# `github.com/foo/bar`.
_PKG_NAME_RE = re.compile(r"^[a-zA-Z0-9._+\-:/@]+$")
# Versionen: druckbares ASCII, max 256 Zeichen (Length wird ueber Field gesetzt).
# Wir verbieten Control-Chars (inkl. NUL) explizit.
_PRINTABLE_ASCII_RE = re.compile(r"^[\x20-\x7e]+$")
# CWE-IDs: `^CWE-\d{1,7}$`
_CWE_ID_RE = re.compile(r"^CWE-\d{1,7}$")
# Architectures (aus §10: Whitelist).
_ARCH_WHITELIST = frozenset({"x86_64", "aarch64", "armv7l", "i686", "ppc64le", "s390x"})
# Bekannte Aliase werden vor dem Whitelist-Check kanonisiert. Reine
# Normalisierung an der Grenze — wir akzeptieren keine unbekannten Werte,
# nur dokumentierte Synonyme aus macOS, FreeBSD und Go-Toolchains.
_ARCH_ALIASES = {
    "arm64": "aarch64",  # macOS, FreeBSD, Docker (Go-Style)
    "amd64": "x86_64",  # Go-Style, Docker, FreeBSD
    "x86": "i686",
    "i386": "i686",
    "aarch64_be": "aarch64",  # Big-Endian-Variante, selten aber real
}
# Agent-Version (semver-light, §10).
_AGENT_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$")
# OS-Family (§10).
_OS_FAMILY_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
# Trivy-Severity-Werte. Trivy schreibt `UNKNOWN` wenn die DB nichts hat.
_TRIVY_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"})
# CVSS-v3-Vector (§10).
_CVSS_V3_VECTOR_RE = re.compile(r"^CVSS:3\.[01]/.+$")
# CVSS-v3 Vector parsing fuer Attack-Vector (Trivy: "AV:N", "AV:A", "AV:L", "AV:P").
_AV_RE = re.compile(r"(?:^|/)AV:([NALP])(?:/|$)")

# Listen- und String-Bounds.
MAX_VULNS_PER_SCAN = 50_000
MAX_RESULTS_PER_SCAN = 1_000
MAX_REFERENCES_PER_VULN = 100
MAX_CWE_IDS_PER_VULN = 50
MAX_VENDOR_IDS_PER_VULN = 32
MAX_VENDOR_ID_LENGTH = 128
MAX_STRING_LENGTH = 65_536  # 64 KB pro String-Feld (§9).
MAX_REF_URL_LENGTH = 2_048  # §10 "max 2 KB pro URL".
MAX_TITLE_LENGTH = 512
MAX_VERSION_LENGTH = 256
MAX_PKG_NAME_LENGTH = 256

# ---------------------------------------------------------------------------
# Host-Snapshot-Bounds (Block O, ADR-0022 §Host-Snapshot-Datenmodell).
# ---------------------------------------------------------------------------
MAX_LISTENERS = 4_096
MAX_PROCESSES = 4_096
MAX_KERNEL_MODULES = 1_024
MAX_SERVICES = 1_024
MAX_TOOLS_GAPS_ITEMS = 32
MAX_TOOLS_GAPS_ITEM_LENGTH = 32

MAX_LISTENER_ADDR_LENGTH = 64
MAX_LISTENER_PROCESS_LENGTH = 64
MAX_PROCESS_USER_LENGTH = 32
MAX_PROCESS_COMM_LENGTH = 64
MAX_PROCESS_ARGS_LENGTH = 4_096
MAX_KERNEL_MODULE_LENGTH = 64
MAX_SERVICE_NAME_LENGTH = 128

# Trivy `Vulnerability.VendorSeverity`: Map `provider -> severity_label`.
# Trivy schreibt die Werte in zwei Varianten — als String (`"high"`) oder
# numerisch (`3`); wir normalisieren auf den lowercase-Label.
MAX_VENDOR_SEVERITY_PROVIDERS = 16

# Trivy-internes Severity-Integer-Mapping. Quelle: Trivy `dbtypes/Severity`
# (SeverityUnknown=0 ... SeverityCritical=4). Zentralisiert in
# `app/services/risk_engine.py` als `VENDOR_SEVERITY_INT_MAP` (Phase B —
# Single-Source-of-Truth fuer Envelope-Validator und Ingest-Mapper,
# kein Drift-Risiko. Import unten am Modul-Anfang via top-level Import.

_LISTENER_PROTOS = frozenset({"tcp", "udp", "tcp6", "udp6"})

# ASCII-only Tools-/Gaps-Items. Bewusst die printable-ASCII-Regex aus §10
# wiederverwenden plus harten Length-Cap.
_TOOLS_GAPS_ITEM_RE = re.compile(r"^[\x20-\x7e]{1,32}$")


# ---------------------------------------------------------------------------
# Wiederverwendbare Validatoren
# ---------------------------------------------------------------------------


def _no_nul_bytes(value: str | None) -> str | None:
    """Lehnt NUL-Bytes ab — Postgres `text` koennte sie nicht speichern."""
    if value is None:
        return None
    if "\x00" in value:
        raise ValueError("NUL-Byte in String-Feld nicht erlaubt")
    return value


def _strip_control_chars(value: str | None) -> str | None:
    """Entfernt Control-Chars ausser Tab und Newline aus Display-Feldern."""
    if value is None:
        return None
    return "".join(ch for ch in value if ch in ("\t", "\n", "\r") or ord(ch) >= 0x20)


# ---------------------------------------------------------------------------
# Sub-Modelle aus dem Trivy-Report
# ---------------------------------------------------------------------------


class TrivyVersionBlock(BaseModel):
    """`scan.Trivy = {"Version": "0.70.0"}` aus dem realen Report."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    version: str | None = Field(
        default=None,
        alias="Version",
        max_length=64,
    )

    @field_validator("version")
    @classmethod
    def _validate_version(cls, v: str | None) -> str | None:
        v = _no_nul_bytes(v)
        if v is not None and not _PRINTABLE_ASCII_RE.match(v):
            raise ValueError("Trivy-Version enthaelt non-ASCII-Zeichen")
        return v


class TrivyDataSource(BaseModel):
    """`Metadata.DataSource` oder `Vulnerability.DataSource` aus Trivy."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    id: str | None = Field(default=None, alias="ID", max_length=64)
    name: str | None = Field(default=None, alias="Name", max_length=128)
    url: str | None = Field(default=None, alias="URL", max_length=512)

    @field_validator("id", "name", "url")
    @classmethod
    def _check_nul(cls, v: str | None) -> str | None:
        return _no_nul_bytes(v)


class TrivyOSBlock(BaseModel):
    """`Metadata.OS` — wenig genutzt, aber zur Vollstaendigkeit."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    family: str | None = Field(default=None, alias="Family", max_length=32)
    name: str | None = Field(default=None, alias="Name", max_length=64)


class TrivyMetadata(BaseModel):
    """`scan.Metadata` — sehr variabel je nach Trivy-Version und DB-Stand.

    Wichtig fuer unsere Persistenz: `DataSource.ID`/`Name` (als
    `trivy_db_version` denormalisiert) und `UpdatedAt` (als
    `trivy_db_updated_at`). Beide sind in der realen `ubuntu-22.04-rke2.json`-
    Fixture NICHT auf Metadata-Ebene gesetzt. Der Ingest-Service muss damit
    leben und fallt-back auf die DataSource-Bloecke pro Vulnerability bzw.
    laesst die Spalten null.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    os: TrivyOSBlock | None = Field(default=None, alias="OS")
    data_source: TrivyDataSource | None = Field(default=None, alias="DataSource")
    updated_at: datetime | None = Field(default=None, alias="UpdatedAt")


class TrivyCVSSEntry(BaseModel):
    """Eine einzelne Provider-Bewertung im `CVSS`-Block (`nvd`, `redhat`, ...).

    Trivy nutzt Felder `V2Vector`/`V2Score` (CVSS v2) und `V3Vector`/`V3Score`
    (CVSS v3). Wir interessieren uns ausschliesslich fuer v3 (Triage-Default).
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    v3_vector: str | None = Field(default=None, alias="V3Vector", max_length=256)
    v3_score: float | None = Field(default=None, alias="V3Score", ge=0.0, le=10.0)

    @field_validator("v3_vector")
    @classmethod
    def _validate_vector(cls, v: str | None) -> str | None:
        v = _no_nul_bytes(v)
        if v is None:
            return None
        if not _CVSS_V3_VECTOR_RE.match(v):
            # Vektor mit falschem Praefix — verwerfen statt mit Muell persistieren.
            raise ValueError("Ungueltiger CVSS-v3-Vector")
        return v


class TrivyPkgIdentifier(BaseModel):
    """`Vulnerability.PkgIdentifier` aus Trivy (ab Schema-Version 2).

    Block N (ADR-0021): wir extrahieren `PURL` (canonical Package-URL) als
    opaken String zur Anzeige in der UI-Ursachen-Zeile. Keine strukturierte
    Validierung der PURL-Komponenten — das ist Sache eines spaeteren
    Parsers, falls/wenn das Update-Befehl-Feature kommt.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    purl: str | None = Field(default=None, alias="PURL", max_length=512)
    uid: str | None = Field(default=None, alias="UID", max_length=64)

    @field_validator("purl", "uid")
    @classmethod
    def _validate_ascii(cls, v: str | None) -> str | None:
        v = _no_nul_bytes(v)
        if v is None or v == "":
            return v
        if not _PRINTABLE_ASCII_RE.match(v):
            raise ValueError("Feld muss druckbares ASCII sein")
        return v


class TrivyEPSSBlock(BaseModel):
    """`EPSS: {Score, Percentile}` — gesehen in `adversarial.json`."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    score: float | None = Field(default=None, alias="Score", ge=0.0, le=1.0)
    percentile: float | None = Field(default=None, alias="Percentile", ge=0.0, le=1.0)


class TrivyVulnerability(BaseModel):
    """Eine Vulnerability aus `Result.Vulnerabilities`.

    Strikte Validierung: ungueltige `VulnerabilityID` oder `Severity` lassen
    den Validator fehlschlagen, womit der Ingest-Service diese eine Vuln
    verwerfen kann ohne den ganzen Scan zu killen.

    Was wir aktiv extrahieren:
      - VulnerabilityID (identifier_key)
      - PkgName, InstalledVersion, FixedVersion
      - Severity, Title, Description
      - CVSS-v3-Score / -Vector (NVD bevorzugt, dann RedHat, dann erster Eintrag)
      - EPSS, KEV (KEV-Flag wenn Trivy Top-Level-Hint mitschickt)
      - CweIDs
      - References (https/http only)
      - PublishedDate / LastModifiedDate (z.Zt. nur Logging — nicht persistiert)
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    vulnerability_id: str = Field(alias="VulnerabilityID", max_length=64)
    pkg_name: str = Field(alias="PkgName", min_length=1, max_length=MAX_PKG_NAME_LENGTH)
    pkg_id: str | None = Field(default=None, alias="PkgID", max_length=512)
    # Per-Vuln-Dateipfad. Trivy liefert diesen Wert vor allem fuer
    # `lang-pkgs`-Walker-Analyzer (`node-pkg`, `python-pkg`, ...), bei denen
    # `Result.Target` nur den Oekosystem-Namen (`"Node.js"`, `"Python"`) traegt
    # und die echte Per-Paket-Location als `Vulnerability.PkgPath` mitgeliefert
    # wird (z.B. `AdminLTE-master/node_modules/vite/package.json`,
    # `usr/lib/python3/dist-packages/.../METADATA`). Der Ingest bevorzugt diesen
    # Wert ueber `Result.Target` und reicht ihn als `target_path` an Pass1
    # (Group-Detection) und Pass2 (Risk-Bewertung) weiter.
    pkg_path: str | None = Field(default=None, alias="PkgPath", max_length=512)
    installed_version: str | None = Field(
        default=None, alias="InstalledVersion", max_length=MAX_VERSION_LENGTH
    )
    fixed_version: str | None = Field(
        default=None, alias="FixedVersion", max_length=MAX_VERSION_LENGTH
    )
    status: str | None = Field(default=None, alias="Status", max_length=32)

    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] = Field(alias="Severity")
    title: str | None = Field(default=None, alias="Title", max_length=MAX_TITLE_LENGTH)
    description: str | None = Field(default=None, alias="Description", max_length=MAX_STRING_LENGTH)

    # Provider-Map: Schluessel sind Trivy-Provider-Namen (`nvd`, `redhat`,
    # `ghsa`, ...), Werte sind `TrivyCVSSEntry`. Wir parsen sie als generischer
    # Dict — Pydantic v2 validiert dann die inneren Modelle.
    cvss: dict[str, TrivyCVSSEntry] | None = Field(default=None, alias="CVSS")

    epss: TrivyEPSSBlock | None = Field(default=None, alias="EPSS")
    # Trivy schreibt im KEV-Fall typischerweise `CISAKnownExploitedVulnerabilities`
    # auf Vuln-Ebene mit `DateAdded`. Wir akzeptieren als Bool oder als Sub-Dict
    # mit `DateAdded`.
    kev_added_at: datetime | None = Field(default=None, alias="CISAKEVDateAdded")
    is_kev_hint: bool | None = Field(default=None, alias="IsKEV")

    # `max_length` bewusst NICHT am Field — der `field_validator` darunter
    # cleant Junk und trimmt auf das Maximum. Field-Constraints feuern als
    # Built-in-Validation VOR `@field_validator(mode="after")` und wuerden
    # einen Reject ausloesen statt das beabsichtigte Trim (siehe v0.6.1).
    cwe_ids: list[str] | None = Field(default=None, alias="CweIDs")
    references: list[str] | None = Field(default=None, alias="References")
    primary_url: str | None = Field(default=None, alias="PrimaryURL", max_length=MAX_REF_URL_LENGTH)
    published_date: datetime | None = Field(default=None, alias="PublishedDate")
    last_modified_date: datetime | None = Field(default=None, alias="LastModifiedDate")

    # Block N (ADR-0021): Ursachen-Felder. `pkg_identifier.purl` ist die
    # canonical Package-URL; `severity_source` der Provider, der die
    # Severity gemeldet hat (`ubuntu`/`nvd`/`ghsa`/...); `vendor_ids` sind
    # Distro-Advisory-IDs (`USN-...`, `RHSA-...`).
    pkg_identifier: TrivyPkgIdentifier | None = Field(default=None, alias="PkgIdentifier")
    severity_source: str | None = Field(default=None, alias="SeveritySource", max_length=64)
    # Wie `cwe_ids`/`references`: KEIN `max_length` am Field — der
    # Validator trimmt defensiv. Cap-Quelle ist `MAX_VENDOR_IDS_PER_VULN`.
    vendor_ids: list[str] | None = Field(default=None, alias="VendorIDs")

    # Block O (ADR-0022): Provider-Severity-Map. Trivy schreibt sie als Dict
    # `provider -> severity` mit zwei Varianten — String (`"high"`) oder
    # Integer (`3`). Der `field_validator(..., mode="before")` normalisiert
    # beide Varianten auf lowercase-String-Labels. Reject bei
    # `> MAX_VENDOR_SEVERITY_PROVIDERS` oder bei NUL/non-ASCII in Keys.
    vendor_severity: dict[str, str] | None = Field(default=None, alias="VendorSeverity")

    # ---- Validators ------------------------------------------------------

    @field_validator("vulnerability_id")
    @classmethod
    def _validate_vuln_id(cls, v: str) -> str:
        if not _CVE_ID_RE.match(v) and not _GHSA_ID_RE.match(v):
            raise ValueError("VulnerabilityID muss CVE-YYYY-NNNN oder GHSA-xxxx-xxxx-xxxx sein")
        return v

    @field_validator("pkg_name")
    @classmethod
    def _validate_pkg_name(cls, v: str) -> str:
        v = _no_nul_bytes(v) or v
        if ".." in v or v.startswith(("/", "-")):
            raise ValueError("PkgName: Path-Traversal- oder Argument-Pattern verboten")
        if not _PKG_NAME_RE.match(v):
            raise ValueError("PkgName enthaelt unzulaessige Zeichen")
        return v

    @field_validator("installed_version", "fixed_version", "pkg_id", "status", "severity_source")
    @classmethod
    def _validate_ascii_field(cls, v: str | None) -> str | None:
        v = _no_nul_bytes(v)
        if v is None or v == "":
            return v
        if not _PRINTABLE_ASCII_RE.match(v):
            raise ValueError("Feld muss druckbares ASCII sein")
        return v

    @field_validator("title", "description")
    @classmethod
    def _scrub_display_text(cls, v: str | None) -> str | None:
        v = _no_nul_bytes(v)
        return _strip_control_chars(v)

    @field_validator("pkg_path")
    @classmethod
    def _validate_pkg_path(cls, v: str | None) -> str | None:
        # Pfade duerfen breiteren Zeichensatz haben (Unicode-Verzeichnisnamen),
        # aber NUL und Control-Chars wuerden Display und LLM-Prompts brechen.
        v = _no_nul_bytes(v)
        return _strip_control_chars(v)

    @field_validator("cwe_ids")
    @classmethod
    def _validate_cwe_ids(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        # §10 + v0.6.1: ungueltige Items verwerfen, dann defensiv auf
        # `MAX_CWE_IDS_PER_VULN` trimmen. Dieser Validator ist die einzige
        # Cap-Quelle — am Field gibt es bewusst kein `max_length`, sonst
        # wuerde der Built-in-Constraint einen harten Reject ausloesen.
        cleaned: list[str] = []
        for item in v:
            if not isinstance(item, str):
                continue
            if "\x00" in item:
                continue
            if _CWE_ID_RE.match(item):
                cleaned.append(item)
        return cleaned[:MAX_CWE_IDS_PER_VULN]

    @field_validator("references")
    @classmethod
    def _validate_references(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        # §10 + v0.6.1: Junk verwerfen, dann defensiv auf
        # `MAX_REFERENCES_PER_VULN` trimmen. Einzige Cap-Quelle —
        # kein `max_length` am Field (sonst harter Reject statt Trim).
        cleaned: list[str] = []
        for item in v:
            if not isinstance(item, str):
                continue
            if "\x00" in item:
                continue
            if len(item) > MAX_REF_URL_LENGTH:
                continue
            # §10: nur http(s). javascript:, file://, data: etc. verwerfen.
            if not item.startswith(("https://", "http://")):
                continue
            # Strict URL-Parse via Pydantic — wirft auf totalen Murks.
            try:
                HttpUrl(item)
            except (ValueError, TypeError):
                continue
            cleaned.append(item)
        return cleaned[:MAX_REFERENCES_PER_VULN]

    @field_validator("vendor_ids")
    @classmethod
    def _validate_vendor_ids(cls, v: list[str] | None) -> list[str] | None:
        """Block N (ADR-0021): defensiver Trim analog `cwe_ids`/`references`.

        Verwirft Items mit NUL-Byte, non-ASCII oder ueberlanger Laenge.
        Cap auf `MAX_VENDOR_IDS_PER_VULN` (32) Items, jedes max
        `MAX_VENDOR_ID_LENGTH` (128) Chars. KEIN `max_length` am Field —
        sonst wuerde der Built-in-Constraint einen harten Reject ausloesen
        statt das beabsichtigte Trim (siehe v0.6.1).
        """
        if v is None:
            return None
        cleaned: list[str] = []
        for item in v:
            if not isinstance(item, str):
                continue
            if "\x00" in item:
                continue
            if len(item) > MAX_VENDOR_ID_LENGTH:
                continue
            if not _PRINTABLE_ASCII_RE.match(item):
                continue
            cleaned.append(item)
        return cleaned[:MAX_VENDOR_IDS_PER_VULN]

    @field_validator("vendor_severity", mode="before")
    @classmethod
    def _normalize_vendor_severity(cls, v: Any) -> dict[str, str] | None:
        """Block O (ADR-0022): normalisiert `VendorSeverity` auf `dict[str, str]`.

        Trivy schreibt die Map in zwei Formaten:

        - String: `{"nvd": "high", "ubuntu": "medium"}`
        - Integer: `{"nvd": 3, "ubuntu": 2}` (interner Severity-Code)

        Wir normalisieren beide auf lowercase-Strings. Unbekannte Integer
        oder unbekannte/non-ASCII Provider-Keys werden vewworfen (per-Item),
        leerer Dict bleibt leerer Dict, `None` bleibt `None`.

        Reject (ValueError) nur bei strukturellem Murks:

        - mehr als `MAX_VENDOR_SEVERITY_PROVIDERS` (16) Provider,
        - Top-Level kein Dict (z.B. Liste),
        - Key kein String, mit NUL oder non-ASCII,
        - Wert weder String noch Integer.
        """
        if v is None:
            return None
        if not isinstance(v, dict):
            raise ValueError("VendorSeverity muss ein Dict sein")
        if len(v) > MAX_VENDOR_SEVERITY_PROVIDERS:
            raise ValueError(
                f"VendorSeverity hat mehr als {MAX_VENDOR_SEVERITY_PROVIDERS} Provider"
            )
        cleaned: dict[str, str] = {}
        for key, raw_value in v.items():
            if not isinstance(key, str):
                raise ValueError("VendorSeverity-Key muss String sein")
            if "\x00" in key:
                raise ValueError("VendorSeverity-Key enthaelt NUL")
            if not _PRINTABLE_ASCII_RE.match(key):
                raise ValueError("VendorSeverity-Key muss druckbares ASCII sein")
            # Length-Cap pro Key — Provider-Namen sind typisch <= 16 Chars,
            # 64 als defensive Obergrenze.
            if len(key) > 64:
                raise ValueError("VendorSeverity-Key ist zu lang")

            if isinstance(raw_value, bool):
                # bool ist subclass von int in Python — separater Check, sonst
                # wuerde `True` als Integer 1 durchgehen.
                raise ValueError("VendorSeverity-Wert darf nicht bool sein")
            if isinstance(raw_value, int):
                cleaned[key.lower()] = _VENDOR_SEVERITY_INT_MAP.get(raw_value, "unknown")
                continue
            if isinstance(raw_value, str):
                stripped = raw_value.strip()
                if "\x00" in stripped or not _PRINTABLE_ASCII_RE.match(stripped):
                    # Per-Item-Drop bei NUL/non-ASCII im Wert.
                    continue
                if len(stripped) > 32:
                    continue
                cleaned[key.lower()] = stripped.lower()
                continue
            raise ValueError("VendorSeverity-Wert muss String oder Integer sein")
        return cleaned

    @field_validator("primary_url")
    @classmethod
    def _validate_primary_url(cls, v: str | None) -> str | None:
        v = _no_nul_bytes(v)
        if v is None or v == "":
            return None
        if not v.startswith(("https://", "http://")):
            return None
        try:
            HttpUrl(v)
        except (ValueError, TypeError):
            return None
        return v

    @model_validator(mode="after")
    def _coerce_kev_hint(self) -> TrivyVulnerability:
        """Wenn `kev_added_at` gesetzt ist, gilt `is_kev_hint=True`."""
        if self.kev_added_at is not None and not self.is_kev_hint:
            self.is_kev_hint = True
        return self

    # ---- Abgeleitete Helfer (nicht persistiert direkt) -------------------

    def best_cvss_v3(self) -> tuple[float | None, str | None]:
        """Liefert (Score, Vector) der bevorzugten Provider-Bewertung.

        Reihenfolge: `nvd` > `ghsa` > `redhat` > erster Eintrag mit `V3Score`.
        Wenn nichts gefunden: (None, None).
        """
        if not self.cvss:
            return (None, None)
        preferred = ("nvd", "ghsa", "redhat")
        for provider in preferred:
            entry = self.cvss.get(provider)
            if entry is not None and entry.v3_score is not None:
                return (entry.v3_score, entry.v3_vector)
        # Erster mit Score.
        for entry in self.cvss.values():
            if entry.v3_score is not None:
                return (entry.v3_score, entry.v3_vector)
        return (None, None)

    def attack_vector_from_cvss(self) -> str:
        """Mappt das `AV:`-Token aus dem CVSS-v3-Vektor auf unser Enum.

        `N` -> `network`, `A` -> `adjacent`, `L` -> `local`, `P` -> `physical`.
        Bei fehlendem oder unbekanntem Vektor: `unknown`.
        """
        _, vector = self.best_cvss_v3()
        if vector is None:
            return "unknown"
        m = _AV_RE.search(vector)
        if not m:
            return "unknown"
        return {
            "N": "network",
            "A": "adjacent",
            "L": "local",
            "P": "physical",
        }.get(m.group(1), "unknown")

    @property
    def package_purl(self) -> str | None:
        """Convenience-Property fuer den Ingest-Mapper.

        Liefert `pkg_identifier.purl` falls vorhanden, sonst `None`.
        """
        if self.pkg_identifier is None:
            return None
        return self.pkg_identifier.purl


class TrivyResult(BaseModel):
    """Ein Trivy-Result-Block (`Results[i]`).

    `Class` ist Whitelist `os-pkgs`/`lang-pkgs`; alles andere wird auf
    `other` gemappt (§10).
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    target: str | None = Field(default=None, alias="Target", max_length=512)
    klass: str | None = Field(default=None, alias="Class", max_length=32)
    type_: str | None = Field(default=None, alias="Type", max_length=64)
    vulnerabilities: list[TrivyVulnerability] | None = Field(
        default=None, alias="Vulnerabilities", max_length=MAX_VULNS_PER_SCAN
    )

    @field_validator("target", "type_")
    @classmethod
    def _check_nul(cls, v: str | None) -> str | None:
        return _no_nul_bytes(v)

    def normalized_class(self) -> Literal["os-pkgs", "lang-pkgs", "other"]:
        if self.klass == "os-pkgs":
            return "os-pkgs"
        if self.klass == "lang-pkgs":
            return "lang-pkgs"
        return "other"


class TrivyReport(BaseModel):
    """Top-Level Trivy-JSON unter `envelope.scan`."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    schema_version: int | None = Field(default=None, alias="SchemaVersion", ge=1, le=99)
    trivy: TrivyVersionBlock | None = Field(default=None, alias="Trivy")
    report_id: str | None = Field(default=None, alias="ReportID", max_length=128)
    created_at: datetime | None = Field(default=None, alias="CreatedAt")
    artifact_name: str | None = Field(default=None, alias="ArtifactName", max_length=256)
    artifact_type: str | None = Field(default=None, alias="ArtifactType", max_length=64)
    metadata: TrivyMetadata | None = Field(default=None, alias="Metadata")
    results: list[TrivyResult] = Field(
        default_factory=list, alias="Results", max_length=MAX_RESULTS_PER_SCAN
    )

    @model_validator(mode="after")
    def _total_vuln_cap(self) -> TrivyReport:
        total = 0
        for r in self.results:
            if r.vulnerabilities is not None:
                total += len(r.vulnerabilities)
                if total > MAX_VULNS_PER_SCAN:
                    raise ValueError(
                        f"Mehr als {MAX_VULNS_PER_SCAN} Vulnerabilities ueber alle Results"
                    )
        return self


# ---------------------------------------------------------------------------
# Wrapper-Envelope aus ARCHITECTURE.md §6
# ---------------------------------------------------------------------------


class HostBlock(BaseModel):
    """`envelope.host` — Pflichtfeld."""

    model_config = ConfigDict(extra="ignore")

    os_family: Annotated[str, Field(max_length=32)]
    os_version: Annotated[str, Field(max_length=64)]
    os_pretty_name: Annotated[str, Field(max_length=256)]
    kernel_version: Annotated[str, Field(max_length=128)]
    architecture: Annotated[str, Field(max_length=16)]
    # Block N (ADR-0021): Agent ab v0.2.0 meldet die Trivy-CLI-Version.
    # Optional fuer Forward-Compat — Agent v0.1.0 sendet das Feld nicht.
    trivy_version: str | None = Field(default=None, max_length=64)

    @field_validator("trivy_version")
    @classmethod
    def _validate_trivy_version(cls, v: str | None) -> str | None:
        v = _no_nul_bytes(v)
        if v is None or v == "":
            return None
        if not _PRINTABLE_ASCII_RE.match(v):
            raise ValueError("trivy_version muss druckbares ASCII sein")
        return v

    @field_validator("os_family")
    @classmethod
    def _validate_os_family(cls, v: str) -> str:
        v = (_no_nul_bytes(v) or "").strip().lower()
        if not _OS_FAMILY_RE.match(v):
            raise ValueError("os_family muss [a-z][a-z0-9_-]{0,31} sein")
        return v

    @field_validator("os_version", "kernel_version", "os_pretty_name")
    @classmethod
    def _validate_printable(cls, v: str) -> str:
        v = _no_nul_bytes(v) or v
        if not _PRINTABLE_ASCII_RE.match(v):
            raise ValueError("Feld muss druckbares ASCII sein")
        return v

    @field_validator("architecture")
    @classmethod
    def _validate_arch(cls, v: str) -> str:
        v = (_no_nul_bytes(v) or v).strip().lower()
        # Alias-Normalisierung: macOS `arm64`, Go `amd64` etc. werden auf die
        # Linux-Canonical-Form gemappt, BEVOR die Whitelist greift. Damit
        # bleibt die persistierte Form einheitlich (`aarch64`/`x86_64`).
        v = _ARCH_ALIASES.get(v, v)
        if v not in _ARCH_WHITELIST:
            raise ValueError(f"architecture muss eine von {sorted(_ARCH_WHITELIST)} sein")
        return v


# ---------------------------------------------------------------------------
# Host-Snapshot-Block (Block O, ADR-0022 §Host-Snapshot-Datenmodell).
#
# Der Agent ab v0.3.0 sendet im Envelope einen optionalen `host_state`-Block
# mit vier Sub-Listen (`listeners`, `processes`, `kernel_modules`, `services`)
# plus `tools_available`/`gaps`-Tracking. Schema ist additiv — Agent 0.2.0
# sendet den Block nicht, das Backend muss damit umgehen (`extra="ignore"`).
#
# Validatoren sind defensive Strict-Whitelists analog Trivy-Schema §10:
# IP-Literal-Validierung via `ipaddress.ip_address()`, Port-Range, ASCII-only,
# NUL-frei, Length-Bounds. Wenn ein einzelnes `ListenerEntry`/`ProcessEntry`
# rejected wird, killt das nur diese Entry (Pydantic-Default); die
# uebergeordnete Liste hat eine Max-Length-Schranke (Pydantic rejected den
# ganzen `HostStateBlock` bei Ueberlauf, das ist Phase-C-Concern).
# ---------------------------------------------------------------------------


class ListenerEntry(BaseModel):
    """Listening-Socket-Eintrag aus `ss` / `netstat`."""

    model_config = ConfigDict(extra="ignore")

    proto: Literal["tcp", "udp", "tcp6", "udp6"]
    addr: Annotated[str, Field(max_length=MAX_LISTENER_ADDR_LENGTH)]
    port: int = Field(ge=0, le=65535)
    process: Annotated[str, Field(max_length=MAX_LISTENER_PROCESS_LENGTH)] | None = None
    pid: int | None = Field(default=None, ge=0, le=2**31 - 1)

    @field_validator("addr")
    @classmethod
    def _validate_addr(cls, v: str) -> str:
        """ASCII-only IPv4/IPv6-Literal-Validierung."""
        v = _no_nul_bytes(v) or v
        if not _PRINTABLE_ASCII_RE.match(v):
            raise ValueError("addr muss druckbares ASCII sein")
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"addr ist kein gueltiges IP-Literal: {v}") from exc
        return v

    @field_validator("process")
    @classmethod
    def _validate_process(cls, v: str | None) -> str | None:
        v = _no_nul_bytes(v)
        if v is None or v == "":
            return None
        if not _PRINTABLE_ASCII_RE.match(v):
            raise ValueError("process muss druckbares ASCII sein")
        return v


class ProcessEntry(BaseModel):
    """Prozess-Eintrag aus `ps`."""

    model_config = ConfigDict(extra="ignore")

    pid: int = Field(ge=0, le=2**31 - 1)
    user: Annotated[str, Field(max_length=MAX_PROCESS_USER_LENGTH)] | None = None
    comm: Annotated[str, Field(max_length=MAX_PROCESS_COMM_LENGTH)] | None = None
    args: Annotated[str, Field(max_length=MAX_PROCESS_ARGS_LENGTH)] | None = None

    @field_validator("user", "comm")
    @classmethod
    def _validate_short_ascii(cls, v: str | None) -> str | None:
        v = _no_nul_bytes(v)
        if v is None or v == "":
            return None
        if not _PRINTABLE_ASCII_RE.match(v):
            raise ValueError("Feld muss druckbares ASCII sein")
        return v

    @field_validator("args")
    @classmethod
    def _validate_args(cls, v: str | None) -> str | None:
        """args darf Whitespace enthalten, aber kein NUL und kein non-ASCII."""
        v = _no_nul_bytes(v)
        if v is None or v == "":
            return None
        if not _PRINTABLE_ASCII_RE.match(v):
            raise ValueError("args muss druckbares ASCII sein")
        return v


def _filter_ascii_strings(items: Any, max_items: int, max_item_length: int) -> list[str]:
    """Filter-Helper fuer `tools_available`/`gaps`/`kernel_modules`/`services`.

    Verwirft Items die nicht-String, NUL-haltig, non-ASCII oder ueberlang
    sind (per-Item-Drop, nicht Reject). Cap auf `max_items` Eintraege.
    Reject (ValueError) wenn die Eingabe selbst keine Liste ist.
    """
    if items is None:
        return []
    if not isinstance(items, list):
        raise ValueError("Feld muss eine Liste sein")
    cleaned: list[str] = []
    for item in items:
        if not isinstance(item, str):
            continue
        if "\x00" in item:
            continue
        if len(item) > max_item_length:
            continue
        if not _PRINTABLE_ASCII_RE.match(item):
            continue
        cleaned.append(item)
    return cleaned[:max_items]


class HostStateBlock(BaseModel):
    """`envelope.host_state` — optional, Forward-Compat-by-design.

    Der Agent ab v0.3.0 sendet diesen Block. Aeltere Agents senden ihn nicht;
    der Envelope ignoriert das Fehlen (`extra="ignore"` greift hier nicht,
    weil der Feld-Default `None` ist — Pre-Triage faellt auf
    `snapshot_available=False`).
    """

    model_config = ConfigDict(extra="ignore")

    snapshot_at: datetime | None = None
    tools_available: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    listeners: list[ListenerEntry] = Field(default_factory=list, max_length=MAX_LISTENERS)
    processes: list[ProcessEntry] = Field(default_factory=list, max_length=MAX_PROCESSES)
    kernel_modules: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)

    @field_validator("tools_available", "gaps", mode="before")
    @classmethod
    def _filter_tools_gaps(cls, v: Any) -> list[str]:
        """Verwirft non-ASCII-Items per-Item; cap auf 32 Strings x 32 Chars."""
        return _filter_ascii_strings(v, MAX_TOOLS_GAPS_ITEMS, MAX_TOOLS_GAPS_ITEM_LENGTH)

    @field_validator("kernel_modules", mode="before")
    @classmethod
    def _filter_kernel_modules(cls, v: Any) -> list[str]:
        return _filter_ascii_strings(v, MAX_KERNEL_MODULES, MAX_KERNEL_MODULE_LENGTH)

    @field_validator("services", mode="before")
    @classmethod
    def _filter_services(cls, v: Any) -> list[str]:
        return _filter_ascii_strings(v, MAX_SERVICES, MAX_SERVICE_NAME_LENGTH)


class TrivyDbBlock(BaseModel):
    """Top-Level-`trivy_db`-Block aus dem Envelope (Agent >= 0.3.1).

    Trivy 0.70 schreibt `DataSource`/`UpdatedAt` nicht zuverlaessig in
    `scan.Metadata`. Der Agent extrahiert die echten DB-Metadaten aus
    `trivy version --format json` und sendet sie separat.
    """

    model_config = ConfigDict(extra="ignore")

    version: str | None = Field(default=None, max_length=32)
    updated_at: datetime | None = None
    next_update_at: datetime | None = None
    downloaded_at: datetime | None = None

    @field_validator("version")
    @classmethod
    def _validate_version(cls, v: str | None) -> str | None:
        v = _no_nul_bytes(v)
        if v is None or v == "":
            return None
        if not _PRINTABLE_ASCII_RE.match(v):
            raise ValueError("trivy_db.version muss druckbares ASCII sein")
        return v


class Envelope(BaseModel):
    """Wrapper-Envelope fuer `POST /api/scans`.

    `agent_version` und `host` sind Pflichtfelder; `scan` wird durch das
    Trivy-Sub-Schema gezogen. `host_state` ist optional und ab Agent v0.3.0
    befuellt (ADR-0022).
    """

    model_config = ConfigDict(extra="ignore")

    agent_version: Annotated[str, Field(max_length=32)]
    host: HostBlock
    scan: TrivyReport
    host_state: HostStateBlock | None = None
    trivy_db: TrivyDbBlock | None = None

    @field_validator("agent_version")
    @classmethod
    def _validate_agent_version(cls, v: str) -> str:
        v = _no_nul_bytes(v) or v
        if not _AGENT_VERSION_RE.match(v):
            raise ValueError("agent_version muss SemVer (z.B. 0.1.0 oder 0.1.0-rc1) sein")
        return v


# ---------------------------------------------------------------------------
# Register-Body
# ---------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    """Body fuer `POST /api/register`."""

    model_config = ConfigDict(extra="ignore")

    master_key: Annotated[str, Field(min_length=1, max_length=512)]
    name: Annotated[str, Field(min_length=1, max_length=64)]
    expected_scan_interval_h: int = Field(default=24, ge=1, le=744)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        v = _no_nul_bytes(v) or v
        # §10: `^[a-zA-Z0-9._\- ]{1,64}$`
        if not re.match(r"^[a-zA-Z0-9._\- ]{1,64}$", v):
            raise ValueError("Server-Name muss [a-zA-Z0-9._- ] (max 64 Zeichen) sein")
        return v


class KeyRotateRequest(BaseModel):
    """Body fuer `POST /api/keys/rotate`."""

    model_config = ConfigDict(extra="ignore")

    target: Literal["master", "server"]
    server_id: int | None = Field(default=None, ge=1)
    current_master_key: Annotated[str, Field(min_length=1, max_length=512)]

    @model_validator(mode="after")
    def _server_id_required_for_server(self) -> KeyRotateRequest:
        if self.target == "server" and self.server_id is None:
            raise ValueError("server_id ist Pflicht wenn target='server'")
        return self


__all__: list[str] = [
    "MAX_CWE_IDS_PER_VULN",
    "MAX_KERNEL_MODULES",
    "MAX_LISTENERS",
    "MAX_PROCESSES",
    "MAX_REFERENCES_PER_VULN",
    "MAX_RESULTS_PER_SCAN",
    "MAX_SERVICES",
    "MAX_TOOLS_GAPS_ITEMS",
    "MAX_TOOLS_GAPS_ITEM_LENGTH",
    "MAX_VENDOR_IDS_PER_VULN",
    "MAX_VENDOR_ID_LENGTH",
    "MAX_VENDOR_SEVERITY_PROVIDERS",
    "MAX_VULNS_PER_SCAN",
    "Envelope",
    "HostBlock",
    "HostStateBlock",
    "KeyRotateRequest",
    "ListenerEntry",
    "ProcessEntry",
    "RegisterRequest",
    "TrivyCVSSEntry",
    "TrivyDataSource",
    "TrivyDbBlock",
    "TrivyEPSSBlock",
    "TrivyMetadata",
    "TrivyOSBlock",
    "TrivyPkgIdentifier",
    "TrivyReport",
    "TrivyResult",
    "TrivyVersionBlock",
    "TrivyVulnerability",
]
