# ADR-0063 — Optionale agentische Upstream-Update-Suche (operator-gated, beratend)

**Status:** Akzeptiert · **Datum:** 2026-06-12

Bezug: [ADR-0061](0061-fix-ownership-lang-pkgs-upstream-lane.md) (`upstream`-Lane — diese ADR reichert upstream-/no-host-patch-Findings an), [ADR-0062](0062-agent-host-update-availability.md) (Host-Flag — die agentische Suche springt für die Fälle an, die der Host nicht beantworten kann), [ADR-0002](0002-openai-compatible-llm.md) (OpenAI-kompatible LLM-Abstraktion), [ADR-0050](0050-remove-llm-chat-assessment.md) (server-weiter LLM-Chat verworfen — diese ADR ist **kein** Chat, sondern ein fokussierter on-demand-Lookup), [ADR-0024](0024-external-epss-kev-enrichment.md) (kontrollierter Outbound für Feeds), ARCHITECTURE §17 (Out-of-Scope).

## Kontext

Nach ADR-0061/0062 bleibt eine Klasse ungelöst: Findings ohne host-applizierbares Update (`upstream` bzw. `host_update_available=false`), für die der Operator **trotzdem** wissen will, ob es einen frischen Upstream-Build gibt, den er manuell / Ansible-ausgerollt einspielen kann. Das betrifft besonders:

- Artefakte **ohne Paketmanager-Eintrag** (Ansible-/manuell ausgerollte Binaries, GitHub-Releases) — der Host-Agent (0062) findet via `rpm -qf` nichts.
- den **zu-alt-Distro/EOL-Fall** — das Repo trägt keinen Fix, Upstream hat aber längst einen.

Das ist genau die manuelle Triage-Arbeit, die der Operator heute selbst macht, wenn er „tailscale · escalate · kein Host-Patch" sieht: „kann ich ein frisches Binary einspielen?". Ein aktuelles agentisches LLM kann diesen Lookup übernehmen — die Provenance ist via Trivys gobinary-Buildinfo gesetzt (Go-Main-Module-Pfad, z. B. `tailscale.com`, plus PURL `pkg:golang/...`), also ein direkter Zeiger aufs Upstream-Repo.

## Entscheidung

Ein **eigenständiges, optionales, operator-gated** Feature „Check for upstream update" — **nicht** der Risk-Reviewer, **kein** Chat (ADR-0050 bleibt verworfen). Es tut genau eins: agentisch beim Upstream (GitHub-Releases / Vendor) nachsehen, ob ein neuerer Build existiert, und das Ergebnis **beratend** mit Quellen anzeigen.

### Zwei harte Leitplanken

1. **Anreicherung, nie Klassifikation.** Das Ergebnis hängt als advisory Metadaten am Finding / an der Group („upstream check: tailscale 1.98.5, released 2026-06-10, built with Go 1.26.4 — likely fixes this; `<release-url>`"). Es **flippt nie automatisch** `risk_band` oder `fix_lane`. Web-Ergebnisse sind non-deterministisch und spoofbar (ein angreifer-kontrolliertes „Release" wäre sonst eine Supply-Chain-Fläche). Der Operator entscheidet — exakt die Arbeit, die er ohnehin täte. Das hält die Determinismus-, Cache- und Threat-Model-Eigenschaften des deterministischen Kern-Pfads (ADR-0061/0062) intakt.
2. **Opt-in & gated.** Outbound-Browsing widerspricht dem air-gap-first-Default. Das Feature ist standardmäßig **aus**, operator-konfiguriert (wie der LLM-Provider), und im Air-Gap-Setup schlicht nicht aktiviert. Eigene Outbound-Allowlist + Doku in `docs/operations.md`.

### Mechanik

- **Trigger:** on-demand, **nicht** pro Scan. Button „Check for upstream update" pro escalate-/no-host-patch-Finding (dort, wo der Operator sonst manuell googelt). Kein Massen-Lauf.
- **Seed:** Go-Main-Module-Pfad / PURL aus der Trivy-Buildinfo, installierte Version, optional systemd-Unit / Binary-Name.
- **Output-Vertrag:** Kandidaten-Version + Release-URL + Datum + (wenn ableitbar) die Toolchain-/Dependency-Version des Builds, immer **zitiert**, als „candidate · verify" markiert, nie als Ground Truth.
- **Cache:** pro `(Modul, installierte Version)` mit TTL — kein Re-Search pro Scan.

## Begründung

- Löst die Fälle, die deterministisch nicht lösbar sind (kein Paket / EOL), ohne den deterministischen Kern zu kontaminieren.
- Air-Gap ist ein Deployment-Modus, kein Veto: optional + gated genügt.
- Mensch-im-Loop matcht die Realität (der Operator spielt das Binary ohnehin selbst ein) und neutralisiert das Hallucination-/Spoofing-Risiko.
- Nutzt vorhandene Provenance (Buildinfo) statt blind zu suchen.

## Konsequenzen

- Neues optionales Feature-Flag/Config (Outbound-Endpoint(s) + Allowlist), Default aus.
- Agentischer Lookup-Service als eigener Pfad (nicht `llm_worker`/`group_chat`); Tool-/Browsing-Fähigkeit des LLM.
- UI: on-demand-Button + advisory-Panel **pro Group-Row der `ESCALATE · Upstream fix`-Karte** (Details + Zustände siehe §UI/UX), „candidate · verify", Quellen-Links. Untrusted Web-/LLM-Output → Sanitization (nh3, **kein** `|safe`), Marker-Neutralisierung wie im group_chat.
- `docs/operations.md`: Outbound-URLs/Allowlist + Air-Gap-„bleibt aus"-Hinweis.
- Threat-Model: Rate-Limit + Kosten-Cap, Spoofing-Awareness (Ergebnis ist Vorschlag, nie Autorität).
- Tests (nur erlaubte Gates): Seed-Extraktion aus Buildinfo, Output-Parsing/Escaping, Cache-Key/TTL, „flippt-Band-nie"-Regression. Live-Browsing-Tests nur nach expliziter User-Genehmigung.
- ARCHITECTURE §17: das fokussierte on-demand-Lookup explizit als Ausnahme zum verworfenen server-weiten Chat (ADR-0050) führen — analog der Group-Chat-Ausnahme in ADR-0055.

## Implementierungs-Erkenntnisse & Produktentscheidungen (Spike 2026-06-12/13)

Ein mehrstufiger Spike (`scripts/spikes/`) hat den Tier-2-Pfad gegen den realen `tailscaled`/CVE-2026-42504-Fall verprobt und in den finalen Entwurf überführt. Befund: der agentische Ansatz **funktioniert und trifft die korrekte, ehrliche Antwort** (`none_yet` — kein veröffentlichtes Tailscale-Release ist mit Go ≥ 1.26.4 gebaut, das neueste `v1.98.5` läuft auf `go 1.26.3`).

### Runtime: dünne Pydantic-AI-Agenten-Schleife, eigene Tools

**Verworfen: GPT-Researcher als Runtime.** GR liefert zwar die autonome Schleife, ist aber an einer gepinnten Dependency dreifach brüchig: veralteter Tavily-Client (tote Parameter `days`/`use_cache` → `400`, still verschluckt), DeepInfra-Embedding-Inkompatibilität (`langchain_openai` schickt Integer-Token-Arrays → `422`), Scraper-Config-Fallen — drei Laufzeit-Patches an fremdem Code = inakzeptables Produktionsrisiko. (Referenz: `test_upstream_research.py`, `test_lean_pipeline.py`.)

**Gewählt: Pydantic-AI** (`scripts/spikes/test_agent_pydantic.py`). Getypte Agenten-Schleife, bei der **wir die Tools besitzen** → keine GR-Fragilität. Plan→Tool→Lesen→Schlussfolgern bis getyptes `final_output` oder `request_limit`. Output ist ein Pydantic-`Verdict`-Modell (kein Freitext-Parsing). Passt zum Pydantic-v2-Stack, model-agnostisch über die bestehende OpenAI-kompatible Provider-Config.

### Modell: geteilter Provider, Operator wählt das Modell

Nutzt **denselben LLM-Provider** wie Reviewer/Chat (ADR-0002/0057, ein `base_url`/Key). Der Operator **wählt das Modell selbst**; Default **`deepseek-ai/DeepSeek-V4-Flash`** (stabil genug fürs Drehbuch, deutlich günstiger), mit dem **Tipp, ein großes Reasoning-/Thinking-Modell** zu wählen, wenn höhere Treffsicherheit gebraucht wird. Beobachtung: Flash macht reines Function-Calling (kein sichtbares Reasoning), folgt dem Drehbuch aber stabil; DeepSeek-V4-Pro/Gemini-2.5-Flash reasonen sichtbar und gründlicher; **Nemotron-3** vermischte CVEs und halluzinierte — schwache Instruction-Follower sind ungeeignet.

### Such-/Fetch-Backend: pluggable, Operator wählt

**Such-Backend operator-konfigurierbar:** **SearXNG** (self-hosted, $0, kein Key — optional **Basic-Auth**), **Tavily**, **Firecrawl**, **Serper** o.ä. Empfehlung/Default **SearXNG** — self-hosted (passt zum Fathometer-Modell), keine Per-Query-Kosten, kein Free-Tier-Treadmill (Tavily 1k / Serper 2,5k Gratis-Suchen sind schnell weg). Verprobt gegen `searx.thekroll.ltd`: lieferte **bessere** Treffer als die paid-APIs (fand `tailscale/tailscale#19982` + die `go.mod` am Release-Tag, die die paid-APIs verfehlten). **Fetch lokal via trafilatura** ($0); wichtig: Raw-Dateien (go.mod, Lockfiles, SBOMs) sind kein HTML-Artikel → bei leerem `extract()` den **Roh-Download** durchreichen, sonst geht die maschinenlesbare Build-Quelle verloren.

### Prompt = deterministisches Drehbuch, ecosystem-agnostisch

Kein Chat — eine **konkrete Recherche-Aufgabe** mit Stopp-Logik. Aus dem Trivy-Finding reingefüttert (**nicht** recherchiert): Paket, installierte Version, CVE, **Ecosystem** (`result_type`), **installierte Build-Komponenten-Version** und **fixende Version** (Trivy `installed`/`fixed`). Einzige Außenfrage: „existiert ein **veröffentlichtes** Release, das mit einer gefixten Komponente gebaut ist?". Regeln, die in den Läufen nötig wurden:

- **Autoritative Release-Liste als alleinige Wahrheit** (Release-API / „Latest"-Marker) — nicht über Snippets/Tags triangulieren.
- **Release ≠ Git-Tag.** Tag-indizierende Tracker (FlakeHub, repology) führen unreleaste Tags, die wie ein Fix *aussehen* (`v1.99.0`/`v1.100.0` mit `go 1.26.4` in der go.mod, aber **kein** Release) — nur veröffentlichte/installierbare Releases zählen.
- **Geschlossene Stopp-Logik:** das neueste Release ist per Definition das neueste — ist es unfixed, existiert keins → `none_yet`, **stopp**. „Abwesenheit eines Belegs IST die Antwort", nicht „weitersuchen".
- **Ecosystem-agnostisch:** das Modell leitet die autoritative Build-Quelle für *diesen* Artefakt-Typ selbst her (go.mod/`toolchain`, Lockfile, Build-Metadaten, SBOM) — **kein** Pinning auf `go.toolchain.rev` o.ä.

### Tier-Trennung (Kern-Erkenntnis)

- **Tier 2 (dieser Web-Agent):** „existiert *überhaupt* ein gefixtes Upstream-Release?" — `fixed_release_exists` vs `none_yet`. Beratend, gecached.
- **Tier 1 (ADR-0062, Host-Agent):** „kann *dieser* Host es installieren?" — `dnf check-update`, deterministisch, lokal.

Der Web-Agent beantwortet die Host-Repo-/Delivery-Frage **nicht** — im Spike ertrank er sonst im Repo-Metadaten-Spelunking. Die Trennung hält den teuren, unsicheren Teil minimal.

### Output-Vertrag

1. **Getyptes Verdikt** (Pydantic), kein Chat-Freitext. Felder ecosystem-generisch: `fixing_component_version`, `latest_release_component_version`, `fixed_build_release`, `delivery ∈ {fixed_release_exists, none_yet}`, `operator_action`, `confidence`, `sources_used`, `reasoning`.
2. **Kein Verdikt ohne Quelle.** Ungegroundete Läufe halluzinieren spezifisch und selbstbewusst (erfundene PR-Nummern/Daten, `confidence: high`).
3. **Budget-Cap + Finalisierung.** `request_limit` deckelt die Schleife. Bei Budget-Ende → gesammelter Stand **einmal ohne Tools** ans Modell für die Schluss-Aussage; Policy **„bis hier nichts gefunden = kein Fix → `none_yet`"**; schlägt das fehl → deterministischer `none_yet`-Fallback. Nie ein stilles Nichts, nie ein Crash.
4. **Deterministischer Konsistenz-Pass.** Erzwingt Invarianten, die selbst gute Modelle fudgen: `fixed_build_release is None ↔ delivery == none_yet`; `build_version < fixing_version → nicht gefixt`.

### UI/UX: Status, kein Chat

Das Feature ist **keine Konversation**, sondern ein gezielter Check mit *einer* eindeutigen End-Aussage. Abgrenzung zum Per-Group-Chat (ADR-0055): kein Verlauf, kein Multi-Turn-Dialog.

**Platzierung.** Der Trigger sitzt **pro Group-Row in der `ESCALATE · Upstream fix — mitigate until rebuild`-Karte** (ADR-0061) — und nur dort. Begründung: nur bei `upstream + escalate` ist „gibt's schon ein gefixtes Release?" dringend und sinnvoll. `upstream + monitor`/`noise` liegen in den Buckets (geringes/kein Risiko) und bekommen **keinen** Button; die `ACT · Apply app update`-Karte hat per Definition einen Host-Patch und braucht ihn nicht. Nebeneffekt: der Agent läuft nur für Findings, die zählen → die Kosten sind dadurch von selbst gedeckelt.

**Zustände (pro Row).**

- *idle:* Button „Check for upstream fix" in der Group-Row.
- *running:* Spinner-Indikator auf dem Button (disabled) + Status-Zeile in/unter der Row, die zeigt, was gerade läuft („checking upstream releases …", ggf. schrittweise). Live, aber kein Chat-Stream.
- *done:* Button bleibt inaktiv; Ergebnis + Reason-Text klappen **unter der Row** auf:
  - gefixtes Release existiert → Version + Datum + `operator_action` („install the upstream build / wait for it to reach your repo"), Quellen als Links, „candidate · verify".
  - kein gefixtes Release → „no fixed release yet" + neuestes Release + dessen verwundbare Komponenten-Version + `operator_action` (mitigate/monitor).
  - abstain/Fehler → „couldn't determine" (keine Quellen / Budget erschöpft), Re-Check anbietbar.
- *cached:* Ergebnis gecached pro `(Artefakt, installierte Version)` → „checked <relative> ago" + Re-Check-Button (invalidiert den Cache-Eintrag).

**Beratend, nie Band-flippend.** Findet der Check „gefixtes Release existiert", ändert sich `operator_action`, aber die Karte bleibt **escalate** — erst Re-Scan + Tier-1 (`dnf check-update`, ADR-0062) bzw. der manuelle Einspiel-Schritt des Operators senken den Band. Der Check informiert, er entscheidet nicht.

**Gating & Sicherheit.** Button nur sichtbar/aktiv, wenn das Feature konfiguriert ist (LLM-Modell + Such-Backend); sonst disabled mit Hinweis auf die Settings. Untrusted Web-/LLM-Output → Sanitization (nh3, **kein** `|safe`), Marker-Neutralisierung wie im group_chat.

### Integration: Verdikt als Chat-Kontext (ADR-0055)

Liegt für eine `(Server, Group)` ein (gecachtes) Upstream-Check-Verdikt vor, wird es **in den Kontext-Snapshot des Per-Group-Chats** aufgenommen — gleichberechtigt neben Host-Fingerprint, Services, Listenern und den OPEN-Findings der Group (ADR-0055 §Snapshot). Klickt der Operator den Help-Button, kann er damit über das Ergebnis mit dem LLM reden („warum kein Fix?", „was heißt mitigate konkret?", „wann landet das im Repo?").

Semantik wie ADR-0055: Snapshot **bei Chat-Start** eingefroren — ein laufender Chat sieht ein später aktualisiertes Verdikt nicht, „New Chat" zieht den frischen Stand. Existiert kein Verdikt, fehlt der Block einfach. Das Verdikt enthält Web-/LLM-Output → im System-Prompt als **untrusted** Daten behandeln (Marker-Neutralisierung wie die übrigen Scanner-Strings, kein `|safe`). Erweitert den ADR-0055-Snapshot um genau dieses eine optionale Feld.

### Kosten / Latenz

SearXNG + trafilatura = **$0 Such-/Fetch-Kosten**; nur LLM-Tokens (Flash, Cent-Bereich pro Lauf). On-demand, gecached pro `(Artefakt, installierte Version)`.

## Re-Open-Trigger

- Auto-Anreicherung (ohne Button, für die ganze escalate-Lane) bei Bedarf — bewusst zunächst on-demand.
- Nicht-Go-Ecosystems (npm/PyPI/crates/Maven-Provenance) analog erschließen, sobald Go trägt.
- Wenn Operatoren das Ergebnis doch als Band-Input wollen: separate ADR mit explizitem Trust-/Signatur-Modell (nie still).
