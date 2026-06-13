# Operator-Notizen — fathometer

Lebende Sammlung von Betriebs-Hinweisen: Outbound-Ziele, Air-Gap-Setup,
Feed-Pull-Health-Checks. Ergaenzt um neue Abschnitte pro Feature.

---

## Upstream-Update-Suche (ADR-0063, optional)

Die agentische Upstream-Update-Suche ist ein **optionales, operator-gated**
Feature (ADR-0063). Es sieht on-demand beim Upstream nach, ob ein neuerer
Build eines Artefakts existiert (z. B. fuer Ansible-/manuell ausgerollte
Binaries ohne Paketmanager-Eintrag oder im EOL-/zu-alt-Distro-Fall). Das
Ergebnis ist **beratend** — es flippt nie automatisch einen `risk_band` oder
`fix_lane`. Der Operator entscheidet.

### Default: AUS (Air-Gap-first)

Das Feature ist **standardmaessig deaktiviert** (`upstream_check_enabled =
false`). Outbound-Browsing widerspricht dem air-gap-first-Default. Es muss
bewusst in den Settings aktiviert und konfiguriert werden (Such-Backend +
Modell), sonst ist der Check-Button inaktiv.

### Air-Gap-Deployment

In einem Air-Gap-Setup bleibt das Feature schlicht **aus**:

- `upstream_check_enabled` nicht aktivieren (Default).
- Den optionalen **`research-worker`-Container** im Compose-Setup **weglassen**.

Es entsteht kein Outbound-Traffic, solange das Feature aus ist.

### Outbound-Ziele (nur bei aktiviertem Feature)

Wenn aktiviert, erzeugt der Research-Agent zwei Arten von Outbound-Calls:

1. **Such-Backend** — die konfigurierte `upstream_search_base_url`
   (SearXNG-Instanz, Tavily-/Serper-/Firecrawl-API). Ein Call pro Suche.
2. **Vom Agenten gefetchte Quell-URLs** — Release-/Repo-/Changelog-Seiten und
   Roh-Dateien (z. B. `go.mod` am Release-Tag, Lockfiles, SBOMs) auf
   GitHub/Vendor-Hosts, die der Agent aus den Suchtreffern auswaehlt. Diese
   Ziele sind **nicht vorab fix** — sie ergeben sich aus den Treffern.

**Egress-Allowlist:** mindestens das Such-Backend-Host + die ueblichen
Quell-Hosts (`github.com`, `raw.githubusercontent.com`, `objects.githubusercontent.com`,
Release-CDNs, Vendor-Domains der ueberwachten Artefakte). Wer eine strikte
Allowlist faehrt, beobachtet die tatsaechlich gefetchten Hosts beim Pilot-Lauf
und ergaenzt sie.

### SSRF-Schutz (Code-seitig) + Container-Isolation

Die vom Agenten gewaehlten Fetch-Ziele (Punkt 2 oben) sind **untrusted** (sie
stammen aus Suchtreffern und LLM-Entscheidungen, die per Prompt-Injection in
Webseiten beeinflussbar sind). `fetch_url` erzwingt daher eine **Code-seitige
SSRF-Allowlist** (`_is_fetch_url_allowed` in `upstream_research.py`): nur
`http`/`https`, DNS-Auflösung **aller** Ziel-IPs und Ablehnung von privaten,
loopback-, link-local- (inkl. `169.254.169.254`-Cloud-Metadata), reservierten
und multicast-Adressen; eigener `httpx`-Download mit `follow_redirects=False`
(Redirects werden geblockt, kein SSRF-Bypass) und festem 30s-Timeout. Die
operator-konfigurierte Such-`base_url` ist davon ausgenommen (darf bewusst eine
interne SearXNG sein) — nur ihr Scheme wird geprueft.

**Defense-in-Depth (Deployment):** zusaetzlich empfohlen, den
`research-worker`-Container per Egress-Firewall auf die Allowlist-Hosts zu
beschraenken und ihm **keinen** Zugriff auf interne Dienste ausser der DB zu
geben (er braucht nur `db` + Internet-Egress, **nicht** `app` oder andere
interne Hosts). Restrisiko DNS-Rebinding (TOCTOU zwischen Auflösung und Connect)
ist dokumentiert in TD-019 — fuer den niederfrequenten on-demand-Charakter
vernachlaessigbar, eine pin-to-resolved-IP-Lösung waere der naechste Schritt.

### Such-Backend-Empfehlung: SearXNG (self-hosted, $0)

Empfohlener Default ist eine **self-hosted SearXNG-Instanz**: kein API-Key,
keine Per-Query-Kosten, kein Free-Tier-Treadmill (passt zum Fathometer-Modell).
Optional mit Basic-Auth (`upstream_search_username` + Fernet-verschluesseltes
Passwort). Verprobt lieferte SearXNG bessere Treffer als die paid-APIs
(Tavily/Serper/Firecrawl). Paid-APIs brauchen einen Fernet-verschluesselten
API-Key (`upstream_search_api_key_encrypted`).

### Modell

Geteilter LLM-Provider wie Risk-Reviewer/Chat (ein `llm_base_url`/Key), aber
**eigenes Modell** (`llm_research_model`, App-Default
`deepseek-ai/DeepSeek-V4-Flash`). **Tipp:** ein grosses Reasoning-/Thinking-
Modell erhoeht die Treffsicherheit deutlich (Spike-Befund ADR-0063 §Modell);
schwache Instruction-Follower halluzinieren und sind ungeeignet. Such-/
Fetch-Kosten sind $0 (SearXNG + lokales Fetch), nur LLM-Tokens fallen an
(Cent-Bereich pro Lauf, gecached pro `(Artefakt, installierte Version)`).
