# ADR-0011 — `package_name@target`-Disambiguation für lang-pkgs-Findings

**Status:** Akzeptiert · **Datum:** 2026-05-14

## Kontext

`ARCHITECTURE.md` §5 spezifiziert für `findings`:

> Pro `(server_id, finding_type, identifier_key, package_name)` existiert
> ein einziger Eintrag — der Unique-Index erzwingt das.

Reale Trivy-Filesystem-Scans (siehe `tests/fixtures/trivy/ubuntu-22.04-rke2.json`)
liefern für eingebettete Go-Binaries (`Class: lang-pkgs`, `Type: gobinary`)
dieselbe `(VulnerabilityID, PkgName)`-Kombination mehrfach pro Server.
Beispiel: `CVE-2026-33811` betrifft die Go-`stdlib` und taucht im Scan in
24 verschiedenen Binaries auf demselben Host auf (`/usr/local/bin/k3s`,
`/usr/local/bin/tailscale`, `/usr/local/bin/runc`, …).

Mit strikter Lesart des Unique-Constraints würden die 24 Vorkommen auf
einen einzigen Finding zusammenfallen. Die Block-C-DoD verlangt aber:

> 306 Vulns parsed, korrekte Class-Verteilung (296 lang-pkgs, 10 os-pkgs)

— d.h. jedes der 24 Vorkommen soll als eigenes Finding sichtbar bleiben,
damit der Operator das **betroffene Binary** (nicht nur den Package-Namen)
in der Triage sieht.

## Entscheidung

Für Findings mit `finding_class = lang-pkgs` wird das Trivy-`Target`
(in der Fixture: der Pfad zum Binary) an `package_name` angehängt:

```
package_name = f"{PkgName}@{Target}"   # z.B. "stdlib@/usr/local/bin/k3s"
```

Begrenzung auf 256 Zeichen (siehe `app/services/findings_ingest.py`
`_disambiguated_package_name`). Für `finding_class = os-pkgs` bleibt
`package_name` unverändert (Target dort ist der Hostname und trägt keine
Disambiguations-Information).

## Begründung

- Behält den Spec-Unique-Constraint `(server_id, finding_type,
  identifier_key, package_name)` unverändert.
- Macht die Triage-Sicht im Dashboard sauber: pro betroffenem Binary eine
  eigene Zeile, mit klar erkennbarer Lokation.
- Vermeidet eine zusätzliche `target`-Spalte mit Folge-Migration —
  Block-C-Scope bleibt eingehalten.
- Reversibel: ein späterer Cleanup-Job kann den Suffix abspalten und in
  eine eigene Spalte schreiben, wenn ein normalisiertes Schema gewünscht
  wird.
- Filterbar: `LIKE 'stdlib@%'` listet alle stdlib-Findings über alle
  Binaries hinweg.

## Konsequenzen

- `package_name` ist im UI für lang-pkgs ein zusammengesetzter Wert.
  Templates müssen den `@`-Split nicht selbst tun — die Anzeige als
  `stdlib@/usr/local/bin/k3s` ist informativ.
- LLM-Prompts (Block G) bekommen `package_name` mit Suffix —
  Prompt-Templates dort sollten den Wert vor der Übergabe ggf. splitten,
  um nicht-irreführende Sätze zu formulieren.
- Bei Block-F-Bulk-Operationen funktioniert "alle Findings derselben CVE
  resolven" weiterhin über `identifier_key`, unabhängig von
  `package_name`.

## Re-Open-Trigger

- Wenn ein späterer Block (D Dashboard, E Triage) zeigt, dass das
  `@target`-Suffix das UI unübersichtlich macht (z.B. lange Pfade), wird
  eine eigene `target`-Spalte mit Migration eingeführt und die
  Disambiguation umgezogen.
- Wenn Trivy ab einer künftigen Version dieselbe Information in einem
  strukturierten Feld pro Vulnerability liefert (z.B.
  `PkgIdentifier.PURL` mit eindeutigem Locator), wird auf das native
  Feld umgeschaltet.
