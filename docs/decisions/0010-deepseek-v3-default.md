# ADR-0010 — DeepSeek V3 als LLM-Default-Modell

**Status:** Akzeptiert · **Datum:** 2026-05-14

## Kontext

Welches Default-Modell konfigurieren wir wenn der User DeepInfra als Provider wählt? Optionen: Llama 3.3 70B Instruct (mainstream, günstig), DeepSeek V3 (stärker in Reasoning, teurer), Qwen 2.5 72B (alternative, vergleichbarer Preis).

## Entscheidung

`deepseek-ai/DeepSeek-V3` als Default-Modell für den DeepInfra-Provider. Im Setup-Wizard und in den Settings ist das Feld vorbefüllt aber editierbar.

## Begründung

CVE-Bewertung verlangt Reasoning über Angriffsvektoren, KEV-Kontext und Server-Topologie — das spielt DeepSeek V3 besser aus als ein generisches Instruct-Modell. Preisunterschied zu Llama 3.3 70B ist absolut moderat (~3× teurer pro Token, aber pro Bewertung weniger als ein Cent). Die Qualität der Triage-Empfehlungen ist der dominante Faktor, nicht der Token-Preis.

## Konsequenzen

- DeepInfra muss das Modell in der Region des Users verfügbar haben (war zum Entscheidungs-Zeitpunkt der Fall).
- Bei Provider-Wechsel zu OpenAI o.ä. muss der User das Modell manuell ändern (das Default-Modell ist DeepInfra-spezifisch).
- Wenn DeepSeek V3 zukünftig deprecated wird, ADR-Update mit neuem Default.

## Re-Open-Trigger

Bei substantiellen Modell-Updates (DeepSeek V4, Llama 4 etc.) erneut bewerten welches Modell die beste Cost-Quality-Position hat.
