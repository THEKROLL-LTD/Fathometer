// dashboard_scan_sync.js
// Vanilla-JS-Port von useScanFlashSync (docs/design/app.jsx Z. 605-634).
//
// Misst jeden .scan-flash-Span innerhalb eines Root-Elements und setzt
// dessen animation-delay so, dass der Cyan-Peak (bei 14% des 5.4s-Zyklus)
// exakt dann eintrifft, wenn der Scan-Beam-Center ueber den Span-Mittelpunkt
// wandert (Sonar-Return-Visual-Language, ADR-0036).
//
// Setup-Hook:
//   - DOMContentLoaded: syncScanFlash(#action-needed-card)
//   - htmx:oobAfterSwap: NUR re-syncen wenn sich die Span-Anzahl im
//     #action-needed-card geaendert hat. Sonst wuerde das Setzen von
//     animation-delay auf den bereits laufenden Spans die Animation
//     resetten und einen Phase-Drift gegenueber dem ::before-Scan-Beam
//     erzeugen — sichtbar als "Schrift-Cyan-Flash steht nicht mehr ueber
//     dem Scan-Beam" nach Tab-Wechsel oder nach ein paar Polling-Ticks.
//     (Bug-Fix 2026-05-23.)

const SCAN_CYCLE_S      = 5.4;
const SCAN_PEAK_FRAC    = 0.14;
const SCAN_SWEEP_S      = SCAN_CYCLE_S * 0.44;
const BEAM_CENTER_START = -25.2;
const BEAM_CENTER_END   = 123.9;

// Letzte beobachtete .scan-flash-Span-Anzahl im action-needed-card. Wenn
// ein OOB-Swap die Zahl der Spans NICHT veraendert (typischer Fall: Zahl
// hat gleiche Stellenzahl, z.B. 24 -> 28), bleiben die Position-Pixel
// nahezu identisch und ein erneutes Setzen von animation-delay wuerde
// die Animation unnoetig restarten -> Phase-Drift gegenueber dem
// Scan-Beam. Wir re-syncen daher nur bei Strukturwechsel.
var _lastSpanCount = null;

/**
 * Setzt pro .scan-flash-Span innerhalb von rootElement einen
 * animation-delay, der mit dem Scan-Beam synchron ist.
 *
 * Wichtig: das Setzen von animation-delay auf einem bereits laufenden
 * Animation-Element RESETTET die Animation in modernen Browsern. Diese
 * Funktion sollte daher nur bei Initial-Mount oder echter Layout-
 * Aenderung aufgerufen werden, nicht bei jedem Werte-Update.
 *
 * @param {HTMLElement} rootElement
 */
function syncScanFlash(rootElement) {
  if (!rootElement) return;
  const cardRect = rootElement.getBoundingClientRect();
  if (cardRect.width === 0) return;

  const peakS = SCAN_CYCLE_S * SCAN_PEAK_FRAC;
  const range = BEAM_CENTER_END - BEAM_CENTER_START;

  rootElement.querySelectorAll('.scan-flash').forEach(function(el) {
    const r = el.getBoundingClientRect();
    if (r.width === 0) return;
    const centerPct = ((r.left + r.width / 2 - cardRect.left) / cardRect.width) * 100;
    const tBeamS = ((centerPct - BEAM_CENTER_START) / range) * SCAN_SWEEP_S;
    // Negative Delays erlaubt — pre-advance in den Zyklus, sodass das
    // erste Frame bereits die korrekte Phase zeigt.
    el.style.animationDelay = (tBeamS - peakS).toFixed(3) + 's';
  });
}

function applyToActionCard() {
  const card = document.getElementById('action-needed-card');
  if (!card) return;
  syncScanFlash(card);
  _lastSpanCount = card.querySelectorAll('.scan-flash').length;
}

/**
 * Re-Sync nach HTMX-OOB-Swap — aber NUR wenn sich die Span-Anzahl
 * tatsaechlich geaendert hat. Sonst Drift-Bug (siehe Datei-Kommentar).
 */
function maybeReSyncAfterOob() {
  const card = document.getElementById('action-needed-card');
  if (!card) return;
  const currentCount = card.querySelectorAll('.scan-flash').length;
  if (currentCount === _lastSpanCount) {
    // Anzahl unveraendert -> Positionen sind nahe genug am alten Stand,
    // kein Re-Sync noetig. Wir akzeptieren minimalen Pixel-Drift damit
    // die Animation-Phase erhalten bleibt.
    return;
  }
  _lastSpanCount = currentCount;
  syncScanFlash(card);
}

// Initialer Sync nach dem DOM-Aufbau.
document.addEventListener('DOMContentLoaded', function() {
  applyToActionCard();

  // Re-Measure wenn Web-Fonts eingetroffen sind (JetBrains-Mono-FOUT
  // kann das Text-Layout veraendern → falsche getBoundingClientRect-Werte
  // im ersten Frame).
  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(applyToActionCard).catch(function() {});
  }
});

// Debounced re-apply nach HTMX OOB-Swaps (Phase F).
// Nur wenn sich die Anzahl der .scan-flash-Spans veraendert hat — sonst
// laeuft die Animation ohne Restart weiter (Sync-Drift-Fix 2026-05-23).
var _oobDebounceTimer = null;
if (document.body) {
  document.body.addEventListener('htmx:oobAfterSwap', function() {
    if (_oobDebounceTimer !== null) {
      clearTimeout(_oobDebounceTimer);
    }
    _oobDebounceTimer = setTimeout(function() {
      _oobDebounceTimer = null;
      maybeReSyncAfterOob();
    }, 50);
  });
}
