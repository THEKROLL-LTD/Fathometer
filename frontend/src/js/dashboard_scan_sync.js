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
//   - htmx:oobAfterSwap: debounced (50ms) re-apply auf #action-needed-card
//     (fuer Phase-F-OOB-Updates, wenn sich die Ziffernanzahl aendert)

const SCAN_CYCLE_S      = 5.4;
const SCAN_PEAK_FRAC    = 0.14;
const SCAN_SWEEP_S      = SCAN_CYCLE_S * 0.44;
const BEAM_CENTER_START = -25.2;
const BEAM_CENTER_END   = 123.9;

/**
 * Setzt pro .scan-flash-Span innerhalb von rootElement einen
 * animation-delay, der mit dem Scan-Beam synchron ist.
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
  syncScanFlash(document.getElementById('action-needed-card'));
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
// Wenn sich die Ziffernanzeige aendert (z.B. 99 → 100), aendert sich das
// Layout der .scan-flash-Spans und die Delays muessen neu berechnet werden.
var _oobDebounceTimer = null;
document.body && document.body.addEventListener('htmx:oobAfterSwap', function() {
  if (_oobDebounceTimer !== null) {
    clearTimeout(_oobDebounceTimer);
  }
  _oobDebounceTimer = setTimeout(function() {
    _oobDebounceTimer = null;
    applyToActionCard();
  }, 50);
});
