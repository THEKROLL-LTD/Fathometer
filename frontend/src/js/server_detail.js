// Block X Phase A0 — Server-Detail-spezifische Vanilla-JS-Helper.
// - setupScanFlashSync: Pendant zu useScanFlashSync aus docs/design/ServerDetail.jsx
// - serverPillPanels: Alpine.data-Component fuer die zwei Header-Pills
// - setupServerDetailHeartbeatTip: Event-Delegation, analog sidebar_heartbeat_tip.js

// Konstanten aus dem JSX-Original (ServerDetail.jsx Z. 31-35).
var SD_SCAN_CYCLE_S      = 5.4;
var SD_SCAN_PEAK_FRAC    = 0.14;
var SD_SCAN_SWEEP_S      = SD_SCAN_CYCLE_S * 0.44;
var SD_BEAM_CENTER_START = -25.2;
var SD_BEAM_CENTER_END   = 123.9;

// WeakMap fuer Cleanup-Tracking pro rootEl: Observer + Listener-Referenzen.
var _scanSyncCleanup = typeof WeakMap !== 'undefined' ? new WeakMap() : null;

/**
 * Setzt pro .scan-flash-Span innerhalb von rootEl einen animation-delay,
 * der mit dem Scan-Beam synchron ist. Identische Logik wie syncScanFlash()
 * in dashboard_scan_sync.js — aber generisch ueber ein beliebiges rootEl.
 *
 * @param {HTMLElement} rootEl
 */
function _doScanFlashSync(rootEl) {
  if (!rootEl) return;
  var cardRect = rootEl.getBoundingClientRect();
  if (cardRect.width === 0) return;
  var peakS = SD_SCAN_CYCLE_S * SD_SCAN_PEAK_FRAC;
  var range = SD_BEAM_CENTER_END - SD_BEAM_CENTER_START;
  rootEl.querySelectorAll('.scan-flash').forEach(function(el) {
    var r = el.getBoundingClientRect();
    if (r.width === 0) return;
    var centerPct = ((r.left + r.width / 2 - cardRect.left) / cardRect.width) * 100;
    var tBeamS = ((centerPct - SD_BEAM_CENTER_START) / range) * SD_SCAN_SWEEP_S;
    el.style.animationDelay = (tBeamS - peakS).toFixed(3) + 's';
  });
}

/**
 * Vanilla-Port von useScanFlashSync aus ServerDetail.jsx.
 *
 * Timet .scan-flash-Spans in .scan-chars-Containern innerhalb von rootEl
 * so, dass der Cyan-Peak-Beam synchron L→R durchlaeuft.
 *
 * Schutz vor Phase-Reset (Block-W-Addendum): Re-Sync findet nur statt,
 * wenn sich die Span-Anzahl in einem .scan-chars-Container geaendert hat.
 *
 * Idempotent: erneuter Aufruf mit demselben rootEl raumt alte
 * Observer/Listener auf (WeakMap-Cleanup).
 *
 * @param {HTMLElement} rootEl
 * @param {Object} [opts]
 */
export function setupScanFlashSync(rootEl, opts) {
  if (!rootEl) return;

  // Vorherigen Cleanup ausfuehren falls setupScanFlashSync zweimal auf
  // demselben rootEl aufgerufen wird (Idempotenz).
  if (_scanSyncCleanup) {
    var prev = _scanSyncCleanup.get(rootEl);
    if (prev) {
      prev.disconnect && prev.disconnect();
      prev.removeOob && prev.removeOob();
      _scanSyncCleanup.delete(rootEl);
    }
  }

  // Letzte Span-Anzahl pro .scan-chars-Container (Phase-Reset-Schutz).
  var lastCounts = new Map();

  function getContainerCounts() {
    var map = new Map();
    rootEl.querySelectorAll('.scan-chars').forEach(function(container) {
      map.set(container, container.querySelectorAll('.scan-flash').length);
    });
    return map;
  }

  function syncIfChanged() {
    var current = getContainerCounts();
    var changed = false;
    current.forEach(function(count, container) {
      if (lastCounts.get(container) !== count) changed = true;
    });
    if (changed || lastCounts.size !== current.size) {
      lastCounts = current;
      _doScanFlashSync(rootEl);
    }
  }

  function syncAlways() {
    lastCounts = getContainerCounts();
    _doScanFlashSync(rootEl);
  }

  // Initialer Sync.
  syncAlways();

  // Re-Sync nach Font-Load (JetBrains-Mono-FOUT kann Layout veraendern).
  if (typeof document !== 'undefined' && document.fonts && document.fonts.ready) {
    document.fonts.ready.then(syncAlways).catch(function() {});
  }

  // ResizeObserver fuer Layout-Aenderungen.
  var ro = null;
  if (typeof ResizeObserver !== 'undefined') {
    ro = new ResizeObserver(syncAlways);
    ro.observe(rootEl);
  }

  // Debounced re-apply nach HTMX OOB-Swaps.
  // Nur re-syncen wenn sich die Span-Anzahl geaendert hat (Phase-Reset-Schutz).
  var oobTimer = null;
  function oobHandler() {
    if (oobTimer !== null) clearTimeout(oobTimer);
    oobTimer = setTimeout(function() {
      oobTimer = null;
      syncIfChanged();
    }, 50);
  }

  var oobTarget = typeof document !== 'undefined' ? document : null;
  if (oobTarget) {
    oobTarget.addEventListener('htmx:oobAfterSwap', oobHandler);
  }

  // Cleanup-Referenzen speichern fuer spaetere Idempotenz.
  if (_scanSyncCleanup) {
    _scanSyncCleanup.set(rootEl, {
      disconnect: function() { if (ro) ro.disconnect(); },
      removeOob: function() {
        if (oobTarget) oobTarget.removeEventListener('htmx:oobAfterSwap', oobHandler);
        if (oobTimer !== null) { clearTimeout(oobTimer); oobTimer = null; }
      },
    });
  }
}

// ── Alpine.data-Component fuer die zwei Header-Pills ─────────────

/**
 * Registriert serverPillPanels als Alpine.data-Component.
 * Single-Open-State: nur ein Panel ('listeners' | 'services' | null) offen.
 * Registrierung defensiv: klappt sowohl wenn Alpine bereits bereit ist
 * als auch wenn alpine:init noch aussteht.
 */
function registerPillPanels() {
  var factory = function() {
    return {
      open: null,
      /**
       * Oeffnet das gewuenschte Panel; schliesst es wenn es bereits offen ist.
       * @param {string} name  'listeners' | 'services'
       */
      toggle: function(name) {
        this.open = this.open === name ? null : name;
      },
    };
  };

  if (typeof window !== 'undefined') {
    if (window.Alpine) {
      window.Alpine.data('serverPillPanels', factory);
    } else {
      document.addEventListener('alpine:init', function() {
        if (window.Alpine) {
          window.Alpine.data('serverPillPanels', factory);
        }
      });
    }
  }
}

// ── Server-Detail Heartbeat-Tooltip (Event-Delegation) ───────────

var SD_HEARTBEAT_STATE_MAP = {
  escalate: { label: 'ESCALATE', cls: 'alarm'   },
  act:      { label: 'ACT',      cls: 'warn'    },
  nominal:  { label: 'NOMINAL',  cls: 'ok'      },
  unknown:  { label: 'UNKNOWN',  cls: 'unknown' },
  '':       { label: 'NOMINAL',  cls: 'ok'      },
};
var SD_TICK_SELECTOR = '.sd-heartbeat__tick:not(.sd-heartbeat__tick--skel)';
var _sdTipByTick = typeof WeakMap !== 'undefined' ? new WeakMap() : null;

/**
 * Lazy: gibt den persistenten .sd-heartbeat-tip-Overlay-DIV zurueck,
 * oder erstellt ihn neu.
 */
function _sdGetOrCreateTip(tick, anchor) {
  var day   = tick.dataset.day  || '';
  var band  = tick.dataset.band || '';
  var hadScan = tick.dataset.hadScan === '1';
  var state = SD_HEARTBEAT_STATE_MAP[band] || SD_HEARTBEAT_STATE_MAP[''];

  var tip = document.createElement('div');
  tip.className = 'sd-heartbeat-tip';

  var dateEl = document.createElement('div');
  dateEl.className = 'heartbeat-tip__date';
  // textContent-only: XSS-Defense (keine innerHTML mit data-*).
  dateEl.textContent = _sdFormatDay(day);
  tip.appendChild(dateEl);

  var stateEl = document.createElement('div');
  stateEl.className = 'heartbeat-tip__state heartbeat-tip__state--' + state.cls;
  stateEl.textContent = state.label;
  tip.appendChild(stateEl);

  if (!hadScan) {
    var hintEl = document.createElement('div');
    hintEl.className = 'heartbeat-tip__hint';
    hintEl.textContent = 'no scan';
    tip.appendChild(hintEl);
  }

  // Position: Tick-Index relativ zu Geschwistern.
  var parent = tick.parentElement;
  var idx = 0;
  var count = 0;
  if (parent) {
    var siblings = parent.querySelectorAll('.sd-heartbeat__tick');
    count = siblings.length;
    for (var i = 0; i < siblings.length; i++) {
      if (siblings[i] === tick) { idx = i; break; }
    }
  }
  var total = count > 0 ? count : 30;
  tip.style.left = (((idx + 0.5) / total) * 100) + '%';

  return tip;
}

function _sdFormatDay(day) {
  // day = "YYYY-MM-DD" -> "May 17, 2026"
  if (!day) return '';
  var d = new Date(day + 'T00:00:00Z');
  if (Number.isNaN(d.getTime())) return day;
  return d.toLocaleDateString('en-US', {
    month: 'short', day: '2-digit', year: 'numeric', timeZone: 'UTC',
  });
}

function _sdRemoveTip(tick) {
  if (!_sdTipByTick) return;
  var existing = _sdTipByTick.get(tick);
  if (existing) { existing.remove(); _sdTipByTick.delete(tick); }
}

/**
 * Richtet Event-Delegation fuer den .sd-heartbeat__tick-Hover-Tooltip ein.
 * Analog sidebar_heartbeat_tip.js aus Block W, aber fuer sd-* Klassen.
 *
 * Delegate sitzt auf rootEl — funktioniert automatisch fuer neue
 * Heartbeat-Strips die via HTMX-OOB in rootEl geswappt werden.
 *
 * @param {HTMLElement} rootEl
 */
export function setupServerDetailHeartbeatTip(rootEl) {
  if (!rootEl) return;

  function onOver(event) {
    var tick = event.target.closest(SD_TICK_SELECTOR);
    if (!tick) return;
    var anchor = tick.closest('.sd-heartbeat');
    if (!anchor) return;
    _sdRemoveTip(tick);
    var tip = _sdGetOrCreateTip(tick, anchor);
    anchor.appendChild(tip);
    if (_sdTipByTick) _sdTipByTick.set(tick, tip);
  }

  function onOut(event) {
    var tick = event.target.closest(SD_TICK_SELECTOR);
    if (!tick) return;
    var next = event.relatedTarget;
    if (next && tick.contains(next)) return;
    _sdRemoveTip(tick);
  }

  rootEl.addEventListener('mouseover', onOver);
  rootEl.addEventListener('mouseout', onOut);
}

// ── Auto-Init bei Modul-Import ────────────────────────────────────

// Alpine.data-Registration laeuft beim Modul-Load (kein DOM-Zugriff).
registerPillPanels();

// ── Oeffentlicher Init-Hook ───────────────────────────────────────

/**
 * Wird vom app.js htmx:afterSettle-Hook aufgerufen (und beim initialen
 * DOMContentLoaded falls .sd-detail-root bereits vorhanden ist).
 *
 * @param {HTMLElement} rootEl
 */
export function initServerDetailModule(rootEl) {
  if (!rootEl) return;
  setupScanFlashSync(rootEl);
  setupServerDetailHeartbeatTip(rootEl);
}
