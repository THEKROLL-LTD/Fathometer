// Application-spezifische Module (Phase C, ADR-0035).
import './sidebar_viewport.js';
import './sidebar_loading_wave.js';
import './sidebar_heartbeat_tip.js';
// Topbar-Nav-Active-State an HTMX-Pane-Swaps koppeln.
import './topbar_nav_sync.js';
// Phase D: Scan-Beam-Sync fuer die Action-Needed-Card (ADR-0036).
import './dashboard_scan_sync.js';
// Phase F: Last-Refresh-Eyebrow-Ticker (ADR-0036).
import './dashboard_last_refresh.js';
// Block X Phase A0: Server-Detail-Helper (ScanFlashSync, PillPanels, HeartbeatTip).
import { initServerDetailModule } from './server_detail.js';

// Hook fuer HTMX-Pane-Swaps: initServerDetailModule auf neu eingefuegte
// .server-detail-Elemente anwenden. (Block X Track A: Wrapper-Klasse
// von .sd-detail-root auf .server-detail umbenannt.)
document.addEventListener('htmx:afterSettle', function(evt) {
  var elt = (evt.detail && evt.detail.elt) ? evt.detail.elt : document;
  var root = null;
  if (elt.classList && elt.classList.contains('server-detail')) {
    root = elt;
  } else if (elt.querySelector) {
    root = elt.querySelector('.server-detail');
  }
  if (root) initServerDetailModule(root);
});

// Initial-Load (nicht-HTMX): .server-detail direkt im Dokument suchen.
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      var root = document.querySelector('.server-detail');
      if (root) initServerDetailModule(root);
    });
  } else {
    var root = document.querySelector('.server-detail');
    if (root) initServerDetailModule(root);
  }
}

// Alpine.start() laeuft hier, NACH allen Alpine.data()-Registrierungen
// aus dem app-Bundle (z.B. serverPillPanels in server_detail.js). Der
// vendor.js-Bundle setzt nur `window.Alpine`; das Starten passiert erst
// nachdem app.js-Komponenten registriert sind, damit Alpine beim DOM-Walk
// alle x-data-Namen aufloesen kann.
if (typeof window !== 'undefined' && window.Alpine && !window.Alpine.__started) {
  window.Alpine.__started = true;
  window.Alpine.start();
}
