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
// .sd-detail-root-Elemente anwenden.
document.addEventListener('htmx:afterSettle', function(evt) {
  var elt = (evt.detail && evt.detail.elt) ? evt.detail.elt : document;
  var root = null;
  if (elt.classList && elt.classList.contains('sd-detail-root')) {
    root = elt;
  } else if (elt.querySelector) {
    root = elt.querySelector('.sd-detail-root');
  }
  if (root) initServerDetailModule(root);
});

// Initial-Load (nicht-HTMX): .sd-detail-root direkt im Dokument suchen.
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      var root = document.querySelector('.sd-detail-root');
      if (root) initServerDetailModule(root);
    });
  } else {
    var root = document.querySelector('.sd-detail-root');
    if (root) initServerDetailModule(root);
  }
}
