/**
 * Stale-Re-Render-Timer fuer relative Zeit-Labels und Stale-Badges.
 *
 * Konsumiert von `dashboard/index.html` (und `_attention.html`) als
 * Alpine-Komponente `staleTick()`. Self-contained, kein Server-Round-Trip.
 *
 * Verhalten (siehe ARCHITECTURE §7 + §15):
 *   - `staleTick` re-rendered alle 60 Sekunden die Relativzeit-Labels
 *     (Elemente mit `data-last-scan-at`) und togglet Stale-Badges
 *     (`data-stale-threshold-h`) rein client-seitig.
 *
 * Hinweis (ADR-0019): Die frueher hier ebenfalls beheimatete
 * `dashboardSse(eventsUrl)`-Komponente wurde mit Block L entfernt;
 * Dashboard-Live-Updates laufen jetzt via HTMX-Polling auf dem
 * Pane- und Sidebar-Container, nicht mehr ueber Server-Sent-Events.
 *
 * Sicherheit:
 *   - Wir schreiben Zeit-Strings ausschliesslich via `textContent` in den DOM.
 *   - Keine `innerHTML`-Writes.
 */

(function () {
  "use strict";

  function relativeTime(iso) {
    if (!iso) return "noch nie";
    const dt = new Date(iso).getTime();
    if (Number.isNaN(dt)) return "noch nie";
    const diffSec = Math.max(0, (Date.now() - dt) / 1000);
    if (diffSec < 60) return "gerade eben";
    if (diffSec < 3600) {
      const m = Math.round(diffSec / 60);
      return `vor ${m}min`;
    }
    if (diffSec < 86400) {
      const h = Math.round(diffSec / 3600);
      return `vor ${h}h`;
    }
    const d = Math.round(diffSec / 86400);
    return `vor ${d} Tag${d === 1 ? "" : "en"}`;
  }

  function staleTick() {
    return {
      timer: null,

      init() {
        // Sofort einmal ticken, damit Labels frisch sind (z.B. nach langer
        // BFCache-Wiederherstellung).
        this.tick();
        this.timer = setInterval(() => this.tick(), 60000);
      },

      tick() {
        // Nur span-Elemente bekommen ein neues `textContent`. Container-
        // Elemente (z.B. die Server-Karte selbst, die `data-last-scan-at`
        // fuer die Stale-Threshold-Logik traegt) duerfen NIEMALS hier
        // beruehrt werden — `textContent = ...` zerstoert deren Kinder.
        document.querySelectorAll("span[data-last-scan-at]").forEach((el) => {
          const ts = el.dataset.lastScanAt;
          if (ts) el.textContent = relativeTime(ts);
        });
        document
          .querySelectorAll("[data-stale-threshold-h]")
          .forEach((badge) => {
            const thresholdH = parseInt(
              badge.dataset.staleThresholdH || "",
              10,
            );
            if (!thresholdH || Number.isNaN(thresholdH)) return;
            // Stale-Threshold-Vergleich relativ zum naechstgelegenen
            // Karten-`data-last-scan-at`, falls vorhanden.
            const card = badge.closest("[data-server-id]");
            const lastScan =
              (card && card.dataset.lastScanAt) ||
              badge.dataset.lastScanAt ||
              "";
            if (!lastScan) {
              badge.classList.add("hidden");
              return;
            }
            const ageH =
              (Date.now() - new Date(lastScan).getTime()) / 1000 / 3600;
            if (ageH >= thresholdH) {
              badge.classList.remove("hidden");
            } else {
              badge.classList.add("hidden");
            }
          });
      },

      destroy() {
        if (this.timer) {
          clearInterval(this.timer);
          this.timer = null;
        }
      },
    };
  }

  window.staleTick = staleTick;
  // Export fuer Tests / Konsolen-Debug.
  window.__secscanRelativeTime = relativeTime;
})();
