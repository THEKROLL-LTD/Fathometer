/**
 * Dashboard-SSE-Live-Updates und Stale-Re-Render-Timer (Block H).
 *
 * Konsumiert von `dashboard/index.html` als Alpine-Komponenten
 * `dashboardSse(eventsUrl)` und `staleTick()`. Beide sind
 * self-contained und teilen sich keinen State.
 *
 * Verhalten (siehe ARCHITECTURE §7 + §14):
 *   - `dashboardSse` oeffnet einen `EventSource` auf `eventsUrl` (default
 *     `/events`) und reagiert auf `scan.received`-Frames: passende
 *     Server-Karte (anhand `data-server-id`) wird ~1.5s mit einem
 *     `ring-primary` umrandet, dazu ein Toast mit Kurzfassung der Deltas.
 *   - `staleTick` re-rendered alle 60 Sekunden die Relativzeit-Labels
 *     (Elemente mit `data-last-scan-at`) und togglet Stale-Badges
 *     (`data-stale-threshold-h`) rein client-seitig, ohne Server-Round-Trip.
 *
 * Sicherheit:
 *   - SSE-Payloads kommen vom eigenen Server (Login-required). Wir
 *     schreiben sie ausschliesslich via `textContent` / Custom-Event-Detail
 *     in den DOM — niemals `innerHTML`.
 *   - Kein automatischer Reconnect-Loop in JS; der Browser macht das
 *     selbst, sobald `EventSource` einen Fehler sieht.
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

  function dispatchToast(detail) {
    window.dispatchEvent(new CustomEvent("toast", { detail: detail }));
  }

  function dashboardSse(eventsUrl) {
    return {
      eventSource: null,
      _highlightTimers: {},

      init() {
        if (!eventsUrl || typeof window.EventSource === "undefined") {
          return;
        }
        try {
          this.eventSource = new EventSource(eventsUrl);
        } catch (e) {
          // EventSource-Konstruktor wirft bei invalider URL — wir
          // schlucken still, das Dashboard funktioniert ohne SSE.
          return;
        }
        this.eventSource.addEventListener("scan.received", (e) => {
          let payload;
          try {
            payload = JSON.parse(e.data);
          } catch (_) {
            return;
          }
          this.onScanReceived(payload || {});
        });
        // EventSource reconnected automatisch bei Netz-Fehlern.
        this.eventSource.onerror = () => {
          /* silent — Browser-Auto-Retry uebernimmt */
        };
      },

      onScanReceived(payload) {
        const serverId = payload.server_id;
        if (serverId == null) return;
        const card = document.querySelector(
          `[data-server-id="${String(serverId).replace(/"/g, "")}"]`,
        );
        if (card) {
          card.classList.add("ring-2", "ring-primary", "transition");
          // Vorherigen Timer fuer dieselbe Karte abbrechen, sonst koennten
          // sich konsekutive Updates die Animation gegenseitig wegschneiden.
          const prev = this._highlightTimers[serverId];
          if (prev) clearTimeout(prev);
          this._highlightTimers[serverId] = setTimeout(() => {
            card.classList.remove("ring-2", "ring-primary", "transition");
            delete this._highlightTimers[serverId];
          }, 1500);

          // Last-Scan-Label sofort auf "gerade eben" setzen, falls vorhanden.
          if (payload.ingested_at) {
            card.querySelectorAll("[data-last-scan-at]").forEach((el) => {
              el.dataset.lastScanAt = payload.ingested_at;
              el.textContent = relativeTime(payload.ingested_at);
            });
          }
        }

        const name = payload.server_name || "Server";
        const nNew = payload.new_finding_count ?? 0;
        const nRes = payload.resolved_count ?? 0;
        dispatchToast({
          msg: `Update ${name}: ${nNew} neu, ${nRes} resolved`,
          kind: "info",
        });
      },

      destroy() {
        if (this.eventSource) {
          this.eventSource.close();
          this.eventSource = null;
        }
        Object.values(this._highlightTimers).forEach((t) => clearTimeout(t));
        this._highlightTimers = {};
      },
    };
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
        document.querySelectorAll("[data-last-scan-at]").forEach((el) => {
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

  window.dashboardSse = dashboardSse;
  window.staleTick = staleTick;
  // Export fuer Tests / Konsolen-Debug.
  window.__secscanRelativeTime = relativeTime;
})();
