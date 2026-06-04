/**
 * Bulk-Ack-Band — Server-Detail "Acknowledge all <band> on this server".
 *
 * ADR-0044 / TICKET-009 Etappe 2. Nutzt den server-scoped Flavor C des
 * Block-F-API `/api/findings/bulk-acknowledge`: der Server resolved die
 * Findings selbst aus `{server_id, risk_band}`. Es wird KEINE ID-Liste
 * durch den Client transportiert (kein 50er-Limit, kein Injection-Vektor).
 *
 * Inline-Confirm/Cancel-Toggle (ADR-0044-Amendment, TICKET-009-Nachzuegler):
 * kein Modal, kein dry_run-Vorabruf, kein Kommentar. Der Rest-Button
 * "Acknowledge all" armiert den Confirm-Slot im selben Header-Slot; "Confirm"
 * feuert direkt den Flavor-C-Apply, "Cancel" geht zurueck in den Ruhezustand.
 *
 * Alpine-Komponente `bulkAckBand(serverId, band, totalCount)`:
 *   - serverId  : int    — Ziel-Server.
 *   - band      : string — eines von escalate/act/mitigate/monitor/noise
 *                          (pending bekommt server-seitig 422, das Template
 *                          rendert dort gar kein Control).
 *   - totalCount: int    — Band-Count aus dem Sektions-Header. Der Count `N`
 *                          in der Confirm-Frage wird server-gerendert; das
 *                          Argument bleibt der Signatur-Kompatibilitaet halber.
 *
 * Sicherheit:
 *   - CSRF-Token aus `<meta name="csrf-token">` via `X-CSRFToken`-Header.
 *   - Antwort-Body wird nie als HTML interpretiert (nur JSON).
 */

(function () {
  "use strict";

  const ENDPOINT = "/api/findings/bulk-acknowledge";

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") || "" : "";
  }

  async function postBulk(body) {
    const res = await fetch(ENDPOINT, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrfToken(),
        Accept: "application/json",
      },
      body: JSON.stringify(body),
    });
    let payload = null;
    try {
      payload = await res.json();
    } catch (e) {
      payload = null;
    }
    if (!res.ok) {
      const msg =
        (payload && (payload.detail || payload.error || payload.message)) ||
        `Fehler ${res.status}`;
      const err = new Error(msg);
      err.status = res.status;
      err.payload = payload;
      throw err;
    }
    return payload || {};
  }

  function bulkAckBand(serverId, band, totalCount) {
    return {
      armed: false,
      busy: false,
      error: null,

      arm() {
        this.error = null;
        this.armed = true;
      },

      cancel() {
        this.armed = false;
      },

      async confirm() {
        if (this.busy) return;
        this.busy = true;
        this.error = null;
        try {
          const data = await postBulk({
            server_scope: {
              server_id: serverId,
              risk_band: band,
            },
            dry_run: false,
          });
          const n = typeof data.count === "number" ? data.count : 0;
          this.$dispatch("toast", {
            msg: `${n} ${band}-Finding${n === 1 ? "" : "s"} abgehakt`,
            kind: "success",
          });
          this.armed = false;
          setTimeout(() => {
            window.location.reload();
          }, 400);
        } catch (e) {
          this.error = e.message || "Fehler beim Anwenden";
          this.$dispatch("toast", { msg: this.error, kind: "error" });
        } finally {
          this.busy = false;
        }
      },
    };
  }

  document.addEventListener("alpine:init", () => {
    window.Alpine.data("bulkAckBand", bulkAckBand);
  });

  // Fallback wenn Alpine bereits laeuft.
  window.bulkAckBand = bulkAckBand;
})();
