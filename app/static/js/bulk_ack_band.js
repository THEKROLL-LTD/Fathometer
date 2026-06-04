/**
 * Bulk-Ack-Band — Server-Detail "Acknowledge all <band> on this server".
 *
 * ADR-0044 / TICKET-009 Etappe 2. Nutzt den server-scoped Flavor C des
 * Block-F-API `/api/findings/bulk-acknowledge`: der Server resolved die
 * Findings selbst aus `{server_id, risk_band}`. Es wird KEINE ID-Liste
 * durch den Client transportiert (kein 50er-Limit, kein Injection-Vektor).
 *
 * Alpine-Komponente `bulkAckBand(serverId, band, totalCount)`:
 *   - serverId  : int    — Ziel-Server.
 *   - band      : string — eines von escalate/act/mitigate/monitor/noise
 *                          (pending bekommt server-seitig 422, das Template
 *                          rendert dort gar kein Control).
 *   - totalCount: int    — Band-Count aus dem Sektions-Header (Anzeige bis
 *                          die dry_run-Response den echten Count liefert).
 *
 * Sicherheit:
 *   - CSRF-Token aus `<meta name="csrf-token">` via `X-CSRFToken`-Header.
 *   - Antwort-Body wird nie als HTML interpretiert (nur JSON).
 *   - Pflicht-Bestaetigungs-Checkbox (`confirm`) muss true sein bevor
 *     `apply()` greift.
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
      open: false,
      busy: false,
      comment: "",
      confirm: false,
      previewCount: null,
      examples: [],
      error: null,

      reset() {
        this.busy = false;
        this.comment = "";
        this.confirm = false;
        this.previewCount = null;
        this.examples = [];
        this.error = null;
      },

      async openModal() {
        this.reset();
        this.open = true;
        await this.$nextTick();
        await this.runDryRun();
      },

      closeModal() {
        this.open = false;
        this.reset();
      },

      _buildPayload(dryRun) {
        return {
          server_scope: {
            server_id: serverId,
            risk_band: band,
          },
          dry_run: !!dryRun,
        };
      },

      async runDryRun() {
        this.busy = true;
        this.error = null;
        try {
          const payload = this._buildPayload(true);
          const data = await postBulk(payload);
          this.previewCount = typeof data.count === "number" ? data.count : 0;
          this.examples = Array.isArray(data.examples) ? data.examples : [];
        } catch (e) {
          this.error = e.message || "Vorschau fehlgeschlagen";
          this.$dispatch("toast", { msg: this.error, kind: "error" });
        } finally {
          this.busy = false;
        }
      },

      async apply() {
        if (this.busy) return;
        if (!this.canApply) return;
        this.busy = true;
        this.error = null;
        try {
          const payload = this._buildPayload(false);
          const trimmed = (this.comment || "").trim();
          if (trimmed) payload.comment = trimmed;
          const data = await postBulk(payload);
          const n = typeof data.count === "number" ? data.count : 0;
          this.$dispatch("toast", {
            msg: `${n} ${band}-Finding${n === 1 ? "" : "s"} abgehakt`,
            kind: "success",
          });
          this.open = false;
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

      get truncatedCount() {
        if (this.previewCount === null) return 0;
        const rest = this.previewCount - this.examples.length;
        return rest > 0 ? rest : 0;
      },

      get canApply() {
        return (
          !this.busy &&
          this.confirm === true &&
          this.previewCount !== null &&
          this.previewCount > 0 &&
          !this.error
        );
      },
    };
  }

  document.addEventListener("alpine:init", () => {
    window.Alpine.data("bulkAckBand", bulkAckBand);
  });

  // Fallback wenn Alpine bereits laeuft.
  window.bulkAckBand = bulkAckBand;
})();
