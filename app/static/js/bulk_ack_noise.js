/**
 * Bulk-Ack-Noise — Server-Detail "Acknowledge all noise on this server".
 *
 * Block O (ADR-0022 §UI-Redesign). Wiederverwendet das Block-F-API
 * `/api/findings/bulk-acknowledge`, setzt aber `risk_band_filter="noise"`.
 * Der Server filtert eingeschleuste nicht-noise-IDs hart aus und liefert
 * sie in `skipped_non_noise_ids` zurueck.
 *
 * Alpine-Komponente `bulkAckNoise({ getIds })` — der Caller liefert eine
 * Closure die das aktuelle Array der noise-Finding-IDs zurueckgibt
 * (typischerweise im Template als Liste vorberechnet).
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

  function bulkAckNoise(getIds) {
    return {
      open: false,
      busy: false,
      comment: "",
      confirm: false,
      previewCount: null,
      previewServerCount: null,
      skippedCount: 0,
      error: null,

      reset() {
        this.busy = false;
        this.comment = "";
        this.confirm = false;
        this.previewCount = null;
        this.previewServerCount = null;
        this.skippedCount = 0;
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
        const ids = (getIds() || []).slice();
        return {
          finding_ids: ids,
          risk_band_filter: "noise",
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
          this.previewServerCount =
            typeof data.server_count === "number" ? data.server_count : 0;
          this.skippedCount = Array.isArray(data.skipped_non_noise_ids)
            ? data.skipped_non_noise_ids.length
            : 0;
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
            msg: `${n} noise-Finding${n === 1 ? "" : "s"} abgehakt`,
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
    window.Alpine.data("bulkAckNoise", bulkAckNoise);
  });

  // Fallback wenn Alpine bereits laeuft.
  window.bulkAckNoise = bulkAckNoise;
})();
