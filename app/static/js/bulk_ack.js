/**
 * Bulk-Acknowledge — gemeinsame Logik fuer:
 *   - Server-Detail-Bulk (Flavor A: finding_ids[])
 *   - Globale Suche (Flavor B: match.cve_id/package_name [+ tag])
 *
 * Wird von zwei Alpine-Komponenten konsumiert (`bulkAckIds` und
 * `bulkAckMatch`). Beide rufen `bulkAckCore()` mit ihrem spezifischen
 * Payload-Builder, der Rest (dry_run -> apply -> Toast -> Reload) ist
 * gemeinsam.
 *
 * Sicherheit:
 *   - CSRF-Token aus `<meta name="csrf-token">` via `X-CSRFToken`-Header.
 *   - Antwort-Body wird nie als HTML interpretiert — wir lesen nur JSON.
 *   - Bei `dry_run=true` kein Schreibvorgang — wir vertrauen dem Server.
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
        `Error ${res.status}`;
      const err = new Error(msg);
      err.status = res.status;
      err.payload = payload;
      throw err;
    }
    return payload || {};
  }

  /**
   * `bulkAckCore({ buildPayload })` — Alpine-Komponente.
   * `buildPayload(dryRun)` muss `{finding_ids?, match?, dry_run, comment?}`
   * zurueckgeben (ohne CSRF; das laeuft als Header).
   */
  function bulkAckCore({ buildPayload }) {
    return {
      open: false,
      busy: false,
      comment: "",
      previewCount: null,
      previewServerCount: null,
      error: null,

      reset() {
        this.busy = false;
        this.comment = "";
        this.previewCount = null;
        this.previewServerCount = null;
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

      async runDryRun() {
        this.busy = true;
        this.error = null;
        try {
          const payload = buildPayload(true);
          payload.dry_run = true;
          const data = await postBulk(payload);
          this.previewCount = typeof data.count === "number" ? data.count : 0;
          this.previewServerCount =
            typeof data.server_count === "number" ? data.server_count : 0;
        } catch (e) {
          this.error = e.message || "Preview failed";
          this.$dispatch("toast", { msg: this.error, kind: "error" });
        } finally {
          this.busy = false;
        }
      },

      async apply() {
        if (this.busy) return;
        if (!this.previewCount || this.previewCount <= 0) return;
        this.busy = true;
        this.error = null;
        try {
          const payload = buildPayload(false);
          payload.dry_run = false;
          const trimmed = (this.comment || "").trim();
          if (trimmed) payload.comment = trimmed;
          const data = await postBulk(payload);
          const n = typeof data.count === "number" ? data.count : 0;
          this.$dispatch("toast", {
            msg: `${n} finding${n === 1 ? "" : "s"} acknowledged`,
            kind: "success",
          });
          this.open = false;
          // Kurz warten damit der Toast sichtbar wird, dann Reload.
          setTimeout(() => {
            window.location.reload();
          }, 400);
        } catch (e) {
          this.error = e.message || "Apply failed";
          this.$dispatch("toast", { msg: this.error, kind: "error" });
        } finally {
          this.busy = false;
        }
      },

      get canApply() {
        return (
          !this.busy &&
          this.previewCount !== null &&
          this.previewCount > 0 &&
          !this.error
        );
      },
    };
  }

  /**
   * Flavor A: explizite Finding-IDs (Server-Detail-Checkbox-Auswahl).
   * Erwartet `getIds()` als Closure (Alpine reicht das aus dem aeusseren
   * x-data herein).
   */
  function bulkAckIds(getIds) {
    return bulkAckCore({
      buildPayload(_dryRun) {
        const ids = (getIds() || []).slice();
        return { finding_ids: ids };
      },
    });
  }

  /**
   * Flavor B: Match-Kriterium (globale Suche).
   * `criterion` ist `{ cve_id?, package_name?, tag? (CSV), status? }`.
   */
  function bulkAckMatch(criterion) {
    return bulkAckCore({
      buildPayload(_dryRun) {
        const match = {};
        if (criterion.cve_id) match.cve_id = criterion.cve_id;
        if (criterion.package_name)
          match.package_name = criterion.package_name;
        if (criterion.tag) match.tag = criterion.tag;
        if (criterion.status) match.status = criterion.status;
        return { match };
      },
    });
  }

  // Globale Registrierung — Alpine.data ist nicht garantiert verfuegbar,
  // wenn das Script vor Alpine laedt; wir haengen auf `alpine:init`.
  document.addEventListener("alpine:init", () => {
    // window.Alpine ist hier verfuegbar.
    window.Alpine.data("bulkAckIds", bulkAckIds);
    window.Alpine.data("bulkAckMatch", bulkAckMatch);
  });

  // Falls Alpine schon initialisiert ist (Sub-Page-Navigation), als Fallback
  // expose direkt am window.
  window.bulkAckIds = bulkAckIds;
  window.bulkAckMatch = bulkAckMatch;
})();
