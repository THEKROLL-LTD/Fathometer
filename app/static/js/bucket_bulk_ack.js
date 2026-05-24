/**
 * Bucket-Bulk-Acknowledge Selection-State (ADR-0037 §(4), TICKET-006 Etappe 3).
 *
 * Verwaltet zwei unabhaengige Selection-Listen:
 *   - bucketSelections : [{server_id, group_id, filter}]
 *   - findingIds       : [int]
 *
 * Counter ist die Summe; Bucket+Finding-Doppelselektion ist ausdruecklich
 * erlaubt (ADR-0037 §(4) — Server dedupliziert; Ack ist idempotent).
 *
 * Submit laeuft als klassischer Form-POST an `/findings/bulk/acknowledge`.
 * Bei HTMX-Header reagiert der Server mit `HX-Redirect`; sonst mit
 * 303-Redirect. Die `<form>` submittet sich von selbst — wir setzen nur
 * `submitting` damit der Button blockiert bleibt waehrend der Browser den
 * Roundtrip macht.
 *
 * Sicherheit:
 *   - CSRF-Token kommt als Hidden-Input aus dem Modal (flask-wtf).
 *   - Inputs (bucket-server, bucket-group, bucket-filter) werden aus
 *     `dataset.*` gelesen — KEINE String-Interpolation in Inline-Handler.
 */
(function () {
  "use strict";

  function bucketBulkSelection() {
    return {
      bucketSelections: [],
      findingIds: [],
      modalOpen: false,
      submitting: false,

      get total() {
        return this.bucketSelections.length + this.findingIds.length;
      },

      toggleBucket(serverId, groupId, filter, checked) {
        const sid = parseInt(serverId, 10);
        const gid = parseInt(groupId, 10);
        if (Number.isNaN(sid) || Number.isNaN(gid)) return;
        const key = sid + "|" + gid;
        if (checked) {
          if (
            !this.bucketSelections.some(
              (b) => b.server_id + "|" + b.group_id === key,
            )
          ) {
            this.bucketSelections.push({
              server_id: sid,
              group_id: gid,
              filter: filter || "",
            });
          }
        } else {
          this.bucketSelections = this.bucketSelections.filter(
            (b) => b.server_id + "|" + b.group_id !== key,
          );
        }
      },

      toggleFinding(id, checked) {
        const fid = parseInt(id, 10);
        if (Number.isNaN(fid)) return;
        if (checked) {
          if (!this.findingIds.includes(fid)) this.findingIds.push(fid);
        } else {
          this.findingIds = this.findingIds.filter((x) => x !== fid);
        }
      },

      clearAll() {
        this.bucketSelections = [];
        this.findingIds = [];
        // Visueller Reset: HTMX-lazy geladene Checkboxen sind nicht im
        // reactive-Graph von Alpine; daher manueller DOM-Sync.
        document
          .querySelectorAll("input[data-bucket-server]")
          .forEach((el) => {
            el.checked = false;
          });
        document
          .querySelectorAll("input[data-bulk-finding-id]")
          .forEach((el) => {
            el.checked = false;
          });
      },

      openModal() {
        this.modalOpen = true;
      },

      closeModal() {
        this.modalOpen = false;
      },

      onSubmit(_ev) {
        // Submit-Button blocken um Doppel-Submit zu verhindern.
        // `<form>` submittet sich von selbst; der Server redirected.
        this.submitting = true;
      },
    };
  }

  document.addEventListener("alpine:init", () => {
    window.Alpine.data("bucketBulkSelection", bucketBulkSelection);
  });
  window.bucketBulkSelection = bucketBulkSelection;
})();
