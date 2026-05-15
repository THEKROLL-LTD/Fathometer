/**
 * LLM-Provider-Settings — Alpine-Helper fuer Preset-Application,
 * Test-Verbindung und das Provider-Wechsel-Confirm-Modal.
 *
 * Wird von `settings/llm_provider.html` via `x-data="llmProviderForm(...)"`
 * konsumiert. Reine UX-Logik — der Server (`app/views/llm_settings.py`)
 * hat Validation- und Auth-Hoheit.
 *
 * Sicherheit:
 *   - CSRF-Token kommt aus `<meta name="csrf-token">` und geht als
 *     Header (analog `bulk_ack.js`).
 *   - `applyPreset` setzt nur Alpine-State (two-way-bound auf die
 *     Inputs) — kein direkter DOM-Write mit untrusted Daten.
 */

(function () {
  "use strict";

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") || "" : "";
  }

  function llmProviderForm({
    presets,
    initialBaseUrl,
    initialModel,
    activeConvCount,
    testConnectionUrl,
  }) {
    return {
      presets: presets || [],
      baseUrl: initialBaseUrl || "",
      model: initialModel || "",
      initialBaseUrl: initialBaseUrl || "",
      initialModel: initialModel || "",
      activeConvCount: activeConvCount || 0,
      testConnectionUrl: testConnectionUrl,
      testing: false,
      testResult: null,
      confirmOpen: false,
      _confirmed: false,

      applyPreset(idxStr) {
        if (idxStr === "") return;
        const p = this.presets[parseInt(idxStr, 10)];
        if (!p) return;
        this.baseUrl = p.base_url;
        this.model = p.model;
      },

      isProviderChanged() {
        return (
          (this.baseUrl || "").trim() !==
            (this.initialBaseUrl || "").trim() ||
          (this.model || "").trim() !== (this.initialModel || "").trim()
        );
      },

      onSubmit(ev) {
        if (this._confirmed) return;
        if (this.activeConvCount > 0 && this.isProviderChanged()) {
          ev.preventDefault();
          this.confirmOpen = true;
        }
      },

      confirmSubmit() {
        this._confirmed = true;
        this.confirmOpen = false;
        // Naechster Frame: das Form-Element submitten.
        this.$nextTick(() => {
          this.$el.submit();
        });
      },

      async testConnection() {
        this.testResult = null;
        this.testing = true;
        try {
          const res = await fetch(this.testConnectionUrl, {
            method: "POST",
            credentials: "same-origin",
            headers: {
              "X-CSRFToken": csrfToken(),
              Accept: "application/json",
            },
          });
          let payload = null;
          try {
            payload = await res.json();
          } catch (e) {
            payload = { success: false, error: "invalid_response" };
          }
          this.testResult = payload;
        } catch (e) {
          this.testResult = {
            success: false,
            error: "network_error",
            message: String(e),
          };
        } finally {
          this.testing = false;
        }
      },
    };
  }

  document.addEventListener("alpine:init", () => {
    window.Alpine.data("llmProviderForm", llmProviderForm);
  });
  // Fallback bei spaeter Initialisierung.
  window.llmProviderForm = llmProviderForm;
})();
