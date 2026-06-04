/**
 * Sidebar-Logik (Block I, §7a).
 *
 * Stellt:
 *   - `sidebarSearch()` Alpine-Component
 *       - Live-Filter der Server-Liste (Substring auf Server-Name + Tag-Namen).
 *       - `/`-Shortcut global: fokussiert das Such-Input wenn kein
 *         Input/Textarea aktiv ist.
 *       - `Esc` leert das Feld und entfokussiert.
 *       - `Enter` mit nicht-leerem Wert navigiert zum Dashboard mit
 *         aktivem `?q=<query>`-Filter (Block M, ADR-0020) via HTMX.
 *         Das Dashboard hat die Cross-Server-Findings-Suche uebernommen;
 *         der frueher hier verlinkte `/findings/search`-Endpoint wurde
 *         in Block-M Phase A ersatzlos entfernt.
 *   - Heartbeat-Tooltip: delegated Hover-Handler auf `#server-list` mit
 *     300ms Delay. Tooltip wird absolut positioniert und nach Mouseleave
 *     wieder entfernt. Reines DOM (kein Alpine-State), damit es auch
 *     funktioniert wenn die Sidebar via HTMX nachgeladen wird.
 *
 * Sicherheit:
 *   - Tooltip-Content kommt aus `data-*`-Attributen, die server-seitig
 *     gerendert wurden (ISO-Datum, Severity-Enum, ganzzahliger KEV-Count).
 *     Wir schreiben sie ausschliesslich via `textContent` in den DOM —
 *     kein `innerHTML`, kein `eval`, kein Funnel fuer Server-Names.
 *   - Globaler `/`-Shortcut respektiert `INPUT`/`TEXTAREA`/contenteditable,
 *     damit Tippen im Form-Feld die Sidebar-Suche nicht ueberraschend
 *     uebernimmt.
 */

(function () {
  "use strict";

  // ---- Sidebar-Search (Alpine) -------------------------------------------

  function normalize(s) {
    return (s || "").toString().toLowerCase().trim();
  }

  function matchesQuery(el, q) {
    if (!q) return true;
    var name = normalize(el.getAttribute("data-server-name"));
    var tags = normalize(el.getAttribute("data-server-tags"));
    return name.indexOf(q) !== -1 || tags.indexOf(q) !== -1;
  }

  function applyFilter(query) {
    var q = normalize(query);
    var rows = document.querySelectorAll('#server-list [data-server-id]');
    rows.forEach(function (el) {
      el.classList.toggle("hidden", !matchesQuery(el, q));
    });
  }

  window.sidebarSearch = function () {
    return {
      query: "",
      onInput: function () {
        applyFilter(this.query);
      },
      clear: function () {
        this.query = "";
        applyFilter("");
        var el = this.$refs && this.$refs.searchInput;
        if (el && typeof el.blur === "function") el.blur();
      },
      submit: function () {
        var q = normalize(this.query);
        if (!q) return;
        // Block M (ADR-0020): Dashboard hat die Cross-Server-Such-Surface
        // uebernommen. `/findings/search` ist weg — wir navigieren zur
        // Dashboard-Route mit `?q=<query>`. Der Dashboard-View parsed `q`
        // via DashboardFilter.from_request() und filtert die Findings-
        // Tabelle entsprechend.
        var url = "/?q=" + encodeURIComponent(q);
        if (window.htmx && typeof window.htmx.ajax === "function") {
          window.htmx.ajax("GET", url, {
            target: "#detail-pane",
            swap: "innerHTML",
            pushUrl: true,
          });
        } else {
          window.location.href = url;
        }
      },
    };
  };

  // ---- Global `/`-Shortcut ------------------------------------------------

  function isEditable(el) {
    if (!el) return false;
    var tag = (el.tagName || "").toUpperCase();
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
    if (el.isContentEditable) return true;
    return false;
  }

  document.addEventListener("keydown", function (e) {
    if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
    if (isEditable(document.activeElement)) return;
    var input = document.getElementById("sidebar-search-input");
    if (!input) return;
    e.preventDefault();
    input.focus();
    if (typeof input.select === "function") input.select();
  });

  // ---- Heartbeat-Tooltip --------------------------------------------------

  var TOOLTIP_DELAY_MS = 300;
  var tooltipEl = null;
  var hoverTimer = null;

  function ensureTooltip() {
    if (tooltipEl) return tooltipEl;
    var el = document.createElement("div");
    el.id = "heartbeat-tooltip";
    el.setAttribute("role", "tooltip");
    el.className = [
      "pointer-events-none",
      "fixed", "z-50",
      "px-2", "py-1",
      "rounded",
      "bg-base-content", "text-base-100",
      "text-xs", "font-mono",
      "shadow-lg",
      "whitespace-nowrap",
      "hidden",
    ].join(" ");
    document.body.appendChild(el);
    tooltipEl = el;
    return el;
  }

  function buildTooltipText(cell) {
    var day = cell.getAttribute("data-day") || "";
    var sev = cell.getAttribute("data-severity") || "";
    var kev = parseInt(cell.getAttribute("data-kev") || "0", 10);
    var scan = cell.getAttribute("data-had-scan") === "1";
    var parts = [day];
    if (sev) {
      parts.push("max " + sev);
    } else if (scan) {
      parts.push("clean");
    } else {
      parts.push("no scan");
    }
    if (kev > 0) parts.push(kev + " KEV");
    return parts.join(" · ");
  }

  function showTooltip(cell) {
    var el = ensureTooltip();
    el.textContent = buildTooltipText(cell);
    el.classList.remove("hidden");
    var rect = cell.getBoundingClientRect();
    // Rechts oberhalb der Pille; vermeide Viewport-Right-Overflow.
    var left = rect.right + 8;
    var top = rect.top - 4;
    var tipW = el.offsetWidth || 160;
    if (left + tipW > window.innerWidth - 4) {
      left = rect.left - tipW - 8;
    }
    if (top < 4) top = 4;
    el.style.left = left + "px";
    el.style.top = top + "px";
  }

  function hideTooltip() {
    if (hoverTimer) {
      clearTimeout(hoverTimer);
      hoverTimer = null;
    }
    if (tooltipEl) tooltipEl.classList.add("hidden");
  }

  function delegatedOver(e) {
    var cell = e.target && e.target.closest && e.target.closest(".heartbeat-cell");
    if (!cell) return;
    if (hoverTimer) clearTimeout(hoverTimer);
    hoverTimer = setTimeout(function () {
      showTooltip(cell);
    }, TOOLTIP_DELAY_MS);
  }

  function delegatedOut(e) {
    var cell = e.target && e.target.closest && e.target.closest(".heartbeat-cell");
    if (!cell) return;
    hideTooltip();
  }

  // Auch Keyboard-Fokus auf einer Pille zeigt Tooltip — Accessibility.
  function delegatedFocus(e) {
    var cell = e.target && e.target.closest && e.target.closest(".heartbeat-cell");
    if (!cell) return;
    if (hoverTimer) clearTimeout(hoverTimer);
    showTooltip(cell);
  }

  function bindHeartbeatTooltips() {
    var root = document.getElementById("server-list");
    if (!root || root.dataset.heartbeatBound === "1") return;
    root.addEventListener("mouseover", delegatedOver, true);
    root.addEventListener("mouseout", delegatedOut, true);
    root.addEventListener("focusin", delegatedFocus, true);
    root.addEventListener("focusout", delegatedOut, true);
    root.dataset.heartbeatBound = "1";
  }

  function init() {
    bindHeartbeatTooltips();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  // HTMX kann die Sidebar austauschen (z.B. nach Tag-Filter-Klick oder
  // nach dem 10s-Polling-Swap aus ADR-0019); wir re-binden Tooltip-Handler
  // defensiv. Idempotent durch `dataset.flag`.
  document.body.addEventListener("htmx:afterSettle", function (evt) {
    bindHeartbeatTooltips();
    // Nach einem Self-Swap der Server-Liste (Polling) sind die `hidden`-
    // Klassen aus der vorherigen Suche weg. Falls eine aktive Suche im
    // Search-Input steht, Filter erneut anwenden, damit der User keine
    // Server zu sehen bekommt, die er gerade weggetippt hat.
    var tgt = evt && evt.detail && evt.detail.target;
    if (tgt && tgt.id === "server-list") {
      var input = document.getElementById("sidebar-search-input");
      if (input && input.value) applyFilter(input.value);
    }
  });
})();
