/**
 * Settings-Tab-Active-Sync (Block AD / ADR-0047 — Folge-Fix).
 *
 * Die horizontale Settings-Tab-Leiste (`#settings-nav`) liegt AUSSERHALB des
 * HTMX-Swap-Targets (`#settings-content`). Beim Tab-Klick wird nur der Content
 * getauscht — der Active-Marker (cyan Bottom-Border) wuerde sonst erst beim
 * naechsten Full-Page-Reload nachziehen. Dieser Helper synchronisiert den
 * Active-Tab client-seitig: pfad-basiert ueber den laengsten passenden
 * `href`-Praefix der aktuellen URL.
 *
 * Reine UX-Spiegelung des Server-Render-Zustands — kein State, keine Daten.
 */
(function () {
  "use strict";

  function hrefPath(a) {
    const raw = a.getAttribute("href") || "";
    try {
      return new URL(raw, window.location.origin).pathname;
    } catch (e) {
      return raw;
    }
  }

  function sync() {
    const nav = document.getElementById("settings-nav");
    if (!nav) return;
    const path = window.location.pathname;
    const items = Array.from(nav.querySelectorAll(".settings-tabs__item"));

    let best = null;
    let bestLen = -1;
    for (const a of items) {
      const href = hrefPath(a);
      if (!href) continue;
      // Exakter Treffer oder Unterpfad (z.B. /settings/llm-reviewer/debug-log).
      if (path === href || path.startsWith(href + "/")) {
        if (href.length > bestLen) {
          best = a;
          bestLen = href.length;
        }
      }
    }

    for (const a of items) {
      const active = a === best;
      a.classList.toggle("settings-tabs__item--active", active);
      a.setAttribute("aria-selected", active ? "true" : "false");
    }
  }

  document.addEventListener("DOMContentLoaded", sync);
  // HTMX schiebt nach dem Tab-Swap die neue URL in die History.
  document.body.addEventListener("htmx:pushedIntoHistory", sync);
  // Browser Back/Forward.
  window.addEventListener("popstate", sync);
})();
