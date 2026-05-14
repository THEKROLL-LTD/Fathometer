// Theme-Toggle fuer secscan.
//
// Das No-Flash-Apply (initiales `data-theme`-Setzen aus Cookie/`prefers-
// color-scheme`) passiert SYNCHRON inline im <head> von base.html — der
// Browser muss das Theme vor dem ersten Paint kennen. Dieses Modul liefert
// die Alpine-Komponente fuer den Dropdown-Toggle: Cookie schreiben, Live-
// Apply, Auto-Mode auf Media-Query-Change reagieren.
//
// Wird mit `defer` geladen — Alpine.js (ebenfalls defer) initialisiert die
// `x-data="themeToggle(...)"`-Komponente erst nach DOMContentLoaded, daher
// reicht das.

(function () {
  "use strict";

  var THEME_COOKIE_MAX_AGE = 60 * 60 * 24 * 365; // 1 Jahr

  function resolveAuto() {
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
      return "dark";
    }
    return "light";
  }

  function applyTheme(value) {
    var resolved = value === "auto" ? resolveAuto() : value;
    document.documentElement.setAttribute("data-theme", resolved);
  }

  function writeCookie(value) {
    document.cookie =
      "theme=" + encodeURIComponent(value) +
      "; Path=/; Max-Age=" + THEME_COOKIE_MAX_AGE + "; SameSite=Lax";
  }

  // Alpine-Komponente. Globale Funktion, damit `x-data="themeToggle(...)"`
  // sie findet. Initial-Wert kommt aus dem Server (`theme`-Cookie/Default).
  window.themeToggle = function (initial) {
    return {
      options: [
        { value: "auto", label: "Theme: Auto" },
        { value: "light", label: "Theme: Hell" },
        { value: "dark", label: "Theme: Dunkel" },
      ],
      current: initial || "auto",

      labelFor: function (value) {
        var found = this.options.find(function (opt) {
          return opt.value === value;
        });
        return found ? found.label : "Theme";
      },

      select: function (value) {
        this.current = value;
        writeCookie(value);
        applyTheme(value);
      },

      init: function () {
        var self = this;
        applyTheme(this.current);

        // Im Auto-Mode auf Systemwechsel reagieren, ohne Reload.
        if (window.matchMedia) {
          var mq = window.matchMedia("(prefers-color-scheme: dark)");
          var handler = function () {
            if (self.current === "auto") {
              applyTheme("auto");
            }
          };
          if (mq.addEventListener) {
            mq.addEventListener("change", handler);
          } else if (mq.addListener) {
            // Safari < 14
            mq.addListener(handler);
          }
        }
      },
    };
  };
})();
