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
  //
  // ADR-0016 / Block-I-Refinement:
  //   Der Header-Toggle ist nur noch ein Sun/Moon-Icon — kein Dropdown mit
  //   `auto`-Option mehr. Wir behalten aber den `auto`-Mode im Backend-
  //   Cookie als zulaessigen Wert (z.B. nach Setup-Default), der Klick
  //   wechselt jedoch explizit zwischen `light` und `dark`. Wenn der
  //   Initialwert `auto` ist, resolven wir gegen `prefers-color-scheme`
  //   und kippen beim ersten Klick auf das Gegenteil.
  window.themeToggle = function (initial) {
    return {
      current: initial || "auto",
      resolvedDark: false,

      // Was das angezeigte Icon entscheidet: ist der gerade angewandte
      // Theme-Wert "dark"? Sun-Icon zeigt im Dark-Mode (Klick -> light).
      _computeResolvedDark: function () {
        if (this.current === "dark") return true;
        if (this.current === "light") return false;
        // auto
        return !!(window.matchMedia &&
          window.matchMedia("(prefers-color-scheme: dark)").matches);
      },

      // Klick wechselt zwischen light und dark (kein auto im Header-Toggle).
      cycle: function () {
        var next = this.resolvedDark ? "light" : "dark";
        this.current = next;
        this.resolvedDark = next === "dark";
        writeCookie(next);
        applyTheme(next);
      },

      init: function () {
        var self = this;
        applyTheme(this.current);
        this.resolvedDark = this._computeResolvedDark();

        // Im Auto-Mode auf Systemwechsel reagieren, ohne Reload.
        if (window.matchMedia) {
          var mq = window.matchMedia("(prefers-color-scheme: dark)");
          var handler = function () {
            if (self.current === "auto") {
              applyTheme("auto");
              self.resolvedDark = self._computeResolvedDark();
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
