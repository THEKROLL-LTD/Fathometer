/**
 * Subtle Fade-In bei HTMX-Polling-Updates (Block I, §7a Should #10).
 *
 * Verhalten:
 *   - Listener auf `htmx:afterSettle` an `document.body`: getauschtes
 *     Target bekommt fuer 1s einen `bg-info/20`-Akzent. Wenn das Target
 *     `#detail-pane` ist (z.B. nach Server-Klick in der Sidebar), faerben
 *     wir es nicht — der Pane-Swap ist schon offensichtlich.
 *
 * Hinweis (ADR-0019): Frueher hat dieses Modul zusaetzlich auf das
 * `fathometer:scan-received`-CustomEvent gehoert, das die ehemalige SSE-
 * Komponente `dashboardSse` gefeuert hat. Mit Block L gibt es keinen
 * SSE-Channel fuers Dashboard mehr — Updates kommen via HTMX-Polling auf
 * dem Pane- und Sidebar-Container und werden durch den `htmx:afterSwap`/
 * `afterSettle`-Listener unten automatisch hervorgehoben.
 *
 * Sicherheit:
 *   - Wir manipulieren ausschliesslich `classList` an bestehenden Elementen.
 *     Keine `innerHTML`-Writes, keine Datenuebernahme aus Event-Detail in
 *     den DOM.
 */

(function () {
  "use strict";

  var ACCENT_CLASSES = ["bg-info/20", "transition-colors", "duration-1000"];
  var HIGHLIGHT_MS = 1000;

  function flash(el) {
    if (!el || !el.classList) return;
    ACCENT_CLASSES.forEach(function (cls) { el.classList.add(cls); });
    setTimeout(function () {
      el.classList.remove("bg-info/20");
      // `transition-colors` und `duration-1000` lassen wir an — die kosten
      // nichts und vermeiden Layout-Thrashing.
    }, HIGHLIGHT_MS);
  }

  document.body.addEventListener("htmx:afterSettle", function (evt) {
    var tgt = evt && evt.detail && evt.detail.target;
    if (!tgt) return;
    // Detail-Pane-Swaps sind durch URL-Change schon sichtbar — kein Flash.
    if (tgt.id === "detail-pane" || tgt.id === "detail-pane-content") return;
    flash(tgt);
  });
})();
