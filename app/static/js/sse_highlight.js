/**
 * Subtle Fade-In bei SSE-/HTMX-Updates (Block I, §7a Should #10).
 *
 * Verhalten:
 *   - Listener auf `htmx:afterSettle` an `document.body`: getauschtes
 *     Target bekommt fuer 1s einen `bg-info/20`-Akzent. Wenn das Target
 *     `#detail-pane` ist (z.B. nach Server-Klick in der Sidebar), faerben
 *     wir es nicht — der Pane-Swap ist schon offensichtlich.
 *   - Listener auf das globale `secscan:scan-received`-CustomEvent
 *     (vom Block-H-SSE-Client dispatcht): findet die Sidebar-Zeile mit
 *     passender `data-server-id` und faerbt sie fuer 1s ein. Falls keine
 *     Zeile in der Sidebar existiert (z.B. Server gerade revoked), passiert
 *     nichts — fail-silent.
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

  // Block H SSE liefert `scan.received`-Events ueber `dashboardSse` an die
  // Karten. Wir hoeren parallel auf ein Custom-Event, das der SSE-Client
  // alternativ feuern kann (`secscan:scan-received` mit detail.server_id).
  // Falls nicht vorhanden -> kein No-Op-Error.
  window.addEventListener("secscan:scan-received", function (ev) {
    var sid = ev && ev.detail && ev.detail.server_id;
    if (!sid) return;
    var row = document.querySelector(
      '#server-list [data-server-id="' + Number(sid) + '"]'
    );
    if (row) flash(row);
  });
})();
