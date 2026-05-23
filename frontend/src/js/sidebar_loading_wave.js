// sidebar_loading_wave.js — Stagger-Reveal-Helper (Phase C, ADR-0035).
//
// Port von useFleetLoading aus docs/design/app.jsx.
// Lauscht auf htmx:afterSwap für den #server-list-Container und setzt
// pro .host-Row einen staggered transitionDelay bevor die
// .host--materializing-Klasse gesetzt wird (triggert skel-materialize CSS).

(function () {
  'use strict';

  const BASE_DELAY_MS = 220;    // Millisekunden bis die erste Row anfängt zu materialisieren
  const STAGGER_STEP_MS = 18;   // Per-Row-Versatz in Millisekunden
  const JITTER_MIN_MS = 80;     // Minimaler Zufalls-Jitter
  const JITTER_RANGE_MS = 240;  // Maximale Zufalls-Jitter-Spanne (80–320 ms)

  // Wird nach einem Swap auf #server-list (oder einem übergeordneten Container)
  // aufgerufen. Iteriert alle .host-Rows im geswapt Fragment und startet die
  // Materialize-Sequenz.
  function triggerMaterializeWave(container) {
    const rows = Array.from(container.querySelectorAll('.host'));
    if (rows.length === 0) return;

    rows.forEach(function (row, i) {
      const jitter = JITTER_MIN_MS + Math.random() * JITTER_RANGE_MS;
      const delay = BASE_DELAY_MS + i * STAGGER_STEP_MS + jitter;

      // transitionDelay auf alle Tick-Cells setzen damit die CSS-Animation
      // mit dem korrekten Versatz startet.
      const ticks = row.querySelectorAll('.host__beat-tick');
      ticks.forEach(function (tick, j) {
        tick.style.animationDelay = (delay + j * STAGGER_STEP_MS) + 'ms';
      });

      // Nach dem Delay die Klasse hinzufügen die die skel-materialize-Animation triggert.
      setTimeout(function () {
        row.classList.add('host--materializing');

        // Klasse nach Animations-Ende wieder entfernen damit ein Re-Swap
        // sauber neu starten kann.
        setTimeout(function () {
          row.classList.remove('host--materializing');
          // animationDelay zurücksetzen.
          const cleanTicks = row.querySelectorAll('.host__beat-tick');
          cleanTicks.forEach(function (tick) {
            tick.style.animationDelay = '';
          });
        }, 700); // etwas länger als die 600ms skel-materialize-Dauer
      }, delay);
    });
  }

  // htmx:afterSwap-Handler auf dem document-Level.
  // Prüft ob der Swap-Target der Sidebar-Server-List-Container ist.
  document.addEventListener('htmx:afterSwap', function (evt) {
    const target = evt.detail && evt.detail.target;
    if (!target) return;

    // Greift wenn der Swap-Target selbst oder ein Vorfahre #server-list ist,
    // oder wenn der Target direkt die Liste ist.
    const isSidebarList =
      target.id === 'server-list' ||
      target.closest('#server-list') !== null ||
      target.querySelector('#server-list') !== null;

    if (!isSidebarList) return;

    // Das tatsächliche Container-Element bestimmen.
    const container =
      target.id === 'server-list'
        ? target
        : target.querySelector('#server-list') || target;

    triggerMaterializeWave(container);
  });
})();
