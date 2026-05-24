// topbar_nav_sync.js — Topbar-Nav-Active-State synchron zur URL halten.
//
// Hintergrund: Topbar liegt ausserhalb von #detail-pane. Bei HTMX-Pane-Swaps
// (Dashboard <-> Findings <-> Server-Detail) wird sie nicht neu gerendert,
// die Jinja-Klassen `topbar__navitem--active` + `aria-current` bleiben am
// urspruenglich beim Page-Load aktiven Item haengen. Dieser Listener hoert
// auf htmx:pushedIntoHistory + htmx:historyRestore und togglet die Klassen
// passend zur neuen `window.location.pathname`.
//
// Pfad-Logik 1:1 aus `app/templates/layout/_header.html` Zeilen 26-31
// (Jinja-Setter fuer _is_findings / _is_dashboard) gespiegelt — Single-
// Source-of-Truth ist serverseitig, hier nur Re-Anwendung nach Pane-Swap.

(function () {
  'use strict';

  function isFindings(p) {
    return p === '/findings' || p.startsWith('/findings/');
  }

  function isDashboard(p) {
    if (isFindings(p)) return false;
    return (
      p === '/' ||
      p === '/dashboard' ||
      (p.startsWith('/dashboard/') && !p.startsWith('/dashboard/findings'))
    );
  }

  function syncActive() {
    const path = window.location.pathname || '/';
    const items = document.querySelectorAll('.topbar__nav .topbar__navitem');
    items.forEach(function (item) {
      const target = item.getAttribute('data-nav') || '';
      const active =
        (target === 'dashboard' && isDashboard(path)) ||
        (target === 'findings' && isFindings(path));
      item.classList.toggle('topbar__navitem--active', active);
      if (active) {
        item.setAttribute('aria-current', 'page');
      } else {
        item.removeAttribute('aria-current');
      }
    });
  }

  document.addEventListener('htmx:pushedIntoHistory', syncActive);
  document.addEventListener('htmx:historyRestore', syncActive);
})();
