// sidebar_viewport.js — Viewport-Aware Sidebar-Polling (Phase C, ADR-0035).
//
// Registriert einen IntersectionObserver der sichtbare .host-Rows trackt
// und alle 60 s einen Batch-POST an /_partials/sidebar/batch schickt.
// CSRF-Token kommt aus <meta name="csrf-token"> (Flask-WTF-Convention).

(function () {
  'use strict';

  // Set der aktuell sichtbaren Server-IDs (Number).
  const visibleServerIds = new Set();

  // CSRF-Token aus Meta-Tag lesen.
  function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  // Batch-POST an /_partials/sidebar/batch.
  // Response ist OOB-HTML; htmx.process() verarbeitet die OOB-Marker.
  function postBatch(ids) {
    if (ids.length === 0) return;

    const token = getCsrfToken();
    fetch('/_partials/sidebar/batch', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': token,
        'HX-Request': 'true',
      },
      body: JSON.stringify({ server_ids: ids }),
    })
      .then(function (resp) {
        if (!resp.ok) return;
        return resp.text();
      })
      .then(function (html) {
        if (!html) return;
        // Fragment in temporäres Element einfügen damit HTMX OOB-Swaps
        // verarbeiten kann.
        const tmp = document.createElement('div');
        tmp.innerHTML = html;
        document.body.appendChild(tmp);
        if (window.htmx) {
          window.htmx.process(tmp);
        }
        // Danach das temporäre Element wieder entfernen falls HTMX
        // die OOB-Elemente bereits in den richtigen Targets bewegt hat.
        requestAnimationFrame(function () {
          if (tmp.parentNode) tmp.parentNode.removeChild(tmp);
        });
      })
      .catch(function (err) {
        console.warn('[sidebar_viewport] batch POST fehlgeschlagen:', err);
      });
  }

  // Debounced-Scroll-Trigger: wenn neue IDs in den Viewport kommen,
  // nicht sofort einen Extra-Request auslösen — 250 ms warten.
  let scrollDebounceTimer = null;
  function onNewIdsVisible() {
    if (scrollDebounceTimer !== null) return;
    scrollDebounceTimer = setTimeout(function () {
      scrollDebounceTimer = null;
      postBatch(Array.from(visibleServerIds));
    }, 250);
  }

  function startPolling() {
    // Initial-Lazy-Load übernimmt der hx-get="/_partials/sidebar" load-Trigger
    // (Block V Muster, _server_list.html). sidebar_batch greift erst beim
    // 60-s-Polling-Tick und beim Scroll-Debounce.
    setInterval(function () {
      postBatch(Array.from(visibleServerIds));
    }, 60_000);
  }

  function initIntersectionObserver() {
    if (!('IntersectionObserver' in window)) {
      // Fallback: alle Server-IDs in den initialen Batch-POST laden.
      console.warn(
        '[sidebar_viewport] IntersectionObserver nicht verfügbar — lade alle Server.'
      );
      const allIds = Array.from(document.querySelectorAll('.host[data-server-id]')).map(
        function (el) { return Number(el.dataset.serverId); }
      );
      postBatch(allIds);
      return;
    }

    const observer = new IntersectionObserver(
      function (entries) {
        let newIdsAppeared = false;
        entries.forEach(function (entry) {
          const id = Number(entry.target.dataset.serverId);
          if (!id) return;
          if (entry.isIntersecting) {
            if (!visibleServerIds.has(id)) {
              visibleServerIds.add(id);
              newIdsAppeared = true;
            }
          } else {
            visibleServerIds.delete(id);
          }
        });
        if (newIdsAppeared) {
          onNewIdsVisible();
        }
      },
      { rootMargin: '200px' }
    );

    // Alle aktuell im DOM vorhandenen .host-Rows observieren.
    function observeAll() {
      document.querySelectorAll('.host[data-server-id]').forEach(function (el) {
        observer.observe(el);
      });
    }

    observeAll();

    // Nach HTMX-Swaps (Sidebar-Reload) neue Rows ebenfalls observieren.
    document.body.addEventListener('htmx:afterSwap', function (evt) {
      const target = evt.detail && evt.detail.target;
      if (!target) return;
      target.querySelectorAll('.host[data-server-id]').forEach(function (el) {
        observer.observe(el);
      });
    });
  }

  // Initialisierung nach DOM-Ready.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      initIntersectionObserver();
      startPolling();
    });
  } else {
    initIntersectionObserver();
    startPolling();
  }
})();
