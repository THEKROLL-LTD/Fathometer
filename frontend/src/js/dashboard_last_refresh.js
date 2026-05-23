// dashboard_last_refresh.js — aktualisiert #dashboard-last-refresh alle 30 s
// mit der aktuellen UTC-Zeit im Format HH:MM UTC.
// Defensive: wenn das Element fehlt (z.B. auf Login-Page), No-Op.

function updateLastRefresh() {
  const el = document.getElementById('dashboard-last-refresh');
  if (!el) return;
  const now = new Date();
  const hh = String(now.getUTCHours()).padStart(2, '0');
  const mm = String(now.getUTCMinutes()).padStart(2, '0');
  el.textContent = `${hh}:${mm} UTC`;
}

document.addEventListener('DOMContentLoaded', () => {
  updateLastRefresh();
  setInterval(updateLastRefresh, 30_000);
});
