// Sidebar Heartbeat-Bar Hover-Tooltip (TICKET-005 Schritt 4).
//
// Event-Delegation auf document.body fuer mouseover/mouseout.
// Pro Hover zur Laufzeit ein .heartbeat-tip-Overlay-DIV bauen und ins
// .host__beat-Parent einhaengen. Sicher gegen XSS: nur textContent,
// kein innerHTML mit data-*-Werten. Skeleton-Cells bekommen kein Tooltip.

const STATE_MAP = {
  escalate: { label: 'ESCALATE', cls: 'alarm' },
  act:      { label: 'ACT',      cls: 'warn'  },
  mitigate: { label: 'ACT',      cls: 'warn'  },
  pending:  { label: 'NOMINAL',  cls: 'ok'    },
  monitor:  { label: 'NOMINAL',  cls: 'ok'    },
  noise:    { label: 'NOMINAL',  cls: 'ok'    },
  unknown:  { label: 'UNKNOWN',  cls: 'unknown' },
  '':       { label: 'NOMINAL',  cls: 'ok'    },
};

const TICK_SELECTOR = '.host__beat-tick:not(.host__beat-tick--skel)';
const tipByTick = new WeakMap();

function formatDay(day) {
  // day = "YYYY-MM-DD" -> "May 17, 2026"
  const d = new Date(day + 'T00:00:00Z');
  if (Number.isNaN(d.getTime())) return day;
  return d.toLocaleDateString('en-US', {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
    timeZone: 'UTC',
  });
}

function buildTip(tick) {
  const day = tick.dataset.day || '';
  const band = tick.dataset.band ?? '';
  const hadScan = tick.dataset.hadScan === '1';
  const state = STATE_MAP[band] || STATE_MAP[''];

  const tip = document.createElement('div');
  tip.className = 'heartbeat-tip';

  const dateEl = document.createElement('div');
  dateEl.className = 'heartbeat-tip__date';
  dateEl.textContent = formatDay(day);
  tip.appendChild(dateEl);

  const stateEl = document.createElement('div');
  stateEl.className = 'heartbeat-tip__state heartbeat-tip__state--' + state.cls;
  stateEl.textContent = state.label;
  tip.appendChild(stateEl);

  if (!hadScan) {
    const hintEl = document.createElement('div');
    hintEl.className = 'heartbeat-tip__hint';
    hintEl.textContent = 'no scan';
    tip.appendChild(hintEl);
  }

  // Position: Tick-Index unter den .host__beat-tick-Geschwistern.
  const parent = tick.parentElement;
  let idx = 0;
  let count = 0;
  if (parent) {
    const siblings = parent.querySelectorAll('.host__beat-tick');
    count = siblings.length;
    for (let i = 0; i < siblings.length; i += 1) {
      if (siblings[i] === tick) { idx = i; break; }
    }
  }
  const total = count > 0 ? count : 30;
  const pct = ((idx + 0.5) / total) * 100;
  tip.style.left = pct + '%';

  return tip;
}

function removeTip(tick) {
  const existing = tipByTick.get(tick);
  if (existing) {
    existing.remove();
    tipByTick.delete(tick);
  }
}

function onOver(event) {
  const tick = event.target.closest(TICK_SELECTOR);
  if (!tick) return;
  // Cleanup falls fuer diesen Tick schon ein Tooltip existiert (Tick-Wechsel-Race).
  removeTip(tick);
  const anchor = tick.closest('.host__beat');
  if (!anchor) return;
  const tip = buildTip(tick);
  anchor.appendChild(tip);
  tipByTick.set(tick, tip);
}

function onOut(event) {
  const tick = event.target.closest(TICK_SELECTOR);
  if (!tick) return;
  // Wenn relatedTarget noch im selben Tick steckt: nicht entfernen.
  const next = event.relatedTarget;
  if (next && tick.contains(next)) return;
  removeTip(tick);
}

document.body.addEventListener('mouseover', onOver);
document.body.addEventListener('mouseout', onOut);
