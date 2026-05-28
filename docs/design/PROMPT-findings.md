Design the **`/findings` page** for Fathometer — the same project whose
Login, Dashboard and Server-Detail pages are already in this canvas.
Extend the existing visual language; do not re-invent it.

The `/findings` page is the operator's cross-fleet triage inbox. Where
`/servers/<id>` answers „what do I have to do on *this* box right now?",
`/findings` answers „across the whole fleet, which `(server ×
application-group)` buckets need my attention?". The data model is a
**Bucket-View**: each bucket is a `(server, application_group)` tuple
with a single Risk-Band evaluation that applies to all findings inside
it (junction model — the same Risk-Band pill that the Server-Detail
application-group cards wear). A separate **Pending-Bucket** at the end
collects findings without a group, cross-server.

Default behaviour: the page renders **empty** until the operator
submits a filter or types a search term. Filter → narrow → drill is the
whole flow. KPI-spam is the failure mode — anything that does not serve
„narrow the fleet, then drill into one bucket" is either pushed one
click away or removed.

## Scope

Topbar, sidebar and footer already ship in the Dashboard, and the
`/servers/<id>` page already ships with the `sd-*` design system. Both
are out of scope here — assume they sit there unchanged. **Reuse `sd-*`
patterns wherever a Server-Detail equivalent exists**: Risk-Band pill
on the band-summary, finding-row with inline AI-assessment expansion,
`sd-cap` neutral/accent tags for EPSS/CVSS/severity, bulk-toolbar look,
skeleton-frame scan-probe sweep. Do not redefine tokens or class
families that already exist.

Your work is **only the contents of the `.main` slot** that mounts when
the operator clicks „Findings" in the topbar nav.

## Build on the canvas

Render a single navigable React file `Findings.jsx` that drops into the
existing `<main className="main">` slot. Include all states as live
components on the canvas — default empty, filter active with buckets,
one bucket expanded, bulk-selection active, pending-bucket expanded,
skeleton during lazy-load. Sections in this exact order:

1. **Header strip** — eyebrow „Findings", display-serif title
   „Findings". Right side: a single mono counter that reads
   `N Gruppen · M Findings` when a filter is active, else blank. No
   action buttons in the header — CSV-export and bulk-ack live in the
   bulk-action-toolbar (4) below.

2. **Filter-bar** — a single horizontal row of mono filter controls,
   wrapping to a second line on narrow viewports. Order, left to right:
   - search input `q` (placeholder „suche CVE, paket, titel, server…",
     widest control, ~30 % of pane width)
   - tag-select (multi)
   - risk-band-select (escalate / act / mitigate / pending / monitor /
     noise / all)
   - application-group-select
   - action-required-select (yes / no / all)
   - severity-min-select (critical / high / medium / low / all)
   - status-select (open / acknowledged / resolved / all)
   - kev-only toggle
   - stale-only toggle

   Submit button („filter →", outlined cyan, mirrors `.auth__submit`).
   Reset link („zurücksetzen", ghost). When any filter is active, a
   small chip-row appears below the bar showing the active filters
   each with an × remove-button; chip-row is hidden when no filter is
   active. There is **no** separate server-filter — server drilldown
   runs through the search input (e.g. typing the hostname).

3. **Empty-state** — renders **instead of the bucket list** when no
   filter is active. Two short mono lines, centered horizontally,
   around 25–30 % from the top of the pane:
   - `> {N} findings im fleet, {M} servers.`
   - `> setze einen filter oder suche nach CVE, paket oder server.`

   The accent-cyan `>` prefix matches the sysline on Server-Detail. No
   illustration, no oversized icon. The filter-bar above stays
   rendered so the operator can act without scrolling.

4. **Bulk-action toolbar** — sits between filter-bar and bucket-list.
   Renders **only** when at least one checkbox is ticked (bucket-header
   or finding-row). Sticky to the top of the pane on scroll. Single
   mono row, hairline-divider above and below:
   - selection counter („N ausgewählt")
   - „auswahl ack" button (outlined cyan, primary)
   - „csv exportieren" link (ghost, download arrow icon)
   - „auswahl aufheben" link (ghost, right-aligned)

   No required-comment input on bulk-ack (ADR-0006).

5. **Bucket-card list** — vertical stack of `<details>` cards in the
   order escalate → act → mitigate → pending → monitor → noise. The
   Pending-Bucket comes as the very last card, regardless of band.
   Each card uses an `sd-band`-style summary row:
   - selection-checkbox (bucket-level — ticking it selects all findings
     in the bucket; semantically separate from individual finding
     checkboxes, both can be active at the same time)
   - Risk-Band pill (outline, cyan only on escalate)
   - server-name in mono, rendered as a link to `/servers/<id>`. Click
     on the link must not toggle the `<details>` — guard with
     `event.stopPropagation`
   - group-label in mono
   - finding-count badge, right-aligned
   - chevron at the very right

   **Card-body** (render one card expanded for the canvas demo, leave
   the others collapsed) is a findings table with **seven columns** —
   `checkbox · CVE+title · package+version-diff · EPSS · CVSS ·
   severity · first-seen`. **No server column** and **no group column**
   in the body — both are redundant with the header pill row. Each
   finding row is itself a `<details>` whose expanded body shows the
   inline „KI-Bewertung" block from Server-Detail (`sd-ai-eyebrow` +
   `sd-ai-text`).

6. **Pending-Bucket card** — structurally identical to other buckets,
   with two differences:
   - header label reads „— ohne Group —"; the Risk-Band pill renders as
     a muted gray „pending" tag
   - body keeps a **server column** as the first non-checkbox column,
     because the Pending-Bucket is cross-server and without it the
     operator can't tell which host a finding comes from. Column order
     in the Pending-Bucket body: `checkbox · server · CVE+title ·
     package+version-diff · EPSS · CVSS · severity · first-seen`

7. **Bucket-body skeleton** — when a bucket is expanded but its
   findings have not arrived yet (lazy-load), render 5 placeholder
   rows using the `sd-skel-frame` scan-probe sweep from the Sidebar
   heartbeat-skel and Server-Detail KPI-tile-skel. The pager renders
   as `— · —` until real data lands.

8. **Sub-pagination** — at the bottom of each expanded bucket-body:
   classic page navigation, 20 findings per page. Style identical to
   `workflow-card__footer` on Server-Detail (`Seite N von M`,
   prev/next chevrons, disabled when on first/last). No outer
   pagination on the bucket-list itself.

## Hard constraints — do not violate

- **No DaisyUI, no Tailwind utility classes.** Semantic BEM-ish class
  names (`.findings__filter-bar`, `.bucket-card`, `.bucket-card__head`,
  `.pending-bucket`, …) so the markup ports 1:1 into the production
  Jinja templates.
- **Reuse `sd-*` classes** from `server-detail.css` where the visual
  element already exists (Risk-Band pill, finding-row layout, inline
  AI-reason block, `sd-cap` tags for EPSS/CVSS/severity, bulk-toolbar
  look, skeleton-frame). Do not duplicate tokens.
- **No comment/note/justification fields anywhere** (ADR-0006).
  Bulk-ack confirms with a single button, no required comment input.
- **Outline-only badges.** No filled backgrounds. Cyan is reserved for
  `escalate`, `KEV`, and `critical` only — `act`/`mitigate`/`pending`/
  `monitor`/`noise` band-pills stay neutral gray.
- **Fixed sort.** No sort-selector, no sort-arrows on column headers.
  Bucket order is risk_band desc → server.name asc → group.label asc
  (Pending-Bucket always last). Findings inside a bucket sort
  KEV desc → EPSS desc → CVSS desc → first_seen asc.
- **Default-empty.** With no filter active, no buckets render — the
  filter-bar plus the two-line centered empty-state are the entire
  page.
- **No outer pagination.** All buckets that match the filter render
  their headers eagerly. Sub-pagination kicks in only inside an
  expanded bucket.
- **Accessibility.** WCAG 2.1 AA contrast on every text-on-surface
  pairing; visible 1 px cyan focus rings on every interactive element;
  keyboard nav order: filter-bar → bulk-toolbar (when visible) → first
  bucket-header → expanded findings (when open) → next bucket-header.

## Output on the canvas

`Findings.jsx` as a live React component, rendered as the **inner
content of `.main` only** (do NOT re-emit `.topbar`, `.sidebar`,
`.footer`, or the outer `.app` grid). Mocked data should mirror the
shape from `server-detail-data.js`: at least one bucket per risk-band,
a Pending-Bucket with 3-4 findings across two servers, total
~12 buckets, ~150 mock findings. Both the empty state and the filtered
state must be reachable on the canvas — a hidden „dev toggle" or two
side-by-side mounts is fine; the goal is that I can click through both
flows. That's it — no diff, no matrix, no annotation. We'll review by
clicking through the canvas.

There is no mockup screenshot for this page. The section list above is
the content/section contract. The visual treatment comes from your own
existing brand and the `sd-*` patterns already in this project. When
the section spec and the existing brand conflict, the brand wins.
