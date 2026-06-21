# VYREX Console — Navigation & IA Redesign TODO

> **Goal:** kill the "27-link table of contents." Turn the sidebar from a flat bookmark
> list into a **command-first, hub-and-spoke, dashboard-as-navigation** experience that has
> a *sense of place* and *task flow*. No backend work required — this is entirely
> `web/console/` (vanilla JS, air-gapped, no deps). Nothing is deleted; every existing
> route is re-homed (mapping in §3).

---

## 1. The problem (today)

- **27 top-level routes** in one flat rail (`ROUTES` in `app.js`), 5 sections:
  Monitor (4) · Investigate (4) · Assure (2) · **Operate (11)** · **Toolkit (8)**.
- Every link has equal visual weight → no hierarchy, no "what do I do first."
- The 8 Toolkit items are *one-off utilities* (Port Scanner, CVE Lookup, Phishing
  Analyzer…) squatting on permanent nav real estate they don't earn.
- The **⌘K command palette already exists** and is the better access pattern — but it's
  hidden behind a shortcut while the giant rail dominates the screen.
- No favorites, no recents, no persona framing, no contextual drilling. You *jump* between
  pages like bookmarks instead of *flowing* through a task (asset → its findings → its case).

**One line:** the platform's depth is real; the navigation makes it feel like a link farm.

---

## 2. The vision — four moves

1. **Collapse 27 → 6 primary destinations** using *hubs* (a primary page that opens with
   its own secondary tabs), so the rail finally has hierarchy.
2. **Make ⌘K the hero.** Promote the command palette to an always-visible omni-bar
   ("Search or jump to… ⌘K") — the power spine, with recents + scoped search + deep actions.
3. **Demote tools to a launcher.** One "Tools" button opens an app-grid of the 8 utilities.
4. **Navigation-by-dashboard.** The Home (Mission Control) tiles are *clickable entry
   points* — you navigate by clicking a live posture gauge / criticals ticker / ATT&CK cell,
   not by hunting a link. Add pins, recents, and a persona lens on top.

---

## 3. Target IA — the new map (every current route re-homed)

| New primary (rail) | Sub-nav tabs (hub) | From today's routes |
|---|---|---|
| **Home** (Mission Control) | — | `overview` |
| **Triage** (the daily driver) | — | `triage` |
| **Investigate** | Cases · Assets · Hunt · Threat Intel · Live Hunt · Coverage | `cases` `assets` `hunt` `intel` `livehunt` `coverage` |
| **Automate** ⭐ | AI Analyst · Automation (n8n) · Playbooks · Alerting | `agent` `automation` `playbooks` `alerting` |
| **Assurance** | Compliance · Trust Center · Reports · Model Card | `compliance` `trust` `reports` `model` |
| **Operations** | Sensors & Fusion · Queue/SLA · Detections · Dashboards | `fusion` `manager` `detections` `dashboards` |
| **Settings** (rail bottom) | — | `settings` |
| **Tools** (launcher, not rail) | app-grid modal | `vitals` `news` `loganalyzer` `phishing` `cvelookup` `irplaybook` `portscan` |
| **Assistant** (persistent "Ask" button) | — | `assistant` |

- ⭐ **Automate** is featured because the governed agentic AI analyst is the headline
  differentiator — it deserves a primary slot, not burial under "Operate".
- Result: **6 primary rail items + Settings** instead of 27. The hub tabs preserve every
  screen and add a "you are here" context the flat list never had.

---

## 4. Workstreams (the TODO)

Effort: S (<½ day) · M (½–1.5 days) · L (2+ days). Priority: **P0** = the core fix,
**P1** = makes it feel premium, **P2** = delight/polish.

### WS-A — Restructure the rail into hubs  *(P0 — the core fix)*
- [ ] **A1 (P0,M)** Add a `hub`/`parent` field to `ROUTES` and a `HUBS` map defining the 6
      primary destinations + their ordered child routes (§3). Keep route keys unchanged so
      deep-links/⌘K still work.
- [ ] **A2 (P0,M)** Rewrite `buildNav()` to render only the **6 primary + Settings** items
      (icon + label), not all 27. Active-state follows the *hub* of the current route.
- [ ] **A3 (P0,M)** Add a **sub-nav tab strip** under the page header that renders the active
      hub's children (e.g. Investigate → Cases · Assets · Hunt · Intel · Live Hunt · Coverage).
      Clicking a tab calls `go(childKey)`; the strip persists while you're in that hub.
- [ ] **A4 (P0,S)** Update `go()` / `routeFromHash()` so landing on a child route lights the
      correct primary in the rail **and** the correct tab in the strip.
- [ ] **A5 (P1,S)** Remember the *last-visited tab per hub* (localStorage) so re-entering a
      hub returns you where you were.

### WS-B — Command-first: elevate ⌘K to a hero omni-bar  *(P0)*
- [ ] **B1 (P0,S)** Replace the topbar search input with a prominent **"Search or jump to…  ⌘K"**
      omni-bar that opens the palette (reuse `openPalette()`); make it the visual focal point.
- [ ] **B2 (P0,M)** Palette upgrades: section-grouped results (Pages / Actions / Recent /
      Entities), fuzzy match, and **arrow-key + type-ahead** already partly there — add result
      grouping + icons per group. (`renderPalette`, `paletteSource` in `app.js`.)
- [ ] **B3 (P1,S)** **Recents**: track the last ~6 visited routes (localStorage) and show them
      at the top of an empty palette and on Home.
- [ ] **B4 (P1,M)** Scope the palette: a leading `>` runs actions only, `#` searches findings,
      `@` jumps to assets/entities — a small "mode" affordance that makes power-use obvious.
- [ ] **B5 (P2,S)** Surface the existing `CMDK_ACTIONS` (Correlate, Generate report, Dispatch
      alerts, Run storyline) more prominently with a "⏎ to run" hint and a one-line description.

### WS-C — Tools launcher (app-grid)  *(P0)*
- [ ] **C1 (P0,M)** Build a **Tools launcher**: a single rail/topbar "Tools" button opens a
      modal **app-grid** (3–4 cols) of the 7 utilities, each a tile with icon + name + one-line
      purpose. Clicking launches the existing view. Removes them from permanent nav.
- [ ] **C2 (P1,S)** Make the launcher searchable + keyboard-navigable; tiles show a tiny live
      stat where cheap (e.g. Node Vitals → current CPU%).
- [ ] **C3 (P1,S)** Mark genuinely *active/operational* tools vs *demo/utility* with a chip so
      the grid reads as a real toolbox, not a pile of widgets.

### WS-D — Mission Control home = navigation-by-dashboard  *(P0/P1)*
- [ ] **D1 (P0,M)** Rebuild Home so its tiles are **clickable entry points**: posture gauge →
      Coverage; criticals ticker → Triage (filtered); SLA tile → Operations/Queue; ATT&CK
      mini-heatmap cell → Coverage filtered to that technique; "AI Analyst proposed N" → Automate.
- [ ] **D2 (P1,M)** A **live "happening now" strip** (recent detections / agent actions) that
      ticks — kills the "it's a static report" feel (reuse the existing Overview ticker; wire
      to SSE later). Respect `prefers-reduced-motion`.
- [ ] **D3 (P1,S)** "For you" row on Home: **Pinned** + **Recents** + **Resume** (last incident
      / last hunt query).

### WS-E — Personalization & persona lens  *(P1)*
- [ ] **E1 (P1,M)** **Pin/favorite** any route or hub-tab (star icon); pins render as a compact
      row at the top of the rail. Persist in localStorage.
- [ ] **E2 (P1,M)** **Persona lens** switcher (Analyst / Manager / Auditor) that reorders the
      rail + sets the default landing (Analyst→Triage, Manager→Operations, Auditor→Assurance).
      Pure client-side reordering; no RBAC change.
- [ ] **E3 (P1,S)** **Collapsible rail** (icon-only mode with hover tooltips) + remember state.
- [ ] **E4 (P2,S)** Per-persona Home tile set (Manager sees SLA/workload first; Auditor sees
      chain-integrity/evidence first).

### WS-F — Contextual flow & wayfinding  *(P1)*
- [ ] **F1 (P1,M)** **Breadcrumbs** that reflect hub → tab → entity (e.g. Investigate › Assets ›
      `web-prod-03`), each segment clickable. Replaces the single static crumb line.
- [ ] **F2 (P1,M)** **Entity-centric drilling**: clicking an asset/IP/CVE/incident anywhere
      lands on its detail hub (extend the existing `window.pivot`), so you *flow* rather than
      jump back to the rail. Add in-view "open in Investigate" affordances.
- [ ] **F3 (P2,S)** **Back/forward within a hub** (the browser hash already supports it — add
      visible ‹ › controls + "recently viewed in this hub").

### WS-G — Make it *interesting* (motion & craft)  *(P1/P2)*
- [ ] **G1 (P1,S)** Rail + tab transitions: subtle active-indicator slide, hub-switch crossfade
      of the content area (reduced-motion safe).
- [ ] **G2 (P2,S)** Hover/peek: rail items show a tiny popover preview (count badges, last
      update) so the nav *informs* instead of just linking.
- [ ] **G3 (P2,S)** First-run **spotlight tour** (3–4 steps) pointing at the omni-bar, hubs,
      Tools launcher, and persona lens — turns "where is everything" into a 20-second intro.
- [ ] **G4 (P2,S)** Count/severity **badges** on rail items (e.g. Triage → open criticals,
      Cases → active incidents) so the rail carries live signal.

### WS-H — Keyboard model & a11y update  *(P0/P1)*
- [ ] **H1 (P0,S)** Re-map the `1–9` number keys to the **6 primary hubs** (not 9 random
      routes); update the `?` cheat-sheet (`toggleShortcuts` in `app.js`).
- [ ] **H2 (P1,S)** `[` / `]` to move between **tabs** within a hub; `g` then letter to jump
      hubs (gmail-style) for power users.
- [ ] **H3 (P1,S)** ARIA: rail = `nav`, tabs = `role=tablist/tab`, launcher = `dialog`; ensure
      focus moves into the content region on route change and the active tab is announced.
- [ ] **H4 (P1,S)** Visible focus rings + keyboard reachability for the new omni-bar, launcher
      grid, persona switcher, and pin stars.

---

## 5. Files touched (all in `web/console/`)
- `assets/app.js` — `ROUTES` (+`hub` field), new `HUBS` map, `buildNav()`, sub-nav strip,
  `go`/`routeFromHash`, palette upgrades, keyboard re-map, pins/recents/persona state.
- `assets/ui.js` — launcher modal, tab strip, breadcrumb, persona switcher, pin star, badges.
- `assets/views.js` — Home (Mission Control) rebuild; entity-drill affordances.
- `assets/app.css` — rail (collapsed/expanded), tab strip, omni-bar, app-grid, badges, motion.
- `index.html` — omni-bar markup in topbar, Tools button, persona switcher slot.

No new routes are removed; `search` stays hidden; deep-links (`#f/<id>`) unchanged.

---

## 6. Suggested sprints
1. **Sprint 1 — "Stop the link farm" (P0):** A1–A4, B1–B2, C1, D1, H1.
   → After this the rail is 6 hubs, ⌘K is the hero, tools are a launcher, Home navigates.
2. **Sprint 2 — "Feels premium" (P1):** A5, B3–B4, C2–C3, D2–D3, E1–E3, F1–F2, H2–H4.
3. **Sprint 3 — "Delight" (P2):** B5, E4, F3, G1–G4.

**Definition of done (Sprint 1+2):** ≤7 primary rail items; every old screen reachable via
hub tabs, ⌘K, or the Tools launcher; Home tiles are clickable entry points; pins + recents +
persona lens work; breadcrumbs + entity drilling give a sense of flow; keyboard model updated.
