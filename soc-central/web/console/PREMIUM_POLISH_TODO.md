# VYREX Console — Premium Polish TODO

> **Audit-only deliverable.** Senior product-design + frontend review of the VYREX analyst
> console, grounded in the actual source (`web/console/`). Diagnoses where it reads as
> "vibe-coded / just shows data" vs. "premium international tool," then a prioritized,
> checkable plan. **Nothing here is implemented yet** — review and reprioritise first.
>
> Inspected (2026-06-17): `index.html` (94 ln), `assets/app.css` (701 ln), `views.js`
> (1757 ln), `ui.js`, `app.js`, `api.js`, `fixtures.js`, `story.js`, `toolkit.js`. Stack
> confirmed: dependency-free vanilla SPA, hash router (`ROUTES` in `app.js`, `go()` swaps
> `#view` innerHTML), styles centralised in `app.css`, design tokens exist in `:root`
> (`app.css:19–56`). No build step, no npm, no CDN — all constraints intact.

---

## 🏆 Biggest wins (the 5 that move the needle most)

1. **Add a spacing scale and enforce it.** There are **zero spacing tokens** and ~22 distinct
   raw px gaps/paddings including off-scale `5/7/9/11/13/14/15px`. One `--s-*` ramp + a sweep is
   the single biggest "premium vs. ad hoc" lever.
2. **Collapse the type scale.** **34 distinct hardcoded `font-size` px** values incl. half-pixels
   (`9.5/10.5/11.5/12.5/13.5px`) — the textbook vibe-coded tell. Tokenise to ~7 steps and purge.
3. **One motion system.** Today: **7 durations** (`.12/.14/.15/.2/.3/.35/.4s`) + **3 curves**
   (`ease` + two different `cubic-bezier`s). Define one easing + 3 durations; apply everywhere.
4. **Skeletons instead of spinners on the 4 hero screens.** `loading()` is a centred spinner used
   **31×**; **0 skeletons** exist. Skeletons remove the "blank → pop" layout shift that reads cheap.
5. **Reconcile the neutral ramp + the "flat" claim.** Cool blue-grays (`#1c2024`, `#181b1f`,
   `#3a3f44`) leak into a warm wine-black palette, and the file header still says "no
   shadows/glows" while a wine **glow** + two mismatched drop-shadows now exist.

---

## Audit scorecard (verdict + evidence)

| # | Dimension | Verdict | Key evidence (file:line / counts) |
|---|---|---|---|
| 1 | Spacing/sizing scale | **Weak** | `app.css` defines radii + 5 font tokens but **no spacing tokens** (`grep --s = 0`). 22 distinct raw px spacings; off-scale `5px×11, 7px×11, 9px×17, 11px×11, 13px, 14px×18, 15px×5`. |
| 2 | Typographic hierarchy | **Weak** | 34 distinct `font-size` px; half-pixels `10.5×30, 11.5×16, 12.5×21, 9.5×9, 13.5×1`. Display sizes `24/26/28/38/40px` untokenised. Weights `400/500/520/560/600` but `@font-face` declares only `font-weight: 400 500` (`app.css:12–17`) → `560/600` clamp/faux-bold **if** woff2 are ever added (today `assets/fonts/` has only README → system stack). 9 distinct `line-height`s, no tokens. |
| 3 | Density & alignment | **OK-ish** | Tables now have sticky header + zebra + 44px rows (good). But **371 inline `style:`** in `views.js` drive per-element ad-hoc px → column/baseline alignment is incidental, not enforced. |
| 4 | Empty / loading / error | **Partial** | 8 `.empty` states with *decent specific copy* (e.g. "No results collected yet — agents return rows as they poll."), but undesigned (bare text, no icon/CTA). **0 skeletons.** Errors **swallowed**: `catch {}` at `views.js:78,84,600,969`; worse, `API._get` falls back to demo fixtures on failure (`api.js`) so a real outage **silently shows demo data** — there is effectively **no error state**. |
| 5 | Motion discipline | **Weak** | 7 durations + 3 curves (above). Two cubic-beziers: `(.4,0,.2,1)` and `(.2,.7,.2,1)`. Focus ring exists globally (`:focus-visible`, `app.css:68`) — good — but off-token `border-radius:3px`. |
| 6 | Colour as system | **Strong base, leaks** | Excellent tinted token ramp + single accent + muted semantics; **no** `#FF0000/#00FF00` misuse. But off-ramp **cool grays**: `#1c2024` (scrollbar `:70`), `#181b1f` (`.btn:hover :165`, `.iconbtn:hover :489`), `#3a3f44` (`.rbar/.rlegend .info :366,:370`); plus `#fff` (`.nbadge :491`), `#1d161b/#181419` (`.attcell :539`) untokenised — contradicting the `:root`-only claim in the header comment. |
| 7 | Surfaces / depth | **Mostly good** | Clean 3-level ramp (`--bg/--surface/--elevated`) + 1px `--line`. But the header comment says **"flat (no gradients/glows/shadows)"** (`app.css:4`) while shadows now exist: `.cmdk-card 0 24px 60px/.5` (`:472`), `.story-cap 0 24px 70px/.6` (`:633`) — **two different elevations**, and `.story-spot` has a wine **glow** `0 0 26px rgba(168,42,71,.35)` (`:627`) which violates "no glows." Either update the doctrine or tokenise to one elevation. |
| 8 | Keyboard-first | **Good, one gap** | `j/k/Enter/Esc`, `/`, `1–9`, `⌘K` all wired (`app.js:87–105`). **No `?` shortcuts overlay** — shortcuts are undiscoverable. Focus order relies on DOM order (acceptable). |
| 9 | Perceived performance | **Weak** | Spinner-gaps (31× `loading()`), no skeletons, no optimistic UI. The finding drawer loads async blocks (attribution graph) **after** first paint → visible layout shift (the very cause of the storyline gate-scroll bug). |
| 10 | Neglected screens | **Partial** | Login is reasonably polished (wine-glow), but uses the same ad-hoc styling. **No 404/unknown-route state**: `routeFromHash` (`app.js:154`) sends unknown hashes to `overview` on load and **no-ops** otherwise. Settings is functional but plain. |
| 11 | Iconography | **Minor inconsistency** | `ic()` strokes at `1.6`, but inline SVGs use `1.7` (search/bell/brand) and one at `2` → 3 stroke widths (`stroke-width 1.6×3, 1.7×4, 2×1`). Sizes mostly 14–17px, not on a strict icon grid. |

**Hero-screen close reads:**
- **Overview** (`views.js:519`): KPIs/risk-band good; spinner load, live ticker via `setInterval` (`:600`, errors `catch {}`-swallowed). No zero-data variant.
- **Finding detail drawer** (`views.js:132`): information-rich and genuinely strong, but the densest pile of inline styles and async-load layout shift; no skeleton; gate sits below late-loading blocks.
- **Fusion / consensus** (`views.js:469`): clean; the new `.consensus-reveal` is the most "designed" component in the app — a good template to standardise the rest toward.
- **Trust Center** (`views.js:655`): strong narrative; egress matrix + integrity cards read premium already.

---

## Phase 1 — Design-token audit & enforcement *(foundational; do first)*

- [ ] **Add a spacing scale `--s-1..--s-8` (4/8/12/16/24/32/48/64) and migrate `app.css`.** Replace raw `gap/padding/margin` px with tokens; snap off-scale `5/7/9/11/13/15px` to the nearest step (and decide 14→12 or 16 deliberately). *Files: `app.css` (+ a follow-up pass on `views.js` inline styles).* · Dim 1 · **L** · **High**
- [ ] **Collapse `font-size` to ~7 tokens and purge half-pixels.** Extend `:root` to a full step set (e.g. `--t-2xs 11 / --t-xs 12 / --t-sm 13 / --t-md 15 / --t-lg 18 / --t-xl 22 / --t-display 30`), kill `9.5/10.5/11.5/12.5/13.5` and one-off `24/26/28/38/40`. *Files: `app.css`, then `views.js`.* · Dim 2 · **L** · **High**
- [ ] **Define line-height + letter-spacing tokens** (`--lh-tight 1.2 / --lh-base 1.5 / --lh-relaxed 1.6`; `--ls-tide .3px / --ls-caps .5px`) and replace the 9 ad-hoc line-heights. *Files: `app.css`.* · Dim 2 · **M** · **Med**
- [ ] **Move the off-ramp hexes into tokens and re-tint them warm.** `#1c2024`→`--scroll-thumb`, `#181b1f`→`--hover-strong`, `#3a3f44`→a wine-tinted `--neutral-3`, `#1d161b/#181419`→`--elevated-2/3`, `#fff`→`--on-critical`. Re-tint the cool grays to match the wine-black ramp. *Files: `app.css:70,165,366,370,489,491,539`.* · Dim 6 · **S** · **High**
- [ ] **Tokenise radii stragglers.** Replace raw `2px/3px/5px/6px/10px` and the `:focus-visible` `3px` with `--r-*`. *Files: `app.css`.* · Dim 1 · **S** · **Med**
- [ ] **Verify the font-weight ladder against the actual font.** Either ship the Inter/IBM Plex woff2 with full weights, or cap requested weights to what the stack provides (avoid `520/560` micro-steps; standardise on `400/500/600`). Decide one heading weight. ⚠️ *Adding woff2 is fine (self-hosted, air-gap-safe) — do NOT fetch from a CDN.* *Files: `app.css:12–17`, `assets/fonts/`.* · Dim 2 · **M** · **Med**
- [ ] **Reconcile the "flat" doctrine.** Either (a) keep flat and remove the drop-shadows/glow, or (b) define exactly one elevation token `--shadow-pop` for truly-floating layers (palette, caption, drawer) and delete the wine glow. Update the `app.css` header comment to match reality. *Files: `app.css:4,472,627,633`.* · Dim 6,7 · **S** · **Med**

## Phase 2 — Empty / loading / error states for hero screens

- [ ] **Build a skeleton primitive** (`skeleton(rows)` shimmer using existing tokens) and use it on Overview, finding drawer, Fusion, Trust in place of `loading()`. Removes blank→pop. *Files: `ui.js` (new `skeleton()`), `app.css`, `views.js` hero loaders.* · Dim 4,9 · **M** · **High**
- [ ] **Add a real error state + stop masking outages as demo data.** Surface a calm, specific "can't reach /api — showing last-known/demo" banner instead of silently swapping to fixtures; replace bare `catch {}` with a typed error slot. ⚠️ *Keep the offline fixture fallback (it's a feature) — just make the demo/offline state visible, never silent.* *Files: `api.js` `_get`, `ui.js`, hero views.* · Dim 4 · **M** · **High**
- [ ] **Design the empty state component** (`emptyState(icon, title, hint, cta?)`) — replace the 8 bare `.empty` strings with an iconed, optionally-actionable block. Keep the good copy. *Files: `ui.js`, `app.css`, `views.js`.* · Dim 4 · **S** · **Med**
- [ ] **Add zero-data variants for Overview & finding drawer** (no findings / finding resolved) so first-run/clean states don't look broken. *Files: `views.js:519,132`.* · Dim 4,10 · **S** · **Med**
- [ ] **Stabilise the finding-drawer load** (reserve space for async blocks / render them in final order) to kill the post-paint layout shift. *Files: `views.js:132–229`.* · Dim 9 · **M** · **Med**

## Phase 3 — Motion & interaction discipline + keyboard-first

- [ ] **One motion system.** Define `--ease: cubic-bezier(.2,.7,.2,1)` + `--dur-fast 120ms / --dur 180ms / --dur-slow 320ms`; replace all 7 durations + 3 curves. *Files: `app.css`, `story.js`.* · Dim 5 · **M** · **High**
- [ ] **Audit hover/active/focus on every interactive element** (rows, chips, cards, kanban cards, sensor tiles) — ensure all three states + a consistent focus ring; remove the off-token focus radius. *Files: `app.css`.* · Dim 5,8 · **M** · **Med**
- [ ] **Add a `?` shortcuts overlay** listing j/k, /, 1–9, ⌘K, Esc — makes the keyboard model discoverable (a hallmark of Linear/Splunk-grade tools). *Files: `app.js`, `ui.js`, `app.css`, `index.html`.* · Dim 8 · **S** · **High**
- [ ] **Unify iconography to one stroke width (1.6) and a 16px grid;** convert the inline `1.7/2` SVGs (search, bell, brand) to the `ic()` set or match its stroke. *Files: `index.html`, `views.js`, `ui.js`.* · Dim 11 · **S** · **Med**
- [ ] **Optimistic UI on triage/lifecycle actions** (update the row immediately, reconcile on response) so the queue feels instant. *Files: `views.js` triage/lifecycle, `api.js`.* · Dim 9 · **M** · **Med**

## Phase 4 — First-impression screens (login, Overview, 404, settings)

- [ ] **Add a designed 404 / unknown-route view** instead of the silent redirect/no-op. *Files: `app.js:139–154`, `views.js`.* · Dim 10 · **S** · **Med**
- [ ] **Polish login to the token system** (spacing/type tokens, focus states, error affordance on bad credentials, caps-lock hint). *Files: `index.html` login block, `app.css`.* · Dim 10 · **S** · **Med**
- [ ] **Overview first-impression pass** — align KPI baselines, tighten the "Run guided demo" row spacing to tokens, ensure the live-ticker has a calm idle state. *Files: `views.js:519`, `app.css`.* · Dim 3,10 · **S** · **Med**
- [ ] **Settings screen pass** — group into titled sections with consistent row rhythm; it currently reads as a plain list. *Files: `views.js` settings.* · Dim 10 · **S** · **Low**

## Phase 5 — Long-tail consistency across remaining screens

- [ ] **Retire inline styles into semantic classes.** Sweep the **371** `style:` literals in `views.js` into utility/component classes once tokens land — the durable fix that keeps the system enforced. *Files: `views.js`, `app.css`.* · Dim 1,2,3 · **L** · **High (long-term)**
- [ ] **Standardise every screen toward the `.consensus-reveal` / Trust quality bar** (section labels, spacing rhythm, panel headers) — Hunt, Detections, Alerting, Playbooks, Reports, Coverage, Live Hunt, Toolkit. *Files: `views.js`.* · Dim 3 · **L** · **Med**
- [ ] **Table polish pass** — consistent column alignment (numeric right + mono), truncation/tooltip rules, consistent row affordances across all `.tbl` instances. *Files: `views.js`, `app.css`.* · Dim 3 · **M** · **Med**
- [ ] **Toolkit visual consistency** (Node Vitals gauges, Phishing score meter, chat bubbles) onto the shared tokens once Phase 1 lands. *Files: `toolkit.js`-driven views in `views.js`, `app.css`.* · Dim 1,6 · **M** · **Low**

---

## NON-GOALS / do NOT do

- ❌ **No framework / npm / build step / CDN / external fetch** — every item above is plain JS/CSS, self-hosted. (Adding self-hosted woff2 is allowed; fetching a font/icon set is not.)
- ❌ **Do not redesign the black + wine-red aesthetic** — refine within it. No re-theming, no new accent.
- ❌ **No new gradients, glows, or decorative effects.** Premium here = restraint. (If anything, *remove* the wine glow on the spotlight; don't add more.)
- ❌ **Do not swap severity to colour-only.** Keep shape+label encoding (WCAG) — it's a strength.
- ❌ **Do not remove the offline fixture fallback** — just make the offline/demo state *visible* instead of silent.
- ❌ **No emoji/icon-font dependencies**; keep the inline-SVG `ic()` set.
- ❌ **Don't chase pixel-perfect at the cost of density** — analysts want dense, aligned data, not whitespace.

---

### Suggested sequencing
Phase 1 is the unlock — most other phases get easier once tokens exist and inline styles can be
swept. Recommended order: **1 → 2 → 3 → 4 → 5**, but within Phase 1, do *spacing tokens* and the
*off-ramp hex re-tint* first (highest impact-per-effort). Re-audit after Phase 1 to confirm the
ad-hoc-value counts dropped before starting the inline-style sweep.
