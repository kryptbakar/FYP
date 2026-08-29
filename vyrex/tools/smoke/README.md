# Console route smoke test

Loads the console in a real browser, signs in, visits every route, and reports any that
threw a JS error or rendered nothing.

**Why it exists.** `ui.js` and `views.js` are shared by all thirty-odd views, so a mistake
in one helper can blank an unrelated screen with no error anywhere — the console just shows
an empty panel. `node --check` and the contract tests in `web/console/tests/` catch syntax
and API-contract bugs; neither catches "this view renders nothing now".

**Not wired into CI, deliberately.** It needs a running stack *and* a browser. The
`js-check` job runs `web/console/tests/*.test.js` with plain node and no server, so a
puppeteer test dropped into that glob would fail for reasons that have nothing to do with
the code. Run this by hand after touching console assets.

## Run it

```bash
# stack must be up: docker compose up -d console api
docker run --rm --add-host=host.docker.internal:host-gateway \
  -e NODE_PATH=/usr/src/app/node_modules \
  -e ROUTES="overview triage cases assets compliance fusion investigations agent automation defense model dashboards settings" \
  -v "$PWD/tools/smoke:/s" -w /usr/src/app \
  zenika/alpine-chrome:with-puppeteer node /s/console-routes.js
```

Exit 0 = every route rendered. Exit 1 = at least one threw or came back empty.

## Three traps this harness hit, so you do not have to

Each of these made it report something confidently wrong, which is worse than not running:

1. **`window.ROUTES` does not exist** — it is a module-scope `const` in `app.js`, and the
   nav uses `data-hub` click handlers rather than `href="#..."`. Both discovery attempts
   found *zero* routes and the whole check passed vacuously. The route list is therefore
   passed in via `$ROUTES`; the script exits 1 if it is empty rather than "passing".
2. **A fixed dwell is not enough** — `fusion` awaits an extra `/explain` call and settles at
   about 4 s. At 1400 ms it was reported broken when it was merely slow.
3. **Waiting for "no skeleton + stable text" measures the PREVIOUS view** — at navigation
   time the old content is still mounted, has no skeleton, and is perfectly stable, so the
   condition passes instantly and every row comes out one route late. `compliance` inherited
   `fusion`'s numbers, which looked exactly like a regression. The fix is to tag the current
   `#view`, then wait for that tag to disappear: detachment is the unambiguous signal.

`portscan` and the other Toolkit routes are left out of the default list on purpose — they
do real work (an actual TCP scan) and block the run.
