// Capture the thesis / demo figure set from the running console.
//
// Screenshots taken by hand drift: different window sizes, a stale build, a half-loaded
// panel, a cursor in shot. Every figure here is captured at a fixed viewport and a 2x
// device scale factor from whatever the console is actually serving, so a figure in the
// write-up can always be regenerated from the commit it was taken at.
//
// Element shots (the graphs) are preferred over full-page where the panel is the subject:
// a cropped 1200x500 SVG reproduces in print far better than a downscaled 1500x2000 page.
//
// Usage (stack up):
//   docker run --rm --add-host=host.docker.internal:host-gateway \
//     -e NODE_PATH=/usr/src/app/node_modules \
//     -v "$PWD/tools/figures:/s" -v "$PWD/dist/figures:/out" -w /usr/src/app \
//     zenika/alpine-chrome:with-puppeteer node /s/capture.js
const puppeteer = require('puppeteer-core');

const BASE = process.env.BASE || 'http://host.docker.internal:3001';
const OUT = process.env.OUT || '/out';

// route, filename, optional element selector, optional settle-extra-ms
const FIGURES = [
  ['overview',       '01-overview',            null,             1200],
  ['overview',       '02-live-pipeline',       '.sf-panel',      1200],
  ['triage',         '03-triage-queue',        null,             800],
  ['investigations', '04-investigations',      null,             2500],
  ['investigations', '05-execution-graph',     '.ing-wrap',      2500],
  ['fusion',         '06-sensors-and-fusion',  null,             3000],
  ['compliance',     '07-compliance',          null,             1500],
  ['cases',          '08-cases',               null,             800],
  ['defense',        '09-autonomous-defense',  null,             1200],
  ['model',          '10-model-card',          null,             800],
];

(async () => {
  const browser = await puppeteer.launch({
    executablePath: '/usr/bin/chromium-browser',
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });
  const page = await browser.newPage();
  // 2x for print. The console is a fluid layout, so the viewport width decides how many
  // bento columns appear — 1600 is the widest that still reads as a laptop screenshot.
  await page.setViewport({ width: 1600, height: 1000, deviceScaleFactor: 2 });

  const errs = [];
  page.on('pageerror', e => errs.push(e.message));

  await page.goto(BASE, { waitUntil: 'domcontentloaded', timeout: 60000 });
  const gated = await page.evaluate(() => {
    const l = document.querySelector('#login'); return !!(l && !l.hidden);
  });
  if (gated) {
    await page.type('#login-user', 'admin').catch(() => {});
    await page.type('#login-pass', 'vyrex');
    await page.evaluate(() => document.querySelector('#login-form')
      .dispatchEvent(new Event('submit', { cancelable: true, bubbles: true })));
    await page.waitForFunction(() => { const l = document.querySelector('#login'); return !l || l.hidden; },
      { timeout: 60000 });
  }
  // The cinematic vault overlay sits ABOVE the booted app for 10-20s. Skipping this wait
  // produces ten identical screenshots of the vault, which is how the first run went.
  await page.waitForFunction(() => { const v = document.querySelector('#vault'); return !v || v.hidden; },
    { timeout: 90000 }).catch(() => console.log('  (vault never hid — figures may be covered)'));

  let ok = 0, skipped = 0;
  for (const [route, name, selector, extra] of FIGURES) {
    // Tag the current view and wait for it to detach, so a slow route is never captured
    // showing the PREVIOUS one — the same trap the route smoke test hit.
    await page.evaluate(() => {
      const v = document.querySelector('#view'); if (v) v.setAttribute('data-fig-stale', '1');
    });
    await page.evaluate(r => { location.hash = r; }, route);
    await page.waitForFunction(() => {
      const v = document.querySelector('#view');
      if (!v || v.hasAttribute('data-fig-stale')) return false;
      if (v.querySelectorAll('[class*="sk"]').length) return false;
      return v.innerText.trim().length > 0;
    }, { timeout: 20000, polling: 300 }).catch(() => {});
    await new Promise(r => setTimeout(r, extra || 800));

    const path = `${OUT}/${name}.png`;
    if (selector) {
      const el = await page.$(selector);
      if (!el) { console.log(`  SKIP ${name} (no ${selector} on #${route})`); skipped++; continue; }
      await el.evaluate(e => e.scrollIntoView({ block: 'center' }));
      await new Promise(r => setTimeout(r, 600));
      await el.screenshot({ path });
    } else {
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({ path });
    }
    const dims = await page.evaluate(s => {
      const t = s ? document.querySelector(s) : document.body;
      if (!t) return '?';
      const b = t.getBoundingClientRect();
      return `${Math.round(b.width)}x${Math.round(b.height)}`;
    }, selector);
    console.log(`  ok   ${name.padEnd(26)} #${route.padEnd(16)} ${dims}`);
    ok++;
  }

  console.log(`\n${ok} figure(s) written to ${OUT}${skipped ? `, ${skipped} skipped` : ''}`);
  if (errs.length) console.log('PAGE ERRORS:\n  ' + [...new Set(errs)].slice(0, 5).join('\n  '));
  await browser.close();
  process.exit(skipped ? 1 : 0);
})().catch(e => { console.error('FAILED:', e.message); process.exit(1); });
