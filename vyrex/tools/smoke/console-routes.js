// Visit every route and report JS errors + whether the view rendered anything.
// Regression net for console edits: ui.js/views.js are shared by all views, so a
// mistake in one helper can blank an unrelated screen silently.
const puppeteer = require('puppeteer-core');
const BASE = process.env.BASE || 'http://host.docker.internal:3001';

(async () => {
  const browser = await puppeteer.launch({
    executablePath: '/usr/bin/chromium-browser',
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1500, height: 950 });

  const errs = [];
  page.on('pageerror', e => errs.push(e.message));
  page.on('console', m => { if (m.type() === 'error' && !/404/.test(m.text())) errs.push(m.text()); });

  await page.goto(BASE, { waitUntil: 'domcontentloaded', timeout: 60000 });
  const gated = await page.evaluate(() => { const l = document.querySelector('#login'); return !!(l && !l.hidden); });
  if (gated) {
    await page.type('#login-user', 'admin').catch(() => {});
    await page.type('#login-pass', 'vyrex');
    await page.evaluate(() => document.querySelector('#login-form')
      .dispatchEvent(new Event('submit', { cancelable: true, bubbles: true })));
    await page.waitForFunction(() => { const l = document.querySelector('#login'); return !l || l.hidden; }, { timeout: 60000 });
  }
  await page.waitForFunction(() => { const v = document.querySelector('#vault'); return !v || v.hidden; },
    { timeout: 90000 }).catch(() => {});

  // ROUTES is a module-scope const and the nav uses data-hub click handlers, not hrefs,
  // so neither window.ROUTES nor a[href^='#'] finds anything - the first two attempts
  // both "passed" against zero routes. The list is injected from the build instead.
  const routes = (process.env.ROUTES || '').split(' ').filter(Boolean);
  if (!routes.length) { console.error('FAILED: no routes supplied'); process.exit(1); }
  console.log('routes discovered:', routes.length);
  if (!routes.length) { console.error('FAILED: discovered no routes — the check would pass vacuously'); process.exit(1); }

  const rows = [];
  for (const r of routes) {
    const before = errs.length;
    // Tag the CURRENT view content, then wait for that tag to disappear. Waiting only for
    // "no skeleton + stable text" was satisfied instantly by the PREVIOUS route's content,
    // which is still mounted at navigation time - so every row was reported one route late
    // and compliance inherited usion's numbers. Detachment is the unambiguous signal.
    await page.evaluate(() => {
      const v = document.querySelector('#view');
      if (v) v.setAttribute('data-rc-stale', '1');
    });
    await page.evaluate(rr => { location.hash = rr; }, r);
    await page.waitForFunction(() => {
      const v = document.querySelector('#view');
      if (!v || v.hasAttribute('data-rc-stale')) return false;      // not replaced yet
      if (v.querySelectorAll('[class*="sk"]').length) return false;  // still skeleton
      return v.innerText.trim().length > 0;
    }, { timeout: 15000, polling: 300 }).catch(() => {});
    await new Promise(t => setTimeout(t, 400));
    const info = await page.evaluate(() => {
      const v = document.querySelector('#view');
      return { chars: v ? v.innerText.trim().length : -1, nodes: v ? v.querySelectorAll('*').length : -1 };
    });
    rows.push({ route: r, ...info, newErrors: errs.length - before });
  }

  const bad = rows.filter(x => x.newErrors > 0 || x.chars < 20);
  rows.forEach(x => console.log(
    `  ${x.newErrors > 0 ? 'ERR ' : x.chars < 20 ? 'THIN' : 'ok  '} ${x.route.padEnd(22)} ${String(x.nodes).padStart(5)} nodes  ${String(x.chars).padStart(6)} chars`));
  console.log(bad.length ? `\n${bad.length} route(s) need attention` : '\nall routes rendered clean');
  if (errs.length) console.log('\nERRORS:\n  ' + [...new Set(errs)].slice(0, 10).join('\n  '));
  await browser.close();
  process.exit(bad.length ? 1 : 0);
})().catch(e => { console.error('FAILED:', e.message); process.exit(1); });
