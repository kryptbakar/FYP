// Does the Command Deck wall board fit on ONE screen, at every size an
// operations display might be?
//
//   docker run --rm --add-host=host.docker.internal:host-gateway \
//     -e NODE_PATH=/usr/src/app/node_modules -v "$PWD:/work" -w /work \
//     zenika/alpine-chrome:with-puppeteer node wall-fit.js
//
// Exits non-zero if any size scrolls or clips, so it can gate a change.
//
// WHY IT CHECKS DESCENDANTS AND NOT JUST PANELS. The first version asserted
// only that each panel had no overflow of its own. It passed while the sensor
// grid displayed 2 of 5 tools, because the clipping happened inside a child
// with overflow:hidden - the panel was honestly reporting no overflow while
// silently dropping content. It now walks every descendant, AND compares what
// a caption claims against what actually renders: "5 tools" printed above two
// visible tiles is a contradiction no geometry assertion would have caught.
//
// Two deliberate exemptions, both documented at the point of use: the live feed
// is a stream (it is SUPPOSED to hold more rows than fit), and a
// -webkit-line-clamp element always reports scrollHeight > clientHeight because
// that is how clamping works - and it shows an ellipsis, so the reader knows.
const puppeteer = require('puppeteer-core');
const BASE = process.env.BASE || 'http://host.docker.internal:3001';
const SIZES = [[1920, 1080], [1600, 900], [2560, 1440], [1366, 768]];

(async () => {
  const b = await puppeteer.launch({ executablePath: '/usr/bin/chromium-browser', args: ['--no-sandbox', '--disable-dev-shm-usage'] });
  const p = await b.newPage();
  const errs = [];
  p.on('pageerror', e => errs.push('pageerror: ' + e.message));

  await p.setViewport({ width: SIZES[0][0], height: SIZES[0][1] });
  await p.goto(BASE, { waitUntil: 'domcontentloaded', timeout: 60000 });
  const gated = await p.evaluate(() => { const l = document.querySelector('#login'); return !!(l && !l.hidden); });
  if (gated) {
    await p.type('#login-user', 'admin').catch(() => {});
    await p.type('#login-pass', 'vyrex');
    await p.evaluate(() => document.querySelector('#login-form').dispatchEvent(new Event('submit', { cancelable: true, bubbles: true })));
    await p.waitForFunction(() => { const l = document.querySelector('#login'); return !l || l.hidden; }, { timeout: 60000 });
  }
  await p.waitForFunction(() => { const v = document.querySelector('#vault'); return !v || v.hidden; }, { timeout: 90000 }).catch(() => {});
  await p.evaluate(() => { location.hash = 'command'; });
  await new Promise(r => setTimeout(r, 8000));
  await p.evaluate(() => toggleWallMode());
  await new Promise(r => setTimeout(r, 1200));

  let bad = 0;
  for (const [w, hgt] of SIZES) {
    await p.setViewport({ width: w, height: hgt });
    await new Promise(r => setTimeout(r, 1500));
    const m = await p.evaluate(() => {
      const sc = document.querySelector('.scroll');
      const bd = document.querySelector('.dk-board');
      const vis = (e) => e.getClientRects().length > 0 && getComputedStyle(e).display !== 'none';

      // Panel-level overflow is NOT enough: a panel whose child has
      // overflow:hidden reports no overflow of its own while silently dropping
      // content (the sensor grid showed 2 of 5 tools and this check passed).
      // So walk every descendant of every visible panel.
      const clipped = [];
      for (const panel of document.querySelectorAll('.dk-board > .dk-card')) {
        if (!vis(panel)) continue;
        const key = panel.getAttribute('data-dk') || '?';
        // The live feed is a STREAM: it deliberately holds more rows than fit and
        // the oldest fall below the fold. That is not clipping of content the panel
        // claims to show, so it is the one documented exclusion here.
        for (const e of [panel, ...panel.querySelectorAll('*')]) {
          if (e.classList && e.classList.contains('dk-feed-list')) continue;
          // Deliberate truncation is not clipping: a -webkit-line-clamp element
          // always reports scrollHeight > clientHeight, and it shows an ellipsis
          // so the reader knows there is more. Same for single-line ellipsis.
          const cs = getComputedStyle(e);
          if (cs.webkitLineClamp !== 'none' || cs.textOverflow === 'ellipsis') continue;
          if (e.scrollHeight > e.clientHeight + 2 && e.clientHeight > 0) {
            const cls = (e.className && e.className.baseVal !== undefined) ? e.className.baseVal : String(e.className || e.tagName);
            clipped.push(`${key}:${cls.split(' ')[0]}(${e.scrollHeight}>${e.clientHeight})`);
            break; // one report per panel is enough to fail it
          }
        }
      }
      // Content-completeness assertions: counts the caption CLAIMS vs what renders.
      const sensorCap = (document.querySelector('[data-dk="sensors"] .dk-sub') || {}).textContent || '';
      const sensorClaim = parseInt(sensorCap, 10) || 0;
      const sensorShown = [...document.querySelectorAll('[data-dk="sensors"] .dk-sensor')]
        .filter(e => e.getBoundingClientRect().bottom
          <= document.querySelector('[data-dk="sensors"]').getBoundingClientRect().bottom + 2).length;
      return {
        docScroll: document.documentElement.scrollHeight - document.documentElement.clientHeight,
        scrollerOverflow: sc.scrollHeight - sc.clientHeight,
        bodyOverflowX: document.body.scrollWidth - document.body.clientWidth,
        boardBottom: Math.round(bd.getBoundingClientRect().bottom),
        viewportH: window.innerHeight,
        visiblePanels: [...document.querySelectorAll('.dk-board > .dk-card')].filter(vis).length,
        sensors: `${sensorShown}/${sensorClaim}`,
        feedRowsVisible: [...document.querySelectorAll('.dk-feed-row')]
          .filter(e => e.getBoundingClientRect().bottom
            <= document.querySelector('[data-dk="feed"]').getBoundingClientRect().bottom + 2).length,
        clipped,
      };
    });
    const fits = m.scrollerOverflow <= 1 && m.docScroll <= 1 && m.bodyOverflowX <= 1
                 && m.boardBottom <= m.viewportH + 2 && m.clipped.length === 0
                 && m.sensors.split('/')[0] === m.sensors.split('/')[1];
    if (!fits) bad++;
    console.log(`${String(w + 'x' + hgt).padEnd(10)} ${fits ? 'PASS' : '*** FAIL ***'}  ` + JSON.stringify(m));
    await p.screenshot({ path: `/out/fit-${w}x${hgt}.png` });
  }
  console.log(errs.length ? 'ERRORS: ' + [...new Set(errs)].join(' | ') : 'no page errors');
  console.log(bad ? `${bad} size(s) failed` : 'all sizes fit on one screen, nothing clipped');
  await b.close();
  process.exit(bad ? 1 : 0);
})().catch(e => { console.error('FAILED:', e.message); process.exit(1); });
