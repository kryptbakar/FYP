/* =====================================================================
   Contract test for API._write — the console's mutation path.

   Guards a specific regression: writes used to fall back to embedded
   fixtures on failure and return them as if the call had succeeded, so a
   failed "escalate" or "dispatch alerts" rendered a green success toast
   while nothing had happened. Worse, a single failed READ flipped
   API.mode to 'demo', after which every subsequent write short-circuited
   to a fixture WITHOUT EVEN ATTEMPTING the request.

   Reads may still fall back to fixtures (that is what keeps the console
   renderable offline) — writes may not.

   Dependency-free, like the rest of the console. Run:
     node web/console/tests/api-write.test.js
   ===================================================================== */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const API_JS = path.join(__dirname, '..', 'assets', 'api.js');
const src = fs.readFileSync(API_JS, 'utf8');

function makeCtx(fetchImpl) {
  const ctx = {
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    FIX: {},
    fetch: fetchImpl,
    console,
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  // `const API = {...}` is a lexical binding, not a property of the context
  // object. Without this export line ctx.API is undefined and every "throws"
  // assertion below would pass on a TypeError rather than the real behaviour.
  vm.runInContext(src + '\n;globalThis.API = API;', ctx);
  if (!ctx.API) throw new Error('harness broken: API not exported from api.js');
  return ctx;
}

let pass = 0, fail = 0;
const check = (name, ok, detail) => {
  if (ok) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? ' — ' + detail : ''}`); }
};

(async () => {
  const SIM = { simulated: true, sentinel: 'FIXTURE' };

  // Assert on the message, not just "it threw": a bare throw-check is also
  // satisfied by a TypeError from a broken harness.
  {
    const ctx = makeCtx(async () => { throw new TypeError('Failed to fetch'); });
    let err = null, returned;
    try { returned = await ctx.API._write('POST', '/alerts/dispatch', {}, SIM); }
    catch (e) { err = e; }
    check('network failure throws (does not return fixture)',
      err && /unreachable/.test(err.message) && /\/alerts\/dispatch/.test(err.message),
      err ? `message was "${err.message}"` : `returned ${JSON.stringify(returned)}`);
  }

  {
    const ctx = makeCtx(async () => ({ ok: false, status: 500, json: async () => ({}) }));
    let err = null, returned;
    try { returned = await ctx.API._write('POST', '/reports', {}, SIM); }
    catch (e) { err = e; }
    check('HTTP 500 throws (does not return fixture)',
      err && /HTTP 500/.test(err.message) && /\/reports/.test(err.message),
      err ? `message was "${err.message}"` : `returned ${JSON.stringify(returned)}`);
  }

  // A refused-but-answered request means the server IS reachable — the
  // LIVE/DEMO badge must not lie about that.
  {
    const ctx = makeCtx(async () => ({ ok: false, status: 403, json: async () => ({}) }));
    try { await ctx.API._write('POST', '/actions/1/approve', {}, SIM); } catch {}
    check("HTTP 403 keeps mode 'live' (server answered)",
      ctx.API.mode === 'live', `mode=${ctx.API.mode}`);
  }

  {
    const ctx = makeCtx(async () => { throw new TypeError('Failed to fetch'); });
    try { await ctx.API._write('POST', '/x', {}, SIM); } catch {}
    check("unreachable server sets mode 'demo'",
      ctx.API.mode === 'demo', `mode=${ctx.API.mode}`);
  }

  // THE REGRESSION.
  {
    let attempted = false;
    const ctx = makeCtx(async () => {
      attempted = true;
      return { ok: true, status: 200, json: async () => ({ real: true }) };
    });
    ctx.API.mode = 'demo';                       // simulate a prior failed read
    const r = await ctx.API._write('POST', '/findings/1/triage', { status: 'escalated' }, SIM);
    check('demo mode still attempts the write', attempted);
    check('demo mode returns the REAL response, not the fixture',
      r && r.real === true, `got ${JSON.stringify(r)}`);
  }

  // Storyline Mode is deterministic by design and keeps its fixtures.
  {
    let attempted = false;
    const ctx = makeCtx(async () => {
      attempted = true; return { ok: true, status: 200, json: async () => ({}) };
    });
    ctx.API._story = true;
    const r = await ctx.API._write('POST', '/x', {}, SIM);
    check('storyline mode returns fixture without touching the network',
      r === SIM && attempted === false);
  }

  // 204 has no body to parse, so the simulated shape is the honest answer.
  {
    const ctx = makeCtx(async () => ({
      ok: true, status: 204, json: async () => { throw new Error('no body'); },
    }));
    const r = await ctx.API._write('PATCH', '/tasks/1', {}, SIM);
    check('204 returns the simulated shape', r === SIM);
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
