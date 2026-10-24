'use strict';
// Tes logika keputusan kanari tanpa dependensi: node canary.test.js
const assert = require('assert');
const { isExposed } = require('../../public_html/assets/install-canary.js');
const X = 'bfcanary:abc123';
const fake = (o) => () => o instanceof Error ? Promise.reject(o)
  : Promise.resolve({ type: o.type || 'basic', status: o.status, text: () => Promise.resolve(o.body || '') });
const cases = [
  ['403 lulus', { status: 403 }, false],
  ['404 lulus', { status: 404, body: X }, false],
  ['opaqueredirect lulus', { type: 'opaqueredirect', status: 0 }, false],
  ['200 berisi nilai gagal', { status: 200, body: X }, true],
  ['200 HTML lain lulus', { status: 200, body: '<html>instal</html>' }, false],
  ['200 nilai terbungkus gagal', { status: 200, body: 'xx<pre>' + X + '</pre>' + 'y'.repeat(500) }, true],
];
(async () => {
  for (const [n, o, want] of cases) { assert.strictEqual(await isExposed(fake(o), '/x', X), want, n); }
  await assert.rejects(isExposed(fake(new Error('net')), '/x', X), 'fetch error tidak memutuskan');
  console.log('OK');
})().catch((e) => { console.error(e.message); process.exit(1); });
