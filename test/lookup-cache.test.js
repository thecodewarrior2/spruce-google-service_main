'use strict';
// 0.6.77: why a re-check is slow, measured (src/timing.js), and lookups shared between instances: Spamhaus's and Cloudflare's
// answers kept in the shared store like Safe Browsing's (a one-way hash of the domain or host), and a re-check after an
// update allowed answers up to 6 hours old (staleOk). Every domain is made up.
const test = require('node:test');
const assert = require('node:assert');
const spruce = require('../src/engine/spruce');
const { createHttp } = require('../src/intel/http');
const { createThreats } = require('../src/intel/threats');
const { createSpamhaus } = require('../src/intel/spamhaus');
const { createApiKey } = require('../src/intel/apikey');
const { memorySecrets } = require('../src/intel/sbkey');
const { MemoryStore } = require('../src/store/memory');
const { loadConfig } = require('../src/config');
const timing = require('../src/timing');

const E = spruce.load();
const HOUR = 60 * 60 * 1000;
const json = (v) => ({ ok: true, status: 200, headers: { get: () => 'application/json' }, json: async () => v, text: async () => JSON.stringify(v) });
function net() {
    const calls = [];
    return { calls, fetch: async (url, init = {}) => {
        const u = new URL(url);
        calls.push(u.host);
        if (/cloudflare-dns\.com$/.test(u.host)) return json({ Status: 0, Answer: [{ type: 1, data: '203.0.113.20' }] });
        if (u.host === 'safebrowsing.googleapis.com') return json({ matches: [] });
        throw new Error(`unexpected ${u.host}`);
    } };
}

test('timing: steps counted, where answers came from, the slowest first', () => {
    timing.reset();
    const snap = timing.snapshot();
    timing.note('Gmail fetch', 900); timing.note('Gmail fetch', 1100);
    timing.note('Spamhaus', 0, 'memory'); timing.note('Spamhaus', 300, 'network');
    const s = timing.since(snap);
    assert.equal(s[0].step, 'Gmail fetch'); assert.equal(s[0].n, 2); assert.equal(s[0].avgMs, 1000);
    assert.deepEqual([s[1].memory, s[1].network], [1, 1]);
    assert.deepEqual(timing.since(timing.snapshot()), [], 'nothing since');
});

test('Safe Browsing: a clean answer older than 30 minutes is asked again on arrival, but a re-check after an update may use it for 6 hours', async () => {
    const n = net(), store = new MemoryStore();
    let now = Date.UTC(2026, 10, 24, 12);
    const cfg = { cloudflareThreats: false, safeBrowsing: true, safeBrowsingKey: 'k-made-up' };
    const make = () => createThreats({ http: createHttp({ fetch: n.fetch }), cfg, engine: E, store, now: () => now });
    const link = [{ url: 'https://statements.madeup-bank.example/view', text: 'View' }];
    await make().checkUrls(link);
    const sb = () => n.calls.filter(h => h === 'safebrowsing.googleapis.com').length;
    assert.equal(sb(), 1);
    now += 2 * HOUR;
    assert.equal((await make().checkUrls(link, { staleOk: true })).get(link[0].url).verdict, 'clean');
    assert.equal(sb(), 1, 'update re-check: the stored answer');
    await make().checkUrls(link);
    assert.equal(sb(), 2, 'arrival or a later look: asked again');
    now += 7 * HOUR;
    await make().checkUrls(link, { staleOk: true });
    assert.equal(sb(), 3, 'older than 6 hours: asked again even for an update re-check');
});

test('Cloudflare: another instance uses the shared answer (only a hash kept)', async () => {
    const n = net(), store = new MemoryStore();
    const cfg = { cloudflareThreats: true, safeBrowsing: false };
    const make = () => createThreats({ http: createHttp({ fetch: n.fetch }), cfg, engine: E, store });
    const before = n.calls.length;
    assert.equal((await make().checkHosts(['links.madeup-shop.example'])).get('links.madeup-shop.example').verdict, 'clean');
    const asked = n.calls.length - before;
    assert.ok(asked >= 1);
    await make().checkHosts(['links.madeup-shop.example']);
    assert.equal(n.calls.length - before, asked, 'the second instance asked nothing');
    assert.ok(!JSON.stringify([...store.cached.entries()]).includes('madeup-shop'), 'no host kept in the clear');
});

test('Spamhaus: shared between instances for an hour; for an update re-check, 6 hours', async () => {
    const store = new MemoryStore();
    let now = Date.UTC(2026, 10, 24, 12);
    const cfg = loadConfig({ STORE: 'memory', ORG_DOMAINS: 'maple-schools.example', PILOT_USERS: 'a@maple-schools.example', SPAMHAUS: 'on' });
    const asked = [];
    const resolver = { resolve4: async (name) => { asked.push(name); throw Object.assign(new Error('nx'), { code: 'ENOTFOUND' }); } };
    const KEY = 'abcdefghijklmnopqrstuvwxyz';
    const make = async () => {
        const sh = createSpamhaus({ cfg, store, resolver, log: { error() {}, warn() {} }, now: () => now });
        const key = createApiKey({ id: 'spamhaus', label: 'Spamhaus', store, secrets: memorySecrets(), keyRe: /^[a-z0-9]{20,40}$/i, test: async () => ({ ok: true }), log: { error() {}, warn() {} } });
        sh.setKey(key);
        await key.save(KEY, 'it.madeup@maple-schools.example').catch(() => {});
        return sh;
    };
    const a = await make();
    await a.checkDomains(['mail.madeup-sender.example']);
    const first = asked.length;
    assert.ok(first >= 2, 'DBL and ZRD asked');
    await (await make()).checkDomains(['mail.madeup-sender.example']);
    assert.equal(asked.length, first, 'another instance: the shared answer');
    now += 2 * HOUR;
    await (await make()).checkDomains(['mail.madeup-sender.example'], { staleOk: true });
    assert.equal(asked.length, first, 'update re-check: still the shared answer');
    await (await make()).checkDomains(['mail.madeup-sender.example']);
    assert.ok(asked.length > first, 'otherwise asked again after an hour');
    assert.ok(!JSON.stringify([...store.cached.entries()]).includes('madeup-sender'), 'no domain kept in the clear');
});
