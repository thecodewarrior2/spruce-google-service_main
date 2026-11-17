'use strict';
// 0.6.17: Threats → Re-checked. "Mark all as seen" takes every listing off the page (not only the banners), and each
// listing has its own "Mark as seen"; something new found in one brings it back. Every record here is made up.
const test = require('node:test');
const assert = require('node:assert');
const A = require('../src/dashboard/aggregate');

const DAY = 86400000, now = Date.UTC(2026, 10, 17, 12);
const rec = (key, campaign, user, at, outcome = 'moved') => ({ key, campaign, user, subject: `Invoice ${campaign}`, receivedAt: at - DAY, processedAt: at - DAY, recheck: { at, outcome } });
const records = [rec('a1', 'c1', 'pat.madeup@maple-schools.example', now - 3 * DAY), rec('a2', 'c1', 'sam.testwood@maple-schools.example', now - 2 * DAY),
    rec('b1', 'c2', 'pat.madeup@maple-schools.example', now - DAY)];
const seenOf = (gs) => Object.fromEntries(gs.map(g => [g.campaign, g.seen]));

test('nothing marked: every listing is new, and the banner counts them all', () => {
    assert.deepEqual(seenOf(A.rechecked(records, now, 14)), { c1: false, c2: false });
    assert.equal(A.recheckAlert(records, now, 0, {}).emails, 3);
});

test('mark all as seen: every listing is seen, the banner is gone; a new re-check brings its listing back', () => {
    const seen = { at: now - 1000, campaigns: {} };
    assert.deepEqual(seenOf(A.rechecked(records, now, 14, seen)), { c1: true, c2: true });
    assert.equal(A.recheckAlert(records, now, seen.at, {}), null);
    const later = records.concat(rec('a3', 'c1', 'lee.samplefield@maple-schools.example', now - 10));
    assert.deepEqual(seenOf(A.rechecked(later, now, 14, seen)), { c1: false, c2: true });
    assert.equal(A.recheckAlert(later, now, seen.at, {}).emails, 1);
});

test('one listing marked as seen: only that one, in the page and the banner', () => {
    const seen = { at: 0, campaigns: { c1: now - 1000 } };
    assert.deepEqual(seenOf(A.rechecked(records, now, 14, seen)), { c1: true, c2: false });
    assert.equal(A.recheckAlert(records, now, 0, seen.campaigns).emails, 1);
});

test('the dashboard: each listing marked on its own, then all; both leave the page and the banner', async () => {
    const http = require('http');
    const { loadConfig } = require('../src/config');
    const { Service } = require('../src/pipeline');
    const { MemoryStore } = require('../src/store/memory');
    const { createApp } = require('../src/server');
    const cfg = loadConfig({ DEMO: '1', MODE: 'monitor', ORG_DOMAINS: 'maple-schools.example' });
    const store = new MemoryStore();
    const t = Date.now();
    for (const r of [rec('a1', 'c1', 'pat.madeup@maple-schools.example', t - 2 * DAY), rec('b1', 'c2', 'pat.madeup@maple-schools.example', t - DAY)]) await store.saveRecord(r);
    const service = new Service({ cfg, store, gmail: {}, log: { error() {}, warn() {} } });
    const srv = http.createServer(createApp({ cfg, store, service }));
    await new Promise(r => srv.listen(0, r));
    const base = `http://127.0.0.1:${srv.address().port}`;
    const page = async () => seenOf((await (await fetch(`${base}/api/rechecked?days=14`)).json()).groups);
    const mark = (body) => fetch(`${base}/api/rechecked/seen`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-requested-with': 'spruce-dashboard' }, body: JSON.stringify(body) });
    try {
        assert.deepEqual(await page(), { c1: false, c2: false });
        assert.equal((await mark({ campaign: 'c1' })).status, 200);
        assert.deepEqual(await page(), { c1: true, c2: false });
        await mark({});
        assert.deepEqual(await page(), { c1: true, c2: true });
        assert.deepEqual(await store.getState('recheckSeenCampaigns'), {}, 'one mark for all replaces the single ones');
    } finally { await new Promise(r => srv.close(r)); }
});
