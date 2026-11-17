'use strict';
// 0.6.1: Health → DMARC & reputation: your domains on blocklists, and in the downloaded phishing lists.
const test = require('node:test');
const assert = require('node:assert');
const zlib = require('zlib');
const { createReputation, scanLists, hostOfEntry } = require('../src/dashboard/reputation');

const blob = (lines) => ({ bytes: zlib.gzipSync(Buffer.from(lines.join('\n'))), info: { updated: 1 } });
const feedsOf = (feeds) => ({ status: async () => feeds.map(f => ({ id: f.id, name: f.name, kind: f.kind, updated: f.off ? null : 1, off: f.off })) });
const storeOf = (blobs) => ({ getBlob: async (k) => blobs[k] || null });

test('the downloaded lists: every entry on a domain or under it, by kind; other domains and look-alikes are not', async () => {
    assert.equal(hostOfEntry('https://Old-Portal.maple-schools.example/login?x=1'), 'old-portal.maple-schools.example');
    assert.equal(hostOfEntry('maple-schools.example/path'), 'maple-schools.example');
    const feeds = feedsOf([{ id: 'urls', name: 'Made-up links', kind: 'url' }, { id: 'sites', name: 'Made-up sites', kind: 'domain' }, { id: 'senders', name: 'Made-up senders', kind: 'address' }, { id: 'gone', name: 'Off', kind: 'domain', off: true }]);
    const store = storeOf({
        feed_urls: blob(['https://old-portal.maple-schools.example/login', 'https://maple-schools.example.evil.example/x', 'http://maple-schools-payroll.example/']),
        feed_sites: blob(['cdn.maple-schools.example', 'other.example']),
        feed_senders: blob(['payroll@maple-schools.example', 'someone@maple-schools-payroll.example']),
        feed_gone: blob(['maple-schools.example'])
    });
    const { out, checked, lists } = await scanLists({ feeds, store, domains: ['maple-schools.example', 'oak.example'] });
    assert.equal(checked, true); assert.equal(lists, 3, 'a list that is off is not read');
    assert.deepEqual(out['maple-schools.example'].map(l => [l.list, l.count, l.entries]), [
        ['Made-up links', 1, ['https://old-portal.maple-schools.example/login']],
        ['Made-up sites', 1, ['cdn.maple-schools.example']],
        ['Made-up senders', 1, ['payroll@maple-schools.example']]]);
    assert.deepEqual(out['oak.example'], []);
});

test('the blocklists: listed, clean, off and not checked; any listing or list entry makes the domain "listed"', async () => {
    const calls = { cf: 0, sb: 0, sh: 0 };
    const intel = {
        threats: {
            enabled: { safeBrowsing: true },
            checkHosts: async (hs) => { calls.cf++; return new Map(hs.map(h => [h, { verdict: h === 'bad.example' ? 'unsafe' : 'clean' }])); },
            checkUrls: async (ls) => { calls.sb++; return new Map(ls.map(l => [l.url, { verdict: 'clean' }])); }
        },
        spamhaus: { checkDomains: async (ds) => { calls.sh++; return new Map(ds.filter(d => d !== 'quiet.example').map(d => [d, { dbl: d === 'bad.example' ? { list: 'phishing', severity: 'danger' } : null, zrdHours: null }])); } },
        feeds: feedsOf([])
    };
    let t = 0;
    const rep = createReputation({ cfg: { cloudflareThreats: true, spamhaus: true }, intel, store: storeOf({}), now: () => t });
    const [good, bad, quiet] = await rep(['good.example', 'bad.example', 'quiet.example']);
    assert.deepEqual(good.services.map(s => s.state), ['clean', 'clean', 'clean']); assert.equal(good.level, 'good');
    assert.deepEqual(bad.services.map(s => s.state), ['listed', 'clean', 'listed']); assert.equal(bad.level, 'bad');
    assert.match(bad.services[2].detail, /phishing/);
    assert.equal(quiet.services[2].state, 'unknown'); assert.equal(quiet.level, 'warn', 'not checked is never clean');
    const n = calls.cf;
    await rep(['good.example']);
    assert.equal(calls.cf, n, 'kept 10 minutes');
    await rep(['good.example'], { fresh: true });
    assert.equal(calls.cf, n + 1, 'Check again reads now');
    const off = await createReputation({ cfg: { cloudflareThreats: false, spamhaus: false }, intel: { threats: { enabled: { safeBrowsing: false } }, feeds: feedsOf([]) }, store: storeOf({}) })(['good.example']);
    assert.deepEqual(off[0].services.map(s => s.state), ['off', 'off', 'off']);
    assert.equal(off[0].level, 'warn', 'nothing checked is not clean');
});
