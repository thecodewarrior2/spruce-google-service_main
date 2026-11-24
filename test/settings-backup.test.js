'use strict';
// 0.6.72: Settings → Backup. Every saved setting in one file and back; the API keys only when ticked, and then only
// encrypted with the admin's passphrase; an import never makes a change the Policy page asks the admin to agree to.
// Every address, domain and key here is made up.
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { loadConfig } = require('../src/config');
const { Service } = require('../src/pipeline');
const { MemoryStore } = require('../src/store/memory');
const { createApp } = require('../src/server');
const B = require('../src/settings-backup');

const ORG = 'maple-schools.example', ADMIN = `it.madeup@${ORG}`;
const FAKE_SB = 'AIzaMadeupMadeupMadeupMadeupMadeup12345';
function memKey(value = null) {
    let v = value;
    return { get: async () => v, save: async (x) => { if (!/^AIza/.test(x)) throw Object.assign(new Error('That doesn\'t look like a key.'), { status: 400 }); v = x; return { tested: false }; }, peek: () => v };
}
function svcOf(env = {}) {
    const cfg = loadConfig(Object.assign({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: `pat.fakewell@${ORG}`, MODE: 'monitor', DIRECTORY_ADMIN: `spruce-directory@${ORG}` }, env));
    const store = new MemoryStore();
    const service = new Service({ cfg, store, gmail: {}, log: { error() {}, warn() {} } });
    return { cfg, store, service };
}

test('the keys are encrypted with the passphrase: never in the clear, and only that passphrase opens them', () => {
    const box = B.encryptKeys({ safeBrowsing: FAKE_SB }, 'a long made-up passphrase');
    assert.ok(!JSON.stringify(box).includes(FAKE_SB), 'not in the clear');
    assert.deepEqual(B.decryptKeys(box, 'a long made-up passphrase'), { safeBrowsing: FAKE_SB });
    assert.throws(() => B.decryptKeys(box, 'another made-up passphrase'), /doesn't open/);
    const bytes = Buffer.from(box.data, 'base64'); bytes[0] ^= 0xff; // always a different first byte
    const changed = Object.assign({}, box, { data: bytes.toString('base64') });
    assert.throws(() => B.decryptKeys(changed, 'a long made-up passphrase'), /doesn't open/, 'a changed file is refused');
    assert.throws(() => B.encryptKeys({}, 'short'), /12 characters/);
});

test('export, then import on another installation: the lists, answers, rules, marks and switches come back; gated policy waits', async () => {
    const a = svcOf();
    await a.service.setPolicy('aiThreshold', 0.92, ADMIN);
    await a.service.setPolicy('allowDomains', ['madeup-vendor.example'], ADMIN);
    await a.service.setPolicy('strictSpam', ['forged-headers'], ADMIN);
    await a.store.setState('spamSenders', { 'deal-blast.example': { by: ADMIN, at: 1, from: 'review', count: 0 } });
    await a.store.setState('brandSenders', { 'walmart|payco-madeup.example': { brand: 'Walmart', domain: 'payco-madeup.example', by: ADMIN, at: 1 } });
    await a.store.setState('rememberedSafe', { fp1: { answer: 'safe', subject: 'Made-up newsletter', by: ADMIN, at: 1 } });
    await a.store.setState('phishTraining', { rules: [{ id: 'r1', name: 'Madeup Trainer', header: 'x-madeup-test', ips: ['192.0.2.0/26'] }], domains: ['madeup-trainer.example'], by: ADMIN, at: 1 });
    await a.store.setState('lookalikeWatch', { found: { 'maple-schoo1s.example': { domain: 'maple-schoo1s.example', status: 'threat', by: ADMIN, at: 1 }, 'maple-school.example': { domain: 'maple-school.example', status: 'new' } } });
    await a.service.setDigest(true, ADMIN);
    await a.service.setUserReports(true, ADMIN);
    const keysA = { safeBrowsing: memKey(FAKE_SB), spamhaus: memKey(null), abusech: null };
    const plain = await B.exportSettings({ service: a.service, store: a.store, cfg: a.cfg, keys: keysA, by: ADMIN });
    assert.equal(plain.keys, null, 'no keys unless ticked');
    const f = await B.exportSettings({ service: a.service, store: a.store, cfg: a.cfg, keys: keysA, by: ADMIN, includeKeys: true, passphrase: 'a long made-up passphrase' });
    const text = JSON.stringify(f);
    assert.ok(!text.includes(FAKE_SB), 'the key is never in the file in the clear');
    assert.deepEqual(Object.keys(f.sections.lookalikes), ['maple-schoo1s.example'], 'only marked look-alikes');
    // Another installation, in enforce-ready monitor mode with nothing saved.
    const b = svcOf();
    const keysB = { safeBrowsing: memKey(null), spamhaus: memKey(null), abusech: null };
    const parsed = B.parseFile(text);
    const p = await B.previewImport(parsed, { service: b.service, store: b.store, cfg: b.cfg });
    const pol = p.sections.find(x => x.id === 'policy');
    assert.ok(pol.changes.some(c => c.key === 'aiThreshold' && c.to === 0.92));
    assert.deepEqual(pol.waits.map(w => w.key), ['strictSpam'], 'Skip review waits for its page');
    assert.equal(p.sections.find(x => x.id === 'senders').parts.find(x => x.name === 'spamSenders').added, 1);
    const out = await B.applyImport(parsed, { service: b.service, store: b.store, cfg: b.cfg, keys: keysB, by: ADMIN, sections: B.SECTION_IDS, passphrase: 'a long made-up passphrase' });
    assert.ok(out.done.every(d => !d.error), JSON.stringify(out.done));
    assert.equal(b.cfg.aiThreshold, 0.92);
    assert.deepEqual(b.cfg.allowDomains, ['madeup-vendor.example']);
    assert.deepEqual(b.cfg.strictSpam || [], [], 'Skip review not turned on by an import');
    assert.ok((await b.store.getState('spamSenders'))['deal-blast.example']);
    assert.ok((await b.store.getState('brandSenders'))['walmart|payco-madeup.example']);
    assert.ok((await b.store.getState('rememberedSafe')).fp1);
    assert.equal((await b.store.getState('phishTraining')).rules[0].name, 'Madeup Trainer');
    assert.equal((await b.store.getState('lookalikeWatch')).found['maple-schoo1s.example'].status, 'threat');
    assert.equal((await b.store.getState('digest')).enabled, true);
    assert.equal((await b.store.getState('userReports')).on, true);
    assert.equal(keysB.safeBrowsing.peek(), FAKE_SB, 'the key saved through the key\'s own save (tested there)');
    assert.match((await b.store.getState('policy-aiThreshold')).by, /\(import\)$/, 'Activity says it came from an import');
    // A wrong passphrase: the keys aren't imported, the rest is.
    const c = svcOf();
    const keysC = { safeBrowsing: memKey(null), spamhaus: memKey(null), abusech: null };
    const out2 = await B.applyImport(parsed, { service: c.service, store: c.store, cfg: c.cfg, keys: keysC, by: ADMIN, sections: B.SECTION_IDS, passphrase: 'not the passphrase' });
    assert.match(out2.done.find(d => d.id === 'keys').error, /doesn't open/);
    assert.equal(keysC.safeBrowsing.peek(), null);
    assert.ok((await c.store.getState('spamSenders'))['deal-blast.example'], 'the other sections still imported');
});

test('an import never switches to enforce mode, lets the AI alone move staff email, changes who is checked or where updates come from', async () => {
    const a = svcOf({ MODE: 'enforce' });
    const f = await B.exportSettings({ service: a.service, store: a.store, cfg: a.cfg, by: ADMIN });
    f.sections.policy.aiMovesInside = true; f.sections.policy.watchScope = 'domain'; f.sections.policy.releasesRepo = 'someone-madeup/elsewhere';
    const b = svcOf();
    const out = await B.applyImport(B.parseFile(JSON.stringify(f)), { service: b.service, store: b.store, cfg: b.cfg, by: ADMIN, sections: ['policy'] });
    const pol = out.done.find(d => d.id === 'policy');
    assert.deepEqual(pol.waits.map(w => w.key).sort(), ['aiMovesInside', 'mode', 'releasesRepo', 'watchScope']);
    assert.equal(b.cfg.mode, 'monitor'); assert.notEqual(b.cfg.aiMovesInside, true); assert.notEqual(b.cfg.watchScope, 'domain');
    // Back to monitor mode from enforce is the safer way: made.
    const back = await B.applyImport(B.parseFile(JSON.stringify(Object.assign({}, f, { sections: { policy: { mode: 'monitor' } } }))), { service: a.service, store: a.store, cfg: a.cfg, by: ADMIN, sections: ['policy'] });
    assert.deepEqual(back.done[0].changed, ['mode']); assert.equal(a.cfg.mode, 'monitor');
});

test('a file that isn\'t a settings file, or holds something unknown or too big, is refused before anything changes', () => {
    assert.throws(() => B.parseFile(''), /Choose a settings file/);
    assert.throws(() => B.parseFile('not json'), /isn't JSON/);
    assert.throws(() => B.parseFile(JSON.stringify({ format: 'other' })), /isn't a settings file/);
    assert.throws(() => B.parseFile(JSON.stringify({ format: B.FORMAT, formatVersion: 99, sections: {} })), /newer kind/);
    assert.throws(() => B.parseFile(JSON.stringify({ format: B.FORMAT, formatVersion: 1, sections: { senders: { brake: {} } } })), /doesn't know/);
    assert.throws(() => B.parseFile(JSON.stringify({ format: B.FORMAT, formatVersion: 1, sections: { senders: { spamSenders: { x: 'not an entry' } } } })), /aren't readable/);
    const big = Object.fromEntries(Array.from({ length: 9000 }, (_, i) => [`s${i}.madeup.example`, { by: ADMIN, note: 'x'.repeat(100) }]));
    assert.throws(() => B.parseFile(JSON.stringify({ format: B.FORMAT, formatVersion: 1, sections: { senders: { spamSenders: big } } })), /too big/);
    assert.throws(() => B.parseFile(JSON.stringify({ format: B.FORMAT, formatVersion: 1, sections: { lookalikes: { 'x.example': { status: 'new' } } } })), /look-alike/);
});

test('the routes: admins only; the keys and an import need the project ID; the passphrase is checked; Activity says what happened', async () => {
    const cfg = loadConfig({ DEMO: '1', MODE: 'monitor', ORG_DOMAINS: ORG, GOOGLE_CLOUD_PROJECT: 'maple-mail-protection' });
    const store = new MemoryStore();
    const warned = [];
    const service = new Service({ cfg, store, gmail: {}, log: { error() {}, warn: (x) => warned.push(JSON.parse(x)) } });
    await store.setState('spamSenders', { 'deal-blast.example': { by: ADMIN, at: 1 } });
    const srv = http.createServer(createApp({ cfg, store, service }));
    await new Promise(r => srv.listen(0, r));
    const base = `http://127.0.0.1:${srv.address().port}`;
    const post = async (path, body) => { const r = await fetch(`${base}/api/settings-backup/${path}`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-requested-with': 'spruce-dashboard' }, body: JSON.stringify(body) }); return { status: r.status, body: await r.json() }; };
    try {
        const plain = await post('export', {});
        assert.equal(plain.status, 200); assert.equal(plain.body.file.keys, null); assert.match(plain.body.name, /^spruce-settings-\d{4}-\d\d-\d\d\.json$/);
        assert.equal((await post('export', { includeKeys: true, passphrase: 'a long made-up passphrase', passphrase2: 'a long made-up passphrase', projectId: 'wrong-project' })).status, 403);
        assert.equal((await post('export', { includeKeys: true, passphrase: 'short', passphrase2: 'short', projectId: 'maple-mail-protection' })).status, 400);
        await new Promise(r => setTimeout(r, 10));
        const withKeys = await post('export', { includeKeys: true, passphrase: 'a long made-up passphrase', passphrase2: 'a long made-up passphrase', projectId: 'maple-mail-protection' });
        assert.ok(withKeys.status === 200 || withKeys.status === 429, `export with keys: ${withKeys.status}`);
        const file = JSON.stringify(plain.body.file);
        const prev = await post('preview', { file });
        assert.equal(prev.status, 200); assert.ok(prev.body.preview.sections.some(s => s.id === 'senders'));
        assert.equal((await post('preview', { file: '{}' })).status, 400);
        assert.equal((await post('import', { file, sections: ['senders'], projectId: 'wrong-project' })).status, 403);
        assert.equal((await post('import', { file, sections: [], projectId: 'maple-mail-protection' })).status, 400);
        await store.setState('spamSenders', {});
        const imp = await post('import', { file, sections: ['senders'], projectId: 'maple-mail-protection' });
        assert.equal(imp.status, 200, JSON.stringify(imp.body));
        assert.ok((await store.getState('spamSenders'))['deal-blast.example']);
        assert.ok(warned.some(w => w.spruceAlert === 'settings-import' && /imported settings/.test(w.message)), 'the admins are alerted');
    } finally { await new Promise(r => srv.close(r)); }
});
