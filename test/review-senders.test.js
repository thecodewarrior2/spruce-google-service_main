'use strict';
// 0.6.40: a Spam answer covers the same address's other emails waiting for review; the rule checks alone don't make mail
// from a verified outside sender suspicious; Review leaves out the senders already on a Sender list. Every sender, address
// and email here is made up.
const test = require('node:test');
const assert = require('node:assert');
const { loadConfig } = require('../src/config');
const { Service } = require('../src/pipeline');
const { MemoryStore } = require('../src/store/memory');
const { decide, rulesOnlyVerified } = require('../src/policy');

const ORG = 'maple-schools.example';
const [PAT, SAM] = ['pat.fakewell', 'sam.testwood'].map(u => `${u}@${ORG}`);
const ADMIN = `it.madeup@${ORG}`;
const make = (mode = 'enforce', extra = {}) => new Service({ cfg: loadConfig(Object.assign({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: [PAT, SAM].join(','), MODE: mode }, extra)),
    store: new MemoryStore(), gmail: { labelId: async (u, n) => `L_${n}`, labels: async () => ['INBOX'], modify: async () => ({}) }, log: { error() {}, warn() {} } });
let n = 0;
const rec = (over) => Object.assign({ key: `k${++n}`, user: PAT, messageId: `m${n}`, processedAt: Date.now(), sender: { address: 'promo@mail.pinboard-tips.example', domain: 'mail.pinboard-tips.example' },
    subject: `Ideas for you ${n}`, auth: { dmarc: 'pass', headerFrom: 'mail.pinboard-tips.example' }, status: 'caution', score: 3, ai: { probability: 0.2 }, action: 'flag', state: 'inbox', campaign: `c${n}` }, over);

test('a Spam answer also answers the same address\'s other emails waiting for review, and Undo takes them back', async () => {
    const svc = make('enforce');
    const a = rec({ action: 'would-move', state: 'inbox' }), b = rec({ user: SAM }), c = rec({ action: 'move', state: 'moved' });
    const other = rec({ sender: { address: 'help@pinboard-tips.example' } }), done = rec({ markedBy: ADMIN, falseAlarm: true });
    for (const r of [a, b, c, other, done]) await svc.store.saveRecord(r);
    await svc.mark(a.key, false, ADMIN, { spam: true, move: true });
    const same = await svc.answerSameSender([a.key], ADMIN);
    assert.deepEqual(same.keys.sort(), [b.key, c.key].sort(), 'the same address only, still waiting');
    assert.equal(same.moved, 1, 'the one still in the Inbox is moved, as the answer did');
    for (const k of same.keys) assert.equal((await svc.store.getRecord(k)).spam, true);
    assert.equal((await svc.store.getRecord(other.key)).markedBy, undefined, 'another address at the same company: not answered');
    assert.equal((await svc.store.getRecord(done.key)).falseAlarm, true, 'an answered one keeps its answer');
    await svc.undoMany(same.keys, ADMIN);
    for (const k of same.keys) assert.equal((await svc.store.getRecord(k)).markedBy || null, null, 'undone');
});

test('the rule checks alone don\'t make a verified outside sender\'s email suspicious; the AI agreeing, or an unconfirmed sender, does', () => {
    const cfg = loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: PAT, MODE: 'enforce' });
    const base = { status: 'caution', score: 4.5, verified: true, inside: false, ai: { probability: 0.1 } };
    assert.equal(decide(base, cfg).action, 'none');
    assert.equal(decide(Object.assign({}, base, { ai: { probability: 0.8 } }), cfg).action, 'flag', 'the AI over the suspicious line');
    assert.equal(decide(Object.assign({}, base, { verified: false }), cfg).action, 'flag', 'Gmail couldn\'t confirm the sender');
    assert.equal(decide(Object.assign({}, base, { inside: true }), cfg).action, 'flag', 'staff mail: the AI doesn\'t read it by default');
    assert.equal(decide(Object.assign({}, base, { platformNote: true }), cfg).action, 'flag', 'a platform\'s notification (a share)');
    assert.equal(decide(Object.assign({}, base, { score: 1 }), cfg).action, 'flag', 'a link check\'s verdict');
    assert.equal(decide(Object.assign({}, base, { status: 'flagged', score: 6 }), cfg).action, 'move', 'what moves is unchanged');
    // A stored record (from before 0.6.40): read from its sender check.
    assert.equal(rulesOnlyVerified(rec({}), cfg), true);
    assert.equal(rulesOnlyVerified(rec({ auth: { dmarc: 'fail' } }), cfg), false);
});

test('Review leaves out the emails of senders on Spam senders, Trusted senders or Brand senders (verified only)', async () => {
    const svc = make('monitor', { ALLOW_ADDRESSES: 'office@friendly-vendor.example' });
    await svc.addSpamSender('mail.pinboard-tips.example', ADMIN);
    await svc.store.setState('brandSenders', { 'Bigstore|bigstore-mail.example': { brand: 'Bigstore', domain: 'bigstore-mail.example' } });
    const listed = await svc.senderListTest();
    assert.equal(listed(rec({})), 'Spam senders');
    assert.equal(listed(rec({ sender: { address: 'office@friendly-vendor.example' }, auth: { dmarc: 'pass', headerFrom: 'friendly-vendor.example' } })), 'Trusted senders');
    assert.equal(listed(rec({ sender: { address: 'news@bigstore-mail.example' }, auth: { dmarc: 'pass', headerFrom: 'bigstore-mail.example' } })), 'Brand senders');
    assert.equal(listed(rec({ auth: { dmarc: 'fail' } })), null, 'a forged copy stays in Review');
    assert.equal(listed(rec({ sender: { address: 'someone@unlisted.example' }, auth: { dmarc: 'pass', headerFrom: 'unlisted.example' } })), null);
});

// 0.6.44: the same, through the dashboard (its record cache keeps the sender check): Review leaves out a Spam sender's
// email and an old rules-only suspicious one from a verified sender, and each item says its sender check.
test('the dashboard\'s Review: sender lists and the suspicious line apply, and each item has its sender check', async () => {
    const http = require('http');
    const { createApp } = require('../src/server');
    const cfg = loadConfig({ DEMO: '1', MODE: 'monitor', ORG_DOMAINS: ORG });
    const svc = new Service({ cfg, store: new MemoryStore(), gmail: { labelId: async () => 'L', modify: async () => ({}) }, log: { error() {}, warn() {} } });
    const t = Date.now();
    const listed = rec({ action: 'would-move', processedAt: t - 1000 });
    const oldRulesOnly = rec({ sender: { address: 'news@verified-shop.example' }, auth: { dmarc: 'pass', headerFrom: 'verified-shop.example' }, processedAt: t - 2000 });
    const unverified = rec({ sender: { address: 'news@unknown-shop.example' }, auth: { dmarc: 'none' }, processedAt: t - 3000 });
    const failed = rec({ action: 'would-move', sender: { address: 'it@forged-help.example' }, auth: { dmarc: 'fail' }, processedAt: t - 4000 });
    for (const r of [listed, oldRulesOnly, unverified, failed]) await svc.store.saveRecord(r);
    await svc.addSpamSender('mail.pinboard-tips.example', ADMIN);
    const srv = http.createServer(createApp({ cfg, store: svc.store, service: svc }));
    await new Promise(r => srv.listen(0, r));
    const get = async (p) => (await fetch(`http://127.0.0.1:${srv.address().port}${p}`)).json();
    try {
        const moved = await get('/api/review?days=7'), sus = await get('/api/review?days=7&queue=suspicious');
        const keys = [...moved.keys, ...sus.keys];
        assert.ok(!keys.includes(listed.key), 'a Spam sender\'s email: not in Review');
        assert.ok(!keys.includes(oldRulesOnly.key), 'rules only, sender confirmed: not suspicious');
        assert.ok(sus.keys.includes(unverified.key), 'rules only, sender not confirmed: suspicious');
        assert.equal(moved.groups.find(g => g.keys.includes(failed.key)).dmarc, 'fail');
        assert.equal(sus.groups.find(g => g.keys.includes(unverified.key)).dmarc, 'none');
    } finally { await new Promise(r => srv.close(r)); }
});

// 0.6.50: Review's count follows the period the dashboard shows, and says how many wait from before it.
test('the pending count follows the period; older waiting emails are counted apart', async () => {
    const http = require('http');
    const { createApp } = require('../src/server');
    const cfg = loadConfig({ DEMO: '1', MODE: 'monitor', ORG_DOMAINS: ORG });
    const svc = new Service({ cfg, store: new MemoryStore(), gmail: { labelId: async () => 'L', modify: async () => ({}) }, log: { error() {}, warn() {} } });
    const DAY = 86400000, t = Date.now();
    const recent = rec({ action: 'would-move', sender: { address: 'a@unlisted-one.example' }, auth: { dmarc: 'fail' }, processedAt: t - DAY });
    const old = rec({ action: 'would-move', sender: { address: 'b@unlisted-two.example' }, auth: { dmarc: 'fail' }, processedAt: t - 12 * DAY });
    for (const r of [recent, old]) await svc.store.saveRecord(r);
    const srv = http.createServer(createApp({ cfg, store: svc.store, service: svc }));
    await new Promise(r => srv.listen(0, r));
    const get = async (p) => (await fetch(`http://127.0.0.1:${srv.address().port}${p}`)).json();
    try {
        const week = await get('/api/pending?days=7'), month = await get('/api/pending?days=30');
        assert.deepEqual([week.unreviewed, week.older, week.olderMoved], [1, 1, 1]);
        assert.deepEqual([month.unreviewed, month.older], [2, 0]);
    } finally { await new Promise(r => srv.close(r)); }
});

// 0.6.51: Gmail can name the organization's domain (header.from=bank.example) for mail from a subdomain
// (alerts@mail.bank.example): the sender is confirmed, as DMARC compares them, so a trusted address there is trusted.
test('a trusted address at a subdomain, Gmail naming its organization\'s domain: trusted; another organization\'s: not', async () => {
    const { readMessage } = require('../src/engine/mime');
    const { senderVerified } = require('../src/engine/analyze');
    const raw = (headerFrom) => Buffer.from(['From: "Madeup Credit Union" <donotreply@mail.madeup-cu.example>', 'To: pat.fakewell@maple-schools.example', 'Subject: Your statement is ready',
        'Message-ID: <s1@mail.madeup-cu.example>', `Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=${headerFrom}`,
        'Content-Type: text/html; charset=utf-8', '', '<p>Your statement is ready. Sign in to view it.</p><p><a href="https://login-madeup-cu-review.example/statement">Verify your account</a></p>'].join('\r\n'));
    assert.equal(senderVerified(await readMessage(raw('madeup-cu.example'))), true, 'the organization\'s domain');
    assert.equal(senderVerified(await readMessage(raw('mail.madeup-cu.example'))), true);
    assert.equal(senderVerified(await readMessage(raw('other-org.example'))), false, 'another organization\'s: no pass for the sender');
    const svc = make('enforce', { ALLOW_ADDRESSES: 'donotreply@mail.madeup-cu.example' });
    const r = await svc.judge('pat.fakewell@maple-schools.example', { id: 'cu1', threadId: 'tcu', internalDate: Date.now() }, await readMessage(raw('madeup-cu.example')));
    assert.equal(r.action, 'none', 'trusted: never moved');
});
