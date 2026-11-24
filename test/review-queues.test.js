'use strict';
// 0.6.68: Review's queues decided in one place (src/review-queues.js). The old filters (0.6.67's server.js, copied below) and
// the classifier must agree on every record; plus the cases by name. Every record here is made up.
const test = require('node:test');
const assert = require('node:assert');
const { rulesOnlyVerified } = require('../src/policy');
const RQ = require('../src/review-queues');

const cfg = { aiSuspicious: 0.65 };
// 0.6.67's filters, as they were.
const old = {
    unreviewed: (r) => (r.action === 'move' || r.action === 'would-move') && r.trigger !== 'admin' && !r.markedBy && !r.userReported,
    reported: (r) => !!r.userReported && !r.markedBy,
    suspicious: (r) => r.action === 'flag' && r.state === 'inbox' && !r.markedBy && !r.userReported && !rulesOnlyVerified(r, cfg),
    promo: (r) => r.action === 'promo' && r.state === 'inbox' && !r.markedBy && !r.promoKept && !r.userReported
};
function oldQueues(all, listed) {
    const records = all.filter(r => r.userReported || !listed(r));
    const moved = records.filter(old.unreviewed);
    const campaigns = new Set(moved.map(r => r.campaign).filter(Boolean));
    const susp = records.filter(old.suspicious);
    return {
        moved: moved.concat(susp.filter(r => r.campaign && campaigns.has(r.campaign))).map(r => r.key).sort(),
        suspicious: susp.filter(r => !r.campaign || !campaigns.has(r.campaign)).map(r => r.key).sort(),
        promotional: records.filter(old.promo).map(r => r.key).sort(),
        reported: records.filter(old.reported).map(r => r.key).sort()
    };
}

function rng(seed) { let s = seed >>> 0; return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32); }
function randomRecords(n, seed) {
    const r = rng(seed), pick = (a) => a[Math.floor(r() * a.length)];
    return Array.from({ length: n }, (_, i) => ({
        key: `k${i}`, campaign: r() < 0.8 ? `c${Math.floor(r() * 40)}` : null,
        action: pick(['move', 'would-move', 'flag', 'promo', 'none']), trigger: pick(['rules', 'ai', 'spam', 'admin', null]),
        state: pick(['inbox', 'inbox', 'moved', 'released', 'reported']), status: pick(['caution', 'flagged', 'clean']), score: pick([0, 3, 4, 6]),
        markedBy: r() < 0.2 ? 'it.madeup@maple-schools.example' : null, userReported: r() < 0.1 ? { at: 1 } : undefined, promoKept: r() < 0.1 ? { by: 'x' } : undefined,
        sender: { address: pick(['news@listed-shop.example', 'billing@madeup-vendor.example']) }, auth: { dmarc: pick(['pass', 'fail', 'none']) },
        ai: { probability: r() }, inside: r() < 0.1, platformNote: r() < 0.05 ? true : undefined
    }));
}

test('the classifier agrees with the old filters on 2,000 made-up records, with and without a Sender list', () => {
    const records = randomRecords(2000, 6868);
    for (const listed of [() => null, (r) => (r.sender.address.startsWith('news@listed') ? 'Spam senders' : null)]) {
        const was = oldQueues(records, listed);
        const Q = RQ.queuesOf(records, { cfg, listed });
        for (const q of RQ.QUEUES) assert.deepEqual(Q[q].map(r => r.key).sort(), was[q], `${q} (${listed.length ? 'with' : 'without'} a list)`);
        // One queue each, never two.
        const seen = new Set();
        for (const q of RQ.QUEUES) for (const r of Q[q]) { assert.ok(!seen.has(r.key), `${r.key} in two queues`); seen.add(r.key); }
    }
});

test('the order, case by case', () => {
    const base = { key: 'k', campaign: null, state: 'inbox', status: 'caution', score: 3, auth: { dmarc: 'none' }, sender: { address: 'a@madeup.example' }, ai: { probability: 0.1 } };
    const q = (over, opts = {}) => RQ.baseQueueOf(Object.assign({}, base, over), Object.assign({ cfg }, opts));
    assert.equal(q({ action: 'move', trigger: 'rules', markedBy: 'it' }), null, 'answered');
    assert.equal(q({ action: 'promo', userReported: { at: 1 } }), 'reported', 'a reported promotional email: Reported only');
    assert.equal(q({ action: 'move', trigger: 'rules', userReported: { at: 1 } }, { listed: () => 'Trusted senders' }), 'reported', 'reported, from a trusted sender: still listed');
    assert.equal(q({ action: 'move', trigger: 'rules' }, { listed: () => 'Spam senders' }), null, 'a sender on a list');
    assert.equal(q({ action: 'would-move', trigger: 'ai' }), 'moved');
    assert.equal(q({ action: 'move', trigger: 'admin' }), null, 'a copy an admin\'s search found');
    assert.equal(q({ action: 'flag' }), 'suspicious');
    assert.equal(q({ action: 'flag', auth: { dmarc: 'pass' } }), null, 'rules only, from a sender Gmail confirmed');
    assert.equal(q({ action: 'flag', state: 'moved' }), null, 'no longer in the Inbox');
    assert.equal(q({ action: 'promo' }), 'promotional');
    assert.equal(q({ action: 'promo', promoKept: { by: 'it' } }), null, 'its company kept');
    // A suspicious copy of a campaign with a moved copy: in Moved, with it.
    const Q = RQ.queuesOf([Object.assign({}, base, { key: 'a', campaign: 'c1', action: 'move', trigger: 'rules' }), Object.assign({}, base, { key: 'b', campaign: 'c1', action: 'flag' }), Object.assign({}, base, { key: 'c', campaign: 'c2', action: 'flag' })], { cfg });
    assert.deepEqual([Q.moved.map(r => r.key), Q.suspicious.map(r => r.key)], [['a', 'b'], ['c']]);
});

test('an answer that also answers other waiting emails leaves a reported one alone', () => {
    assert.equal(RQ.waitingForAnswer({ action: 'move' }), true);
    assert.equal(RQ.waitingForAnswer({ action: 'move', userReported: { at: 1 } }), false);
    assert.equal(RQ.waitingForAnswer({ action: 'move', markedBy: 'it' }), false);
});

test('0.6.68: a Spam answer for the same address, and a company\'s Promotional answer, leave a reported email in Review → Reported', async () => {
    const { loadConfig } = require('../src/config');
    const { Service } = require('../src/pipeline');
    const { MemoryStore } = require('../src/store/memory');
    const ORG = 'maple-schools.example', ADMIN = `it.madeup@${ORG}`;
    const svc = new Service({ cfg: loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: `pat.fakewell@${ORG}`, MODE: 'monitor' }), store: new MemoryStore(),
        gmail: { labelId: async () => 'L', modify: async () => ({}), labels: async () => ['INBOX'] }, log: { error() {}, warn() {} } });
    const now = Date.now();
    const rec = (key, over) => Object.assign({ key, user: `pat.fakewell@${ORG}`, messageId: key, processedAt: now, receivedAt: now, state: 'inbox', falseAlarm: null, signals: [],
        sender: { address: 'deals@em.madeup-store.example', domain: 'em.madeup-store.example' }, auth: { dmarc: 'pass' } }, over);
    for (const r of [rec('answered', { action: 'flag', spam: true, falseAlarm: false, markedBy: ADMIN }), rec('waiting', { action: 'would-move', trigger: 'spam' }), rec('reported', { action: 'would-move', trigger: 'spam', userReported: { at: now } })]) await svc.store.saveRecord(r);
    const out = await svc.answerSameSender(['answered'], ADMIN);
    assert.deepEqual(out.keys, ['waiting'], 'the waiting one answered, not the reported one');
    assert.equal((await svc.store.getRecord('reported')).markedBy, undefined);
    // Review → Promotional: a company's waiting emails, not one its reader reported.
    const promo = (key, over) => rec(key, Object.assign({ action: 'promo', promotional: { company: 'madeup-store.example', signs: ['x'] } }, over));
    const list = [promo('p1'), promo('p2', { userReported: { at: now } }), promo('p3', { promoKept: { by: ADMIN } })];
    assert.deepEqual((await svc.promoWaiting('madeup-store.example', list)).map(r => r.key), ['p1']);
});

test('0.6.75: Ignore suspicious leaves suspicious emails out of Review; the other queues are as before', () => {
    const recs = randomRecords(400, 75);
    const on = Object.assign({}, cfg, { ignoreSuspicious: true });
    const a = RQ.queuesOf(recs, { cfg }), b = RQ.queuesOf(recs, { cfg: on });
    assert.ok(a.suspicious.length > 0, 'some suspicious emails to ignore');
    assert.equal(b.suspicious.length, 0, 'no Suspicious queue');
    for (const q of ['promotional', 'reported']) assert.deepEqual(b[q].map(r => r.key), a[q].map(r => r.key), q);
    // A suspicious copy of a campaign with a moved copy is still in Moved (one answer covers every copy); the rest are in none.
    const moved = new Set(b.moved.map(r => r.key));
    for (const r of a.moved) assert.ok(moved.has(r.key) || r.action === 'flag', r.key);
    for (const r of a.suspicious) assert.equal(b.of.has(r.key), false, r.key);
    assert.equal(RQ.baseQueueOf({ key: 'x', action: 'flag', state: 'inbox', status: 'flagged', score: 6 }, { cfg: on }), null);
    assert.equal(RQ.baseQueueOf({ key: 'x', action: 'move', state: 'moved', trigger: 'rules' }, { cfg: on }), 'moved');
});
