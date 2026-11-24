'use strict';
// 0.6.76: sender standing (src/standing.js). Where the AI's score is the only thing that objects to an email from a sender
// with standing (history, or an admin's Mark safe), it isn't marked suspicious and isn't moved (Review instead); every other
// check judges it as before, and an email that doesn't mail the way the sender usually does gets no standing. Every person,
// address and domain is made up.
const test = require('node:test');
const assert = require('node:assert');
const { loadConfig } = require('../src/config');
const { Service } = require('../src/pipeline');
const { MemoryStore } = require('../src/store/memory');
const { readMessage } = require('../src/engine/mime');
const ST = require('../src/standing');
const RQ = require('../src/review-queues');
const E = require('../src/engine/spruce').load();

const ORG = 'maple-schools.example';
const ADMIN = `it.madeup@${ORG}`, PAT = `pat.fakewell@${ORG}`;
const DAY = ST.DAY;
let n = 0;
const raw = ({ from = 'statements@mail.madeupbank.example', dmarc = 'pass', link = 'https://secure.madeupbank.example/statement', replyTo = null, extraHead = [] } = {}) => Buffer.from([
    `From: "Madeup Bank" <${from}>`, `To: ${PAT}`, 'Subject: Your statement is ready', `Message-ID: <s${++n}@madeupbank.example>`,
    ...(replyTo ? [`Reply-To: ${replyTo}`] : []), ...extraHead,
    `Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=bounce.madeupbank.example; dkim=pass header.i=@madeupbank.example; dmarc=${dmarc} header.from=${from.split('@')[1]}`,
    'Content-Type: text/html', '', `<p>Your November statement is ready.</p><p><a href="${link}">View statement</a></p>`].join('\r\n'));
const factsOf = (o) => readMessage(raw(o));
// What analyze would say of an email only the AI objects to (the rules found nothing).
const aiOnly = (facts, p = 0.8) => ({ status: 'clean', score: 0, signals: [], links: [], confirmedBy: [], strictSigns: {}, verified: facts.auth && facts.auth.dmarc === 'pass', inside: false,
    ai: { probability: p }, linkUrls: [String((/href="([^"]+)"/.exec(facts.html || '') || [])[1] || 'https://secure.madeupbank.example/statement')] });

function svcOf(env = {}) {
    let now = Date.UTC(2026, 10, 1, 15);
    const cfg = loadConfig(Object.assign({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: PAT, MODE: 'enforce', DIRECTORY_ADMIN: `spruce-directory@${ORG}` }, env));
    const store = new MemoryStore();
    const svc = new Service({ cfg, store, gmail: { modify: async () => ({}), labelId: async (u, l) => `L_${l}` }, log: { error() {}, warn() {} }, now: () => now });
    return { cfg, store, svc, at: () => now, advance: (ms) => { now += ms; } };
}
// A sender with a month of clean mail, mailing the way the test's emails do.
async function establish(t, facts, result) {
    for (let d = 0; d < 35; d++) {
        await t.svc.learnStanding(facts, result, { now: t.at(), day: `2026-11-${String(1 + (d % 28)).padStart(2, '0')}-${d}` });
        t.advance(DAY);
    }
}

test('standing.js: who can have standing, history thresholds, the profile, a Phishing answer', async () => {
    const f = await factsOf();
    assert.equal(ST.senderDomain(E, f, [ORG]), 'madeupbank.example', 'the registrable domain');
    assert.equal(ST.senderDomain(E, { senderAddress: '@gmail.com' }, [ORG]), null, 'never free-mail');
    assert.equal(ST.senderDomain(E, { senderAddress: `x@${ORG}` }, [ORG]), null, 'never your own domain');
    const r = aiOnly(f), flag = { action: 'flag', trigger: null };
    assert.equal(ST.whyNotEligible(r, f, flag), null);
    assert.ok(ST.whyNotEligible(Object.assign({}, r, { status: 'caution' }), f, flag), 'the rules found something');
    assert.ok(ST.whyNotEligible(r, f, { action: 'move', trigger: 'rules+ai' }), 'moved by the rules too');
    assert.ok(ST.whyNotEligible(Object.assign({}, r, { strictSigns: { forgedHeaders: ['message-id'] } }), f, flag), 'forged headers');
    assert.ok(ST.whyNotEligible(Object.assign({}, r, { verified: false }), await factsOf({ dmarc: 'fail' }), flag), 'DMARC failed');
    assert.ok(ST.whyNotEligible(Object.assign({}, r, { links: [{ severity: 'danger' }] }), f, flag), 'a flagged link');
    assert.ok(ST.whyNotEligible(r, f, flag, { relay: true }), 'a platform notification');
    const prof = ST.profileOf(E, f, r), now = Date.UTC(2026, 11, 15);
    const doc = { first: now - 40 * DAY, days: 8, count: 30, prof };
    assert.deepEqual(ST.standingFor(doc, prof, now).ok, true);
    assert.equal(ST.standingFor(Object.assign({}, doc, { first: now - 10 * DAY }), prof, now).ok, false, 'too new');
    assert.equal(ST.standingFor(Object.assign({}, doc, { count: 3 }), prof, now).ok, false, 'too few clean emails');
    assert.equal(ST.standingFor(Object.assign({}, doc, { phishAt: now - DAY, phishBy: ADMIN }), prof, now).ok, false, 'answered Phishing');
    const otherLinks = ST.profileOf(E, await factsOf({ link: 'https://madeupbank-verify.example/login' }), Object.assign({}, r, { linkUrls: ['https://madeupbank-verify.example/login'] }));
    const s = ST.standingFor(doc, otherLinks, now);
    assert.equal(s.ok, false); assert.deepEqual(s.breaks, ['links']); assert.match(s.why, /links to a site it hasn't used/);
    // Only hashes are kept.
    assert.ok(!JSON.stringify(prof).includes('madeupbank'), 'no domain in the clear');
    // An answer: Mark safe gives standing at once; a later Phishing ends it; a Mark safe after that gives it back.
    const fresh = { first: now - DAY, days: 1, count: 1, prof, safe: { at: now - 1000, by: ADMIN } };
    assert.equal(ST.standingFor(fresh, prof, now).kind, 'answer');
    assert.equal(ST.standingFor(Object.assign({}, fresh, { phishAt: now - 500 }), prof, now).ok, false);
});

test('show only (the default): nothing changes, the why says what standing would have done', async () => {
    const t = svcOf();
    assert.equal(t.cfg.senderStanding, 'show');
    const f = await factsOf(), r = aiOnly(f);
    await establish(t, f, r);
    const out = await t.svc.applyStanding(f, r, { action: 'move', trigger: 'ai', why: 'the AI was 95% sure' }, { now: t.at() });
    assert.equal(out.decision.action, 'move', 'still moved');
    assert.match(out.decision.why, /sender standing \(show only\) would have sent it to Review instead of moving it/);
    assert.equal(out.note.ok, true); assert.equal(out.note.effect, 'review'); assert.equal(out.note.kind, 'history');
});

test('on: suspicious → not flagged, moved → Review; a changed pattern, DMARC failing or a forged header → as before', async () => {
    const t = svcOf({ SENDER_STANDING: 'on' });
    const f = await factsOf(), r = aiOnly(f);
    // No standing yet: nothing changes.
    let out = await t.svc.applyStanding(f, r, { action: 'flag', trigger: null, why: 'AI 80%' }, { now: t.at() });
    assert.equal(out.decision.action, 'flag'); assert.equal(out.note.ok, false);
    await establish(t, f, r);
    out = await t.svc.applyStanding(f, r, { action: 'flag', trigger: null, why: 'AI 80%' }, { now: t.at() });
    assert.equal(out.decision.action, 'none', 'not marked suspicious');
    out = await t.svc.applyStanding(f, aiOnly(f, 0.97), { action: 'move', trigger: 'ai', why: 'AI 97%' }, { now: t.at() });
    assert.equal(out.decision.action, 'flag'); assert.equal(out.decision.standing, true); assert.match(out.decision.why, /waits in Review/);
    // A new Reply-To domain: what a taken-over account looks like.
    const f2 = await factsOf({ replyTo: 'billing@madeup-elsewhere.example' });
    out = await t.svc.applyStanding(f2, aiOnly(f2, 0.97), { action: 'move', trigger: 'ai', why: 'AI 97%' }, { now: t.at() });
    assert.equal(out.decision.action, 'move', 'moved as before'); assert.match(out.note.why, /new Reply-To domain/);
    // DMARC failing: no standing at all.
    const f3 = await factsOf({ dmarc: 'fail' });
    out = await t.svc.applyStanding(f3, Object.assign(aiOnly(f3, 0.97), { verified: false }), { action: 'move', trigger: 'ai', why: 'AI 97%' }, { now: t.at() });
    assert.equal(out.decision.action, 'move'); assert.equal(out.note, null);
    // Forged headers (a rule sign), or the rules moving it too: as before.
    out = await t.svc.applyStanding(f, Object.assign(aiOnly(f, 0.97), { strictSigns: { forgedHeaders: ['message-id'] } }), { action: 'move', trigger: 'ai', why: 'x' }, { now: t.at() });
    assert.equal(out.decision.action, 'move');
    out = await t.svc.applyStanding(f, aiOnly(f, 0.97), { action: 'move', trigger: 'rules+ai', why: 'x' }, { now: t.at() });
    assert.equal(out.decision.action, 'move');
    // Off: nothing learned, nothing changed.
    const off = svcOf({ SENDER_STANDING: 'off' });
    await off.svc.learnStanding(f, r, { now: off.at(), day: 'd1' });
    assert.equal(await off.store.getStanding(ST.keyOf('madeupbank.example')), null);
});

test('answers: Mark safe gives standing at once, Phishing ends it, Undo takes either back', async () => {
    const t = svcOf({ SENDER_STANDING: 'on' });
    const f = await factsOf(), r = aiOnly(f);
    const note = (await t.svc.applyStanding(f, r, { action: 'flag', trigger: null, why: 'AI 80%' }, { now: t.at() })).note;
    const rec = { key: `${PAT}|m1`, user: PAT, messageId: 'm1', action: 'flag', state: 'inbox', processedAt: t.at(), sender: { address: 'statements@mail.madeupbank.example', domain: 'mail.madeupbank.example', name: 'Madeup Bank' },
        auth: { dmarc: 'pass' }, verified: true, inside: false, signals: [], standing: note };
    await t.store.saveRecord(rec);
    await t.svc.mark(rec.key, true, ADMIN);
    let out = await t.svc.applyStanding(f, r, { action: 'flag', trigger: null, why: 'AI 80%' }, { now: t.at() + 1000 });
    assert.equal(out.decision.action, 'none', 'Mark safe gave standing'); assert.equal(out.note.kind, 'answer');
    // Phishing on another of its emails ends it.
    const rec2 = Object.assign({}, rec, { key: `${PAT}|m2`, messageId: 'm2', standing: undefined });
    await t.store.saveRecord(rec2);
    t.advance(5000);
    await t.svc.mark(rec2.key, false, ADMIN);
    out = await t.svc.applyStanding(f, r, { action: 'flag', trigger: null, why: 'AI 80%' }, { now: t.at() + 1000 });
    assert.equal(out.decision.action, 'flag', 'Phishing ended it'); assert.match(out.note.why, /answered Phishing/);
    // Undo of the Phishing answer gives it back.
    await t.svc.undoAnswer(rec2.key, ADMIN);
    out = await t.svc.applyStanding(f, r, { action: 'flag', trigger: null, why: 'AI 80%' }, { now: t.at() + 2000 });
    assert.equal(out.decision.action, 'none');
    // Undo of the Mark safe takes it away.
    await t.svc.undoAnswer(rec.key, ADMIN);
    out = await t.svc.applyStanding(f, r, { action: 'flag', trigger: null, why: 'AI 80%' }, { now: t.at() + 3000 });
    assert.equal(out.decision.action, 'flag');
});

test('Review: an email standing kept from being moved waits in Suspicious, even with Ignore suspicious on', () => {
    const cfg = { aiSuspicious: 0.65, ignoreSuspicious: true };
    const held = { key: 'a', action: 'flag', state: 'inbox', status: 'clean', standing: { applied: 'review' } };
    const plain = { key: 'b', action: 'flag', state: 'inbox', status: 'clean', ai: { probability: 0.7 } };
    assert.equal(RQ.baseQueueOf(held, { cfg }), 'suspicious');
    assert.equal(RQ.baseQueueOf(plain, { cfg }), null);
    assert.equal(RQ.baseQueueOf(Object.assign({}, held, { markedBy: ADMIN }), { cfg }), null, 'answered: gone');
});

test('the setting: off, show or on; nothing else', async () => {
    const t = svcOf();
    await t.svc.setPolicy('senderStanding', 'on', ADMIN);
    assert.equal(t.svc.cfg.senderStanding, 'on');
    await assert.rejects(() => t.svc.setPolicy('senderStanding', 'always', ADMIN), /off, show or on/);
    assert.ok((await t.store.listEvents(0)).some(e => /turned on sender standing/.test(e.text)));
});
