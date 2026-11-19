'use strict';
// 0.6.39: answers behave the same wherever they are given, and can be undone. Every sender, address and email here is
// made up.
const test = require('node:test');
const assert = require('node:assert');
const { loadConfig } = require('../src/config');
const { Service } = require('../src/pipeline');
const { MemoryStore } = require('../src/store/memory');
const { readMessage } = require('../src/engine/mime');

const ORG = 'maple-schools.example';
const [PAT, SAM] = ['pat.fakewell', 'sam.testwood'].map(u => `${u}@${ORG}`);
const ADMIN = `it.madeup@${ORG}`;
let n = 0;
// A brand's name from another domain (5): moved (enforce), recorded as would-move (monitor).
const raw = (to, subject = 'Your rewards statement') => Buffer.from([
    `From: "PayPal Rewards" <rewards@mail.points-club.example>`, `To: ${to}`, `Subject: ${subject}`, `Message-ID: <p${++n}@mail.points-club.example>`,
    'Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass header.from=mail.points-club.example', 'Content-Type: text/plain', '', 'Your points statement is ready.'].join('\r\n'));
function make(mode = 'enforce') {
    const calls = [];
    const gmail = { labelId: async (u, nm) => `L_${nm}`, labels: async () => ['INBOX'], modify: async (u, id, add, remove) => { calls.push({ id, add, remove }); return {}; } };
    return { svc: new Service({ cfg: loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: [PAT, SAM].join(','), MODE: mode }), store: new MemoryStore(), gmail, log: { error() {}, warn() {} } }), calls };
}
const judge = async (svc, user, subject) => svc.judge(user, { id: `m${n + 1}-${user}`, threadId: `t${n + 1}`, internalDate: Date.now() }, await readMessage(raw(user, subject)));

test('Undo puts back the answer, the move it made and the sender it added', async () => {
    const { svc } = make('monitor');
    const r = await judge(svc, PAT);
    assert.equal(r.action, 'would-move');
    const out = await svc.mark(r.key, false, ADMIN, { spam: true, addSender: true });
    assert.equal(out.spamSenderAdded, 'mail.points-club.example');
    let rec = await svc.store.getRecord(r.key);
    assert.deepEqual([rec.falseAlarm, rec.spam, rec.markedBy], [false, true, ADMIN]);
    const undone = await svc.undoAnswer(r.key, ADMIN);
    assert.ok(undone.record);
    rec = await svc.store.getRecord(r.key);
    assert.deepEqual([rec.falseAlarm, !!rec.spam, rec.markedBy || null, rec.undo], [null, false, null, null], 'unanswered again');
    assert.deepEqual(await svc.spamSenderList(), [], 'the sender it added is off the list again');
    assert.equal((await svc.undoAnswer(r.key, ADMIN)).status, 409, 'one step only');
});

test('Undo of an answer that moved the email moves it back', async () => {
    const { svc, calls } = make('enforce');
    await svc.addSpamSender('elsewhere.example', ADMIN);
    // An email recorded but left in the Inbox (suspicious): answering Spam moves it.
    const r = await judge(svc, PAT);
    await svc.store.updateRecord(r.key, { action: 'flag', state: 'inbox' });
    const m = await svc.mark(r.key, false, ADMIN, { spam: true, move: true });
    assert.equal(m.moved, 'moved');
    await svc.undoAnswer(r.key, ADMIN);
    const rec = await svc.store.getRecord(r.key);
    assert.equal(rec.state, 'inbox');
    assert.ok(calls.some(c => c.add.includes('INBOX') && c.remove.includes('SPAM')), 'back in the Inbox');
});

test('a campaign\'s answers: Not sure clears Spam, Confirm clears earlier answers, False alarm answers each copy fully', async () => {
    const { svc } = make('monitor');
    const a = await judge(svc, PAT, 'Points week');
    const b = await judge(svc, SAM, 'Points week');
    const key = (await svc.store.getRecord(a.key)).campaign;
    await svc.mark(a.key, false, ADMIN, { spam: true });
    await svc.setAside(a.key, ADMIN);
    assert.equal((await svc.store.getRecord(a.key)).spam, false, 'Not sure after Spam: no Spam verdict left');
    const sp = await svc.answerCampaign(key, 'spam', ADMIN);
    assert.equal(sp.done, 2, 'every copy');
    await svc.confirmCampaign(key, ADMIN);
    for (const k of [a.key, b.key]) { const rec = await svc.store.getRecord(k); assert.deepEqual([rec.falseAlarm, rec.spam, rec.unclear], [false, false, false]); }
    await svc.releaseCampaign(key, ADMIN);
    for (const k of [a.key, b.key]) assert.equal((await svc.store.getRecord(k)).falseAlarm, true, 'answered Not phishing, replacing phishing');
});
