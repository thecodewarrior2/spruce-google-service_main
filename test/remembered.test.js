'use strict';
// 0.6.56: remembered Not phishing answers. An admin's Not phishing answers every identical copy (the same sender, subject,
// text, links and attachments: src/remember.js), to anyone, for 90 days, when Gmail confirms the sender and nothing outside
// the email says otherwise; a dismissed campaign's later copies are answered too. Every person and address is made up.
const test = require('node:test');
const assert = require('node:assert');
const { loadConfig } = require('../src/config');
const { Service } = require('../src/pipeline');
const { MemoryStore } = require('../src/store/memory');
const { readMessage } = require('../src/engine/mime');
const { fingerprintOf, linkKey } = require('../src/remember');
const E = require('../src/engine/spruce').load();

const ORG = 'maple-schools.example';
const [PAT, SAM, LEE] = ['pat.fakewell', 'sam.testwood', 'lee.madeup'].map(u => `${u}@${ORG}`);
const ADMIN = `it.madeup@${ORG}`;
let n = 0;
const raw = (to, { from = 'notices@madeup-vendor.example', dmarc = 'pass', subject = 'Action needed: confirm your account by Friday', body = 'Hello, please confirm your account details by Friday using the link below.', link = 'https://portal.madeup-vendor.example/confirm' } = {}) => Buffer.from([
    `From: "Madeup Vendor" <${from}>`, `To: ${to}`, `Subject: ${subject}`, `Message-ID: <m${++n}@madeup-vendor.example>`,
    `Authentication-Results: mx.google.com; spf=${dmarc === 'pass' ? 'pass' : 'fail'}; dkim=${dmarc === 'pass' ? 'pass' : 'none'}; dmarc=${dmarc} header.from=${from.split('@')[1]}`,
    'Content-Type: text/html', '', `<p>${body}</p><p><a href="${link}">Confirm</a></p>`].join('\r\n'));
const facts = async (to, opts) => readMessage(raw(to, opts));

test('the fingerprint: identical copies match; any other text, document, attachment or sender doesn\'t', async () => {
    const a = fingerprintOf(await facts(PAT), PAT), b = fingerprintOf(await facts(SAM), SAM);
    assert.equal(a, b, 'the same email to two people');
    assert.match(a, /^[0-9a-f]{32}$/);
    assert.equal(fingerprintOf(await facts(PAT, { subject: 'Action needed: confirm your account by Friday 11/27' }), PAT), a, 'numbers in the subject don\'t count');
    assert.notEqual(fingerprintOf(await facts(PAT, { body: 'Hello, please send your password today using the link below.' }), PAT), a, 'other words');
    assert.notEqual(fingerprintOf(await facts(PAT, { from: 'billing@madeup-vendor.example' }), PAT), a, 'another sender address');
    // A mailing service's per-copy tracking code: the same; another shared document: different.
    assert.equal(linkKey('https://click.madeup-mailer.example/ls/click/AbC123xyZ987LongTrackingToken?upn=99'), linkKey('https://click.madeup-mailer.example/ls/click/ZzZ999aaa111OtherTrackingTok?upn=12'));
    assert.notEqual(linkKey('https://docs.google.com/document/d/1AbCdEfGhIjKlMnOp/edit'), linkKey('https://docs.google.com/document/d/9ZyXwVuTsRqPoNmLk/edit'));
    assert.equal(linkKey('https://docs.google.com/document/d/1AbCdEfGhIjKlMnOp/edit?utm_source=x'), linkKey('https://docs.google.com/document/d/1AbCdEfGhIjKlMnOp/edit'), 'only utm_ parameters taken out');
    assert.notEqual(fingerprintOf(await facts(PAT, { link: 'https://docs.google.com/document/d/9ZyXwVuTsRqPoNmLk/edit' }), PAT),
        fingerprintOf(await facts(PAT, { link: 'https://docs.google.com/document/d/1AbCdEfGhIjKlMnOp/edit' }), PAT), 'another document');
    const withFile = (content) => fingerprintOf(Object.assign({}, { senderAddress: 'x@madeup.example', subject: 's', visibleText: 't', links: [], attachmentFiles: [{ name: 'a.pdf', type: 'application/pdf', size: 3, content: Buffer.from(content) }] }), PAT);
    assert.notEqual(withFile('one'), withFile('two'), 'another attachment');
});

const make = (mode = 'monitor') => {
    const modified = [];
    const svc = new Service({ cfg: loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: [PAT, SAM, LEE].join(','), MODE: mode, SUSPICIOUS_LABEL: 'on' }), store: new MemoryStore(),
        gmail: { labelId: async (u, nm) => `L_${nm}`, labels: async () => ['INBOX'], modify: async (u, id, add, remove) => { modified.push({ u, id, add, remove }); return {}; } }, log: { error() {}, warn() {} } });
    svc.modified = modified;
    return svc;
};
const judge = async (svc, user, opts = {}) => { n++; return svc.judge(user, { id: `m${n}-${user}`, threadId: `t${n}`, internalDate: Date.now(), labelIds: ['INBOX'] }, await readMessage(raw(user, opts))); };

test('0.6.59: the fingerprint leaves out the name a greeting gives and a subject\'s leading name; the rest still counts', () => {
    const f = (text, subject = 'Your invoice is ready') => fingerprintOf({ senderAddress: 'billing@madeup-vendor.example', subject, visibleText: text, links: [], attachmentFiles: [], people: { to: [] } }, 'jmadeup@maple-schools.example');
    assert.equal(f('Dear Pat,\nYour invoice is attached.\nThanks'), f('Dear Sam,\nYour invoice is attached.\nThanks'), 'Dear Pat / Dear Sam');
    assert.equal(f('Good morning Ms. Samplefield:\nYour invoice is attached.'), f('Good morning Mr. Testwood:\nYour invoice is attached.'));
    assert.equal(f('Hi Pat Madeup,\nYour invoice is attached.'), f('hi sam,\nYour invoice is attached.'));
    assert.equal(f('x', 'Pat, your invoice is ready'), f('x', 'Sam, your invoice is ready'), 'a subject\'s leading name');
    assert.notEqual(f('Dear Pat,\nYour invoice is attached.'), f('Dear Pat,\nYour invoice is attached. Wire the payment today.'), 'other words still count');
    assert.notEqual(f('Dear Pat,\nYour invoice is attached.'), f('Your invoice is attached, dear Pat, and overdue.'), 'only a greeting at the start of a line');
    // (0.6.66) "To" and "Attention" begin ordinary sentences: what follows them still counts.
    assert.notEqual(f('Hello,\nTo view your invoice, open the portal.'), f('Hello,\nTo confirm your password, open the portal.'), 'a To line');
    assert.notEqual(f('Attention all staff, the office closes early.'), f('Attention payroll update required, the office closes early.'), 'an Attention line');
    assert.notEqual(f('Dear valued customer of our bank today,\nX'), f('Dear friend,\nX'), 'only a name (up to three words) after a greeting');
    assert.notEqual(f('x', 'Urgent action needed, now'), f('x', 'Reminder action needed, now'), 'a subject\'s leading name is one word');
    // (0.6.66) The reader's own name is taken out as a whole word only ("sam" isn't taken out of "same").
    const g = (user) => fingerprintOf({ senderAddress: 'billing@madeup-vendor.example', subject: 'Same day delivery', visibleText: 'Your order ships the same day.', links: [], attachmentFiles: [], people: { to: [] } }, user);
    assert.equal(g('sam.testwood@maple-schools.example'), g('pat.fakewell@maple-schools.example'));
});

test('Mark safe on one copy: the waiting copies and every later identical copy answered the same way; a forged one isn\'t', async (t) => {
    const was = E.model.analyze;
    E.model.analyze = async () => ({ probability: 0.97, reasons: [], model: 'phish-tiny', version: 'test' });
    t.after(() => { E.model.analyze = was; });
    const svc = make();
    const first = await judge(svc, PAT), waiting = await judge(svc, SAM);
    assert.equal(first.action, 'would-move', first.why);
    const rec = await svc.store.getRecord(first.key);
    assert.match(rec.fingerprint, /^[0-9a-f]{32}$/);
    assert.equal(rec.verified, true);
    const m = await svc.mark(first.key, true, ADMIN);
    assert.ok(m.record && m.record.falseAlarm);
    // The copy already waiting: answered too.
    const w = await svc.store.getRecord(waiting.key);
    assert.deepEqual([w.falseAlarm, w.markedBy], [true, ADMIN], 'the waiting copy answered');
    assert.ok(svc.store.events.some(e => /identical copies to anyone are answered the same way for 90 days.*1 waiting copy answered now/.test(e.text)));
    // A later copy to someone else: recorded, answered, never moved, no Suspicious label, not counted as flagged.
    const later = await judge(svc, LEE);
    assert.equal(later.action, 'flag', later.why);
    const lr = await svc.store.getRecord(later.key);
    assert.deepEqual([lr.falseAlarm, lr.markedBy, lr.autoAnswered.kind], [true, ADMIN, 'remembered']);
    assert.match(lr.why, /it\.madeup@maple-schools\.example marked an identical email safe, so it is answered the same way and left alone/);
    assert.ok(!svc.modified.some(x => x.id === `m${n}-${LEE}`), 'no label, nothing moved');
    // The list (Settings → Sender lists → Remembered answers).
    const list = await svc.rememberedList();
    assert.equal(list.length, 1);
    assert.equal(list[0].sender, 'notices@madeup-vendor.example');
    assert.equal(list[0].by, ADMIN);
    assert.equal(list[0].was, 'Phishing (would move)', '(0.6.59) what the service had taken it for');
    // A forged copy (Gmail couldn't confirm the sender) is judged as usual.
    const forged = await judge(svc, LEE, { dmarc: 'fail' });
    assert.notEqual((await svc.store.getRecord(forged.key)).markedBy, ADMIN, 'not answered');
    // Another email from the same sender, with the same subject: judged as usual.
    const other = await judge(svc, LEE, { body: 'Hello, your mailbox will close today unless you sign in at the link below.' });
    assert.equal((await svc.store.getRecord(other.key)).markedBy, null);
    // Removed: later copies judged as usual again.
    await svc.forgetAnswer(list[0].id, ADMIN);
    const again = await judge(svc, LEE);
    assert.equal((await svc.store.getRecord(again.key)).markedBy, null);
});

test('Undo takes the remembered answer back; nothing strong is ever answered; a dismissed campaign\'s later copies are answered', async (t) => {
    const was = E.model.analyze;
    E.model.analyze = async () => ({ probability: 0.97, reasons: [], model: 'phish-tiny', version: 'test' });
    t.after(() => { E.model.analyze = was; });
    const svc = make();
    const first = await judge(svc, PAT);
    await svc.mark(first.key, true, ADMIN);
    assert.equal((await svc.rememberedList()).length, 1);
    await svc.undoAnswer(first.key, ADMIN);
    assert.equal((await svc.rememberedList()).length, 0, 'undone');
    // Strong evidence (a link on a phishing list, a failed sender check…) is never answered by a remembered answer.
    await svc.mark(first.key, true, ADMIN);
    const fp = (await svc.store.getRecord(first.key)).fingerprint;
    assert.equal(await svc.autoAnswerOf({ fingerprint: fp, strong: true, links: [] }, true, { trigger: 'rules' }, 'x'), null);
    assert.equal(await svc.autoAnswerOf({ fingerprint: fp, links: [{ severity: 'danger' }] }, true, { trigger: 'ai' }, 'x'), null);
    assert.equal(await svc.autoAnswerOf({ fingerprint: fp, links: [] }, true, { trigger: 'spam' }, 'x'), null, 'not phishing isn\'t not spam');
    assert.deepEqual(await svc.autoAnswerOf({ fingerprint: fp, links: [] }, true, { trigger: 'ai' }, 'x'), { kind: 'remembered', by: ADMIN });
    // A dismissed campaign: its later copies (another text, the same sender domain and subject) are answered too.
    const other = await judge(svc, SAM, { body: 'Hello, a different note about confirming your account by Friday.' });
    const orec = await svc.store.getRecord(other.key);
    await svc.releaseCampaign(orec.campaign, ADMIN);
    const later = await judge(svc, LEE, { body: 'Hello, yet another wording about confirming your account by Friday.' });
    const lr = await svc.store.getRecord(later.key);
    assert.deepEqual([lr.falseAlarm, lr.autoAnswered && lr.autoAnswered.kind], [true, 'campaign'], lr.why);
    assert.match(lr.why, /dismissed this campaign as a false alarm, so it is answered the same way/);
});
