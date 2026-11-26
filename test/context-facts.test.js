'use strict';
// 0.6.85: the facts beyond an email's text, gathered for the AI's next input format (src/context-facts.js): Gmail's
// category, the unsubscribe marker, the mailing service, the sender's history (with what differs this time), the
// conversation, how many of your people got it, the sender's domain age; and the words in documents and pictures for the
// retraining export. The current model doesn't read them: no verdict changes. Every person, address, domain and file is
// made up.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { PDFDocument } = require('pdf-lib');
const { zipSync, strToU8 } = require('fflate');
const CF = require('../src/context-facts');
const ST = require('../src/standing');
const { readAttachments } = require('../src/engine/attachments');
const ocr = require('../src/engine/ocr');
const { readMessage } = require('../src/engine/mime');
const { analyze } = require('../src/engine/analyze');
const { loadConfig } = require('../src/config');
const { Service } = require('../src/pipeline');
const { MemoryStore } = require('../src/store/memory');
const training = require('../src/training');
const E = require('../src/engine/spruce').load();

const ORG = 'maple-schools.example', PAT = `pat.fakewell@${ORG}`, LEE = `lee.samplefield@${ORG}`;
const DAY = 24 * 60 * 60 * 1000;
let n = 0;
const raw = ({ to = PAT, subject = 'Your statement is ready', head = [], link = 'https://secure.madeupbank.example/statement', text = 'Your November statement is ready.' } = {}) => Buffer.from([
    'From: "Madeup Bank" <statements@mail.madeupbank.example>', `To: ${to}`, `Subject: ${subject}`, `Message-ID: <c${++n}@madeupbank.example>`, ...head,
    'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=bounce.madeupbank.example; dkim=pass header.i=@madeupbank.example; dkim=pass header.i=@mailer.madeup-esp.example; dmarc=pass header.from=mail.madeupbank.example',
    'Content-Type: text/html', '', `<p>${text}</p><p><a href="${link}">View statement</a></p>`].join('\r\n'));

test('the facts: Gmail\'s category, the unsubscribe marker, the conversation, the mailing service', async () => {
    assert.equal(CF.categoryOf(['INBOX', 'CATEGORY_UPDATES']), 'updates');
    assert.equal(CF.categoryOf(['INBOX', 'CATEGORY_PERSONAL']), 'primary');
    assert.equal(CF.categoryOf(['INBOX']), null, 'none: unknown');
    const plain = await readMessage(raw());
    assert.equal(CF.unsubscribeOf(plain), null);
    const listed = await readMessage(raw({ head: ['List-Unsubscribe: <https://mail.madeupbank.example/u/1>'] }));
    assert.equal(CF.unsubscribeOf(listed), 'listed', 'a List-Unsubscribe header the sender didn\'t sign for one click');
    assert.deepEqual(CF.threadOf(plain, null), { reply: false, size: null, readerWrote: null });
    const reply = await readMessage(raw({ subject: 'RE: your question', head: ['In-Reply-To: <a1@maple-schools.example>'] }));
    assert.deepEqual(CF.threadOf(reply, { size: 3, readerWrote: true }), { reply: true, size: 3, readerWrote: true }, 'a real answer to the reader\'s own email');
    assert.deepEqual(CF.threadOf(reply, { size: 1, readerWrote: false }), { reply: true, size: 1, readerWrote: false }, 'a "RE:" answering nothing in the mailbox');
    assert.equal(CF.mailerOf(E, plain, ['https://secure.madeupbank.example/statement']), 'madeup-esp.example', 'a third party\'s verified DKIM signature');
});

test('the history: a first email, a regular sender, a regular sender writing differently (an account taken over), a Phishing answer', async () => {
    const now = Date.UTC(2026, 11, 1);
    const f = await readMessage(raw());
    const usual = { linkUrls: ['https://secure.madeupbank.example/statement'] };
    const prof = ST.profileOf(E, f, usual);
    assert.deepEqual(CF.historyOf(null, prof, now, now - 1000), { first: true }, 'first seen today');
    assert.deepEqual(CF.historyOf(null, prof, now, now - 10 * DAY), { days: 10, emails: 0 }, 'seen, but no clean confirmed mail counted');
    assert.equal(CF.historyOf(undefined, prof, now, undefined), null, 'unknown');
    const doc = { first: now - 90 * DAY, days: 20, count: 45, prof };
    assert.deepEqual(CF.historyOf(doc, prof, now), { days: 90, emails: 45, activeDays: 20, safe: false, phish: false, breaks: [] });
    const odd = ST.profileOf(E, await readMessage(raw({ link: 'https://madeupbank-docs.example/view', head: ['Reply-To: billing@madeup-elsewhere.example'] })), { linkUrls: ['https://madeupbank-docs.example/view'] });
    assert.deepEqual(CF.historyOf(doc, odd, now).breaks, ['reply', 'links'], 'a new Reply-To and a link site it never used: how a known sender taken over looks');
    assert.equal(CF.historyOf(Object.assign({}, doc, { phishAt: now - DAY }), prof, now).phish, true);
});

test('cleanContext keeps only labels, counts and yes/no answers', () => {
    const c = CF.cleanContext({ category: 'updates', unsubscribe: 'listed', mailer: 'Madeup <b>ESP</b>', recipients: 12.4, senderAgeDays: 3650,
        history: { days: 90, emails: 45, activeDays: 20, safe: true, breaks: ['links', 'evil'], extra: 'x' }, thread: { reply: true, size: 2, readerWrote: false }, bodyText: 'never kept', category2: 'x' });
    assert.deepEqual(c, { category: 'updates', unsubscribe: 'listed', mailer: 'Madeup bESPb', history: { days: 90, emails: 45, activeDays: 20, safe: true, breaks: ['links'] },
        thread: { reply: true, size: 2, readerWrote: false }, recipients: 12, senderAgeDays: 3650 });
    assert.equal(CF.cleanContext({ category: 'secret-tab' }).category, null);
});

test('documents\' words (PDF, Word, Excel), and pictures\' words only when asked (OCR, nothing downloaded)', async () => {
    const doc = await PDFDocument.create();
    doc.addPage([600, 400]).drawText('Invoice 1001 is past due. Pay by Friday.', { x: 40, y: 300, size: 14 });
    const pdf = Buffer.from(await doc.save());
    const docx = Buffer.from(zipSync({ '[Content_Types].xml': strToU8('<Types/>'), 'word/document.xml': strToU8('<w:document><w:body><w:p><w:r><w:t>Please review the</w:t></w:r><w:r><w:t xml:space="preserve"> new schedule &amp; sign.</w:t></w:r></w:p></w:body></w:document>') }));
    const xlsx = Buffer.from(zipSync({ '[Content_Types].xml': strToU8('<Types/>'), 'xl/sharedStrings.xml': strToU8('<sst><si><t>Vendor bank change form</t></si><si><t>Routing</t></si></sst>') }));
    const r = await readAttachments([{ name: 'invoice.pdf', type: 'application/pdf', content: pdf }, { name: 'schedule.docx', type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', content: docx },
        { name: 'form.xlsx', type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', content: xlsx }]);
    assert.match(r.attachmentText, /Invoice 1001 is past due\. Pay by Friday\./);
    assert.match(r.attachmentText, /Please review the new schedule & sign\./);
    assert.match(r.attachmentText, /Vendor bank change form\nRouting/);
    // (read twice: the second from the memo, same words)
    assert.equal((await readAttachments([{ name: 'invoice.pdf', type: 'application/pdf', content: pdf }])).attachmentText, 'Invoice 1001 is past due. Pay by Friday.');
    const png = fs.readFileSync(path.join(__dirname, 'fixtures', 'ocr-made-up.png'));
    const pic = [{ name: 'notice.png', type: 'image/png', content: png }];
    assert.equal((await readAttachments(pic)).pictureText, '', 'on arrival pictures aren\'t read for words');
    const proxy = process.env.HTTPS_PROXY;
    process.env.HTTPS_PROXY = 'http://127.0.0.1:9';   // nothing may be downloaded
    try {
        const t = (await readAttachments(pic, { readPictures: true })).pictureText;
        assert.match(t, /mailbox is almost full/i);
        assert.match(t, /Sign in today/i);
    } finally { if (proxy === undefined) delete process.env.HTTPS_PROXY; else process.env.HTTPS_PROXY = proxy; await ocr.stop(); }
    assert.equal(ocr.tidy('a\n|| ~ .\nVerify your account now'), 'Verify your account now', 'OCR noise lines dropped');
});

test('analyze: the facts reach aiFacts.extra and the result, the model\'s input doesn\'t change', async () => {
    const f = await readMessage(raw());
    const base = await analyze(f, { mailbox: PAT, orgDomains: [ORG] });
    const now = Date.UTC(2026, 11, 1);
    const withFacts = await analyze(f, { mailbox: PAT, orgDomains: [ORG], keepAiFacts: true, now, firstSeenAt: now - 5 * DAY, standingDoc: null,
        extraFacts: CF.arrivalFacts({ labelIds: ['INBOX', 'CATEGORY_UPDATES'], facts: f, recipients: 3 }) });
    assert.deepEqual(withFacts.extraFacts, { category: 'updates', unsubscribe: null, mailer: 'madeup-esp.example', history: { days: 5, emails: 0 }, thread: { reply: false, size: null, readerWrote: null }, recipients: 3, senderAgeDays: null });
    assert.equal(withFacts.aiFacts.extra.category, 'updates');
    assert.equal(withFacts.aiFacts.extra.attachmentText, '');
    assert.equal(base.aiFacts, undefined, 'the words of documents and pictures only for the retraining export');
    assert.equal(withFacts.ai.probability, base.ai.probability, 'format 3 doesn\'t read them: the same score');
    assert.equal(E.modelInputText(withFacts.aiFacts), E.modelInputText(Object.assign({}, withFacts.aiFacts, { extra: undefined })), 'the same input');
});

test('the pipeline: recorded on the email (aiContext), copies counted across the organization, the export carries them', async () => {
    let now = Date.UTC(2026, 11, 1, 15);
    const store = new MemoryStore();
    const raws = new Map();
    const gmail = {
        raw: async (u, id) => ({ id, threadId: 't', labelIds: ['INBOX', 'CATEGORY_UPDATES'], internalDate: now, raw: raws.get(`${u}|${id}`) }),
        threadInfo: async () => ({ size: 1, readerWrote: false }),
        labelId: async (u, l) => `L_${l}`, modify: async () => ({})
    };
    const cfg = loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: `${PAT},${LEE}`, MODE: 'monitor' });
    const svc = new Service({ cfg, store, gmail, log: { error() {}, warn() {} }, now: () => now });
    // A lure every rule flags (a phishing-list look-alike login page, a fake reply), sent to two people.
    const lure = (to) => raw({ to, subject: 'RE: Payment', head: ['In-Reply-To: <x9@madeup-elsewhere.example>'], link: 'https://madeupbank-login.example/verify', text: 'Your account is locked. Verify your password now to avoid suspension.' });
    const recs = [];
    for (const u of [PAT, LEE]) {
        const id = `m${++n}`;
        raws.set(`${u}|${id}`, lure(u));
        const r = await svc.judge(u, { id, threadId: 't', labelIds: ['INBOX', 'CATEGORY_UPDATES'], internalDate: now }, await readMessage(raws.get(`${u}|${id}`)));
        recs.push(r);
        now += 1000;
    }
    const all = await store.listRecords({ sinceMs: 0 });
    const ctx = all.map(r => r.aiContext).filter(Boolean);
    assert.equal(ctx.length, 2, 'both copies flagged and recorded');
    assert.equal(ctx[0].category, 'updates');
    assert.deepEqual(ctx[0].thread, { reply: true, size: 1, readerWrote: false });
    assert.deepEqual(ctx.map(c => c.recipients).sort(), ctx.length === 2 ? [1, 2] : [ctx[0].recipients], 'the second copy knows the first');
    assert.ok(!JSON.stringify(ctx).includes('Verify your password'), 'no content on the record');
    await svc.flushStats();
    assert.equal(await svc.copiesSoFar(all[0].campaign, svc.dayOf(now)), 2, 'written with the day\'s counters');
    // The export: as on arrival.
    await svc.setTrainingExport(true, `it.madeup@${ORG}`);
    for (const r of all) await svc.mark(r.key, false, `it.madeup@${ORG}`);
    const out = await svc.trainingExport({ by: `it.madeup@${ORG}` });
    assert.equal(out.rows.length, 1, 'one per campaign');
    const x = out.rows[0].facts.extra;
    assert.equal(x.category, 'updates');
    assert.equal(x.thread.reply, true);
    assert.ok(!training.problems(out.rows[0]).some(p => /address|phone/.test(p)), 'nothing personal in it');
});
