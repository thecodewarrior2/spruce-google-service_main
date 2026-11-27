'use strict';
// 0.6.98: a sender's history from Gmail (src/mailbox-history.js): asked of the reader's mailbox when the service doesn't know
// the sender yet, cached for the organization. Every address and email here is made up.
const test = require('node:test');
const assert = require('node:assert');
const { MailboxHistory, historyFromGmail } = require('../src/mailbox-history');
const CF = require('../src/context-facts');
const { loadConfig } = require('../src/config');
const { Service } = require('../src/pipeline');
const { MemoryStore } = require('../src/store/memory');
const { readMessage } = require('../src/engine/mime');

const ORG = 'maple-schools.example', PAT = `pat.fakewell@${ORG}`, SAM = `sam.testwood@${ORG}`;
// A mailbox's search results: per address, the ages (in days) of the emails it has from them, and whether it wrote to them.
const fakeGmail = (book) => {
    const calls = [];
    return { calls, searchCount: async (user, q) => {
        calls.push(q);
        if (q.startsWith('older_than:')) return { any: book.__young ? false : true, estimate: 1 };   // the mailbox holds old mail
        const m = /^(from|in:sent to):?\s*([^\s]+)(?: older_than:(\d+)([dy]))?$/.exec(q.replace('in:sent to:', 'in:sent to: '));
        const sent = q.startsWith('in:sent');
        const addr = sent ? q.split('to:')[1].trim() : q.split(' ')[0].slice(5);
        const b = book[addr] || { ages: [], wrote: false };
        if (sent) return { any: !!b.wrote, estimate: b.wrote ? 3 : 0 };
        const older = /older_than:(\d+)([dy])/.exec(q);
        const min = older ? Number(older[1]) * (older[2] === 'y' ? 365 : 1) : 0;
        const hits = b.ages.filter(a => a > min);
        return { any: hits.length > 0, estimate: hits.length };
    } };
};

test('the lookup: older mail (a day, a month, a year), about how much, and whether anyone wrote to them; asked once, then cached', async () => {
    const gmail = fakeGmail({ 'billing@vendor.example': { ages: [2, 40, 500, 900], wrote: true }, 'new@stranger.example': { ages: [] } });
    const store = new MemoryStore();
    const mh = new MailboxHistory({ gmail, store });
    assert.deepEqual(Object.assign({}, await mh.of(PAT, 'billing@vendor.example', 'h1'), { at: 0 }), { received: 4, ageDays: 365, wrote: true, deep: true, at: 0 });
    const n = gmail.calls.length;
    await mh.of(SAM, 'billing@vendor.example', 'h1');
    assert.equal(gmail.calls.length, n, 'cached for the whole organization: no more Gmail calls');
    const mh2 = new MailboxHistory({ gmail, store });
    await mh2.of(SAM, 'billing@vendor.example', 'h1');
    assert.equal(gmail.calls.length, n, 'and in the shared store, for the other instances');
    const none = await mh.of(PAT, 'new@stranger.example', 'h2');
    assert.deepEqual([none.received, none.ageDays, none.wrote], [0, 0, false]);
    assert.ok(!gmail.calls.some(q => /older_than:30d/.test(q) && q.includes('stranger')), 'no further questions once nothing is older than a day');
    assert.deepEqual(historyFromGmail(none), { first: true });
    assert.deepEqual(historyFromGmail({ received: 4, ageDays: 365, wrote: true }), { days: 365, emails: 4 });
    assert.equal(await new MailboxHistory({ gmail: {}, store }).of(PAT, 'x@y.example', 'h3'), null, 'no search: unknown');
});

test('the AI\'s history: Gmail\'s where the service\'s is missing, too new, or "first"', () => {
    const E = require('../src/engine/spruce').load();
    const now = Date.UTC(2026, 11, 20), DAY = 86400000;
    const facts = { senderAddress: 'billing@vendor.example', subject: 'Invoice', links: [] };
    const h = (o) => CF.checkFacts(E, facts, { linkUrls: [] }, Object.assign({ now }, o)).history;
    const gh = { received: 40, ageDays: 365, wrote: true };
    assert.deepEqual(h({ firstSeenAt: now, historySince: now + 5 * DAY, gmailHistory: gh }), { days: 365, emails: 40 }, 'new install');
    assert.deepEqual(h({ firstSeenAt: now - 3600000, gmailHistory: gh }), { days: 365, emails: 40 }, 'the service\'s "first" email');
    assert.equal(h({ standingDoc: { first: now - 90 * DAY, count: 20, days: 15, prof: {} }, firstSeenAt: now - 90 * DAY, gmailHistory: gh }).emails, 20, 'the service\'s own, when it has it');
});

test('the service: from the install on, a known sender is no "first email", a new one is; forged or inside senders aren\'t looked up', async () => {
    const store = new MemoryStore();
    const gmail = Object.assign(fakeGmail({ 'billing@longtime-vendor.example': { ages: [3, 60, 800], wrote: true } }), { labelId: async (u, l) => `L_${l}`, modify: async () => ({}) });
    const cfg = loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: PAT, MODE: 'monitor' });
    const svc = new Service({ cfg, store, gmail, log: { error() {}, warn() {} } });
    let n = 0;
    const mail = (from, dmarc = 'pass') => Buffer.from([`From: Billing <${from}>`, `To: ${PAT}`, 'Subject: Your statement', `Message-ID: <h${++n}@x.example>`,
        `Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=${from.split('@')[1]}; dkim=pass header.i=@${from.split('@')[1]}; dmarc=${dmarc} header.from=${from.split('@')[1]}`,
        'Content-Type: text/plain', '', 'Your monthly statement is ready. Please review the attached summary of your account activity.'].join('\r\n'));
    const judge = async (from, dmarc) => { const r = await svc.judge(PAT, { id: `m${n}`, threadId: `t${n}`, labelIds: ['INBOX'], internalDate: Date.now() }, await readMessage(mail(from, dmarc))); return r.key ? store.getRecord(r.key) : null; };
    const known = await judge('billing@longtime-vendor.example');
    assert.ok(!known || !known.signals.some(x => x.kind === 'first-time'), 'a sender this mailbox has had mail from for years');
    const fresh = await judge('billing@brand-new-vendor.example');
    assert.ok(fresh && fresh.signals.some(x => x.kind === 'first-time'), 'Gmail has nothing from it: a first email, even on the install\'s first day');
    const before = gmail.calls.length;
    await judge('billing@forged-vendor.example', 'fail');
    await judge(`office@${ORG}`);
    assert.equal(gmail.calls.length, before, 'not asked for a sender Gmail couldn\'t confirm, nor for mail from inside');
});

test('a new Google Workspace (mailboxes with nothing over 30 days old): "nothing from this sender" means nothing; one mailbox\'s "nothing" isn\'t another\'s', async () => {
    const DAY = 86400000;
    const young = Object.assign(fakeGmail({ 'billing@vendor.example': { ages: [] } }), {});
    const store = new MemoryStore();
    const mh = new MailboxHistory({ gmail: { searchCount: async (u, q) => (q.startsWith('older_than:') ? { any: false, estimate: 0 } : young.searchCount(u, q)) }, store });
    const h = await mh.of(PAT, 'billing@vendor.example', 'k1', 'boxPat');
    assert.equal(h.deep, false);
    assert.equal(historyFromGmail(h), null, 'unknown for the AI, not "first"');
    // Another, older mailbox that has years of mail from the same sender isn't given Pat's "nothing".
    const mh2 = new MailboxHistory({ gmail: fakeGmail({ 'billing@vendor.example': { ages: [400] } }), store });
    assert.equal((await mh2.of(SAM, 'billing@vendor.example', 'k1', 'boxSam')).received, 1);
    // The service on a new Workspace's first day: no "first email" sign (the learning period's rule applies).
    const svcStore = new MemoryStore();
    const gmail = { searchCount: async (u, q) => ({ any: false, estimate: 0 }), labelId: async (u, l) => `L_${l}`, modify: async () => ({}) };
    const svc = new Service({ cfg: loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: PAT, MODE: 'monitor' }), store: svcStore, gmail, log: { error() {}, warn() {} } });
    const raw = Buffer.from(['From: Billing <billing@vendor.example>', `To: ${PAT}`, 'Subject: Your statement', 'Message-ID: <nw1@x.example>',
        'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=vendor.example; dkim=pass header.i=@vendor.example; dmarc=pass header.from=vendor.example', 'Content-Type: text/plain', '', 'Your monthly statement is ready.'].join('\r\n'));
    const r = await svc.judge(PAT, { id: 'nw1', threadId: 't', labelIds: ['INBOX'], internalDate: Date.now() }, await readMessage(raw));
    const rec = r.key ? await svcStore.getRecord(r.key) : null;
    assert.ok(!rec || !rec.signals.some(x => x.kind === 'first-time'), 'a new Workspace: no "first email" for everyone');
    assert.ok(DAY);
});
