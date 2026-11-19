'use strict';
// 0.6.52: Promotional mail (src/promotional.js): Gmail's Promotions category, or a one-click unsubscribe the sender signed,
// from a verified outside sender the checks found nothing in. Never moved for that: listed in Review → Promotional, where
// an admin answers once per company (Spam, or Keep). Every sender, address and email here is made up.
const test = require('node:test');
const assert = require('node:assert');
const { loadConfig } = require('../src/config');
const { Service } = require('../src/pipeline');
const { MemoryStore } = require('../src/store/memory');
const { readMessage } = require('../src/engine/mime');
const { promotionalSigns, oneClickSigned } = require('../src/promotional');

const ORG = 'maple-schools.example';
const [PAT, SAM] = ['pat.fakewell', 'sam.testwood'].map(u => `${u}@${ORG}`);
const ADMIN = `it.madeup@${ORG}`;
let n = 0;
// A store's newsletter: signed one-click unsubscribe (both headers in the DKIM signature of the From's organization) unless
// told otherwise.
const raw = (to, { from = 'deals@em.bigstore.example', dmarc = 'pass', dkimDomain = 'bigstore.example', oneClick = true, signed = true, subject } = {}) => Buffer.from([
    `From: "Bigstore Weekly Deals" <${from}>`, `To: ${to}`, `Subject: ${subject || `Weekend sale, part ${++n}`}`, `Message-ID: <p${n}@em.bigstore.example>`,
    `DKIM-Signature: v=1; a=rsa-sha256; d=${dkimDomain}; s=k1; h=from:to:subject${signed ? ':list-unsubscribe:list-unsubscribe-post' : ''}; bh=x; b=y`,
    `Authentication-Results: mx.google.com; dkim=${dmarc === 'pass' ? 'pass' : 'none'} header.i=@${dkimDomain}; spf=pass; dmarc=${dmarc} header.from=${from.split('@')[1]}`,
    'List-Unsubscribe: <https://em.bigstore.example/u/abc>, <mailto:u@em.bigstore.example>',
    ...(oneClick ? ['List-Unsubscribe-Post: List-Unsubscribe=One-Click'] : []),
    'Content-Type: text/plain', '', 'Thirty percent off headphones this weekend. Shop the sale on our site.'].join('\r\n'));
const make = (mode = 'enforce', extra = {}) => {
    const modified = [];
    const svc = new Service({ cfg: loadConfig(Object.assign({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: [PAT, SAM].join(','), MODE: mode }, extra)), store: new MemoryStore(),
        gmail: { labelId: async (u, nm) => `L_${nm}`, labels: async () => ['INBOX'], modify: async (u, id, add, remove) => { modified.push({ u, id, add, remove }); return {}; } }, log: { error() {}, warn() {} } });
    svc.modified = modified;
    return svc;
};
const judge = async (svc, user, opts = {}, labelIds = ['INBOX']) => svc.judge(user, { id: `m${n}-${user}`, threadId: `t${n}`, internalDate: Date.now(), labelIds }, await readMessage(raw(user, opts)));

test('the signs: a signed one-click unsubscribe, or Gmail\'s Promotions category; nothing else counts', async () => {
    const facts = async (opts) => readMessage(raw(PAT, opts));
    assert.equal(oneClickSigned(await facts()), true);
    assert.equal(oneClickSigned(await facts({ oneClick: false })), false, 'List-Unsubscribe alone: any list mail, receipts too');
    assert.equal(oneClickSigned(await facts({ signed: false })), false, 'not under the signature: anyone could add it');
    assert.equal(oneClickSigned(await facts({ dkimDomain: 'mailer-platform.example' })), false, 'signed only by the platform, not the company');
    assert.equal(oneClickSigned(await facts({ dmarc: 'fail' })), false, 'DKIM not passing');
    assert.deepEqual(promotionalSigns(await facts({ oneClick: false }), ['INBOX', 'CATEGORY_PROMOTIONS']), ['Gmail put it in its Promotions category']);
    assert.deepEqual(promotionalSigns(await facts({ oneClick: false }), ['INBOX', 'CATEGORY_UPDATES']), []);
});

test('promotional mail is recorded for Review, never moved; labeled in enforce mode only; filed under the company, not the platform', async () => {
    const svc = make();
    const r = await judge(svc, PAT);
    assert.deepEqual([r.action, r.trigger, r.state], ['promo', 'promotional', 'inbox']);
    const rec = await svc.store.getRecord(r.key);
    assert.equal(rec.promotional.company, 'bigstore.example', 'the From address\'s organization');
    assert.match(rec.why, /one-click unsubscribe/);
    assert.ok(svc.modified.some(m => m.add.includes('L_SPRUCE/Promotional')), 'its label');
    assert.ok(!svc.modified.some(m => m.add.includes('SPAM')), 'never moved for being promotional');
    const monitor = make('monitor');
    assert.equal((await judge(monitor, PAT)).action, 'promo');
    assert.equal(monitor.modified.length, 0, 'monitor mode leaves mailboxes untouched');
    assert.equal((await judge(make('enforce', { PROMOTIONAL: 'off' }), PAT)).action, 'none', 'turned off');
});

test('not for forged, inside, allowlisted or taken-back senders; Gmail\'s category alone is enough', async () => {
    const svc = make('enforce', { ALLOW_ADDRESSES: 'news@trusted-store.example' });
    assert.notEqual((await judge(svc, PAT, { dmarc: 'fail' })).action, 'promo', 'unverified: judged as usual');
    assert.equal((await judge(svc, PAT, { from: `news@${ORG}`, dkimDomain: ORG })).action, 'none', 'staff newsletters are never promotional');
    assert.equal((await judge(svc, PAT, { from: 'news@trusted-store.example', dkimDomain: 'trusted-store.example' })).action, 'none', 'allowlisted');
    await svc.rememberSpamRescue(SAM, 'deals@em.bigstore.example');
    assert.equal((await judge(svc, SAM)).action, 'none', 'Sam took this company\'s spam back out of Spam');
    assert.equal((await judge(svc, PAT, { oneClick: false }, ['INBOX', 'CATEGORY_PROMOTIONS'])).action, 'promo');
    assert.equal((await judge(svc, PAT, { oneClick: false }, ['INBOX'])).action, 'none', 'neither sign');
});

test('Keep: the company leaves Review and its later mail isn\'t listed; removing it lists it again', async () => {
    const svc = make();
    const a = await judge(svc, PAT), b = await judge(svc, SAM, { from: 'news@bigstore.example' });
    const other = await judge(svc, PAT, { from: 'deals@shop.otherstore.example', dkimDomain: 'otherstore.example' });
    assert.equal((await svc.promoWaiting('bigstore.example')).length, 2, 'two addresses, one company');
    const out = await svc.answerPromotional('bigstore.example', 'keep', ADMIN);
    assert.equal(out.done, 2);
    assert.ok((await svc.store.getRecord(a.key)).promoKept && (await svc.store.getRecord(b.key)).promoKept);
    assert.ok(!(await svc.store.getRecord(other.key)).promoKept, 'another company: still waiting');
    assert.deepEqual((await svc.promoKeptList()).map(x => x.company), ['bigstore.example']);
    assert.equal((await judge(svc, PAT)).action, 'none', 'kept: not listed again');
    await svc.removePromoKept('bigstore.example', ADMIN, { undoKeys: out.keys });
    assert.ok(!(await svc.store.getRecord(a.key)).promoKept, 'Undo: back in Review');
    assert.equal((await judge(svc, PAT)).action, 'promo');
    assert.equal((await svc.answerPromotional('', 'keep', ADMIN)).status, 400);
});

test('Spam: each waiting email answered Spam (moved in enforce mode), its sender on Spam senders by the usual rule; later mail goes to Spam', async () => {
    const svc = make();
    const a = await judge(svc, PAT);
    const out = await svc.answerPromotional('bigstore.example', 'spam', ADMIN, { addSender: true });
    assert.equal(out.done, 1);
    assert.equal(out.moved, 1);
    const rec = await svc.store.getRecord(a.key);
    assert.deepEqual([rec.state, rec.spam, rec.falseAlarm, rec.markedBy], ['moved', true, false, ADMIN]);
    assert.deepEqual(out.spamSendersAdded, ['em.bigstore.example'], 'the mailing subdomain, not the whole company: its receipts stay checked');
    const later = await judge(svc, SAM);
    assert.deepEqual([later.action, later.trigger], ['move', 'spam']);
    assert.equal((await judge(svc, SAM, { from: 'receipts@bigstore.example' })).trigger, 'promotional', 'its main domain\'s mail: checked as usual');
});
