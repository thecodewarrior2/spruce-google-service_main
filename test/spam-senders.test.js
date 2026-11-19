'use strict';
// 0.6.35: Spam senders (Settings → Sender lists): an admin's Spam answer can add the sender; its verified mail then goes
// straight to Spam, as spam, whatever the other checks find. Every sender, address and email here is made up.
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
const raw = (to, { dmarc = 'pass', from = 'tips@email.recipe-site.example', subject } = {}) => Buffer.from([
    `From: "Recipe Site Tips" <${from}>`, `To: ${to}`, `Subject: ${subject || `Weeknight dinners, part ${++n}`}`, `Message-ID: <r${n}@email.recipe-site.example>`,
    `Authentication-Results: mx.google.com; dkim=${dmarc === 'pass' ? 'pass' : 'none'}; spf=${dmarc === 'pass' ? 'pass' : 'softfail'}; dmarc=${dmarc} header.from=${from.split('@')[1]}`,
    'List-Unsubscribe: <https://email.recipe-site.example/u>', 'Content-Type: text/plain', '', 'Five dinners in thirty minutes. Read more on our site. Unsubscribe.'].join('\r\n'));
const make = (mode = 'enforce', extra = {}) => new Service({ cfg: loadConfig(Object.assign({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: [PAT, SAM].join(','), MODE: mode }, extra)), store: new MemoryStore(),
    gmail: { labelId: async (u, nm) => `L_${nm}`, modify: async () => ({}) }, log: { error() {}, warn() {} } });
const judge = async (svc, user, opts) => svc.judge(user, { id: `m${n}-${user}`, threadId: `t${n}`, internalDate: Date.now() }, await readMessage(raw(user, opts)));

test('a sender on Spam senders: its verified mail goes straight to Spam, as spam, whatever the checks find', async () => {
    const svc = make();
    const before = await judge(svc, PAT);
    assert.equal(before.action, 'none', 'an ordinary newsletter: left alone');
    assert.equal((await svc.addSpamSender('email.recipe-site.example', ADMIN)).key, 'recipe-site.example', 'kept as its organization\'s domain');
    const r = await judge(svc, PAT);
    assert.deepEqual([r.action, r.trigger], ['move', 'spam']);
    const rec = await svc.store.getRecord(r.key);
    assert.equal(rec.spamSender, 'recipe-site.example');
    assert.match(rec.why, /recipe-site\.example is on Settings → Sender lists → Spam senders/);
    assert.notEqual((await judge(svc, PAT, { dmarc: 'fail' })).trigger, 'spam', 'forged: judged as usual, never straight to Spam');
    const monitor = make('monitor');
    await monitor.addSpamSender('recipe-site.example', ADMIN);
    assert.equal((await judge(monitor, PAT)).action, 'would-move', 'monitor mode: recorded only');
});

test('not for a person who took its spam back, nor an allowlisted sender; removed: checked as usual', async () => {
    const svc = make('enforce', { ALLOW_ADDRESSES: 'tips@email.trusted-recipes.example' });
    await svc.addSpamSender('recipe-site.example', ADMIN);
    await svc.rememberSpamRescue(SAM, 'tips@email.recipe-site.example');
    assert.equal((await judge(svc, SAM)).action, 'none', 'Sam took its spam back');
    assert.equal((await judge(svc, PAT)).trigger, 'spam');
    await svc.addSpamSender('trusted-recipes.example', ADMIN);
    assert.equal((await judge(svc, PAT, { from: 'tips@email.trusted-recipes.example' })).action, 'none', 'allowlisted wins');
    await svc.removeSpamSender('recipe-site.example', ADMIN);
    assert.equal((await judge(svc, PAT)).action, 'none');
});

test('a Spam answer with "also send future mail straight to Spam" adds a verified sender; refused for own domains and personal providers', async () => {
    const svc = make();
    await svc.addSpamSender('', ADMIN).then(r => assert.equal(r.status, 400));
    assert.equal((await svc.addSpamSender(`news@${ORG}`, ADMIN)).status, 400, 'own domain');
    assert.equal((await svc.addSpamSender('gmail.com', ADMIN)).status, 400, 'a personal provider is everyone\'s');
    assert.equal((await svc.addSpamSender('someone@gmail.com', ADMIN)).key, 'someone@gmail.com', 'an address there');
    // A record to answer: a flagged email from the newsletter (a brand's name on it).
    const flagged = await svc.judge(PAT, { id: 'f1', threadId: 'tf', internalDate: Date.now() }, await readMessage(Buffer.from([
        'From: "PayPal Recipes" <tips@email.recipe-site.example>', `To: ${PAT}`, 'Subject: Dinner deals', 'Message-ID: <f1@email.recipe-site.example>',
        'Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass header.from=email.recipe-site.example', 'Content-Type: text/plain', '', 'Deals.'].join('\r\n'))));
    const out = await svc.mark(flagged.key, false, ADMIN, { spam: true, addSender: true });
    assert.equal(out.spamSenderAdded, 'recipe-site.example');
    assert.ok((await svc.spamSenderList()).some(x => x.key === 'recipe-site.example' && x.from === 'review'));
});
