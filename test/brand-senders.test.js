'use strict';
// 0.6.29: a reviewer's "False alarm" on an email whose only sign was a brand's name from another verified domain
// teaches the service that domain is a real sender for the brand; an admin removes it. Every address, school and
// company here is made up (payco-invoicing.example stands for a payment company that sends a store's invoices).
const test = require('node:test');
const assert = require('node:assert');
const { loadConfig } = require('../src/config');
const { Service } = require('../src/pipeline');
const { MemoryStore } = require('../src/store/memory');
const { readMessage } = require('../src/engine/mime');
const { analyze } = require('../src/engine/analyze');

const ORG = 'maple-schools.example';
const [PAT, SAM] = ['pat.fakewell', 'sam.testwood'].map(u => `${u}@${ORG}`);
const ADMIN = `it.madeup@${ORG}`;
const raw = (to, { dmarc = 'pass', from = 'no-reply@payco-invoicing.example', name = 'Walmart Business: Pay By Invoice Support', subject = 'We received your payment on Pay By Invoice' } = {}) => Buffer.from([
    `From: "${name}" <${from}>`, `To: ${to}`, `Subject: ${subject}`, `Message-ID: <m${Math.random().toString(36).slice(2)}@payco-invoicing.example>`,
    `Authentication-Results: mx.google.com; dkim=${dmarc === 'pass' ? 'pass' : 'none'}; spf=${dmarc === 'pass' ? 'pass' : 'softfail'}; dmarc=${dmarc} header.from=${from.split('@')[1]}`,
    'Content-Type: text/plain; charset=utf-8', '', 'Thank you for your payment. The amount has been posted to your account. Account: Maple Example Middle School.'].join('\r\n'));
const make = () => new Service({ cfg: loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: [PAT, SAM].join(','), MODE: 'monitor' }), store: new MemoryStore(),
    gmail: { labelId: async (u, n) => `L_${n}`, modify: async () => ({}) }, log: { error() {}, warn() {} } });
let n = 0;
const judge = async (svc, user, opts) => svc.judge(user, { id: `m${++n}`, threadId: `t${n}`, internalDate: Date.now() }, await readMessage(raw(user, opts)));
// The signs of an email as the service now reads it (judge returns only the verdict of an email it leaves alone).
const signsNow = async (svc, user, opts) => analyze(await readMessage(raw(user, opts)), { mailbox: user, orgDomains: [ORG], firstTime: true, brandSenders: await svc.brandSenderSet() });
const brandSign = (r) => (r.signals || []).find(s => /^The sender's name says “Walmart Business/.test(s.text));

test('a false alarm on a brand\'s name from another verified domain teaches it; later verified mail isn\'t counted for it', async () => {
    const svc = make();
    const first = await judge(svc, PAT);
    assert.equal(brandSign(first).weight, 5);
    assert.equal(brandSign(first).kind, 'brand-name-other');
    await svc.mark(first.key, true, ADMIN);
    assert.deepEqual((await svc.brandSenderList()).map(x => [x.brand, x.domain, x.by]), [['Walmart', 'payco-invoicing.example', ADMIN]]);
    assert.ok((await svc.store.listEvents(0, { limit: 20 })).some(e => e.kind === 'brand-sender' && /payco-invoicing\.example is now a confirmed sender for Walmart/.test(e.text)));
    // (a different email from the same sender: the copies of the email answered are that answer's already)
    const NEXT = { subject: 'Your monthly statement is ready' };
    const later = await judge(svc, SAM, NEXT);
    assert.deepEqual([later.action, later.status], ['none', 'clean'], 'its next email is left alone');
    const now = await signsNow(svc, SAM, NEXT);
    assert.equal(brandSign(now).weight, 0);
    assert.equal(brandSign(now).kind, 'brand-sender-confirmed');
    assert.match(brandSign(now).text, /your organization's reviewers confirmed payco-invoicing\.example is a real sender for Walmart/);
    assert.ok(now.ai && now.ai.probability < 0.5, `the AI is told it is the brand's sender: ${now.ai && now.ai.probability}`);
    assert.equal(brandSign(await signsNow(svc, SAM, Object.assign({ dmarc: 'fail' }, NEXT))).weight, 5, 'forged: judged as before');
    const otherBrand = (await signsNow(svc, SAM, Object.assign({ name: 'Amazon Business Support' }, NEXT))).signals.find(s => /“Amazon Business Support”/.test(s.text));
    assert.equal(otherBrand.weight, 5, 'only the brand it was confirmed for');
    assert.equal((await svc.removeBrandSender('walmart|payco-invoicing.example', ADMIN)).ok, true);
    assert.equal(brandSign(await signsNow(svc, SAM, NEXT)).weight, 5, 'removed: judged as before');
});

test('not learned when the email had another sign, failed its sender check, or was answered phishing', async () => {
    const svc = make();
    const placeholder = await judge(svc, PAT, { subject: 'Your code {{Offer_Code}} is ready' });
    assert.ok(placeholder.signals.some(s => s.weight > 0 && s.kind !== 'brand-name-other' && !['outside-org', 'first-time'].includes(s.kind)), JSON.stringify(placeholder.signals.map(s => [s.kind, s.weight])));
    await svc.mark(placeholder.key, true, ADMIN);
    const forged = await judge(svc, PAT, { dmarc: 'fail' });
    await svc.mark(forged.key, true, ADMIN);
    const phish = await judge(svc, SAM);
    await svc.mark(phish.key, false, ADMIN);
    assert.deepEqual(await svc.brandSenderList(), []);
    // (0.6.81) Why not, for the page: the other sign, and the failed sender check; nothing for the Phishing answer's email.
    const store = svc.store;
    const why = async (k) => svc.brandSenderWhyNot(await store.getRecord(k));
    assert.match((await why(placeholder.key)).why, /other signs too/);
    assert.equal((await why(placeholder.key)).brand, 'Walmart');
    assert.match((await why(forged.key)).why, /DMARC/);
    assert.ok(!/@/.test(JSON.stringify(await why(placeholder.key))), 'no address');
});
