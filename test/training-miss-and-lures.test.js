'use strict';
// 0.6.32: a training rule's header seen in an email the rule didn't match says why (the rules table, Activity, Check an
// email); and three checks a phishing-training lure showed missing: the organization's domain written inside another
// domain, a hidden decoy link, and Xero's name. Every domain here is made up; the IP addresses are documentation ones.
const test = require('node:test');
const assert = require('node:assert');
const { loadConfig } = require('../src/config');
const { Service } = require('../src/pipeline');
const { MemoryStore } = require('../src/store/memory');
const { readMessage } = require('../src/engine/mime');
const { analyze } = require('../src/engine/analyze');

const ORG = 'maple.k12.example', PAT = `pat.fakewell@${ORG}`, ADMIN = `it.madeup@${ORG}`;
const mail = ({ from = 'Billing <billing@vendor-notices.example>', replyTo = '', ip = '198.51.100.7', headers = [], html = '<p>Your statement is ready.</p>' } = {}) => readMessage(Buffer.from([
    `Received: from out.vendor-notices.example (out.vendor-notices.example. [${ip}]) by mx.google.com with ESMTPS id x for <${PAT}>; Wed, 18 Nov 2026 09:06:50 -0800`,
    `From: ${from}`, `To: ${PAT}`, ...(replyTo ? [`Reply-To: ${replyTo}`] : []), 'Subject: Statement', `Message-ID: <s${Math.random().toString(36).slice(2)}@vendor-notices.example>`,
    'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=vendor-notices.example', ...headers, 'Content-Type: text/html; charset=utf-8', '', html].join('\r\n')), { ownDomains: [ORG] });
const judge = async (opts) => analyze(await mail(opts), { mailbox: PAT, orgDomains: [ORG], firstTime: true });
const sign = (r, kind) => r.signals.find(s => s.kind === kind);

test('a training rule\'s header from an address the rule doesn\'t list: why, on the rule and in Check an email', async () => {
    const svc = new Service({ cfg: loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: PAT, MODE: 'monitor' }), store: new MemoryStore(),
        gmail: { labelId: async (u, n) => `L_${n}`, modify: async () => ({}) }, log: { error() {}, warn() {} } });
    assert.ok((await svc.addTrainingRule({ name: 'Madeup Trainer', header: 'X-MADEUP-TEST', ips: '192.0.2.0/26' }, ADMIN)).ok !== false);
    const HDR = ['X-MADEUP-TEST: This is a phishing security test'];
    const facts = await mail({ headers: HDR, ip: '198.51.100.7' });
    const r = await svc.judge(PAT, { id: 'm1', threadId: 't1', internalDate: Date.now() }, facts);
    assert.notEqual(r.training, 'Madeup Trainer', 'not matched');
    const missed = Object.values((await svc.store.getState('phishTrainingMissed')) || {});
    assert.equal(missed.length, 1);
    assert.equal(missed[0].count, 1);
    assert.match(missed[0].why, /Gmail received it from 198\.51\.100\.7, not one of the rule's sending addresses/);
    assert.ok((await svc.store.listEvents(0, { limit: 20 })).some(e => e.kind === 'training-miss'));
    const raw = (await mail({ headers: HDR })).rawForHeaders;
    assert.ok(raw);
    const pasted = await svc.checkPasted([`Received: from out.vendor-notices.example (out.vendor-notices.example. [198.51.100.7]) by mx.google.com with ESMTPS id x; Wed, 18 Nov 2026 09:06:50 -0800`,
        'From: Billing <billing@vendor-notices.example>', `To: ${PAT}`, 'Subject: Statement', ...HDR, 'Content-Type: text/plain', '', 'Your statement is ready.'].join('\r\n'), { by: ADMIN });
    assert.equal(pasted.training, null);
    assert.equal(pasted.trainingMiss.length, 1);
    assert.match(pasted.trainingMiss[0].why, /198\.51\.100\.7/);
    // From a listed address: a training email, and no miss.
    const ok = await svc.judge(PAT, { id: 'm2', threadId: 't2', internalDate: Date.now() }, await mail({ headers: HDR, ip: '192.0.2.10' }));
    assert.equal(ok.training, 'Madeup Trainer');
    assert.equal(Object.values((await svc.store.getState('phishTrainingMissed')) || {})[0].count, 1);
});

test('the organization\'s domain written inside another domain: 5, in the reply address, the sender or a link', async () => {
    const reply = await judge({ replyTo: 'Billing <billing.7@maple-k12-example.gmail.login-helpdesk.example>' });
    assert.equal(sign(reply, 'org-domain-inside').weight, 5);
    assert.match(sign(reply, 'org-domain-inside').text, /The reply address \(maple-k12-example\.gmail\.login-helpdesk\.example\) writes your organization's domain \(maple\.k12\.example\)/);
    assert.equal(sign(await judge({ from: 'Help Desk <help@maple-k12.account-check.example>' }), 'org-domain-inside').weight, 5, 'without its last part');
    const link = await judge({ html: '<p><a href="https://maple.k12.example.account-check.example/login">Sign in</a></p>' });
    assert.equal(sign(link, 'org-domain-inside').weight, 5, 'a link: the full domain followed by another ending');
    assert.equal(sign(await judge({ html: '<p><a href="https://maple-k12-example.lms-vendor.example/courses">Your courses</a></p>' }), 'org-domain-inside'), undefined,
        'a link to a service\'s tenant named after the district: not counted');
    assert.equal(sign(await judge({ replyTo: `Office <office@${ORG}>` }), 'org-domain-inside'), undefined, 'the organization\'s own domain');
    assert.equal(sign(await judge({ replyTo: 'Signing <dse@maple-k12-example.docusign.net>' }), 'org-domain-inside'), undefined, 'a well-known company\'s own domain');
});

test('a hidden, empty link beside a visible one to the same site: 5 (0.6.33); a newsletter\'s hidden mobile block: nothing', async () => {
    const decoy = await judge({ html: '<p>Reconnect your account.</p><a href="https://reconnect.lure-site.example/a1" style="height:0;opacity:0;width:0;"> </a><a href="https://reconnect.lure-site.example/a2">Reconnect Now</a>' });
    assert.equal(sign(decoy, 'hidden-decoy-link').weight, 5);
    assert.ok(decoy.score >= 5 && decoy.status === 'flagged', 'flagged on its own');
    const responsive = await judge({ html: '<div style="display:none"><a href="https://news.shop-example.example/m">Shop the sale</a></div><div><a href="https://news.shop-example.example/d">Shop the sale</a></div>' });
    assert.equal(sign(responsive, 'hidden-decoy-link'), undefined);
});

test('Xero\'s name from another domain is an imitation', async () => {
    const r = await judge({ from: 'Xero <xero@verify-bank-details.example>' });
    assert.equal(sign(r, 'brand-name-other').weight, 5);
    assert.match(sign(r, 'brand-name-other').text, /isn't Xero's address/);
});

test('0.6.33: a store\'s co-branded card from the bank that issues it: its links to the bank behind the store\'s address aren\'t dangerous', async () => {
    const html = '<p>Stack your savings.</p>' + [0, 1, 2].map(i => `<a href="https://cards.tdbank.com/r?${i}">https://www.target.com/deals</a>`).join(' ') + '<a href="https://cards.tdbank.com/s">Shop Deals</a>';
    const r = await judge({ from: '"Store Circle Card" <card@cards.tdbank.com>', html });
    assert.equal(r.status, 'clean', JSON.stringify(r.signals.map(s => [s.kind, s.weight])));
    assert.ok(!r.signals.some(s => /dangerous/.test(s.text)), 'no dangerous links');
    const unknown = await judge({ from: '"Store Circle Card" <card@cards.circle-rewards.example>', html: html.replace(/cards\.tdbank\.com/g, 'cards.circle-rewards.example') });
    assert.ok(unknown.signals.some(s => /dangerous/.test(s.text)), 'the same links to an unknown site: still dangerous');
    assert.equal(sign(await judge({ from: 'TD Bank <alerts@td-bank-secure.example>' }), 'brand-name-other').weight, 5, 'TD Bank is a known brand now');
});

test('0.6.34: a newsletter\'s hidden, empty link to its own site, the sender verified: not counted; unverified, or to another site: 5', async () => {
    const news = (dmarc, site = 'links.cooking-site.example') => readMessage(Buffer.from([
        'From: "Cooking Site Tips" <tips@email.cooking-site.example>', `To: ${PAT}`, 'Subject: Can glass dishes go in the oven?', 'Message-ID: <n1@email.cooking-site.example>',
        `Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=${dmarc} header.from=email.cooking-site.example`, 'Content-Type: text/html; charset=utf-8', '',
        `<p>Reheating dinner? Read this first.</p><a href="https://${site}/t1" style="height:0;opacity:0;width:0;"> </a><a href="https://${site}/t2">Read More</a>`].join('\r\n')), { ownDomains: [ORG] });
    const own = await analyze(await news('pass'), { mailbox: PAT, orgDomains: [ORG], firstTime: true });
    assert.equal(sign(own, 'hidden-decoy-link').weight, 0);
    assert.notEqual(own.status, 'flagged');
    assert.equal(sign(await analyze(await news('fail'), { mailbox: PAT, orgDomains: [ORG], firstTime: true }), 'hidden-decoy-link').weight, 5, 'the sender not verified');
    assert.equal(sign(await analyze(await news('pass', 'go.lure-site.example'), { mailbox: PAT, orgDomains: [ORG], firstTime: true }), 'hidden-decoy-link').weight, 5, 'to another site');
});
