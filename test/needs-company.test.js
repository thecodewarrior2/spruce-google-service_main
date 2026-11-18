'use strict';
// 0.6.19: signs that count only together with another warning sign (hidden filler below the message, a colleague's
// name or a copied colleague on a domain that merely resembles the organization's); padded list mail with nothing
// else wrong is spam, moved to Spam as such; a partner running a brand's program; a well-known brand's text on another
// established company's own link. Every name, address, company and text here is made up.
const test = require('node:test');
const assert = require('node:assert');
const spruce = require('../src/engine/spruce');
const { readMessage } = require('../src/engine/mime');
const { analyze } = require('../src/engine/analyze');
const { decide } = require('../src/policy');
const { loadConfig } = require('../src/config');

const E = spruce.load();
const ORG = 'maple-schools.example', USER = `pat.fakewell@${ORG}`;
const colleagues = new Set([E.colleagueNameHash('Misty Samplefield')]);
const FILLER = `<div style="height:3000px"></div><p>${'Unrelated filler text from an old forum post about garden tools. '.repeat(6)}</p>`;
const mail = ({ from = 'Lakeview Garden Club <news@lakeviewgardens.example>', subject = 'Spring plant sale this Saturday', html = '<p>Our spring plant sale is this Saturday from nine to noon.</p>', dmarc = 'pass', extra = [] } = {}) =>
    readMessage(Buffer.from([`From: ${from}`, `To: ${USER}`, `Subject: ${subject}`, 'Message-ID: <n1@lakeviewgardens.example>', ...extra,
        `Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=${dmarc} header.from=${(/@([^>\s]+)/.exec(from) || [])[1]}`, 'Content-Type: text/html; charset=utf-8', '', html].join('\r\n')));
const judge = async (opts, ctx = {}) => analyze(await mail(opts), Object.assign({ mailbox: USER, orgDomains: [ORG], colleagues, firstTime: true }, ctx));
const enforce = loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: USER, MODE: 'enforce' });
const monitor = loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: USER });
const ruleCheck = (r) => Object.assign({}, r, { ai: { probability: 0.1 } });   // the rules alone: the AI's score kept low
const sign = (r, kind) => r.signals.find(s => s.kind === kind);

test('hidden filler, from outside, the first time, nothing else: shown, not counted, not suspicious', async () => {
    const r = await judge({ html: `<p>Our spring plant sale is this Saturday from nine to noon.</p>${FILLER}` });
    const s = sign(r, 'hidden-filler');
    assert.equal(s.weight, 0);
    assert.match(s.text, /Alone it isn't counted: nothing else in the email is suspicious\.$/);
    assert.equal(r.status, 'clean', JSON.stringify(r.signals));
    assert.equal(r.spam, undefined, 'not list mail: nothing to move');
    assert.equal(decide(ruleCheck(r), enforce, {}).action, 'none');
});

test('hidden filler in list or marketing mail, nothing else: spam, moved to Spam as spam (monitor mode: would be)', async () => {
    for (const opts of [{ extra: ['List-Unsubscribe: <https://lakeviewgardens.example/unsub?u=7>'] }, { extra: ['Precedence: bulk'] },
        { html: `<p>Big spring sale, 40% off everything.</p><p><a href="https://lakeviewgardens.example/unsub">Unsubscribe</a></p>${FILLER}` }]) {
        if (!opts.html) opts.html = `<p>Big spring sale, 40% off everything.</p>${FILLER}`;
        const r = await judge(opts);
        assert.equal(r.status, 'clean');
        assert.ok(r.spam && /spam trick/.test(r.spam.why), JSON.stringify(opts));
        const d = decide(ruleCheck(r), enforce, {});
        assert.deepEqual([d.action, d.trigger], ['move', 'spam']);
        assert.match(d.why, /^spam: list or marketing mail/);
        assert.deepEqual([decide(ruleCheck(r), monitor, {}).action, decide(ruleCheck(r), monitor, {}).trigger], ['would-move', 'spam']);
        assert.equal(decide(ruleCheck(r), Object.assign({}, enforce, { moveOnRules: false }), {}).action, 'none', 'moving on the rules off: not moved');
        assert.equal(decide(Object.assign(ruleCheck(r), { inside: true }), enforce, {}).action, 'none', 'never mail from inside');
        assert.equal(decide(Object.assign(ruleCheck(r), { status: 'trusted' }), enforce, {}).action, 'none', 'never an allowlisted sender');
    }
});

test('0.6.27: padded list mail from an established sender (DMARC passing, domain a year old or more) is left alone', async () => {
    const intel = (days) => ({ rdap: { ageDays: async () => days } });
    const opts = () => ({ extra: ['List-Unsubscribe: <https://lakeviewgardens.example/unsub?u=7>'], html: `<p>A new pie recipe for the holidays.</p>${FILLER}` });
    const old = await judge(opts(), { intel: intel(4000) });
    assert.equal(old.spam, undefined, 'a long-held, verified newsletter domain: not spam');
    assert.equal(sign(old, 'hidden-filler').weight, 0);
    assert.match(sign(old, 'hidden-filler').text, /Not moved as spam either: Gmail verified the sender, and its domain is more than a year old/);
    assert.equal(decide(ruleCheck(old), enforce, {}).action, 'none');
    for (const [days, why] of [[200, 'a domain under a year old'], [null, 'an unknown age']]) {
        const r = await judge(opts(), { intel: intel(days) });
        assert.ok(r.spam && /spam trick/.test(r.spam.why), `still spam with ${why}`);
    }
    const failing = await judge(Object.assign(opts(), { dmarc: 'fail' }), { intel: intel(4000) });
    assert.equal(sign(failing, 'hidden-filler').weight, 3, 'the sender check failing: another sign, so the filler counts (judged as phishing, as before)');
});

test('hidden filler with another warning sign counts as before (3), and is judged as phishing, not spam', async () => {
    const r = await judge({ subject: 'Your mailbox is full: verify your account now', html: `<p>Your mailbox storage is full. Verify your password within 24 hours or lose your email.</p>${FILLER}`, dmarc: 'fail', extra: ['List-Unsubscribe: <https://x.example/u>'] });
    assert.equal(sign(r, 'hidden-filler').weight, 3);
    assert.equal(r.spam, undefined);
    assert.ok(r.score >= 5, JSON.stringify(r.signals));
});

test('a colleague\'s name on a domain that only resembles the organization\'s: needs another sign', async () => {
    const from = 'Misty Samplefield <misty@drugfree-maple-schools.example>';
    const alone = sign(await judge({ from, subject: 'Coalition meeting notes', html: '<p>Hi all, the notes from Tuesday\'s coalition meeting are below. Thanks, Misty</p>' }), 'sender-colleague-name');
    assert.equal(alone.weight, 0);
    assert.match(alone.text, /imitating your organization's domain\. Alone it isn't counted/);
    const asks = sign(await judge({ from, subject: 'Quick favor', html: '<p>Are you available? I need a quick favor. Text me your cell number.</p>' }), 'sender-colleague-name');
    assert.equal(asks.weight, 3, 'with what impersonators ask: counted');
    const another = await judge({ from, subject: 'Coalition meeting notes', html: '<p>Hi all, notes below. Misty</p>', dmarc: 'fail' });
    assert.equal(sign(another, 'sender-colleague-name').weight, 3, 'with Gmail\'s sender check failing: counted');
});

test('a colleague copied in at a resembling address: needs another sign', async () => {
    const extra = ['Cc: Misty Samplefield <misty@drugfree-maple-schools.example>'];
    const alone = await judge({ extra });
    assert.equal(sign(alone, 'colleague-copied-lookalike').weight, 0);
    assert.equal(alone.status, 'clean');
    const lure = await judge({ extra, subject: 'Invoice overdue: wire the payment today', html: '<p>Please wire the payment today. I have copied our superintendent. Keep this confidential.</p>', dmarc: 'fail' });
    assert.equal(sign(lure, 'colleague-copied-lookalike').weight, 3);
});

test('a brand\'s program run by a partner that the name also gives, from its own verified address: not counted', async () => {
    const own = (name, address, dmarcPassFor) => E.nameAddressSigns(name, address, ORG, null, null, { dmarc: 'pass', dmarcPassFor });
    const ok = own('PayPal Future Coders - Sample Scholarship Fund', 'marketing@samplescholarshipfund.example', 'samplescholarshipfund.example');
    assert.deepEqual(ok.map(s => [s.kind, s.weight]), [['brand-partner-name', 0]]);
    assert.match(ok[0].text, /a program of PayPal run by the organization the name also gives/);
    for (const [name, address, why] of [
        ['PayPal Future Coders - Sample Scholarship Fund', 'marketing@samplescholarshipfund.example', 'DMARC not passing'],
        ['PayPal - Account Center', 'x@accountcenter.example', 'an account desk\'s words, not an organization'],
        ['PayPal - Lakeview', 'x@lakeview.example', 'one word: no organization\'s name'],
        ['PayPal Security', 'x@samplefieldtrading.example', 'the sender\'s organization not in the name']]) {
        const dm = why === 'DMARC not passing' ? '' : address.split('@')[1];
        assert.equal(own(name, address, dm)[0].weight, 5, why);
    }
    // A new domain: an imitation after all (analyze.js).
    const intel = { threats: { enabled: {}, checkUrls: async () => new Map(), checkHosts: async (h) => new Map(h.map(x => [x, { verdict: 'clean', by: 'Cloudflare Security' }])) },
        feeds: { urlHit: async () => null, addressHit: async () => null, domainHit: async () => null }, rdap: { ageDays: async () => 3 },
        ownership: { of: async () => ({ state: 'unknown', how: '' }), ofCompany: async () => ({ state: 'unknown', how: '' }) } };
    const young = await judge({ from: '"PayPal Future Coders - Sample Scholarship Fund" <marketing@samplescholarshipfund.example>', subject: 'Apply for a coding scholarship' }, { intel });
    assert.ok(sign(young, 'young-sender-domain'));
    assert.equal(sign(young, 'brand-partner-name').weight, 5);
    assert.match(sign(young, 'brand-partner-name').text, /the sender's domain is new or listed, so it counts as PayPal's name on another address\.$/);
});

test('a well-known brand\'s text on another established company\'s own link: not dangerous, a note of no weight', async () => {
    const HOTEL = 'lakeviewhotels.example';
    const links = `<p><a href="https://links.h5.${HOTEL}/c/1">paypal.com</a></p><p><a href="https://links.h5.${HOTEL}/c/2">paypal.com</a></p><p><a href="https://www.${HOTEL}/">Book</a></p>`;
    const intelOf = ({ owned = true, days = 4000, verdict = 'clean' } = {}) => ({
        threats: { enabled: { safeBrowsing: false }, checkUrls: async () => new Map(), checkHosts: async (h) => new Map(h.map(x => [x, { verdict, by: 'Cloudflare Security' }])) },
        feeds: { urlHit: async () => null, addressHit: async () => null, domainHit: async () => null }, rdap: { ageDays: async () => days },
        ownership: { of: async () => ({ state: 'unknown', how: '' }), ofCompany: async (d) => (owned && d === HOTEL ? { state: 'owned', how: 'registered to Lakeview Hotels Group through a corporate registrar' } : { state: 'unknown', how: '' }) } });
    const opts = { from: 'Sample Rewards Card <offers@samplerewards.example>', subject: 'Earn points on your next stay', html: `<p>Earn points on your next stay.</p>${links}` };
    const r = await judge(opts, { intel: intelOf() });
    assert.ok(!r.signals.some(s => s.kind === 'dangerous-links'), JSON.stringify(r.signals));
    assert.equal(sign(r, 'brand-to-brand-link').weight, 0);
    assert.match(sign(r, 'brand-to-brand-link').text, /^2 links show a well-known brand but go to lakeviewhotels\.example, an established company's own domain/);
    const dangerous = (x) => x.signals.some(s => s.kind === 'dangerous-links') && !sign(x, 'brand-to-brand-link');
    assert.ok(dangerous(await judge(opts, { intel: intelOf({ owned: false }) })), 'not proven the company\'s');
    assert.ok(dangerous(await judge(opts, { intel: intelOf({ days: 20 }) })), 'a new domain');
    assert.ok(dangerous(await judge(Object.assign({}, opts, { dmarc: 'fail' }), { intel: intelOf() })), 'the sender not verified');
    const shared = Object.assign({}, opts, { html: '<p>See the offer.</p><p><a href="https://docs.google.com/forms/d/e/abc/viewform">paypal.com</a></p>' });
    assert.ok(dangerous(await judge(shared, { intel: intelOf() })), 'a page anyone can make (a form) stays dangerous');
});
