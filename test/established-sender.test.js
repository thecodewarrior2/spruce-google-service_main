'use strict';
// 0.6.20: a brand's name from an established company's own domain (a bank issuing a card in the brand's name), whose
// public records show a corporate registrar and long registration ("likely"), with Gmail's sender check passing and every
// link back to the sender's own domain: not counted. Every name, address and text here is made up.
const test = require('node:test');
const assert = require('node:assert');
const spruce = require('../src/engine/spruce');
const { readMessage } = require('../src/engine/mime');
const { analyze } = require('../src/engine/analyze');

const E = spruce.load();
const ORG = 'maple-schools.example', USER = `pat.fakewell@${ORG}`;
const BANK = 'samplefieldbank.example';
const LINKS = `<p><a href="https://e.emails.${BANK}/v/1">See this in a browser</a> <a href="https://e.emails.${BANK}/c/2">PayPal Credit Card</a> <a href="https://e.emails.${BANK}/c/3">Shop Now</a> <a href="https://e.emails.${BANK}/c/4">Pay your bill</a></p>`;
const mail = ({ html = `<p>Spread the cost of your next order over six months with your PayPal Credit account.</p>${LINKS}`, dmarc = 'pass' } = {}) =>
    readMessage(Buffer.from([`From: PayPal Credit <paypalcredit@emails.${BANK}>`, `To: ${USER}`, 'Subject: Special financing on your next order',
        `Message-ID: <c1@emails.${BANK}>`, `Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=${dmarc} header.from=emails.${BANK}`,
        'Content-Type: text/html; charset=utf-8', '', html].join('\r\n')));
const intelOf = ({ state = 'likely', days = 11000, verdict = 'clean' } = {}) => ({
    threats: { enabled: { safeBrowsing: false }, checkUrls: async () => new Map(), checkHosts: async (h) => new Map(h.map(x => [x, { verdict, by: 'Cloudflare Security' }])) },
    feeds: { urlHit: async () => null, addressHit: async () => null, domainHit: async () => null }, rdap: { ageDays: async () => days },
    ownership: { of: async () => ({ state, how: state === 'unknown' ? '' : 'registered through Sample Corporate Domains, a corporate registrar; registered 30 years ago' }), ofCompany: async () => ({ state: 'unknown', how: '' }) } });
const judge = async (opts, intel) => analyze(await mail(opts), { mailbox: USER, orgDomains: [ORG], colleagues: null, firstTime: true, intel });
const nameSign = (r) => r.signals.find(s => /The sender's name says “PayPal Credit”/.test(s.text));

test('a card issuer\'s mail under the brand\'s name, from its own established domain, links back to it: not counted', async () => {
    const r = await judge({}, intelOf());
    const s = nameSign(r);
    assert.equal(s.weight, 0, JSON.stringify(r.signals));
    assert.match(s.text, new RegExp(`every link goes back to ${BANK.replace('.', '\\.')}, so it counts as that company writing about a product it runs, not an imitation\\.$`));
    assert.equal(r.status, 'clean', JSON.stringify(r.signals));
});

test('still counted: sender check failing, a link elsewhere, a new domain, or no corporate record', async () => {
    assert.equal(nameSign(await judge({ dmarc: 'fail' }, intelOf())).weight, 3, 'DMARC failed');
    assert.equal(nameSign(await judge({ html: `<p>Confirm your PayPal Credit account.</p><p><a href="https://paypal-credit-review.example/login">Account Summary</a></p>${LINKS}` }, intelOf())).weight, 3, 'a link to another domain');
    assert.equal(nameSign(await judge({}, intelOf({ days: 10 }))).weight, 3, 'a new domain');
    assert.equal(nameSign(await judge({}, intelOf({ state: 'unknown' }))).weight, 5, 'nothing in the public records: as before');
    assert.equal(nameSign(await judge({}, intelOf({ state: 'owned' }))).weight, 0, 'proven the brand\'s: as before');
});
