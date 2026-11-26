'use strict';
// 0.6.28: a brand's invoicing run by a payment company from its own domain (Walmart Business's Pay By Invoice, run by
// TreviPay) is no imitation when Gmail verified the sender; forged, it is. The school, amount and IDs are made up.
const test = require('node:test');
const assert = require('node:assert');
const { readMessage } = require('../src/engine/mime');
const { analyze } = require('../src/engine/analyze');

const ORG = 'maple-schools.example', USER = `pat.fakewell@${ORG}`;
const mail = ({ dmarc = 'pass', from = 'no-reply@trevipay.app', name = 'Walmart Business: Pay By Invoice Support' } = {}) => readMessage(Buffer.from([
    `From: "${name}" <${from}>`, `To: ${USER}`, `Reply-To: walmartbusinesssupport@trevipay.app`,
    'Subject: We received your payment on Walmart Business: Pay By Invoice', 'Message-ID: <p1@mail.maple-billing.example>',
    `Authentication-Results: mx.google.com; dkim=${dmarc === 'pass' ? 'pass' : 'none'}; spf=${dmarc === 'pass' ? 'pass' : 'softfail'}; dmarc=${dmarc} header.from=${from.split('@')[1]}`,
    'Content-Type: text/html; charset=utf-8', '',
    '<h2>Payment Received</h2><p>Thank you for your payment on Walmart Business: Pay By Invoice. The below amount has been posted to your account.</p>'
    + '<p>Account: Maple Example Middle School</p><p>Payment ID: 0a0b0c0d</p><p>Amount: $123.45</p>'
    + '<p>If you would like to view your invoices or payment details, please visit your online account.</p><p><a href="https://www.trevipay.app/payments">View Payment History</a></p>'
    + '<p>Invoice, Payment, &amp; Credit Support<br>TreviPay</p>'].join('\r\n')));
const judge = async (opts) => analyze(await mail(opts), { mailbox: USER, orgDomains: [ORG], firstTime: true });
const brand = (r) => r.signals.find(s => /The sender's name says “Walmart Business/.test(s.text));

test('Walmart Business invoicing from TreviPay, verified: a note of no weight, not an imitation', async () => {
    const r = await judge();
    const s = brand(r);
    assert.equal(s.weight, 0, JSON.stringify(r.signals));
    assert.equal(s.kind, 'brand-billing-service');
    assert.match(s.text, /TreviPay's, the company that runs Walmart's invoicing, and Gmail verified it/);
    assert.ok(r.score < 3, `not suspicious on the rules: ${JSON.stringify(r.signals.map(x => [x.kind, x.weight]))}`);
    assert.ok(r.ai && r.ai.probability < 0.5, `the AI is told it is Walmart's own invoicing sender: ${r.ai && r.ai.probability}`);
});

test('forged (DMARC failing), from a look-alike of TreviPay, or another brand\'s name on TreviPay: judged as before', async () => {
    assert.equal(brand(await judge({ dmarc: 'fail' })).weight, 5, 'not verified: may be forged');
    assert.equal(brand(await judge({ from: 'no-reply@trevipay-billing.example' })).weight, 5, 'a domain that only resembles TreviPay\'s');
    const other = (await judge({ name: 'Amazon Business: Pay By Invoice Support' })).signals.find(s => /The sender's name says “Amazon Business/.test(s.text));
    assert.equal(other.weight, 5, 'only the brands listed for the service');
});

// 0.6.88: what the AI is told about who the sender claims to be agrees with the rule checks: a card issued by a bank for a
// brand (PayPal Credit from Synchrony), and a brand's other domain the public records prove its company's (the ownership
// lookup, which the rules read and the AI's identity fact didn't get). Forged, or from a domain that only resembles them,
// it is still "not the brand's".
test('0.6.88: PayPal Credit from Synchrony, and what the public records prove: the brand\'s, for the AI and the rules', async () => {
    const E = require('../src/engine/spruce').load();
    const SYF = 'statements@mail.synchronybank.com';
    const id = (name, from, dmarc = true) => E.aiSenderIdentity(name, from, { own: [ORG], dmarcPassFor: dmarc ? from.split('@')[1] : '' });
    assert.deepEqual(id('PayPal Credit', SYF), { brand: 'PayPal', owner: 'yes' });
    assert.deepEqual(id('PayPal Credit', SYF, false), { brand: 'PayPal', owner: 'no' }, 'not verified');
    assert.equal(id('PayPal Credit', 'alerts@synchronybank-alerts.example').owner, 'no', 'only resembles Synchrony');
    assert.equal(id('Chase', SYF).owner, 'no', 'not a brand Synchrony issues for');
    const r = await analyze(await mail({ from: SYF, name: 'PayPal Credit' }), { mailbox: USER, orgDomains: [ORG], keepAiFacts: true });
    const s = r.signals.find(x => /The sender's name says “PayPal Credit/.test(x.text));
    assert.equal(s.weight, 0); assert.match(s.text, /the bank that issues PayPal's credit card and credit/);
    assert.deepEqual(r.aiFacts.identity, { brand: 'PayPal', owner: 'yes' });
    // Acrobat Sign's notification, proven by Gmail for adobesign.com: Adobe's own, for the AI (it was told "not Adobe's").
    const adobe = await analyze(await mail({ from: 'adobesign@adobesign.com', name: 'Dana Madeup via Adobe Acrobat Sign' }), { mailbox: USER, orgDomains: [ORG], keepAiFacts: true });
    assert.equal(adobe.aiFacts.identity && adobe.aiFacts.identity.owner, 'yes', JSON.stringify(adobe.aiFacts.identity));
    // The public records proving a sender's domain the brand's company's reach the AI's identity fact (analyze passes them).
    const owned = { ownership: { of: async () => ({ state: 'owned', how: 'made-up proof' }) } };
    const shop = await analyze(await mail({ from: 'hello@madeupbank-shopping.example', name: 'Capital One Shopping' }), { mailbox: USER, orgDomains: [ORG], keepAiFacts: true, intel: owned });
    assert.equal(shop.aiFacts.identity && shop.aiFacts.identity.owner, 'yes', JSON.stringify(shop.aiFacts.identity));
    const unproven = await analyze(await mail({ from: 'hello@madeupbank-shopping.example', name: 'Capital One Shopping' }), { mailbox: USER, orgDomains: [ORG], keepAiFacts: true });
    assert.equal(unproven.aiFacts.identity.owner, 'no', 'no proof: as before');
});
