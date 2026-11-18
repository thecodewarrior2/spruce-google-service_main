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
