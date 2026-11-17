'use strict';
// 0.6.18: the "renewal" callback scam (a bill for security software or a tech-support plan, an amount and a phone
// number to call, from a free mail account) and a mass mailer's unfilled placeholder in the subject. Every email,
// name and number here is made up; the phone numbers are the fictional 555 ones.
const test = require('node:test');
const assert = require('node:assert');
const { readMessage } = require('../src/engine/mime');
const { analyze } = require('../src/engine/analyze');
const { decide } = require('../src/policy');
const { loadConfig } = require('../src/config');
const E = require('../src/engine/spruce').load();

const ORG = 'maple-schools.example', USER = `pat.madeup@${ORG}`;
const enforce = loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: USER, MODE: 'enforce' });
const mail = ({ from = 'someone@gmail.com', subject, body }) => Buffer.from([`From: "Billing Desk" <${from}>`, `To: ${USER}`, `Subject: ${subject}`,
    'Message-ID: <cb1@mail.gmail.com>', `Authentication-Results: mx.google.com; dkim=pass header.i=@${from.split('@')[1]}; spf=pass; dmarc=pass header.from=${from.split('@')[1]}`,
    'Content-Type: text/plain; charset=utf-8', '', body].join('\r\n'));
const judge = async (raw) => { const r = await analyze(await readMessage(raw), { mailbox: USER, orgDomains: [ORG], intel: null }); return { r, action: decide(r, enforce, {}).action }; };
const BILL = 'Your Geek Squad protection plan renewed today.\nPlan: Home Tech Care, 3 years\nAmount charged: $389.50\nIf you have questions about this charge, our help desk is at (555) 014-2290.';

test('a security-software bill with a number to call, from a free mail account: strong on its own, moved', async () => {
    const { r, action } = await judge(mail({ subject: 'Renewal receipt #A55-201', body: BILL }));
    const s = r.signals.find(x => x.kind === 'callback-bill-free-mail');
    assert.equal(s.weight, 5);
    assert.match(s.text, /Geek Squad.*\(gmail\.com\).*don't call it/);
    assert.equal(action, 'move');
});

test('not the scam: the same bill from a company\'s own domain, a free-mail bill naming no such brand, or no number', () => {
    const none = (subject, text, from) => assert.deepEqual(E.freeMailBillSigns(subject, text, from, E.isPersonalMailDomain), [], `${from}: ${text.slice(0, 40)}`);
    none('Renewal receipt', BILL, 'billing@geeksquad-plans.example');
    none('Field trip money', 'The field trip costs $25.00 per student, invoice attached. Call me at (555) 014-7781 with questions.', 'coach.pat.sample@gmail.com');
    none('Renewal receipt', BILL.replace(/our help desk is at.*$/, 'reply to this email.'), 'someone@gmail.com');
});

test('"if this looks unfamiliar, call…": the callback wording, now also in its "unfamiliar" and "don\'t recognize" forms', () => {
    for (const t of ['If this purchase looks unfamiliar, call (555) 014-3321 to cancel the order.', 'If you don\'t recognize this payment, call our desk at 555-014-3321.']) assert.equal(E.bodyScamSigns(t).length, 1, t);
    assert.deepEqual(E.bodyScamSigns('Your order shipped. Questions? Call 555-014-3321.'), [], 'a number to call alone');
});

test('a mass mailer\'s placeholder left unfilled in the subject: a caution of 2; ordinary braces are not', () => {
    const kinds = (s) => E.subjectScamSigns(s).map(x => x.kind).filter(Boolean);
    assert.deepEqual(kinds('Your reward is waiting {{Offer_Code}}'), ['unfilled-placeholder']);
    assert.deepEqual(kinds('Hello {{ first name}}, claim now'), ['unfilled-placeholder']);
    assert.deepEqual(kinds('Math club: solve {x | x > 2} by Friday'), []);
    assert.equal(E.subjectScamSigns('Your reward is waiting {{Offer_Code}}').find(x => x.kind).weight, 2);
});
