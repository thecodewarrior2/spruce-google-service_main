'use strict';
// 0.6.22: a mail provider's own delivery report ("Delivery Status Notification (Failure)" from Google's mail system,
// its DMARC passing, written as a delivery report) isn't scored by the AI; the rule checks still read it. Forged,
// from anyone else, or not a delivery report: scored as before. Every address and text here is made up.
const test = require('node:test');
const assert = require('node:assert');
const { readMessage } = require('../src/engine/mime');
const { analyze } = require('../src/engine/analyze');
const { decide } = require('../src/policy');
const { loadConfig } = require('../src/config');

const ORG = 'maple-schools.example', USER = `office@${ORG}`;
const bounce = ({ from = 'Mail Delivery Subsystem <mailer-daemon@googlemail.com>', dmarc = 'pass', headerFrom = 'googlemail.com', report = true } = {}) => readMessage(Buffer.from([
    `From: ${from}`, `To: ${USER}`, 'Subject: Delivery Status Notification (Failure)', 'Message-ID: <b1@mx.example>', 'MIME-Version: 1.0',
    `Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=${dmarc} header.from=${headerFrom}`,
    report ? 'Content-Type: multipart/report; boundary="b"; report-type=delivery-status' : 'Content-Type: multipart/mixed; boundary="b"', '',
    '--b', 'Content-Type: text/plain; charset=utf-8', '',
    "Address not found. Your message wasn't delivered to sam.testwood@samplefield.example because the address couldn't be found, or is unable to receive mail.",
    '--b', 'Content-Type: message/delivery-status', '', 'Reporting-MTA: dns; googlemail.com', '', 'Final-Recipient: rfc822; sam.testwood@samplefield.example', 'Action: failed', 'Status: 5.1.1',
    '--b', 'Content-Type: message/rfc822', '', `From: ${USER}`, 'To: sam.testwood@samplefield.example', 'Subject: Field trip forms', '', 'Hi Sam, the field trip forms are attached.',
    '--b--', ''].join('\r\n')));
const judge = async (opts) => analyze(await bounce(opts), { mailbox: USER, orgDomains: [ORG], firstTime: false, readAttachments: false });
const enforce = loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: USER, MODE: 'enforce' });

test('Google\'s own delivery report, its DMARC passing: the AI doesn\'t score it; nothing recorded', async () => {
    const r = await judge();
    assert.equal(r.ai.skipped, 'bounce');
    assert.equal(r.ai.probability, null);
    assert.equal(decide(r, enforce, {}).action, 'none', JSON.stringify(r.signals));
});

test('forged, from another sender, or not a delivery report: the AI scores it as before', async () => {
    for (const [opts, why] of [[{ dmarc: 'fail' }, 'DMARC failing'],
        [{ from: 'Mail Delivery Subsystem <mailer-daemon@googlemail-delivery.example>', headerFrom: 'googlemail-delivery.example' }, 'a look-alike domain'],
        [{ from: 'Mail Delivery Subsystem <dana.madeup.1985@gmail.com>', headerFrom: 'gmail.com' }, 'a person\'s mailbox at the provider'],
        [{ report: false }, 'not written as a delivery report']]) {
        const r = await judge(opts);
        assert.notEqual(r.ai.skipped, 'bounce', why);
        assert.equal(typeof r.ai.probability, 'number', why);
    }
});
