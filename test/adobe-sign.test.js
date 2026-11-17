'use strict';
// 0.6.21: Adobe Acrobat Sign's own domains (adobesign.com, echosign.com) are Adobe's, and its sending mailbox
// (adobesign@adobesign.com) is a platform notification, judged by the person who sent the document (the Reply-To),
// as DocuSign's are. Forged or look-alike ones still count. Every name, address and text here is made up.
const test = require('node:test');
const assert = require('node:assert');
const spruce = require('../src/engine/spruce');
const { readMessage } = require('../src/engine/mime');
const { analyze } = require('../src/engine/analyze');
const N = require('../src/engine/notifications');

const E = spruce.load();
const ORG = 'maple-schools.example', USER = `pat.fakewell@${ORG}`;
const mail = ({ from = '"Dana Madeup via Adobe Acrobat Sign" <adobesign@adobesign.com>', dmarc = 'pass', headerFrom = 'adobesign.com' } = {}) => readMessage(Buffer.from([
    `From: ${from}`, `To: ${USER}`, 'Reply-To: Dana Madeup <dana.madeup@samplebroker.example>', 'Subject: Signature requested on "Sample Plan Renewal Form"',
    'Message-ID: <s1@samplebroker.example>', `Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=${dmarc} header.from=${headerFrom}`, 'Content-Type: text/html; charset=utf-8', '',
    '<p>Dana Madeup has requested your signature on "Sample Plan Renewal Form".</p><p><a href="https://samplebroker.na4.adobesign.com/public/esign?tsid=abc">Review and sign</a></p>' +
    '<p>To pass this on, <a href="https://na4.documents.adobe.com/public/delegate?x=1">delegate</a>.</p><p>Powered by Adobe Acrobat Sign</p>'].join('\r\n')));
const judge = async (opts) => analyze(await mail(opts), { mailbox: USER, orgDomains: [ORG], firstTime: true, readAttachments: false });
const brandSigns = (r) => r.signals.filter(s => /isn't Adobe's address/.test(s.text));

test('Acrobat Sign\'s domains are Adobe\'s', () => {
    const adobe = E.SENDER_NAME_BRANDS.find(b => b.name === 'Adobe');
    for (const d of ['adobesign.com', 'na4.adobesign.com', 'echosign.com', 'adobe.com']) assert.ok(E.senderDomainOwnedBy(adobe, d), d);
    assert.ok(!E.senderDomainOwnedBy(adobe, 'adobesign-docs.example'));
    assert.equal(E.aiSenderIdentity('Dana Madeup via Adobe Acrobat Sign', 'adobesign@adobesign.com', { own: [ORG] }).owner, 'yes');
});

test('a signature request through Acrobat Sign: a notification for the person who sent it, no brand sign', async () => {
    const f = await mail();
    const relay = N.platformNotification(f, [ORG]);
    assert.deepEqual([relay.platform, relay.name, relay.address], ['Adobe Acrobat Sign', 'Dana Madeup', 'dana.madeup@samplebroker.example']);
    const r = await judge();
    assert.deepEqual(brandSigns(r), []);
    assert.equal(r.status, 'clean', JSON.stringify(r.signals));
});

test('forged or look-alike Acrobat Sign mail still counts', async () => {
    const forged = await judge({ dmarc: 'fail' });
    assert.ok(forged.score >= 5, JSON.stringify(forged.signals));
    const look = await judge({ from: '"Dana Madeup via Adobe Acrobat Sign" <adobesign@adobesign-docs.example>', headerFrom: 'adobesign-docs.example' });
    assert.equal(brandSigns(look)[0].weight, 5);
});
