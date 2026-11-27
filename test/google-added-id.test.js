'use strict';
// 0.6.91: a Message-ID Gmail wrote itself (…SMTPIN_ADDED_MISSING / SMTPIN_ADDED_BROKEN@mx.google.com): half a point, from
// outside the organization only; never given to the AI. Every sender, address and email here is made up.
const test = require('node:test');
const assert = require('node:assert');
const { analyze, googleAddedIdSigns } = require('../src/engine/analyze');
const { readMessage } = require('../src/engine/mime');
const E = require('../src/engine/spruce').load();

const ORG = 'maple-schools.example', PAT = `pat.fakewell@${ORG}`;
const raw = (from, mid, text = 'Hello, your order is ready for pickup at the front desk.') => Buffer.from([`From: Front Desk <${from}>`, `To: ${PAT}`, 'Subject: Order ready',
    ...(mid ? [`Message-ID: ${mid}`] : []), `Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=${from.split('@')[1]}; dkim=pass header.i=@${from.split('@')[1]}; dmarc=pass header.from=${from.split('@')[1]}`,
    'Content-Type: text/plain', '', text].join('\r\n'));
const BROKEN = '<6720a1b2c3d4e5f6.SMTPIN_ADDED_BROKEN@mx.google.com>', MISSING = '<5f1e2d3c4b5a6978.SMTPIN_ADDED_MISSING@mx.google.com>';

test('the sign: either kind Gmail writes, outside only; an ordinary or another provider\'s ID is nothing', () => {
    const s = googleAddedIdSigns({ messageIdHeader: BROKEN }, false);
    assert.deepEqual(s.map(x => [x.kind, x.weight]), [['google-added-message-id', 0.5]]);
    assert.match(s[0].text, /breaks the email standard/);
    assert.match(googleAddedIdSigns({ messageIdHeader: MISSING }, false)[0].text, /didn't write one/);
    assert.deepEqual(googleAddedIdSigns({ messageIdHeader: BROKEN }, true), [], 'your own organization\'s mail (a copier, a script)');
    for (const mid of ['<abc123@shop.example>', '<CA+x1y2@mail.gmail.com>', '<x.SMTPIN_ADDED_BROKEN@evil.example>', '']) assert.deepEqual(googleAddedIdSigns({ messageIdHeader: mid }, false), [], mid);
});

test('in analyze: half a point, alone never suspicious, not in the AI\'s input; not for your own staff', async () => {
    const opts = { mailbox: PAT, orgDomains: [ORG], keepAiFacts: true };
    const plain = await analyze(await readMessage(raw('desk@shop.example', '<abc123@shop.example>')), opts);
    const added = await analyze(await readMessage(raw('desk@shop.example', BROKEN)), opts);
    assert.ok(added.signals.some(s => s.kind === 'google-added-message-id' && s.weight === 0.5));
    assert.equal(added.status, plain.status, 'alone: the same verdict');
    assert.ok(!added.aiFacts.mailChecks.includes('google-added-message-id'), 'not among the header checks the AI reads');
    assert.equal(E.modelInputText(added.aiFacts, E.model.meta.inputFormat), E.modelInputText(plain.aiFacts, E.model.meta.inputFormat), 'the AI reads the same text');
    assert.equal(added.ai && added.ai.probability, plain.ai && plain.ai.probability, 'the same AI score');
    const staff = await analyze(await readMessage(raw(`copier@${ORG}`, MISSING, 'Scanned document attached.')), opts);
    assert.ok(!staff.signals.some(s => s.kind === 'google-added-message-id'), 'a copier in your own domain');
});
