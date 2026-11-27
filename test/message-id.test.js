'use strict';
// 0.6.56: a Message-ID in the name of a big mail provider (Gmail, Outlook, Yahoo, iCloud) on mail that shows no sign of
// having come through it is a copied ID (a forged header). Every address and host here is made up.
const test = require('node:test');
const assert = require('node:assert');
const E = require('../src/engine/spruce').load();

const USER = 'reader@maple-schools.example';
// The receiver's own records (Gmail writes these on every email it receives): never proof of the sender's provider.
const ARRIVAL = ['Received: by 2002:a05:6a10:1234 with SMTP id abc; Fri, 20 Nov 2026 10:00:02 -0800',
    'Received: from relay.vps-host.example (relay.vps-host.example. [203.0.113.7]) by mx.google.com with ESMTPS id x1; Fri, 20 Nov 2026 10:00:01 -0800',
    'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=madeup-billing.example; dmarc=pass header.from=madeup-billing.example'];
const raw = (messageId, extra = []) => [...ARRIVAL, ...extra, 'From: "Billing" <billing@madeup-billing.example>', `To: ${USER}`, 'Subject: Your invoice',
    'Date: Fri, 20 Nov 2026 10:00:00 -0800', `Message-ID: ${messageId}`, 'Content-Type: text/plain', '', 'Hello.'].join('\r\n');
const forged = (r) => E.headerAnomalies(r, USER, E.gmailReceiver).find(s => s.kind === 'forged-message-id');

test('a Gmail, Outlook, Yahoo or iCloud message ID with no sign of that provider is a copied ID', () => {
    const g = forged(raw('<CAF1abc2def3@mail.gmail.com>'));
    assert.ok(g, 'Gmail');
    assert.equal(g.weight, 2);
    assert.match(g.text, /claims it was written in Gmail, but nothing else in its headers shows it came through Gmail/);
    assert.ok(forged(raw('<SA1PR12MB0001.namprd12.prod.outlook.com>'.replace('<', '<abc@'))), 'Outlook');
    assert.ok(forged(raw('<123456.789.1700000000@mail.yahoo.com>')), 'Yahoo');
    assert.ok(forged(raw('<0A1B2C3D-0000@icloud.com>')), 'iCloud');
});

test('mail really sent through the provider, or an ID on any other domain, is not counted', () => {
    // Sent from Gmail: its signature and the headers Gmail's sending servers add.
    assert.equal(forged(raw('<CAF1abc2def3@mail.gmail.com>', ['DKIM-Signature: v=1; a=rsa-sha256; d=gmail.com; s=20230601; h=from:to:subject; bh=x; b=y', 'X-Gm-Message-State: AOJu0Yx'])), undefined);
    // A school on Google Workspace: its own signature, delivered from Google's servers.
    assert.equal(forged(raw('<CAF1abc2def3@mail.gmail.com>', ['Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) by mx.google.com with SMTPS id y2'])), undefined);
    // A Microsoft 365 organization: Exchange's headers and its onmicrosoft.com signature.
    assert.equal(forged(raw('<abc@SA1PR12MB0001.namprd12.prod.outlook.com>', ['X-MS-Exchange-Organization-AuthAs: Anonymous', 'DKIM-Signature: v=1; d=madeupschool.onmicrosoft.com; s=selector1; bh=x; b=y'])), undefined);
    assert.equal(forged(raw('<abc@SA1PR12MB0001.namprd12.prod.outlook.com>', ['Received: from NAM12-SN1-obe.outbound.protection.outlook.com (mail-sn1nam12on2101.outbound.protection.outlook.com [40.107.0.1]) by mx.google.com with ESMTPS id z3'])), undefined);
    // A mailing service's own ID, or the sender's: normal.
    assert.equal(forged(raw('<0100018c.abc@email.amazonses.com>')), undefined);
    assert.equal(forged(raw('<20261120.abc@madeup-billing.example>')), undefined);
    assert.equal(forged(raw('')), undefined, 'no Message-ID at all: not this check');
});

test('the AI reads only the checks it was trained on: the new kind changes the rules, not the model\'s input', () => {
    const { modelInputText } = E;
    const facts = { subject: 'Your invoice', senderName: 'Billing', senderAddress: 'billing@madeup-billing.example', bodyText: 'Hello.', links: [], mailChecks: ['forged-message-id'] };
    assert.equal(modelInputText(facts), modelInputText(Object.assign({}, facts, { mailChecks: [] })));
});

test('0.6.59: the analysis tells the policy\'s Straight to Spam what it found: a forged ID, and Gmail\'s DMARC result', async () => {
    const { readMessage } = require('../src/engine/mime');
    const { analyze } = require('../src/engine/analyze');
    const ctx = { mailbox: USER, orgDomains: ['maple-schools.example'] };
    const a = await analyze(await readMessage(Buffer.from(raw('<CAF1abc2def3@mail.gmail.com>'))), ctx);
    assert.deepEqual([a.strictSigns.forgedHeaders, a.strictSigns.dmarc], [['forged-message-id'], null], 'forged ID; DMARC passed');
    const failing = raw('<a1@madeup-billing.example>').replace('dmarc=pass', 'dmarc=fail');
    const b = await analyze(await readMessage(Buffer.from(failing)), ctx);
    assert.deepEqual([b.strictSigns.forgedHeaders, b.strictSigns.dmarc], [[], 'fail']);
    const flagged = raw('<a1@madeup-billing.example>', ['X-Spam-Flag: YES']);
    assert.deepEqual((await analyze(await readMessage(Buffer.from(flagged)), ctx)).strictSigns.spamHeaders, ['spam-flag'], '(0.6.65) a relay\'s spam flag');
    const none = raw('<a1@madeup-billing.example>').replace('dmarc=pass', 'dmarc=none');
    assert.equal((await analyze(await readMessage(Buffer.from(none)), ctx)).strictSigns.dmarc, 'missing');
});

// 0.6.93: more providers, each recognised by its own signature, headers or delivery record (never the ID's shape); mailing
// lists, news gateways and resent mail aren't counted. Hosts, IDs and selectors are made up in the providers' formats.
test('0.6.93: AOL, Zoho, Proton, GMX, Yandex, Mail.ru, Fastmail and Xfinity IDs with no sign of the provider are copied IDs', () => {
    for (const [name, id] of [['AOL', '<msgid-test-1@aol.com>'], ['AOL', '<msgid-test-2@verizon.net>'], ['Zoho Mail', '<msgid-test-12@zohomail.eu>'], ['Proton Mail', '<msgid-test-14=@proton.me>'],
        ['GMX', '<msgid-test-3@gmx.net>'], ['GMX', '<msgid-test-4@web.de>'], ['Yandex', '<1234567890123456@mail.yandex.ru>'], ['Mail.ru', '<1758700000.123456789@f323.i.mail.ru>'],
        ['Fastmail', '<0a1b2c3d-0000-4e5f@app.fastmail.com>'], ['Xfinity', '<123456789.12345.1700000000000@connect.xfinity.com>']]) {
        const f = forged(raw(id));
        assert.ok(f, `${name}: ${id}`);
        assert.match(f.text, new RegExp(`written in ${name.replace('.', '\\.')}`));
    }
});

test('0.6.93: real mail through each provider is not counted: its signature, its own headers, or its servers delivering it', () => {
    const ok = (id, extra, why) => assert.equal(forged(raw(id, extra)), undefined, why);
    // AOL webmail writes a Yahoo ID and signs as aol.com; Verizon and AT&T as theirs; their sending servers add X-Sonic headers.
    ok('<1234567890.123456.1700000000000@mail.yahoo.com>', ['DKIM-Signature: v=1; a=rsa-sha256; d=aol.com; s=a2048; bh=x; b=y'], 'AOL webmail');
    ok('<msgid-test-5@verizon.net>', ['DKIM-Signature: v=1; d=verizon.net; s=a2048; bh=x; b=y'], 'Verizon, from a mail program');
    ok('<msgid-test-6@att.net>', ['X-Sonic-ID: 0a1b2c3d4e5f'], 'AT&T');
    ok('<msgid-test-13@zoho.com>', ['Received: from sender4-op-o12.zoho.com (sender4-op-o12.zoho.com [136.143.188.12]) by mx.google.com with ESMTPS id z9'], 'Zoho');
    ok('<msgid-test-15=@pm.me>', ['X-Pm-Message-Id: <msgid-test-15=@pm.me>'], 'Proton');
    ok('<msgid-test-7@gmx.de>', ['X-UI-Sender-Class: 00000000-0000-0000-0000-000000000000', 'X-Provags-ID: V03:K1:abc'], 'GMX, from a mail program');
    ok('<msgid-test-8@web.de>', ['DKIM-Signature: v=1; d=Web.DE; s=s29768273; bh=x; b=y'], 'web.de (its signature in capitals)');
    ok('<1234567890123456@mail.yandex.ru>', ['X-Yandex-Fwd: 1'], 'Yandex');
    ok('<1758700000.123456789@f323.i.mail.ru>', ['Received: from send123.i.mail.ru (send123.i.mail.ru [95.163.59.1]) by mx.google.com with ESMTPS id k1'], 'Mail.ru');
    ok('<0a1b2c3d-0000-4e5f@app.fastmail.com>', ['DKIM-Signature: v=1; d=messagingengine.com; s=fm3; bh=x; b=y'], 'Fastmail (also on a custom domain)');
    ok('<123456789.12345.1700000000000@connect.xfinity.com>', ['DKIM-Signature: v=1; d=comcast.net; s=20190202a; bh=x; b=y'], 'Xfinity');
    // Another provider's ID with only this provider's signs is still counted (the sign must be the claimed provider's).
    assert.ok(forged(raw('<msgid-test-9@gmx.net>', ['X-Pm-Message-Id: <msgid-test-10@pm.me>'])), 'a GMX ID with Proton\'s header');
});

test('0.6.93: mail a mailing list, a news gateway or a resend passed on keeps the original ID: not counted', () => {
    for (const h of ['List-Id: <school-news.lists.madeup.example>', 'List-Post: <mailto:news@lists.madeup.example>', 'Resent-From: forwarder@madeup.example', 'Newsgroups: madeup.lists.discussion']) {
        assert.equal(forged(raw('<msgid-test-11@gmx.de>', [h])), undefined, h);
        assert.equal(forged(raw('<CAF1abc2def3@mail.gmail.com>', [h])), undefined, `${h} (Gmail too)`);
    }
});
