'use strict';
// 0.6.24: Adobe Campaign's click tracker (a brand's marketing mail sent through it) is an email provider's tracker:
// a link whose text shows the brand's site but goes to the tracker isn't dangerous, as with SendGrid or Mailchimp.
// Every name, address and text here is made up.
const test = require('node:test');
const assert = require('node:assert');
const spruce = require('../src/engine/spruce');
const { readMessage } = require('../src/engine/mime');
const { analyze } = require('../src/engine/analyze');

const E = spruce.load();
const ORG = 'maple-schools.example', USER = `pat.fakewell@${ORG}`;
const T = 'https://samplecable-mid-prod1-all-t.adobe-campaign.com/r/?id=h12ab,fa05dc0,de47f6&e=abc&s=xyz';

test('Adobe Campaign\'s tracker is an email provider\'s', () => {
    assert.equal(E.detectLinkProblem('www.paypal.com', T, T, E.builtinTrackers, {}), null);
    const N = 'https://samplecable.neolane.net/r/?id=1';
    assert.equal(E.detectLinkProblem('www.paypal.com', N, N, E.builtinTrackers, {}), null);
    const L = 'https://adobe-campaign-login.example/r/?id=1';
    assert.notEqual(E.detectLinkProblem('www.paypal.com', L, L, E.builtinTrackers, {}), null, 'a look-alike is not');
});

test('a brand\'s marketing mail through Adobe Campaign: its links aren\'t dangerous', async () => {
    const links = [1, 2, 3].map(i => `<a href="${T}&n=${i}">www.paypal.com</a>`).join(' ');
    const f = await readMessage(Buffer.from(['From: Sample Cable <offers@updates.samplecable.example>', `To: ${USER}`, 'Subject: Faster home internet this month',
        'Message-ID: <a1@updates.samplecable.example>', 'Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass header.from=updates.samplecable.example',
        'Content-Type: text/html; charset=utf-8', '', `<p>Upgrade your home internet this month.</p><p>${links}</p>`].join('\r\n')));
    const r = await analyze(f, { mailbox: USER, orgDomains: [ORG], readAttachments: false });
    assert.ok(!r.signals.some(s => s.kind === 'dangerous-links'), JSON.stringify(r.signals));
});
