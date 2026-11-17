'use strict';
// 0.6.25: the links sign has one weight however many links are flagged, set by the worst: 5 for a blocked or listed
// site or a link that is evidence on its own (a look-alike, a hidden "@" name, code to run); 3 for a site with a low
// reputation (new, or on Spamhaus's lists); 2 for links flagged only by their text. Every name and address is made up.
const test = require('node:test');
const assert = require('node:assert');
const { readMessage } = require('../src/engine/mime');
const { analyze } = require('../src/engine/analyze');

const ORG = 'maple-schools.example', USER = `pat.fakewell@${ORG}`;
const mail = (links) => readMessage(Buffer.from(['From: Sample Rewards <offers@samplerewards.example>', `To: ${USER}`, 'Subject: This week\'s offers',
    'Message-ID: <w1@samplerewards.example>', 'Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass header.from=samplerewards.example',
    'Content-Type: text/html; charset=utf-8', '', `<p>This week's offers.</p><p>${links.map(([t, u]) => `<a href="${u}">${t}</a>`).join(' ')}</p>`].join('\r\n')));
const intelOf = ({ days = 4000, unsafe = [] } = {}) => ({
    threats: { enabled: { safeBrowsing: false }, checkUrls: async () => new Map(), checkHosts: async (h) => new Map(h.map(x => [x, unsafe.includes(x) ? { verdict: 'unsafe', reason: 'blocked by Cloudflare Security as phishing', by: 'Cloudflare Security' } : { verdict: 'clean', by: 'Cloudflare Security' }])) },
    feeds: { urlHit: async () => null, addressHit: async () => null, domainHit: async () => null }, rdap: { ageDays: async () => days },
    ownership: { of: async () => ({ state: 'unknown', how: '' }), ofCompany: async () => ({ state: 'unknown', how: '' }) } });
const linkSign = async (links, intel = intelOf()) => (await analyze(await mail(links), { mailbox: USER, orgDomains: [ORG], readAttachments: false, intel })).signals.find(s => s.kind === 'dangerous-links');
const brandLink = (i) => ['www.paypal.com', `https://links.sampletracker.example/c/${i}`];

test('links flagged only by their text, nothing known against the site: 2, however many', async () => {
    for (const n of [1, 2, 7]) {
        const s = await linkSign(Array.from({ length: n }, (_, i) => brandLink(i)));
        assert.equal(s.weight, 2, `${n} links`);
        assert.match(s.text, /Nothing is known against the site \(not blocked, listed or new\), so it counts 2\.$/);
    }
});

test('a site with a low reputation (registered in the last 90 days): 3, however many', async () => {
    for (const n of [1, 3]) assert.equal((await linkSign(Array.from({ length: n }, (_, i) => brandLink(i)), intelOf({ days: 20 }))).weight, 3, `${n} links`);
});

test('a blocked site, or a link that is evidence on its own: 5, even one among many', async () => {
    const plain = [['Read more', 'https://www.samplerewards.example/a'], ['Offers', 'https://www.samplerewards.example/b']];
    assert.equal((await linkSign([...plain, ['Claim', 'https://claim-now.example/x']], intelOf({ unsafe: ['claim-now.example'] }))).weight, 5, 'blocked by Cloudflare');
    assert.equal((await linkSign([...plain, ['PayPal', 'https://paypa1.com/login']])).weight, 5, 'a look-alike of a brand\'s domain');
    assert.equal((await linkSign([...plain, ['Sign in', 'https://paypal.com@claim-now.example/']])).weight, 5, 'a name hidden before "@"');
    assert.equal((await linkSign([...plain, brandLink(1), brandLink(2)], intelOf({ unsafe: ['links.sampletracker.example'] }))).weight, 5, 'the text-flagged links\' site blocked');
});
