'use strict';
// (0.5.73) Allowed link domains (Settings → Allowlist): a phishing list's listing of the whole domain doesn't flag
// links to it (a newsletter's click tracker listed by mistake), in anyone's mail; a listing of the exact page still
// does, and where a link leads is judged as before. Made-up domains and lists.
const test = require('node:test');
const assert = require('node:assert');
const { readMessage } = require('../src/engine/mime');
const { analyze } = require('../src/engine/analyze');
const { policyValue } = require('../src/pipeline');

// A list that has the whole of tracker.vendor.example and evil-login.example, and one exact page on the tracker.
const LIST = 'HaGeZi Threat Intelligence Feeds';
const feeds = {
    urlHit: async (url, { exactOnly = false } = {}) => {
        if (url === 'https://l.vendor.example/hacked/login') return 'OpenPhish community feed';
        if (exactOnly) return null;
        const host = new URL(url).hostname;
        return /(^|\.)l\.vendor\.example$|(^|\.)evil-login\.example$/.test(host) ? LIST : null;
    },
    domainHit: async () => null, addressHit: async () => null, confidenceOf: () => 'list'
};
const raw = (html) => Buffer.from(['From: "Vendor News" <news@vendor.example>', 'To: reader@maple-schools.example', 'Subject: This week\'s deals', 'Message-ID: <n1@vendor.example>',
    'Authentication-Results: mx.google.com; dkim=pass header.i=@vendor.example; spf=pass; dmarc=pass header.from=vendor.example', 'Content-Type: text/html', '', html].join('\r\n'));
const judge = async (html, allowLinkDomains) => analyze(await readMessage(raw(html)), { mailbox: 'reader@maple-schools.example', orgDomains: ['maple-schools.example'],
    intel: { feeds }, allowLinkDomains, readAttachments: false });
const LINKS = '<p>New deals this week.</p><a href="https://l.vendor.example/c/abc">Shop now</a> <a href="https://l.vendor.example/c/def">See more</a>';

test('a link domain on a list is dangerous until it is allowed; then its listing is a note of no weight', async () => {
    let r = await judge(LINKS, []);
    assert.deepEqual(r.links.map(l => l.severity), ['danger', 'danger']);
    assert.ok(r.signals.some(s => s.kind === 'dangerous-links' && s.weight === 5));
    r = await judge(LINKS, ['l.vendor.example']);
    assert.ok(r.links.every(l => l.severity !== 'danger'), JSON.stringify(r.links));
    assert.ok(!r.signals.some(s => s.kind === 'dangerous-links'));
    const note = r.signals.find(s => s.kind === 'allowed-link-domain');
    assert.ok(note && note.weight === 0 && /l\.vendor\.example/.test(note.text) && note.text.includes(LIST), JSON.stringify(r.signals));
    // Its parent domain allows it too; another site's listing still counts.
    r = await judge(`${LINKS} <a href="https://evil-login.example/x">Sign in</a>`, ['vendor.example']);
    assert.deepEqual(r.links.filter(l => l.severity === 'danger').map(l => new URL(l.url).hostname), ['evil-login.example'], 'only the other site (the record lists flagged links only)');
    assert.ok(r.signals.some(s => s.kind === 'dangerous-links'));
});

test('an exact page listed on an allowed link domain still flags its link', async () => {
    const r = await judge('<a href="https://l.vendor.example/hacked/login">Sign in</a>', ['l.vendor.example']);
    assert.equal(r.links[0].severity, 'danger');
    assert.match(r.links[0].reason, /OpenPhish/);
    assert.ok(!r.signals.some(s => s.kind === 'allowed-link-domain'), 'the link was flagged: no note');
});

test('the setting: one site per line; not shared hosting, shorteners, suffixes, big brands or your own domains', () => {
    const now = { orgDomains: ['maple-schools.example'] };
    assert.deepEqual(policyValue('allowLinkDomains', 'l.vendor.example\nVendor2.example', now), ['l.vendor.example', 'vendor2.example']);
    for (const [v, why] of [['github.io', /other people's sites/], ['pages.github.io', /anyone can put up a page/], ['someone.netlify.app', /anyone can put up a page/],
        ['bit.ly', /link shortener/], ['co.uk', /suffix/], ['docs.google.com', /never listed whole/], ['storage.googleapis.com', /never listed whole|cloud-storage/],
        ['maple-schools.example', /own domain/], ['news.maple-schools.example', /own domain/], ['not a domain', /isn't a domain/]]) {
        assert.throws(() => policyValue('allowLinkDomains', v, now), (e) => e.status === 400 && why.test(e.message), v);
    }
});
