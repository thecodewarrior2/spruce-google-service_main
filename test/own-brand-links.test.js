'use strict';
// 0.6.17: a link whose text shows another site but which goes to the sender's own domain, when public records prove
// that domain is the company it is named after (registered to it through a corporate registrar, say) and Gmail's DMARC
// check passed for it: the company's own click tracker, also behind a partner's text (a co-branded card). Not
// dangerous; a note of no weight. A look-alike can't have that proof, so it stays dangerous; so does the same link when
// DMARC didn't pass or a lookup found something against it. Every company, address and text here is made up.
const test = require('node:test');
const assert = require('node:assert');
const { readMessage } = require('../src/engine/mime');
const { analyze } = require('../src/engine/analyze');
const { decide } = require('../src/policy');
const { loadConfig } = require('../src/config');
const { companyWordOf } = require('../src/engine/mailers');

const ORG = 'maple-schools.example', USER = `sam.testwood@${ORG}`;
const OWN = 'email-lakeviewhotels.example';
const mail = ({ from = `offers@${OWN}`, dmarc = 'pass', links } = {}) => Buffer.from([`From: "Lakeview Hotels Rewards" <${from}>`, `To: ${USER}`,
    'Subject: Your points are waiting', 'Message-ID: <r1@mail.lakeview.example>',
    `Authentication-Results: mx.google.com; dkim=pass header.i=@${from.split('@')[1]}; spf=pass; dmarc=${dmarc} header.from=${from.split('@')[1]}`,
    'Content-Type: text/html; charset=utf-8', '', `<p>Book your next stay and earn more points.</p>${links}`].join('\r\n'));
const linkTo = (host, text) => `<p><a href="https://${host}/c/9f2a?u=31">${text}</a></p>`;
const LINKS = linkTo(`click.${OWN}`, 'www.lakeviewhotels.example') + linkTo(`click.${OWN}`, 'paypal.com') + linkTo(`click.${OWN}`, 'Book now');
// The lookups, made up: Cloudflare's verdict, the lists, the ages, and whose a domain is.
const intelOf = ({ owner = { [OWN]: 'owned' }, blocked = [] } = {}) => {
    const asked = [];
    return { asked,
        threats: { enabled: { safeBrowsing: false }, checkUrls: async () => new Map(),
            checkHosts: async (hosts) => new Map(hosts.map(h => [h, blocked.some(b => h.endsWith(b)) ? { verdict: 'unsafe', by: 'Cloudflare Security', reason: 'Cloudflare Security blocks it as malware or phishing' } : { verdict: 'clean', by: 'Cloudflare Security' }])) },
        feeds: { urlHit: async () => null, addressHit: async () => null, domainHit: async () => null },
        rdap: { ageDays: async () => 4000 },
        ownership: { of: async () => ({ state: 'unknown', how: '' }), ofCompany: async (d, name, homes) => { asked.push([d, name, homes]); return owner[d] === 'owned' ? { state: 'owned', how: 'registered to Lakeview Hotels Group through a corporate registrar' } : { state: 'unknown', how: '' }; } }
    };
};
const judge = async (raw, intel) => analyze(await readMessage(raw), { mailbox: USER, orgDomains: [ORG], intel });
const enforce = loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: USER, MODE: 'enforce' });

test('the company a domain is named after: its marketing words taken off', () => {
    assert.equal(companyWordOf('email-lakeviewhotels.example'), 'lakeviewhotels');
    assert.equal(companyWordOf('lakeviewhotels-news.example'), 'lakeviewhotels');
    assert.equal(companyWordOf('go-mail.example'), null, 'nothing but marketing words');
    assert.equal(companyWordOf('two-words.example'), null, 'more than one word: no single company');
    assert.equal(companyWordOf('abc.example'), null, 'too short to name a company');
});

test('the sender\'s own proven domain behind its own and a partner\'s text: not dangerous, a note of no weight', async () => {
    const intel = intelOf();
    const r = await judge(mail({ links: LINKS }), intel);
    assert.ok(!r.signals.some(s => s.kind === 'dangerous-links'), JSON.stringify(r.signals));
    const note = r.signals.find(s => s.kind === 'own-brand-link');
    assert.equal(note.weight, 0);
    assert.match(note.text, /^2 links show another site but go to the sender's own domain, email-lakeviewhotels\.example, which public records prove is the company it is named after \(registered to Lakeview Hotels Group/);
    for (const l of r.links.filter(x => /lakeviewhotels|paypal/.test(x.text || ''))) assert.match(l.reason, /the sender's own domain, proven to be Lakeviewhotels's .*not counted$/);
    assert.deepEqual(intel.asked, [[OWN, 'lakeviewhotels', ['lakeviewhotels.example', 'lakeviewhotels.com']]], 'one lookup for the domain, against the company\'s own site');
    assert.notEqual(decide(r, enforce, {}).action, 'move');
});

test('no proof, DMARC not passing, a link elsewhere, or a lookup against it: judged as before', async () => {
    // (the partner's text, a protected brand, stays dangerous; no note)
    const dangerous = (r) => r.links.some(l => /paypal/.test(l.reason || '') && l.severity === 'danger') && !r.signals.some(s => s.kind === 'own-brand-link');
    assert.ok(dangerous(await judge(mail({ links: LINKS }), intelOf({ owner: {} }))), 'not proven the company\'s (a look-alike registered by anyone)');
    assert.ok(dangerous(await judge(mail({ links: LINKS, dmarc: 'fail' }), intelOf())), 'Gmail\'s DMARC check failed: the sender isn\'t that domain');
    const blocked = await judge(mail({ links: LINKS }), intelOf({ blocked: [OWN] }));
    assert.ok(blocked.links.every(l => l.severity === 'danger') && !blocked.signals.some(s => s.kind === 'own-brand-link'), 'Cloudflare blocks it: dangerous, its block the reason');
    const elsewhere = linkTo('click.lakeview-rewards-login.example', 'paypal.com');
    assert.ok(dangerous(await judge(mail({ links: elsewhere }), intelOf({ owner: { 'lakeview-rewards-login.example': 'owned' } }))), 'not the sender\'s own domain');
    const amber = await judge(mail({ links: linkTo(`click.${OWN}`, 'www.lakeviewhotels.example') }), intelOf({ owner: {} }));
    assert.equal(amber.links[0].severity, 'caution', 'an ordinary site\'s text, unproven: amber as before');
});
