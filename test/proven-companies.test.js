'use strict';
// 0.6.48: no hand-kept company families. A company's other domains are proven from public records and learned for the
// link checks: owned for everything, likely for links only; shared by every instance through the store. Every domain but
// the brands' main ones is made up.
const test = require('node:test');
const assert = require('node:assert');
const E = require('../src/engine/spruce').load();
const { createCompanyIndex } = require('../src/intel/companies');
const { MemoryStore } = require('../src/store/memory');
const { readMessage } = require('../src/engine/mime');
const { analyze } = require('../src/engine/analyze');

test('learned domains: owned counts everywhere, likely for links only; a main domain stays main', () => {
    E.learnCompanyDomains([{ domain: 'msdocs-madeup.example', name: 'Microsoft', state: 'owned' }, { domain: 'msstore-madeup.example', name: 'Microsoft', state: 'likely' }], true);
    const ms = E.SENDER_NAME_BRANDS.find(b => b.name === 'Microsoft');
    assert.equal(E.brandOfDomain('msdocs-madeup.example'), 'Microsoft');
    assert.equal(E.brandOfDomain('msstore-madeup.example'), 'Microsoft', 'for the link checks');
    assert.ok(E.senderDomainOwnedBy(ms, 'msdocs-madeup.example'));
    assert.ok(!E.senderDomainOwnedBy(ms, 'msstore-madeup.example'), 'likely is no proof for a sender\'s name');
    assert.equal(E.companyDomainState('microsoft.com'), 'main');
    E.learnCompanyDomains([], true);
    assert.equal(E.brandOfDomain('msdocs-madeup.example'), null, 'a reload replaces them');
    assert.equal(E.brandOfDomain('youtube.com'), null, 'no hand-kept family: Google\'s youtube.com only once proven');
});

test('the shared store: what one instance proves, another loads; entries over 60 days dropped', async () => {
    const store = new MemoryStore();
    let t = Date.now();
    const a = createCompanyIndex({ store, engine: E, now: () => t, log: { error() {} } });
    a.learn('goodocs-madeup.example', 'Google', 'owned');
    await a.write();
    E.learnCompanyDomains([], true);
    const b = createCompanyIndex({ store, engine: E, now: () => t, log: { error() {} } });
    assert.equal(await b.load(), 1);
    assert.equal(E.brandOfDomain('goodocs-madeup.example'), 'Google');
    t += 61 * 86400000;
    assert.equal(await b.load(), 0, 'too old');
    assert.equal(E.brandOfDomain('goodocs-madeup.example'), null);
});

test('a link between two of the sender company\'s other domains (the company its name claims): both proven, not counted; one unproven, as before', async () => {
    E.learnCompanyDomains([], true);
    const raw = Buffer.from(['From: "Microsoft" <account@msnotify-madeup.example>', 'To: pat.fakewell@maple-schools.example', 'Subject: Your files', 'Message-ID: <m1@maple-schools.example>',
        'Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass header.from=msnotify-madeup.example', 'Content-Type: text/html; charset=utf-8', '',
        '<p>Your files are ready.</p><p><a href="https://msfiles-madeup.example/open">msmail-madeup.example/files</a></p>'].join('\r\n'));
    const intelWith = (owner) => ({
        threats: { enabled: { safeBrowsing: false }, checkUrls: async () => new Map(), checkHosts: async (hosts) => new Map(hosts.map(h => [h, { verdict: 'clean', by: 'Cloudflare Security' }])) },
        feeds: { urlHit: async () => null, addressHit: async () => null, domainHit: async () => null }, rdap: { ageDays: async () => 4000 },
        ownership: { of: async (d, brand, opts) => (opts && opts.link && owner[d] ? { state: owner[d], how: `made-up proof for ${d}` } : { state: 'unknown', how: '' }), ofCompany: async () => ({ state: 'unknown', how: '' }) } });
    const judge = async (owner) => analyze(await readMessage(raw), { mailbox: 'pat.fakewell@maple-schools.example', orgDomains: ['maple-schools.example'], intel: intelWith(owner) });
    const both = await judge({ 'msfiles-madeup.example': 'owned', 'msmail-madeup.example': 'likely' });
    assert.ok(both.signals.some(s => s.kind === 'same-company-link'), JSON.stringify(both.signals));
    assert.ok(!both.links.some(l => l.severity), 'not counted');
    const one = await judge({ 'msfiles-madeup.example': 'owned' });
    assert.ok(!one.signals.some(s => s.kind === 'same-company-link'), 'one side unproven: judged as before');
});

// 0.6.49: a domain an admin confirmed from a registry's own web page (for registries the service can't read).
test('confirmed company domains: added with where it was checked, refused when wrong, proof for the lookup, removed', async () => {
    const { loadConfig } = require('../src/config');
    const { Service } = require('../src/pipeline');
    const { createOwnership } = require('../src/intel/ownership');
    const ORG = 'maple-schools.example', ADMIN = `it.madeup@${ORG}`;
    const svc = new Service({ cfg: loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: `pat.fakewell@${ORG}` }), store: new MemoryStore(), gmail: {}, log: { error() {}, warn() {} } });
    assert.equal((await svc.addConfirmedDomain('shop-madeup.example', 'Amazon', '', ADMIN)).status, 400, 'where it was checked is required');
    assert.equal((await svc.addConfirmedDomain('shop-madeup.example', 'Nobody', 'a page', ADMIN)).status, 400, 'a known company');
    assert.equal((await svc.addConfirmedDomain('gmail.com', 'Google', 'a page', ADMIN)).status, 400, 'a personal provider: everyone\'s');
    assert.equal((await svc.addConfirmedDomain(`x.${ORG}`, 'Amazon', 'a page', ADMIN)).status, 400, 'our own domain');
    assert.equal((await svc.addConfirmedDomain('amazon.com', 'Amazon', 'a page', ADMIN)).status, 400, 'already its main domain');
    assert.equal((await svc.addConfirmedDomain('www.shop-madeup.example/page', 'Amazon', 'a page', ADMIN)).status, 400, 'the domain itself');
    const out = await svc.addConfirmedDomain('Shop-Madeup.Example', 'Amazon', 'the registry\'s page: Amazon Madeup S.a r.l.', ADMIN);
    assert.equal(out.domain, 'shop-madeup.example');
    assert.equal(out.confirmed[0].note, 'the registry\'s page: Amazon Madeup S.a r.l.');
    assert.ok((await svc.store.listEvents(0, { limit: 5 })).some(e => /confirmed shop-madeup\.example as Amazon's domain/.test(e.text)));
    const own = createOwnership({ http: { request: async () => { throw new Error('not asked'); } }, store: svc.store, engine: E, rdapServer: async () => null });
    const r = await own.of('shop-madeup.example', 'Amazon');
    assert.equal(r.state, 'owned');
    assert.match(r.how, /^confirmed by it\.madeup@maple-schools\.example from the registry's own page/);
    assert.equal((await own.of('shop-madeup.example', 'PayPal')).state, 'unknown', 'only for the company it was confirmed for');
    // Suspended by the 30-day check: no longer proof.
    await svc.store.setState('allowWatch', { domains: { 'shop-madeup.example': { review: { suspended: true } } } });
    const later = createOwnership({ http: { request: async () => ({ ok: true, status: 200, json: async () => ({ Status: 0, Answer: [] }) }) }, store: svc.store, engine: E, rdapServer: async () => null });
    assert.notEqual((await later.of('shop-madeup.example', 'Amazon')).state, 'owned', 'suspended');
    assert.equal((await svc.removeConfirmedDomain('shop-madeup.example', ADMIN)).confirmed.length, 0);
    E.learnCompanyDomains([], true);
});
