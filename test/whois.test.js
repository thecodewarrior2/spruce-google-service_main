'use strict';
// 0.6.47: WHOIS as the ownership lookup's fallback, when RDAP leaves the registrant organization blank (some registrars
// blank it there but keep it in WHOIS). Made-up WHOIS servers and answers; no real one is asked.
const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('events');
const { createWhois, field } = require('../src/intel/whois');
const spruce = require('../src/engine/spruce');
const { createOwnership } = require('../src/intel/ownership');
const { MemoryStore } = require('../src/store/memory');

// A made-up port-43 world: server → (query → answer), or 'hang'.
function fakeConnect(world, asked = []) {
    return ({ host }) => {
        const s = new EventEmitter();
        s.setEncoding = () => {};
        s.destroy = () => {};
        s.write = (q) => { const query = q.trim(); asked.push([host, query]); const a = world[host] && world[host][query]; if (a === 'hang' || a === undefined && world[host] === 'hang') return; setImmediate(() => { s.emit('data', a || ''); s.emit('end'); }); };
        setImmediate(() => s.emit('connect'));
        return s;
    };
}
const WORLD = {
    'whois.iana.org': { example: 'domain: EXAMPLE\nwhois: whois.registry.example\n' },
    'whois.registry.example': {
        'corp-docs.example': 'Domain Name: CORP-DOCS.EXAMPLE\nRegistrar WHOIS Server: whois.corpregistrar.example\nRegistrar: Madeup Corporate Domains\n',
        'hidden-org.example': 'Domain Name: HIDDEN-ORG.EXAMPLE\nRegistrar WHOIS Server: whois.corpregistrar.example\n'
    },
    'whois.corpregistrar.example': {
        'corp-docs.example': 'Domain Name: corp-docs.example\nRegistrant Name: REDACTED FOR PRIVACY\nRegistrant Organization: PayPal, Inc.\nRegistrant Country: US\n',
        'hidden-org.example': 'Registrant Organization: REDACTED FOR PRIVACY\n'
    }
};

test('the registrant organization from the registrar\'s WHOIS, through the registry\'s; hidden: none', async () => {
    const asked = [];
    const w = createWhois({ connect: fakeConnect(WORLD, asked) });
    assert.equal(await w.registrantOrg('corp-docs.example'), 'PayPal, Inc.');
    assert.deepEqual(asked.map(a => a[0]), ['whois.iana.org', 'whois.registry.example', 'whois.corpregistrar.example']);
    assert.equal(await w.registrantOrg('hidden-org.example'), '', 'redacted');
    assert.equal(asked.filter(a => a[0] === 'whois.iana.org').length, 1, 'the ending\'s server asked once');
    assert.equal(field('Registrant Organisation: Example Ltd\n', ['registrant organisation']), 'Example Ltd');
});

test('a WHOIS server that doesn\'t answer is given up', async () => {
    const w = createWhois({ connect: fakeConnect({ 'whois.iana.org': 'hang' }), waitMs: 50 });
    await assert.rejects(w.registrantOrg('corp-docs.example'), /no answer/);
});

test('in the ownership lookup: RDAP blank, WHOIS names the brand, a corporate registrar: proof (WHOIS)', async () => {
    const E = spruce.load();
    const http = { request: async (url) => {
        const u = new URL(url);
        if (u.hostname === 'cloudflare-dns.com') return { ok: true, status: 200, json: async () => ({ Status: 0, Answer: [] }) };
        return { ok: true, status: 200, json: async () => ({ events: [], entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'MarkMonitor Inc.']]] }, { roles: ['registrant'], vcardArray: ['vcard', [['fn', {}, 'text', '']]] }] }) };
    } };
    const own = createOwnership({ http, store: new MemoryStore(), engine: E, rdapServer: async () => 'https://rdap.registry.example/', whois: createWhois({ connect: fakeConnect(WORLD) }) });
    assert.deepEqual(await own.of('corp-docs.example', 'PayPal'), { state: 'owned', how: 'registered to PayPal, Inc. through MarkMonitor Inc. (WHOIS)' });
    const noWhois = createOwnership({ http, store: new MemoryStore(), engine: E, rdapServer: async () => 'https://rdap.registry.example/' });
    assert.notEqual((await noWhois.of('corp-docs.example', 'PayPal')).state, 'owned', 'without WHOIS: no registrant, no proof');
});
