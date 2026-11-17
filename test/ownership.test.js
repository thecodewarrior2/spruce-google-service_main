'use strict';
// (0.5.64) Whose a sender's domain is when its name claims a brand: from public records (made-up DNS and RDAP
// answers here), never from a hand-kept list. Every domain but the brands' own is made up.
const test = require('node:test');
const assert = require('node:assert');
const spruce = require('../src/engine/spruce');
const { createOwnership } = require('../src/intel/ownership');
const { MemoryStore } = require('../src/store/memory');
const { readMessage } = require('../src/engine/mime');
const { analyze } = require('../src/engine/analyze');

const E = spruce.load();
const RDAP = 'https://rdap.registry.example/';
// world: { 'name|TYPE': [records], rdap: { domain: { registrar, registrant, created } } }
function fakeHttp(world) {
    const asked = [];
    const reply = (body, ok = true) => ({ ok, status: ok ? 200 : 404, json: async () => body });
    return {
        asked,
        request: async (url) => {
            asked.push(url);
            const u = new URL(url);
            if (u.hostname === 'cloudflare-dns.com') {
                const name = u.searchParams.get('name'), type = u.searchParams.get('type');
                const data = world[`${name}|${type}`] || [];
                return reply({ Status: 0, Answer: data.map(d => ({ type: type === 'NS' ? 2 : 16, data: type === 'TXT' ? `"${d}"` : `${d}.` })) });
            }
            const m = /\/domain\/(.+)$/.exec(u.pathname);
            const r = m && world.rdap && world.rdap[decodeURIComponent(m[1])];
            if (!r) return reply({}, false);
            const ent = (role, name) => ({ roles: [role], vcardArray: ['vcard', [['fn', {}, 'text', name]]] });
            return reply({ events: r.created ? [{ eventAction: 'registration', eventDate: new Date(r.created).toISOString() }] : [],
                entities: [r.registrar ? ent('registrar', r.registrar) : null, r.registrant ? ent('registrant', r.registrant) : null].filter(Boolean) });
        }
    };
}
const make = (world) => {
    const http = fakeHttp(world);
    return { http, own: createOwnership({ http, store: new MemoryStore(), engine: E, rdapServer: async () => RDAP }) };
};
const YEARS = (n) => Date.now() - n * 365 * 86400000;

test('owned: name servers under the brand\'s domain, or the same set as the brand\'s; shared providers prove nothing', async () => {
    let { own } = make({ 'service.xoom.com|NS': [], 'xoom.com|NS': ['ns1-pchnet.paypal.com', 'pdns100.ultradns.com'] });
    assert.deepEqual(await own.of('service.xoom.com', 'PayPal'), { state: 'owned', how: 'its name servers are PayPal\'s (ns1-pchnet.paypal.com)' });
    ({ own } = make({ 'brand-mail.example|NS': ['a.dns.brandops.example', 'b.dns.brandops.example'], 'paypal.com|NS': ['a.dns.brandops.example', 'b.dns.brandops.example'] }));
    assert.equal((await own.of('brand-mail.example', 'PayPal')).state, 'owned');
    ({ own } = make({ 'paypal-help.example|NS': ['pdns100.ultradns.com', 'pdns100.ultradns.net'], 'paypal.com|NS': ['pdns100.ultradns.com', 'pdns100.ultradns.net'] }));
    assert.equal((await own.of('paypal-help.example', 'PayPal')).state, 'unknown', 'a provider every customer shares');
});

test('owned: DMARC reports either way (the other way only with the brand\'s authorization, not a wildcard)', async () => {
    let { own } = make({ '_dmarc.facebook.com|TXT': ['v=DMARC1; p=reject; rua=mailto:a@fbmail-reports.example'] });
    assert.match((await own.of('fbmail-reports.example', 'Meta')).how, /facebook\.com sends its own DMARC reports to it/);
    const theirs = { '_dmarc.paypal-notices.example|TXT': ['v=DMARC1; p=reject; rua=mailto:d@paypal.com'] };
    ({ own } = make(theirs));
    assert.equal((await own.of('paypal-notices.example', 'PayPal')).state, 'unknown', 'reports sent to the brand: anyone can write that');
    ({ own } = make(Object.assign({ 'paypal-notices.example._report._dmarc.paypal.com|TXT': ['v=DMARC1'] }, theirs)));
    assert.equal((await own.of('paypal-notices.example', 'PayPal')).state, 'owned');
});

test('the registry: a corporate registrar and a registrant naming the brand is proof; with one more link, likely; else unknown', async () => {
    let { own } = make({ rdap: { 'pp-transfers.example': { registrar: 'MarkMonitor Inc.', registrant: 'PayPal, Inc.' } } });
    assert.equal((await own.of('pp-transfers.example', 'PayPal')).how, 'registered to PayPal, Inc. through MarkMonitor Inc.');
    ({ own } = make({ rdap: { 'pp-transfers.example': { registrar: 'MarkMonitor Inc.', created: YEARS(8) } } }));
    assert.deepEqual(await own.of('pp-transfers.example', 'PayPal'), { state: 'likely', how: 'registered through MarkMonitor Inc., a corporate registrar; registered 8 years ago' });
    ({ own } = make({ rdap: { 'pp-transfers.example': { registrar: 'Cheap Names LLC', registrant: 'PayPal Fan Club', created: YEARS(8) } } }));
    assert.equal((await own.of('pp-transfers.example', 'PayPal')).state, 'unknown', 'any registrar, a registrant anyone can type');
});

test('asked once: the answer is kept (also an unknown one, for a day); personal mail and unknown brands are never asked', async () => {
    const { http, own } = make({ 'xoom.com|NS': ['ns1-pchnet.paypal.com'] });
    await own.of('service.xoom.com', 'PayPal');
    const n = http.asked.length;
    await own.of('other.xoom.com', 'PayPal');
    assert.equal(http.asked.length, n, 'the same registrable domain: not asked again');
    assert.equal((await own.of('someone@gmail.com', 'PayPal')).state, 'unknown');
    assert.equal((await own.of('xoom.com', 'Nobody Inc')).state, 'unknown');
    assert.equal(http.asked.length, n);
});

test('in the email\'s verdict: "Xoom, a PayPal Service" from a domain shown to be PayPal\'s is no sign; unproven, the sign stays', async () => {
    const raw = (from) => Buffer.from([`From: "Xoom, a PayPal Service" <${from}>`, 'To: pat@maple-schools.example', 'Subject: Your transfer is complete', 'Message-ID: <x1@xoom.example>',
        'Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass', 'Content-Type: text/plain; charset=utf-8', '', 'Your money transfer was delivered.'].join('\r\n'));
    const intelWith = (state, how = '') => ({ ownership: { of: async () => ({ state, how }) } });
    const judge = async (from, intel) => analyze(await readMessage(raw(from)), { mailbox: 'pat@maple-schools.example', orgDomains: ['maple-schools.example'], intel, readAttachments: false });
    const brandSign = (r) => r.signals.filter(s => /PayPal/.test(s.text || '')).map(s => s.weight);
    assert.deepEqual(brandSign(await judge('noreply@service.xoom.com', intelWith('owned', 'its name servers are PayPal\'s (ns1-pchnet.paypal.com)'))), [0]);
    assert.deepEqual(brandSign(await judge('noreply@service.xoom.com', intelWith('likely', 'registered through MarkMonitor Inc., a corporate registrar; registered 20 years ago'))), [E.SIGNAL_CAUTION_SCORE]);
    assert.deepEqual(brandSign(await judge('noreply@xoom-transfers.example', intelWith('unknown'))), [5]);
    assert.deepEqual(brandSign(await judge('noreply@service.xoom.com', null)), [5], 'without the lookups: as before');
});

// (0.5.65) A personal account's own address in its name ("1Jo.Doe@gmail.com 27jodoe" from that Gmail address, a
// parent writing to a teacher) claims nothing: it named Google before. A personal account calling itself Google
// still counts. Made-up names and addresses.
test('a personal account\'s own address in its name is no claim to be Google; "Google Security" from it still is', async () => {
    const raw = (name, from) => Buffer.from([`From: "${name}" <${from}>`, 'To: pat@maple-schools.example', 'Subject: Field trip tomorrow', 'Message-ID: <p1@mail.gmail.com>',
        'Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass header.from=gmail.com', 'Content-Type: text/plain; charset=utf-8', '', 'Hello, can you tell me where the field trip is tomorrow?'].join('\r\n'));
    const judge = async (name, from) => analyze(await readMessage(raw(name, from)), { mailbox: 'pat@maple-schools.example', orgDomains: ['maple-schools.example'], readAttachments: false });
    const google = (r) => r.signals.filter(s => /Google's/.test(s.text || '')).map(s => s.weight);
    assert.deepEqual(google(await judge('1Jo.Doe@gmail.com 27jodoe', '1jo.doe@gmail.com')), []);
    assert.deepEqual(google(await judge('Google Security', '1jo.doe@gmail.com')), [5]);
});

// (0.5.70) Government agencies send through GovDelivery (Granicus): "IRS Newswire" <irs@service.govdelivery.com> with
// its sender check passed is no sign; failed, it is forged (5); a company's name there, or an agency's on another
// domain, still counts.
test('an agency\'s bulletin through GovDelivery is no sign; failed, forged; a company\'s name there still counts', async () => {
    const raw = (name, from, dmarc) => Buffer.from([`From: "${name}" <${from}>`, 'To: pat@maple-schools.example', 'Subject: IRS Newswire: new guidance', 'Message-ID: <g1@service.govdelivery.com>',
        `Authentication-Results: mx.google.com; dkim=pass header.i=@service.govdelivery.com; spf=pass; dmarc=${dmarc} header.from=service.govdelivery.com`, 'Content-Type: text/plain; charset=utf-8', '', 'The IRS issued new guidance today.'].join('\r\n'));
    const judge = async (name, from, dmarc = 'pass') => analyze(await readMessage(raw(name, from, dmarc)), { mailbox: 'pat@maple-schools.example', orgDomains: ['maple-schools.example'], readAttachments: false });
    const sign = (r) => r.signals.filter(s => /The sender's name says/.test(s.text || '')).map(s => [s.weight, /GovDelivery/.test(s.text)]);
    assert.deepEqual(sign(await judge('IRS Newswire', 'irs@service.govdelivery.com')), [[0, true]]);
    assert.deepEqual(sign(await judge('IRS Newswire', 'irs@service.govdelivery.com', 'fail')), [[5, true]]);
    assert.deepEqual(sign(await judge('PayPal', 'service@service.govdelivery.com')), [[5, false]]);
    assert.deepEqual(sign(await judge('IRS Newswire', 'irs@refund-help.example')), [[5, false]]);
});

// (0.5.74) "Lakeside Ink LLC via QuickBooks" from the business's own address (QuickBooks sends invoices through it), its
// DMARC passing: no claim to be Intuit. Without the pass, with a brand before "via", or from a domain carrying the brand's
// name, the sign stays. Made-up businesses and domains.
test('"Business via QuickBooks" from its own verified address is no sign; forged, branded or look-alike, it still is', async () => {
    const raw = (name, from, dmarc) => Buffer.from([`From: "${name}" <${from}>`, 'To: pat@maple-schools.example', 'Subject: Reminder: Invoice 1042 from Lakeside Ink', 'Message-ID: <q1@mail.gmail.com>',
        `Authentication-Results: mx.google.com; dkim=pass header.i=@${from.split('@')[1]}; spf=pass; dmarc=${dmarc} header.from=${from.split('@')[1]}`, 'Content-Type: text/plain; charset=utf-8', '', 'Your invoice is attached. Thank you for your business.'].join('\r\n'));
    const judge = async (name, from, dmarc = 'pass') => analyze(await readMessage(raw(name, from, dmarc)), { mailbox: 'pat@maple-schools.example', orgDomains: ['maple-schools.example'], readAttachments: false });
    const sign = (r) => r.signals.filter(s => /The sender's name says/.test(s.text || '')).map(s => s.weight);
    const ok = await judge('Lakeside Ink LLC via QuickBooks', 'sales@lakeside-ink.example');
    assert.deepEqual(sign(ok), [0]);
    assert.notEqual(ok.status, 'flagged');
    assert.deepEqual(sign(await judge('Lakeside Ink LLC via QuickBooks', 'sales@lakeside-ink.example', 'fail')), [5]);
    assert.deepEqual(sign(await judge('Intuit via QuickBooks', 'sales@lakeside-ink.example')), [5]);
    assert.deepEqual(sign(await judge('Billing via QuickBooks', 'billing@quickbooks-billing.example')), [5]);
});
