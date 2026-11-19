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

test('0.6.45: the same DMARC report mailbox as the brand\'s, through a corporate registrar, is proof; either alone isn\'t', async () => {
    const reports = { '_dmarc.paypal.com|TXT': ['v=DMARC1; p=reject; rua=mailto:paypal-account@rua.reports-service.example'],
        '_dmarc.pp-shopping.example|TXT': ['v=DMARC1; p=reject; rua=mailto:paypal-account@rua.reports-service.example; ruf=mailto:x@ruf.reports-service.example'] };
    let { own } = make(Object.assign({ rdap: { 'pp-shopping.example': { registrar: 'MarkMonitor Inc.', created: YEARS(6) } } }, reports));
    const r = await own.of('pp-shopping.example', 'PayPal');
    assert.equal(r.state, 'owned');
    assert.match(r.how, /same mailbox as paypal\.com's \(paypal-account@rua\.reports-service\.example\), and it is registered through MarkMonitor Inc\./);
    ({ own } = make(Object.assign({ rdap: { 'pp-shopping.example': { registrar: 'Cheap Names LLC', created: YEARS(6) } } }, reports)));
    assert.equal((await own.of('pp-shopping.example', 'PayPal')).state, 'unknown', 'anyone can copy the report address into their own record');
    ({ own } = make({ rdap: { 'pp-shopping.example': { registrar: 'MarkMonitor Inc.', created: YEARS(6) } },
        '_dmarc.paypal.com|TXT': ['v=DMARC1; rua=mailto:paypal-account@rua.reports-service.example'], '_dmarc.pp-shopping.example|TXT': ['v=DMARC1; rua=mailto:other@rua.reports-service.example'] }));
    assert.equal((await own.of('pp-shopping.example', 'PayPal')).state, 'likely', 'the same report service, another account: a corporate registrar and its age only');
    ({ own } = make({ rdap: { 'pp-shopping.example': { registrar: 'MarkMonitor Inc.', created: YEARS(6) } },
        '_dmarc.paypal.com|TXT': ['v=DMARC1; rua=mailto:dmarc_rua@reports-service.example'], '_dmarc.pp-shopping.example|TXT': ['v=DMARC1; rua=mailto:dmarc_rua@reports-service.example'] }));
    assert.equal((await own.of('pp-shopping.example', 'PayPal')).state, 'likely', 'an address every customer of the report service shares: no proof');
    const { accountMailbox } = require('../src/intel/ownership');
    const pp = { name: 'PayPal', tokens: ['paypal'] };
    assert.deepEqual(['paypal-account@rua.x.example', 'k3v9q2x7@rua.x.example', 'dmarc_rua@x.example', 'dmarc_agg@x.example', 'd@x.example'].map(b => accountMailbox(b, pp)), [true, true, false, false, false]);
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
    const raw = (from, body = 'Your money transfer was delivered.') => Buffer.from([`From: "Xoom, a PayPal Service" <${from}>`, 'To: pat@maple-schools.example', 'Subject: Your transfer is complete', 'Message-ID: <x1@xoom.example>',
        'Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass', 'Content-Type: text/plain; charset=utf-8', '', body].join('\r\n'));
    const intelWith = (state, how = '') => ({ ownership: { of: async () => ({ state, how }) } });
    const judge = async (from, intel, body) => analyze(await readMessage(raw(from, body)), { mailbox: 'pat@maple-schools.example', orgDomains: ['maple-schools.example'], intel, readAttachments: false });
    const brandSign = (r) => r.signals.filter(s => /PayPal/.test(s.text || '')).map(s => s.weight);
    assert.deepEqual(brandSign(await judge('noreply@service.xoom.com', intelWith('owned', 'its name servers are PayPal\'s (ns1-pchnet.paypal.com)'))), [0]);
    const likely = intelWith('likely', 'registered through MarkMonitor Inc., a corporate registrar; registered 20 years ago');
    // (0.6.20) An established company's domain, its DMARC passing, no link anywhere else: no sign; (0.6.46) a link
    // elsewhere: half a point (the link is judged on its own).
    assert.deepEqual(brandSign(await judge('noreply@service.xoom.com', likely)), [0]);
    assert.deepEqual(brandSign(await judge('noreply@service.xoom.com', likely, 'Your money transfer was delivered. Review it: https://transfer-review.example/login')), [0.5]);
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

// (0.6.3) Gmail sometimes writes no DMARC result (mail between two accounts of one Google Workspace): it is worked out
// from the SPF and DKIM results Gmail verified, as DMARC defines it (either one passing for the From address's own
// domain). A result Gmail wrote is kept: "dmarc=fail" stays a failure. Made-up addresses.
test('no DMARC result from Gmail, for your own domains only: worked out from aligned DKIM or SPF; never another domain\'s, never over a written one', async () => {
    const raw = (from, auth) => Buffer.from([`From: "Jo Madeupson" <${from}>`, 'To: pat@maple-academy.example', 'Subject: Re:', 'Message-ID: <d1@mail.gmail.com>',
        `Authentication-Results: mx.google.com; ${auth}`, 'Content-Type: text/plain; charset=utf-8', '', 'See you Thursday.'].join('\r\n'));
    const OWN = ['maple-schools.example', 'maple-academy.example'];
    const judge = async (from, auth) => { const f = await readMessage(raw(from, auth), { ownDomains: OWN }); return { f, r: await analyze(f, { mailbox: 'pat@maple-academy.example', orgDomains: ['maple-schools.example', 'maple-academy.example'], readAttachments: false }) }; };
    let { f, r } = await judge('jo@maple-academy.example', 'dkim=pass header.i=@maple-academy.example header.s=google; arc=pass (i=1); spf=pass (google.com: domain of jo@maple-academy.example designates 209.85.220.41 as permitted sender) smtp.mailfrom=jo@maple-academy.example');
    assert.deepEqual([f.auth.dmarc, f.auth.derived, f.auth.headerFrom, r.inside], ['pass', 'DKIM', 'maple-academy.example', true]);
    ({ f, r } = await judge('jo@maple-academy.example', 'dkim=none; spf=pass smtp.mailfrom=bounce@mail.maple-academy.example'));
    assert.deepEqual([f.auth.dmarc, f.auth.derived, r.inside], ['pass', 'SPF', true], 'SPF for a subdomain of the same domain is aligned');
    ({ f, r } = await judge('jo@maple-academy.example', 'dkim=pass header.i=@bulk-mailer.example; spf=pass smtp.mailfrom=bounce@bulk-mailer.example'));
    assert.deepEqual([f.auth.dmarc, r.inside], [null, false], 'another domain\'s signature proves nothing about the From address');
    ({ f, r } = await judge('jo@maple-academy.example', 'dkim=pass header.i=@maple-academy.example; spf=pass smtp.mailfrom=jo@maple-academy.example; dmarc=fail header.from=maple-academy.example'));
    assert.deepEqual([f.auth.dmarc, f.auth.derived, r.inside], ['fail', undefined, false], 'a result Gmail wrote is kept');
    ({ f } = await judge('news@vendor.example', 'dkim=pass header.i=@vendor.example; spf=pass smtp.mailfrom=bounce@vendor.example'));
    assert.deepEqual([f.auth.dmarc, f.auth.derived], [null, undefined], 'another organization\'s domain: what Gmail wrote, as before');
});

// (0.6.3) A copy its mailbox's owner sent (SENT, or their own address never delivered: no verification, no Received
// line) is their own mail, never judged; mail delivered to them always has both. Made-up addresses.
test('a mailbox owner\'s own sent copy is never judged; a delivered copy from the same address is', async () => {
    const { ownSentCopy } = require('../src/pipeline');
    const bare = await readMessage(Buffer.from(['From: Jo Madeupson <jo@maple-academy.example>', 'To: Pat Mockwell <pat@maple-academy.example>', 'Subject: Re:', 'Message-ID: <s1@mail.gmail.com>', 'Content-Type: text/plain', '', 'ok see you then'].join('\r\n')));
    assert.equal(ownSentCopy('jo@maple-academy.example', { labelIds: [] }, bare), true, 'in the sender\'s own mailbox, never delivered');
    assert.equal(ownSentCopy('pat@maple-academy.example', { labelIds: ['INBOX'] }, bare), false, 'in someone else\'s mailbox: judged (as unverified)');
    assert.equal(ownSentCopy('pat@maple-academy.example', { labelIds: ['SENT', 'INBOX'] }, bare), true, 'Gmail\'s SENT label');
    const delivered = await readMessage(Buffer.from(['Received: from mail-sor-f41.google.com by mx.google.com', 'Authentication-Results: mx.google.com; dkim=pass header.i=@maple-academy.example; spf=pass smtp.mailfrom=jo@maple-academy.example',
        'From: Jo Madeupson <jo@maple-academy.example>', 'To: jo@maple-academy.example', 'Subject: note to self', 'Message-ID: <s2@mail.gmail.com>', 'Content-Type: text/plain', '', 'reminder'].join('\r\n')));
    assert.equal(ownSentCopy('jo@maple-academy.example', { labelIds: ['INBOX'] }, delivered), false, 'delivered through the receiving server: judged as any mail');
});

test('0.6.17: any company by the name its domain carries: the same proof as for a brand; cached; a short or odd name is not looked up', async () => {
    let { own, http } = make({ rdap: { 'email-lakeviewhotels.example': { registrar: 'CSC Corporate Domains, Inc.', registrant: 'Lakeviewhotels International, Inc.' } } });
    assert.deepEqual(await own.ofCompany('click.email-lakeviewhotels.example', 'lakeviewhotels', ['lakeviewhotels.example']),
        { state: 'owned', how: 'registered to Lakeviewhotels International, Inc. through CSC Corporate Domains, Inc.' });
    const n = http.asked.length;
    await own.ofCompany('email-lakeviewhotels.example', 'lakeviewhotels', ['lakeviewhotels.example']);
    assert.equal(http.asked.length, n, 'kept');
    ({ own } = make({ rdap: { 'email-lakeviewhotels.example': { registrar: 'Cheap Names LLC', registrant: 'Lakeviewhotels International, Inc.' } } }));
    assert.notEqual((await own.ofCompany('email-lakeviewhotels.example', 'lakeviewhotels', [])).state, 'owned', 'a registrant anyone can type, at any registrar');
    ({ own, http } = make({}));
    assert.deepEqual(await own.ofCompany('email-abc.example', 'abc', []), { state: 'unknown', how: '' });
    assert.equal(http.asked.length, 0, 'a name under 4 letters isn\'t looked up');
});

// 0.6.46: the company's own name servers under a third domain named after it; the answers kept 60 days (refreshed after
// 50), no proof 7 days, a failed lookup 6 hours (never a lower score: it counts as no proof).
test('0.6.46: name servers under a third domain named after the company, shared by both, are proof; a provider\'s aren\'t', async () => {
    let { own } = make({ 'pp-payments.example|NS': ['ns1.paypalcorp-dns.example', 'ns0098.secondary.dnshost.example'], 'paypal.com|NS': ['ns1.paypalcorp-dns.example', 'ns0119.secondary.dnshost.example'] });
    assert.deepEqual(await own.of('pp-payments.example', 'PayPal'), { state: 'owned', how: 'it and paypal.com are both served by paypalcorp-dns.example\'s own name servers (ns1.paypalcorp-dns.example)' });
    ({ own } = make({ 'pp-payments.example|NS': ['ns1.bighost-dns.example'], 'paypal.com|NS': ['ns1.bighost-dns.example', 'ns2.other.example'] }));
    assert.equal((await own.of('pp-payments.example', 'PayPal')).state, 'unknown', 'a host not named after the company: anyone\'s');
});

test('0.6.46: how long answers are kept; an old proof is refreshed in the background; a failure is kept 6 hours', async () => {
    const DAY = 86400000, store = new MemoryStore();
    let t = Date.now(), calls = 0;
    const http = { request: async (url) => { calls++; if (/failing-lookup/.test(url)) throw new Error('timeout'); return { ok: true, status: 200, json: async () => ({ Status: 0, Answer: [] }) }; } };
    const own = createOwnership({ http, store, engine: E, rdapServer: async () => null, now: () => t });
    const ttl = (key) => store.cached.get(`own|${key}`).exp - Date.now();
    assert.deepEqual(await own.of('failing-lookup.example', 'PayPal'), { state: 'unknown', how: '', failed: true });
    assert.ok(Math.abs(ttl('failing-lookup.example|PayPal') - 6 * 3600000) < 60000, 'a failure: 6 hours');
    assert.equal((await own.of('no-proof.example', 'PayPal')).state, 'unknown');
    assert.ok(Math.abs(ttl('no-proof.example|PayPal') - 7 * DAY) < 60000, 'no proof: 7 days');
    // An old proof in the shared store: returned at once, and asked again in the background.
    await store.setCached('own', 'old-proof.example|PayPal', { at: t - 51 * DAY, state: 'owned', how: 'made up' }, 60 * DAY);
    const before = calls;
    const other = createOwnership({ http, store, engine: E, rdapServer: async () => null, now: () => t });
    assert.deepEqual(await other.of('old-proof.example', 'PayPal'), { state: 'owned', how: 'made up' });
    await new Promise(r => setTimeout(r, 50));
    assert.ok(calls > before, 'refreshed in the background');
    assert.equal((await store.getCached('own', 'old-proof.example|PayPal')).state, 'owned', 'a refresh that finds nothing doesn\'t replace a proof');
});
