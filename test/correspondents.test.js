'use strict';
// 0.6.87: a look-alike of a company that mails you (src/correspondents.js). Sender standing keeps the companies with clean
// mail here under one-way hashes; a sender, Reply-To or link domain one small change away from one of them is a sign.
// Every company, person and domain is made up.
const test = require('node:test');
const assert = require('node:assert');
const C = require('../src/correspondents');
const ST = require('../src/standing');
const { loadConfig } = require('../src/config');
const { Service } = require('../src/pipeline');
const { MemoryStore } = require('../src/store/memory');
const { readMessage } = require('../src/engine/mime');
const E = require('../src/engine/spruce').load();

const ORG = 'maple-schools.example', PAT = `pat.fakewell@${ORG}`;
const VENDOR = 'tallpinefurniture.example';
const keys = new Set([VENDOR, 'fernwoodsupply.com'].map(ST.keyOf));

test('the near-misses: a hyphen, a letter changed, dropped, added or swapped, "rn" for "m", a word added, another ending', () => {
    const hit = (d) => C.imitates(d, keys);
    for (const d of ['tallpine-furniture.example', 'tallpinefurnlture.example', 'talpinefurniture.example', 'tallpinefurnituree.example', 'tallpinefurnitrue.example',
        'tallpinefurniture-billing.example', 'invoice-tallpinefurniture.example', 'fernwoodsupply.co', 'fernwoodsupp1y.com']) assert.ok(hit(d), d);
    assert.equal(hit(VENDOR), null, 'the company itself');
    assert.equal(hit('madeupbank.example'), null, 'nothing like it');
    assert.equal(hit('tallpine.example'), null, 'a different, shorter name');
    assert.match(hit('tallpinefurnlture.example').how, /"l" for "i"/);
    assert.equal(C.imitates('rnadeupco.example', new Set([ST.keyOf('madeupco.example')])).how, '"rn" written for "m"');
    // Short names one letter apart are often two real companies: left alone (another ending still counts).
    assert.equal(C.imitates('abcde.example', new Set([ST.keyOf('abcdf.example')])), null);
    assert.ok(C.imitates('acmeco.net', new Set([ST.keyOf('acmeco.com')])));
    assert.equal(C.imitates('tallpine-furniture.example', new Set()), null, 'no companies known yet');
});

test('the signs: the sender by its age and Gmail\'s check, a Reply-To, a link; never free mail or your own domain', async () => {
    const facts = (from, dmarc = 'pass', extra = []) => readMessage(Buffer.from([`From: Accounts <accounts@${from}>`, `To: ${PAT}`, 'Subject: Updated remittance details', 'Message-ID: <r1@x.example>', ...extra,
        `Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=${from}; dkim=pass header.i=@${from}; dmarc=${dmarc} header.from=${from}`, 'Content-Type: text/plain', '', 'Please update our bank details on file.'].join('\r\n')));
    const signs = async (from, o = {}, dmarc, extra) => C.lookalikeSigns(E, await facts(from, dmarc, extra), o.links || [], Object.assign({ keys, orgDomains: [ORG], verified: dmarc !== 'fail' }, o));
    const s = (await signs('tallpine-furniture.example', { senderAge: 12 }))[0];
    assert.equal(s.kind, 'correspondent-lookalike'); assert.equal(s.weight, 5, 'registered 12 days ago');
    assert.match(s.text, /looks like tallpinefurniture\.example, a company that mails your organization \(an extra "-"\), and tallpine-furniture\.example was registered 12 days ago/);
    assert.equal((await signs('tallpine-furniture.example', {}, 'fail'))[0].weight, 5, 'Gmail couldn\'t confirm it');
    assert.equal((await signs('tallpine-furniture.example', { senderAge: null }))[0].weight, 3, 'confirmed, age unknown');
    const old = (await signs('tallpine-furniture.example', { senderAge: 3000 }))[0];
    assert.equal(old.weight, 1, 'confirmed and 8 years old: likely the same company\'s other domain');
    assert.match(old.text, /may be the same company's other domain/);
    assert.deepEqual(await signs(VENDOR), [], 'the vendor itself');
    const rt = await signs('madeup-elsewhere.example', {}, 'pass', ['Reply-To: ap@tallpinefurnlture.example']);
    assert.deepEqual(rt.map(x => [x.kind, x.weight]), [['correspondent-lookalike-reply-to', 3]]);
    const ln = await signs('madeup-elsewhere.example', { links: [{ url: 'https://pay.fernwoodsupp1y.com/invoice' }] });
    assert.deepEqual(ln.map(x => [x.kind, x.weight]), [['correspondent-lookalike-link', 2]]);
    // Free mail and your own domain are never a company's look-alike here.
    assert.deepEqual(C.lookalikeSigns(E, { senderAddress: '@gmail.com' }, [], { keys: new Set([ST.keyOf('gmail.co')]), orgDomains: [ORG] }), []);
    assert.deepEqual(C.lookalikeSigns(E, { senderAddress: `x@${ORG}` }, [], { keys: new Set([ST.keyOf('maple-school.example')]), orgDomains: [ORG] }), []);
    // Answers cached per domain.
    const cache = new Map();
    await signs('tallpine-furniture.example', { cache });
    assert.ok(cache.has('tallpine-furniture.example'));
});

test('the service: the companies with standing (3 clean emails, or Mark safe; not after a Phishing answer), and an email from a look-alike flagged', async () => {
    let now = Date.UTC(2026, 11, 1, 15);
    const store = new MemoryStore();
    const cfg = loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: PAT, MODE: 'monitor' });
    const svc = new Service({ cfg, store, gmail: { modify: async () => ({}), labelId: async (u, l) => `L_${l}` }, log: { error() {}, warn() {} }, now: () => now });
    await store.updateStanding(ST.keyOf(VENDOR), () => ({ first: now - 90 * ST.DAY, last: now, days: 12, count: 14, prof: {} }));
    await store.updateStanding(ST.keyOf('fewmails.example'), () => ({ first: now, last: now, days: 1, count: 2, prof: {} }));
    await store.updateStanding(ST.keyOf('markedsafe.example'), () => ({ first: now, last: now, days: 1, count: 1, prof: {}, safe: { at: now, by: 'it' } }));
    await store.updateStanding(ST.keyOf('answeredphish.example'), () => ({ first: now, last: now, days: 9, count: 30, prof: {}, phishAt: now }));
    const set = await svc.correspondentKeys();
    assert.ok(set.has(ST.keyOf(VENDOR)) && set.has(ST.keyOf('markedsafe.example')));
    assert.ok(!set.has(ST.keyOf('fewmails.example')), 'two emails: not yet');
    assert.ok(!set.has(ST.keyOf('answeredphish.example')), 'answered Phishing');
    const mail = (from) => Buffer.from([`From: Accounts Receivable <ar@${from}>`, `To: ${PAT}`, 'Subject: Updated remittance details', `Message-ID: <m${from}@x.example>`,
        `Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=${from}; dkim=pass header.i=@${from}; dmarc=pass header.from=${from}`, 'Content-Type: text/plain', '',
        'Hello, please note our remittance details for open invoices. Thank you.'].join('\r\n'));
    const r = await svc.judge(PAT, { id: 'm1', threadId: 't1', labelIds: ['INBOX'], internalDate: now }, await readMessage(mail('tallpine-furniture.example')));
    const rec = await store.getRecord(r.key);
    assert.ok(rec, 'recorded');
    const sign = rec.signals.find(x => x.kind === 'correspondent-lookalike');
    assert.ok(sign && sign.weight >= 3, JSON.stringify(rec.signals));
    assert.notEqual(rec.action, 'none');
    const real = await svc.judge(PAT, { id: 'm2', threadId: 't2', labelIds: ['INBOX'], internalDate: now }, await readMessage(mail(VENDOR)));
    const realRec = real.key ? await store.getRecord(real.key) : null;
    assert.ok(!realRec || !realRec.signals.some(x => /correspondent-lookalike/.test(x.kind)), 'the vendor itself: no sign');
});
