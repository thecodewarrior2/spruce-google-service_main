'use strict';
// 0.6.30: every domain on an allow list is looked up again every 30 days; a change flags it for review, and one that
// means it may have lapsed or changed hands suspends it until an admin answers. The admins are emailed. Every domain,
// address and registrar here is made up.
const test = require('node:test');
const assert = require('node:assert');
const { loadConfig } = require('../src/config');
const { Service } = require('../src/pipeline');
const { MemoryStore } = require('../src/store/memory');
const { readMessage } = require('../src/engine/mime');
const { compareSnapshots } = require('../src/allowwatch');

const ORG = 'maple-schools.example', PAT = `pat.fakewell@${ORG}`, ADMIN = `it.madeup@${ORG}`;
const DAY = 24 * 60 * 60 * 1000;
const VENDOR = 'lakeview-supply.example';

function setup() {
    let t = Date.UTC(2026, 10, 1);
    const reg = new Map([[VENDOR, { exists: true, created: Date.UTC(2009, 3, 2), expires: Date.UTC(2030, 3, 2), registrar: 'Madeup Registrar, Inc.', ns: ['ns1.madeup-dns.example', 'ns2.madeup-dns.example'] }]]);
    const sent = [];
    const intel = { rdap: { ageDays: async () => 3000, record: async (d) => reg.get(d) || { exists: false, created: null, expires: null, registrar: '', ns: [] } } };
    const gmail = { labelId: async (u, n) => `L_${n}`, modify: async () => ({}), insert: async (user, raw) => { sent.push({ user, raw: String(raw) }); return { id: `ins${sent.length}` }; }, groupMembers: async () => [] };
    const cfg = loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: PAT, MODE: 'enforce', ADMIN_EMAILS: ADMIN, ALLOW_DOMAINS: VENDOR });
    const svc = new Service({ cfg, store: new MemoryStore(), gmail, intel, now: () => t, log: { error() {}, warn() {} } });
    return { svc, reg, sent, later: (days) => { t += days * DAY; } };
}
let n = 0;
// A brand's name from the vendor's domain (5): moved, unless the domain is allowlisted.
const invoice = (subject = 'Your invoice is ready') => readMessage(Buffer.from([`From: "PayPal Billing" <billing@${VENDOR}>`, `To: ${PAT}`, `Subject: ${subject}`, `Message-ID: <i${++n}@${VENDOR}>`,
    `Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass header.from=${VENDOR}`, 'Content-Type: text/plain', '',
    'Your invoice is attached. Verify your account password today or your account will be suspended. Pay now with a gift card.'].join('\r\n')));
const judge = async (svc, subject) => svc.judge(PAT, { id: `m${n}`, threadId: `t${n}`, internalDate: svc.now() }, await invoice(subject));

test('the first look takes a snapshot; nothing changed 30 days later: nothing to review', async () => {
    const { svc, later } = setup();
    assert.equal((await svc.checkAllowlists()).checked, 1);
    assert.deepEqual((await svc.allowReviewList()).review, []);
    later(10);
    assert.equal((await svc.checkAllowlists()).checked, 0, 'not due before 30 days');
    later(21);
    const r = await svc.checkAllowlists();
    assert.deepEqual([r.checked, r.flagged], [1, []]);
    assert.equal((await svc.allowedNow(`billing@${VENDOR}`)).allowed, true);
});

test('registered again: suspended, the admins emailed, its mail judged like anyone\'s and tagged; "Still trusted" with release', async () => {
    const { svc, reg, sent, later } = setup();
    await svc.checkAllowlists();
    const before = await judge(svc, 'Invoice 1');
    assert.deepEqual([before.action, before.status], ['none', 'trusted'], 'allowlisted: never moved');
    later(31);
    reg.set(VENDOR, Object.assign({}, reg.get(VENDOR), { created: Date.UTC(2026, 10, 20), registrar: 'Another Madeup Registrar LLC', ns: ['ns1.parked-madeup.example'] }));
    const r = await svc.checkAllowlists();
    assert.deepEqual([r.flagged, r.suspended], [[VENDOR], [VENDOR]]);
    const list = (await svc.allowReviewList()).review;
    assert.equal(list.length, 1);
    assert.equal(list[0].suspended, true);
    assert.deepEqual(list[0].changes.map(c => c.kind), ['registered-again', 'registrar', 'nameservers']);
    assert.equal(sent.length, 1, 'one email to the admin');
    assert.equal(sent[0].user, ADMIN);
    assert.match(sent[0].raw, /lakeview-supply\.example on your allow list needs review \(suspended\)/);
    assert.ok((await svc.store.listEvents(0, { limit: 20 })).some(e => e.kind === 'allowlist-review'));
    assert.deepEqual(await svc.allowedNow(`billing@${VENDOR}`), { allowed: false, suspended: VENDOR });
    const held = await judge(svc, 'Invoice 2');
    assert.equal(held.action, 'move', 'suspended: judged like anyone\'s');
    const rec = await svc.store.getRecord(held.key);
    assert.equal(rec.allowSuspended, VENDOR);
    assert.equal((await svc.allowReviewList()).review[0].emails, 1);
    const out = await svc.resolveAllowReview(VENDOR, ADMIN, { release: true });
    assert.equal(out.answered, 1);
    assert.equal((await svc.store.getRecord(held.key)).falseAlarm, true);
    assert.deepEqual(out.review, []);
    assert.equal((await svc.allowedNow(`billing@${VENDOR}`)).allowed, true, 'trusted again');
    later(31);
    assert.deepEqual((await svc.checkAllowlists()).flagged, [], 'the new snapshot is the one compared with');
});

test('only new name servers: flagged, still trusted', async () => {
    const { svc, reg, later } = setup();
    await svc.checkAllowlists();
    later(31);
    reg.set(VENDOR, Object.assign({}, reg.get(VENDOR), { ns: ['a.new-dns-host.example', 'b.new-dns-host.example'] }));
    const r = await svc.checkAllowlists();
    assert.deepEqual([r.flagged, r.suspended], [[VENDOR], []]);
    assert.equal((await svc.allowedNow(`billing@${VENDOR}`)).allowed, true);
});

test('what counts as a change', () => {
    const was = { exists: true, created: 1000, expires: Date.UTC(2030, 0, 1), registrar: 'A', ns: ['ns1.x.example'], blocked: '', listed: '', spamhaus: '' };
    const at = Date.UTC(2026, 10, 1);
    assert.deepEqual(compareSnapshots(was, Object.assign({}, was), at), []);
    assert.deepEqual(compareSnapshots(was, Object.assign({}, was, { registrar: '', ns: [], created: null }), at), [], 'unknown is no change');
    assert.deepEqual(compareSnapshots(was, { exists: false }, at).map(c => [c.kind, c.suspend]), [['gone', true]]);
    assert.deepEqual(compareSnapshots(was, Object.assign({}, was, { expires: Date.UTC(2026, 9, 1) }), at).map(c => c.kind), ['expired']);
    assert.deepEqual(compareSnapshots(was, Object.assign({}, was, { ns: ['ns1.x.example', 'ns3.x.example'] }), at), [], 'one name server added: routine');
    assert.deepEqual(compareSnapshots(was, Object.assign({}, was, { listed: 'Madeup List' }), at).map(c => [c.kind, c.suspend]), [['listed', true]]);
});
