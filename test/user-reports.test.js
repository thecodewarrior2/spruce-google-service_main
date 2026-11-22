'use strict';
// 0.6.60: Settings → User reports. Gmail's own "Report phishing" raises a "User reported phishing" alert in Google's Alert
// Center; turned on, the hourly run reads the new alerts and puts each reported email of a watched mailbox in Review →
// Reported. Every address, sender and email here is made up.
const test = require('node:test');
const assert = require('node:assert');
const { loadConfig } = require('../src/config');
const { Service } = require('../src/pipeline');
const { MemoryStore } = require('../src/store/memory');
const { readMessage } = require('../src/engine/mime');

const ORG = 'maple-schools.example';
const [PAT, SAM, LEE] = ['pat.fakewell', 'sam.testwood', 'lee.notreal'].map(u => `${u}@${ORG}`);
const ADMIN = `it.madeup@${ORG}`;
const raw = (to, mid) => Buffer.from([
    'From: "Payroll Desk" <payroll@paystub-madeup.example>', `To: ${to}`, 'Subject: Your pay statement is ready', `Message-ID: <${mid}>`,
    'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=paystub-madeup.example; dmarc=pass header.from=paystub-madeup.example',
    'Content-Type: text/plain', '', 'Your November pay statement is ready. Sign in to view it.'].join('\r\n'));

function make({ alerts = [], fail = null } = {}) {
    const mails = new Map();   // `${user}|${rfcId}` → { id, labelIds }
    const calls = { alerts: [], search: [] };
    const gmail = {
        labelId: async (u, n) => `L_${n}`, labels: async () => ['INBOX'], modify: async () => ({}),
        alerts: async (admin, opts) => { calls.alerts.push({ admin, opts }); if (fail) throw new Error(fail); return alerts; },
        search: async (user, q, opts) => { calls.search.push({ user, q, opts }); const m = mails.get(`${user}|${q.replace(/^rfc822msgid:/, '')}`); return { ids: m ? [m.id] : [], next: null }; },
        raw: async (user, id) => { const m = [...mails.values()].find(x => x.id === id && x.user === user); return { id, threadId: `t-${id}`, labelIds: m.labelIds, internalDate: Date.now(), raw: raw(user, m.rfc) }; }
    };
    const svc = new Service({ cfg: loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: [PAT, SAM].join(','), MODE: 'enforce' }), store: new MemoryStore(), gmail, log: { error() {}, warn() {} } });
    svc.mails = mails; svc.calls = calls;
    return svc;
}
const alert = (id, at, messages) => ({ alertId: id, createTime: new Date(at).toISOString(), type: 'User reported phishing', source: 'Gmail phishing', data: { messages } });

test('off by default; turned on only with an admin of the organization; the change is noted', async () => {
    const svc = make();
    assert.equal((await svc.userReports()).on, false);
    assert.equal(await svc.followUserReports(), null, 'nothing read while off');
    assert.equal(svc.calls.alerts.length, 0);
    assert.equal((await svc.setUserReports(true, 'someone@elsewhere.example', ADMIN)).status, 400);
    const on = await svc.setUserReports(true, ADMIN, ADMIN);
    assert.equal(on.userReports.on, true);
    assert.ok(svc.store.events.some(e => /turned on User reports/.test(e.text)));
});

test('a reported email goes to Review → Reported: an existing record is marked, one the checks let through is read and recorded; others are skipped', async () => {
    const now = Date.now();
    const svc = make({ alerts: [alert('a1', now - 3600e3, [{ recipient: PAT, messageId: 'r1@paystub-madeup.example' }, { recipient: SAM, messageId: '<r2@paystub-madeup.example>' },
        { recipient: LEE, messageId: 'r3@paystub-madeup.example' }, { recipient: 'x@elsewhere.example', messageId: 'r4@x.example' }, { recipient: PAT, messageId: 'gone@x.example' }])] });
    for (const u of [PAT, SAM]) await svc.store.putUser(u, { watched: true });
    svc.mails.set(`${PAT}|r1@paystub-madeup.example`, { id: 'g1', user: PAT, rfc: 'r1@paystub-madeup.example', labelIds: ['SPAM'] });
    svc.mails.set(`${SAM}|r2@paystub-madeup.example`, { id: 'g2', user: SAM, rfc: 'r2@paystub-madeup.example', labelIds: ['SPAM'] });
    // PAT's copy was recorded on arrival (suspicious); SAM's was let through.
    await svc.store.saveRecord({ key: `${PAT}|g1`, user: PAT, messageId: 'g1', processedAt: now - 7200e3, receivedAt: now - 7200e3, action: 'flag', state: 'inbox', falseAlarm: null, sender: { address: 'payroll@paystub-madeup.example', domain: 'paystub-madeup.example' }, signals: [] });
    await svc.setUserReports(true, ADMIN, ADMIN);
    const out = await svc.followUserReports();
    assert.deepEqual(out.found, { added: 1, marked: 1, notWatched: 2, notFound: 1, already: 0 });
    assert.ok(svc.calls.search.every(c => c.opts.includeSpamTrash), 'Spam is searched too (a reported email is there)');
    assert.match(svc.calls.alerts[0].opts.filter, /^type="User reported phishing" AND createTime >= "\d{4}-/);
    assert.equal(svc.calls.alerts[0].admin, ADMIN);
    const marked = await svc.store.getRecord(`${PAT}|g1`);
    assert.equal(marked.userReported.alertId, 'a1');
    const added = await svc.store.getRecord(`${SAM}|g2`);
    assert.deepEqual([added.action, added.state, added.userReported.alertId], ['flag', 'reported', 'a1']);
    assert.match(added.why, /its reader reported it as phishing in Gmail \(Report phishing\)/);
    assert.ok(svc.store.events.some(e => e.kind === 'user-report' && /2 emails reported as phishing by their readers in Gmail are waiting in Review → Reported/.test(e.text)));
    // Read again: the alert isn't read twice; the cursor moved.
    const again = await svc.followUserReports();
    assert.deepEqual([again.alerts, again.emails], [0, 0]);
    assert.ok((await svc.userReports()).cursor >= now - 3600e3);
    // An admin's answer: recorded as usual, nothing moved (Gmail already moved it).
    const m = await svc.mark(`${SAM}|g2`, false, ADMIN, { move: true });
    assert.equal(m.moved, 'not-in-inbox');
});

test('Google refusing: said plainly with the fix (the scope, the API, the admin), recorded, and an alert once a day', async () => {
    const svc = make({ fail: 'token for it.madeup@maple-schools.example: unauthorized_client' });
    await svc.setUserReports(true, ADMIN, ADMIN);
    const t = await svc.testUserReports(ADMIN, ADMIN);
    assert.equal(t.ok, false);
    assert.match(t.why, /scope apps\.alerts isn't on its domain-wide delegation entry/);
    assert.match(t.fix, /https:\/\/www\.googleapis\.com\/auth\/apps\.alerts/);
    const out = await svc.followUserReports();
    assert.match(out.error, /apps\.alerts/);
    assert.equal((await svc.store.getState('userReportsHealth')).ok, false);
    const off = make({ fail: 'HTTP 403: Alert Center API has not been used in project 123 before or it is disabled. SERVICE_DISABLED' });
    assert.match((await off.testUserReports(ADMIN, ADMIN)).why, /Alert Center API isn't turned on/);
});

test('the dashboard: Review → Reported lists the reports nobody answered, even from a Trusted sender; the count reaches the tab title', async () => {
    const http = require('http');
    const { createApp } = require('../src/server');
    const cfg = loadConfig({ DEMO: '1', MODE: 'monitor', ORG_DOMAINS: ORG, ALLOW_DOMAINS: 'paystub-madeup.example' });
    const store = new MemoryStore();
    const svc = new Service({ cfg, store, gmail: { labelId: async () => 'L', modify: async () => ({}) }, log: { error() {}, warn() {} } });
    const now = Date.now();
    const base = { user: PAT, processedAt: now - 3600e3, receivedAt: now - 3600e3, state: 'inbox', falseAlarm: null, sender: { address: 'payroll@paystub-madeup.example', domain: 'paystub-madeup.example' }, auth: { dmarc: 'pass', headerFrom: 'paystub-madeup.example' }, signals: [] };
    await store.saveRecord(Object.assign({ key: `${PAT}|a`, messageId: 'a', action: 'flag', userReported: { at: now } }, base));
    await store.saveRecord(Object.assign({ key: `${PAT}|c`, messageId: 'c', action: 'flag' }, base));   // the same Trusted sender, not reported: not listed
    await store.saveRecord(Object.assign({ key: `${PAT}|b`, messageId: 'b', action: 'flag', userReported: { at: now }, markedBy: ADMIN, falseAlarm: false }, base));
    const srv = http.createServer(createApp({ cfg, store, service: svc }));
    await new Promise(r => srv.listen(0, r));
    const get = async (pth) => (await fetch(`http://127.0.0.1:${srv.address().port}${pth}`)).json();
    try {
        const rv = await get('/api/review?queue=reported&days=7');
        assert.equal(rv.queue, 'reported');
        assert.deepEqual(rv.keys, [`${PAT}|a`]);
        assert.equal(rv.counts.reported, 1);
        assert.equal(rv.counts.suspicious, 0, 'listed only under Reported');
        assert.equal(rv.reportedOn, false, '(0.6.61) off: the dashboard hides the tab unless reports still wait');
        const p = await get('/api/pending?days=7');
        assert.equal(p.reported, 1);
        assert.equal(p.reportedOn, false);
        await svc.setUserReports(true, ADMIN, ADMIN);
        assert.equal((await get('/api/review?queue=moved&days=7')).reportedOn, true, 'turned on: the tab is shown');
        assert.ok(p.total >= 1);
    } finally { await new Promise(r => srv.close(r)); }
});
