'use strict';
// 0.5.35: delivered mail is checked again. Each email left in the Inbox keeps short hashes of its link sites
// and sender with its "checked" marker; when a phishing list's daily download adds one, the emails that have
// it are checked again in full and moved (enforce mode) or recorded (monitor mode), with who got them,
// whether they were opened and (Settings → Link clicks) what Gmail's logs say. Every address, site and email
// here is made up.
const test = require('node:test');
const assert = require('node:assert');
const spruce = require('../src/engine/spruce');
const R = require('../src/recheck');
const { createHttp } = require('../src/intel/http');
const { createFeeds } = require('../src/intel/feeds');
const { MemoryStore } = require('../src/store/memory');
const { Service } = require('../src/pipeline');
const { loadConfig } = require('../src/config');

const E = spruce.load();
const ORG = 'maple-schools.example';
const HOUR = 3600 * 1000, DAY = 24 * HOUR;
const silent = { error() {}, warn() {} };
const text = (body, status = 200) => ({ ok: status < 400, status, text: async () => body, json: async () => JSON.parse(body), headers: { get: () => null } });
const filler = (f) => Array.from({ length: 30 }, (_, i) => f(i));

test('the hashes: link sites and the domains above them, a shared-hosting page by its exact address, the sender; never the organization\'s or a protected brand\'s sites', () => {
    const ix = R.indexOf(E, { urls: ['https://login.fresh-phish.example/verify?u=1', 'https://www.maple-schools.example/calendar', 'https://accounts.google.com/x', 'https://pub-123.r2.dev/page.html'],
        sender: 'Billing <billing@vendor-mail.example>'.replace(/.*</, '').replace('>', ''), orgDomains: [ORG] });
    const has = (k, v) => ix.includes(`${k}${R.hashOf(v)}`);
    assert.ok(has('d', 'login.fresh-phish.example') && has('d', 'fresh-phish.example'));
    assert.ok(!has('d', 'example'), 'never a bare ending');
    assert.ok(!has('d', 'www.maple-schools.example') && !has('d', 'maple-schools.example'), 'not our own sites');
    assert.ok(!has('d', 'accounts.google.com') && !has('d', 'google.com'), 'not a protected brand\'s');
    assert.ok(!has('d', 'pub-123.r2.dev') && !has('d', 'r2.dev'), 'shared hosting: not the whole site');
    assert.ok(has('u', E.normalizeFeedUrl('https://pub-123.r2.dev/page.html')), 'the exact page');
    assert.ok(has('s', 'billing@vendor-mail.example'));
    assert.ok(ix.every(x => /^[dus][0-9a-f]{16}$/.test(x)), 'only hashes');
    // A list's entries are looked for by the same hashes.
    assert.deepEqual(R.entryHashes(E, 'domain', 'fresh-phish.example'), [`d${R.hashOf('fresh-phish.example')}`]);
    assert.deepEqual(R.entryHashes(E, 'url', 'https://login.fresh-phish.example/a/b'), [`d${R.hashOf('login.fresh-phish.example')}`]);
    assert.deepEqual(R.entryHashes(E, 'url', 'https://pub-123.r2.dev/page.html'), [`u${R.hashOf(E.normalizeFeedUrl('https://pub-123.r2.dev/page.html'))}`]);
    const many = R.indexOf(E, { urls: filler(i => `https://a${i}.site${i}.example/`), sender: 'x@y.example' });
    assert.equal(many.length, R.INDEX_MAX);
});

test('Gmail\'s log events: found by the email\'s Message-ID wherever it sits; the event type read', () => {
    const ev = { id: { time: '2026-11-12T15:04:00.000Z' }, events: [{ name: 'delivery', parameters: [
        { name: 'event_info', messageValue: { parameter: [{ name: 'mail_event_type', intValue: '15' }] } },
        { name: 'message', messageValue: { parameter: [{ name: 'rfc2822_message_id', value: '<q1@vendor-mail.example>' }, { name: 'subject', value: 'Invoice' }] } }] }] };
    assert.equal(R.eventNames(ev, 'q1@vendor-mail.example'), true);
    assert.equal(R.eventNames(ev, '<q1@vendor-mail.example>'), true);
    assert.equal(R.eventNames(ev, 'q2@vendor-mail.example'), false);
    assert.equal(R.eventType(ev.events[0]), 15);
    assert.equal(R.eventHasMessageId(ev), true);
    assert.equal(R.eventHasMessageId({ events: [{ parameters: [{ name: 'event_info', messageValue: { parameter: [{ name: 'mail_event_type', intValue: '7' }] } }] }] }), false);
});

// A district with one list (Phishing Army) that adds fresh-phish.example on its second download.
function setup({ mode = 'enforce', recheck = true, env = {} } = {}) {
    let now = Date.UTC(2026, 10, 10, 9);
    const listed = new Set(filler(i => `bad${i}.example`));
    const fetch = async (url) => {
        const u = new URL(url);
        if (u.host === 'phishing.army') return text([...listed].join('\n'));
        if (u.pathname.startsWith('/openphish/')) return text(filler(i => `https://p${i}.example/x`).join('\n'));
        if (u.pathname.startsWith('/0xDanielLopez/')) return text(filler(i => `2026-11-01 00:00:00,r,domain,rep${i}.example,#phishing,https://x.com/r/${i}`).join('\n'));
        if (u.pathname.startsWith('/hagezi/')) return text(filler(i => `hz${i}.example`).join('\n'));
        return text(filler(i => `s${i}@scam.example`).join('\n'));
    };
    const store = new MemoryStore();
    const feeds = createFeeds({ http: createHttp({ fetch }), store, engine: E, now: () => now, log: silent });
    const cfg = loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: `a@${ORG}`, FIRST_SEEN_LEARNING_DAYS: '0', MODE: mode, RECHECK: recheck ? 'true' : 'false', ALERT_EMAIL: `it@${ORG}`, ...env });
    const boxes = new Map();   // `${user}|${id}` → { raw, labels }
    const gmail = {
        modified: [], events: [],
        raw: async (user, id) => { const m = boxes.get(`${user}|${id}`); if (!m) throw Object.assign(new (require('../src/gmail/client').GoogleApiError)(404, 'gone', 'GET'), {}); return { id, threadId: `t-${id}`, labelIds: [...m.labels], historyId: '100', internalDate: m.at, raw: m.raw }; },
        labels: async (user, id) => [...boxes.get(`${user}|${id}`).labels],
        threadSize: async () => 1,
        labelId: async (u, name) => `L_${name}`,
        modify: async (user, id, add, remove) => { gmail.modified.push({ user, id, add, remove }); const m = boxes.get(`${user}|${id}`); for (const l of add) m.labels.add(l); for (const l of remove) m.labels.delete(l); return {}; },
        gmailEvents: async (admin, mailbox, q) => { gmail.events.push({ admin, mailbox, filters: q.filters }); return (gmail.logs[mailbox] || []).filter(e => !q.filters || q.filters === `event_info.mail_event_type==${e.type}`).map(e => e.ev); },
        logs: {}
    };
    const svc = new Service({ cfg, store, gmail, intel: { feeds }, now: () => now, log: silent });
    const deliver = async (user, id, raw, { opened = false } = {}) => {
        boxes.set(`${user}|${id}`, { raw, labels: new Set(['INBOX', ...(opened ? [] : ['UNREAD'])]), at: now });
        return svc.processMessage(user, id);
    };
    return { svc, store, feeds, gmail, boxes, listed, deliver, cfg, clock: { get: () => now, add: (ms) => { now += ms; } } };
}
// An email nobody knows is bad on arrival (0.5.50: an ordinary newsletter; the earlier payroll "statement" with a
// sign-in link reads as phishing to phish-tiny 0.18.0 on arrival, so there was nothing left for the re-check to find),
// its link on the site a list adds a day later.
const lure = (to, n = 1) => Buffer.from([`From: Payroll Center <notices@payroll-center.example>`, `To: ${to}`, 'Subject: November newsletter', `Message-ID: <st${n}@payroll-center.example>`,
    'Authentication-Results: mx.google.com; dkim=pass header.i=@payroll-center.example; spf=pass; dmarc=pass header.from=payroll-center.example',
    'Content-Type: text/html; charset=utf-8', '', '<p>Hello, here is our November newsletter: this month\'s office hours and the holiday schedule.</p><p><a href="https://www.fresh-phish.example/news">Read the newsletter</a></p><p>Payroll Center</p>'].join('\r\n'));

test('a list adds a site after the email was delivered: every copy still in an Inbox is found, checked again and moved; the admins are alerted; opened is said', async () => {
    const t = setup();
    await t.feeds.sync();                                     // the lists' first download (nothing is "new")
    await t.store.setState('feedsAttemptedAt', t.clock.get());
    await t.store.setState('installedAt', t.clock.get() - 30 * DAY);
    const users = [`ana@${ORG}`, `ben@${ORG}`, `cy@${ORG}`];
    for (const [i, u] of users.entries()) await t.deliver(u, `m${i}`, lure(u, i), { opened: i === 0 });
    assert.equal(t.gmail.modified.length, 0, 'not known on arrival: left in the Inbox');
    assert.ok(users.every(u => (t.store.seenIds.get(`${u}|m${users.indexOf(u)}`).ix || []).includes(`d${R.hashOf('fresh-phish.example')}`)), 'the hashes kept with the checked marker');
    // A day later the list has the site; the hourly job downloads it, finds the copies and checks them.
    t.clock.add(21 * HOUR); t.listed.add('fresh-phish.example');
    const out = await t.svc.syncFeeds();
    assert.equal(out.feeds.find(f => f.id === 'phishingarmy').added, 1, 'the count only, not the entries');
    assert.deepEqual([out.recheck.found, out.rechecked.moved], [3, 3]);
    for (const [i, u] of users.entries()) {
        const r = await t.store.getRecord(`${u}|m${i}`);
        assert.equal(r.state, 'moved');
        assert.equal(r.recheck.outcome, 'moved');
        assert.equal(r.recheck.before, 'none');
        assert.equal(r.recheck.list, E.PHISH_FEEDS.find(f => f.id === 'phishingarmy').name);
        assert.equal(r.recheck.site, 'fresh-phish.example');
        assert.equal(r.recheck.opened, i === 0);
        assert.equal(r.arrival.action, 'none');
        assert.ok(r.receivedAt < r.recheck.at);
        assert.match(r.why, /^found on a re-check \(Phishing Army.* listed fresh-phish\.example after it was delivered\)/);
        assert.ok(t.boxes.get(`${u}|m${i}`).labels.has('SPAM') && !t.boxes.get(`${u}|m${i}`).labels.has('INBOX'));
    }
    const alert = (await t.store.listEvents(0)).find(e => e.kind === 'recheck' && e.alert);
    assert.ok(alert, 'an alert, emailed');
    assert.match(alert.text, /3 emails delivered earlier are now found to be phishing \(Phishing Army.* listed fresh-phish\.example\).*3 moved to Spam.*1 had been opened.*Threats → Re-checked/);
    assert.deepEqual(await t.store.getState('recheckQueue'), []);
    // Done once: the next run finds nothing more to do.
    t.clock.add(HOUR);
    const again = await t.svc.syncFeeds();
    assert.ok(!again.rechecked);
});

test('monitor mode: recorded as "would move", left in the Inbox; an email no longer in the Inbox isn\'t moved; mail older than RECHECK_DAYS isn\'t looked for', async () => {
    const t = setup({ mode: 'monitor' });
    await t.feeds.sync();
    await t.store.setState('feedsAttemptedAt', t.clock.get());
    await t.store.setState('installedAt', t.clock.get() - 30 * DAY);
    await t.deliver(`old@${ORG}`, 'o1', lure(`old@${ORG}`, 9));
    t.clock.add(8 * DAY);
    await t.store.setState('feedsAttemptedAt', t.clock.get());
    await t.deliver(`ana@${ORG}`, 'm1', lure(`ana@${ORG}`, 1));
    await t.deliver(`ben@${ORG}`, 'm2', lure(`ben@${ORG}`, 2));
    t.boxes.get(`ben@${ORG}|m2`).labels.delete('INBOX');          // ben archived it
    t.clock.add(21 * HOUR); t.listed.add('fresh-phish.example');
    const out = await t.svc.syncFeeds();
    assert.equal(out.recheck.found, 2, 'the 9-day-old email isn\'t looked for');
    const a = await t.store.getRecord(`ana@${ORG}|m1`), b = await t.store.getRecord(`ben@${ORG}|m2`);
    assert.deepEqual([a.action, a.state, a.recheck.outcome], ['would-move', 'inbox', 'would-move']);
    assert.deepEqual([b.action, b.state, b.recheck.outcome, b.recheck.where], ['flag', 'inbox', 'not-in-inbox', 'archived']);
    assert.match(b.why, /already left the Inbox \(archived by its reader\)/);
    assert.equal(t.gmail.modified.filter(m => m.add.includes('SPAM')).length, 0);
    assert.equal(await t.store.getRecord(`old@${ORG}|o1`), null);
});

test('off (RECHECK=false): no hashes kept, nothing re-checked', async () => {
    const t = setup({ recheck: false });
    await t.feeds.sync();
    await t.store.setState('feedsAttemptedAt', t.clock.get());
    await t.deliver(`ana@${ORG}`, 'm1', lure(`ana@${ORG}`, 1));
    assert.equal(t.store.seenIds.get(`ana@${ORG}|m1`).ix, undefined);
    t.clock.add(21 * HOUR); t.listed.add('fresh-phish.example');
    const out = await t.svc.syncFeeds();
    assert.ok(!out.recheck && !out.rechecked);
});

test('an admin\'s decision stands: a released email or one marked a false alarm isn\'t moved by a re-check', async () => {
    const t = setup();
    await t.feeds.sync();
    await t.store.setState('feedsAttemptedAt', t.clock.get());
    await t.deliver(`ana@${ORG}`, 'm1', lure(`ana@${ORG}`, 1));
    // (made so: a record of the email, marked a false alarm by an admin)
    const rec = { key: `ana@${ORG}|m1`, user: `ana@${ORG}`, messageId: 'm1', processedAt: t.clock.get(), receivedAt: t.clock.get(), action: 'flag', state: 'inbox', falseAlarm: true, sender: { address: 'notices@payroll-center.example', domain: 'payroll-center.example' }, signals: [] };
    await t.store.saveRecord(rec);
    t.clock.add(21 * HOUR); t.listed.add('fresh-phish.example');
    await t.svc.syncFeeds();
    assert.equal((await t.store.getRecord(rec.key)).state, 'inbox');
    assert.equal(t.gmail.modified.length, 0);
});

test('0.6.59: reviewed mail is never judged again: marked safe, phishing or spam, Not sure, or promotional mail an admin kept', async () => {
    const t = setup();
    const base = { processedAt: t.clock.get(), receivedAt: t.clock.get(), state: 'inbox', sender: { address: 'notices@payroll-center.example', domain: 'payroll-center.example' }, signals: [] };
    const cases = [
        { action: 'flag', falseAlarm: true, markedBy: `it@${ORG}` },
        { action: 'flag', falseAlarm: false, markedBy: `it@${ORG}` },
        { action: 'flag', falseAlarm: false, spam: true, markedBy: `it@${ORG}` },
        { action: 'flag', falseAlarm: null, unclear: true },
        { action: 'promo', falseAlarm: null, promoKept: { by: `it@${ORG}`, at: t.clock.get() } }
    ];
    for (const [i, c] of cases.entries()) {
        const id = `r${i}`;
        await t.deliver(`ana@${ORG}`, id, lure(`ana@${ORG}`, 1));
        await t.store.saveRecord(Object.assign({ key: `ana@${ORG}|${id}`, user: `ana@${ORG}`, messageId: id }, base, c));
        const out = await t.svc.recheckMessage({ user: `ana@${ORG}`, id, source: 'update', version: 'test' });
        assert.equal(out.outcome, 'skipped', JSON.stringify(c));
    }
    assert.equal(t.gmail.modified.length, 0);
});

test('Link clicks (off by default): Gmail\'s logs say who opened it and who clicked a link; a click is an alert', async () => {
    const t = setup();
    await t.feeds.sync();
    await t.store.setState('feedsAttemptedAt', t.clock.get());
    await t.store.setState('installedAt', t.clock.get() - 30 * DAY);
    await t.deliver(`ana@${ORG}`, 'm1', lure(`ana@${ORG}`, 1), { opened: true });
    await t.deliver(`ben@${ORG}`, 'm2', lure(`ben@${ORG}`, 2));
    const at = new Date(t.clock.get() + 20 * 60 * 1000).toISOString();
    const ev = (type, id) => ({ type, ev: { id: { time: at }, events: [{ name: 'delivery', parameters: [{ name: 'event_info', messageValue: { parameter: [{ name: 'mail_event_type', intValue: String(type) }] } }, { name: 'message', messageValue: { parameter: [{ name: 'rfc2822_message_id', value: id }] } }] }] } });
    t.gmail.logs[`ana@${ORG}`] = [ev(7, '<st1@payroll-center.example>'), ev(15, '<st1@payroll-center.example>'), ev(15, '<other@elsewhere.example>')];
    t.gmail.logs[`ben@${ORG}`] = [ev(15, '<other@elsewhere.example>')];
    assert.deepEqual(await t.svc.clickLogs(), { on: false, admin: '' });
    t.clock.add(21 * HOUR); t.listed.add('fresh-phish.example');
    let out = await t.svc.syncFeeds();
    assert.ok(!out.clicks, 'off: Gmail\'s logs not read');
    assert.equal(t.gmail.events.length, 0);
    assert.equal((await t.svc.setClickLogs(true, 'someone@elsewhere.example', `it@${ORG}`)).status, 400);
    await t.svc.setClickLogs(true, `it@${ORG}`, `it@${ORG}`);
    assert.ok((await t.store.listEvents(0)).some(e => e.admin && /turned on Link clicks \(Gmail's logs read as it@maple-schools\.example\)/.test(e.text)));
    t.clock.add(HOUR);
    out = await t.svc.syncFeeds();
    assert.deepEqual([out.clicks.checked, out.clicks.clicked], [2, 1]);
    assert.ok(t.gmail.events.every(e => e.admin === `it@${ORG}` && /^event_info\.mail_event_type==(15|16|7)$/.test(e.filters)));
    const a = (await t.store.getRecord(`ana@${ORG}|m1`)).recheck.clicks, b = (await t.store.getRecord(`ben@${ORG}|m2`)).recheck.clicks;
    assert.deepEqual([a.clicked, a.opened, a.clickedAt, a.named], [true, true, Date.parse(at), true]);
    assert.deepEqual([b.clicked, b.opened, b.named], [false, false, false], 'another email\'s click isn\'t this one\'s');
    const alert = (await t.store.listEvents(0)).find(e => e.kind === 'recheck-click');
    assert.ok(alert && alert.alert);
    assert.match(alert.text, /ana@maple-schools\.example \(an email from notices@payroll-center\.example, at .* UTC\).*resetting it/);
    // Looked at again later (Google's logs can be late), not every hour; never again once a click is found.
    const n = t.gmail.events.length;
    t.clock.add(HOUR); await t.svc.syncFeeds();
    assert.equal(t.gmail.events.length, n, 'within 3 hours: not again');
    t.clock.add(3 * HOUR); await t.svc.syncFeeds();
    assert.deepEqual(t.gmail.events.slice(n).map(e => e.mailbox), [`ben@${ORG}`, `ben@${ORG}`, `ben@${ORG}`]);
    // The test: the admin's own log for the last day.
    t.gmail.logs[`it@${ORG}`] = [ev(7, '<x1@elsewhere.example>')];
    const tested = await t.svc.testClickLogs('', `it@${ORG}`);
    assert.deepEqual([tested.ok, tested.events, tested.named], [true, 1, 1]);
});

test('suspicious mail is checked again an hour and a day after it arrived', async () => {
    const t = setup();
    await t.feeds.sync();
    await t.store.setState('feedsAttemptedAt', t.clock.get());
    const rec = { key: `ana@${ORG}|m1`, user: `ana@${ORG}`, messageId: 'm1', processedAt: t.clock.get(), receivedAt: t.clock.get(), action: 'flag', state: 'inbox', falseAlarm: null, sender: { address: 'notices@payroll-center.example', domain: 'payroll-center.example' }, signals: [], score: 3 };
    t.boxes.set(rec.key, { raw: lure(rec.user, 1), labels: new Set(['INBOX']), at: t.clock.get() });
    await t.store.saveRecord(rec);
    t.clock.add(30 * 60 * 1000); await t.svc.syncFeeds();
    assert.equal((await t.store.getRecord(rec.key)).laterChecks, undefined, 'not yet an hour old');
    t.clock.add(HOUR); await t.svc.syncFeeds();
    assert.equal((await t.store.getRecord(rec.key)).laterChecks, 1, 'checked again: nothing new');
    t.clock.add(HOUR); await t.svc.syncFeeds();
    assert.equal((await t.store.getRecord(rec.key)).laterChecks, 1, 'not every hour');
    // By the next day the site is on a list (in this instance's copy): the second look moves it.
    t.listed.add('fresh-phish.example');
    await t.feeds.sync({ force: true });
    await t.store.setState('recheckQueue', []);
    t.clock.add(22 * HOUR); await t.svc.syncFeeds();
    const r = await t.store.getRecord(rec.key);
    assert.deepEqual([r.state, r.recheck.outcome, r.recheck.source, r.recheck.round, r.laterChecks], ['moved', 'moved', 'later', 2, 2]);
    assert.match(r.why, /checked again a day after it arrived/);
});

test('0.5.39: Link clicks\' Test explains Google\'s refusal: the Reports privilege missing, or the scope', async () => {
    const t = setup();
    const { GoogleApiError } = require('../src/gmail/client');
    t.gmail.gmailEvents = async () => { throw new GoogleApiError(401, '{ "error": { "code": 401, "message": "Access denied. You are not authorized to read activity records." } }', `GET /spruce-directory%40${ORG}/applications/gmail`); };
    let r = await t.svc.testClickLogs(`spruce-directory@${ORG}`, `it@${ORG}`);
    assert.equal(r.ok, false);
    assert.match(r.why, /spruce-directory@maple-schools\.example isn't allowed to read Google's activity reports: its admin role doesn't have the Reports privilege/);
    assert.match(r.fix, /Admin roles → the role .* \(the directory admin's is "SPRUCE group reader"\) → Privileges → Admin console privileges → tick Reports/);
    assert.equal((await t.store.getState('clickLogsTest')).why, r.why);
    t.gmail.gmailEvents = async () => { throw new Error(`token for spruce-directory@${ORG}: HTTP 401 {"error":"unauthorized_client"} (is domain-wide delegation set up for https://www.googleapis.com/auth/admin.reports.audit.readonly?)`); };
    r = await t.svc.testClickLogs(`spruce-directory@${ORG}`, `it@${ORG}`);
    assert.match(r.why, /scope admin\.reports\.audit\.readonly isn't on its domain-wide delegation entry/);
    assert.match(r.fix, /Manage Domain Wide Delegation .* add https:\/\/www\.googleapis\.com\/auth\/admin\.reports\.audit\.readonly/);
    // The hourly look says the same in its alert.
    await t.svc.setClickLogs(true, `spruce-directory@${ORG}`, `it@${ORG}`);
    await t.store.saveRecord({ key: `ana@${ORG}|m1`, user: `ana@${ORG}`, messageId: 'm1', rfc822MessageId: 'x@y.example', processedAt: t.clock.get(), receivedAt: t.clock.get(), action: 'move', state: 'moved', sender: { address: 'a@b.example' }, recheck: { at: t.clock.get(), outcome: 'moved' } });
    t.gmail.gmailEvents = async () => { throw new GoogleApiError(401, 'Access denied. You are not authorized to read activity records.', 'GET /x'); };
    await t.svc.followClicks();
    const alert = (await t.store.listEvents(0)).find(e => e.kind === 'click-logs');
    assert.match(alert.text, /isn't allowed to read Google's activity reports.*tick Reports/);
});

// --- 0.5.51: the sender's and Reply-To domains; look-alikes; updates that change the checks ---------------

test('0.5.51: the hashes also hold the sender\'s domain and its Reply-To domains (with the domains above), never a personal mailbox provider\'s or our own', () => {
    const ix = R.indexOf(E, { urls: [], sender: 'payroll@mail.maple-schoo1s.example', replyTo: ['desk@reply-desk.example'], orgDomains: [ORG] });
    const has = (v) => ix.includes(`d${R.hashOf(v)}`);
    assert.ok(has('mail.maple-schoo1s.example') && has('maple-schoo1s.example') && has('reply-desk.example'));
    const personal = R.indexOf(E, { sender: 'someone@gmail.com', replyTo: [`x@${ORG}`], orgDomains: [ORG] });
    assert.deepEqual(personal, [`s${R.hashOf(E.normalizeSenderEntry('someone@gmail.com'))}`], 'only the address');
    // A list's or a look-alike's domain finds them by the same hash.
    assert.deepEqual(R.entryHashes(E, 'domain', 'maple-schoo1s.example'), [`d${R.hashOf('maple-schoo1s.example')}`]);
    // The words for each reason.
    assert.equal(R.foundWords({ source: 'lookalike', list: 'marked', site: 'maple-schoo1s.example' }), 'an admin marked maple-schoo1s.example a threat after it was delivered');
    assert.equal(R.foundWords({ source: 'lookalike', list: 'found', site: 'maple-schoo1s.example' }), 'the look-alike watch found maple-schoo1s.example imitating your domain after it was delivered');
    assert.equal(R.foundWords({ source: 'update', version: '0.5.51' }, { delivered: false }), 'version 0.5.51 changed how email is checked');
    const A = require('../src/dashboard/aggregate');
    assert.equal(A.recheckReason({ source: 'update', version: '0.5.51' }), 'Version 0.5.51 changed how email is checked');
    assert.equal(A.recheckReason({ source: 'lookalike', list: 'marked', site: 'x.example' }), 'An admin marked x.example a threat');
});

// The level this version runs (package.json): the tests raise it by one to stand for an update that changes the checks.
const LEVEL = require('../src/checks-level').checksLevel();

test('0.5.51: an update that changes the checks (checksLevel raised) re-checks the mail of the last 24 hours still in the Inbox, newest first, once; one that doesn\'t, nothing', async () => {
    const t = setup();
    const VERSION = require('../package.json').version;
    await t.feeds.sync();
    await t.store.setState('feedsAttemptedAt', t.clock.get());
    await t.store.setState('installedAt', t.clock.get() - 30 * DAY);
    // The first run of a version with checks levels: the level is recorded, nothing is checked again.
    let out = await t.svc.syncFeeds();
    assert.equal((await t.store.getState('checksLevel')).level, LEVEL);
    assert.ok(!out.checksUpdate && !(await t.store.getState('updateRecheck')));
    await t.deliver(`old@${ORG}`, 'o1', lure(`old@${ORG}`, 9));
    t.clock.add(30 * HOUR);
    await t.store.setState('feedsAttemptedAt', t.clock.get());
    await t.deliver(`ana@${ORG}`, 'm1', lure(`ana@${ORG}`, 1), { opened: true });
    t.clock.add(5 * 60 * 1000);
    await t.deliver(`ben@${ORG}`, 'm2', lure(`ben@${ORG}`, 2));
    t.boxes.get(`ben@${ORG}|m2`).labels.delete('INBOX');          // ben archived it
    // (This instance's checks now catch the newsletter: its list copy has the site, without a list's re-check.)
    t.listed.add('fresh-phish.example');
    await t.feeds.sync({ force: true });
    await t.store.setState('recheckQueue', []);
    // A version that changes nothing in the checks (the same level): nothing is checked again.
    t.clock.add(HOUR);
    out = await t.svc.syncFeeds();
    assert.ok(!out.checksUpdate && !out.rechecked);
    assert.equal(await t.store.getRecord(`ana@${ORG}|m1`), null);
    // A version that changes them: the two emails of the last 24 hours, not the one from 31 hours ago.
    t.svc.checksLevel = () => LEVEL + 1;
    t.clock.add(HOUR);
    out = await t.svc.syncFeeds();
    assert.equal(out.checksUpdate.queued, 2);
    assert.equal(out.rechecked.checked, 2);
    const a = await t.store.getRecord(`ana@${ORG}|m1`), b = await t.store.getRecord(`ben@${ORG}|m2`);
    assert.deepEqual([a.state, a.recheck.source, a.recheck.version, a.recheck.outcome, a.recheck.opened], ['moved', 'update', VERSION, 'moved', true]);
    assert.match(a.why, new RegExp(`^found on a re-check \\(version ${VERSION.replace(/\./g, '\\.')} changed how email is checked after it was delivered\\)`));
    assert.deepEqual([b.recheck.outcome, b.recheck.where], ['not-in-inbox', 'archived']);
    assert.equal(await t.store.getRecord(`old@${ORG}|o1`), null, 'older than RECHECK_AFTER_UPDATE_HOURS');
    const events = await t.store.listEvents(0);
    assert.ok(events.some(e => e.kind === 'recheck' && new RegExp(`Version ${VERSION.replace(/\./g, '\\.')} changes how email is checked: the mail delivered in the last 24 hours`).test(e.text)));
    assert.ok(events.some(e => e.alert && /changed how email is checked/.test(e.text)), 'the alert says why');
    assert.ok((await t.store.getState('updateRecheck')).doneAt);
    // Once: the next run checks nothing again; nor does a version that goes back (rolled back).
    t.clock.add(HOUR);
    out = await t.svc.syncFeeds();
    assert.ok(!out.rechecked && (!out.checksUpdate || out.checksUpdate.queued === 0));
    t.svc.checksLevel = () => LEVEL;
    t.clock.add(HOUR);
    out = await t.svc.syncFeeds();
    assert.ok(!out.rechecked);
});

test('0.5.51: RECHECK_AFTER_UPDATE_HOURS=0, or re-checking off: the update is noted, nothing is checked again', async () => {
    for (const env of [{ RECHECK_AFTER_UPDATE_HOURS: '0' }, { RECHECK: 'false' }]) {
        const t = setup({ recheck: env.RECHECK !== 'false', env: env.RECHECK_AFTER_UPDATE_HOURS ? env : {} });
        await t.feeds.sync();
        await t.store.setState('feedsAttemptedAt', t.clock.get());
        await t.svc.syncFeeds();
        await t.deliver(`ana@${ORG}`, 'm1', lure(`ana@${ORG}`, 1));
        t.svc.checksLevel = () => LEVEL + 1;
        t.clock.add(HOUR);
        const out = await t.svc.syncFeeds();
        assert.ok(!out.rechecked && !(await t.store.getState('updateRecheck')));
        assert.ok((await t.store.listEvents(0)).some(e => /changes how email is checked; delivered mail isn't checked again/.test(e.text)));
    }
});

test('0.5.51: the sweep after an update takes copies that arrived in the same millisecond, across runs, and stops at RECHECK_AFTER_UPDATE_MAX', async () => {
    const t = setup({ env: { RECHECK_AFTER_UPDATE_MAX: '8' } });
    await t.feeds.sync();
    await t.store.setState('feedsAttemptedAt', t.clock.get());
    await t.svc.syncFeeds();
    const now = t.clock.get();
    for (let i = 0; i < 7; i++) t.store.seenIds.set(`u${i}@${ORG}|x${i}`, { at: now, state: 'done', ix: ['d0'], rx: now - HOUR });
    for (let i = 7; i < 10; i++) t.store.seenIds.set(`u${i}@${ORG}|x${i}`, { at: now, state: 'done', ix: ['d0'], rx: now - 2 * HOUR });
    t.svc.checksLevel = () => LEVEL + 1;
    t.svc.runRechecks = async () => null;                 // (only the queueing here)
    // Room for 3 at a time (the queue nearly full).
    await t.store.setState('recheckQueue', Array.from({ length: 2997 }, (_, i) => ({ user: `q${i}@${ORG}`, id: `q${i}` })));
    const taken = new Set();
    for (let run = 0; run < 5; run++) {
        t.clock.add(HOUR);
        await t.svc.syncFeeds();
        const q = await t.store.getState('recheckQueue');
        for (const it of q.filter(x => x.source === 'update')) taken.add(`${it.user}|${it.id}`);
        await t.store.setState('recheckQueue', q.filter(x => x.source !== 'update'));
    }
    const sw = await t.store.getState('updateRecheck');
    assert.equal(taken.size, 8, 'each copy once, up to the maximum');
    assert.equal(sw.queued, 8);
    assert.ok(sw.doneAt);
    for (let i = 0; i < 7; i++) assert.ok(taken.has(`u${i}@${ORG}|x${i}`), 'the newest first, all 7 of the same millisecond');
});

test('0.5.51: an admin marks a look-alike a threat: the delivered mail from it is checked again', async () => {
    const t = setup();
    await t.feeds.sync();
    await t.store.setState('feedsAttemptedAt', t.clock.get());
    await t.store.setState('installedAt', t.clock.get() - 30 * DAY);
    const LOOK = 'maple-schoo1s.example';
    await t.store.setState('lookalikeWatch', { found: { [LOOK]: { domain: LOOK, first: t.clock.get() - 40 * DAY, last: t.clock.get(), mx: true, web: false, status: 'harmless', gone: null } } });
    // (marked harmless at first: no sign on arrival)
    const raw = (to) => Buffer.from([`From: Payroll Office <payroll@${LOOK}>`, `To: ${to}`, 'Subject: Direct deposit form', `Message-ID: <dd1@${LOOK}>`,
        `Authentication-Results: mx.google.com; dkim=pass header.i=@${LOOK}; spf=pass; dmarc=pass header.from=${LOOK}`,
        'Content-Type: text/plain; charset=utf-8', '', 'Hello, please see the attached schedule for the holiday pay dates. Payroll Office'].join('\r\n'));
    await t.deliver(`ana@${ORG}`, 'm1', raw(`ana@${ORG}`));
    const before = await t.store.getRecord(`ana@${ORG}|m1`);
    assert.ok((t.store.seenIds.get(`ana@${ORG}|m1`).ix || []).includes(`d${R.hashOf(LOOK)}`), 'its sender\'s domain is in its hashes');
    t.clock.add(2 * HOUR);
    const marked = await t.svc.markLookalike(LOOK, 'threat', `it@${ORG}`);
    assert.equal(marked.recheck.found, 1);
    const r = await t.svc.runRechecks({ budgetMs: 20000 });
    assert.equal(r.checked, 1);
    const rec = await t.store.getRecord(`ana@${ORG}|m1`);
    assert.ok(rec && rec.recheck, 'checked again');
    assert.deepEqual([rec.recheck.source, rec.recheck.list, rec.recheck.site], ['lookalike', 'marked', LOOK]);
    assert.ok(RECHECK_WORSE(before, rec), `a stronger verdict than on arrival (${before ? before.action : 'none'} → ${rec.action})`);
    assert.match(rec.why, /an admin marked maple-schoo1s\.example a threat after it was delivered/);
    // Marking it a threat again changes nothing: nothing more is looked for.
    assert.equal((await t.svc.markLookalike(LOOK, 'threat', `it@${ORG}`)).recheck, null);
});
const RECHECK_WORSE = (a, b) => ({ none: 0, flag: 1, 'would-move': 2, move: 3 })[b.action] > ({ none: 0, flag: 1, 'would-move': 2, move: 3 })[a ? a.action : 'none'];
