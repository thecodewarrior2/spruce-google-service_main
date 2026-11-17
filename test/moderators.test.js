'use strict';
// 0.6.1: moderators (MODERATOR_GROUP) review emails, and never reach Settings, Health or what moves a whole campaign.
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { createApp, moderatorMay } = require('../src/server');
const { loadConfig, configProblems } = require('../src/config');
const { buildDemo } = require('../src/demo/seed');
const { Service } = require('../src/pipeline');
const { authorizeAdmin, adminGroupCheck } = require('../src/auth/verify');

const gmail = { labelId: async (u, n) => `L_${n}`, modify: async () => ({}) };

test('roles: an admin listed or in ADMIN_GROUP; a member of MODERATOR_GROUP is a moderator; a failed moderator check is a no, never a 503', async () => {
    const cfg = loadConfig({ ORG_DOMAINS: 'maple-schools.example', ADMIN_EMAILS: 'it.director@maple-schools.example', ADMIN_GROUP: 'spruce-admins@maple-schools.example',
        MODERATOR_GROUP: 'spruce-moderators@maple-schools.example', DIRECTORY_ADMIN: 'dir@maple-schools.example' });
    const groups = { 'spruce-admins@maple-schools.example': ['it.helpdesk@maple-schools.example'], 'spruce-moderators@maple-schools.example': ['office.clerk@maple-schools.example', 'it.helpdesk@maple-schools.example', 'pal@elsewhere.example'] };
    const g = { hasMember: async (admin, group, e) => { if (e === 'boom@maple-schools.example' && group.startsWith('spruce-moderators')) throw new Error('HTTP 404'); return (groups[group] || []).includes(e); } };
    const adminCheck = adminGroupCheck(cfg, g), modCheck = adminGroupCheck(cfg, g, () => Date.now(), cfg.moderatorGroups);
    const who = (e) => authorizeAdmin(e, cfg, adminCheck, modCheck);
    assert.deepEqual(await who('it.director@maple-schools.example'), { ok: true, email: 'it.director@maple-schools.example', role: 'admin' });
    assert.equal((await who('it.helpdesk@maple-schools.example')).role, 'admin', 'in both groups: an admin');
    assert.equal((await who('office.clerk@maple-schools.example')).role, 'moderator');
    assert.equal((await who('teacher@maple-schools.example')).status, 403);
    assert.equal((await who('pal@elsewhere.example')).status, 403, 'outside the organization: never through a group');
    const boom = await who('boom@maple-schools.example');
    assert.equal(boom.ok, false); assert.equal(boom.status, 403);
});

test('MODERATOR_GROUP: a list, or off; it needs DIRECTORY_ADMIN like ADMIN_GROUP', () => {
    assert.deepEqual(loadConfig({ MODERATOR_GROUP: 'Spruce-Moderators@maple-schools.example' }).moderatorGroups, ['spruce-moderators@maple-schools.example']);
    assert.deepEqual(loadConfig({ MODERATOR_GROUP: 'off' }).moderatorGroups, []);
    assert.deepEqual(loadConfig({}).moderatorGroups, []);
    const base = { ROLE: 'admin', ORG_DOMAINS: 'maple-schools.example', DELEGATED_SA: 'x@y.iam.gserviceaccount.com', IAP_AUDIENCE: 'a', ADMIN_EMAILS: 'a@maple-schools.example' };
    assert.ok(configProblems(loadConfig(Object.assign({ MODERATOR_GROUP: 'm@maple-schools.example' }, base))).some(p => /MODERATOR_GROUP needs DIRECTORY_ADMIN/.test(p)));
    assert.ok(!configProblems(loadConfig(Object.assign({ MODERATOR_GROUP: 'off' }, base))).some(p => /MODERATOR_GROUP/.test(p)));
});

test('what a moderator may call: the review pages, answers, whole campaigns and reading mail; never settings, health, look-alikes, the brake, release alone or exports', () => {
    for (const r of ['GET /api/session', 'GET /api/overview', 'GET /api/review', 'GET /api/message', 'GET /api/messages', 'GET /api/campaigns', 'GET /api/rechecked', 'GET /api/users', 'GET /api/help',
        'POST /api/mark', 'POST /api/unclear', 'POST /api/rescan', 'POST /api/check', 'POST /api/campaign/confirm', 'POST /api/campaign/release', 'POST /api/campaign/find',
        'POST /api/message/context']) assert.equal(moderatorMay(r), true, r);
    for (const a of ['phishing', 'false-alarm', 'unclear']) assert.equal(moderatorMay('POST /api/bulk', a), true, a);
    assert.equal(moderatorMay('POST /api/bulk', 'release'), false);
    for (const r of ['GET /api/settings', 'POST /api/policy', 'GET /api/status', 'GET /api/health', 'GET /api/readiness', 'GET /api/activity', 'GET /api/lookalikes', 'POST /api/lookalikes/mark',
        'POST /api/release', 'POST /api/resume', 'GET /api/export.csv',
        'POST /api/training-export', 'POST /api/training-export/allow', 'GET /api/update', 'POST /api/update', 'POST /api/rechecked/seen', 'GET /api/mailboxes', 'POST /api/digest/send']) assert.equal(moderatorMay(r), false, r);
});

test('the service refuses a moderator whatever the page shows, and says the role on every answer', async () => {
    const cfg = loadConfig({ DEMO: '1', DEMO_ROLE: 'moderator', ORG_DOMAINS: 'maple-schools.example' });
    const { store } = await buildDemo({ cfg, now: Date.now() });
    const service = new Service({ cfg, store, gmail });
    const srv = http.createServer(createApp({ cfg, store, service }));
    await new Promise(r => srv.listen(0, r));
    const call = (method, p, body) => new Promise((resolve, reject) => {
        const req = http.request({ port: srv.address().port, path: p, method, headers: { 'x-requested-with': 'spruce-dashboard', 'content-type': 'application/json' } }, (res) => {
            let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d ? JSON.parse(d) : {} }));
        });
        req.on('error', reject);
        if (body) req.write(JSON.stringify(body));
        req.end();
    });
    try {
        const s = await call('GET', '/api/session');
        assert.equal(s.status, 200); assert.equal(s.body.role, 'moderator'); assert.equal(s.body.admin, 'demo-moderator@example.org');
        const r = await call('GET', '/api/review?days=30');
        assert.equal(r.status, 200); assert.ok(r.body.groups.length);
        for (const [m, p] of [['GET', '/api/settings'], ['GET', '/api/status'], ['GET', '/api/health'], ['GET', '/api/activity'], ['GET', '/api/lookalikes']]) assert.equal((await call(m, p)).status, 403, p);
        const key = r.body.groups[0].keys[0];
        assert.equal((await call('POST', '/api/release', { key })).status, 403);
        assert.equal((await call('POST', '/api/bulk', { keys: [key], action: 'release' })).status, 403, 'moving back is not an answer');
        assert.equal((await call('POST', '/api/policy', { key: 'mode', value: 'enforce', projectId: 'demo-project' })).status, 403);
        const marked = await call('POST', '/api/bulk', { keys: [key], action: 'unclear' });
        assert.equal(marked.status, 200); assert.equal(marked.body.done, 1);
        assert.equal((await store.getRecord(key)).markedBy, 'demo-moderator@example.org', 'Activity and the record name the moderator');
    } finally { srv.close(); }
});

test('a false alarm in Spam goes back to the Inbox (Review, Messages, ticked together); one in the Inbox stays', async () => {
    const cfg = loadConfig({ DEMO: '1', ORG_DOMAINS: 'maple-schools.example' });
    const { store } = await buildDemo({ cfg, now: Date.now() });
    const calls = [];
    const g = { labelId: async (u, n) => `L_${n}`, modify: async (...a) => { calls.push(a); return {}; } };
    const service = new Service({ cfg, store, gmail: g });
    const all = await store.listRecords({ sinceMs: 0, limit: 100000 });
    const inSpam = all.filter(r => r.state === 'moved' && !r.markedBy);
    const inInbox = all.find(r => r.state === 'inbox' && !r.markedBy);
    const one = await service.mark(inSpam[0].key, true, 'mod@maple-schools.example');
    assert.equal(one.released, true);
    assert.equal(one.record.state, 'released'); assert.equal(one.record.falseAlarm, true);
    assert.deepEqual(calls[0].slice(2), [['INBOX', `L_${cfg.releasedLabel}`], ['SPAM', `L_${cfg.movedLabel}`]]);
    const kept = await service.mark(inInbox.key, true, 'mod@maple-schools.example');
    assert.equal(kept.released, false); assert.equal(kept.record.state, 'inbox');
    const bulk = await service.bulk(inSpam.slice(1, 3).map(r => r.key), 'false-alarm', 'mod@maple-schools.example');
    assert.equal(bulk.done, 2); assert.equal(bulk.released, 2);
});
