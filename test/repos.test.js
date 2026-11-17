'use strict';
// (0.6.9) The two repositories an installation downloads from (RELEASES_REPO, MODEL_REPO): no default, GitHub or
// GitLab (or another host for the model), changed on the dashboard only with the project ID, a ticked box and the
// admin's own address, and then an alert. Made-up repositories.
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const repos = require('../src/repos');
const { createReleases } = require('../src/releases');
const { loadConfig } = require('../src/config');
const { Service, policyValue } = require('../src/pipeline');
const { MemoryStore } = require('../src/store/memory');
const { createApp } = require('../src/server');

const SHA = 'f'.repeat(40);

test('addresses: GitHub, GitLab and other hosts; refused when not https, with a password, or with ? or #', () => {
    assert.deepEqual(repos.parseRepo('district-copy/releases'), { kind: 'github', host: 'github.com', path: 'district-copy/releases', url: 'https://github.com/district-copy/releases.git' }, 'OWNER/REPO, as before 0.6.9');
    assert.equal(repos.parseRepo('https://github.com/district-copy/releases.git').kind, 'github');
    const gl = repos.parseRepo('https://gitlab.com/district/tools/releases');
    assert.deepEqual([gl.kind, gl.path], ['gitlab', 'district/tools/releases']);
    assert.equal(repos.parseRepo('https://gitlab.district-copy.example/it/releases').kind, 'gitlab', 'a GitLab server of its own');
    assert.equal(repos.parseRepo('https://code.district-copy.example/it/model').kind, 'other');
    assert.equal(repos.rawUrl('district-copy/releases', SHA, 'package.json'), `https://raw.githubusercontent.com/district-copy/releases/${SHA}/package.json`);
    assert.equal(repos.rawUrl(gl, SHA, 'package.json'), `https://gitlab.com/district/tools/releases/-/raw/${SHA}/package.json`);
    assert.equal(repos.rawBase('https://code.district-copy.example/it/model'), 'https://code.district-copy.example/it/model');
    assert.equal(repos.newestCommit(gl).url, 'https://gitlab.com/api/v4/projects/district%2Ftools%2Freleases/repository/commits/main');
    assert.equal(repos.newestCommit('https://code.district-copy.example/it/x'), null, 'another host: versions can\'t be listed');
    assert.equal(repos.problem(''), '', 'empty: not set (allowed)');
    for (const [bad, why] of [['http://github.com/a/b', /Only https/], ['https://me:secret@github.com/a/b', /name or password/], ['https://github.com/a/b?x=1', /\? or #/],
        ['ftp://x/y', /Only https/], ['not an address', /isn't a web address/], ['https://localhost/a', /public domain/], [`https://github.com/${'a'.repeat(300)}`, /longer than/]])
        assert.match(repos.problem(bad), why, bad);
});

test('the approved versions from GitLab; none set: nothing asked; another host: update from Cloud Shell', async () => {
    const calls = [];
    const f = async (url) => {
        calls.push(url);
        const body = /\/repository\/commits\/main$/.test(url) ? { id: SHA, committed_date: '2026-11-17T08:00:00Z' }
            : url.endsWith('/package.json') ? JSON.stringify({ version: '9.9.9', installLevel: 1 })
            : url.endsWith('/CHANGELOG.md') ? '# Changelog\n\n## 9.9.9: Newer\n\n- x\n'
            : url.endsWith('/VENDOR.json') ? JSON.stringify({ model: '1.0.0', modelSource: { repository: 'https://gitlab.com/district/model', commit: 'c'.repeat(40) } }) : null;
        return body === null ? { ok: false, status: 404 } : { ok: true, status: 200, json: async () => body, text: async () => body };
    };
    const n = await createReleases({ repo: 'https://gitlab.com/district/tools/releases', fetch: f }).newest();
    assert.deepEqual([n.version, n.commit, n.date, n.repo, n.modelSource.repository], ['9.9.9', SHA, '2026-11-17T08:00:00Z', 'https://gitlab.com/district/tools/releases', 'https://gitlab.com/district/model']);
    assert.ok(calls.slice(1).every(u => u.startsWith(`https://gitlab.com/district/tools/releases/-/raw/${SHA}/`)));
    calls.length = 0;
    await assert.rejects(createReleases({ repo: '', fetch: f }).newest(), /no release repository is set/);
    await assert.rejects(createReleases({ repo: 'https://code.district-copy.example/it/releases', fetch: f }).newest(), /update from Cloud Shell/);
    assert.equal(calls.length, 0, 'nothing asked');
});

test('on the dashboard: refused without the ticked box and the admin\'s own address; then saved, noted and alerted; the page shows both', async () => {
    assert.equal(policyValue('releasesRepo', ' https://github.com/district-copy/releases '), 'https://github.com/district-copy/releases');
    assert.equal(policyValue('modelRepo', ''), '', 'cleared: not set');
    assert.throws(() => policyValue('releasesRepo', 'http://github.com/a/b'), (e) => e.status === 400 && /The release repository: Only https/.test(e.message));
    const cfg = loadConfig({ DEMO: '1', ORG_DOMAINS: 'maple-schools.example', STORE: 'memory' });
    assert.deepEqual([cfg.releasesRepo, cfg.modelRepo], ['', ''], 'no default');
    const store = new MemoryStore();
    const warned = [];
    const service = new Service({ cfg, store, gmail: {}, log: { error() {}, warn: (l) => warned.push(l) } });
    const srv = http.createServer(createApp({ cfg, store, service }));
    await new Promise(r => srv.listen(0, r));
    const base = `http://127.0.0.1:${srv.address().port}`;
    const post = async (body) => { const res = await fetch(`${base}/api/policy`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-requested-with': 'spruce-dashboard' }, body: JSON.stringify(body) }); return { status: res.status, body: await res.json() }; };
    try {
        const value = 'https://github.com/district-copy/releases';
        let out = await post({ key: 'releasesRepo', value, projectId: 'demo-project' });
        assert.equal(out.status, 400); assert.match(out.body.error, /Tick the box and type your own admin address/);
        out = await post({ key: 'releasesRepo', value, projectId: 'demo-project', agree: true, adminEmail: 'someone.else@maple-schools.example' });
        assert.equal(out.status, 400, 'another admin\'s address');
        out = await post({ key: 'releasesRepo', value, projectId: 'wrong-project', agree: true, adminEmail: 'demo-admin@example.org' });
        assert.equal(out.status, 403);
        assert.equal(cfg.releasesRepo, '', 'nothing changed');
        out = await post({ key: 'releasesRepo', value, projectId: 'demo-project', agree: true, adminEmail: 'demo-admin@example.org' });
        assert.equal(out.status, 200, JSON.stringify(out.body));
        assert.equal(cfg.releasesRepo, value);
        const ev = store.events.map(e => e.text);
        assert.ok(ev.some(t => /changed the release repository on the dashboard .*from not set to https:\/\/github\.com\/district-copy\/releases/.test(t)), ev.join('\n'));
        assert.ok(store.events.some(e => e.alert && e.kind === 'repos'), 'an alert');
        assert.ok(warned.some(l => /"spruceAlert":"repos"/.test(l)), 'emailed (Cloud Monitoring reads the log line)');
        const page = await (await fetch(`${base}/api/update`)).json();
        assert.equal(page.repos.releasesRepo.value, value);
        assert.equal(page.repos.modelRepo.value, '');
    } finally { srv.close(); }
});
