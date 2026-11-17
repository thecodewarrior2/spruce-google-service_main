'use strict';
// 0.6.1: Health → DMARC reads your domains' DMARC and SPF records and says what they mean.
const test = require('node:test');
const assert = require('node:assert');
const { createDmarcCheck, gradeDmarc, gradeSpf, tagsOf, parentsOf } = require('../src/dashboard/dmarc');

test('grading a DMARC record: reject is strong; none, a low pct or sp=none can be stronger; none, two or no policy need attention', () => {
    assert.equal(gradeDmarc(['v=DMARC1; p=reject; rua=mailto:r@maple-schools.example']).level, 'good');
    assert.equal(gradeDmarc(['v=DMARC1; p=quarantine; rua=mailto:r@maple-schools.example']).level, 'good');
    const none = gradeDmarc(['v=DMARC1; p=none']);
    assert.equal(none.level, 'warn'); assert.ok(none.notes.some(n => /rua=/.test(n)), 'no report address is said');
    assert.equal(gradeDmarc(['v=DMARC1; p=reject; pct=25; rua=mailto:r@x.example']).level, 'warn');
    assert.equal(gradeDmarc(['v=DMARC1; p=reject; sp=none; rua=mailto:r@x.example']).level, 'warn');
    assert.equal(gradeDmarc([]).level, 'bad');
    assert.equal(gradeDmarc(['v=DMARC1; p=reject', 'v=DMARC1; p=none']).level, 'bad');
    assert.equal(gradeDmarc(['v=DMARC1; rua=mailto:r@x.example']).level, 'bad');
    assert.deepEqual(tagsOf('v=DMARC1; P=reject ;rua=mailto:a@b.example'), { v: 'DMARC1', p: 'reject', rua: 'mailto:a@b.example' });
});

test('grading SPF: -all and ~all are fine; +all, two records, none or no "all" are not', () => {
    assert.equal(gradeSpf(['v=spf1 include:_spf.google.com -all']).level, 'good');
    assert.equal(gradeSpf(['v=spf1 include:_spf.google.com ~all']).level, 'good');
    assert.equal(gradeSpf(['v=spf1 +all']).level, 'bad');
    assert.equal(gradeSpf(['v=spf1 a', 'v=spf1 mx']).level, 'bad');
    assert.equal(gradeSpf(['v=spf1 include:_spf.google.com']).level, 'warn');
    assert.equal(gradeSpf([]).level, 'warn');
    assert.deepEqual(parentsOf('students.maple-schools.example'), ['maple-schools.example']);
    assert.deepEqual(parentsOf('maple-schools.example'), []);
});

test('the lookup: long records joined, a subdomain falls back to its parent, a failure is said and not kept, answers kept 10 minutes', async () => {
    const zone = {
        '_dmarc.maple-schools.example': ['"v=DMARC1; p=reject; " "rua=mailto:dmarc@maple-schools.example"'],
        'maple-schools.example': ['"v=spf1 include:_spf.google.com -all"', '"google-site-verification=x"'],
        'students.maple-schools.example': ['"v=spf1 -all"']
    };
    const asked = []; let down = false; let t = 0;
    const http = { request: async (url) => {
        const name = new URL(url).searchParams.get('name'); asked.push(name);
        if (down) return { ok: false, status: 503 };
        const recs = zone[name];
        return { ok: true, json: async () => (recs ? { Status: 0, Answer: recs.map(data => ({ type: 16, data })) } : { Status: 3 }) };
    } };
    const check = createDmarcCheck({ http, now: () => t });
    const [main, sub] = await check(['maple-schools.example', 'students.maple-schools.example']);
    assert.deepEqual(main.dmarc.records, ['v=DMARC1; p=reject; rua=mailto:dmarc@maple-schools.example']);
    assert.equal(main.dmarc.level, 'good'); assert.deepEqual(main.spf.records, ['v=spf1 include:_spf.google.com -all']);
    assert.equal(sub.dmarc.records.length, 0); assert.equal(sub.dmarc.inherited.domain, 'maple-schools.example');
    assert.match(sub.dmarc.words, /maple-schools\.example's applies/);
    const n = asked.length;
    await check(['maple-schools.example']);
    assert.equal(asked.length, n, 'kept');
    down = true;
    const [failed] = await check(['maple-schools.example'], { fresh: true });
    assert.match(failed.error, /HTTP 503/);
    down = false; t += 11 * 60 * 1000;
    assert.equal((await check(['maple-schools.example']))[0].dmarc.level, 'good');
    const off = await createDmarcCheck({ http: null })(['maple-schools.example']);
    assert.match(off[0].error, /no way to reach DNS/);
});
