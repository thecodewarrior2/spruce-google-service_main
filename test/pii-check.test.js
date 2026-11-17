'use strict';
// 0.6.13: personal information is checked before every commit and push (tools/pii-check.js, .githooks/), and the
// whole repository here. The examples below are put together when the test runs, so this file holds none itself.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { scanLine, scan, addedLines, luhn, collect } = require('../tools/pii-check');

const at = (local, domain) => `${local}@${domain}`;
const kinds = (line, opts) => scanLine(line, opts).map(f => f.kind);

test('email addresses: reserved names pass; a personal mailbox or a real domain is a finding unless allowed', () => {
    const none = { allow: new Set(), terms: [] };
    assert.deepEqual(kinds(`From ${at('pat.mockwell', 'maple-schools.example')} and ${at('a', 'b.test')}`, none), []);
    assert.deepEqual(kinds(`write to ${at('made-up.person.01', 'gma' + 'il.com')}`, none), ['a personal mailbox address']);
    assert.deepEqual(kinds(`write to ${at('principal', 'real-district-' + 'k12.org')}`, none), ['an email address at a real domain']);
    const allow = new Set(['@vendor-' + 'mail.com', at('someone', 'gma' + 'il.com')]);
    assert.deepEqual(kinds(`${at('noreply', 'news.vendor-' + 'mail.com')} ${at('someone', 'gma' + 'il.com')}`, { allow, terms: [] }), [], 'an allowed organization, its subdomains, an allowed address');
    assert.deepEqual(kinds(at('other', 'gma' + 'il.com'), { allow: new Set(['@gma' + 'il.com']), terms: [] }), ['a personal mailbox address'], 'a personal provider is never allowed whole');
});

test('numbers and addresses: SSN, card (Luhn), phone (not the fictional 555), street; private words', () => {
    const none = { allow: new Set(), terms: [] };
    assert.deepEqual(kinds(`SSN ${'123-45'}-${'6789'}`, none), ['a Social Security number']);
    assert.ok(luhn('5555' + '5555' + '5555' + '4444'));
    assert.deepEqual(kinds(`card ${['5555', '5555', '5555', '4444'].join(' ')}`, none), ['a payment card number']);
    assert.deepEqual(kinds(`card ${['1234', '5678', '9012', '3456'].join(' ')}`, none), [], 'fails the Luhn check: not a card');
    assert.deepEqual(kinds(`call (${'999'}) ${'867'}-${'5301'}`, none), ['a phone number']);
    assert.deepEqual(kinds(`call (555) ${'201'}-${'3344'}`, none), [], 'the fictional 555 numbers');
    assert.deepEqual(kinds(`at ${'1428'} Elm ${'Street'}, Springfield`, none), ['a street address']);
    assert.deepEqual(kinds('Version 0.6.13, 294 tests, 2026-11-17, 127.0.1.2', none), [], 'versions, counts, dates and IPs are not findings');
    assert.deepEqual(kinds('Mail from Oakwood Unified today', { allow: new Set(), terms: ['oakwood unified'] }), ['one of your private words (.pii-terms)']);
});

test('a diff: only the lines it adds, with where they are', () => {
    const diff = ['diff --git a/x.md b/x.md', '--- a/x.md', '+++ b/x.md', '@@ -3,0 +4,2 @@', `+a line with ${at('x', 'gma' + 'il.com')}`, '+fine', '@@ -9 +11 @@', '-old', '+new'].join('\n');
    assert.deepEqual(addedLines(diff), [{ where: 'x.md:4', line: `a line with ${at('x', 'gma' + 'il.com')}` }, { where: 'x.md:5', line: 'fine' }, { where: 'x.md:11', line: 'new' }]);
    assert.equal(scan(addedLines(diff)).length, 1);
});

test('the hooks are in place: pre-commit, commit-msg and pre-push run the check; npm install turns them on', () => {
    const root = path.join(__dirname, '..');
    for (const [hook, mode] of [['pre-commit', '--staged'], ['commit-msg', '--message'], ['pre-push', '--pre-push']]) {
        const f = path.join(root, '.githooks', hook);
        assert.match(fs.readFileSync(f, 'utf8'), new RegExp(`node tools/pii-check\\.js ${mode}`), hook);
        assert.ok(fs.statSync(f).mode & 0o111, `${hook} is executable`);
    }
    assert.match(require('../package.json').scripts.prepare, /core\.hooksPath \.githooks/);
    assert.match(fs.readFileSync(path.join(root, '.gitignore'), 'utf8'), /^\.pii-terms$/m, 'your private words are never committed');
});

test('the whole repository: no personal information in any tracked file', () => {
    const found = scan(collect(['--all']));
    assert.deepEqual(found.map(f => `${f.where}: ${f.kind}: ${f.text}`), []);
});
