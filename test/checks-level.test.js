'use strict';
// 0.5.51: only an update that changes how email is checked re-checks delivered mail. package.json's checksLevel
// says so; the fingerprint of the files that judge email (src/checks-level.js) keeps the decision from being
// forgotten: a change to them needs either the level raised or a recorded "cosmetic" (tools/checks-level.js).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { FILES, checksLevel, fingerprint } = require('../src/checks-level');

test('the files that judge email are as recorded: a change to them raises checksLevel or is recorded as cosmetic (node tools/checks-level.js)', () => {
    const rec = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'checks-fingerprint.json'), 'utf8'));
    assert.equal(rec.checksLevel, checksLevel(), 'package.json\'s checksLevel is the recorded one: node tools/checks-level.js --raised after raising it');
    assert.equal(rec.fingerprint, fingerprint(),
        'The files that judge email changed. If the change affects how any email is judged: raise "checksLevel" in package.json by one, then '
        + 'node tools/checks-level.js --raised (delivered mail is checked again after the update). If it is only comments or wording: '
        + 'node tools/checks-level.js --cosmetic "what changed".');
});

test('the fingerprint covers the checks and the model, not the dashboard or the documentation', () => {
    for (const f of FILES) assert.ok(fs.existsSync(path.join(__dirname, '..', f)), f);
    assert.ok(FILES.includes('vendor/spruce/shared.js') && FILES.includes('src/engine/analyze.js') && FILES.includes('src/policy.js'));
    assert.ok(!FILES.some(f => /^public\/|^docs\/|\.md$|src\/server\.js|src\/dashboard\//.test(f)));
    // The model: its pinned SHA-256 changes the fingerprint.
    const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'checks-'));
    for (const f of [...FILES, 'package.json', 'vendor/spruce/VENDOR.json']) { fs.mkdirSync(path.dirname(path.join(tmp, f)), { recursive: true }); fs.copyFileSync(path.join(__dirname, '..', f), path.join(tmp, f)); }
    const before = fingerprint(tmp);
    const v = JSON.parse(fs.readFileSync(path.join(tmp, 'vendor/spruce/VENDOR.json'), 'utf8'));
    v.modelSource.files['vendor/spruce/models/phish-tiny/model.onnx'].sha256 = '0'.repeat(64);
    fs.writeFileSync(path.join(tmp, 'vendor/spruce/VENDOR.json'), JSON.stringify(v));
    assert.notEqual(fingerprint(tmp), before, 'a new model is a change to the checks');
    // A note in VENDOR.json that isn't the model's hash: not.
    v.modelSource.files['vendor/spruce/models/phish-tiny/model.onnx'].sha256 = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'vendor/spruce/VENDOR.json'), 'utf8')).modelSource.files['vendor/spruce/models/phish-tiny/model.onnx'].sha256;
    v.note = 'changed';
    fs.writeFileSync(path.join(tmp, 'vendor/spruce/VENDOR.json'), JSON.stringify(v));
    assert.equal(fingerprint(tmp), before);
    fs.rmSync(tmp, { recursive: true, force: true });
});
