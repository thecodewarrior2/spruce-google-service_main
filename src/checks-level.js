'use strict';
// The checks level (0.5.51): which updates change how email is checked, so that only those re-check
// delivered mail (src/recheck.js, pipeline.js checksUpdate).
//
// package.json's "checksLevel" is raised by one in a version that changes how an email is judged: a rule,
// a sign or its weight, the AI model or its input, how the lists or other services are matched, what the
// policy does with a score. A version that only changes the dashboard, the wording, the documentation, the
// installation or comments keeps it. The running service remembers the level it last ran (Firestore
// state/checksLevel); when a new version's level is higher, it checks again the mail delivered in the last
// RECHECK_AFTER_UPDATE_HOURS that is still in the Inbox.
//
// So that a change to the checks can't go out without that decision, test/checks-level.test.js keeps a
// fingerprint of the files that judge email (FILES below, and the model's SHA-256 from
// vendor/spruce/VENDOR.json) in test/fixtures/checks-fingerprint.json, and fails when they changed but the
// fingerprint wasn't recorded again. `node tools/checks-level.js` records it, saying which it was: the level
// raised (the checks changed) or --cosmetic (only comments or wording that no email's verdict depends on).
// A change elsewhere that changes what these files are given (pipeline.js passes analyze() what it knows
// about the sender, the thread, the colleagues…) raises the level by hand too.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');

// The files that judge an email, relative to the repository.
const FILES = [
    'vendor/spruce/shared.js', 'vendor/spruce/decoders.js', 'vendor/spruce/ai.js',
    'src/engine/analyze.js', 'src/engine/attachments.js', 'src/engine/html.js', 'src/engine/language.js', 'src/engine/mailers.js',
    'src/engine/mime.js', 'src/engine/model.js', 'src/engine/network.js', 'src/engine/notifications.js', 'src/engine/replychain.js',
    'src/engine/spruce.js',
    'src/intel/feeds.js', 'src/intel/abusech.js', 'src/intel/threats.js', 'src/intel/spamhaus.js', 'src/intel/rdap.js', 'src/intel/index.js',
    'src/policy.js', 'src/lookalike.js', 'src/simulations.js'
];

// The level this version runs (package.json).
function checksLevel(root = ROOT) {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    return Number(pkg.checksLevel) || 0;
}

// SHA-256 over each judging file's bytes and the model files' pinned SHA-256 (the model isn't committed:
// VENDOR.json pins it), in a fixed order.
function fingerprint(root = ROOT) {
    const h = crypto.createHash('sha256');
    for (const f of FILES) {
        const buf = fs.readFileSync(path.join(root, f));
        h.update(`${f}\0${crypto.createHash('sha256').update(buf).digest('hex')}\n`);
    }
    const vendor = JSON.parse(fs.readFileSync(path.join(root, 'vendor/spruce/VENDOR.json'), 'utf8'));
    const files = (vendor.modelSource && vendor.modelSource.files) || {};
    for (const k of Object.keys(files).filter(k => k.startsWith('vendor/spruce/models/')).sort()) h.update(`${k}\0${files[k].sha256}\n`);
    return h.digest('hex');
}

module.exports = { FILES, checksLevel, fingerprint };
