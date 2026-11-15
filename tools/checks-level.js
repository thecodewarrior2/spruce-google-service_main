#!/usr/bin/env node
'use strict';
// tools/checks-level.js — records whether a change to the files that judge email changes the checks
// (src/checks-level.js says why).
//
//     node tools/checks-level.js                     says whether the fingerprint changed since it was recorded
//     node tools/checks-level.js --raised            records it: this version changes how email is checked
//                                                    (package.json checksLevel raised by one first); delivered
//                                                    mail is checked again after the update
//     node tools/checks-level.js --cosmetic "why"    records it: only comments or wording no verdict depends on
//                                                    (same level); nothing is checked again
const fs = require('fs');
const path = require('path');
const { checksLevel, fingerprint } = require('../src/checks-level');

const ROOT = path.resolve(__dirname, '..');
const FIXTURE = path.join(ROOT, 'test/fixtures/checks-fingerprint.json');

const a = process.argv.slice(2);
const level = checksLevel(), now = fingerprint();
let rec = null;
try { rec = JSON.parse(fs.readFileSync(FIXTURE, 'utf8')); } catch (e) { /* none yet */ }
const fail = (m) => { console.error(m); process.exit(1); };

if (!a.length) {
    if (!rec) fail('No fingerprint recorded yet: node tools/checks-level.js --raised');
    if (rec.fingerprint === now && rec.checksLevel === level) { console.log(`The checks are as recorded (level ${level}).`); process.exit(0); }
    fail(`The files that judge email changed since the fingerprint was recorded (level ${rec.checksLevel}; package.json says ${level}).\n`
        + `If the change affects how any email is judged: raise "checksLevel" in package.json by one, then node tools/checks-level.js --raised.\n`
        + `If it is only comments or wording no verdict depends on: node tools/checks-level.js --cosmetic "what changed".`);
}
if (a[0] === '--raised') {
    if (rec && level <= rec.checksLevel) fail(`Raise "checksLevel" in package.json first (it is ${level}; recorded: ${rec.checksLevel}).`);
    fs.writeFileSync(FIXTURE, JSON.stringify({ checksLevel: level, fingerprint: now, note: rec ? 'Recorded by tools/checks-level.js --raised: this level changed how email is checked.' : 'The first level recorded (0.5.51).' }, null, 2) + '\n');
    console.log(rec ? `Recorded: checks level ${level}. After the update, delivered mail is checked again.` : `Recorded the first level (${level}).`);
} else if (a[0] === '--cosmetic') {
    const why = String(a[1] || '').trim();
    if (!why) fail('Say what changed: node tools/checks-level.js --cosmetic "comments in analyze.js"');
    if (!rec) fail('No fingerprint recorded yet: node tools/checks-level.js --raised');
    if (level !== rec.checksLevel) fail(`package.json's checksLevel (${level}) isn't the recorded one (${rec.checksLevel}): a cosmetic change keeps it.`);
    fs.writeFileSync(FIXTURE, JSON.stringify({ checksLevel: level, fingerprint: now, note: `Recorded by tools/checks-level.js --cosmetic: ${why.slice(0, 200)}` }, null, 2) + '\n');
    console.log(`Recorded as cosmetic (level ${level} kept): nothing is checked again for it.`);
} else fail('Usage: node tools/checks-level.js [--raised | --cosmetic "what changed"]');
