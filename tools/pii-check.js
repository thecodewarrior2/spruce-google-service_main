#!/usr/bin/env node
'use strict';
// tools/pii-check.js — refuses personal information (PII) before it is committed or pushed (CLAUDE.md: "Before every
// commit and every push"). The git hooks in .githooks/ run it on every commit and push (once per clone:
// `git config core.hooksPath .githooks`), and the tests run it over every tracked file (test/pii-check.test.js).
//
//     node tools/pii-check.js --staged            the lines a commit adds (pre-commit)
//     node tools/pii-check.js --message FILE      a commit message (commit-msg)
//     node tools/pii-check.js --range A..B        the lines and messages of the commits in A..B
//     node tools/pii-check.js --pre-push          what a push sends (git's pre-push hook gives the refs on stdin)
//     node tools/pii-check.js --all               every tracked file as it is now
//
// What it looks for (made-up data uses maple-schools.example and other reserved names: .example, .test, .invalid):
//   - an email address at a domain that isn't reserved for examples, unless tools/pii-allow.txt lists it (a
//     service's own address, like noreply@google.com). An address at a personal mailbox provider (gmail.com,
//     outlook.com…) is always a finding unless listed there too;
//   - a phone number, a US Social Security number, a payment card number (13 to 19 digits that pass the Luhn check),
//     a street address (a house number, a name, and Street, Avenue, Road…);
//   - a person's name: a common first name (src/names.js) followed by a surname, in text (Firstname Lastname) or in an
//     address (firstname.lastname@…), whose surname isn't on tools/pii-names.txt: the plainly made-up surnames the tests,
//     docs and demo use (Madeup, Samplefield, Testwood…), and the words after a first name that are no surname;
//   - your own private words: one per line in .pii-terms (in the repository, never committed: .gitignore) or in the
//     file SPRUCE_PII_TERMS names. Put your district's name and domains there: they are checked without ever being
//     written into the repository.
// A finding stops the commit or push and says where. A false alarm: write it again with made-up data, or (only for
// something that is no person's: a vendor's no-reply address, a documented example number) add the exact text to
// tools/pii-allow.txt with a comment saying why. Never allow a real person's detail.
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const git = (...a) => execFileSync('git', a, { cwd: ROOT, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });

const RESERVED = /(^|\.)(example|test|invalid|localhost)$|^example\.(com|org|net)$/i;
// Personal mailbox providers: anyone can have an address there, so an address at one is a person's (the provider's own
// domain only: mail.gmail.com is Google's servers, not a mailbox).
const PERSONAL_DOMAINS = new Set(['gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 'rocketmail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'icloud.com', 'me.com', 'mac.com',
    'aol.com', 'proton.me', 'protonmail.com', 'pm.me', 'gmx.com', 'gmx.net', 'mail.com', 'zoho.com', 'yandex.com', 'comcast.net', 'att.net', 'verizon.net', 'sbcglobal.net', 'bellsouth.net', 'cox.net', 'charter.net']);
const PERSONAL = { test: (d) => PERSONAL_DOMAINS.has(String(d).toLowerCase()) };
const EMAIL = /[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}/g;
const PHONE = /(?<![\w.-])(?:\+?1[ .-]?)?\(?[2-9]\d{2}\)?[ .-]\d{3}[ .-]\d{4}(?![\w-])/g;
const SSN = /(?<![\w-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\w-])/g;
const CARD = /(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])/g;
const STREET = /\b\d{1,5}\s+(?:[NSEW]\.?\s+)?[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Highway|Hwy|Parkway|Pkwy|Place|Pl|Terrace|Circle|Cir)\b\.?/g;

function luhn(digits) {
    let sum = 0;
    for (let i = 0; i < digits.length; i++) {
        let d = Number(digits[digits.length - 1 - i]);
        if (i % 2) { d *= 2; if (d > 9) d -= 9; }
        sum += d;
    }
    return sum % 10 === 0;
}

// tools/pii-allow.txt: one exact text a line ("# …" comments); privateTerms: .pii-terms and SPRUCE_PII_TERMS.
function readList(file) {
    try { return fs.readFileSync(file, 'utf8').split('\n').map(l => l.replace(/\s+#.*$/, '').trim()).filter(l => l && !l.startsWith('#')); }
    catch (e) { return []; }
}
// The common first names in src/names.js (its FIRST list), read from the file so that file stays as it is.
let firstNames = null, lastNames = null;
function namesBlock(which) {
    const m = new RegExp(`const ${which} = \`([^\`]*)\``).exec(fs.readFileSync(path.join(ROOT, 'src', 'names.js'), 'utf8'));
    return new Set((m ? m[1] : '').split(/\s+/).filter(Boolean));
}
function firstNameSet() { return firstNames || (firstNames = namesBlock('FIRST')); }
// ... and its common surnames: a capitalized word before one of them is a name too, whatever the first name.
function lastNameSet() { return lastNames || (lastNames = namesBlock('LAST')); }
// tools/pii-names.txt: one word a line, compared without case.
const nameList = () => new Set(readList(path.join(ROOT, 'tools', 'pii-names.txt')).map(s => s.toLowerCase()));
const NAME_PAIR = /\b([A-Z][a-z]+)\s+((?:Mc|Mac|O')?[A-Z][a-z]+(?:-[A-Z][a-z]+)?)\b/g;
// A quoted two-word display name before an address ("Firstname Lastname" <…>): a person, whatever the first name.
const NAME_SHOWN = /\\?"([A-Z][a-z]+) ((?:Mc|Mac|O')?[A-Z][a-z]+(?:-[A-Z][a-z]+)?)\\?"\s*</g;
const NAME_ADDR = /\b([a-z]+)[._]([a-z]+)(?:[._-]?[a-z0-9]+)*@/g;
const allowList = () => new Set(readList(path.join(ROOT, 'tools', 'pii-allow.txt')).map(s => s.toLowerCase()));
const privateTerms = () => [...readList(path.join(ROOT, '.pii-terms')), ...(process.env.SPRUCE_PII_TERMS ? readList(process.env.SPRUCE_PII_TERMS) : [])]
    .map(t => t.toLowerCase()).filter(t => t.length >= 3);

// The findings in one line of text: [{ kind, text }].
function scanLine(line, { allow = allowList(), terms = privateTerms(), names = nameList(), first = firstNameSet(), last = lastNameSet() } = {}) {
    const out = [];
    const allowed = (t) => allow.has(String(t).toLowerCase());
    for (const m of line.matchAll(EMAIL)) {
        const addr = m[0].replace(/\.+$/, ''), domain = addr.split('@')[1].toLowerCase();
        if (allowed(addr) || RESERVED.test(domain)) continue;
        // "@domain" in the allow list: that organization's addresses and its subdomains' (never a personal provider's)
        if (!PERSONAL.test(domain) && domain.split('.').some((x, i, a) => i < a.length - 1 && allowed(`@${a.slice(i).join('.')}`))) continue;
        out.push({ kind: PERSONAL.test(domain) ? 'a personal mailbox address' : 'an email address at a real domain', text: addr });
    }
    for (const m of line.matchAll(SSN)) if (!allowed(m[0])) out.push({ kind: 'a Social Security number', text: m[0] });
    // (555 numbers are the fictional ones films and examples use)
    for (const m of line.matchAll(PHONE)) if (!allowed(m[0]) && !/^\D*(?:1\D*)?\(?555\b/.test(m[0]) && !/[^\d]555[ .-]01\d\d/.test(` ${m[0]}`)) out.push({ kind: 'a phone number', text: m[0] });
    for (const m of line.matchAll(CARD)) {
        const digits = m[0].replace(/\D/g, '');
        if (digits.length >= 13 && digits.length <= 19 && luhn(digits) && !/^(\d)\1+$/.test(digits) && !allowed(m[0])) out.push({ kind: 'a payment card number', text: m[0] });
    }
    for (const m of line.matchAll(STREET)) if (!allowed(m[0])) out.push({ kind: 'a street address', text: m[0] });
    // A person's name: a first name, then a surname not on the made-up list.
    for (const m of line.matchAll(NAME_PAIR)) {
        const [a, b] = [m[1].toLowerCase(), m[2].toLowerCase()];
        if ((first.has(a) || last.has(b)) && !first.has(b) && !names.has(b) && !names.has(a) && !allowed(m[0])) out.push({ kind: 'a person\'s name (its surname isn\'t a made-up one: tools/pii-names.txt)', text: m[0] });
    }
    for (const m of line.matchAll(NAME_SHOWN)) {
        const t = `${m[1]} ${m[2]}`;
        if (!names.has(m[2].toLowerCase()) && !names.has(m[1].toLowerCase()) && !allowed(t) && !out.some(f => f.text === t)) out.push({ kind: 'a person\'s name (its surname isn\'t a made-up one: tools/pii-names.txt)', text: t });
    }
    for (const m of line.matchAll(NAME_ADDR)) {
        const [a, b] = [m[1], m[2]];
        if (first.has(a) && b.length > 1 && !first.has(b) && !names.has(b) && !allowed(`${a}.${b}`)) out.push({ kind: 'a person\'s name in an address (its surname isn\'t a made-up one: tools/pii-names.txt)', text: `${a}.${b}` });
    }
    const low = line.toLowerCase();
    for (const t of terms) if (low.includes(t)) out.push({ kind: 'one of your private words (.pii-terms)', text: t });
    return out;
}

// [{ where, line }] → findings with where they are.
function scan(lines, opts = {}) {
    const allow = allowList(), terms = privateTerms(), names = nameList(), first = firstNameSet(), last = lastNameSet();
    const out = [];
    for (const l of lines) for (const f of scanLine(l.line, Object.assign({ allow, terms, names, first, last }, opts))) out.push(Object.assign({ where: l.where }, f));
    return out;
}

// The lines a diff adds, with file:line.
function addedLines(diff) {
    const out = [];
    let file = null, n = 0;
    for (const l of diff.split('\n')) {
        if (l.startsWith('+++ ')) { file = l.slice(4).replace(/^b\//, ''); continue; }
        const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)/.exec(l);
        if (hunk) { n = Number(hunk[1]); continue; }
        if (file === null || file === '/dev/null') continue;
        if (l.startsWith('+')) { out.push({ where: `${file}:${n}`, line: l.slice(1) }); n++; }
        else if (!l.startsWith('-')) n++;
    }
    return out;
}
const SKIP_FILES = /^(package-lock\.json|test\/fixtures\/(model-reference\.json|model-input-format\.jsonl))$/;
const binaryOk = (f) => !/\.(png|jpe?g|gif|ico|woff2?|onnx|bin|zip|gz)$/i.test(f);

function linesOfFile(f) {
    const text = fs.readFileSync(path.join(ROOT, f), 'utf8');
    return text.split('\n').map((line, i) => ({ where: `${f}:${i + 1}`, line }));
}
function collect(argv) {
    const [mode, arg] = argv;
    if (mode === '--staged') return addedLines(git('diff', '--cached', '-U0', '--no-color', '--diff-filter=ACMR')).filter(l => !SKIP_FILES.test(l.where.split(':')[0]));
    if (mode === '--message') return fs.readFileSync(arg, 'utf8').split('\n').filter(l => !l.startsWith('#')).map((line, i) => ({ where: `commit message:${i + 1}`, line }));
    if (mode === '--range') {
        const lines = addedLines(git('diff', '-U0', '--no-color', '--diff-filter=ACMR', arg)).filter(l => !SKIP_FILES.test(l.where.split(':')[0]));
        const commits = git('rev-list', arg).split('\n').filter(Boolean);
        for (const c of commits) git('log', '-1', '--format=%B', c).split('\n').forEach((line, i) => lines.push({ where: `commit ${c.slice(0, 7)} message:${i + 1}`, line }));
        return lines;
    }
    if (mode === '--pre-push') {
        // Each line: <local ref> <local sha> <remote ref> <remote sha>. A new branch: its commits no remote has yet.
        const ZERO = /^0+$/;
        const lines = [];
        for (const l of fs.readFileSync(0, 'utf8').split('\n').filter(Boolean)) {
            const [, local, , remote] = l.split(' ');
            if (!local || ZERO.test(local)) continue;                       // a deletion sends nothing
            const commits = (ZERO.test(remote || '0') ? git('rev-list', local, '--not', '--remotes') : git('rev-list', `${remote}..${local}`)).split('\n').filter(Boolean);
            for (const c of commits) {
                const parent = git('rev-list', '--parents', '-n', '1', c).trim().split(' ')[1];
                const diff = parent ? git('diff', '-U0', '--no-color', '--diff-filter=ACMR', parent, c) : git('show', '-U0', '--no-color', '--format=', c);
                lines.push(...addedLines(diff).filter(x => !SKIP_FILES.test(x.where.split(':')[0])).map(x => Object.assign(x, { where: `${c.slice(0, 7)} ${x.where}` })));
                git('log', '-1', '--format=%B', c).split('\n').forEach((line, i) => lines.push({ where: `commit ${c.slice(0, 7)} message:${i + 1}`, line }));
            }
        }
        return lines;
    }
    if (mode === '--all') return git('ls-files').split('\n').filter(f => f && binaryOk(f) && !SKIP_FILES.test(f) && fs.existsSync(path.join(ROOT, f))).flatMap(linesOfFile);
    return null;
}

if (require.main === module) {
    const lines = collect(process.argv.slice(2));
    if (!lines) { console.error('Usage: node tools/pii-check.js --staged | --message FILE | --range A..B | --pre-push | --all'); process.exit(2); }
    const found = scan(lines);
    if (!found.length) { process.exit(0); }
    console.error(`Personal information check: ${found.length} finding${found.length === 1 ? '' : 's'} (nothing was committed or pushed):`);
    for (const f of found.slice(0, 50)) console.error(`  ${f.where}: ${f.kind}: ${f.text}`);
    if (found.length > 50) console.error(`  …and ${found.length - 50} more.`);
    console.error('Write it again with made-up data (maple-schools.example, .example names). Only something that is no person\'s (a vendor\'s\n'
        + 'no-reply address, a documented example) may go in tools/pii-allow.txt, with a comment saying why. CLAUDE.md, "Personal information".');
    process.exit(1);
}

module.exports = { scanLine, scan, addedLines, luhn, collect };
