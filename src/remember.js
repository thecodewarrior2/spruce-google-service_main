'use strict';
// (0.6.56) Remembered "Mark safe" answers (0.6.59: was "Not phishing"). An admin who marks an email safe answers every identical copy:
// to other people, and later. "Identical" is a fingerprint, a one-way hash (SHA-256) of the email's
//   - sender: the exact From address;
//   - subject: lower case, the reader's mailbox name, "Re:"/"Fwd:" and numbers taken out;
//   - text: the whole visible text, the same way (and the names the To line gives the reader, and (0.6.59) the name
//     after a greeting: "Dear Pat," and "Dear Sam," match; a subject's leading "Name," too);
//   - links: every link as the email has it. On a site where anyone shares a document or a file (Google Docs and Drive,
//     SharePoint, OneDrive, Dropbox, Box, DocuSign, forms, link shorteners…) the WHOLE link, so another document never
//     matches; elsewhere its host and path, with long random parts (a mailing service's per-copy tracking) taken out;
//   - attachments: each attached file's own SHA-256.
// Only the hash is kept (on the email's record, and in state rememberedSafe with the sender, the campaign's label and who
// answered): never the email. The pipeline uses a remembered answer only when Gmail confirmed the sender (DMARC) and
// nothing outside the email says otherwise (pipeline.js autoAnswerOf).
const crypto = require('crypto');

const KEEP_MS = 90 * 24 * 60 * 60 * 1000;   // a remembered answer lasts 90 days from the answer
const MAX_REMEMBERED = 3000;                 // the most kept (the least recently seen dropped first): a state document holds 1 MiB

// Sites where anyone shares a document, a file or a form, or shortens a link: the whole link counts.
const SHARE_HOSTS = /(^|\.)(docs\.google\.com|drive\.google\.com|sites\.google\.com|forms\.gle|goo\.gl|sharepoint\.com|onedrive\.live\.com|1drv\.ms|forms\.office\.com|forms\.microsoft\.com|dropbox\.com|dropboxusercontent\.com|box\.com|docusign\.net|docusign\.com|wetransfer\.com|we\.tl|jotform\.com|typeform\.com|canva\.com|notion\.site|bit\.ly|tinyurl\.com|t\.co|ow\.ly|rebrand\.ly|is\.gd|cutt\.ly|shorturl\.at)$/i;

// (0.6.59) The name a greeting gives ("Dear Pat," "Hi Sam Madeup:" "Good morning Ms. Samplefield,"), at the start of the
// text or of a line, up to the comma, colon or line end: copies of one email to different people greet each by name,
// and the To line doesn't always carry it (no display name, or a nickname). The greeting word itself stays.
const GREETING = /(^|\n)([ \t]*(?:dear|hi|hello|hey|hiya|greetings|good (?:morning|afternoon|evening|day)|attention|attn|to)\b)[ \t]+[^\n,:;!?]{1,40}(?=[,:;!?]|\n|$)/gu;
// A subject that starts with the reader's name and a comma ("Pat, your invoice is ready"): the name is left out.
const SUBJECT_NAME = /^\s*[\p{L}'’.-]{2,20}(?:\s+[\p{L}'’.-]{2,20})?\s*,\s*/u;

function words(t, drop, { subject = false } = {}) {
    let s = String(t || '').toLowerCase().normalize('NFKC');
    s = subject ? s.replace(/^((re|fw|fwd)\s*:\s*)+/g, '').replace(SUBJECT_NAME, '') : s.replace(GREETING, '$1$2 ');
    for (const d of drop) if (d.length >= 3) s = s.split(d).join(' ');
    return s.replace(/^((re|fw|fwd)\s*:\s*)+/g, '').replace(/[0-9]+/g, ' ').replace(/[^\p{L}]+/gu, ' ').trim();
}

// A link as the fingerprint counts it.
function linkKey(href) {
    let u;
    try { u = new URL(String(href || '').trim()); } catch (e) { return String(href || '').trim().toLowerCase().slice(0, 300); }
    if (!/^https?:$/.test(u.protocol)) return `${u.protocol}${u.pathname}`.toLowerCase().slice(0, 300);
    const host = u.hostname.toLowerCase();
    if (SHARE_HOSTS.test(host)) {
        for (const k of [...u.searchParams.keys()]) if (/^utm_/i.test(k)) u.searchParams.delete(k);
        return `${host}${u.pathname}${u.searchParams.toString() ? `?${u.searchParams.toString()}` : ''}`.slice(0, 500);
    }
    // A long or random-looking part of the path (a per-copy tracking code) is taken out; the query is left out.
    const path = u.pathname.split('/').map(p => (p.length >= 16 || (p.length >= 8 && /\d/.test(p) && /[a-z]/i.test(p)) ? '*' : p.toLowerCase())).join('/');
    return `${host}${path}`.slice(0, 300);
}

// The fingerprint of an email (32 hex digits), from the facts mime.readMessage gives; user: the reader's address.
function fingerprintOf(facts, user) {
    const local = String(user || '').split('@')[0].toLowerCase();
    const named = ((facts.people && facts.people.to) || []).flatMap(p => String(p.name || '').toLowerCase().split(/\s+/));
    const drop = [local, ...local.split(/[._-]+/), ...named].filter(Boolean).sort((a, b) => b.length - a.length);
    const links = [...new Set((facts.links || []).map(l => linkKey(l.href || l.url || '')).filter(Boolean))].sort();
    const files = (facts.attachmentFiles || []).filter(a => !a.inline).map(a => (a.content ? crypto.createHash('sha256').update(a.content).digest('hex') : `${a.type}|${a.size}`)).sort();
    const parts = [String(facts.senderAddress || '').toLowerCase(), words(facts.subject, drop, { subject: true }), words(facts.visibleText, drop).slice(0, 50000), links, files];
    return crypto.createHash('sha256').update(JSON.stringify(parts)).digest('hex').slice(0, 32);
}

module.exports = { fingerprintOf, linkKey, KEEP_MS, MAX_REMEMBERED, SHARE_HOSTS };
