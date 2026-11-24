'use strict';
// (0.6.76) Sender standing: when the AI's score is the only thing that objects to an email from a sender with standing,
// it doesn't make the email suspicious, and it doesn't move it (the email goes to Review → Suspicious instead). Nothing
// else changes: the rule checks (DMARC, forged headers or Message-ID, spam headers, threat lists, look-alikes, links a
// security service or a list flags…), Skip review, Spam senders, the brakes and a reader's Gmail report judge it as before.
//
// Standing belongs to a sender's domain (its registrable domain: e.example for news.e.example), never to free-mail
// domains (anyone can have an address there) or the organization's own, and only to an email whose DMARC check passed
// for that domain. It is earned two ways:
//   - history: the domain has mailed the organization for ESTABLISHED.days or more, on ESTABLISHED.activeDays different
//     days or more, ESTABLISHED.emails emails or more that the checks found nothing in (the only mail that counts), and
//     nobody ever answered one of its emails Phishing;
//   - an answer: an admin marked one of its emails safe (Review, Mail, an email's page), and no Phishing answer came after.
// Either way the email must look like the sender's usual mail: its profile, a short outline of how the domain mails (the
// domains that sign it (DKIM), the domain the mail service sends it from (SPF), its Reply-To domains, the domains its links
// go to, and whether it attaches files), learned from its clean mail and from its emails marked safe. A value never seen
// before (a new Reply-To, links to a site it has never used, a first attachment, another signing domain) is what a
// taken-over account looks like: then standing doesn't apply to that email.
// Only one-way hashes are kept (SHA-256, the first 16 digits): never an address, a domain in the clear, or any content.
const crypto = require('crypto');

const DAY = 24 * 60 * 60 * 1000;
const ESTABLISHED = { days: 30, activeDays: 5, emails: 10 };
const PROFILE_MAX = 40;          // the most values kept per part of the profile (the most recent)
const MODES = ['off', 'show', 'on'];
const PARTS = ['dkim', 'via', 'reply', 'links'];

const hash = (s) => crypto.createHash('sha256').update(`standing|${String(s || '').toLowerCase()}`).digest('hex').slice(0, 16);
const regOf = (E, d) => { const x = String(d || '').toLowerCase().replace(/\.$/, ''); try { return E.registrableDomain(x) || x; } catch (e) { return x; } };
const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase(); } catch (e) { return ''; } };

// The sender's domain standing is kept for (its registrable domain), or null: none for free-mail, the organization's own.
function senderDomain(E, facts, orgDomains = []) {
    const from = String((facts && facts.senderAddress) || '').toLowerCase().split('@')[1] || '';
    if (!from) return null;
    const reg = regOf(E, from);
    if (!reg || !reg.includes('.')) return null;
    try { if (E.isPersonalMailDomain && E.isPersonalMailDomain(from)) return null; } catch (e) { /* not known: kept */ }
    if ((orgDomains || []).some(o => regOf(E, o) === reg)) return null;
    return reg;
}
const keyOf = (reg) => hash(`domain|${reg}`);

// An email's profile, hashed: { dkim, via, reply, links: [hash…], attach }.
function profileOf(E, facts, result) {
    const auth = (facts && facts.auth) || {};
    const uniq = (l) => [...new Set(l.filter(Boolean))].sort();
    const from = regOf(E, String(facts.senderAddress || '').split('@')[1] || '');
    return {
        dkim: uniq((auth.dkimDomains || []).map(d => hash(regOf(E, d)))),
        via: uniq([auth.spfDomain ? hash(regOf(E, auth.spfDomain)) : '']),
        reply: uniq((facts.replyTo || []).map(a => regOf(E, String(a || '').split('@')[1] || '')).filter(d => d && d !== from).map(hash)),
        links: uniq(((result && result.linkUrls) || []).map(hostOf).filter(Boolean).map(h => hash(regOf(E, h)))),
        attach: ((facts.attachmentFiles || facts.attachments || []).filter(a => a && !a.inline)).length > 0
    };
}

// Signs that, present at all, keep standing from applying (on top of the email's status being clean): what imitates
// someone, hides something, or comes from a list.
const BLOCKING_SIGNS = /lookalike|spoof|colleague|inside-name|hidden|dangerous|blocked|listed|scam|young|first-time|brand|reply-to|forged|spam-flag|mismatch/;

// Whether the AI alone objects to this email and nothing else does: the only emails standing can change. null when it
// can, or why not.
function whyNotEligible(result, facts, decision, { relay = false } = {}) {
    if (!decision || !['flag', 'move', 'would-move'].includes(decision.action)) return 'not flagged';
    if (decision.autoAnswer || decision.held || decision.promotional) return 'answered otherwise';
    if (decision.action !== 'flag' && decision.trigger !== 'ai') return 'not moved by the AI alone';
    if (relay) return 'a platform\'s notification';
    if (!result || result.inside || result.status !== 'clean') return 'the rule checks found something';
    if (!facts || !facts.auth || facts.auth.dmarc !== 'pass' || !result.verified) return 'the sender check (DMARC) didn\'t pass';
    if ((result.links || []).length) return 'a link is flagged';
    if ((result.confirmedBy || []).length) return 'something outside the email confirms it';
    const s = result.strictSigns || {};
    if ((s.forgedHeaders || []).length || (s.spamHeaders || []).length || s.senderListed || s.dangerousLinks) return 'its headers or a list say otherwise';
    if ((result.signals || []).some(x => x && x.weight > 0 && BLOCKING_SIGNS.test(String(x.kind || '')))) return 'a sign the rules found';
    if (result.spamSender || result.allowSuspended) return 'a sender list';
    const p = result.ai && typeof result.ai.probability === 'number' ? result.ai.probability : null;
    if (p === null) return 'no AI score';
    return null;
}

// The standing a sender's record gives this email's profile: { kind: 'history'|'answer', ok, why, breaks }, or null.
function standingFor(doc, prof, now) {
    if (!doc) return null;
    const phish = doc.phishAt || 0;
    const answer = doc.safe && doc.safe.at > phish ? doc.safe : null;
    const history = !phish && now - (doc.first || now) >= ESTABLISHED.days * DAY && (doc.days || 0) >= ESTABLISHED.activeDays && (doc.count || 0) >= ESTABLISHED.emails;
    if (!answer && !history) {
        return { kind: null, ok: false, why: phish ? `an email from this sender was answered Phishing${doc.phishBy ? ` by ${doc.phishBy}` : ''}` : `the sender has no standing yet (${Math.floor((now - (doc.first || now)) / DAY)} days, ${doc.days || 0} days with mail, ${doc.count || 0} clean emails)` };
    }
    const kind = answer ? 'answer' : 'history';
    const p = doc.prof || {};
    const breaks = PARTS.filter(k => (prof[k] || []).some(v => !(p[k] || []).includes(v)));
    if (prof.attach && !p.attach) breaks.push('attach');
    const by = answer ? `${answer.by} marked an email from it safe` : `it has mailed you for ${Math.floor((now - doc.first) / DAY)} days (${doc.count} clean emails)`;
    if (breaks.length) return { kind, ok: false, breaks, why: `${by}, but this email doesn't mail the way it usually does (${breaks.map(b => BREAK_WORDS[b]).join(', ')})` };
    return { kind, ok: true, why: by };
}
const BREAK_WORDS = { dkim: 'another signing domain (DKIM)', via: 'another mail service (SPF)', reply: 'a new Reply-To domain', links: 'links to a site it hasn\'t used', attach: 'an attachment, which it doesn\'t usually send' };

// What standing does to the decision: 'clear' (suspicious → not flagged) or 'review' (moved → Review → Suspicious).
const effectOf = (decision) => (decision.action === 'flag' ? 'clear' : 'review');

// Adds a delta ({ now, day, n, prof }) to a sender's record (or a new one): what the stores' updateStanding runs.
function addTo(doc, delta) {
    const d = Object.assign({ first: delta.now, last: delta.now, lastDay: null, days: 0, count: 0, prof: {} }, doc || {});
    d.first = Math.min(d.first || delta.now, delta.first || delta.now);
    d.last = Math.max(d.last || 0, delta.now);
    if (delta.day && d.lastDay !== delta.day) { d.days = (d.days || 0) + 1; d.lastDay = delta.day; }
    d.count = (d.count || 0) + (delta.n || 0);
    d.prof = mergeProfile(d.prof, delta.prof);
    return d;
}
function mergeProfile(a = {}, b = {}) {
    const out = {};
    for (const k of PARTS) {
        const l = (a[k] || []).filter(v => !(b[k] || []).includes(v)).concat(b[k] || []);
        out[k] = l.slice(-PROFILE_MAX);
    }
    out.attach = !!(a.attach || b.attach);
    return out;
}

module.exports = { DAY, ESTABLISHED, MODES, PARTS, hash, senderDomain, keyOf, profileOf, whyNotEligible, standingFor, effectOf, addTo, mergeProfile };
