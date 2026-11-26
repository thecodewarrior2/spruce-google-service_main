'use strict';
// (0.6.85) What the service knows about an email beyond its own text, gathered for the AI's next input format (format 4,
// phish-tiny's next model): Gmail's category, bulk-mail markers, the sender's history with the organization (with what
// differs this time), the conversation it belongs to, how many of your people got it, and how old the sender's domain is.
// None of it is content: labels, counts and yes/no answers, kept on an email's record (rec.aiContext) and given to the
// retraining export, so the next model learns from them. The current model (format 3) doesn't read them: no verdict
// changes until a format-4 model is synced.
//
// Every fact is null when unknown, so a model reads "unknown" rather than a guess.
const ST = require('./standing');
const { sendingService } = require('./engine/mailers');
const { oneClickSigned, headerValues } = require('./promotional');

const DAY = 24 * 60 * 60 * 1000;

// Gmail's category of the message (its tabs): primary, updates, promotions, social or forums; null when Gmail put none.
const CATEGORIES = { CATEGORY_PERSONAL: 'primary', CATEGORY_UPDATES: 'updates', CATEGORY_PROMOTIONS: 'promotions', CATEGORY_SOCIAL: 'social', CATEGORY_FORUMS: 'forums' };
function categoryOf(labelIds) {
    for (const l of labelIds || []) if (CATEGORIES[l]) return CATEGORIES[l];
    return null;
}

// The unsubscribe marker bulk mail carries: 'one-click signed' (both headers, signed by the sender's own organization:
// promotional.js oneClickSigned), 'listed' (a List-Unsubscribe header only), or null (none).
function unsubscribeOf(facts) {
    try { if (oneClickSigned(facts)) return 'one-click signed'; } catch (e) { /* no headers */ }
    const H = headerValues(facts && facts.rawForHeaders);
    return (H['list-unsubscribe'] || []).length ? 'listed' : null;
}

// The mailing service that sent it for the sender: a link through a known mailing service's tracker (its name), or a
// third party whose DKIM signature Gmail verified (its domain); null when the sender sent it itself (or nothing says).
function mailerOf(E, facts, linkUrls) {
    for (const u of linkUrls || []) {
        let p = null;
        try { p = E.emailTrackerProvider(u); } catch (e) { p = null; }
        if (p && p !== 'an email provider') return String(p).slice(0, 60);
    }
    const reg = (d) => { try { return E.registrableDomain(String(d || '').toLowerCase()) || ''; } catch (e) { return ''; } };
    for (const d of ((facts && facts.auth && facts.auth.dkimDomains) || [])) {
        const s = sendingService(d, facts, reg);
        if (s) return s.domain;
    }
    return null;
}

// The sender's history with the organization, from its standing record (src/standing.js: clean mail Gmail confirmed,
// counted while Settings → Policy → Sender standing isn't off) and when the address was first seen writing to anyone:
//   { first: true }                                    the address's first email to the organization (today);
//   { days, emails, activeDays, safe, phish, breaks }  a sender with clean mail before; breaks: what differs this time
//                                                      ('dkim', 'via', 'reply', 'links', 'attach': standing.js);
//   { days: n, emails: 0 }                             seen before, but no clean, confirmed mail counted;
//   null                                               unknown (no sender domain, or not read).
// Two-sided on purpose: a regular sender writing the way it always does, and one writing differently (a new link site, a
// new Reply-To), which is how a known sender's account taken over looks.
function historyOf(doc, prof, now, firstSeenAt) {
    const seenDays = typeof firstSeenAt === 'number' ? Math.max(0, Math.floor((now - firstSeenAt) / DAY)) : null;
    if (!doc || !doc.count) {
        if (seenDays === null) return doc === undefined ? null : { days: null, emails: 0 };
        return now - firstSeenAt < DAY ? { first: true } : { days: seenDays, emails: 0 };
    }
    const p = doc.prof || {};
    const breaks = ST.PARTS.filter(k => ((prof && prof[k]) || []).some(v => !(p[k] || []).includes(v)));
    if (prof && prof.attach && !p.attach) breaks.push('attach');
    return {
        days: Math.max(0, Math.floor((now - (doc.first || now)) / DAY)),
        emails: doc.count || 0,
        activeDays: doc.days || 0,
        safe: !!(doc.safe && doc.safe.at > (doc.phishAt || 0)),
        phish: !!doc.phishAt,
        breaks
    };
}

// The conversation: { reply, size, readerWrote }. reply: the subject and headers say it answers an earlier email; size: the
// emails the conversation holds in this mailbox (null when not read); readerWrote: the reader sent one of them (a real
// answer to their own email), null when unknown. A "RE:" answering nothing in the mailbox is a fake reply chain.
function threadOf(facts, info) {
    const reply = /^\s*(re|aw|sv|antw)\s*:/i.test(String((facts && facts.subject) || '')) && !!((facts && facts.inReplyTo) || ((facts && facts.references) || []).length);
    if (!reply) return { reply: false, size: null, readerWrote: null };
    const size = info && typeof info.size === 'number' ? info.size : typeof info === 'number' ? info : null;
    return { reply: true, size, readerWrote: info && typeof info.readerWrote === 'boolean' ? info.readerWrote : null };
}

// The facts known before the checks run (the pipeline's part); analyze adds the sender's domain age and the history
// (which needs the email's links), then hands the lot to the model as aiFacts.extra.
function arrivalFacts({ labelIds, facts, threadInfo = null, recipients = null }) {
    return {
        category: categoryOf(labelIds),
        unsubscribe: unsubscribeOf(facts),
        thread: threadOf(facts, threadInfo),
        recipients: typeof recipients === 'number' ? recipients : null
    };
}

// What analyze adds: the mailing service, the history and the domain's age (days; null when the registry didn't say).
function checkFacts(E, facts, result, { standingDoc, firstSeenAt, now, senderAge }) {
    let history = null;
    if (standingDoc !== undefined || typeof firstSeenAt === 'number') {
        const prof = (() => { try { return ST.profileOf(E, facts, result); } catch (e) { return null; } })();
        history = historyOf(standingDoc, prof, now, firstSeenAt);
    }
    return {
        mailer: mailerOf(E, facts, result.linkUrls),
        history,
        senderAgeDays: typeof senderAge === 'number' && isFinite(senderAge) ? Math.max(0, Math.round(senderAge)) : null
    };
}

// For the record and the export: only the known keys, each a label, a number, a yes/no or a short list (never content).
function cleanContext(x) {
    if (!x || typeof x !== 'object') return null;
    const num = (v) => (typeof v === 'number' && isFinite(v) ? Math.max(0, Math.round(v)) : null);
    const lab = (v, max = 60) => (typeof v === 'string' && v ? v.replace(/[^\w .@:+-]/g, '').slice(0, max) : null);
    const h = x.history;
    const t = x.thread;
    return {
        category: Object.values(CATEGORIES).includes(x.category) ? x.category : null,
        unsubscribe: ['one-click signed', 'listed'].includes(x.unsubscribe) ? x.unsubscribe : null,
        mailer: lab(x.mailer),
        history: !h ? null : h.first ? { first: true } : {
            days: num(h.days), emails: num(h.emails) || 0,
            ...(h.activeDays !== undefined ? { activeDays: num(h.activeDays) } : {}),
            ...(h.safe ? { safe: true } : {}), ...(h.phish ? { phish: true } : {}),
            ...(Array.isArray(h.breaks) ? { breaks: h.breaks.filter(b => ['dkim', 'via', 'reply', 'links', 'attach'].includes(b)) } : {})
        },
        thread: !t ? null : { reply: !!t.reply, size: num(t.size), readerWrote: typeof t.readerWrote === 'boolean' ? t.readerWrote : null },
        recipients: num(x.recipients),
        senderAgeDays: num(x.senderAgeDays)
    };
}

module.exports = { CATEGORIES, categoryOf, unsubscribeOf, mailerOf, historyOf, threadOf, arrivalFacts, checkFacts, cleanContext };
