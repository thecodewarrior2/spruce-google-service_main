'use strict';
// Re-checking delivered mail (0.5.35). Phishing sites are often put on a list hours after their email
// arrived. Each email left in the Inbox keeps, with its "checked" marker (seen/{user|id}), a few short
// one-way hashes: of its link sites (each host and the domains above it), of the exact address of a link
// on shared hosting (a cloud-storage page, where only the exact page can be listed), of the sender's
// address, and (0.5.51) of the sender's domain and its Reply-To domains (with the domains above them).
// When the daily download of a phishing list brings new entries, or (0.5.51) the look-alike watch finds a
// domain imitating the district's or an admin marks one a threat, their hashes find the emails that link
// there (or come from there, or ask for replies there) in every mailbox; each is then checked again in
// full, with the same rules, AI and brakes as on arrival (pipeline.js recheckMessage). The hashes only find
// candidates: nothing is decided on them, and they are never shown.
//
// (0.5.51) After an update that changes how email is checked (package.json checksLevel raised; see
// src/checks-level.js), the mail delivered in the last RECHECK_AFTER_UPDATE_HOURS that is still in the
// Inbox is checked again too, newest first; an update that changes nothing in the checks re-checks nothing.
//
// Nothing readable is kept: a hash of a site can only be matched against a site already known (a list's
// entry), not turned back into it.
const crypto = require('crypto');

const INDEX_MAX = 24;          // hashes kept per email
const QUERY_CHUNK = 30;        // Firestore's array-contains-any takes at most 30 values
const ADDED_MAX = 50000;       // new entries looked for per list and download (more: a list changed its format)

const hashOf = (v) => crypto.createHash('sha256').update(`spruce-recheck|${v}`).digest('hex').slice(0, 16);
const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase().replace(/\.$/, ''); } catch (e) { return ''; } };
const ownDomain = (host, orgDomains) => (orgDomains || []).some(d => host === d || host.endsWith(`.${d}`));

// A host and the domains above it, down to two labels (login.evil.example → login.evil.example,
// evil.example), as the lists are matched (feeds.js domainHitIn).
function hostAndParents(host) {
    const parts = host.split('.').filter(Boolean), out = [];
    for (let i = 0; i < parts.length - 1; i++) out.push(parts.slice(i).join('.'));
    return out;
}

// The hashes kept for an email: urls (its links, where they lead, links found in attachments), its
// sender's address, and (0.5.51) the sender's domain and replyTo's domains, each with the domains above
// it (as link sites are: a listed or look-alike domain finds mail from it as well as mail linking to it).
// Never the organization's own sites (a list never flags them whole: feeds.js exactOnly) nor the protected
// brands' (never on a list: feeds.js sanitize).
function indexOf(E, { urls = [], sender = '', replyTo = [], orgDomains = [] } = {}) {
    const out = new Set();
    const add = (k) => { if (out.size < INDEX_MAX) out.add(k); };
    if (sender && sender.includes('@')) add(`s${hashOf(E.normalizeSenderEntry(sender))}`);
    const seenHosts = new Set();
    const addDomain = (host) => {
        host = String(host || '').toLowerCase().replace(/\.$/, '');
        if (!host || !host.includes('.') || seenHosts.has(host) || ownDomain(host, orgDomains)) return;
        let reg = '';
        try { reg = E.registrableDomain(host); } catch (e) { reg = host; }
        // (a personal mailbox's provider, gmail.com…, is never listed whole: its sender address is enough)
        if (E.PROTECTED_DOMAINS.has(reg) || (typeof E.isPersonalMailDomain === 'function' && E.isPersonalMailDomain(reg))) return;
        seenHosts.add(host);
        for (const h of hostAndParents(host)) add(`d${hashOf(h)}`);
    };
    const domainOf = (a) => { const i = String(a || '').lastIndexOf('@'); return i > 0 ? String(a).slice(i + 1).replace(/>.*$/, '') : ''; };
    if (sender && sender.includes('@')) addDomain(domainOf(sender));
    for (const a of (replyTo || []).slice(0, 2)) addDomain(domainOf(a));
    for (const u of urls) {
        if (out.size >= INDEX_MAX) break;
        const host = hostOf(u);
        if (!host || !host.includes('.') || ownDomain(host, orgDomains)) continue;
        let reg = '';
        try { reg = E.registrableDomain(host); } catch (e) { reg = host; }
        if (E.PROTECTED_DOMAINS.has(reg)) continue;
        if (E.cloudStoragePage(u)) {
            // Shared hosting: only the exact page can be listed.
            const n = E.normalizeFeedUrl(u);
            if (n) add(`u${hashOf(n)}`);
            continue;
        }
        if (seenHosts.has(host)) continue;
        seenHosts.add(host);
        for (const h of hostAndParents(host)) add(`d${hashOf(h)}`);
    }
    return [...out];
}

// The hashes a list's new entry is looked for by, and what to say about it: a domain entry by its own
// hash (an email's link to it, or to a site under it, has it); a URL entry by its host (the full check
// then decides whether the exact page is the one listed) or, on shared hosting, by its exact address;
// a sender address by its hash.
function entryHashes(E, kind, entry) {
    if (kind === 'domain') return [`d${hashOf(String(entry).toLowerCase())}`];
    if (kind === 'address') return [`s${hashOf(E.normalizeSenderEntry(entry))}`];
    if (kind === 'url') {
        const host = hostOf(entry);
        if (!host) return [];
        if (E.cloudStoragePage(entry)) { const n = E.normalizeFeedUrl(entry); return n ? [`u${hashOf(n)}`] : []; }
        return [`d${hashOf(host)}`];
    }
    return [];
}

// The new entries of downloads ([{ name, kind, entries }]), as a Map hash → { site, list }: what the
// re-checks look for, and what they say about it.
function lookFor(E, added) {
    const out = new Map();
    for (const a of added || []) {
        for (const entry of (a.entries || []).slice(0, ADDED_MAX)) {
            const site = a.kind === 'url' ? (hostOf(entry) || entry) : entry;
            for (const h of entryHashes(E, a.kind, entry)) if (!out.has(h)) out.set(h, { site, list: a.name, kind: a.kind, source: a.source || 'lists' });
        }
    }
    return out;
}

const chunks = (list, n = QUERY_CHUNK) => { const out = []; for (let i = 0; i < list.length; i += n) out.push(list.slice(i, i + n)); return out; };

// Whether a value anywhere in a Gmail log event (the Reports API's parameters, nested to any depth) is
// this email's Message-ID: Google doesn't document where an event names its message, so every value is
// looked at (with or without the angle brackets).
function eventNames(ev, rfcId) {
    const want = String(rfcId || '').replace(/^<|>$/g, '').toLowerCase();
    if (!want) return false;
    const stack = [ev];
    let n = 0;
    while (stack.length && n++ < 5000) {
        const v = stack.pop();
        if (v == null) continue;
        if (typeof v === 'string') { if (v.replace(/^<|>$/g, '').toLowerCase() === want) return true; continue; }
        if (typeof v === 'object') for (const x of Object.values(v)) stack.push(x);
    }
    return false;
}
// Whether an event names a message at all: a parameter called something like message_id with a value, or
// a value shaped like a Message-ID (<…@…>). Settings → Link clicks's test, to tell whether this domain's
// logs can be matched to emails.
function eventHasMessageId(ev) {
    const stack = [ev];
    let n = 0;
    while (stack.length && n++ < 5000) {
        const v = stack.pop();
        if (typeof v === 'string') { if (/^<[^\s<>@]+@[^\s<>@]+>$/.test(v)) return true; continue; }
        if (!v || typeof v !== 'object') continue;
        if (typeof v.name === 'string' && /message_?id/i.test(v.name) && typeof v.value === 'string' && v.value.includes('@')) return true;
        for (const x of Object.values(v)) stack.push(x);
    }
    return false;
}
// The mail_event_type of an event (event_info.mail_event_type), wherever it sits.
function eventType(ev) {
    for (const p of (ev && ev.parameters) || []) {
        if (p.name === 'event_info' && p.messageValue) for (const q of p.messageValue.parameter || []) if (q.name === 'mail_event_type') return Number(q.intValue != null ? q.intValue : q.value);
        if (p.name === 'mail_event_type') return Number(p.intValue != null ? p.intValue : p.value);
    }
    return null;
}

// Why an email was checked again, in words (the record's recheck: { source, site, list, round, version }):
// for its record's "why", the alert and the dashboard (public/app.js has the same words).
function foundWords(rc, { delivered = true } = {}) {
    const after = delivered ? ' after it was delivered' : '';
    if (!rc) return '';
    if (rc.source === 'lists') return `${rc.list || 'A phishing list'} listed ${rc.site || 'one of its sites'}${after}`;
    if (rc.source === 'lookalike') return rc.list === 'marked' ? `an admin marked ${rc.site || 'a look-alike'} a threat${after}` : `the look-alike watch found ${rc.site || 'a domain'} imitating your domain${after}`;
    if (rc.source === 'update') return `version ${rc.version || 'a new version'} changed how email is checked${after}`;
    return `checked again ${rc.round === 2 ? 'a day' : 'an hour'} after it arrived`;
}

module.exports = { foundWords, indexOf, entryHashes, lookFor, hashOf, chunks, eventNames, eventHasMessageId, eventType, hostAndParents, INDEX_MAX, QUERY_CHUNK, ADDED_MAX };
