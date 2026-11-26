'use strict';
// (0.6.87) A look-alike of a company that mails you: a sender, Reply-To or link domain one small change away from the domain
// of a company with standing here (src/standing.js: clean mail Gmail confirmed, at least MIN_EMAILS emails, or an admin's
// Mark safe). The classic invoice and bank-change fraud against a school district writes from tallpine-furniture.example
// to the district's real vendor tallpinefurniture.example; brand lists know only well-known companies, and the look-alike
// watch only the district's own domain.
//
// No list of companies is kept in the clear: standing records are kept under one-way hashes of their domains. For a domain
// that has no standing itself, the near-misses (a letter dropped, added, changed or swapped; "rn" for "m"; a hyphen; another
// ending; a word such as "billing" or "invoice" added) are worked out, hashed the same way, and looked up in the set of
// correspondents' hashes. A match names the near-miss it found: the company it imitates.
const ST = require('./standing');

const MIN_LABEL = 6;            // a name shorter than this is left alone: short names one letter apart are often two real companies
const MAX_VARIANTS = 4000;
const ENDINGS = ['com', 'net', 'org', 'co', 'us', 'info', 'biz', 'io', 'app', 'online', 'site', 'xyz', 'top', 'live', 'shop', 'edu', 'cc', 'email', 'services'];
const WORDS = ['billing', 'invoice', 'invoices', 'pay', 'payment', 'payments', 'accounts', 'account', 'ap', 'ar', 'finance', 'secure', 'mail', 'email', 'support',
    'team', 'inc', 'llc', 'corp', 'group', 'us', 'usa', 'online', 'portal', 'docs', 'files', 'share', 'hr', 'payroll', 'admin', 'office', 'service', 'services'];
const ALPHA = 'abcdefghijklmnopqrstuvwxyz0123456789-';
const SWAPS = [['rn', 'm'], ['m', 'rn'], ['vv', 'w'], ['w', 'vv'], ['cl', 'd'], ['d', 'cl'], ['nn', 'm'], ['ii', 'u']];

// A registrable domain's name and ending ("tallpinefurniture", "example"); null when it has no dot.
function split(reg) {
    const i = String(reg || '').indexOf('.');
    return i > 0 ? { label: reg.slice(0, i), suffix: reg.slice(i + 1) } : null;
}

// The domains one small change away: [{ domain, how }]. how says what differs, in words.
function variantsOf(reg) {
    const p = split(reg);
    if (!p) return [];
    const out = new Map();
    const add = (label, suffix, how) => {
        if (out.size >= MAX_VARIANTS || !label || label.length < 2 || /^-|-$|--/.test(label)) return;
        const d = `${label}.${suffix}`;
        if (d !== reg && !out.has(d)) out.set(d, how);
    };
    const { label, suffix } = p;
    // A word added to the name, with or without a hyphen ("tallpinefurniture-billing"): the name without it.
    for (const w of WORDS) {
        for (const re of [new RegExp(`^${w}-?(.+)$`), new RegExp(`^(.+?)-?${w}$`)]) {
            const m = re.exec(label);
            if (m && m[1].length >= MIN_LABEL) { add(m[1], suffix, `"${w}" added to the name`); for (const e of ENDINGS) add(m[1], e, `"${w}" added and a different ending`); }
        }
    }
    // Another ending (.co for .com).
    if (label.length >= MIN_LABEL - 1) for (const e of ENDINGS) if (e !== suffix) add(label, e, `the ending .${suffix} instead of .${e}`);
    if (label.length < MIN_LABEL) return [...out].map(([domain, how]) => ({ domain, how }));
    for (let i = 0; i < label.length; i++) {
        add(label.slice(0, i) + label.slice(i + 1), suffix, `an extra "${label[i]}"`);                                   // a letter added (the real name lacks it)
        for (const c of ALPHA) if (c !== label[i]) add(label.slice(0, i) + c + label.slice(i + 1), suffix, `"${label[i]}" for "${c}"`);   // a letter changed
        if (i + 1 < label.length && label[i] !== label[i + 1]) add(label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2), suffix, 'two letters swapped');
    }
    for (let i = 0; i <= label.length; i++) for (const c of ALPHA) add(label.slice(0, i) + c + label.slice(i), suffix, `a missing "${c}"`);   // a letter dropped
    for (const [a, b] of SWAPS) {
        for (let i = label.indexOf(a); i >= 0; i = label.indexOf(a, i + 1)) add(label.slice(0, i) + b + label.slice(i + a.length), suffix, `"${a}" written for "${b}"`);
    }
    return [...out].map(([domain, how]) => ({ domain, how }));
}

// The correspondent a domain imitates: { domain, how }, or null (it is one itself, it imitates none, or it can't be told).
// keys: a Set of standing keys (ST.keyOf) of the companies that mail you.
function imitates(reg, keys) {
    if (!reg || !keys || !keys.size || keys.has(ST.keyOf(reg))) return null;
    for (const v of variantsOf(reg)) if (keys.has(ST.keyOf(v.domain))) return v;
    return null;
}

// The signs for one email (analyze.js): its sender's domain, its Reply-To domains and its links' domains, each looked up
// once. senderAge: the sender domain's age in days (null unknown); verified: Gmail's DMARC check passed for it.
//   sender: 5 when its domain is under YOUNG_DAYS old or Gmail couldn't confirm it (how such fraud looks: a domain registered
//   days before); 3 when Gmail confirmed it and its age isn't known or under OLD_DAYS; 1 when it is confirmed and older than
//   OLD_DAYS (more likely the same company's other domain, or another real company: said, and it keeps sender standing
//   from applying, but not suspicious on its own). A Reply-To 3, a link 2 (the first of each; the sender's own domain once).
const YOUNG_DAYS = 180, OLD_DAYS = 730, MAX_LINK_DOMAINS = 10;
function lookalikeSigns(E, facts, judgedLinks, { keys, orgDomains = [], senderAge = null, verified = false, cache = null } = {}) {
    if (!keys || !keys.size) return [];
    const reg = (d) => {
        const x = String(d || '').toLowerCase().replace(/\.$/, '');
        if (!x || !x.includes('.')) return null;
        let r; try { r = E.registrableDomain(x) || x; } catch (e) { r = x; }
        try { if (E.isPersonalMailDomain && E.isPersonalMailDomain(x)) return null; } catch (e) { /* kept */ }
        if (orgDomains.some(o => { try { return (E.registrableDomain(String(o).toLowerCase()) || o) === r; } catch (e) { return o === r; } })) return null;
        return r;
    };
    const look = (r) => {
        if (!r) return null;
        if (cache && cache.has(r)) return cache.get(r);
        const v = imitates(r, keys);
        if (cache) { if (cache.size >= 5000) cache.delete(cache.keys().next().value); cache.set(r, v); }
        return v;
    };
    const out = [];
    const from = reg(String(facts.senderAddress || '').split('@')[1]);
    const s = look(from);
    if (s) {
        const young = typeof senderAge === 'number' && senderAge < YOUNG_DAYS, old = typeof senderAge === 'number' && senderAge >= OLD_DAYS;
        out.push({ weight: young || !verified ? 5 : old ? 1 : 3, kind: 'correspondent-lookalike', text: `The sender's domain ${from} looks like ${s.domain}, a company that mails your organization (${s.how})${young ? `, and ${from} was registered ${Math.round(senderAge)} days ago` : ''}${!verified ? '; Gmail couldn\'t confirm the sender' : ''}${verified && old && !young ? `; ${from} is ${Math.round(senderAge / 365)} years old and Gmail confirmed it, so it may be the same company's other domain` : ''}. Invoice and bank-change fraud writes from such a look-alike of a real vendor.` });
    }
    const seen = new Set([from]);
    for (const a of facts.replyTo || []) {
        const r = reg(String(a).split('@').pop());
        if (!r || seen.has(r)) continue;
        seen.add(r);
        const v = look(r);
        if (v) { out.push({ weight: 3, kind: 'correspondent-lookalike-reply-to', text: `Replies go to ${r}, which looks like ${v.domain}, a company that mails your organization (${v.how}).` }); break; }
    }
    let linkDomains = 0;
    for (const j of judgedLinks || []) {
        const r = reg(hostOf(j.finalUrl || j.url));
        if (!r || seen.has(r) || ++linkDomains > MAX_LINK_DOMAINS) continue;
        seen.add(r);
        const v = look(r);
        if (v) { out.push({ weight: 2, kind: 'correspondent-lookalike-link', text: `A link goes to ${r}, which looks like ${v.domain}, a company that mails your organization (${v.how}).` }); break; }
    }
    return out;
}
const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase(); } catch (e) { return ''; } };

module.exports = { variantsOf, imitates, lookalikeSigns, MIN_LABEL, YOUNG_DAYS, OLD_DAYS };
