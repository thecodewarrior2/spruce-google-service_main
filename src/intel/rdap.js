'use strict';
// How old a domain is, from its registry's public record (RDAP; the extension's domainRegistration).
// The registry for an ending comes from IANA's bootstrap list (data.iana.org/rdap/dns.json, kept a
// month). Only the DOMAIN NAME is sent, to its own registry. Answers are kept in the shared store for
// 30 days (an unknown one for a day), so each domain is asked about once a month for the whole district.
// An answer slower than WAIT_MS is "unknown" (and not kept): a slow registry never holds an email up.
// (0.5.64) serverFor also gives the ownership lookups (src/intel/ownership.js) a registry's RDAP address.
const { TtlCache } = require('./http');
const timing = require('../timing');
const BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const KEEP_MS = 30 * 24 * 60 * 60 * 1000, UNKNOWN_KEEP_MS = 24 * 60 * 60 * 1000;
const WAIT_MS = 4000;
const DAY = 24 * 60 * 60 * 1000;

// Answers are also remembered by each instance for MEMO_MS, so a domain in many emails costs one
// Firestore read per instance, not one per email.
const MEMO_MS = 6 * 60 * 60 * 1000;

function createRdap({ http, store, engine, now = () => Date.now() }) {
    let bootstrap = null, bootstrapAt = 0;
    const flights = new Map();
    const memo = new TtlCache(20000);

    async function serverFor(tld) {
        if (!bootstrap || now() - bootstrapAt > KEEP_MS) {
            let map = await store.getCached('rdap', 'bootstrap');
            if (!map) {
                const res = await http.request(BOOTSTRAP_URL, {}, 10000);
                if (!res.ok) throw new Error(`IANA bootstrap: HTTP ${res.status}`);
                const data = await res.json();
                map = {};
                for (const [tlds, urls] of data.services || []) {
                    const https = (urls || []).find(u => /^https:\/\//.test(u));
                    if (https) for (const t of tlds) map[String(t).toLowerCase()] = https.endsWith('/') ? https : `${https}/`;
                }
                await store.setCached('rdap', 'bootstrap', map, KEEP_MS);
            }
            bootstrap = map; bootstrapAt = now();
        }
        return bootstrap[tld] || null;
    }

    async function lookup(reg) {
        const base = await serverFor(reg.split('.').pop());
        if (!base) return { created: null };
        const res = await http.request(`${base}domain/${encodeURIComponent(reg)}`, { headers: { accept: 'application/rdap+json' } }, WAIT_MS);
        if (!res.ok) return { created: null };
        const data = await res.json();
        const ev = (data.events || []).find(e => e && e.eventAction === 'registration' && e.eventDate);
        const t = ev ? Date.parse(ev.eventDate) : NaN;
        return { created: Number.isFinite(t) ? t : null };
    }

    // Age in days of a domain's registrable part, or null when unknown.
    async function ageDays(domain) {
        const reg = engine.registrableDomain(String(domain || '').toLowerCase());
        if (!reg || !engine.SENDER_DOMAIN_RE.test(reg)) return null;
        const t0 = Date.now();
        const mem = memo.get(reg);
        const hit = mem !== undefined ? mem : await store.getCached('age', reg).catch(() => null);
        let v = hit;
        const from = mem !== undefined ? 'memory' : hit ? 'store' : 'network';
        if (!v) {
            if (!flights.has(reg)) {
                flights.set(reg, (async () => {
                    let timer;
                    const late = new Promise(r => { timer = setTimeout(() => r(null), WAIT_MS); });
                    let out;
                    try { out = await Promise.race([lookup(reg), late]); } catch (e) { out = null; } finally { clearTimeout(timer); }
                    if (out) await store.setCached('age', reg, out, out.created ? KEEP_MS : UNKNOWN_KEEP_MS).catch(() => {});
                    return out;
                })().finally(() => flights.delete(reg)));
            }
            v = await flights.get(reg);
        }
        if (v && mem === undefined) memo.set(reg, v, v.created ? MEMO_MS : Math.min(MEMO_MS, UNKNOWN_KEEP_MS));
        timing.note('Domain age (RDAP)', Date.now() - t0, from);
        return v && v.created ? Math.max(0, Math.floor((now() - v.created) / DAY)) : null;
    }
    // (0.6.30) A domain's registration as the registry says it now (never cached), for the allow lists' 30-day check
    // (src/allowwatch.js): { exists, created, expires, registrar, ns } (ms times, the registrar's name, the name servers
    // sorted), exists false when the registry has no such domain, or null when it couldn't be asked.
    async function record(domain) {
        const reg = engine.registrableDomain(String(domain || '').toLowerCase());
        if (!reg || !engine.SENDER_DOMAIN_RE.test(reg)) return null;
        try {
            const base = await serverFor(reg.split('.').pop());
            if (!base) return null;
            const res = await http.request(`${base}domain/${encodeURIComponent(reg)}`, { headers: { accept: 'application/rdap+json' } }, WAIT_MS);
            if (res.status === 404) return { exists: false, created: null, expires: null, registrar: '', ns: [] };
            if (!res.ok) return null;
            const data = await res.json();
            const at = (action) => { const ev = (data.events || []).find(e => e && e.eventAction === action && e.eventDate); const t = ev ? Date.parse(ev.eventDate) : NaN; return Number.isFinite(t) ? t : null; };
            const ent = (data.entities || []).find(e => e && [].concat(e.roles || []).includes('registrar'));
            const fn = ent && Array.isArray(ent.vcardArray) && Array.isArray(ent.vcardArray[1]) ? (ent.vcardArray[1].find(v => Array.isArray(v) && v[0] === 'fn') || [])[3] : '';
            const ns = [...new Set((data.nameservers || []).map(n => String((n && n.ldhName) || '').toLowerCase().replace(/\.$/, '')).filter(Boolean))].sort();
            return { exists: true, created: at('registration'), expires: at('expiration'), registrar: String(fn || (ent && ent.handle) || '').slice(0, 120), ns: ns.slice(0, 12) };
        } catch (e) { return null; }
    }
    // (0.5.64) The registry's RDAP base for an ending, for the ownership lookups (src/intel/ownership.js).
    return { ageDays, serverFor, record };
}

module.exports = { createRdap };
