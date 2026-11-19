'use strict';
// (0.5.64) Does a sender's domain belong to the brand its name claims? ("Xoom, a PayPal Service" from
// service.xoom.com.) The brand table in vendor/spruce/shared.js knows each brand's main domain(s); any other
// domain is judged from public records, as the S.P.R.U.C.E+ extension does (brandOwnership in its
// background.js), never from a hand-kept list:
//   owned — proof that needs the brand's own DNS, or a registrar a forger can't use:
//     • the brand's DMARC record sends its reports to the domain;
//     • the domain's DMARC record sends its reports to the brand, and the brand publishes the RFC 7489
//       authorization for them (<domain>._report._dmarc.<brand>; a wildcard that answers for any name
//       vouches for no one, so it doesn't count);
//     • its name servers are under the brand's domain (ns1-pchnet.paypal.com), or the same set as the brand's
//       (not at providers whose servers every customer shares, nor a per-customer pool's names);
//     • a corporate brand-protection registrar (MarkMonitor, CSC…) and a registrant naming the brand;
//     • (0.6.45) a corporate registrar and DMARC reports sent to the very same mailbox as the brand's (one company's
//       account at a report service).
//   likely — a corporate registrar plus one more link to the brand (reports sent to it, a registrant naming
//     it, the same per-customer name servers, or a year or more of age): a caution, never moved.
//   unknown — anything less: judged as before.
// What is sent: domain names only, to Cloudflare's public resolver (DNS over HTTPS) and to the domain's
// registry and registrar (RDAP). Answers are kept in the shared store for 30 days (unknown: a day), and by each
// instance for MEMO_MS; one lookup at a time per domain and brand.
const { TtlCache } = require('./http');

const DOH = 'https://cloudflare-dns.com/dns-query';
// (0.6.46) Answers kept: proof (owned) and likely 60 days, refreshed in the background once REFRESH_MS old so a busy
// morning never waits on one; "no proof" 7 days; a lookup that failed (a request with no answer) 6 hours, so a domain on
// many emails isn't asked again and again meanwhile. A failure never lowers a score: it counts as no proof.
const DAY_MS = 24 * 60 * 60 * 1000;
const KEEP_MS = 60 * DAY_MS, REFRESH_MS = 50 * DAY_MS, UNKNOWN_KEEP_MS = 7 * DAY_MS, FAILED_KEEP_MS = 6 * 60 * 60 * 1000;
const keepFor = (v) => (v.state !== 'unknown' ? KEEP_MS : v.failed ? FAILED_KEEP_MS : UNKNOWN_KEEP_MS);
const MEMO_MS = 6 * 60 * 60 * 1000;
const WAIT_MS = 4000;          // each request; the whole answer is awaited at most OWNERSHIP_WAIT_MS (analyze.js)
const CORPORATE_REGISTRARS = /markmonitor|csc corporate domains|corporation service company|com laude|nom-iq|safenames|godaddy corporate domains|brandsight|lexsynergy|nameshield|ip twins|registrarsafe|abion\b|appdetex|safebrands/i;
const NS_CUSTOMER_POOL = [/^dns\d+\.(p\d+)\.nsone\.net$/, /^ns\d+\.(p\d+)\.dynect\.net$/, /^([a-z]+)\.ns\.cloudflare\.com$/];
const NS_SHARED = /(^|\.)(ultradns\.(com|net|org|biz|info|co\.uk)|googledomains\.com|azure-dns\.(com|net|org|info)|domaincontrol\.com|registrar-servers\.com|he\.net|wixdns\.net|squarespacedns\.com|name-services\.com|worldnic\.com|ui-dns\.(com|de|org|biz)|ionos\.(com|de)|hostgator\.com|bluehost\.com|dreamhost\.com|siteground\.net|ovh\.net|cloudns\.net|dnsmadeeasy\.com)$/i;
const REDACTED = /redacted|privacy|protected|withheld|not disclosed|gdpr|data protected|statutory masking/i;

const recordTags = (txt) => Object.fromEntries(String(txt || '').split(';').map(p => p.trim()).filter(Boolean).map(p => { const i = p.indexOf('='); return i < 0 ? [p.toLowerCase(), ''] : [p.slice(0, i).trim().toLowerCase(), p.slice(i + 1).trim()]; }));
// The registrable domains a DMARC record's rua= and ruf= reports go to.
function reportDomains(tags, registrable) {
    const out = new Set();
    if (tags) for (const k of ['rua', 'ruf']) for (const part of String(tags[k] || '').split(',')) {
        const m = /mailto:[^@\s!,;]+@([a-z0-9.-]+)/i.exec(part.trim());
        if (m) { const d = registrable(m[1].toLowerCase()); if (d) out.add(d); }
    }
    return out;
}
// (0.6.45) Whether a report mailbox is one company's own account at a report service, not an address the service gives
// every customer (dmarc_rua@…, dmarc_agg@…, d@…): its name carries the brand's name (capital-one@…), or it is an account
// number (letters and digits, 8 or more: c7xrs-8253@…).
function accountMailbox(box, brand) {
    const local = String(box || '').split('@')[0].toLowerCase();
    const flat = local.replace(/[^a-z0-9]/g, '');
    const names = [brand.name, ...(brand.tokens || [])].filter(n => !(brand.ambiguousTokens || []).includes(n)).map(n => String(n).toLowerCase().replace(/[^a-z0-9]/g, '')).filter(n => n.length >= 3);
    if (names.some(n => flat.includes(n))) return true;
    return flat.length >= 8 && /[a-z]/.test(flat) && /\d/.test(flat);
}
// (0.6.45) The mailboxes (whole addresses) a DMARC record's reports go to, lowercased.
function reportMailboxes(tags) {
    const out = new Set();
    if (tags) for (const k of ['rua', 'ruf']) for (const part of String(tags[k] || '').split(',')) {
        const m = /mailto:([^@\s!,;]+@[a-z0-9.-]+)/i.exec(part.trim());
        if (m) out.add(m[1].toLowerCase());
    }
    return out;
}
// Two sorted name-server lists: 'exact' when the same set (leaving out shared providers' servers and per-customer
// pool names), 'pool' when they share a provider's per-customer pool (a hint only), else null.
function sameOperatorNs(a, b) {
    if (!a.length || !b.length) return null;
    const pool = (h) => { for (let i = 0; i < NS_CUSTOMER_POOL.length; i++) { const m = NS_CUSTOMER_POOL[i].exec(h); if (m) return `${i}:${m[1]}`; } return ''; };
    const A = a.filter(h => !NS_SHARED.test(h) && !pool(h)), B = b.filter(h => !NS_SHARED.test(h) && !pool(h));
    if (A.length && A.length === B.length && A.every((h, i) => h === B[i])) return { kind: 'exact', host: A[0] };
    const poolsB = new Set(b.map(pool).filter(Boolean));
    const shared = a.find(h => pool(h) && poolsB.has(pool(h)));
    return shared ? { kind: 'pool', host: shared } : null;
}
// (0.6.46) A name server both domains use, under a third domain named after the company (its name, a token of it, or the
// first word of either domain: ns1.jpmorganchase.com for chase.com and jpmorgan.com), not a provider's: '' if none.
function ownNameServer(a, b, reg, home, brand) {
    const regOf = (h) => h.split('.').slice(-2).join('.');
    const words = [brand.name, ...(brand.tokens || []), reg.split('.')[0], home.split('.')[0]].map(w => String(w).toLowerCase().replace(/[^a-z0-9]/g, '')).filter(w => w.length >= 3);
    const B = new Set(b);
    return a.find(h => {
        if (!B.has(h) || NS_SHARED.test(h) || NS_CUSTOMER_POOL.some(re => re.test(h))) return false;
        const d = regOf(h);
        if (d === reg || d === home) return false;
        const label = d.split('.')[0].replace(/[^a-z0-9]/g, '');
        return words.some(w => label.includes(w));
    }) || '';
}
// Whether an RDAP registrant names the brand (its name or tokens, not its ambiguous ones), as whole words.
function registrantNamesBrand(E, registrant, brand) {
    const text = E.foldName(registrant).replace(/[^a-z0-9& ]+/g, ' ').replace(/\s+/g, ' ').trim();
    if (!text) return false;
    const words = new Set(text.split(' '));
    const ambiguous = new Set(brand.ambiguousTokens || []);
    const names = [brand.name.toLowerCase(), ...(brand.tokens || [])].filter(n => !ambiguous.has(n));
    return names.some(n => (n.includes(' ') ? ` ${text} `.includes(` ${n} `) : words.has(n)));
}
// The organization (or name) of the first entity with this role in an RDAP answer, nested ones included;
// '' when none or redacted.
function rdapWho(data, role) {
    const all = [];
    (function walk(list) { for (const e of Array.isArray(list) ? list : []) { if (e && typeof e === 'object') { all.push(e); walk(e.entities); } } })(data && data.entities);
    for (const e of all) {
        if (!(Array.isArray(e.roles) && e.roles.includes(role)) || !Array.isArray(e.vcardArray)) continue;
        const props = Array.isArray(e.vcardArray[1]) ? e.vcardArray[1] : [];
        const get = (k) => { const p = props.find(x => Array.isArray(x) && x[0] === k && typeof x[3] === 'string' && x[3].trim()); return p ? p[3].trim().slice(0, 120) : ''; };
        const v = get('org') || get('fn');
        if (v && !REDACTED.test(v)) return v;
    }
    return '';
}
// The registrar's own RDAP address for the domain (not the registry's), where a thin registry leaves the
// registrant out.
function registrarLink(data, base) {
    const pick = (links) => { for (const l of Array.isArray(links) ? links : []) { const h = String((l && l.href) || ''); if (/^https:\/\//i.test(h) && /\/domain\//i.test(h) && !h.startsWith(base)) return h; } return ''; };
    if (pick(data && data.links)) return pick(data.links);
    for (const e of (data && data.entities) || []) if (Array.isArray(e.roles) && e.roles.includes('registrar') && pick(e.links)) return pick(e.links);
    return '';
}

// http: src/intel/http.js; rdapServer(tld): the registry's RDAP base (src/intel/rdap.js).
function createOwnership({ http, store, engine: E, rdapServer, now = () => Date.now() }) {
    const memo = new TtlCache(5000);
    const flights = new Map();
    const settle = async (f) => { try { return await f(); } catch (e) { return null; } };
    async function dns(name, type) {
        const res = await http.request(`${DOH}?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: 'application/dns-json' } }, WAIT_MS);
        if (!res.ok) throw new Error(`DNS: HTTP ${res.status}`);
        return (await res.json()).Answer || [];
    }
    const txt = async (name) => (await dns(name, 'TXT')).filter(r => r.type === 16).map(r => String(r.data || '').replace(/^"|"$/g, '').replace(/"\s*"/g, ''));
    const dmarcTags = async (d) => (await txt(`_dmarc.${d}`)).map(recordTags).find(t => /^dmarc1$/i.test(t.v || '')) || null;
    const nameServers = async (d) => (await dns(d, 'NS')).filter(r => r.type === 2).map(r => String(r.data || '').toLowerCase().replace(/\.$/, '')).filter(Boolean).sort();
    // RFC 7489's authorization: <domain>._report._dmarc.<home> has a DMARC1 record, and a random name there
    // doesn't (a wildcard vouches for anyone).
    async function authorized(domain, home) {
        const has = async (name) => (await txt(name)).some(t => /^\s*v\s*=\s*dmarc1\b/i.test(t));
        if (!await has(`${domain}._report._dmarc.${home}`)) return false;
        return !await has(`probe-${Math.random().toString(36).slice(2, 10)}._report._dmarc.${home}`);
    }
    async function registration(reg) {
        const base = await rdapServer(reg.split('.').pop());
        if (!base) return {};
        const res = await http.request(`${base}domain/${encodeURIComponent(reg)}`, { headers: { accept: 'application/rdap+json' } }, WAIT_MS);
        if (!res.ok) return {};
        const data = await res.json();
        const ev = (data.events || []).find(e => e && e.eventAction === 'registration' && e.eventDate);
        const out = { created: ev ? Date.parse(ev.eventDate) || null : null, registrar: rdapWho(data, 'registrar'), registrant: rdapWho(data, 'registrant') };
        const more = !out.registrant ? registrarLink(data, base) : '';
        if (more) {
            const r2 = await settle(() => http.request(more, { headers: { accept: 'application/rdap+json' } }, WAIT_MS));
            if (r2 && r2.ok) { const d2 = await settle(() => r2.json()); if (d2) { out.registrant = rdapWho(d2, 'registrant'); out.registrar = out.registrar || rdapWho(d2, 'registrar'); } }
        }
        return out;
    }

    async function lookup(reg, brand) {
        const proof = [], hints = [];
        // (0.6.46) Requests with no answer, counted: an unknown answer after one is a failure (kept 6 hours, not 7 days).
        let failures = 0;
        const settle = async (f) => { try { return await f(); } catch (e) { failures++; return null; } };
        const homes = (brand.home || brand.domains || []).slice(0, 3).filter(h => h !== reg);
        // 1. DMARC reporting, either way.
        const myTags = await settle(() => dmarcTags(reg));
        const mine = reportDomains(myTags, E.registrableDomain), myBoxes = reportMailboxes(myTags);
        let sameBox = '';
        for (const home of homes) {
            const homeTags = await settle(() => dmarcTags(home));
            if (reportDomains(homeTags, E.registrableDomain).has(reg)) { proof.push(`${home} sends its own DMARC reports to it`); break; }
            // (0.6.45) Both send their reports to the very same mailbox at a report service (brand@rua.reports.example):
            // one company's account there. Anyone could copy that address into their own record, so it counts only
            // with a corporate registrar (below), which a forger can't use, and only an account's own mailbox (accountMailbox):
            // a report service's address every customer shares says nothing.
            if (!sameBox) { const box = [...reportMailboxes(homeTags)].find(x => myBoxes.has(x) && accountMailbox(x, brand)); if (box) sameBox = `its DMARC reports go to the same mailbox as ${home}'s (${box})`; }
            if (mine.has(home)) {
                if (await settle(() => authorized(reg, home))) proof.push(`its DMARC reports go to ${home}, which publishes the authorization for them`);
                else hints.push(`its DMARC reports go to ${home}`);
                break;
            }
        }
        // 2. Name servers.
        if (!proof.length) {
            const ns = (await settle(() => nameServers(reg))) || [];
            let poolHint = '';
            for (const home of homes) {
                const under = ns.find(h => h === home || h.endsWith(`.${home}`));
                if (under) { proof.push(`its name servers are ${brand.name}'s (${under})`); break; }
                const homeNs = ns.length ? (await settle(() => nameServers(home))) || [] : [];
                const same = ns.length ? sameOperatorNs(ns, homeNs) : null;
                if (same && same.kind === 'exact') { proof.push(`it uses the same name servers as ${home} (${same.host})`); break; }
                // (0.6.46) Both served by name servers under a third domain named after the company (ns1.jpmorganchase.com
                // for chase.com and jpmorgan.com): the company's own DNS, which a forger's domain can't be served from.
                const own = ownNameServer(ns, homeNs, reg, home, brand);
                if (own) { proof.push(`it and ${home} are both served by ${E.registrableDomain(own) || own}'s own name servers (${own})`); break; }
                if (same && !poolHint) poolHint = `its DNS provider assigned it the same name servers as ${home} (${same.host})`;
            }
            if (!proof.length && poolHint) hints.push(poolHint);
        }
        // 3. The registry and the registrar.
        const info = (await settle(() => registration(reg))) || {};
        const corporate = !!info.registrar && CORPORATE_REGISTRARS.test(info.registrar);
        const named = !!info.registrant && registrantNamesBrand(E, info.registrant, brand);
        if (corporate && named) proof.push(`registered to ${info.registrant} through ${info.registrar}`);
        else if (corporate && sameBox) proof.push(`${sameBox}, and it is registered through ${info.registrar}, a corporate registrar`);
        else {
            if (sameBox) hints.push(sameBox);
            if (named) hints.push(`registered to ${info.registrant}`);
            if (corporate) hints.push(`registered through ${info.registrar}, a corporate registrar`);
        }
        const age = info.created ? Math.floor((now() - info.created) / 86400000) : null;
        if (age !== null && age >= 365) hints.push(`registered ${Math.floor(age / 365)} year${age >= 730 ? 's' : ''} ago`);
        const state = proof.length ? 'owned' : corporate && hints.length >= 2 ? 'likely' : 'unknown';
        return Object.assign({ state, how: state === 'owned' ? proof.join('; ') : state === 'likely' ? hints.join('; ') : '' }, state === 'unknown' && failures ? { failed: true } : {});
    }

    // A domain's answer: this instance's memory, else the shared store (an old proof refreshed in the background), else
    // asked now (one lookup at a time per domain and brand).
    // refresh: an old proof asked again; a refresh that finds less (nothing, or a failure) doesn't replace it: the proof
    // stays until its 60 days end, then the domain is asked afresh.
    function ask(key, reg, brand, { refresh = false } = {}) {
        if (!flights.has(key)) {
            flights.set(key, (async () => {
                const v = await lookup(reg, brand).catch(() => ({ state: 'unknown', how: '', failed: true }));
                if (refresh && v.state === 'unknown') return v;
                await store.setCached('own', key, Object.assign({ at: now() }, v), keepFor(v)).catch(() => {});
                memo.set(key, v, Math.min(MEMO_MS, keepFor(v)));
                return v;
            })().finally(() => flights.delete(key)));
        }
        return flights.get(key);
    }
    async function answer(key, reg, brand) {
        const stored = await store.getCached('own', key).catch(() => null);
        if (stored && stored.state) {
            const { at, ...v } = stored;
            if (v.state !== 'unknown' && now() - (Number(at) || 0) > REFRESH_MS) ask(key, reg, brand, { refresh: true }).catch(() => {});
            memo.set(key, v, MEMO_MS);
            return v;
        }
        return ask(key, reg, brand);
    }
    // { state: 'owned' | 'likely' | 'unknown', how } for a domain and the brand a sender's name claims.
    async function of(domain, brandName) {
        const brand = (E.SENDER_NAME_BRANDS || []).find(b => b.name === brandName);
        const reg = E.registrableDomain(String(domain || '').toLowerCase());
        if (!brand || !reg || !E.SENDER_DOMAIN_RE.test(reg) || E.isPersonalMailDomain(reg)) return { state: 'unknown', how: '' };
        const key = `${reg}|${brand.name}`;
        const mem = memo.get(key);
        if (mem) return mem;
        return answer(key, reg, brand);
    }
    // (0.6.17) The same proof for a company that isn't in the brand table: a link's own domain, named after the
    // company (email-lakeviewhotels.example: "lakeviewhotels"), against that company's name and main site(s). { state, how }.
    async function ofCompany(domain, name, homes = []) {
        const reg = E.registrableDomain(String(domain || '').toLowerCase());
        const token = String(name || '').toLowerCase();
        if (!reg || !/^[a-z0-9]{4,}$/.test(token) || !E.SENDER_DOMAIN_RE.test(reg) || E.isPersonalMailDomain(reg)) return { state: 'unknown', how: '' };
        const brand = { name: token, tokens: [token], home: [...new Set(homes.map(h => E.registrableDomain(String(h).toLowerCase())).filter(Boolean))].slice(0, 3) };
        const key = `${reg}|company:${token}`;
        const mem = memo.get(key);
        if (mem) return mem;
        return answer(key, reg, brand);
    }
    return { of, ofCompany };
}

module.exports = { createOwnership, sameOperatorNs, registrantNamesBrand, reportMailboxes, accountMailbox, ownNameServer, CORPORATE_REGISTRARS };
