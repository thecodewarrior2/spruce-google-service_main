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
//     • a corporate brand-protection registrar (MarkMonitor, CSC…) and a registrant naming the brand.
//   likely — a corporate registrar plus one more link to the brand (reports sent to it, a registrant naming
//     it, or a year or more of age): a caution, never moved.
//   unknown — anything less: judged as before.
// What is sent: domain names only, to Cloudflare's public resolver (DNS over HTTPS) and to the domain's
// registry and registrar (RDAP). Answers are kept in the shared store for 30 days (unknown: a day).
const { TtlCache } = require('./http');

const DOH = 'https://cloudflare-dns.com/dns-query';
const KEEP_MS = 30 * 24 * 60 * 60 * 1000, UNKNOWN_KEEP_MS = 24 * 60 * 60 * 1000;
const MEMO_MS = 6 * 60 * 60 * 1000;
const WAIT_MS = 4000;          // each lookup; the whole answer is awaited at most TOTAL_MS (analyze.js)
const CORPORATE_REGISTRARS = /markmonitor|csc corporate domains|corporation service company|com laude|nom-iq|safenames|godaddy corporate domains|brandsight|lexsynergy|nameshield|ip twins|registrarsafe|abion\b|appdetex|safebrands/i;
const NS_CUSTOMER_POOL = [/^dns\d+\.(p\d+)\.nsone\.net$/, /^ns\d+\.(p\d+)\.dynect\.net$/, /^([a-z]+)\.ns\.cloudflare\.com$/];
const NS_SHARED = /(^|\.)(ultradns\.(com|net|org|biz|info|co\.uk)|googledomains\.com|azure-dns\.(com|net|org|info)|domaincontrol\.com|registrar-servers\.com|he\.net|wixdns\.net|squarespacedns\.com|name-services\.com|worldnic\.com|ui-dns\.(com|de|org|biz)|ionos\.(com|de)|hostgator\.com|bluehost\.com|dreamhost\.com|siteground\.net|ovh\.net|cloudns\.net|dnsmadeeasy\.com)$/i;
const REDACTED = /redacted|privacy|protected|withheld|not disclosed|gdpr|data protected|statutory masking/i;

const recordTags = (txt) => Object.fromEntries(String(txt || '').split(';').map(p => p.trim()).filter(Boolean).map(p => { const i = p.indexOf('='); return i < 0 ? [p.toLowerCase(), ''] : [p.slice(0, i).trim().toLowerCase(), p.slice(i + 1).trim()]; }));
function reportDomains(tags, registrable) {
    const out = new Set();
    if (tags) for (const k of ['rua', 'ruf']) for (const part of String(tags[k] || '').split(',')) {
        const m = /mailto:[^@\s!,;]+@([a-z0-9.-]+)/i.exec(part.trim());
        if (m) { const d = registrable(m[1].toLowerCase()); if (d) out.add(d); }
    }
    return out;
}
function sameOperatorNs(a, b) {
    if (!a.length || !b.length) return null;
    const pool = (h) => { for (let i = 0; i < NS_CUSTOMER_POOL.length; i++) { const m = NS_CUSTOMER_POOL[i].exec(h); if (m) return `${i}:${m[1]}`; } return ''; };
    const A = a.filter(h => !NS_SHARED.test(h) && !pool(h)), B = b.filter(h => !NS_SHARED.test(h) && !pool(h));
    if (A.length && A.length === B.length && A.every((h, i) => h === B[i])) return { kind: 'exact', host: A[0] };
    const poolsB = new Set(b.map(pool).filter(Boolean));
    const shared = a.find(h => pool(h) && poolsB.has(pool(h)));
    return shared ? { kind: 'pool', host: shared } : null;
}
function registrantNamesBrand(E, registrant, brand) {
    const text = E.foldName(registrant).replace(/[^a-z0-9& ]+/g, ' ').replace(/\s+/g, ' ').trim();
    if (!text) return false;
    const words = new Set(text.split(' '));
    const ambiguous = new Set(brand.ambiguousTokens || []);
    const names = [brand.name.toLowerCase(), ...(brand.tokens || [])].filter(n => !ambiguous.has(n));
    return names.some(n => (n.includes(' ') ? ` ${text} `.includes(` ${n} `) : words.has(n)));
}
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
        const homes = (brand.home || brand.domains || []).slice(0, 3).filter(h => h !== reg);
        // 1. DMARC reporting, either way.
        const mine = reportDomains(await settle(() => dmarcTags(reg)), E.registrableDomain);
        for (const home of homes) {
            if (reportDomains(await settle(() => dmarcTags(home)), E.registrableDomain).has(reg)) { proof.push(`${home} sends its own DMARC reports to it`); break; }
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
                const same = ns.length ? sameOperatorNs(ns, (await settle(() => nameServers(home))) || []) : null;
                if (same && same.kind === 'exact') { proof.push(`it uses the same name servers as ${home} (${same.host})`); break; }
                if (same && !poolHint) poolHint = `its DNS provider assigned it the same name servers as ${home} (${same.host})`;
            }
            if (!proof.length && poolHint) hints.push(poolHint);
        }
        // 3. The registry and the registrar.
        const info = (await settle(() => registration(reg))) || {};
        const corporate = !!info.registrar && CORPORATE_REGISTRARS.test(info.registrar);
        const named = !!info.registrant && registrantNamesBrand(E, info.registrant, brand);
        if (corporate && named) proof.push(`registered to ${info.registrant} through ${info.registrar}`);
        else {
            if (named) hints.push(`registered to ${info.registrant}`);
            if (corporate) hints.push(`registered through ${info.registrar}, a corporate registrar`);
        }
        const age = info.created ? Math.floor((now() - info.created) / 86400000) : null;
        if (age !== null && age >= 365) hints.push(`registered ${Math.floor(age / 365)} year${age >= 730 ? 's' : ''} ago`);
        const state = proof.length ? 'owned' : corporate && hints.length >= 2 ? 'likely' : 'unknown';
        return { state, how: state === 'owned' ? proof.join('; ') : state === 'likely' ? hints.join('; ') : '' };
    }

    // { state: 'owned' | 'likely' | 'unknown', how } for a domain and the brand a sender's name claims.
    async function of(domain, brandName) {
        const brand = (E.SENDER_NAME_BRANDS || []).find(b => b.name === brandName);
        const reg = E.registrableDomain(String(domain || '').toLowerCase());
        if (!brand || !reg || !E.SENDER_DOMAIN_RE.test(reg) || E.isPersonalMailDomain(reg)) return { state: 'unknown', how: '' };
        const key = `${reg}|${brand.name}`;
        const mem = memo.get(key);
        if (mem) return mem;
        const stored = await store.getCached('own', key).catch(() => null);
        if (stored && stored.state) { memo.set(key, stored, MEMO_MS); return stored; }
        if (!flights.has(key)) {
            flights.set(key, (async () => {
                const v = await lookup(reg, brand).catch(() => ({ state: 'unknown', how: '' }));
                await store.setCached('own', key, v, v.state === 'unknown' ? UNKNOWN_KEEP_MS : KEEP_MS).catch(() => {});
                memo.set(key, v, v.state === 'unknown' ? Math.min(MEMO_MS, UNKNOWN_KEEP_MS) : MEMO_MS);
                return v;
            })().finally(() => flights.delete(key)));
        }
        return flights.get(key);
    }
    return { of };
}

module.exports = { createOwnership, sameOperatorNs, registrantNamesBrand, CORPORATE_REGISTRARS };
