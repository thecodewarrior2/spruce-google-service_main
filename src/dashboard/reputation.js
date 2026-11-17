'use strict';
// (0.6.1) Health → DMARC & reputation: whether your own domains (ORG_DOMAINS) are on a blocklist, and what the
// phishing lists the service downloads say about them.
//   - Cloudflare Security DNS: whether it blocks the domain as malware or phishing (CLOUDFLARE_THREATS);
//   - Google Safe Browsing: the domain's home page (https:// and http://), with the service's key (Settings → Safe
//     Browsing; off: not checked);
//   - Spamhaus DBL, the Domain Blocklist, and ZRD (a brand-new domain), with the service's DQS key (Settings →
//     Spamhaus; off: not checked). 2 lookups a domain, counted against the day's Spamhaus limit;
//   - the downloaded phishing lists (Settings → About): every entry for the domain or any name under it (a link
//     on a school site that was hacked, a listed sender address), read from the lists' stored copies.
// The lookups are the service's own (src/intel: threats, spamhaus); nothing here changes how an email is judged.
// Kept 10 minutes; Check again reads them now. A lookup that fails is "not checked", never "clean".
const zlib = require('zlib');

const KEEP_MS = 10 * 60 * 1000;
const SHOWN = 5;   // entries shown a list; the count says how many in all

// The host of a list's line: a link (https://host/path) or a bare host or address.
function hostOfEntry(line) {
    const m = /^[a-z][a-z0-9+.-]*:\/\/([^/:?#@]+)/i.exec(line);
    return (m ? m[1] : String(line).split('/')[0]).toLowerCase().replace(/\.$/, '');
}
const under = (host, domain) => host === domain || host.endsWith(`.${domain}`);

// One pass over each downloaded list, for every domain at once: { domain: [{ list, kind, count, entries }] }.
async function scanLists({ feeds, store, domains }) {
    const out = Object.fromEntries(domains.map(d => [d, []]));
    if (!feeds || !store) return { out, checked: false, lists: 0 };
    let lists = 0;
    for (const f of await feeds.status()) {
        if (f.off || !f.updated) continue;
        const b = await store.getBlob(`feed_${f.id}`).catch(() => null);
        if (!b) continue;
        lists++;
        const hits = Object.fromEntries(domains.map(d => [d, []]));
        for (const line of zlib.gunzipSync(b.bytes).toString('utf8').split('\n')) {
            if (!line) continue;
            const host = f.kind === 'address' ? line.toLowerCase().split('@').pop() : hostOfEntry(line);
            for (const d of domains) if (under(host, d)) hits[d].push(line);
        }
        for (const d of domains) if (hits[d].length) out[d].push({ list: f.name, kind: f.kind, count: hits[d].length, entries: hits[d].slice(0, SHOWN) });
    }
    return { out, checked: true, lists };
}

// Made-up answers for demo mode (no network): one subdomain listed, to show what a listing looks like.
function demoAnswer(domain) {
    return { domain, services: [
        { name: 'Cloudflare Security DNS', state: 'clean', detail: 'Not blocked as malware or phishing.' },
        { name: 'Google Safe Browsing', state: 'off', detail: 'Not checked: Safe Browsing is off (Settings → Safe Browsing).' },
        { name: 'Spamhaus DBL', state: 'off', detail: 'Not checked: Spamhaus is off (Settings → Spamhaus).' }],
    lists: [{ list: 'Phishing Army (demo)', kind: 'domain', count: 1, entries: [`old-portal.${domain}`] }], listsChecked: 1, level: 'bad', checkedAt: Date.now() };
}

// intel: src/intel (threats, spamhaus, feeds); store: for the lists' stored copies.
function createReputation({ cfg, intel, store, demo = false, now = () => Date.now() }) {
    let kept = null;
    async function services(d) {
        const out = [];
        const threats = intel && intel.threats;
        // Cloudflare Security DNS
        if (!threats || !cfg.cloudflareThreats) out.push({ name: 'Cloudflare Security DNS', state: 'off', detail: 'Not checked: the DNS threat checks are off (CLOUDFLARE_THREATS).' });
        else {
            const r = (await threats.checkHosts([d]).catch(() => new Map())).get(d);
            out.push(!r || r.verdict === 'unknown' ? { name: 'Cloudflare Security DNS', state: 'unknown', detail: `Not checked${r && r.reason ? ` (${r.reason})` : ''}.` }
                : r.verdict === 'unsafe' ? { name: 'Cloudflare Security DNS', state: 'listed', detail: 'Blocked as malware or phishing: people using Cloudflare\'s security resolver can\'t reach it.' }
                : { name: 'Cloudflare Security DNS', state: 'clean', detail: 'Not blocked as malware or phishing.' });
        }
        // Google Safe Browsing: the home page
        if (!threats || !threats.enabled || !threats.enabled.safeBrowsing) out.push({ name: 'Google Safe Browsing', state: 'off', detail: 'Not checked: Safe Browsing is off (Settings → Safe Browsing).' });
        else {
            const urls = [`https://${d}/`, `http://${d}/`];
            const m = await threats.checkUrls(urls.map(url => ({ url, text: '' }))).catch(() => new Map());
            const rs = urls.map(u => m.get(u)).filter(Boolean);
            const bad = rs.find(r => r.verdict === 'unsafe');
            out.push(bad ? { name: 'Google Safe Browsing', state: 'listed', detail: `${bad.reason || 'Listed'}: Chrome and Gmail warn people who open it.` }
                : rs.length && rs.every(r => r.verdict === 'clean') ? { name: 'Google Safe Browsing', state: 'clean', detail: 'Its home page isn\'t listed.' }
                : { name: 'Google Safe Browsing', state: 'unknown', detail: `Not checked${rs[0] && rs[0].reason ? ` (${rs[0].reason})` : ''}.` });
        }
        // Spamhaus DBL and ZRD
        const sh = intel && intel.spamhaus;
        if (!sh || !cfg.spamhaus) out.push({ name: 'Spamhaus DBL', state: 'off', detail: 'Not checked: Spamhaus is off (Settings → Spamhaus).' });
        else {
            const r = (await sh.checkDomains([d]).catch(() => new Map())).get(d);
            out.push(!r ? { name: 'Spamhaus DBL', state: 'unknown', detail: 'Not checked (no key saved, the day\'s limit reached, or Spamhaus couldn\'t be reached: Settings → Spamhaus).' }
                : r.dbl ? { name: 'Spamhaus DBL', state: 'listed', detail: `On the Domain Blocklist as ${r.dbl.list || 'listed'}. Many mail servers refuse or flag mail that links to it.` }
                : { name: 'Spamhaus DBL', state: 'clean', detail: `Not on the Domain Blocklist${r.zrdHours !== null && r.zrdHours !== undefined ? `; Spamhaus first saw it ${r.zrdHours} hours ago (Zero Reputation Domains)` : ''}.` });
        }
        return out;
    }
    return async function check(domains, { fresh = false } = {}) {
        if (!fresh && kept && now() - kept.at < KEEP_MS) return kept.list;
        if (demo) return (kept = { at: now(), list: domains.map(demoAnswer) }).list;
        const scan = await scanLists({ feeds: intel && intel.feeds, store, domains }).catch(e => ({ out: Object.fromEntries(domains.map(d => [d, []])), checked: false, error: String(e.message || e) }));
        const list = await Promise.all(domains.map(async (d) => {
            const sv = await services(d);
            const lists = scan.out[d] || [];
            // (clean only when something was checked: every service off and no list downloaded is "partly checked")
            const anyChecked = sv.some(s => s.state === 'clean') || (scan.checked && scan.lists > 0);
            const level = sv.some(s => s.state === 'listed') || lists.length ? 'bad' : sv.some(s => s.state === 'unknown') || !scan.checked || !anyChecked ? 'warn' : 'good';
            return { domain: d, services: sv, lists, listsChecked: scan.checked ? scan.lists : 0, listsError: scan.error || null, level, checkedAt: now() };
        }));
        kept = { at: now(), list };
        return list;
    };
}

module.exports = { createReputation, scanLists, hostOfEntry };
