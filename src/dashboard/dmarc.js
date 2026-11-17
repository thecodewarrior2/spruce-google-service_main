'use strict';
// (0.6.1) Health → DMARC & reputation: each of your own domains' (ORG_DOMAINS) DMARC record and SPF record, as published in DNS,
// what they say, and what would make them stronger. Read through Cloudflare's public resolver (DNS over HTTPS), as
// the look-alike watch does: only your domain names are sent. Kept 10 minutes; Check again reads them now.
// Not a judging file: nothing here changes how an email is judged (Gmail's own DMARC result, on each email, does).

const DOH = 'https://cloudflare-dns.com/dns-query';
const KEEP_MS = 10 * 60 * 1000;
const WAIT_MS = 5000;

// A DMARC record's tags (v=DMARC1; p=reject; rua=mailto:…), lower-case names, values as written.
const tagsOf = (txt) => Object.fromEntries(String(txt || '').split(';').map(p => p.trim()).filter(Boolean)
    .map(p => { const i = p.indexOf('='); return i < 0 ? [p.toLowerCase(), ''] : [p.slice(0, i).trim().toLowerCase(), p.slice(i + 1).trim()]; }));
const isDmarc = (t) => /^\s*v\s*=\s*dmarc1\s*(;|$)/i.test(t);
const isSpf = (t) => /^\s*v=spf1(\s|$)/i.test(t);
// The parent domains a subdomain's DMARC can fall back to (receivers use its organizational domain), nearest first,
// down to two labels: students.maple-schools.example → maple-schools.example.
function parentsOf(domain) {
    const l = domain.split('.'), out = [];
    for (let i = 1; l.length - i >= 2 && out.length < 3; i++) out.push(l.slice(i).join('.'));
    return out;
}

// How strong a DMARC record is: { level: 'good' | 'warn' | 'bad', words, notes: [what to improve] }.
function gradeDmarc(records, inherited) {
    if (!records.length) return { level: 'bad', words: inherited ? `No record of its own: ${inherited.domain}'s applies (p=${inherited.tags.sp || inherited.tags.p || '?'})` : 'No DMARC record', notes: [
        inherited ? `It is covered by ${inherited.domain}'s record. Publish one of its own to set its policy directly.` : 'Anyone can send mail that claims to come from this domain, and receivers have no policy to apply. Publish a TXT record at _dmarc. Start with p=none and a rua address, then move to quarantine and reject.'] };
    if (records.length > 1) return { level: 'bad', words: 'More than one DMARC record', notes: ['Receivers ignore DMARC when there is more than one record: keep exactly one TXT record starting v=DMARC1 at _dmarc.'] };
    const t = tagsOf(records[0]), p = String(t.p || '').toLowerCase(), sp = String(t.sp || '').toLowerCase();
    const pct = t.pct === undefined ? 100 : Number(t.pct);
    const notes = [];
    if (!['none', 'quarantine', 'reject'].includes(p)) return { level: 'bad', words: 'The record has no valid policy (p=)', notes: ['A DMARC record needs p=none, p=quarantine or p=reject right after v=DMARC1.'] };
    if (p === 'none') notes.push('p=none only reports: mail that fails DMARC is still delivered. When the reports show your own senders pass, move to p=quarantine, then p=reject.');
    if (p === 'quarantine') notes.push('p=quarantine sends failing mail to spam. p=reject, when your reports show your own senders all pass, refuses it outright.');
    if (pct < 100 && p !== 'none') notes.push(`pct=${t.pct}: the policy applies to only ${t.pct}% of failing mail. Raise it to 100.`);
    if (sp && sp === 'none' && p !== 'none') notes.push('sp=none: subdomains are only reported on, though the domain itself is protected. Remove sp= or set it as strong as p=.');
    if (!t.rua) notes.push('No rua= address: nobody receives the aggregate reports that show who sends mail as this domain.');
    const level = p === 'reject' && pct >= 100 && sp !== 'none' ? 'good' : p === 'none' ? 'warn' : pct < 100 || sp === 'none' ? 'warn' : 'good';
    const words = p === 'reject' ? 'Reject: failing mail is refused' : p === 'quarantine' ? 'Quarantine: failing mail goes to spam' : 'None: monitoring only';
    return { level, words: pct < 100 && p !== 'none' ? `${words} (${t.pct}% of it)` : words, notes };
}
function gradeSpf(records) {
    if (!records.length) return { level: 'warn', words: 'No SPF record', notes: ['Publish an SPF record (v=spf1 … -all or ~all) naming the servers that send your mail: DMARC passes on SPF or DKIM.'] };
    if (records.length > 1) return { level: 'bad', words: 'More than one SPF record', notes: ['Receivers treat more than one SPF record as an error: merge them into one.'] };
    const r = records[0], all = (/\s([~?+-]?)all\s*$/i.exec(r) || [])[1];
    if (all === undefined) return { level: 'warn', words: 'No "all" at the end', notes: ['End the record with -all (or ~all) so other servers are not treated as allowed.'] };
    if (all === '+' || all === '') return { level: 'bad', words: '+all: every server is allowed', notes: ['+all lets anyone send as this domain. Use -all or ~all.'] };
    if (all === '?') return { level: 'warn', words: '?all: neutral', notes: ['?all says nothing about other servers. Use ~all or -all.'] };
    return { level: 'good', words: all === '-' ? '-all: other servers fail' : '~all: other servers soft-fail', notes: [] };
}

// Made-up records for demo mode (no network): one strong domain, one to improve.
const DEMO = {
    '_dmarc.maple-schools.example': ['v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@maple-schools.example; adkim=r; aspf=r'],
    'maple-schools.example': ['v=spf1 include:_spf.google.com ~all', 'google-site-verification=demo-not-a-real-token'],
    '_dmarc.students.maple-schools.example': ['v=DMARC1; p=none'],
    'students.maple-schools.example': ['v=spf1 include:_spf.google.com ?all']
};

// http: src/intel/http.js (or null in demo mode).
function createDmarcCheck({ http, demo = false, now = () => Date.now() }) {
    const kept = new Map();
    async function txt(name) {
        if (demo) return { found: Object.prototype.hasOwnProperty.call(DEMO, name), records: DEMO[name] || [] };
        if (!http) throw new Error('no way to reach DNS here');
        const res = await http.request(`${DOH}?name=${encodeURIComponent(name)}&type=TXT`, { headers: { accept: 'application/dns-json' } }, WAIT_MS);
        if (!res.ok) throw new Error(`DNS: HTTP ${res.status}`);
        const j = await res.json();
        if (j.Status !== 0 && j.Status !== 3) throw new Error(`DNS answered status ${j.Status}`);
        // A long TXT record comes as several quoted strings: joined, as receivers read it.
        return { found: j.Status === 0, records: (j.Answer || []).filter(r => r.type === 16).map(r => String(r.data || '').replace(/^"|"$/g, '').replace(/"\s*"/g, '')) };
    }
    // One domain's records and grades; its parents' DMARC record when it has none of its own. A failed lookup
    // is an error (shown, and not kept).
    async function one(domain) {
        const d = String(domain).toLowerCase();
        try {
            const [dm, root] = await Promise.all([txt(`_dmarc.${d}`), txt(d)]);
            const dmarc = dm.records.filter(isDmarc), spf = root.records.filter(isSpf);
            let inherited = null;
            for (const parent of dmarc.length ? [] : parentsOf(d)) {
                const pr = (await txt(`_dmarc.${parent}`)).records.filter(isDmarc);
                if (pr.length === 1) { inherited = { domain: parent, record: pr[0], tags: tagsOf(pr[0]) }; break; }
            }
            return { domain: d, dmarc: Object.assign({ records: dmarc, tags: dmarc.length === 1 ? tagsOf(dmarc[0]) : null, inherited }, gradeDmarc(dmarc, inherited)),
                spf: Object.assign({ records: spf }, gradeSpf(spf)), checkedAt: now() };
        } catch (e) {
            return { domain: d, error: String(e.message || e).slice(0, 200), checkedAt: now() };
        }
    }
    return async function check(domains, { fresh = false } = {}) {
        return Promise.all(domains.map(async (d) => {
            const hit = kept.get(d);
            if (!fresh && hit && now() - hit.checkedAt < KEEP_MS) return hit;
            const out = await one(d);
            if (!out.error) kept.set(d, out);
            return out;
        }));
    };
}

module.exports = { createDmarcCheck, gradeDmarc, gradeSpf, tagsOf, parentsOf };
