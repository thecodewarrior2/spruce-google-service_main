'use strict';
// The service's work, step by step:
//   1. Gmail tells Pub/Sub a mailbox changed ({ emailAddress, historyId }); Pub/Sub pushes it here.
//   2. The messages added to its Inbox since the last change are fetched (raw, as received).
//   3. Each is read (engine/mime) and judged (engine/analyze) like the extension judges an opened
//      email, and the policy (policy.js) decides: move to Spam, record only, or nothing.
//   4. The decision is carried out and recorded for the dashboard (nothing of the email's text is kept:
//      sender, subject and the checks' findings only; see docs/PRIVACY.md).
// Every step is safe to repeat: a message already analyzed is skipped, so a repeated notification does
// nothing twice. One instance at a time judges a message (it claims it first). A message whose check
// failed is tried again (MAX_TRIES in all) when Pub/Sub delivers the notification again: until every
// listed message is done, the mailbox's sync position stays where it was, and it only ever moves forward.
const crypto = require('crypto');
const { readMessage } = require('./engine/mime');
const { analyze, aiReading, senderVerified, platformNotification, shareSource } = require('./engine/analyze');
const { MASS_SHARE } = require('./engine/notifications');
const { decide, isAllowed } = require('./policy');
const { GoogleApiError } = require('./gmail/client');
const { compareHistoryIds, movesForward } = require('./store/history');
const { buildDigest, mime, isSummary, localParts } = require('./digest');
const A = require('./dashboard/aggregate');
const { looksLikeReply } = require('./engine/replychain');
const training = require('./training');
const spruce = require('./engine/spruce');
const repos = require('./repos');
const { indexOf: recheckIndex, lookFor, foundWords, eventNames, eventHasMessageId, eventType } = require('./recheck');
const { checksLevel: currentChecksLevel } = require('./checks-level');
const { variantsOf: lookalikeVariants, weightOf: lookalikeWeight, NEW_DAYS: LOOKALIKE_NEW_DAYS } = require('./lookalike');
const sims = require('./simulations');

const DAY = 24 * 60 * 60 * 1000;
// (0.6.26) Spam a person took back out of Spam: that sender's mail isn't moved as spam for them again for SPAM_KEEP_MS;
// when SPAM_SHARED people or more took back the same sender's, for no one (until an admin says to keep moving it).
const SPAM_KEEP_MS = 180 * DAY, SPAM_SHARED = 3, SPAM_RESCUED_MAX = 300;
const HOUR = 60 * 60 * 1000;
const LIST_RETRY_MS = 3 * HOUR;   // a phishing list that missed its download is tried again this often (0.5.22)
const ERRORS_ALERT = 25;   // errors in an hour that make an alert (0.5.29)
// Missed changes that make an alert (0.5.31): in 24 hours, or one mailbox in 7 days. The defaults of
// GAPS_ALERT_DAY and GAPS_ALERT_MAILBOX.
const GAPS_DAY = 10, GAPS_MAILBOX = 3;
const MAX_TRIES = 3;   // tries per message before it is left unchecked (and an alert)
// Re-checking delivered mail (0.5.35): queued emails at most, found per list download at most, checked
// at once, and the hourly run's time for them.
const RECHECK_QUEUE_MAX = 3000, RECHECK_FIND_MAX = 3000, RECHECK_PARALLEL = 12, RECHECK_BUDGET_MS = 40 * 1000;
// How far each action goes: a re-check records an email again only when it now goes further than before.
const RECHECK_RANK = { none: 0, flag: 1, 'would-move': 2, move: 3 };
// After an update that changes the checks (0.5.51): emails queued per hourly run at most (as the queue has room).
const UPDATE_QUEUE_STEP = 1500;
const PROCESS_STARTED = Date.now();   // this instance runs the version it started with: mail after it was judged by it
const PKG_VERSION = require('../package.json').version;
// The look-alike watch (0.5.36): candidates asked per hourly run.
const LOOKALIKE_BATCH = 80;
const WHERE_WORDS = { archived: 'archived by its reader', spam: 'in Spam', trash: 'in the Trash', inbox: 'in the Inbox' };
// How long a claim keeps other instances off a message: longer than a request may run (the worker's
// timeout is 120 s), so only a claim left by an instance that stopped is taken over.
const CLAIM_LEASE_MS = 5 * 60 * 1000;
// How long a notification waits for messages another instance is judging before it keeps the place.
const WAIT_FOR_OTHERS_MS = 5000;
// How often a mailbox's "last notification" time is written when its history position doesn't move (it
// is written with the position otherwise): Health → Service status and the quiet-mailbox alert (QUIET_HOURS,
// 12 by default) need no more.
const NOTED_EVERY_MS = 10 * 60 * 1000;
// How long a mailbox's sync position may wait when its notifications bring nothing new (handleNotification).
const QUIET_POSITION_MS = 30 * 60 * 1000;
// Senders remembered per instance (about 100 bytes each).
const SENDERS_KEPT = 100000;
// How often the worker writes the day's counters it added up (src/server.js; see Service.count).
const STAT_FLUSH_MS = 5000;
// The daily renewal of the watches (Gmail stops notifying for a mailbox whose watch isn't renewed for 7
// days): RENEW_PARALLEL at a time (users.watch costs 100 quota units: about 400,000 a minute, a third of the
// project's 1,200,000), within RENEW_BUDGET_MS so the run ends before the worker's 120-second timeout,
// new mailboxes and the watches renewed longest ago first. Those left are continued by the hourly job
// (syncFeeds, 0.5.53). One renewed less than RENEW_FRESH_MS ago waits; WATCH_MS is how long a watch lasts.
const RENEW_PARALLEL = 10, RENEW_BUDGET_MS = 95 * 1000, RENEW_FRESH_MS = 12 * 60 * 60 * 1000, WATCH_MS = 7 * 24 * 60 * 60 * 1000;
// A day in UTC, kept for callers outside the service. The daily counters' key is the day in the
// organization's time zone (this.dayOf, 0.5.27).
const dayOf = (ms) => new Date(ms).toISOString().slice(0, 10);
const hourOf = (ms) => new Date(ms).toISOString().slice(0, 13);
// The Message-ID header without its angle brackets: what Google Workspace's Email log search and the
// security investigation tool look an email up by.
const messageIdOf = (v) => String(v || '').trim().replace(/^<|>$/g, '').slice(0, 300);
// The address in a From header ("Name <a@b>" or "a@b").
const addressOf = (from) => { const m = /<([^<>@\s]+@[^<>\s]+)>/.exec(String(from || '')); return (m ? m[1] : String(from || '').trim()).toLowerCase(); };
// The AI's answer as a record keeps it: the score, the model, the sentences that weighed most (unless
// STORE_AI_QUOTES=off), and why there is no score (an email in a language the model doesn't read).
function aiRecord(ai, cfg) {
    if (!ai) return null;
    const out = { probability: ai.probability, model: ai.model,
        reasons: cfg.storeAiQuotes ? (ai.reasons || []).map(r => ({ sentence: String(r.sentence).slice(0, 160), facts: !!r.facts })) : [] };
    if (ai.skipped) { out.skipped = ai.skipped; out.language = ai.language || null; }
    return out;
}

// At most n at once; the others wait their turn, first come first served.
class Slots {
    constructor(n) { this.free = n; this.waiting = []; }
    async run(fn) {
        if (this.free > 0) this.free--; else await new Promise(r => this.waiting.push(r));
        try { return await fn(); } finally { const next = this.waiting.shift(); if (next) next(); else this.free++; }
    }
}
// Emails downloaded and checked at once per instance (the worker takes 32 requests at once, most of them
// notifications with nothing new), and of those, how many over LARGE_BYTES (attachments): 12 downloads
// of the largest Gmail sends plus 2 being read fit in the worker's 1 GiB.
const EMAIL_SLOTS = 12, LARGE_SLOTS = 2, LARGE_BYTES = 4 * 1024 * 1024;
// (0.6.6) Re-scans (an admin's button: each reads the email from Gmail and runs every check and the AI again):
// RESCAN_SLOTS at once per instance, at most RESCAN_QUEUE_MAX more waiting, and one email again only
// RESCAN_COOLDOWN_MS after its last re-scan (kept on its record, so every instance knows).
const RESCAN_SLOTS = 2, RESCAN_QUEUE_MAX = 8, RESCAN_COOLDOWN_MS = 30 * 1000;
// (0.6.7) Switching the service off (stopAll): Gmail told STOP_PARALLEL mailboxes at a time, within STOP_BUDGET_MS.
const STOP_PARALLEL = 10, STOP_BUDGET_MS = 80 * 1000;
// Runs fn over items, n at a time, until stop() says so.
async function pool(items, n, fn, stop = () => false) {
    let i = 0;
    const worker = async () => { while (i < items.length && !stop()) { const item = items[i++]; await fn(item); } };
    await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
}
// Sender addresses are remembered as a hash only (as the extension's senderHistoryKey).
const senderHash = (address) => crypto.createHash('sha256').update(String(address || '').toLowerCase()).digest('hex').slice(0, 16);
const recordKey = (user, messageId) => `${user}|${messageId}`;

// Emails of one campaign share a sender domain and a subject once numbers, the recipient's name and
// spacing are taken out ("Invoice 4471 for alex" ~ "Invoice 9920 for sam").
function campaignOf(senderDomain, subject, user) {
    const local = String(user || '').split('@')[0].toLowerCase();
    let s = String(subject || '').toLowerCase().normalize('NFKC');
    // The recipient's mailbox name and its parts ("rowan.mockley", "rowan", "mockley").
    for (const part of [local, ...local.split(/[._-]+/)].filter(p => p.length >= 3)) s = s.split(part).join('');
    s = s.replace(/^(re|fw|fwd)\s*:\s*/g, '').replace(/[0-9]+/g, '#').replace(/[^\p{L}#]+/gu, ' ').trim().slice(0, 120);
    const key = crypto.createHash('sha256').update(`${senderDomain}|${s}`).digest('hex').slice(0, 12);
    return { key, label: `${senderDomain}: ${s || '(no subject)'}`.slice(0, 160) };
}

// What Google refusing Gmail's logs means, and what to do (0.5.39; Settings → Link clicks): { why, fix }.
// "not authorized to read activity records": the admin's role lacks the Reports privilege; a token refused:
// the scope isn't on the domain-wide delegation entry.
function reportsProblem(e, admin) {
    const msg = String((e && e.message) || e || '');
    if (/token for .*(unauthorized_client|access_denied|invalid_grant)|domain-wide delegation set up/i.test(msg)) return {
        why: 'Google didn\'t give the service access to Gmail\'s logs: the scope admin.reports.audit.readonly isn\'t on its domain-wide delegation entry (or the account doesn\'t exist).',
        fix: 'Admin console → Security → Access and data control → API controls → Manage Domain Wide Delegation → the service\'s client ID → Edit: add https://www.googleapis.com/auth/admin.reports.audit.readonly to the line, then Authorize. Test again in a few minutes.' };
    if (/not authorized to read activity records|HTTP 40[13]\b/i.test(msg)) return {
        why: `${admin} isn't allowed to read Google's activity reports: its admin role doesn't have the Reports privilege.`,
        fix: `Admin console → Account → Admin roles → the role ${admin} has (the directory admin's is "SPRUCE group reader") → Privileges → Admin console privileges → tick Reports → Save. Or type a super admin's address instead. Test again in a few minutes (role changes take a little while).` };
    return { why: `Google answered: ${msg.replace(/\s+/g, ' ').slice(0, 200)}`, fix: 'docs/INSTALL.md, "Link clicks".' };
}

// The new entries of the lists' downloads, taken out of feeds.sync's answer (they don't go into the
// hourly job's response or the dashboard's): [{ name, kind, entries }].
function takeAdded(out) {
    const added = [];
    for (const f of (out && out.feeds) || []) {
        if (Array.isArray(f.added)) { if (f.added.length) added.push({ name: f.name, kind: f.kind, entries: f.added }); f.added = f.added.length; }
    }
    return added;
}

// "Watching 3 mailboxes. spruce-pilot@…: 5 entries, 3 people watched; left out: 1 not active, 1 outside
// your domains (elsewhere.example). 1 couldn't be watched (see the error)."
function watchSummary({ ok, failed, stopped, groups, extra, ou, orgDomains, renewed = null, left = 0, domain = null }) {
    const n = (k, one, many = `${one}s`) => `${k} ${k === 1 ? one : many}`;
    const parts = [`Watching ${n(ok, 'mailbox', 'mailboxes')}.`];
    if (renewed !== null && left) parts.push(`Renewed now: ${renewed}${left ? `; ${left} more within the next hours (each hourly run continues; a watch lasts 7 days; new mailboxes and the oldest watches first)` : ''}.`);
    if (domain !== null) parts.push(`The whole domain (Settings → Mailboxes): ${n(domain, 'active mailbox', 'active mailboxes')} of ${orgDomains.join(', ')} in the directory.`);
    for (const g of groups) {
        const out = [];
        if (g.inactive) out.push(`${g.inactive} not active (suspended or archived)`);
        if (g.outside) out.push(`${g.outside} outside your domains (${g.outsideDomains.join(', ')}; ORG_DOMAINS is ${orgDomains.join(', ')})`);
        if (g.everyone) out.push(`${n(g.everyone, '"all users in the organization" entry', '"all users in the organization" entries')}, which ${g.everyone === 1 ? "isn't" : "aren't"} expanded: add people or groups instead`);
        parts.push(`${g.group}: ${n(g.entries, 'entry', 'entries')}${g.groups ? ` (${n(g.groups, 'group')} inside it, whose members are listed too)` : ''}, ${n(g.people, 'person', 'people')} to watch${out.length ? `; left out: ${out.join(', ')}` : ''}.`);
    }
    if (ou) parts.push(`Plus the users of ${ou}.`);
    if (extra) parts.push(`Plus ${n(extra, 'address', 'addresses')} from PILOT_USERS.`);
    if (failed) parts.push(`${n(failed, 'mailbox', 'mailboxes')} couldn't be watched (see the errors).`);
    if (stopped) parts.push(`Stopped watching ${n(stopped, 'mailbox', 'mailboxes')} no longer ${domain !== null ? 'in the domain' : 'in the pilot'}.`);
    return parts.join(' ');
}

// --- The policy settings an admin can change on the dashboard (Settings, with the project ID) ----------
// The settings in POLICY_KEYS (the mode, the AI lines, the optional services, the allowlists, the brake
// (0: automatic), the time zone, how long records are kept, who is watched…) come from deploy/settings.env
// (the services' environment). A change on the dashboard is kept in Firestore (state/policy-<key>: { value, env, before,
// by, at }) and applies to every instance within POLICY_REFRESH_MS. It records the settings.env value it
// replaced (env): when settings.env later has another value for the same setting (changed, then
// install.sh), that one is newer and applies. The most recent change wins, wherever it was made.
const POLICY_KEYS = ['mode', 'aiThreshold', 'aiSuspicious', 'aiScansInside', 'aiMovesInside', 'safeBrowsing', 'spamhaus', 'abusech', 'suspiciousLabel', 'recheck', 'brakePerHour', 'timeZone', 'allowDomains', 'allowAddresses', 'allowLinkDomains', 'retentionDays', 'watchScope', 'releasesRepo', 'modelRepo'];
const LIST_KEYS = ['allowDomains', 'allowAddresses', 'allowLinkDomains'];
const MAX_ALLOWED = 500;
const DOMAIN_RE = /^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
// A list as kept: lower case, no repeats, sorted (from a list, or text with one entry per line or
// separated by commas or semicolons: an entry with a space in it is reported whole).
const asList = (v) => [...new Set((Array.isArray(v) ? v : String(v || '').split(/[\r\n,;]+/)).map(x => String(x).trim().toLowerCase()).filter(Boolean))].sort();
const POLICY_REFRESH_MS = 30 * 1000;
const MIN_KEEP_DAYS = 14, MAX_KEEP_DAYS = 365;   // retentionDays (config.js says the same)
// Marks a configuration whose envPolicy was taken here (Service's constructor), so it is taken only once.
const OWN_ENV = Symbol('envPolicy of this configuration');
// Two values of one setting are the same: lists in any order or spelling, numbers as numbers (a number
// from settings.env may be text).
const sameSetting = (a, b) => (Array.isArray(a) || Array.isArray(b) ? asList(a).join(',') === asList(b).join(',')
    : typeof a === 'number' || typeof b === 'number' ? Number(a) === Number(b) : String(a) === String(b));
// (0.5.73) Domains that can't be allowed link domains: sites where anyone can put up a page (a phishing page there
// is listed as its own subdomain, so allowing the platform would hide all of them), link shorteners (any address
// behind them), and suffixes under which anyone registers (co.uk). The big brands' own domains (google.com) and
// personal mail services are never listed whole anyway (feeds.js sanitize), and cloud-storage hosts only page by
// page (vendor/spruce/shared.js cloudStoragePage). This guards what an admin types; it judges no email.
const OPEN_HOSTING = new Set(['github.io', 'gitlab.io', 'blogspot.com', 'wordpress.com', 'wixsite.com', 'weebly.com', 'squarespace.com', 'square.site',
    'godaddysites.com', 'webflow.io', 'netlify.app', 'vercel.app', 'herokuapp.com', 'glitch.me', 'onrender.com', 'workers.dev', 'pages.dev', 'web.app',
    'firebaseapp.com', 'r2.dev', 'notion.site', 'gitbook.io', 'framer.app', 'carrd.co', 'mystrikingly.com', 'jimdosite.com', 'surge.sh', 'replit.app',
    'repl.co', 'ngrok.io', 'ngrok-free.app', 'trycloudflare.com', 'azurewebsites.net', 'cloudfront.net', 'amplifyapp.com', 'appspot.com', 'blob.core.windows.net',
    'typeform.com', 'jotform.com', 'formstack.com', 'wufoo.com', 'canva.site', 'my.canva.site', 'linktr.ee', 'ipfs.io', 'dweb.link']);
function linkDomainRefused(x, E) {
    const reg = E.registrableDomain(x) || x;
    if (OPEN_HOSTING.has(x) || OPEN_HOSTING.has(reg)) return x === reg || OPEN_HOSTING.has(x) ? `${x} hosts other people's sites: a phishing page there is listed by its own address, and allowing ${x} would hide all of them.`
        : `${x} is a site on ${reg}, where anyone can put up a page: its links are judged as they are found.`;
    if (E.publicShorteners.includes(x) || E.publicShorteners.includes(reg)) return `${x} is a link shortener: allowing it would let any address behind its links through.`;
    if (/^(co|com|net|org|gov|edu|ac|ne|or|go|gob|nic|mil|sch)\.[a-z]{2}$/.test(x) || !x.includes('.')) return `${x} is a suffix many sites share, not one site.`;
    if (E.isPersonalMailDomain(reg) || E.PROTECTED_DOMAINS.has(reg)) return `${x} is never listed whole by the phishing lists (only single pages are), so there is nothing to allow.`;
    try { if (E.cloudStoragePage(`https://${x}/x`)) return `${x} is a cloud-storage host, where anyone can put up a page: the lists match it page by page only, so there is nothing to allow.`; } catch (e) { /* not one */ }
    return '';
}
function validTimeZone(z) { try { new Intl.DateTimeFormat('en-US', { timeZone: z }); return true; } catch (e) { return false; } }
// The value as stored, or an error (status 400) saying what is allowed. now: the settings in force, for
// the checks between them: orgDomains (the organization's own domains, which can't be allowlisted, or a
// staff account taken over would never be moved), and the two AI lines (the suspicious line is never
// above the move threshold).
function policyValue(key, v, now = {}) {
    const orgDomains = Array.isArray(now) ? now : now.orgDomains || [];
    const bad = (msg) => { throw Object.assign(new Error(msg), { status: 400 }); };
    if (LIST_KEYS.includes(key)) {
        const items = asList(v);
        if (items.length > MAX_ALLOWED) bad(`At most ${MAX_ALLOWED} entries.`);
        for (const x of items) {
            const domain = key === 'allowAddresses' ? x.split('@')[1] || '' : x;
            if (key === 'allowAddresses' && !/^[^\s@]+@[^\s@]+$/.test(x)) bad(`"${x.slice(0, 80)}" isn't an email address.`);
            if (!DOMAIN_RE.test(domain)) bad(`"${x.slice(0, 80)}" isn't a domain${key === 'allowAddresses' ? ' at the end of an address' : ''}.`);
            if (key === 'allowDomains' && orgDomains.some(d => x === d || x.endsWith(`.${d}`) || d.endsWith(`.${x}`))) bad(`${x} is your organization's own domain: it can't be allowlisted, or a staff account taken over would never be moved. Allowlist single addresses instead.`);
            if (key === 'allowLinkDomains') {
                if (orgDomains.some(d => x === d || x.endsWith(`.${d}`) || d.endsWith(`.${x}`))) bad(`${x} is your organization's own domain: the phishing lists already flag its links only by the exact page listed, never the whole site.`);
                const why = linkDomainRefused(x, spruce.load());
                if (why) bad(why);
            }
        }
        return items;
    }
    if (key === 'releasesRepo' || key === 'modelRepo') {
        const s = String(v === null || v === undefined ? '' : v).trim();
        const why = repos.problem(s);
        if (why) bad(`${key === 'releasesRepo' ? 'The release repository' : 'The model repository'}: ${why}`);
        return s;
    }
    if (key === 'mode') return v === 'monitor' || v === 'enforce' ? v : bad('The mode is monitor or enforce.');
    if (key === 'watchScope') return v === 'pilot' || v === 'domain' ? v : bad('Who is checked is the pilot or the whole domain.');
    const pc = (x) => `${Math.round(Number(x) * 1000) / 10}%`;
    if (key === 'aiThreshold') {
        const n = Number(v), floor = typeof now.aiSuspicious === 'number' ? now.aiSuspicious : 0.5;
        return Number.isFinite(n) && n > 0.5 && n >= floor && n <= 1 ? Math.round(n * 1000) / 1000
            : bad(`The AI move threshold is from the suspicious line (${pc(floor)}) to 100%. To go lower, lower the suspicious line first.`);
    }
    if (key === 'aiSuspicious') {
        const n = Number(v), ceiling = typeof now.aiThreshold === 'number' ? now.aiThreshold : 1;
        return Number.isFinite(n) && n >= 0.5 && n <= ceiling ? Math.round(n * 1000) / 1000
            : bad(`The AI suspicious line is from 50% to the move threshold (${pc(ceiling)}). To go higher, raise the move threshold first.`);
    }
    if (key === 'aiScansInside' || key === 'aiMovesInside' || key === 'safeBrowsing' || key === 'spamhaus' || key === 'abusech' || key === 'suspiciousLabel' || key === 'recheck') {
        if (v === true || v === false) return v;
        const t = String(v).trim().toLowerCase();
        return ['on', 'true', 'yes', '1'].includes(t) ? true : ['off', 'false', 'no', '0'].includes(t) ? false
            : bad({ aiScansInside: 'Whether the AI reads mail from inside is on or off.', aiMovesInside: 'Whether the AI alone moves mail from inside is on or off.', safeBrowsing: 'Google Safe Browsing is on or off.', suspiciousLabel: 'The Suspicious label is on or off.', recheck: 'Re-checking delivered mail is on or off.', spamhaus: 'Spamhaus is on or off.', abusech: 'abuse.ch is on or off.' }[key]);
    }
    if (key === 'brakePerHour') { const n = Number(v); return n === 0 || (Number.isInteger(n) && n >= 10 && n <= 100000) ? n : bad('The brake is automatic, or a whole number of moves an hour from 10 to 100,000.'); }
    if (key === 'timeZone') { const z = String(v || '').trim(); return z && validTimeZone(z) ? z : bad('The time zone is an IANA name, for example America/New_York.'); }
    if (key === 'retentionDays') { const n = Number(v); return Number.isInteger(n) && n >= MIN_KEEP_DAYS && n <= MAX_KEEP_DAYS ? n : bad(`Records are kept a whole number of days, from ${MIN_KEEP_DAYS} to ${MAX_KEEP_DAYS}.`); }
    return bad('That setting can\'t be changed on the dashboard.');
}
function policyWords(key, v) {
    if (LIST_KEYS.includes(key)) { const l = asList(v); return l.length ? (l.length > 5 ? `${l.length} entries` : l.join(', ')) : 'none'; }
    if (key === 'mode') return v === 'enforce' ? 'enforce' : 'monitor';
    if (key === 'releasesRepo' || key === 'modelRepo') return String(v || '').trim() ? repos.shown(v) : 'not set';
    if (key === 'watchScope') return v === 'domain' ? 'the whole domain' : 'the pilot';
    if (key === 'aiThreshold' || key === 'aiSuspicious') return `${Math.round(Number(v) * 1000) / 10}%`;
    if (key === 'brakePerHour') return Number(v) ? `${Number(v).toLocaleString('en-US')} moves an hour` : 'automatic (half the watched mailboxes, at least 100)';
    if (key === 'retentionDays') return `${Number(v)} days`;
    if (key === 'aiScansInside' || key === 'aiMovesInside' || key === 'safeBrowsing' || key === 'spamhaus' || key === 'abusech' || key === 'suspiciousLabel' || key === 'recheck') return v ? 'on' : 'off';
    return String(v);
}

// (0.6.3) A copy its mailbox's own owner sent: Gmail's SENT label, or the owner's own address with nothing showing it
// was ever delivered (no receiving server's verification, no Received line: mail from anyone else always has both).
// Their own mail, never judged: the AI read a student's sent replies as "outside" mail.
function ownSentCopy(user, msg, facts) {
    if (((msg && msg.labelIds) || []).includes('SENT')) return true;
    const me = String(user || '').toLowerCase();
    return !!me && String((facts && facts.senderAddress) || '').toLowerCase() === me && !(facts && facts.auth) && !/^received:/im.test(String((facts && facts.rawHead) || ''));
}

class Service {
    // statFlushMs: the day's counters of checked emails are added up here and written at most this often
    // (one write for all of them; 0, as in the tests: each at once). The worker uses STAT_FLUSH_MS.
    constructor({ cfg, store, gmail, intel = null, now = () => Date.now(), log = console, waitForOthersMs = WAIT_FOR_OTHERS_MS, statFlushMs = 0, checksLevel = currentChecksLevel }) {
        this.cfg = cfg; this.store = store; this.gmail = gmail; this.intel = intel; this.now = now; this.log = log;
        this.checksLevel = checksLevel;   // (0.5.51) package.json's checksLevel; the tests give another
        this.waitForOthersMs = waitForOthersMs;
        this.statFlushMs = statFlushMs; this.statBuf = new Map(); this.statFlushedAt = Date.now();
        // What deploy/settings.env says (the environment), before any change made on the dashboard
        // (loadConfig keeps it; a configuration made by hand, as in the tests, gets it here).
        // A plain copy (Object.assign({}, cfg, { mode })) takes its own values, not the original's.
        if (!Object.isFrozen(cfg) && !cfg[OWN_ENV]) {
            cfg.envPolicy = Object.fromEntries(POLICY_KEYS.map(k => [k, cfg[k]]));
            Object.defineProperty(cfg, OWN_ENV, { value: true });
        }
        this.policyState = {}; this.policyReadAt = 0;
        // Kept per instance, as they never change once known: when each sender was first seen (a hash, as
        // in Firestore), and the campaigns whose alert has been sent.
        this.installedAt = null; this.senderSeen = new Map(); this.alerted = new Set();
        this.emailSlots = new Slots(EMAIL_SLOTS); this.largeSlots = new Slots(LARGE_SLOTS); this.rescanSlots = new Slots(RESCAN_SLOTS);
    }
    // The day an instant falls on in the organization's time zone (TIME_ZONE, Settings → Policy).
    dayOf(ms) { return A.dayIn(ms, this.cfg.timeZone); }
    // A large email (over LARGE_BYTES) is read and judged LARGE_SLOTS at a time.
    readAndJudge(user, msg, opts) {
        const go = async () => this.judge(user, msg, await readMessage(msg.raw, { ownDomains: this.cfg.orgDomains }), opts);
        return msg.raw && msg.raw.length > LARGE_BYTES ? this.largeSlots.run(go) : go();
    }
    // A day's counter of checked emails (scanned, moved, …): written at once, or added up and written with
    // the others every statFlushMs (a busy instance writes once every few seconds, not once per email, and
    // a campaign makes no counter document hot). Counts are written on the next email after that, and when
    // the instance stops (flushStats, from server.js).
    async count(day, field) {
        if (!this.statFlushMs) return this.store.incStat(day, field);
        const k = `${day}|${field}`;
        this.statBuf.set(k, (this.statBuf.get(k) || 0) + 1);
        if (Date.now() - this.statFlushedAt >= this.statFlushMs) await this.flushStats();
    }
    async flushStats() {
        if (!this.statBuf.size) return;
        const buf = this.statBuf;
        this.statBuf = new Map(); this.statFlushedAt = Date.now();
        const byDay = new Map();
        for (const [k, n] of buf) { const [day, field] = k.split('|'); byDay.set(day, Object.assign(byDay.get(day) || {}, { [field]: n })); }
        for (const [day, counts] of byDay) {
            try { await this.store.incStats(day, counts); }
            catch (e) {   // kept for the next try
                for (const [f, n] of Object.entries(counts)) this.statBuf.set(`${day}|${f}`, (this.statBuf.get(`${day}|${f}`) || 0) + n);
                this.log.error('writing the day\'s counters:', e);
            }
        }
    }
    // When a sender was first seen: Firestore's answer (a transaction on senders/{hash}) the first time on
    // this instance, then this instance's copy.
    async firstSeen(hash, now) {
        if (this.senderSeen.has(hash)) return this.senderSeen.get(hash);
        const first = await this.store.senderFirstSeen(hash, now);
        if (this.senderSeen.size >= SENDERS_KEPT) this.senderSeen.delete(this.senderSeen.keys().next().value);
        this.senderSeen.set(hash, first);
        return first;
    }

    // Reads the dashboard's changes (at most every POLICY_REFRESH_MS, or now with force) and applies the
    // ones still in force to this.cfg, which every check reads when it runs.
    async refreshPolicy({ force = false } = {}) {
        if (!force && Date.now() - this.policyReadAt < POLICY_REFRESH_MS) return this.policyState;
        this.policyReadAt = Date.now();
        let rows;
        try { rows = await Promise.all(POLICY_KEYS.map(k => this.store.getState(`policy-${k}`))); }
        catch (e) { this.log.error('reading the policy changed on the dashboard:', e); return this.policyState; }
        this.policyState = Object.fromEntries(POLICY_KEYS.map((k, i) => [k, rows[i] || null]));
        this.applyPolicy();
        return this.policyState;
    }
    // The values in force: the dashboard's where still in force, settings.env's otherwise.
    applyPolicy() {
        const env = this.cfg.envPolicy;
        const values = Object.fromEntries(POLICY_KEYS.map(k => { const o = this.policyState[k]; return [k, o && sameSetting(o.env, env[k]) ? o.value : env[k]]; }));
        if (typeof this.cfg.setPolicyValues === 'function') this.cfg.setPolicyValues(values);   // (loadConfig's)
        else Object.assign(this.cfg, values);
    }
    // For Settings: each setting's value in force, and where it comes from.
    policyInfo() {
        return Object.fromEntries(POLICY_KEYS.map(k => {
            const o = this.policyState[k], kept = !!(o && sameSetting(o.env, this.cfg.envPolicy[k]));
            return [k, { value: this.cfg[k], env: this.cfg.envPolicy[k], changed: kept ? { by: o.by, at: o.at, before: o.before } : null,
                replaced: o && !kept ? { by: o.by, at: o.at, value: o.value } : null }];
        }));
    }
    // A change made on the dashboard (the server checks the project ID, and the agreement for enforce mode).
    // In force at once here, everywhere within POLICY_REFRESH_MS; noted in Activity → What admins did (not
    // emailed, 0.5.28: an alert is a problem).
    async setPolicy(key, raw, by) {
        if (!POLICY_KEYS.includes(key)) throw Object.assign(new Error('That setting can\'t be changed on the dashboard.'), { status: 400 });
        const value = policyValue(key, raw, { orgDomains: this.cfg.orgDomains, aiThreshold: this.cfg.aiThreshold, aiSuspicious: this.cfg.aiSuspicious });
        await this.refreshPolicy({ force: true });
        const before = this.cfg[key];
        if (sameSetting(before, value)) return { key, value, unchanged: true };
        const rec = { value, env: this.cfg.envPolicy[key], before, by, at: this.now() };
        await this.store.setState(`policy-${key}`, rec);
        this.policyState[key] = rec; this.applyPolicy();
        const how = key === 'watchScope' ? 'confirmed with the project ID and their own address, and agreed' : key === 'mode' && value === 'enforce' ? 'confirmed with the project ID, and agreed' : 'confirmed with the project ID';
        const listChange = () => {
            const was = asList(before), now = asList(value);
            const added = now.filter(x => !was.includes(x)), removed = was.filter(x => !now.includes(x));
            const part = (verb, l) => (l.length ? `${verb} ${l.length > 10 ? `${l.length} entries` : l.join(', ')}` : '');
            const changes = [part('added', added), part('removed', removed)].filter(Boolean).join('; ');
            if (key === 'allowLinkDomains') return `${by} changed the allowed link domains on the dashboard (${how}): ${changes}. A phishing list's listing of their whole domain no longer flags links to them, in anyone's mail (a listing of the exact page still does; the other link checks still apply).`;
            return `${by} changed the allowlisted ${key === 'allowDomains' ? 'domains' : 'addresses'} on the dashboard (${how}): ${changes}. Mail from them is never moved when Gmail's DMARC check passes for it.`;
        };
        const text = LIST_KEYS.includes(key) ? listChange()
            : key === 'releasesRepo' ? `${by} changed the release repository on the dashboard (${how}), from ${policyWords(key, before)} to ${policyWords(key, value)}: Settings → Update now offers the versions there, and an update installs them.`
            : key === 'modelRepo' ? `${by} changed the model repository on the dashboard (${how}), from ${policyWords(key, before)} to ${policyWords(key, value)}: the next build downloads the AI model's files from there (each version's pinned files only).`
            : key === 'watchScope' ? (value === 'domain'
                ? `${by} switched the service to the whole domain on the dashboard (${how}): every active mailbox of ${this.cfg.orgDomains.join(', ')} is watched and checked from the next re-read of the directory (started now), not only the pilot. The mode (${this.cfg.mode}) and the brakes apply to all of them.`
                : `${by} switched the service back to the pilot on the dashboard (${how}): only the pilot's mailboxes are checked; the others' watches are stopped at the next re-read (started now).`)
            : key === 'aiScansInside' ? `${by} turned ${value ? 'on' : 'off'} the AI for mail from inside the organization on the dashboard (${how}): ${value ? `the AI reads it too now; its score alone ${this.cfg.aiMovesInside ? `moves it at ${policyWords('aiThreshold', this.cfg.aiThreshold)} or more ("AI alone moves inside mail" is on)` : 'still doesn\'t move it'}` : this.cfg.aiMovesInside ? 'but "AI alone moves inside mail" is on and needs it, so the AI keeps reading inside mail until that is off' : 'the rule checks alone read it now (its links, its headers and the rest)'}.`
            : key === 'aiMovesInside' ? (value
                ? `${by} turned on "AI alone moves inside mail" on the dashboard (${how}): an email from inside the organization that the AI scores ${policyWords('aiThreshold', this.cfg.aiThreshold)} or more is ${this.cfg.mode === 'enforce' ? 'moved to Spam' : 'recorded as "would move" (monitor mode)'} on the AI score alone, as outside mail is. The AI reads inside mail for it.`
                : `${by} turned off "AI alone moves inside mail" on the dashboard (${how}): the AI score alone no longer moves mail from inside the organization; the rules still can (a staff account taken over).${this.cfg.aiScansInside ? '' : ' The AI stops reading inside mail ("AI on inside mail" is off).'}`)
            : key === 'suspiciousLabel' ? (value
                ? `${by} turned on the Suspicious label on the dashboard (${how}): from now on, an email that is suspicious but not moved gets the label ${this.cfg.suspiciousLabelName} in its mailbox, so its reader sees it, in monitor mode too. Nothing is moved by it.`
                : `${by} turned off the Suspicious label on the dashboard (${how}): no more emails get it; the ones that have it keep it.`)
            : key === 'safeBrowsing' ? (value
                ? `${by} turned on Google Safe Browsing on the dashboard (${how}): the addresses of the links in each email are now also looked up with Google (without the part after "#", and one-time links without their query), within 30 seconds everywhere.`
                : `${by} turned off Google Safe Browsing on the dashboard (${how}): links are no longer sent to Google. The saved key stays in Secret Manager until it is removed.`)
            : key === 'mode'
            ? (value === 'enforce' ? `${by} switched to enforce mode on the dashboard (${how}): from now on, emails the policy flags are moved to Spam.`
                : `${by} switched to monitor mode on the dashboard (${how}): nothing is moved from now on, and emails already moved stay in Spam.`)
            : `${by} changed ${({ aiThreshold: 'the AI move threshold', aiSuspicious: 'the AI suspicious line', aiScansInside: 'whether the AI reads mail from inside the organization', aiMovesInside: 'whether the AI alone moves mail from inside the organization', brakePerHour: 'the brake', timeZone: 'the time zone', retentionDays: 'how long records are kept' })[key]} from ${policyWords(key, before)} to ${policyWords(key, value)} on the dashboard (${how}).`
              + (key === 'timeZone' ? ' The weekly summary uses it now; the nightly jobs move to it the next time deploy/install.sh runs.' : '')
              + (key === 'retentionDays' ? (value < before ? ` Records older than ${value} days are deleted over the next hours, the oldest first.`
                  : ` Records saved from now on are kept ${value} days; the ones already saved keep the date they had (${before} days after they arrived).`) : '');
        await this.adminNotice('settings', text, { policy: key });
        return { key, value, before };
    }

    // A Pub/Sub notification. Returns a summary (for logs and tests).
    async handleNotification({ emailAddress, historyId }) {
        await this.refreshPolicy();
        const user = String(emailAddress || '').toLowerCase();
        if (!user || !historyId) return { ignored: 'malformed' };
        // The mailbox's state, read once (whether it is watched, and where its history was read up to).
        const u = (await this.store.getUser(user)) || {};
        if (!u.watched && (u.stoppedAt || !this.cfg.pilotUsers.includes(user))) return { ignored: 'not watched' };
        // When Gmail last notified: written with the sync position (one write, not two); when that doesn't
        // move, at most every NOTED_EVERY_MS.
        const noted = { lastNotification: this.now() };
        const note = async () => { if (this.now() - (Number(u.lastNotification) || 0) >= NOTED_EVERY_MS) await this.store.putUser(user, noted); };
        if (!u.historyId) { await this.store.raiseHistoryId(user, String(historyId), noted); return { started: true }; }
        let added;
        try { added = await this.gmail.addedSince(user, u.historyId); }
        catch (e) {
            if (e instanceof GoogleApiError && e.status === 404) {
                // Too long since the last change we know of (Gmail keeps about a week): start again from now.
                // Checking goes on from now, and the Inbox mail since the last notification (at most a
                // week) is caught up on, a little with each later notification (backfillStep).
                const p = await this.gmail.profile(user);
                const after = Math.max(Number(u.lastNotification) || 0, this.now() - 7 * DAY);
                await this.store.putUser(user, Object.assign({ historyId: String(p.historyId), backfill: { after, pageToken: null, checked: 0 } }, noted));
                // (0.5.32: said plainly, as the alert does; "missed" read as "emails missed")
                await this.store.addEvent({ kind: 'gap', missed: true, user, text: `The service fell behind on ${user}'s mailbox: Gmail no longer had the list of what changed there since the service last looked (it keeps about a week). New mail is checked from now on, and the mail still in the Inbox since ${new Date(after).toISOString().slice(0, 16).replace('T', ' ')} UTC is being checked too, a batch at a time; mail deleted or moved out of the Inbox meanwhile isn't. Not a problem when it happens now and then (docs/ALERTS.md, "The service fell behind").` });
                await this.gapCheck(user).catch(e => this.log.error('counting the gaps:', e));
                return { resynced: true };
            }
            throw e;
        }
        const results = [];
        // Anything left to do (a failed try, a message another instance is still on): the sync position
        // stays, so this part of the history is read again (held: the server asks Pub/Sub to deliver the
        // notification again later).
        let hold = false;
        // Emails the service moved that the user took back to the Inbox.
        const listedAsNew = new Set(added.ids);
        const inboxedAt = added.inboxedAt || {};
        for (const id of added.inboxed || []) {
            try {
                const r = await this.userReleased(user, id, { at: inboxedAt[id], listedAsNew: listedAsNew.has(id) });
                // Not one the service recorded: maybe one it never checked (the user took it out of Spam).
                if (r && r.noRecord && !listedAsNew.has(id)) await this.checkUnseenInbox(user, id);
            } catch (e) { this.log.error(`user release ${user} ${id}:`, e); }
        }
        const busy = [];
        for (const id of added.ids) {
            let r;
            try { r = await this.processMessage(user, id); }
            catch (e) {
                if (!e.gaveUp) hold = true;
                const why = String(e && e.message || e).slice(0, 300);
                await this.store.incStat(this.dayOf(this.now()), 'errors');
                await this.store.addEvent({ kind: 'error', user, text: e.gaveUp
                    ? `A message couldn't be checked after ${MAX_TRIES} tries and was left where it is: ${why}`
                    : `A message couldn't be checked (try ${e.tries || 1} of ${MAX_TRIES}; it is tried again in a minute or so): ${why}` });
                this.log.error(`process ${user} ${id}:`, e);
                // An email left unchecked is a gap in the protection: the admins are told (0.5.29, once a day).
                if (e.gaveUp) await this.alertDaily('unchecked-mail', `An email to ${user} couldn't be checked after ${MAX_TRIES} tries and was left in the mailbox unchecked (${why.slice(0, 160)}). Any more today are listed in Health → Activity → Errors and gaps.`).catch(() => {});
                await this.gmailTrouble(e, user);
                continue;
            }
            if (r && r.busy) busy.push(id);
            else if (r) results.push(r);
        }
        if (busy.length && !(await this.othersDone(user, busy))) hold = true;
        // Nothing new for the Inbox (the user read or archived something; two thirds of notifications): the
        // sync position can wait up to QUIET_POSITION_MS, as the next notification reads the history from
        // where it is (2 quota units). No write, no transaction.
        const nothingNew = !added.ids.length && !(added.inboxed || []).length && !added.more && !u.backfill;
        if (hold || !movesForward(String(added.historyId), u.historyId)) await note();
        else if (nothingNew && this.now() - (Number(u.lastNotification) || 0) < QUIET_POSITION_MS) { /* written later */ }
        else await this.store.raiseHistoryId(user, String(added.historyId), noted);
        if (u.backfill) { try { await this.backfillStep(user, u.backfill); } catch (e) { this.log.error(`backfill ${user}:`, e); } }
        if (this.log.info) this.log.info(`notification: ${added.ids.length} new in the Inbox, ${results.length} checked${hold ? ', some left to try again' : ''}`);
        return Object.assign({ processed: results.length, results }, hold ? { held: true } : {}, added.more ? { more: true } : {});
    }

    // Messages another instance had: done within WAIT_FOR_OTHERS_MS? (Two notifications for one email
    // usually come together, and each would otherwise keep the place for the other.)
    async othersDone(user, ids) {
        const until = Date.now() + this.waitForOthersMs;
        let left = ids;
        for (;;) {
            const done = await Promise.all(left.map(id => this.store.seen(user, id)));
            left = left.filter((id, i) => !done[i]);
            if (!left.length) return true;
            if (Date.now() >= until) return false;
            await new Promise(r => setTimeout(r, 200));
        }
    }

    // One message: claimed, judged, then marked done. A failed try lets it go to be tried again (up to
    // MAX_TRIES), and throws with e.tries and e.gaveUp. { busy: true }: another instance has it.
    async processMessage(user, id) {
        const claim = await this.store.claim(user, id, this.now(), CLAIM_LEASE_MS);
        if (claim.done) return null;
        if (claim.busy) return { busy: true };
        let out;
        try { out = await this.checkMessage(user, id, claim.tries); }
        catch (e) {
            const err = e instanceof Error ? e : new Error(String(e));
            err.tries = claim.tries;
            err.gaveUp = claim.tries >= MAX_TRIES;
            try {
                if (err.gaveUp) await this.store.markSeen(user, id, { failed: true });
                else await this.store.unclaim(user, id);
            } catch (e2) { /* the claim runs out by itself (CLAIM_LEASE_MS) */ }
            throw err;
        }
        await this.store.markSeen(user, id, (out && out.recheckIndex) || {});
        return out;
    }

    // A share from outside (a platform's notification for a person outside, or an outside email linking a
    // document, form or signature request: notifications.js shareSource): how many of the organization's
    // people the same outside account reached this hour (store.shareReach, by hashes). Reaching MASS_SHARE
    // is the usual sign of an account taken over elsewhere: an alert, once per account and hour.
    async countShare(facts, user, now) {
        const src = shareSource(facts, this.cfg.orgDomains);
        if (!src) return 0;
        try {
            const r = await this.store.shareReach(senderHash(src.address), senderHash(user), now, MASS_SHARE);
            if (r.crossed) {
                await this.alert('mass-share', `${src.address} (outside your organization) sent the same ${src.relay ? `${src.relay.via} share` : 'share or signature request'} to ${r.count} of your people within the hour. If it's phishing, Threats → Campaigns → open it → Confirm phishing moves every copy.`);
            }
            return r.count;
        } catch (e) {
            this.log.error(JSON.stringify({ message: `Couldn't count an outside share: ${String(e && e.message || e).slice(0, 200)}` }));
            return 0;
        }
    }

    // "Check an email" (dashboard): an email an admin pasted (its original, from Gmail's "Show original")
    // or uploaded, judged as on arrival with the same lookups, in the current mode, brakes aside.
    // Nothing is stored, moved or counted. The answer has a record's shape, for the same view.
    async checkPasted(raw, { by = '' } = {}) {
        const facts = await readMessage(Buffer.from(String(raw), 'utf8'), { ownDomains: this.cfg.orgDomains });
        const allowlisted = isAllowed(this.cfg, facts.senderAddress), verified = senderVerified(facts);
        // Judged for the recipient in the organization, if the email names one; else for the admin.
        const mailbox = (facts.to || []).find(a => this.cfg.orgDomains.includes(a.split('@')[1])) || by;
        const result = await analyze(facts, { mailbox, orgDomains: this.cfg.orgDomains, allowLinkDomains: this.cfg.allowLinkDomains, trusted: allowlisted && verified, firstTime: false, intel: this.intel, colleagues: await this.colleagueNames(), selfNameHash: this.selfNameHash(mailbox), aiInside: this.aiReadsInside(), lookalikes: await this.lookalikeMap() });
        result.allowlistedUnverified = allowlisted && !verified;
        let decision = decide(result, this.cfg, {});
        // (a phishing-training email is let through, unchecked, on arrival: said so, 0.5.44)
        const training = await this.trainingOf(facts);
        if (training) decision = { action: 'none', trigger: null, why: `a phishing-training email (${training.name}): let through unchecked, as set in Settings → Phishing training. The checks below show what they would find` };
        const domain = (facts.senderAddress.split('@')[1] || '').toLowerCase();
        return {
            pasted: true, training: training ? training.name : null, key: null, messageId: null, rfc822MessageId: messageIdOf(facts.messageIdHeader), user: mailbox,
            receivedAt: facts.date || null, processedAt: this.now(),
            sender: { name: facts.senderName.slice(0, 200), address: facts.senderAddress.slice(0, 320), domain }, subject: facts.subject.slice(0, 300),
            status: result.status, score: result.score, signals: result.signals.slice(0, 30), links: result.links.slice(0, 20), checks: result.checks || null,
            ai: result.ai ? { probability: result.ai.probability, model: result.ai.model, reasons: (result.ai.reasons || []).map(r => ({ sentence: String(r.sentence).slice(0, 160), facts: !!r.facts })) } : null,
            auth: facts.auth ? Object.assign({ dmarc: facts.auth.dmarc, spf: facts.auth.spf, dkim: facts.auth.dkim }, facts.auth.derived ? { derived: facts.auth.derived } : {}) : null,
            attachments: facts.attachments.slice(0, 10).map(a => ({ name: a.name.slice(0, 120), type: a.type })),
            attachmentFindings: (result.attachmentFindings || []).slice(0, 12),
            action: decision.action, trigger: decision.trigger, why: decision.why, mode: this.cfg.mode,
            evidence: decision.action === 'none' ? null : result.strong ? 'strong' : 'weak', confirmedBy: result.confirmedBy || []
        };
    }

    // The colleague-name check's list: the full name of everyone in the directory, kept only as one-way hashes
    // (the extension's colleagueNameHash: "Notreal, Avery" = "Avery Notreal"), in memory, read again every 12 hours
    // (after a failure, every hour). Off (null) without DIRECTORY_ADMIN or with COLLEAGUE_NAMES=off; a
    // failed read (no Users → Read privilege or no admin.directory.user.readonly scope) keeps the last list
    // and is noted in state/colleagueNames for Health → Service status, never alerted. Emails checked
    // while it is being read wait for the same read.
    async colleagueNames() {
        if (!this.cfg.colleagueNames || !this.cfg.directoryAdmin || !this.gmail || typeof this.gmail.userNames !== 'function') return null;
        const now = this.now(), c = this.colleagues;
        if (c && now - c.at < (c.error ? HOUR : 12 * HOUR)) return c.hashes;
        if (this.colleaguesLoading) return this.colleaguesLoading;
        this.colleaguesLoading = (async () => {
            try {
                const E = require('./engine/spruce').load();
                const names = await this.gmail.userNames(this.cfg.directoryAdmin);
                // Each { name, email } (or a name alone): only one-way hashes are kept, in memory.
                const people = names.map(n => (typeof n === 'string' ? { name: n, email: '' } : n || {}));
                const hashes = new Set(people.map(p => E.colleagueNameHash(p.name)).filter(Boolean));
                const byEmail = new Map(people.filter(p => p.email).map(p => [String(p.email).toLowerCase(), E.colleagueNameHash(p.name)]).filter(([, h]) => h));
                this.colleagues = { hashes, byEmail, at: now, error: null };
                await this.store.setState('colleagueNames', { at: now, names: hashes.size, error: null }).catch(() => {});
            } catch (e) {
                const error = String(e && e.message || e).slice(0, 300);
                this.colleagues = { hashes: c ? c.hashes : null, byEmail: c ? c.byEmail : null, at: now, error };
                await this.store.setState('colleagueNames', { at: now, names: c && c.hashes ? c.hashes.size : 0, error }).catch(() => {});
                if (!c || !c.error) this.log.warn(JSON.stringify({ message: `Couldn't read the directory's names for the colleague-name check: ${error}` }));
            } finally { this.colleaguesLoading = null; }
            return this.colleagues.hashes;
        })();
        return this.colleaguesLoading;
    }

    // The recipient's own name's hash (colleagueNames), or ''.
    selfNameHash(user) { const c = this.colleagues; return (c && c.byEmail && c.byEmail.get(String(user || '').toLowerCase())) || ''; }

    // Whether the AI model reads mail from inside the organization (verified: your domains, DMARC passing):
    // AI_SCANS_INSIDE (Settings → Policy), off by default; AI_MOVES_INSIDE needs it, so it counts too.
    aiReadsInside() { return !!(this.cfg.aiScansInside || this.cfg.aiMovesInside); }

    // "Show more" on an email's AI opinion: what the model reads of it, sentence by sentence, each with how far
    // it leans toward phishing, so an admin can decide with the surrounding text. Read from Gmail now (the
    // service stores no email text), with addresses, phone numbers and long numbers already replaced as the
    // model sees them; nothing is stored or moved, and Activity notes who looked.
    async aiContext(key, by) {
        const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };
        const rec = await this.store.getRecord(key);
        if (!rec || !rec.user || !rec.messageId) fail(404, 'That email isn\'t recorded.');
        let msg;
        try { msg = await this.gmail.raw(rec.user, rec.messageId); }
        catch (e) { if (e && e.status === 404) fail(404, 'The email is no longer in the mailbox (deleted for good): its text can\'t be read.'); throw e; }
        if (!msg || !msg.raw || !msg.raw.length) fail(404, 'The email is no longer in the mailbox: its text can\'t be read.');
        const facts = await readMessage(msg.raw, { ownDomains: this.cfg.orgDomains });
        const allowlisted = isAllowed(this.cfg, facts.senderAddress), verified = senderVerified(facts);
        const result = await analyze(facts, { mailbox: rec.user, orgDomains: this.cfg.orgDomains, allowLinkDomains: this.cfg.allowLinkDomains, trusted: allowlisted && verified, firstTime: false, intel: this.intel, keepAiFacts: true, aiInside: this.aiReadsInside(), lookalikes: await this.lookalikeMap() });
        const skipped = result.ai && result.ai.skipped;
        // (0.5.66) The whole email: every sentence of its visible text (the service reads at most about 20,000
        // characters of any email), not only the 8,000 the model is given; the model's own cut of a long text keeps
        // its start and end, so the score is the same.
        const reading = !skipped && result.language.english ? await aiReading(Object.assign({}, result.aiFacts, { bodyText: String(facts.visibleText || '') })) : null;
        await this.store.addEvent({ kind: 'check', user: rec.user,
            text: `${by} opened an email (the whole email and what the AI reads of it) to ${rec.user} from ${(rec.sender && rec.sender.domain) || 'an unknown sender'} (read from Gmail just now; nothing stored).` });
        // (0.6.6) The email itself, whatever the AI did with it (it skips mail from inside and other languages, and a
        // picture or an attachment has no text for it): as received, read from Gmail now, never stored. Text only:
        // the page never renders its HTML, loads its pictures or makes its links clickable.
        const cut = (t, n) => { t = String(t || ''); return t.length > n ? `${t.slice(0, n)}…` : t; };
        const ppl = (l) => (l || []).slice(0, 50).map(p => ({ name: cut(p.name, 200), address: cut(p.address, 320) }));
        const email = {
            subject: cut(facts.subject, 1000), date: facts.date || null,
            from: { name: cut(facts.senderName, 200), address: facts.senderAddress }, to: ppl(facts.people && facts.people.to), cc: ppl(facts.people && facts.people.cc),
            replyTo: ppl(facts.people && facts.people.replyTo),
            text: cut(facts.visibleText, 20000), quoted: cut(facts.quotedText, 20000), hidden: cut(facts.hiddenText, 5000),
            links: (facts.links || []).slice(0, 200).map(l => ({ text: cut(l.text, 300), href: cut(l.href, 2000), hidden: !!l.hidden })),
            attachments: (facts.attachments || []).slice(0, 50).map(a => ({ name: cut(a.name, 300), type: cut(a.type, 100), size: a.size || 0 })),
            pictures: facts.pictures || 0
        };
        return { language: result.language, reading, skipped: skipped || null, email };
    }

    // An email re-scanned (Review, Messages, its page: Re-scan): read again from its mailbox and judged as it
    // would be now, with today's checks and model, as "Check an email" does. Its scores, AI opinion and signs
    // become the new ones (the email's page shows the newest scan); what they were on arrival is kept once
    // (arrival), and what happened to it (moved, flagged...) stays: nothing is moved, and the admin decides
    // with the usual buttons. Noted in Activity. (0.6.6) Refused within RESCAN_COOLDOWN_MS of the email's last
    // re-scan, or when more than RESCAN_QUEUE_MAX wait for a slot (server.js refuses the same email twice at once).
    async rescan(key, by) {
        const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };
        const before = await this.store.getRecord(key);
        const ago = before && before.rescan && before.rescan.at ? this.now() - before.rescan.at : Infinity;
        if (ago < RESCAN_COOLDOWN_MS) fail(429, `This email was re-scanned ${Math.max(1, Math.round(ago / 1000))} seconds ago${before.rescan.by ? ` by ${before.rescan.by}` : ''}: it can be re-scanned again in ${Math.ceil((RESCAN_COOLDOWN_MS - ago) / 1000)} seconds.`);
        if (this.rescanSlots.waiting.length >= RESCAN_QUEUE_MAX) fail(429, 'Many emails are being re-scanned right now: try again in a moment.');
        return this.rescanSlots.run(() => this.rescanNow(key, by));
    }
    async rescanNow(key, by) {
        const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };
        const rec = await this.store.getRecord(key);
        if (!rec || !rec.user || !rec.messageId) fail(404, 'That email isn\'t recorded.');
        let msg;
        try { msg = await this.gmail.raw(rec.user, rec.messageId); }
        catch (e) { if (e && e.status === 404) fail(404, 'The email is no longer in the mailbox (deleted for good): it can\'t be re-scanned.'); throw e; }
        if (!msg || !msg.raw || !msg.raw.length) fail(404, 'The email is no longer in the mailbox: it can\'t be re-scanned.');
        const facts = await readMessage(msg.raw, { ownDomains: this.cfg.orgDomains });
        if (ownSentCopy(rec.user, msg, facts)) fail(409, `This copy is ${rec.user}'s own sent message (it was never delivered to them), so it isn't judged. Mark it Not phishing to clear it from the review.`);
        const allowlisted = isAllowed(this.cfg, facts.senderAddress), verified = senderVerified(facts);
        // The sender counts as new if it was on arrival (by now it isn't, and that would change the rules'
        // score, not the model or the checks): from the arrival's signs, kept with them after a re-scan.
        const firstTime = rec.arrival ? !!rec.arrival.firstTime : (rec.signals || []).some(x => x && x.kind === 'first-time');
        const result = await analyze(facts, { mailbox: rec.user, orgDomains: this.cfg.orgDomains, allowLinkDomains: this.cfg.allowLinkDomains, trusted: allowlisted && verified, firstTime, intel: this.intel, colleagues: await this.colleagueNames(), selfNameHash: this.selfNameHash(rec.user), aiInside: this.aiReadsInside(), lookalikes: await this.lookalikeMap(),
            threadSize: await this.threadSizeOf(rec.user, rec.threadId, facts) });
        result.allowlistedUnverified = allowlisted && !verified;
        const decision = decide(result, this.cfg, {});
        const ai = aiRecord(result.ai, this.cfg);
        // What it was on arrival: kept from the first re-scan on (a record re-scanned by 0.5.3 still has it in ai).
        const arrival = rec.arrival || { at: rec.processedAt, score: rec.score, status: rec.status, firstTime,
            ai: rec.ai && typeof rec.ai.probability === 'number' ? { probability: rec.ai.probability, model: rec.ai.model || null } : null };
        const rescan = {
            at: this.now(), by, mode: this.cfg.mode,
            model: ai ? ai.model : null, ai: ai && typeof ai.probability === 'number' ? ai.probability : null,
            score: result.score, status: result.status, action: decision.action, trigger: decision.trigger, why: decision.why
        };
        const patch = { rescan, arrival, ai, score: result.score, status: result.status, signals: result.signals.slice(0, 20), links: result.links.slice(0, 10), checks: result.checks || null, inside: !!result.inside, attachmentFindings: (result.attachmentFindings || []).slice(0, 12) };
        const record = await this.store.updateRecord(key, patch);
        const pc = (x) => (typeof x === 'number' ? `${Math.round(x * 100)}%` : 'none');
        const was = arrival.ai ? arrival.ai.probability : null;
        const now = { move: 'it would be moved to Spam', 'would-move': 'it would be recorded as "would move"', flag: 'it would be recorded as suspicious', none: 'nothing would happen' }[decision.action] || decision.action;
        await this.store.addEvent({ kind: 'check', user: rec.user,
            text: `${by} re-scanned an email to ${rec.user} from ${(rec.sender && rec.sender.domain) || 'an unknown sender'}: AI ${pc(rescan.ai)} with ${rescan.model || 'no model'} (${pc(was)} on arrival${arrival.ai && arrival.ai.model && arrival.ai.model !== rescan.model ? ` with ${arrival.ai.model}` : ''}), rules score ${rescan.score} (${arrival.score} on arrival); now ${now}. Nothing was moved.` });
        return { record, rescan };
    }

    // An email that came into the Inbox other than by arriving there (the user took it out of Spam, or
    // moved it from another folder) and that the service never checked: checked now and recorded, never
    // moved (the user put it there), with an alert when the checks flag it. Older mail moved back from an
    // archive (over 7 days) is left alone.
    async checkUnseenInbox(user, id) {
        const claim = await this.store.claim(user, id, this.now(), CLAIM_LEASE_MS);
        if (claim.done || claim.busy) return null;
        try {
            let msg;
            try { msg = await this.gmail.raw(user, id); }
            catch (e) { if (e instanceof GoogleApiError && e.status === 404) { await this.store.markSeen(user, id); return null; } throw e; }
            const recent = msg.internalDate && this.now() - msg.internalDate < 7 * DAY;
            let out = null;
            if (recent && msg.labelIds.includes('INBOX') && !msg.labelIds.some(l => l === 'SENT' || l === 'DRAFT' || l === 'SPAM')) {
                out = await this.emailSlots.run(() => this.readAndJudge(user, msg, { userPlaced: true }));
            }
            await this.store.markSeen(user, id, (out && out.recheckIndex) || {});
            return out;
        } catch (e) { await this.store.unclaim(user, id).catch(() => {}); throw e; }
    }

    // After a gap in a mailbox's history: its Inbox mail since b.after is checked, 25 at a time with each
    // notification, until done (messages already checked are skipped by their claim).
    async backfillStep(user, b) {
        const { ids, next } = await this.gmail.search(user, `in:inbox after:${Math.floor(b.after / 1000)}`, { max: 25, pageToken: b.pageToken || null });
        let checked = b.checked || 0;
        for (const id of ids) {
            try { const r = await this.processMessage(user, id); if (r && !r.busy) checked++; }
            catch (e) { this.log.error(`backfill ${user} ${id}:`, e); }
        }
        if (next) { await this.store.putUser(user, { backfill: Object.assign({}, b, { pageToken: next, checked }) }); return { more: true, checked }; }
        await this.store.putUser(user, { backfill: null });
        await this.store.addEvent({ kind: 'gap', user, text: `Caught up on ${user}'s Inbox after the gap: ${checked} emails checked.` });
        return { more: false, checked };
    }

    checkMessage(user, id, tries) { return this.emailSlots.run(() => this.checkMessageNow(user, id, tries)); }
    async checkMessageNow(user, id, tries) {
        let msg;
        try { msg = await this.gmail.raw(user, id); }
        catch (e) { if (e instanceof GoogleApiError && e.status === 404) return null; throw e; } // deleted before it was read
        // The service's own weekly summary (put in an admin's Inbox): never judged.
        if (isSummary(msg.raw)) return null;
        // An earlier try that moved it and failed before its record was written: write the record now,
        // without moving it again (it has the service's own label, which only the service adds).
        if (tries > 1 && !(await this.store.getRecord(recordKey(user, id)))
            && msg.labelIds.includes(await this.gmail.labelId(user, this.cfg.movedLabel))) {
            return this.readAndJudge(user, msg, { alreadyMoved: true });
        }
        // Only mail that arrived in the Inbox: not the user's own sent mail or drafts, nor what Gmail already put in Spam.
        if (!msg.labelIds.includes('INBOX') || msg.labelIds.some(l => l === 'SENT' || l === 'DRAFT' || l === 'SPAM')) return null;
        return this.readAndJudge(user, msg);
    }

    // Analysis, decision, action and record for one message (also used by the tests and the demo).
    // alreadyMoved: an earlier try moved it (and was counted); only the record is written.
    // userPlaced: the user moved it into the Inbox themselves (checkUnseenInbox): never moved.
    async judge(user, msg, facts, { alreadyMoved = false, userPlaced = false } = {}) {
        if (!alreadyMoved && ownSentCopy(user, msg, facts)) return { user, messageId: msg.id, action: 'none', own: true };
        const now = this.now();
        const day = this.dayOf(now);
        if (!alreadyMoved) await this.count(day, 'scanned');
        // A phishing-training email (Settings → Phishing training, 0.5.44): let through, unchecked, only counted.
        const training = alreadyMoved ? null : await this.trainingOf(facts);
        if (training) { await this.count(day, 'training'); await this.noteTraining(training); return { user, messageId: msg.id, action: 'none', training: training.name }; }
        // Both never change once set, so each instance asks Firestore once: when the service was installed,
        // and when each sender was first seen (a campaign's 10,000 copies cost one look, not 10,000).
        const installedAt = this.installedAt || (this.installedAt = (await this.store.getState('installedAt')) || (await this.store.setState('installedAt', now), now));
        // A platform's notification for a person (a Drive share, DocuSign…) is first seen by the person's own
        // address, not the platform's, which every share comes from (0.5.16).
        const relay = platformNotification(facts, this.cfg.orgDomains);
        const who = relay ? relay.address : facts.senderAddress;
        // (0.6.7) What the checks need from elsewhere, asked at once (they were asked one after another).
        const [first, shareReach, threadSize, colleagues, lookalikes] = await Promise.all([who ? this.firstSeen(senderHash(who), now) : now,
            alreadyMoved ? 0 : this.countShare(facts, user, now), this.threadSizeOf(user, msg.threadId, facts), this.colleagueNames(), this.lookalikeMap()]);
        const learning = now - installedAt < this.cfg.firstSeenLearningDays * DAY;
        // Allowlisted only with DMARC passing for the address (policy.js).
        const allowlisted = isAllowed(this.cfg, facts.senderAddress), verified = senderVerified(facts);
        const result = await analyze(facts, { mailbox: user, orgDomains: this.cfg.orgDomains, allowLinkDomains: this.cfg.allowLinkDomains, trusted: allowlisted && verified, firstTime: !!who && !learning && now - first < DAY, intel: this.intel,
            colleagues, selfNameHash: this.selfNameHash(user), shareReach, aiInside: this.aiReadsInside(), lookalikes, threadSize });
        result.allowlistedUnverified = allowlisted && !verified;
        await this.applySpamMemory(user, facts, result);
        // (0.6.7) The brake is read only when it matters: when the email would be moved (enforce mode). It was read
        // for every email; the decision is the same.
        let decision = decide(result, this.cfg, { brake: false });
        if (!alreadyMoved && decision.action === 'move' && await this.brakeOn(now)) decision = decide(result, this.cfg, { brake: true });
        if (alreadyMoved) decision = { action: 'move', trigger: decision.trigger, why: `${decision.why || 'moved'} (moved by an earlier try)` };
        if (userPlaced && (decision.action === 'move' || decision.action === 'would-move')) {
            decision = { action: 'flag', trigger: decision.trigger, why: `${decision.why}; the user moved it into the Inbox themselves (out of Spam or another folder), so it isn't moved` };
        }
        if (decision.action === 'none') return this.withIndex({ user, messageId: msg.id, action: 'none', status: result.status, ai: result.ai && result.ai.probability }, msg, facts, result);
        const senderDomain = (facts.senderAddress.split('@')[1] || '').toLowerCase();
        const campaign = campaignOf(senderDomain, facts.subject, user);
        const campaignLabel = this.cfg.storeSubjects ? campaign.label : senderDomain;
        // The brake was already on (decide): held for the admin's resume.
        let held = decision.braked ? 'brake' : null;
        if (decision.action === 'move' && !alreadyMoved) ({ decision, held } = await this.brakes(decision, result, campaign.key, campaignLabel, now));

        let state = 'inbox';
        if (decision.action === 'move') {
            if (!alreadyMoved) {
                const moved = await this.gmail.labelId(user, this.cfg.movedLabel);
                await this.gmail.modify(user, msg.id, ['SPAM', moved], ['INBOX']);
            }
            state = 'moved';
        } else if (decision.action === 'would-move' && this.cfg.monitorLabel) {
            await this.gmail.modify(user, msg.id, [await this.gmail.labelId(user, this.cfg.monitorLabel)], []);
        }
        // Suspicious, not moved: a label its reader sees, when the setting is on (0.5.33; off by default).
        let labeled = false;
        if (decision.action === 'flag' && this.cfg.suspiciousLabel) {
            try { await this.gmail.modify(user, msg.id, [await this.gmail.labelId(user, this.cfg.suspiciousLabelName)], []); labeled = true; }
            catch (e) { this.log.error(`suspicious label ${user} ${msg.id}:`, e); }
        }
        const rec = this.recordOf(user, msg, facts, result, decision, { now, campaign, campaignLabel, senderDomain, held, state, userPlaced, labeled });
        await this.store.saveRecord(rec);
        await this.count(day, decision.action === 'move' ? 'moved' : decision.action === 'would-move' ? 'wouldMove' : 'flagged');
        if (decision.action === 'move' && !this.alerted.has(campaign.key)) {
            // (counted until the campaign's alert is sent; after that this instance writes nothing more)
            if (await this.store.campaignMoved(campaign.key, this.cfg.campaignAlertAfter, now, () => this.alerted.add(campaign.key))) {
                await this.alert('campaign', `A large campaign: ${this.cfg.campaignAlertAfter} copies of "${campaignLabel}" moved to Spam so far (${rec.evidence} evidence). The dashboard's Threats → Campaigns page lists who received it.`, { campaign: campaign.key });
            }
        }
        if (userPlaced && result.status === 'flagged') {
            await this.alert('user-inbox', `${user} moved an email from ${rec.sender.address} into their Inbox (it didn't arrive there), and the checks flag it (score ${rec.score}). Make sure it's safe, or confirm it as phishing and warn them.`, { user, key: rec.key });
        }
        return state === 'moved' ? rec : this.withIndex(rec, msg, facts, result);
    }

    // An email left in the Inbox keeps a few hashes with its "checked" marker, to be found again when a
    // phishing list later adds its link site or its sender (src/recheck.js; RECHECK, on by default).
    // They go with the marker's own write (processMessage): no write of their own. Not enumerable, so the
    // object returned stays what it was.
    withIndex(out, msg, facts, result) {
        if (!this.cfg.recheck) return out;
        try {
            const ix = recheckIndex(spruce.load(), { urls: result.linkUrls || [], sender: facts.senderAddress, replyTo: facts.replyTo || [], orgDomains: this.cfg.orgDomains });
            if (ix.length) Object.defineProperty(out, 'recheckIndex', { value: { ix, rx: Number(msg.internalDate) || this.now() }, enumerable: false });
        } catch (e) { this.log.error('re-check index:', e); }
        return out;
    }

    // An email's record (judge, and recheckMessage since 0.5.35): what the dashboard shows and keeps.
    recordOf(user, msg, facts, result, decision, { now, campaign, campaignLabel, senderDomain, held = null, state, userPlaced = false, labeled = false }) {
        return {
            key: recordKey(user, msg.id), user, messageId: msg.id, threadId: msg.threadId || '',
            // The message's history id when it was read: an Inbox label added after it is the user's.
            readHistoryId: msg.historyId ? String(msg.historyId) : null,
            rfc822MessageId: messageIdOf(facts.messageIdHeader),
            receivedAt: msg.internalDate || facts.date || now, processedAt: now,
            sender: { name: facts.senderName.slice(0, 200), address: facts.senderAddress.slice(0, 320), domain: senderDomain },
            subject: this.cfg.storeSubjects ? facts.subject.slice(0, 300) : '',
            campaign: campaign.key, campaignLabel,
            status: result.status, score: result.score, signals: result.signals.slice(0, 20), links: result.links.slice(0, 10), checks: result.checks || null,
            ai: aiRecord(result.ai, this.cfg),
            auth: facts.auth ? Object.assign({ dmarc: facts.auth.dmarc, spf: facts.auth.spf, dkim: facts.auth.dkim }, facts.auth.derived ? { derived: facts.auth.derived } : {}) : null,
            attachments: facts.attachments.slice(0, 10).map(a => ({ name: a.name.slice(0, 120), type: a.type })),
            attachmentFindings: (result.attachmentFindings || []).slice(0, 12),
            action: decision.action, trigger: decision.trigger, why: decision.why, braked: held === 'brake', held, mode: this.cfg.mode,
            // How sure: strong = the rules flagged it and something outside the email confirms it.
            evidence: result.strong ? 'strong' : 'weak', confirmedBy: result.confirmedBy || [],
            ownAddressUnverified: !!(result.ownAddress && !result.inside), userPlaced: userPlaced || undefined,
            // From inside the organization (your domains, DMARC passing), as the policy judged it (Model health).
            inside: !!result.inside,
            state, releasedBy: null, releasedAt: null, falseAlarm: null, markedBy: null,
            suspiciousLabel: labeled || undefined
        };
    }

    // The brakes, for a move about to be made (enforce mode). In order:
    //   - an admin's decision on the campaign: released (a false alarm) is never moved; confirmed is;
    //   - the campaign hold: on weak evidence (nothing outside the email confirms it), copies of one
    //     campaign beyond CAMPAIGN_HOLD_AFTER are held until an admin confirms or releases it. Strong
    //     evidence is never held, so a clear phishing campaign reaches every mailbox;
    //   - the domain-wide brake, a last resort against a misfire: more than brakeLimit() moves in the
    //     clock hour (counted exactly, a slot reserved before each move) stops moving everywhere.
    // Held copies are recorded as "would move" and can be moved later (moveHeld).
    async brakes(decision, result, campaignKey, campaignLabel, now) {
        const cs = await this.store.getCampaign(campaignKey);
        const released = (d) => ({ decision: { action: 'flag', trigger: d.trigger, why: `${d.why}; an admin dismissed this campaign as a false alarm, so its copies aren't moved` }, held: null });
        if (cs && cs.decision === 'released') return released(decision);
        if (!result.strong && !(cs && cs.decision === 'confirmed')) {
            const h = await this.store.campaignHold(campaignKey, this.cfg.campaignHoldAfter, now, campaignLabel);
            if (h.decision === 'released') return released(decision);
            if (h.held) {
                if (h.first) await this.alert('campaign-held', `Moving copies of "${campaignLabel}" is paused: more than ${this.cfg.campaignHoldAfter} were moved on evidence nothing outside the email confirms, so the next ones stay in the Inbox, like any email not moved. Confirm it as phishing (every copy is moved to Spam) or dismiss it as a false alarm (the moved ones go back to the Inbox): on the dashboard, Threats → Campaigns, then open the campaign.`, { campaign: campaignKey });
                return { decision: { action: 'would-move', trigger: decision.trigger, why: `${decision.why} (not moved: moving this campaign is paused after ${this.cfg.campaignHoldAfter} copies on evidence nothing outside the email confirms, until an admin confirms it or dismisses it)` }, held: 'campaign' };
            }
        }
        const resumedAt = Number(await this.store.getState('brakeResumedAt')) || 0;
        const limit = await this.brakeLimit();
        const slot = await this.store.reserveMove(`${hourOf(now)}|${resumedAt}`, limit, now);
        if (!slot.ok) {
            await this.tripBrake(now, slot.count, limit);
            return { decision: { action: 'would-move', trigger: decision.trigger, why: `${decision.why} (brake on: not moved)`, braked: true }, held: 'brake' };
        }
        return { decision, held: null };
    }
    // The domain-wide limit: BRAKE_PER_HOUR, or half the watched mailboxes (at least 100).
    async brakeLimit() {
        if (this.cfg.brakePerHour > 0) return this.cfg.brakePerHour;
        return Math.max(100, Math.ceil((Number(await this.store.getState('watchedCount')) || 0) / 2));
    }
    // The brake comes on: only the instance that sets it first alerts (the others' moves were refused too).
    async tripBrake(now, count, limit) {
        if (!(await this.store.setStateIfUnset('brake', { at: now, moves: count, limit }))) return;
        await this.alert('brake', `${count} emails were moved within the hour (limit ${limit}). Moving has stopped in every mailbox: from now on, emails that would be moved stay in the Inbox, like any other email, until an admin resumes on the dashboard (Today), which can also move them then.`);
    }

    // An alert: in Health → Activity (and Today's Recent activity), and a log line Cloud Monitoring emails to
    // ALERT_EMAIL (install.sh).
    // (0.6.26) Spam memory. A sender is its domain (its organization's registrable domain), or the address itself at a
    // personal mail provider (gmail.com: one person, not everyone there). Kept as one-way hashes with the person's.
    spamSenderKey(address) {
        const a = String(address || '').toLowerCase(), d = a.split('@')[1] || '';
        if (!d) return '';
        const E = spruce.load();
        return E.isPersonalMailDomain(d) ? a : (E.registrableDomain(d) || d);
    }
    async rememberSpamRescue(user, address, now = this.now()) {
        const sender = this.spamSenderKey(address);
        if (!sender) return;
        const who = senderHash(user);
        await this.store.setCached('spamok', `${who}|${senderHash(sender)}`, { at: now }, SPAM_KEEP_MS);
        const all = Object.assign({}, (await this.store.getState('spamRescued')) || {});
        for (const [k, v] of Object.entries(all)) if (!v || now - (v.last || 0) > SPAM_KEEP_MS) delete all[k];
        const e = all[sender] = Object.assign({ users: [], first: now, shared: false, keep: false }, all[sender]);
        if (!e.users.includes(who)) e.users = [...e.users, who].slice(-50);
        e.last = now;
        const becameShared = !e.shared && e.users.length >= SPAM_SHARED;
        if (becameShared) e.shared = true;
        const keys = Object.keys(all).sort((a, b) => (all[b].last || 0) - (all[a].last || 0));
        for (const k of keys.slice(SPAM_RESCUED_MAX)) delete all[k];
        await this.store.setState('spamRescued', all);
        if (becameShared && !e.keep) await this.store.addEvent({ kind: 'spam-rescued', text: `${e.users.length} people took mail from ${sender} back out of Spam, where the service had moved it as spam. Its mail is no longer moved as spam for anyone (it is still checked for phishing). If it is mail your district wants, add it to Settings → Allowlist; if it is spam after all, choose "Keep moving it" in Settings → Allowlist → Spam people took back.` });
    }
    // Whether this person (or, once SPAM_SHARED people took it back, everyone) keeps this sender's spam: null, or why.
    async spamKept(user, address) {
        const sender = this.spamSenderKey(address);
        if (!sender) return null;
        if (await this.store.getCached('spamok', `${senderHash(user)}|${senderHash(sender)}`)) return 'they took mail from this sender back out of Spam before';
        const e = ((await this.store.getState('spamRescued')) || {})[sender];
        if (e && e.shared && !e.keep && this.now() - (e.last || 0) <= SPAM_KEEP_MS) return `${e.users.length} people took mail from this sender back out of Spam`;
        return null;
    }
    // Applies the memory to an analyzed email: spam from a verified sender someone kept is not moved as spam.
    async applySpamMemory(user, facts, result) {
        if (!result || !result.spam || !result.verified) return;
        const why = await this.spamKept(user, facts.senderAddress).catch(() => null);
        if (why) result.spam = undefined;
    }
    // Settings → Allowlist: the senders several people took back (0.6.26), newest first; keep: an admin's "keep moving it".
    async spamRescuedList() {
        const all = (await this.store.getState('spamRescued')) || {};
        const now = this.now();
        return Object.entries(all).filter(([, v]) => v && v.shared && now - (v.last || 0) <= SPAM_KEEP_MS)
            .map(([sender, v]) => ({ sender, people: v.users.length, first: v.first, last: v.last, keep: !!v.keep, keepBy: v.keepBy || null }))
            .sort((a, b) => b.last - a.last);
    }
    async setSpamKeep(sender, keep, by) {
        const all = Object.assign({}, (await this.store.getState('spamRescued')) || {});
        const e = all[String(sender || '').toLowerCase()];
        if (!e || !e.shared) return { error: 'That sender isn\'t on the list.', status: 404 };
        all[String(sender).toLowerCase()] = Object.assign({}, e, { keep: !!keep, keepBy: keep ? by : null });
        await this.store.setState('spamRescued', all);
        await this.store.addEvent({ kind: 'settings', text: keep ? `${by} chose to keep moving spam from ${sender} to Spam, though ${e.users.length} people took some back (each of them still keeps it).`
            : `${by} chose to stop moving spam from ${sender} for everyone, as ${e.users.length} people took some back.` });
        return { ok: true, list: await this.spamRescuedList() };
    }
    async alert(kind, text, extra = {}) {
        await this.store.addEvent(Object.assign({ kind, text, alert: true }, extra));
        if (this.log.warn) this.log.warn(JSON.stringify({ severity: 'WARNING', spruceAlert: kind, message: text }));
    }
    // Alerts are the problems the admins are emailed about (0.5.28): a list that missed its download, a
    // service or the AI model that stopped working, the brake, a campaign paused… An admin's own action (a
    // policy change, an update started, a Safe Browsing key) isn't one: it is recorded in Activity → What
    // admins did, and not emailed.
    async adminNotice(kind, text, extra = {}) { await this.store.addEvent(Object.assign({ kind, text, admin: true }, extra)); }
    // A "RE:" email's conversation size in this mailbox (0.5.33: a fake reply chain), only for one that names
    // an earlier email (one that names none needs no look); null when unknown.
    async threadSizeOf(user, threadId, facts) {
        if (!threadId || !this.gmail.threadSize || !looksLikeReply(facts.subject) || !(facts.inReplyTo || (facts.references || []).length)) return null;
        try { return await this.gmail.threadSize(user, threadId); } catch (e) { return null; }
    }
    // Gmail refusing the service (0.5.29): domain-wide delegation removed or its scopes changed, the service
    // account's token refused. Every email then goes unchecked, while Gmail's notifications keep coming (so
    // the "quiet" alert never fires): the admins are told at once, then once a day while it lasts.
    static isGmailAccessError(e) {
        const m = String((e && e.message) || e || '');
        return /^token for .*: HTTP 4\d\d/.test(m) || /unauthorized_client|invalid_grant|Delegation denied|domain-wide delegation/i.test(m)
            || (e && (e.status === 401 || (e.status === 403 && !/rateLimitExceeded|userRateLimitExceeded/i.test(m))));
    }
    async gmailTrouble(e, user) {
        if (!Service.isGmailAccessError(e)) return false;
        return this.alertDaily('gmail-access', `Gmail refused the service for ${user} (${String((e && e.message) || e).slice(0, 200)}): new mail there isn't checked. Usually the domain-wide delegation was removed or its scopes changed: Admin console → Security → Access and data control → API controls → Manage Domain Wide Delegation (docs/INSTALL.md, step 3). bash deploy/doctor.sh checks the rest. More: docs/ALERTS.md, "Gmail refused the service".`).catch(() => false);
    }
    // An alert at most once a day (per kind and UTC day, whichever instance sees it first): for a problem that
    // lasts (a lookup service down, the AI model not loading). key: once a day per key instead (a mailbox).
    async alertDaily(kind, text, extra = {}, { key = kind } = {}) {
        if (!(await this.store.setStateIfUnset(`alert-${key}-${new Date(this.now()).toISOString().slice(0, 10)}`, { at: this.now() }))) return false;
        await this.alert(kind, text, extra);
        return true;
    }
    // Missed changes (0.5.31). One now and then is normal: Gmail keeps a mailbox's history for about a week,
    // and the service catches up on the Inbox by itself. Many are a sign something is wrong, and an alert
    // (once a day): across the organization, GAPS_DAY or more within 24 hours (notifications weren't processed
    // for days: the worker down or failing, Pub/Sub backing up); one mailbox, GAPS_MAILBOX or more within 7
    // days (its watch, or a bug). Both are settings (GAPS_ALERT_DAY, GAPS_ALERT_MAILBOX).
    async gapCheck(user) {
        const now = this.now();
        const missed = (e) => e.kind === 'gap' && (e.missed === true || /were missed \(history too old\)|fell behind on/.test(String(e.text || '')));
        const week = (await this.store.listEvents(now - 7 * DAY, { limit: 5000 })).filter(missed);
        const day = week.filter(e => e.at >= now - DAY);
        const mine = week.filter(e => e.user === user);
        const perDay = this.cfg.gapsAlertDay || GAPS_DAY, perMailbox = this.cfg.gapsAlertMailbox || GAPS_MAILBOX;
        const out = { day: day.length, mailbox: mine.length, alerted: [] };
        if (day.length >= perDay) {
            const boxes = new Set(day.map(e => e.user)).size;
            if (await this.alertDaily('gaps', `The service fell behind on ${boxes} mailbox${boxes === 1 ? '' : 'es'} in the last 24 hours (${day.length} time${day.length === 1 ? '' : 's'}). `
                + `What happened: Gmail no longer had the list of what changed in ${boxes === 1 ? 'that mailbox' : 'those mailboxes'} since the service last looked (it keeps about a week), so the service started again from now and is checking the mail still in each Inbox from that time. `
                + `What it means for mail: new mail reached those Inboxes before it was checked; mail still in the Inbox is being checked now, but mail already deleted or moved out of the Inbox wasn't. `
                + `Why: once in a while is normal, after an outage. This many usually means Gmail's notifications weren't being processed for days (the worker stopped or kept failing, Pub/Sub backed up), or a bug. `
                + `What to do: 1) Health → Service status: are the worker, the jobs and the notifications all right now? 2) Health → Activity → Errors and gaps: since when? 3) In Cloud Shell: bash deploy/doctor.sh. If you know why (an outage, a long upgrade), nothing more is needed: the service catches up by itself ("Caught up on …" in Activity). `
                + `More: docs/ALERTS.md, "The service fell behind".`)) out.alerted.push('gaps');
        }
        if (mine.length >= perMailbox) {
            if (await this.alertDaily('gaps-mailbox', `The service fell behind on ${user}'s mailbox ${mine.length} times in the last 7 days. `
                + `What happened: each time, Gmail no longer had the list of what changed in that mailbox since the service last looked, so the service started again and checked the mail still in its Inbox. `
                + `What it means for mail: mail that arrived meanwhile reached the Inbox before it was checked; mail deleted or moved out of the Inbox meanwhile wasn't checked. `
                + `Why: once in a while is normal; this often for one mailbox usually means Gmail stops notifying the service about it, a problem with that account, or a bug. Other mailboxes aren't affected unless they have their own alert. `
                + `What to do: 1) Settings → Mailboxes: when did Gmail last notify the service about it? 2) Settings → Mailboxes → Read the directory again now (it renews every watch). 3) Admin console → Users: is the account active, licensed, with Gmail on? If it goes on, it may be a bug: note the mailbox and the times (Health → Activity, search for it). `
                + `More: docs/ALERTS.md, "The service fell behind on one mailbox".`, { user }, { key: `gaps-${senderHash(user)}` })) out.alerted.push('gaps-mailbox');
        }
        return out;
    }

    async brakeOn() { return !!(await this.store.getState('brake')); }
    // The admin resumes: the hour's count starts again (a new counter), and with moveHeld the copies the
    // brake held since it came on are moved now (those still in the Inbox).
    async resume(by, { moveHeld = false } = {}) {
        const brake = await this.store.getState('brake');
        await this.store.setState('brakeResumedAt', this.now());
        await this.store.setState('brake', null);
        const out = moveHeld && brake ? await this.moveHeld(r => r.held === 'brake' && r.processedAt >= brake.at, by, 'resumed moving', { sinceMs: brake.at }) : null;
        await this.store.addEvent({ kind: 'resume', text: `Moving resumed by ${by}${out ? (out.monitor ? '' : `; ${out.moved} emails left in the Inbox while the brake was on were moved to Spam${out.gone ? `, ${out.gone} no longer in the Inbox` : ''}`) : ''}.` });
        return { ok: true, held: out };
    }

    // Moves held or recorded copies now, those still in the Inbox (an admin's resume or confirmation;
    // not counted by the brake). Enforce mode only. { moved, gone, failed, left }.
    // records: the candidates when the caller has them (a campaign's), else the last 14 days' (or sinceMs on).
    async moveHeld(match, by, how, { budgetMs = 200000, max = 5000, records = null, sinceMs = null } = {}) {
        if (this.cfg.mode !== 'enforce') return { moved: 0, gone: 0, failed: 0, left: 0, monitor: true };
        const recs = (records || await this.store.listRecords({ sinceMs: sinceMs !== null ? sinceMs : this.now() - 14 * DAY, limit: 100000 }))
            .filter(r => r.state === 'inbox' && r.action !== 'move' && match(r)).slice(0, max);
        const start = Date.now();
        const out = { moved: 0, gone: 0, failed: 0, left: 0 };
        await pool(recs, 10, async (r) => {
            try { out[await this.moveRecord(r, by, how)]++; } catch (e) { out.failed++; this.log.error(`move held ${r.key}:`, e); }
        }, () => Date.now() - start > budgetMs);
        out.left = recs.length - out.moved - out.gone - out.failed;
        return out;
    }
    // One recorded email still in the Inbox, moved to Spam because an admin decided so (the caller checks
    // enforce mode). 'moved', or 'gone' when it isn't in the Inbox any more (deleted, archived, moved by
    // the user), and then it is left where it is.
    async moveRecord(r, by, how) {
        let labels = null;
        try { labels = await this.gmail.labels(r.user, r.messageId); } catch (e) { if (!(e instanceof GoogleApiError && e.status === 404)) throw e; }
        if (!labels || !labels.includes('INBOX')) return 'gone';
        await this.gmail.modify(r.user, r.messageId, ['SPAM', await this.gmail.labelId(r.user, this.cfg.movedLabel)], ['INBOX']);
        const now = this.now();
        await this.store.updateRecord(r.key, { action: 'move', state: 'moved', held: null, braked: false, why: `${r.why}; moved when ${by} ${how}`, heldMovedBy: by, heldMovedAt: now });
        await this.store.incStat(this.dayOf(now), 'moved');
        return 'moved';
    }

    // --- Campaigns: an admin's decision for every copy -----------------------------------------
    // A campaign's records (of the last 90 days): asked of the store by campaign, not found among the newest.
    async campaignRecords(key) { return this.store.listCampaignRecords(key, this.now() - 90 * DAY); }
    // Confirmed as phishing: every recorded copy still in the Inbox is moved (enforce mode), every copy
    // is marked phishing, later copies are moved without being held, and with search the watched
    // mailboxes are searched for copies the service didn't record (findCopies).
    async confirmCampaign(key, by, { search = false } = {}) {
        const recs = await this.campaignRecords(key);
        if (!recs.length) return { error: 'not found', status: 404 };
        // Within the dashboard's request time (5 minutes): moving first, then searching with what is left.
        const start = Date.now();
        await this.store.setCampaign(key, { decision: 'confirmed', decidedBy: by, decidedAt: this.now(), label: recs[0].campaignLabel });
        const moved = await this.moveHeld(r => r.campaign === key, by, 'confirmed the campaign as phishing', { budgetMs: 150000, records: recs });
        for (const r of recs) if (r.falseAlarm !== false) await this.store.updateRecord(r.key, { falseAlarm: false, markedBy: by });
        const found = search ? await this.findCopies(key, by, { budgetMs: Math.max(30000, 240000 - (Date.now() - start)) }) : null;
        await this.store.addEvent({ kind: 'campaign', campaign: key, text: `${by} confirmed "${recs[0].campaignLabel}" as phishing${moved.monitor ? ' (monitor mode: nothing moved)' : `: ${moved.moved} copies moved to Spam`}${found ? `; a search of ${found.searched} mailboxes found ${found.found} more${found.moved ? `, ${found.moved} moved` : ''}` : ''}.` });
        return { moved, found };
    }
    // A false alarm: every moved copy is released, every copy marked a false alarm, and later copies
    // aren't moved.
    async releaseCampaign(key, by) {
        const recs = await this.campaignRecords(key);
        if (!recs.length) return { error: 'not found', status: 404 };
        await this.store.setCampaign(key, { decision: 'released', decidedBy: by, decidedAt: this.now(), label: recs[0].campaignLabel });
        let released = 0, failed = 0;
        await pool(recs, 10, async (r) => {
            try {
                if (r.state === 'moved') { const out = await this.release(r.key, by, { quiet: true }); if (out.record) released++; }
                else if (r.falseAlarm !== true) await this.store.updateRecord(r.key, { falseAlarm: true, markedBy: by });
            } catch (e) { failed++; this.log.error(`release ${r.key}:`, e); }
        });
        await this.store.addEvent({ kind: 'campaign', campaign: key, text: `${by} dismissed "${recs[0].campaignLabel}" as a false alarm: ${released} copies moved back to the Inbox${failed ? `, ${failed} couldn't be moved back` : ''}. Later copies aren't moved.` });
        return { released, failed };
    }
    // Copies of a campaign the service didn't record (judged clean when they came, or before the pilot):
    // each watched mailbox's Inbox of the last 7 days is searched for mail from the campaign's senders (5 at most),
    // and a message counts when its sender's domain and subject make the same campaign. Confirmed
    // campaigns' copies are moved (enforce mode); others are recorded as "would move".
    async findCopies(key, by, { budgetMs = 200000 } = {}) {
        const recs = await this.campaignRecords(key);
        const senders = [...new Set(recs.map(r => r.sender && r.sender.address).filter(Boolean))].slice(0, 5);
        const users = (await this.store.listUsers()).filter(u => u.watched).map(u => u.email);
        const out = { searched: 0, of: users.length, found: 0, moved: 0, failed: 0 };
        if (!senders.length) return out;
        const cs = await this.store.getCampaign(key);
        const moving = !!(cs && cs.decision === 'confirmed') && this.cfg.mode === 'enforce';
        const known = new Set(recs.map(r => r.key));
        const q = `in:inbox newer_than:7d from:(${senders.join(' OR ')})`;
        const start = Date.now();
        await pool(users, 20, async (user) => {
            try {
                const { ids } = await this.gmail.search(user, q, { max: 50 });
                out.searched++;
                for (const id of ids) {
                    if (known.has(recordKey(user, id))) continue;
                    const m = await this.gmail.headers(user, id);
                    const address = addressOf(m.from), domain = address.split('@')[1] || '';
                    if (campaignOf(domain, m.subject, user).key !== key || !m.labelIds.includes('INBOX')) continue;
                    out.found++;
                    if (moving) await this.gmail.modify(user, id, ['SPAM', await this.gmail.labelId(user, this.cfg.movedLabel)], ['INBOX']);
                    const now = this.now();
                    await this.store.saveRecord({
                        key: recordKey(user, id), user, messageId: id, threadId: m.threadId || '', readHistoryId: null, rfc822MessageId: messageIdOf(m.messageId),
                        receivedAt: m.internalDate || now, processedAt: now,
                        sender: { name: '', address: address.slice(0, 320), domain }, subject: this.cfg.storeSubjects ? String(m.subject).slice(0, 300) : '',
                        campaign: key, campaignLabel: recs[0].campaignLabel, status: 'flagged', score: null,
                        signals: [{ weight: 0, kind: 'campaign-copy', text: `A copy of a campaign ${by} confirmed as phishing.` }], links: [], checks: null, ai: null, auth: null, attachments: [],
                        action: moving ? 'move' : 'would-move', trigger: 'admin', why: `found by ${by}'s search for copies of the campaign${moving ? '' : this.cfg.mode === 'enforce' ? ' (not moved: the campaign isn\'t confirmed)' : ' (monitor mode: not moved)'}`,
                        braked: false, held: null, mode: this.cfg.mode, evidence: 'admin', confirmedBy: [],
                        state: moving ? 'moved' : 'inbox', releasedBy: null, releasedAt: null, falseAlarm: false, markedBy: by
                    });
                    await this.store.incStat(this.dayOf(now), moving ? 'moved' : 'wouldMove');
                    if (moving) out.moved++;
                }
            } catch (e) { out.failed++; this.log.error(`find copies ${user}:`, e); }
        }, () => Date.now() - start > budgetMs);
        return out;
    }

    // Puts a moved email back in the Inbox (and records who did it).
    async release(key, by, { quiet = false } = {}) {
        const rec = await this.store.getRecord(key);
        if (!rec) return { error: 'not found' };
        if (rec.state !== 'moved') return { error: `it is ${rec.state === 'released' ? 'already back in the Inbox' : 'still in the Inbox'}` };
        const released = await this.gmail.labelId(rec.user, this.cfg.releasedLabel);
        const moved = await this.gmail.labelId(rec.user, this.cfg.movedLabel);
        // Noted first: the Inbox label this adds comes back in the history, and must not read as the user's.
        await this.store.updateRecord(key, { releasingAt: this.now() });
        await this.gmail.modify(rec.user, rec.messageId, ['INBOX', released], ['SPAM', moved]);
        const now = this.now();
        const out = await this.store.updateRecord(key, { state: 'released', releasedBy: by, releasedByUser: false, releasedAt: now, falseAlarm: rec.falseAlarm === null ? true : rec.falseAlarm, markedBy: rec.markedBy || by });
        await this.store.incStat(this.dayOf(now), 'released');
        if (!quiet) await this.store.addEvent({ kind: 'release', user: rec.user, text: `${by} moved an email from ${rec.sender.address} to ${rec.user} back to the Inbox.` });
        return { record: out };
    }
    // The user moved an email the service had put in Spam back to the Inbox (or marked it "Not spam"). The
    // service never moves it again; the record says so, counts as a false alarm (an admin can still mark
    // it phishing, which matters: a user who rescued real phishing may be about to click it).
    // at: the history id of the Inbox label; listedAsNew: the same history lists the message as new.
    async userReleased(user, messageId, { at, listedAsNew = false } = {}) {
        const key = recordKey(user, messageId);
        const rec = await this.store.getRecord(key);
        if (!rec) return { noRecord: true };
        if (rec.state !== 'moved') return null;
        // Only an Inbox label added after the service read the message can be the user's: the label it
        // arrived with can show in the same history. Where the order isn't known, a message the history
        // lists as new is taken to have arrived with it.
        const order = compareHistoryIds(at, rec.readHistoryId);
        if (order !== null ? order <= 0 : listedAsNew) return null;
        const now = this.now();
        if (rec.releasingAt && now - rec.releasingAt < 10 * 60 * 1000) return null; // an admin's release under way
        const out = await this.store.updateRecord(key, { state: 'released', releasedBy: user, releasedByUser: true, releasedAt: now,
            falseAlarm: rec.falseAlarm === null || rec.falseAlarm === undefined ? true : rec.falseAlarm, markedBy: rec.markedBy || null });
        await this.store.incStat(this.dayOf(now), 'released');
        await this.store.incStat(this.dayOf(now), 'userReleased');
        // (0.6.26) Spam (not phishing) the user took back, from a sender Gmail verified: remembered for them.
        if (rec.trigger === 'spam' && rec.auth && rec.auth.dmarc === 'pass') await this.rememberSpamRescue(user, rec.sender.address, now).catch((e) => this.log.error('spam memory:', e));
        const strong = rec.score >= 5 && rec.trigger !== 'ai';
        const text = strong ? `${user} moved an email from ${rec.sender.address} back to the Inbox, though the checks flagged it (score ${rec.score}). Make sure it's safe, or mark it phishing and warn them.`
                            : `${user} moved an email from ${rec.sender.address} back to the Inbox (counted as a false alarm).`;
        if (strong) await this.alert('user-release', text, { user, key });
        else await this.store.addEvent({ kind: 'user-release', user, key, text });
        return out;
    }

    // An admin's verdict on one email: a false alarm (not phishing), or phishing. With move, phishing that
    // is still in the Inbox is also moved to Spam, in enforce mode only (Review's "Phishing: move to
    // Spam"). moved: 'moved'; 'gone' (no longer in the Inbox); 'monitor' (nothing is moved in monitor
    // mode); 'not-in-inbox' (already in Spam, or moved back by an admin, whose decision stands); or null.
    // (0.6.26) spam: confirmed, as spam rather than phishing (falseAlarm false, spam true): Review's "Spam", and the
    // retraining export's class.
    async mark(key, falseAlarm, by, { move = false, quiet = false, spam = false } = {}) {
        const rec = await this.store.getRecord(key);
        if (!rec) return { error: 'not found' };
        let out = await this.store.updateRecord(key, Object.assign({ falseAlarm: !!falseAlarm, markedBy: by, spam: !falseAlarm && !!spam }, rec.unclear ? { unclear: false } : {}));
        if (falseAlarm && rec.falseAlarm !== true) await this.store.incStat(this.dayOf(this.now()), 'falseAlarms');
        // A false alarm loses the Suspicious label it was given (0.5.33).
        if (falseAlarm && rec.suspiciousLabel) {
            try { await this.gmail.modify(rec.user, rec.messageId, [], [await this.gmail.labelId(rec.user, this.cfg.suspiciousLabelName)]); out = await this.store.updateRecord(key, { suspiciousLabel: false }); }
            catch (e) { this.log.error(`suspicious label off ${rec.user} ${rec.messageId}:`, e); }
        }
        // (0.6.1) A false alarm that is in Spam goes back to the Inbox at once (Review, Messages, ticked together).
        let released = false;
        if (falseAlarm && rec.state === 'moved') {
            const r = await this.release(key, by, { quiet });
            if (r && r.record) { out = r.record; released = true; }
        }
        let moved = null;
        if (!falseAlarm && move) {
            await this.refreshPolicy();
            const as = spam ? 'spam' : 'phishing';
            moved = this.cfg.mode !== 'enforce' ? 'monitor' : rec.state !== 'inbox' || rec.action === 'move' ? 'not-in-inbox' : await this.moveRecord(out, by, `confirmed it as ${as}`);
            if (moved === 'moved') {
                out = await this.store.getRecord(key);
                if (!quiet) await this.store.addEvent({ kind: 'mark', user: rec.user, text: `${by} confirmed an email from ${rec.sender.address} to ${rec.user} as ${as} and moved it to Spam.` });
            }
        }
        return { record: out, moved, released };
    }

    // (0.5.60) An admin's "Ignore, treat as suspicious": neither clearly phishing nor clearly safe (an outside request
    // for access to a form, say), so the reader decides. The email stays where it is, with its Suspicious label; it
    // leaves the review queues (reviewed: markedBy), is never a training example (no falseAlarm: the retraining export
    // takes only phishing and false alarms), and the later checks and the re-check after an update leave it alone.
    // Marking it phishing or not phishing afterwards replaces this.
    async setAside(key, by, { quiet = false } = {}) {
        const rec = await this.store.getRecord(key);
        if (!rec) return { error: 'not found' };
        const out = await this.store.updateRecord(key, { unclear: true, falseAlarm: null, markedBy: by });
        if (!quiet) await this.store.addEvent({ kind: 'mark', user: rec.user, text: `${by} set aside an email from ${rec.sender.address} to ${rec.user} as unclear: left as it is, for the reader to decide, and not used for retraining.` });
        return { record: out };
    }

    // Cloud Scheduler, daily (spruce-renew-watches; also install.sh and Settings → Mailboxes' "Read the directory
    // again now"): watch every mailbox of the pilot, or of the whole domain (Settings → Mailboxes), again (a
    // watch lasts 7 days) and stop watching those no longer in it. Within budgetMs; what is left is recorded
    // (state/watchLeft) and the hourly job continues it. Switches the service on again after stopAll.
    async renewWatches({ budgetMs = RENEW_BUDGET_MS, parallel = RENEW_PARALLEL } = {}) {
        const started = Date.now();
        if (await this.store.getState('stopped')) await this.store.setState('stopped', null);   // (0.6.7) switched on again
        await this.refreshPolicy();
        const users = new Set(this.cfg.pilotUsers);
        const groups = [];
        const whole = this.cfg.watchScope === 'domain';
        let domainCount = null;
        // A failed directory read stops here, before any watch is stopped by mistake, and says so.
        try {
            // (0.5.53) The whole domain: every active mailbox of ORG_DOMAINS (Settings → Mailboxes).
            if (whole) { const all = await this.gmail.domainUsers(this.cfg.directoryAdmin, this.cfg.orgDomains); domainCount = all.length; for (const u of all) users.add(u); }
            else for (const g of this.cfg.pilotGroups) {
                const found = {};
                const members = await this.gmail.groupMembers(this.cfg.directoryAdmin, g, this.cfg.orgDomains, found);
                for (const u of members) users.add(u);
                groups.push(Object.assign({ group: g, people: members.length, entries: members.length, inactive: 0, outside: 0, outsideDomains: [], everyone: 0, groups: 0 }, found));
            }
            if (!whole && this.cfg.pilotOu) for (const u of await this.gmail.usersInOu(this.cfg.directoryAdmin, this.cfg.pilotOu)) users.add(u);
        } catch (e) {
            await this.alert('error', whole
                ? `Couldn't read the directory's mailboxes for the whole domain (${this.cfg.orgDomains.join(', ')}) as ${this.cfg.directoryAdmin}: ${String(e.message).slice(0, 200)}. The whole domain needs the Users → Read privilege in that admin's role and the admin.directory.user.readonly scope in the domain-wide delegation (docs/INSTALL.md, "The colleague-name check"). Nothing was stopped.`
                : `Couldn't read who is in the pilot (${[...this.cfg.pilotGroups, this.cfg.pilotOu].filter(Boolean).join(', ')}) as ${this.cfg.directoryAdmin}: ${String(e.message).slice(0, 200)}. Check the admin's role and the domain-wide delegation scopes.`);
            throw e;
        }
        // Every mailbox's state in one read (not one read per mailbox).
        const known = new Map((await this.store.listUsers()).map(u => [u.email, u]));
        const now = this.now();
        const expiry = (u) => { const k = known.get(u); return k && k.watched && Number(k.watchExpiration) || 0; };
        // New members and the watches renewed longest ago first; one renewed in the last RENEW_FRESH_MS waits.
        const todo = [...users].filter(u => expiry(u) < now + WATCH_MS - RENEW_FRESH_MS).sort((a, b) => expiry(a) - expiry(b));
        const out = new Map();   // user → new expiration
        let failed = 0;
        const over = () => Date.now() - started > budgetMs;
        await pool(todo, parallel, async (user) => {
            try {
                const w = await this.gmail.watch(user, this.cfg.pubsubTopic);
                const k = known.get(user);
                const exp = Number(w.expiration) || null;
                await this.store.putUser(user, Object.assign({ watched: true, watchExpiration: exp, stoppedAt: null, stopPending: false }, k && k.historyId ? {} : { historyId: String(w.historyId) }));
                out.set(user, exp || now + WATCH_MS);
            } catch (e) {
                failed++;
                await this.store.addEvent({ kind: 'error', user, text: `Couldn't watch ${user}'s mailbox: ${String(e.message).slice(0, 200)}` });
            }
        }, over);
        let stopped = 0;
        const gone = [...known.values()].filter(u => u.watched && !users.has(u.email));
        await pool(gone, parallel, async (u) => {
            try { await this.gmail.stop(u.email); } catch (e) { /* already stopped */ }
            await this.store.putUser(u.email, { watched: false, watchExpiration: null });
            stopped++;
        }, over);
        // (Stopped before 0.4.1, their watches' end left behind: cleared, so "watches ending" counts only
        // the watched.)
        await pool([...known.values()].filter(u => !u.watched && u.watchExpiration && !users.has(u.email)), parallel, (u) => this.store.putUser(u.email, { watchExpiration: null }), over);
        // Watched now: every member whose watch (renewed now, or before) hasn't ended. The automatic brake
        // is half of these.
        const ok = [...users].filter(u => (out.get(u) || expiry(u)) > now).length;
        const left = todo.length - out.size - failed;
        await this.store.setState('watchedCount', ok);
        // (0.5.53) Mailboxes still to watch, and watches still to stop: the hourly job continues them (syncFeeds).
        await this.store.setState('watchLeft', { left: left + Math.max(0, gone.length - stopped), at: now, scope: whole ? 'domain' : 'pilot' });
        // What was found, for Activity (and the log, without addresses): so a count that looks
        // wrong says why.
        const text = watchSummary({ ok, failed, stopped, groups, extra: this.cfg.pilotUsers.length, ou: whole ? '' : this.cfg.pilotOu, orgDomains: this.cfg.orgDomains, renewed: out.size, left, domain: domainCount });
        await this.store.addEvent({ kind: 'watch', text });
        if (this.log.info) this.log.info(`renew-watches: ${text}`);
        return { watched: ok, renewed: out.size, left, failed };
    }

    // (0.5.53) Settings → Mailboxes: how many mailboxes each choice watches, read from the directory now (at most
    // every 10 minutes): { domain: count | null, domainError, pilot: count | null, pilotError, watched, scope }.
    // The whole domain's count needs the Users → Read privilege and the admin.directory.user.readonly scope.
    async scopePreview({ force = false } = {}) {
        if (!force && this.scopeCache && Date.now() - this.scopeCache.at < 10 * 60 * 1000) return Object.assign({}, this.scopeCache.v, { watched: Number(await this.store.getState('watchedCount')) || 0, scope: this.cfg.watchScope });
        const v = { domain: null, domainError: '', pilot: null, pilotError: '' };
        const msg = (e) => String((e && e.message) || e).slice(0, 200);
        if (!this.cfg.directoryAdmin) v.domainError = v.pilotError = 'DIRECTORY_ADMIN isn\'t set.';
        else {
            try { v.domain = (await this.gmail.domainUsers(this.cfg.directoryAdmin, this.cfg.orgDomains)).length; }
            catch (e) { v.domainError = `${msg(e)}. The whole domain needs the Users → Read privilege in ${this.cfg.directoryAdmin}'s admin role and the admin.directory.user.readonly scope in the domain-wide delegation (docs/INSTALL.md, "The colleague-name check").`; }
            try {
                const pilot = new Set(this.cfg.pilotUsers);
                for (const g of this.cfg.pilotGroups) for (const u of await this.gmail.groupMembers(this.cfg.directoryAdmin, g, this.cfg.orgDomains)) pilot.add(u);
                if (this.cfg.pilotOu) for (const u of await this.gmail.usersInOu(this.cfg.directoryAdmin, this.cfg.pilotOu)) pilot.add(u);
                v.pilot = pilot.size;
            } catch (e) { v.pilotError = msg(e); }
        }
        this.scopeCache = { at: Date.now(), v };
        return Object.assign({}, v, { watched: Number(await this.store.getState('watchedCount')) || 0, scope: this.cfg.watchScope });
    }

    // (0.6.7) The off switch (deploy/stop.sh). First every mailbox stops counting as watched (its notifications are
    // ignored from then on, PILOT_USERS too), and an unfinished renewal is dropped (the hourly job continued it,
    // watching them again); then Gmail is told to stop notifying, STOP_PARALLEL at a time within budgetMs, and
    // the hourly job finishes what is left (it never renews while stopped). Before, one mailbox at a time with no
    // time limit: a district's 10,000 took about 50 minutes, past the request's 2. Any renewal (the daily job,
    // which stop.sh pauses; install.sh; the dashboard's "Read the directory again now") starts it again.
    async stopAll({ budgetMs = STOP_BUDGET_MS, parallel = STOP_PARALLEL } = {}) {
        const started = Date.now(), at = this.now();
        await this.store.setState('watchLeft', null);
        await this.store.setState('stopped', { at, left: null });
        const todo = (await this.store.listUsers()).filter(u => u.watched || u.stopPending);
        await pool(todo, 25, (u) => this.store.putUser(u.email, { watched: false, watchExpiration: null, stopPending: true, stoppedAt: at }));
        const out = await this.finishStopping({ users: todo, budgetMs: Math.max(0, budgetMs - (Date.now() - started)), parallel });
        await this.store.addEvent({ kind: 'mode', text: out.left ? `All ${todo.length} mailbox watches were switched off: their notifications are ignored. Gmail was told to stop notifying for ${out.stopped}; the hourly job tells it for the other ${out.left}.`
            : `All ${todo.length} mailbox watches were stopped.` });
        return { stopped: todo.length, gmailStopped: out.stopped, left: out.left };
    }
    // Gmail told to stop notifying for the mailboxes switched off (stopPending), within budgetMs: those given
    // (stopAll's, all of them), else those still pending (the hourly job). How many are left goes in state/stopped.
    async finishStopping({ users = null, budgetMs = STOP_BUDGET_MS, parallel = STOP_PARALLEL } = {}) {
        const started = Date.now();
        const todo = (users || (await this.store.listUsers())).filter(u => u.stopPending || users);
        let stopped = 0;
        await pool(todo, parallel, async (u) => {
            try { await this.gmail.stop(u.email); } catch (e) { /* already stopped, or not a mailbox */ }
            await this.store.putUser(u.email, { stopPending: false });
            stopped++;
        }, () => Date.now() - started > budgetMs);
        const left = todo.length - stopped;
        const st = (await this.store.getState('stopped')) || {};
        await this.store.setState('stopped', Object.assign({}, st, { at: st.at || this.now(), left }));
        return { stopped, left };
    }

    // Old documents deleted (the hourly job, last, since 0.4.1; POST /tasks/purge for an older installation's daily
    // job): records after RETENTION_DAYS; Activity (what admins did, alerts) after AUDIT_DAYS (0.5.29, a year by default).
    purge(opts = {}) { return this.store.purge(this.now() - this.cfg.retentionDays * DAY, Object.assign({ eventsBeforeMs: this.now() - (this.cfg.auditDays || 365) * DAY }, opts)); }

    // Cloud Scheduler, hourly (the spruce-sync-feeds job), each step within what is left of the worker's
    // 120-second request: the health check and the weekly summary; the phishing lists, downloaded once a day
    // for everyone (src/intel/feeds.js; a list that missed its download is tried again every LIST_RETRY_MS);
    // the re-checks of delivered mail, Gmail's logs for them and the look-alike watch; an update's problems;
    // the watches the daily renewal or the off switch didn't finish.
    // Since 0.4.1 it also deletes what Firestore's TTL policies don't (documents written before 0.4.0),
    // last, with what is left of the request's time (at most 30 s): no daily job of its own, so the
    // installation keeps to Cloud Scheduler's 3 free jobs.
    async syncFeeds() {
        const started = Date.now();
        await this.refreshPolicy();
        let health, digest = null, out;
        try { health = await this.health(); } catch (e) { health = { error: String(e.message || e).slice(0, 200) }; }
        try { digest = await this.maybeDigest(); } catch (e) { digest = { error: String(e.message || e).slice(0, 200) }; this.log.error('weekly summary:', e); }
        if (digest) health.digest = digest;
        if (!this.intel || !this.intel.feeds) out = { health, skipped: 'phishing lists are off' };
        else {
            const last = Number(await this.store.getState('feedsAttemptedAt')) || 0;
            const retried = Number(await this.store.getState('feedsRetriedAt')) || 0;
            // Once a day: 20 hours, so a run that starts a little early doesn't wait another hour.
            if (this.now() - last >= 20 * HOUR) { await this.store.setState('feedsAttemptedAt', this.now()); out = Object.assign({ health }, await this.intel.feeds.sync()); }
            // A list that missed its download is tried again every 3 hours (only that one), not a day later.
            else if (this.now() - Math.max(last, retried) >= LIST_RETRY_MS && (await this.intel.feeds.status()).some(l => l.missed === 'failed')) {
                await this.store.setState('feedsRetriedAt', this.now());
                out = Object.assign({ health, retry: true }, await this.intel.feeds.sync({ retryFailed: true }));
            } else out = { health, skipped: 'checked within the day' };
            if (out.feeds) { try { await this.listsAlert(out.feeds); } catch (e) { this.log.error('phishing lists, alert:', e); } }
            // What the downloads added: delivered mail that has it is checked again (0.5.35).
            const added = takeAdded(out);
            if (added.length) { try { out.recheck = await this.recheckFromLists(added); } catch (e) { out.recheck = { error: String(e.message || e).slice(0, 200) }; this.log.error('re-check, finding the emails:', e); } }
        }
        // Re-checks (0.5.35): suspicious mail an hour and a day old is queued; the queue is checked within the
        // request's time (the rest at the next run); then Gmail's logs for the re-checked (Link clicks).
        try {
            // (0.5.51) An update that changed how email is checked: recent delivered mail, queued.
            try { const u = await this.checksUpdate(); if (u) out.checksUpdate = u; } catch (e) { out.checksUpdate = { error: String(e.message || e).slice(0, 200) }; this.log.error('re-check after an update:', e); }
            await this.queueLaterChecks();
            const budget = Math.min(RECHECK_BUDGET_MS, 75 * 1000 - (Date.now() - started));
            if (budget > 0) { const r = await this.runRechecks({ budgetMs: budget }); if (r) out.rechecked = r; }
        } catch (e) { out.rechecked = { error: String(e.message || e).slice(0, 200) }; this.log.error('re-check:', e); }
        try {
            const budget = Math.min(15 * 1000, 90 * 1000 - (Date.now() - started));
            if (budget > 0) { const c = await this.followClicks({ budgetMs: budget }); if (c) out.clicks = c; }
        } catch (e) { this.log.error('link clicks:', e); }
        // The look-alike watch (0.5.36): the next candidates.
        try {
            const budget = Math.min(12 * 1000, 95 * 1000 - (Date.now() - started));
            if (budget > 0) { const l = await this.lookalikeStep({ budgetMs: budget }); if (l) out.lookalikes = l; }
        } catch (e) { this.log.error('look-alike watch:', e); }
        // An update from Settings → Update that failed, or stopped (0.5.28): the build records it in Activity;
        // the admins are emailed here, once (the build itself can't send the email).
        try { await this.updateProblems(); } catch (e) { this.log.error('the last update\'s outcome:', e); }
        // An approved version that needs a manual install (0.5.24): noted, and the admins alerted once.
        if (this.releases) {
            try { const m = await require('./update').checkManualInstall({ cfg: this.cfg, store: this.store, releases: this.releases, cloudrun: this.cloudrun || null, alert: (t) => this.alert('update-manual', t) }); if (m) out.manualInstall = m.manual.version; }
            catch (e) { /* GitHub not reachable: the page says so */ }
        }
        // (0.5.53) Watches the daily renewal didn't get to (a whole domain of 10,000 mailboxes, just switched to, or
        // back): continued here each hour, with what is left of the request's time. While switched off, only the
        // mailboxes Gmail hasn't yet been told to stop for are continued.
        try {
            const wl = await this.store.getState('watchLeft'), off = await this.store.getState('stopped');
            const budget = Math.min(45 * 1000, 95 * 1000 - (Date.now() - started));
            if (off) { if (off.left && budget >= 15 * 1000) out.stopping = await this.finishStopping({ budgetMs: budget }); }   // (0.6.7) switched off: never renewed here
            else if (wl && wl.left > 0 && budget >= 15 * 1000) out.watches = await this.renewWatches({ budgetMs: budget });
        } catch (e) { out.watches = { error: String(e.message || e).slice(0, 200) }; this.log.error('watches, continued:', e); }
        const budgetMs = Math.min(30 * 1000, 105 * 1000 - (Date.now() - started));
        if (budgetMs > 0) { try { out.purged = await this.purge({ budgetMs }); } catch (e) { out.purged = { error: String(e.message || e).slice(0, 200) }; } }
        return out;
    }

    // A list that missed its download (0.5.22): an alert (Activity, and emailed to ALERT_EMAIL, the admins by
    // default), when a list newly fails, and once a day while one keeps failing; Today's "Needs attention" says
    // so until it downloads again. (A list downloading again is noted in Activity by feeds.js.)
    async listsAlert(results) {
        const failed = (results || []).filter(r => r.error);
        if (!failed.length) return false;
        const last = Number(await this.store.getState('listsAlertAt')) || 0;
        if (!failed.some(r => r.newly) && this.now() - last < DAY) return false;
        await this.store.setState('listsAlertAt', this.now());
        const n = failed.length;
        await this.alert('list-download', `${n === 1 ? 'A phishing list' : `${n} phishing lists`} missed ${n === 1 ? 'its' : 'their'} download: ${failed.map(r => `${r.name} (${r.error})`).join('; ')}. `
            + `The previous copy is still used, and the download is tried again every 3 hours. Dashboard: Settings → About shows each list's state, with a Re-check button.`);
        return true;
    }
    // An update from Settings → Update that failed, or still runs after update.js's RUNNING_MS: emailed once
    // per update (whichever instance first), the text returned.
    async updateProblems() {
        const up = await this.store.getState('update');
        if (!up || !up.at) return null;
        const stalled = ['requested', 'building'].includes(up.phase) && this.now() - up.at > require('./update').RUNNING_MS;
        if (up.phase !== 'failed' && !stalled) return null;
        if (!(await this.store.setStateIfUnset(`updateProblemEmailed-${up.at}`, { at: this.now() }))) return null;
        const text = up.phase === 'failed'
            ? `The update from ${up.from || 'the installed version'} to ${up.version} failed: ${up.message || 'it stopped'}. Nothing changed, unless the deploy stopped half-way (then bash deploy/rollback.sh goes back). Cloud Build's history has the log (tag spruce-update).`
            : `The update to ${up.version} asked for by ${up.by || 'an admin'} didn't finish within 45 minutes. Cloud Build's history (tag spruce-update) says why; Settings → Update shows it too.`;
        // (a failed one is already in Activity, recorded by the build: emailed only; a stalled one is recorded too)
        if (up.phase === 'failed') { if (this.log.warn) this.log.warn(JSON.stringify({ severity: 'WARNING', spruceAlert: 'update-failed', message: text })); }
        else await this.alert('update-failed', text);
        return text;
    }
    // An admin's "Re-check" (Settings → About): every list that missed its download, or isn't up to date, is
    // downloaded again now; one downloaded within the day is left as it is (the projects publish them for free).
    async recheckLists(by) {
        if (!this.intel || !this.intel.feeds) return { error: 'The phishing lists are off (PHISHING_LISTS=off).', status: 400 };
        const out = await this.intel.feeds.sync({ retryFailed: true });
        // What the downloads added: delivered mail that has it is checked again (0.5.35), some now, the rest
        // at the next hourly run.
        const added = takeAdded(out);
        if (added.length) {
            try { if (await this.recheckFromLists(added)) await this.runRechecks({ budgetMs: 20 * 1000 }); }
            catch (e) { this.log.error('re-check:', e); }
        }
        const got = out.feeds.filter(r => r.count != null), failed = out.feeds.filter(r => r.error);
        await this.store.addEvent({ kind: 'lists', admin: true, text: `${by} re-checked the phishing lists: ${got.length ? `${got.map(r => r.name).join(', ')} downloaded` : 'none needed a download'}${failed.length ? `; ${failed.map(r => r.name).join(', ')} still missed ${failed.length === 1 ? 'its' : 'their'} download` : ''}.` });
        return { feeds: out.feeds, recovered: out.recovered || [], lists: await this.intel.feeds.status() };
    }

    // --- Re-checking delivered mail (0.5.35) ----------------------------------------------------------
    // Delivered mail is checked again, in full (the same rules, AI, lists and brakes as on arrival), when
    //   - a phishing list's daily download adds a site or a sender that an email of the last RECHECK_DAYS
    //     days has (found by its hashes, src/recheck.js), in every mailbox that got a copy;
    //   - an email found suspicious on arrival (not moved) is an hour old, and again when a day old: a
    //     site too new to be on a list or blocked by Safe Browsing often is by then;
    //   - (0.5.51) the look-alike watch finds a new domain imitating the district's, or an admin marks one a
    //     threat: the emails of the last RECHECK_DAYS days from it, asking for replies to it or linking to it;
    //   - (0.5.51) an update changes how email is checked (package.json checksLevel raised; an update that
    //     only changes the dashboard, wording or documentation doesn't): the mail delivered in the last
    //     RECHECK_AFTER_UPDATE_HOURS that is still in the Inbox, newest first (checksUpdate).
    // What the check says now is done as on arrival: moved to Spam (enforce mode, through the brakes),
    // recorded as "would move" (monitor mode), or recorded as suspicious. Never moved: an email no longer
    // in the Inbox (its reader archived, deleted or reported it), one an admin released or marked, one its
    // reader put in the Inbox themselves. Each is on the dashboard (Threats → Re-checked) with who got it,
    // whether they had opened it and, with Settings → Link clicks on, what Gmail's logs say they did; the
    // admins are alerted.
    async queueRechecks(items) {
        if (!items || !items.length) return 0;
        const q = (await this.store.getState('recheckQueue')) || [];
        const have = new Set(q.map(x => `${x.user}|${x.id}`));
        let n = 0;
        for (const it of items) {
            const k = `${it.user}|${it.id}`;
            if (have.has(k) || q.length >= RECHECK_QUEUE_MAX) continue;
            have.add(k); q.push(Object.assign({ queuedAt: this.now() }, it)); n++;
        }
        if (n) await this.store.setState('recheckQueue', q);
        return n;
    }
    // The new entries of the lists' downloads ([{ name, kind, entries }]): the delivered emails that have
    // one, queued.
    async recheckFromLists(added) {
        if (!this.cfg.recheck) return null;
        const lists = (added || []).filter(a => a && a.entries && a.entries.length);
        if (!lists.length) return null;
        const want = lookFor(spruce.load(), lists);
        if (!want.size) return null;
        const hits = await this.store.findIndexed([...want.keys()], this.now() - this.cfg.recheckDays * DAY, RECHECK_FIND_MAX);
        const items = hits.map(h => {
            const w = (h.ix || []).map(x => want.get(x)).find(Boolean) || {};
            return { user: h.user, id: h.id, receivedAt: h.receivedAt || null, source: w.source || 'lists', site: String(w.site || '').slice(0, 200), list: w.list || '' };
        });
        return { entries: want.size, found: hits.length, queued: await this.queueRechecks(items) };
    }
    // Suspicious mail (recorded, not moved) an hour old, and again a day old: queued.
    async queueLaterChecks() {
        if (!this.cfg.recheck) return 0;
        const now = this.now();
        // (0.6.7) Two short windows, each read on its own: an hour old (up to 6 h, for runs missed) and a day old (up to
        // 30 h). Before, one read of the last 50 hours, newest first, at most 3,000: past that, the day-old round was
        // never reached, and a gone email was asked for again every hour for two days.
        const [hourOld, dayOld] = await Promise.all([this.store.listRecords({ sinceMs: now - 6 * HOUR, untilMs: now - HOUR, limit: 3000 }),
            this.store.listRecords({ sinceMs: now - 30 * HOUR, untilMs: now - DAY, limit: 3000 })]);
        const open = (r) => r.action === 'flag' && r.state === 'inbox' && r.falseAlarm == null && !r.unclear && !r.userPlaced && !r.recheck;
        const due = [...hourOld.filter(r => open(r) && (r.laterChecks || 0) === 0), ...dayOld.filter(r => open(r) && (r.laterChecks || 0) <= 1)];
        return this.queueRechecks(due.slice(0, 1000).map(r => ({ user: r.user, id: r.messageId, receivedAt: r.receivedAt || null, source: 'later', round: (r.laterChecks || 0) + 1 })));
    }
    // (0.5.51) After an update that changes how email is checked. state/checksLevel: the level last run
    // ({ level, version, at }); none yet (this version's first run): recorded, nothing checked again.
    // A higher level starts a sweep (state/updateRecheck: { level, version, since, until, boundary, queued,
    // max, startedAt, doneAt }) of the "checked" markers of the mail delivered since RECHECK_AFTER_UPDATE_HOURS
    // before it, still in the Inbox (only those keep re-check hashes), newest first: each hourly run queues
    // the next ones as the queue has room, up to RECHECK_AFTER_UPDATE_MAX. Mail that arrived after this
    // instance started was judged by this version already: not taken. A lower level (a version rolled back)
    // is recorded, nothing checked again.
    async checksUpdate() {
        const level = this.checksLevel(), now = this.now();
        const st = await this.store.getState('checksLevel');
        if (!st || typeof st.level !== 'number') { await this.store.setState('checksLevel', { level, version: PKG_VERSION, at: now }); return null; }
        let started = null;
        if (st.level !== level) {
            await this.store.setState('checksLevel', { level, version: PKG_VERSION, at: now, previous: st.level });
            const hours = this.cfg.recheckAfterUpdateHours, max = this.cfg.recheckAfterUpdateMax;
            if (level > st.level && this.cfg.recheck && hours > 0 && max > 0) {
                const until = Math.min(now, PROCESS_STARTED);
                started = { level, version: PKG_VERSION, since: until - hours * HOUR, until, boundary: [], queued: 0, max, startedAt: now, doneAt: null };
                await this.store.setState('updateRecheck', started);
                await this.store.addEvent({ kind: 'recheck', text: `Version ${PKG_VERSION} changes how email is checked: the mail delivered in the last ${hours} hours that is still in the Inbox is being checked again, newest first (at most ${max.toLocaleString('en-US')} emails).` });
            } else if (level > st.level) {
                await this.store.addEvent({ kind: 'recheck', text: `Version ${PKG_VERSION} changes how email is checked; delivered mail isn't checked again (${this.cfg.recheck ? 'RECHECK_AFTER_UPDATE_HOURS or RECHECK_AFTER_UPDATE_MAX is 0' : 're-checking delivered mail is off'}).` });
            }
        }
        const sw = started || await this.store.getState('updateRecheck');
        if (!sw || sw.doneAt || !this.cfg.recheck) return started ? { started: true } : null;
        const q = (await this.store.getState('recheckQueue')) || [];
        const room = Math.min(RECHECK_QUEUE_MAX - q.length, UPDATE_QUEUE_STEP, sw.max - sw.queued);
        if (room <= 0) {
            if (sw.queued >= sw.max) { sw.doneAt = now; await this.store.setState('updateRecheck', sw); }
            return { version: sw.version, queued: 0, total: sw.queued, done: !!sw.doneAt };
        }
        // Newest first; the emails at the boundary's exact time already taken are left out (copies of one
        // email often arrive in the same millisecond).
        const boundary = new Set(sw.boundary || []);
        const got = await this.store.listIndexedSince(sw.since, sw.until, room + boundary.size);
        const fresh = got.filter(g => !boundary.has(`${g.user}|${g.id}`)).slice(0, room);
        const n = await this.queueRechecks(fresh.map(g => ({ user: g.user, id: g.id, receivedAt: g.receivedAt || null, source: 'update', version: sw.version })));
        sw.queued += n;
        if (got.length < room + boundary.size || !fresh.length) sw.doneAt = now;
        else {
            const last = fresh[fresh.length - 1].receivedAt;
            const at = fresh.filter(g => g.receivedAt === last).map(g => `${g.user}|${g.id}`);
            sw.boundary = (last === sw.until ? [...boundary, ...at] : at).slice(-5000);
            sw.until = last;
        }
        await this.store.setState('updateRecheck', sw);
        return { version: sw.version, queued: n, total: sw.queued, done: !!sw.doneAt };
    }
    // The queue, RECHECK_PARALLEL at a time, until budgetMs is spent (the rest at the next hourly run).
    // An email whose check fails is tried again (3 tries in all).
    async runRechecks({ budgetMs = RECHECK_BUDGET_MS } = {}) {
        const started = Date.now();
        const queue = (await this.store.getState('recheckQueue')) || [];
        if (!queue.length) return null;
        const results = [], retry = [];
        while (queue.length && Date.now() - started < budgetMs) {
            const batch = queue.splice(0, RECHECK_PARALLEL);
            const outs = await Promise.all(batch.map(it => this.emailSlots.run(() => this.recheckMessage(it)).catch(e => {
                this.log.error(`re-check ${it.user} ${it.id}:`, e);
                if ((it.tries || 1) < 3) retry.push(Object.assign({}, it, { tries: (it.tries || 1) + 1 }));
                return { item: it, outcome: 'error', error: String((e && e.message) || e).slice(0, 200) };
            })));
            results.push(...outs);
        }
        await this.store.setState('recheckQueue', queue.concat(retry).slice(0, RECHECK_QUEUE_MAX));
        await this.recheckReport(results);
        const count = (o) => results.filter(r => r.outcome === o).length;
        return { checked: results.length, left: queue.length + retry.length, moved: count('moved'), wouldMove: count('would-move') + count('held'), notInInbox: count('not-in-inbox'), suspicious: count('flag') };
    }

    // One email checked again (item: { user, id, source: 'lists'|'lookalike'|'update'|'later', site, list, round, version }).
    async recheckMessage(item) {
        const { user, id } = item;
        const key = recordKey(user, id), now = this.now();
        const before = await this.store.getRecord(key);
        // A decision already made stands: moved or released, an admin's mark, the reader's own choice, a
        // re-check that already moved it or would.
        // (A copy held by a brake waits for the admins: the brake's resume on Today, or the campaign's decision
        // on Threats → Campaigns.)
        if (before && (before.state !== 'inbox' || before.falseAlarm != null || before.unclear || before.userPlaced || before.held || (before.recheck && before.recheck.outcome !== 'flag'))) return { item, outcome: 'skipped' };
        let msg;
        try { msg = await this.gmail.raw(user, id); }
        catch (e) { if (e instanceof GoogleApiError && e.status === 404) return { item, outcome: 'gone' }; throw e; }
        if (!msg || !msg.raw || !msg.raw.length || isSummary(msg.raw)) return { item, outcome: 'gone' };
        const labels = msg.labelIds || [];
        const where = labels.includes('INBOX') ? 'inbox' : labels.includes('SPAM') ? 'spam' : labels.includes('TRASH') ? 'trash' : 'archived';
        // Opened: Gmail's UNREAD label is gone (its reader opened it, or marked it read).
        const opened = !labels.includes('UNREAD');
        const facts = await readMessage(msg.raw, { ownDomains: this.cfg.orgDomains });
        if (ownSentCopy(user, msg, facts)) return { item, outcome: 'skipped' };   // (its owner's own sent mail: 0.6.3)
        if (await this.trainingOf(facts)) return { item, outcome: 'skipped' };   // (a phishing-training email: 0.5.44)
        const allowlisted = isAllowed(this.cfg, facts.senderAddress), verified = senderVerified(facts);
        // A new sender on arrival stays one (as for an admin's re-scan); unknown for mail not recorded then.
        const firstTime = before ? (before.arrival ? !!before.arrival.firstTime : (before.signals || []).some(x => x && x.kind === 'first-time')) : false;
        const result = await analyze(facts, { mailbox: user, orgDomains: this.cfg.orgDomains, allowLinkDomains: this.cfg.allowLinkDomains, trusted: allowlisted && verified, firstTime, intel: this.intel,
            colleagues: await this.colleagueNames(), selfNameHash: this.selfNameHash(user), aiInside: this.aiReadsInside(), lookalikes: await this.lookalikeMap(), threadSize: await this.threadSizeOf(user, msg.threadId, facts) });
        result.allowlistedUnverified = allowlisted && !verified;
        await this.applySpamMemory(user, facts, result);
        let decision = decide(result, this.cfg, { brake: await this.brakeOn() });
        const was = before ? before.action : 'none';
        if ((RECHECK_RANK[decision.action] || 0) <= (RECHECK_RANK[was] || 0)) {
            if (before && item.source === 'later') await this.store.updateRecord(key, { laterChecks: (before.laterChecks || 0) + 1, laterCheckAt: now });
            return { item, outcome: 'unchanged', action: decision.action };
        }
        const senderDomain = (facts.senderAddress.split('@')[1] || '').toLowerCase();
        const campaign = campaignOf(senderDomain, facts.subject, user);
        const campaignLabel = this.cfg.storeSubjects ? campaign.label : senderDomain;
        let held = decision.braked ? 'brake' : null;
        if ((decision.action === 'move' || decision.action === 'would-move') && where !== 'inbox') {
            decision = { action: 'flag', trigger: decision.trigger, why: `${decision.why}; it had already left the Inbox (${WHERE_WORDS[where]}), so it wasn't moved` };
            held = null;
        } else if (decision.action === 'move') ({ decision, held } = await this.brakes(decision, result, campaign.key, campaignLabel, now));
        let state = 'inbox';
        if (decision.action === 'move') {
            await this.gmail.modify(user, id, ['SPAM', await this.gmail.labelId(user, this.cfg.movedLabel)], ['INBOX']);
            state = 'moved';
        } else if (decision.action === 'would-move' && this.cfg.monitorLabel) {
            try { await this.gmail.modify(user, id, [await this.gmail.labelId(user, this.cfg.monitorLabel)], []); } catch (e) { this.log.error(`monitor label ${user} ${id}:`, e); }
        }
        let labeled = !!(before && before.suspiciousLabel);
        if (decision.action === 'flag' && this.cfg.suspiciousLabel && !labeled && where === 'inbox') {
            try { await this.gmail.modify(user, id, [await this.gmail.labelId(user, this.cfg.suspiciousLabelName)], []); labeled = true; }
            catch (e) { this.log.error(`suspicious label ${user} ${id}:`, e); }
        }
        const found = foundWords(item);
        decision = Object.assign({}, decision, { why: `found on a re-check (${found}): ${decision.why}` });
        const outcome = state === 'moved' ? 'moved' : decision.action === 'would-move' ? (held ? 'held' : 'would-move') : where !== 'inbox' ? 'not-in-inbox' : 'flag';
        const recheck = { at: now, source: item.source, site: item.site || null, list: item.list || null, round: item.round || null, version: item.version || null,
            before: was, beforeScore: before ? before.score : null, outcome, where, opened, movedAt: state === 'moved' ? now : null, clicks: null };
        const rec = this.recordOf(user, msg, facts, result, decision, { now, campaign, campaignLabel, senderDomain, held, state, labeled });
        rec.recheck = recheck;
        if (item.source === 'later') rec.laterChecks = ((before && before.laterChecks) || 0) + 1;
        if (before) {
            const keep = new Set(['key', 'user', 'messageId', 'threadId', 'readHistoryId', 'processedAt', 'releasedBy', 'releasedAt', 'falseAlarm', 'markedBy', 'unclear', 'userPlaced']);
            const patch = Object.fromEntries(Object.entries(rec).filter(([k, v]) => !keep.has(k) && v !== undefined));
            patch.arrival = before.arrival || { at: before.processedAt, score: before.score, status: before.status, action: before.action, firstTime,
                ai: before.ai && typeof before.ai.probability === 'number' ? { probability: before.ai.probability, model: before.ai.model || null } : null };
            await this.store.updateRecord(key, patch);
        } else {
            // Clean on arrival (nothing was recorded then): recorded now.
            rec.arrival = { at: rec.receivedAt, action: 'none' };
            await this.store.saveRecord(rec);
        }
        await this.count(this.dayOf(now), state === 'moved' ? 'moved' : decision.action === 'would-move' ? 'wouldMove' : 'flagged');
        return { item, outcome, key, user, opened, where, sender: rec.sender.address, campaign: campaign.key, campaignLabel, site: item.site || '', list: item.list || '', source: item.source, version: item.version || null };
    }

    // The admins are told what a run found: an alert (emailed) when phishing had been delivered, in Activity
    // only when an email is now just suspicious.
    async recheckReport(results) {
        const bad = results.filter(r => ['moved', 'would-move', 'held', 'not-in-inbox'].includes(r.outcome));
        const sus = results.filter(r => r.outcome === 'flag');
        if (bad.length) {
            const n = (o) => bad.filter(r => r.outcome === o).length;
            const camps = [...new Set(bad.map(r => r.campaignLabel))];
            const why = [...new Set(bad.filter(r => r.source && r.source !== 'later').map(r => foundWords(r, { delivered: false })))].slice(0, 3);
            const parts = [n('moved') ? `${n('moved')} moved to Spam` : '', n('would-move') ? `${n('would-move')} would be moved (monitor mode: left in the Inbox)` : '',
                n('held') ? `${n('held')} left in the Inbox by a brake` : '', n('not-in-inbox') ? `${n('not-in-inbox')} had already left the Inbox` : ''].filter(Boolean);
            const opened = bad.filter(r => r.opened).length;
            await this.alert('recheck', `Re-checked mail: ${bad.length} ${bad.length === 1 ? 'email' : 'emails'} delivered earlier ${bad.length === 1 ? 'is' : 'are'} now found to be phishing`
                + `${why.length ? ` (${why.join('; ')})` : ''}, from ${camps.slice(0, 3).map(c => `"${c}"`).join(', ')}${camps.length > 3 ? ` and ${camps.length - 3} more` : ''}: ${parts.join(', ')}. `
                + `${opened ? `${opened} had been opened. ` : 'None had been opened. '}Who got them, when, and what Gmail's logs say they did: dashboard, Threats → Re-checked. More: docs/ALERTS.md, "Re-checked mail".`,
                { rechecked: bad.length });
        }
        if (sus.length) await this.store.addEvent({ kind: 'recheck', text: `Re-checked mail: ${sus.length} ${sus.length === 1 ? 'email' : 'emails'} delivered earlier ${sus.length === 1 ? 'is' : 'are'} now found suspicious and left in the Inbox (${[...new Set(sus.map(r => r.campaignLabel))].slice(0, 3).join(', ')}). Threats → Re-checked lists them.` });
    }

    // Settings → Link clicks (0.5.35; off by default): Gmail's logs (Admin SDK Reports API) read as an admin
    // with the Reports privilege, for each re-checked email: when its reader first opened it, and whether
    // they clicked a link in it.
    async clickLogs() { return Object.assign({ on: false, admin: '' }, await this.store.getState('clickLogs')); }
    // One email's events in its reader's Gmail log, from 5 minutes before it arrived: mail_event_type 15 and 16
    // (a link clicked), 7 (opened), each matched to the email by its Message-ID; the first time of each.
    async clicksOf(rec, admin) {
        const now = this.now();
        const from = (Number(rec.receivedAt) || now - this.cfg.recheckDays * DAY) - 5 * 60 * 1000;
        const out = { checkedAt: now, checks: ((rec.recheck && rec.recheck.clicks && rec.recheck.clicks.checks) || 0) + 1, clicked: false, clickedAt: null, opened: false, openedAt: null, named: false };
        for (const type of [15, 16, 7]) {
            const evs = await this.gmail.gmailEvents(admin, rec.user, { startTime: from, endTime: now, filters: `event_info.mail_event_type==${type}`, max: 2000 });
            for (const ev of evs) {
                if (!eventNames(ev, rec.rfc822MessageId)) continue;
                out.named = true;
                const at = Date.parse(ev.id && ev.id.time) || null;
                const t = eventType(ev) || type;
                if (t === 15 || t === 16) { out.clicked = true; if (at && (!out.clickedAt || at < out.clickedAt)) out.clickedAt = at; }
                if (t === 7) { out.opened = true; if (at && (!out.openedAt || at < out.openedAt)) out.openedAt = at; }
            }
        }
        return out;
    }
    // Gmail's logs for re-checked emails: first at the hourly run (usually the one that re-checked it), then again (Google's logs can take hours)
    // every 3 hours, 4 times in all, within 3 days of the re-check, until a click is found. A click found
    // is an alert; logs that can't be read are an alert once a day.
    async followClicks({ budgetMs = 15000, max = 100 } = {}) {
        const cl = await this.clickLogs();
        if (!cl.on || !cl.admin) return null;
        const started = Date.now(), now = this.now();
        const recs = (await this.store.listRecords({ sinceMs: now - (this.cfg.recheckDays + 2) * DAY, limit: 5000 }))
            .filter(r => r.recheck && r.rfc822MessageId && now - r.recheck.at < 3 * DAY && ['moved', 'would-move', 'held', 'not-in-inbox', 'flag'].includes(r.recheck.outcome))
            .filter(r => !r.recheck.clicks || (!r.recheck.clicks.clicked && (r.recheck.clicks.checks || 0) < 4 && now - r.recheck.clicks.checkedAt >= 3 * HOUR));
        const clicked = [];
        let checked = 0, failed = null;
        for (const r of recs.slice(0, max)) {
            if (Date.now() - started > budgetMs) break;
            try {
                const c = await this.clicksOf(r, cl.admin);
                checked++;
                await this.store.updateRecord(r.key, { recheck: Object.assign({}, r.recheck, { clicks: c }) });
                if (c.clicked) clicked.push(Object.assign({}, r, { clickedAt: c.clickedAt }));
            } catch (e) { const p = reportsProblem(e, cl.admin); failed = `${p.why} ${p.fix}`; break; }
        }
        await this.store.setState('clickLogsHealth', { at: now, ok: !failed, error: failed, checked });
        if (failed) await this.alertDaily('click-logs', `Gmail's logs couldn't be read for re-checked mail (Settings → Link clicks, as ${cl.admin}): ${failed} More: docs/ALERTS.md, "Gmail's logs couldn't be read".`);
        if (clicked.length) {
            const who = clicked.slice(0, 5).map(r => `${r.user} (an email from ${r.sender.address}${r.clickedAt ? `, at ${new Date(r.clickedAt).toISOString().slice(0, 16).replace('T', ' ')} UTC` : ''})`);
            await this.alert('recheck-click', `A link was clicked in mail later found to be phishing: ${who.join('; ')}${clicked.length > 5 ? ` and ${clicked.length - 5} more` : ''}. Their password may have been given away: consider resetting it, ending their sessions and checking their sign-ins (Admin console). Dashboard: Threats → Re-checked. More: docs/ALERTS.md, "A link was clicked".`, { clicked: clicked.length });
        }
        return { checked, clicked: clicked.length, error: failed };
    }
    // Settings → Link clicks: on (with the admin to read the logs as) or off; Test reads the admin's own
    // mailbox's log for the last day, and says whether its events name the emails they are about.
    async setClickLogs(on, admin, by) {
        const was = await this.clickLogs();
        const a = String(admin || was.admin || '').trim().toLowerCase();
        if (on && !/^[^\s@]+@[^\s@]+$/.test(a)) return { error: 'Type the address of the admin whose rights read Gmail\'s logs.', status: 400 };
        if (on && !this.cfg.orgDomains.includes(a.split('@')[1])) return { error: `${a} isn't in your organization's domains (${this.cfg.orgDomains.join(', ')}).`, status: 400 };
        const v = { on: !!on, admin: on ? a : was.admin || '', by, at: this.now() };
        await this.store.setState('clickLogs', v);
        await this.adminNotice('settings', `${by} turned ${on ? `on Link clicks (Gmail's logs read as ${a})` : 'off Link clicks'}.`);
        return { clickLogs: v };
    }
    async testClickLogs(admin, by) {
        const cl = await this.clickLogs();
        const a = String(admin || cl.admin || '').trim().toLowerCase();
        if (!/^[^\s@]+@[^\s@]+$/.test(a)) return { error: 'Type the admin\'s address first.', status: 400 };
        const now = this.now();
        let evs;
        try { evs = await this.gmail.gmailEvents(a, a, { startTime: now - DAY, endTime: now, max: 200 }); }
        catch (e) {
            const p = reportsProblem(e, a);
            const error = `${p.why} ${p.fix}`;
            await this.store.setState('clickLogsTest', { at: now, by, admin: a, ok: false, error, why: p.why, fix: p.fix });
            return { ok: false, error, why: p.why, fix: p.fix };
        }
        const named = evs.filter(eventHasMessageId).length;
        const t = { at: now, by, admin: a, ok: true, events: evs.length, named };
        await this.store.setState('clickLogsTest', t);
        return t;
    }

    // --- The look-alike watch (0.5.36) ------------------------------------------------------------------
    // src/lookalike.js says what it does. State (state/lookalikeWatch): { cursor, passStartedAt, passes,
    // baselineDone, lastPassAt, found: { domain: { domain, first, last, mx, web, ageDays, status, gone,
    // by, at } } }. status: 'baseline' (there before the watch), 'new' (appeared since, or registered in the
    // last 30 days), 'threat', 'ours', 'harmless' (an admin's marks).
    // The look-alikes that count in mail ({ domain → weight }), from a copy kept 5 minutes per instance (and
    // dropped at once when this instance changes the list). (0.6.7) One read at a time per instance: when the
    // copy expires, the emails being checked at that moment wait for the same read (each read the document before).
    lookalikeMap() {
        if (this.lookalikeCache && Date.now() - this.lookalikeCache.at < 5 * 60 * 1000) return Promise.resolve(this.lookalikeCache.map);
        return this.lookalikeLoading || (this.lookalikeLoading = this.loadLookalikeMap().finally(() => { this.lookalikeLoading = null; }));
    }
    async loadLookalikeMap() {
        const map = new Map();
        try {
            const w = await this.store.getState('lookalikeWatch');
            for (const e of Object.values((w && w.found) || {})) { const k = lookalikeWeight(e); if (k) map.set(e.domain, k); }
        } catch (e) { /* none this time */ }
        this.lookalikeCache = { at: Date.now(), map };
        return map;
    }
    // The next candidates (a pass over all of them at most once a day), up to batch, within budgetMs; new
    // look-alikes are an alert. The first pass only learns what is already there (baseline), unless RDAP says
    // a domain was registered within LOOKALIKE_NEW_DAYS.
    async lookalikeStep({ budgetMs = 12000, batch = LOOKALIKE_BATCH } = {}) {
        if (!this.cfg.lookalikeWatch || !this.intel || !this.intel.dnsCheck || !this.cfg.orgDomains.length) return null;
        const started = Date.now(), now = this.now();
        const w = Object.assign({ cursor: 0, passStartedAt: 0, passes: 0, baselineDone: false, lastPassAt: null, found: {} }, await this.store.getState('lookalikeWatch'));
        const cands = lookalikeVariants(spruce.load(), this.cfg.orgDomains);
        if (w.cursor >= cands.length || !w.passStartedAt) {
            if (w.passStartedAt && now - w.passStartedAt < DAY) return { idle: true };
            w.cursor = 0; w.passStartedAt = now;
        }
        const newly = [];
        let asked = 0, failed = 0;
        while (w.cursor < cands.length && asked < batch && Date.now() - started < budgetMs) {
            const part = cands.slice(w.cursor, Math.min(cands.length, w.cursor + 8, w.cursor + batch - asked));
            const answers = await Promise.all(part.map(d => this.intel.dnsCheck(d)));
            for (const [i, d] of part.entries()) {
                const r = answers[i];
                if (!r) { failed++; continue; }
                const e = w.found[d];
                if (!r.exists) { if (e && !e.gone) e.gone = now; continue; }
                if (e) {
                    const back = !!e.gone;
                    Object.assign(e, { last: now, mx: r.mx, web: r.web, gone: null });
                    // Gone and registered again: someone else may have it now.
                    if (back && !['ours'].includes(e.status)) { e.status = 'new'; e.first = now; newly.push(e); }
                    continue;
                }
                const ageDays = this.intel.rdap ? await this.intel.rdap.ageDays(d).catch(() => null) : null;
                const fresh = typeof ageDays === 'number' && ageDays < LOOKALIKE_NEW_DAYS;
                const entry = { domain: d, first: now, last: now, mx: r.mx, web: r.web, ageDays: typeof ageDays === 'number' ? ageDays : null, status: w.baselineDone || fresh ? 'new' : 'baseline', gone: null };
                w.found[d] = entry;
                if (entry.status === 'new') newly.push(entry);
            }
            w.cursor += part.length; asked += part.length;
        }
        if (w.cursor >= cands.length) { w.passes = (w.passes || 0) + 1; w.baselineDone = true; w.lastPassAt = now; }
        w.candidates = cands.length;
        await this.store.setState('lookalikeWatch', w);
        this.lookalikeCache = null;
        // (0.5.51) Delivered mail from them, asking for replies to them or linking to them: checked again.
        if (newly.length) {
            try { await this.recheckFromLists([{ name: 'found', source: 'lookalike', kind: 'domain', entries: newly.map(e => e.domain) }]); }
            catch (e) { this.log.error('re-check, look-alikes:', e); }
        }
        if (newly.length) {
            const words = (e) => `${e.domain} (mail servers: ${e.mx ? 'yes' : 'no'}; a website: ${e.web ? 'yes' : 'no'}${typeof e.ageDays === 'number' ? `; registered ${e.ageDays} day${e.ageDays === 1 ? '' : 's'} ago` : ''})`;
            await this.alert('lookalike', `${newly.length === 1 ? 'A domain that imitates yours was registered' : `${newly.length} domains that imitate yours were registered`}: ${newly.slice(0, 5).map(words).join('; ')}${newly.length > 5 ? ` and ${newly.length - 5} more` : ''}. `
                + `Mail from ${newly.length === 1 ? 'it' : 'them'}, replies to ${newly.length === 1 ? 'it' : 'them'} and links to ${newly.length === 1 ? 'it' : 'them'} now count as strong signs of phishing. If the district registered ${newly.length === 1 ? 'it' : 'one'} itself, mark it so: dashboard, Threats → Look-alikes. More: docs/ALERTS.md, "A look-alike of your domain".`,
                { domains: newly.map(e => e.domain).slice(0, 20) });
        }
        return { asked, failed, cursor: w.cursor, of: cands.length, found: Object.keys(w.found).length, newly: newly.length };
    }
    // An admin's mark on a found look-alike: ours, harmless, threat, or back to watching as found.
    async markLookalike(domain, status, by) {
        if (!['ours', 'harmless', 'threat', 'watch'].includes(status)) return { error: 'Choose ours, harmless, threat or watch.', status: 400 };
        const w = await this.store.getState('lookalikeWatch');
        const e = w && w.found && w.found[String(domain || '').toLowerCase()];
        if (!e) return { error: 'That domain isn\'t on the list.', status: 404 };
        // (what the watch found it as, for "watch it again")
        if (!e.firstStatus) e.firstStatus = e.status === 'new' || e.status === 'baseline' ? e.status : 'baseline';
        const weightBefore = lookalikeWeight(e);
        e.status = status === 'watch' ? e.firstStatus : status;
        Object.assign(e, { by, at: this.now() });
        await this.store.setState('lookalikeWatch', w);
        this.lookalikeCache = null;
        const words = { ours: 'the district\'s own (no sign in mail)', harmless: 'someone else\'s, harmless (no sign in mail)', threat: 'a threat (a strong sign in mail)', watch: 'watched as found' }[status];
        await this.adminNotice('lookalike-mark', `${by} marked the look-alike ${e.domain} as ${words}.`);
        // (0.5.51) Marked a threat (it was a weak sign or none): delivered mail from it, asking for replies to it
        // or linking to it is checked again, at the next hourly run.
        let recheck = null;
        if (status === 'threat' && lookalikeWeight(e) === 'strong' && weightBefore !== 'strong') {
            try { recheck = await this.recheckFromLists([{ name: 'marked', source: 'lookalike', kind: 'domain', entries: [e.domain] }]); }
            catch (err) { this.log.error('re-check, look-alike marked:', err); }
        }
        return { entry: e, recheck };
    }

    // --- Phishing-training emails (0.5.44; Settings → Phishing training) ------------------------------------
    // src/simulations.js says how they are recognized. state/phishTraining: { rules: [{ id, name, header,
    // headerShown, valueHash, ips }], domains: [], by, at } (a secret value only as a one-way hash);
    // state/phishTrainingSeen: { [name]: lastSeen } (each instance writes it at most every 10 minutes).
    // The settings are read at most once a minute per instance (a failed read keeps the last copy).
    trainingSettings() {
        if (this.trainingCache && Date.now() - this.trainingCache.at < 60 * 1000) return Promise.resolve(this.trainingCache.v);
        return this.trainingLoading || (this.trainingLoading = this.loadTrainingSettings().finally(() => { this.trainingLoading = null; }));   // (0.6.7) one read at a time
    }
    async loadTrainingSettings() {
        let v = null;
        try { v = await this.store.getState('phishTraining'); } catch (e) { v = (this.trainingCache && this.trainingCache.v) || null; }
        this.trainingCache = { at: Date.now(), v };
        return v;
    }
    async trainingOf(facts) {
        const st = await this.trainingSettings();
        if (!st) return null;
        try { return await sims.matchTraining(spruce.load(), facts, st); } catch (e) { this.log.error('phishing training:', e); return null; }
    }
    async noteTraining(t) {
        this.trainingSeen = this.trainingSeen || new Map();
        this.trainingSeen.set(t.name, this.now());
        if (this.trainingSeenAt && Date.now() - this.trainingSeenAt < 10 * 60 * 1000) return;
        this.trainingSeenAt = Date.now();
        try { await this.store.setState('phishTrainingSeen', Object.assign({}, await this.store.getState('phishTrainingSeen'), Object.fromEntries(this.trainingSeen))); } catch (e) { /* next time */ }
    }
    async trainingChange(change, by, words) {
        const cur = Object.assign({ rules: [], domains: [] }, await this.store.getState('phishTraining'));
        const next = change(cur);
        if (next.error) return next;
        const v = Object.assign({}, cur, next, { by, at: this.now() });
        await this.store.setState('phishTraining', v.rules.length || v.domains.length ? v : null);
        this.trainingCache = null;
        await this.adminNotice('settings', `${by} ${words(next)}.`);
        return { ok: true };
    }
    addTrainingRule(input, by) {
        const r = sims.ruleFrom(input || {});
        if (r.error) return Promise.resolve({ error: r.error, status: 400 });
        return this.trainingChange((cur) => (cur.rules.length >= sims.MAX_RULES ? { error: `At most ${sims.MAX_RULES} rules.`, status: 400 } : { rules: [...cur.rules, r.rule] }), by,
            () => `added the phishing-training rule "${r.rule.name}" (header ${r.rule.headerShown}${r.rule.valueHash ? ', with a secret value' : ''}${r.rule.ips.length ? `, from ${r.rule.ips.length} sending address${r.rule.ips.length === 1 ? '' : 'es'}` : ''}): emails it matches are let through unchecked`);
    }
    removeTrainingRule(id, by) {
        let gone = null;
        return this.trainingChange((cur) => { gone = cur.rules.find(x => x.id === id); return gone ? { rules: cur.rules.filter(x => x.id !== id) } : { error: 'That rule isn\'t there.', status: 404 }; }, by,
            () => `removed the phishing-training rule "${gone.name}"`);
    }
    // (0.5.61) Edit a rule in place (same id, so its "last matched" stays): name, header, sending addresses; the
    // secret value is kept (it is stored only as a hash of the header and the value, so a new header needs it typed
    // again), replaced when a new one is typed, or removed (clearValue: then sending addresses are needed).
    editTrainingRule(id, input, by) {
        let before = null, after = null;
        return this.trainingChange((cur) => {
            before = cur.rules.find(x => x.id === id);
            if (!before) return { error: 'That rule isn\'t there (another admin may have removed it). Nothing was changed.', status: 404 };
            const header = String(input.header || '').trim();
            const typed = typeof input.value === 'string' ? input.value.trim() : '';
            const keep = !typed && !input.clearValue && !!before.valueHash;
            if (keep && header.toLowerCase() !== before.header) return { error: 'The secret value is kept only as a one-way hash of the header and the value, so with a new header it has to be typed again. Nothing was changed.', status: 400 };
            const r = sims.ruleFrom({ name: input.name, header, value: keep ? 'kept' : typed, ips: input.ips });
            if (r.error) return { error: `${r.error} Nothing was changed.`, status: 400 };
            after = Object.assign({}, r.rule, { id: before.id, valueHash: keep ? before.valueHash : r.rule.valueHash });
            return { rules: cur.rules.map(x => (x.id === id ? after : x)) };
        }, by, () => `edited the phishing-training rule "${before.name}"${after.name !== before.name ? ` (now "${after.name}")` : ''}: header ${after.headerShown}${after.valueHash ? (after.valueHash === before.valueHash ? ', secret value kept' : ', with a new secret value') : ', no secret value'}${after.ips.length ? `, from ${after.ips.length} sending address${after.ips.length === 1 ? '' : 'es'}` : ', from any address'}`);
    }
    setTrainingDomains(text, by) {
        const d = sims.domainsFrom(spruce.load(), text);
        if (d.invalid.length) return Promise.resolve({ error: `Not a domain: ${d.invalid.slice(0, 5).join(', ')}. Nothing was changed.`, status: 400 });
        if (d.refused.length) return Promise.resolve({ error: `Never a training domain: ${d.refused.slice(0, 5).map(x => `${x.domain} (${x.why})`).join('; ')}. A real phishing email linking only there would be let through. List only domains your vendor owns. Nothing was changed.`, status: 400 });
        return this.trainingChange(() => ({ domains: d.domains }), by,
            () => (d.domains.length ? `set the phishing-training link domains (${d.domains.length}: ${d.domains.slice(0, 5).join(', ')}${d.domains.length > 5 ? '…' : ''}): an email whose links all go there is let through unchecked` : 'removed the phishing-training link domains'));
    }

    // --- The weekly summary email (Settings → Weekly summary; off by default) --------------------------
    // To the dashboard's admins in the organization: ADMIN_EMAILS and the members of ADMIN_GROUP.
    async digestRecipients() {
        const out = new Set(this.cfg.adminEmails);
        for (const g of this.cfg.adminGroups) for (const u of await this.gmail.groupMembers(this.cfg.directoryAdmin, g, this.cfg.orgDomains)) out.add(u);
        return [...out].filter(a => this.cfg.orgDomains.includes(a.split('@')[1]));
    }
    async digestContent(now = this.now()) {
        const records = await this.store.listRecords({ sinceMs: now - 8 * DAY, limit: 100000 });
        const stats = await this.store.getStats(this.dayOf(now - 7 * DAY), this.dayOf(now));
        const events = await this.store.listEvents(now - 7 * DAY);
        const users = (await this.store.listUsers()).filter(u => u.watched);
        const held = (await this.store.listHeldCampaigns()).filter(c => !c.decision).length;
        const readiness = this.cfg.mode === 'enforce' ? null : A.readiness(records, { now, days: 7, mode: this.cfg.mode, installedAt: await this.store.getState('installedAt'),
            brakeLimit: await this.brakeLimit(), holdAfter: this.cfg.campaignHoldAfter, watched: users.length,
            lastNotification: Math.max(0, ...users.map(u => Number(u.lastNotification) || 0)) || null, quietHours: this.cfg.quietHours, renew: null });
        return buildDigest(records, stats, events, { now, mode: this.cfg.mode, timeZone: this.cfg.timeZone, dashboardUrl: this.cfg.dashboardUrl,
            watched: users.length, held, brake: !!(await this.store.getState('brake')), readiness });
    }
    // Puts this week's summary in each admin's Inbox now. { sent, to, failed }.
    async sendDigest({ by = null } = {}) {
        const to = await this.digestRecipients();
        if (!to.length) return { sent: 0, to: [], failed: [], error: 'nobody to send it to (ADMIN_EMAILS, ADMIN_GROUP)' };
        const d = await this.digestContent();
        const org = this.cfg.orgDomains[0] || 'localhost';
        const from = `"S.P.R.U.C.E Mail Protection Service" <${this.cfg.directoryAdmin || `no-reply@${org}`}>`;
        const out = { sent: 0, to, failed: [] };
        for (const user of to) {
            try {
                const raw = mime({ from, to: user, subject: d.subject, text: d.text, date: new Date(this.now()), messageId: `<spruce-summary-${this.now()}-${crypto.randomBytes(6).toString('hex')}@${org}>` });
                const r = await this.gmail.insert(user, raw, ['INBOX', 'UNREAD']);
                if (r && r.id) await this.store.markSeen(user, r.id);   // (and isSummary) never judged
                out.sent++;
            } catch (e) { out.failed.push(user); this.log.error(`weekly summary to ${user}:`, e); }
        }
        const st = (await this.store.getState('digest')) || {};
        await this.store.setState('digest', Object.assign({}, st, { lastSentAt: this.now(), lastSentBy: by }));
        await this.store.addEvent({ kind: 'digest', text: `The weekly summary was put in ${out.sent} admin Inbox${out.sent === 1 ? '' : 'es'}${by ? ` (sent now by ${by})` : ''}${out.failed.length ? `; ${out.failed.length} couldn't be reached` : ''}.` });
        return out;
    }
    // From the hourly job: on Monday from 7 AM (TIME_ZONE), once a week, when it is on.
    async maybeDigest() {
        const st = (await this.store.getState('digest')) || {};
        if (!st.enabled) return null;
        const t = localParts(this.now(), this.cfg.timeZone);
        if (t.weekday !== 1 || t.hour < 7) return null;
        if (!(await this.store.setStateIfUnset(`digest-${t.week}`, { at: this.now() }))) return null;   // once, whichever instance
        return this.sendDigest();
    }
    async setDigest(enabled, by) {
        const st = (await this.store.getState('digest')) || {};
        await this.store.setState('digest', Object.assign({}, st, { enabled: !!enabled, updatedBy: by, updatedAt: this.now() }));
        await this.store.addEvent({ kind: 'settings', text: `${by} turned the weekly summary email ${enabled ? 'on' : 'off'}.` });
        return { enabled: !!enabled };
    }

    // --- The retraining export (Health → Retraining examples; off until an admin allows it in Settings → Retraining)
    // The emails an admin marked (confirmed phishing; with falseAlarms, false alarms too), one per
    // campaign, newest first, read from Gmail now and turned into the extension's training format with
    // the people taken out (src/training.js). Nothing of them is stored: the rows are only returned.
    // Judged again (without the colleague, look-alike and thread lookups) for the facts the model reads;
    // nothing is counted.
    async trainingExport({ days = 90, falseAlarms = false, by = '', max = 100, budgetMs = 150000 } = {}) {
        const st = (await this.store.getState('trainingExport')) || {};
        if (!st.enabled) return { error: 'off' };
        const records = await this.store.listRecords({ sinceMs: this.now() - days * DAY, limit: 100000 });
        const { groups, conflicting } = training.pickRecords(records, { falseAlarms });
        const rows = [], counts = { phishing: 0, genuine: 0, gone: 0, failed: 0, notReached: 0, notEnglish: 0, conflicting, candidates: groups.length };
        const started = Date.now();
        let reached = 0;
        // The newest copy still in a mailbox (up to 3 tried): a copy deleted since doesn't lose the campaign.
        const readOne = async (copies) => {
            for (const rec of copies.slice(0, 3)) {
                let msg;
                try { msg = await this.gmail.raw(rec.user, rec.messageId); }
                catch (e) { if (e && e.status === 404) continue; throw e; }
                if (msg && msg.raw && msg.raw.length && !isSummary(msg.raw)) return { rec, msg };
            }
            return null;
        };
        await pool(groups, 4, async (copies) => {
            reached++;
            try {
                const got = await readOne(copies);
                if (!got) { counts.gone++; return; }
                const { rec, msg } = got;
                const facts = await readMessage(msg.raw, { ownDomains: this.cfg.orgDomains });
                const allowlisted = isAllowed(this.cfg, facts.senderAddress), verified = senderVerified(facts);
                const result = await analyze(facts, { mailbox: rec.user, orgDomains: this.cfg.orgDomains, allowLinkDomains: this.cfg.allowLinkDomains, trusted: allowlisted && verified, firstTime: false, intel: this.intel, keepAiFacts: true });
                // The model learns English only (an email clearly in another language is left out, and counted).
                if (!result.language.english) { counts.notEnglish++; return; }
                const label = rec.falseAlarm === false ? 1 : 0;
                // (0.6.26) The three-way class (genuine, spam, phishing) beside the two-way label the training reads today.
                // (0.5.56) The whole body (aiFacts holds only what the model is given, at most 8,000 characters).
                rows.push({ at: rec.processedAt, row: training.example(rec, label, Object.assign({}, result.aiFacts, { bodyText: String(facts.visibleText || '') }), facts.people, this.cfg.orgDomains) });
            } catch (e) { counts.failed++; this.log.error(`retraining export ${copies[0].key}:`, e); }
        }, () => rows.length >= max || Date.now() - started > budgetMs);
        counts.notReached = groups.length - reached;
        const out = rows.sort((a, b) => b.at - a.at).slice(0, max).map(x => x.row);
        counts.phishing = out.filter(r => r.label === 1).length; counts.genuine = out.length - counts.phishing;
        counts.spam = out.filter(r => r.class === 'spam').length;
        await this.store.addEvent({ kind: 'training', text: `${by} downloaded the retraining export: ${out.length} example${out.length === 1 ? '' : 's'} (${counts.phishing} phishing or spam${counts.spam ? `, ${counts.spam} of them marked as spam` : ''}${falseAlarms ? `, ${counts.genuine} false alarm${counts.genuine === 1 ? '' : 's'}` : ''}) from the last ${days} days${counts.gone ? `; ${counts.gone} no longer in a mailbox` : ''}. Nothing of them was stored.` });
        return { rows: out, counts, days, falseAlarms };
    }
    async setTrainingExport(enabled, by) {
        const st = (await this.store.getState('trainingExport')) || {};
        await this.store.setState('trainingExport', Object.assign({}, st, { enabled: !!enabled, updatedBy: by, updatedAt: this.now() }));
        await this.store.addEvent({ kind: 'settings', text: `${by} ${enabled ? 'allowed' : 'turned off'} the retraining export (Health → Retraining examples: Download for retraining).` });
        return { enabled: !!enabled };
    }

    // --- Several emails at once (Messages, and Review) -----------------------------------------------
    // action: release | false-alarm | phishing | unclear (set aside). { done, skipped, failed }. Each works as
    // for one email: phishing still in the Inbox is moved to Spam too (enforce mode; moved says how many), a
    // false alarm in Spam goes back to the Inbox (released says how many). One Activity line for all of them.
    async bulk(keys, action, by) {
        const out = { done: 0, skipped: 0, failed: 0 };
        if (action === 'phishing' || action === 'spam') out.moved = 0;
        if (action === 'false-alarm') out.released = 0;
        await pool(keys, 10, async (key) => {
            try {
                const r = action === 'release' ? await this.release(key, by, { quiet: true }) : action === 'unclear' ? await this.setAside(key, by, { quiet: true })
                    : await this.mark(key, action === 'false-alarm', by, { move: action === 'phishing' || action === 'spam', quiet: true, spam: action === 'spam' });
                if (r && r.record) out.done++; else out.skipped++;
                if (r && r.moved === 'moved') out.moved++;
                if (r && r.released) out.released++;
            } catch (e) { out.failed++; this.log.error(`bulk ${action} ${key}:`, e); }
        });
        const what = { release: 'moved back to the Inbox', 'false-alarm': 'marked as false alarms', phishing: 'confirmed as phishing', spam: 'confirmed as spam', unclear: 'set aside as unclear (left as they are, not used for retraining)' }[action];
        if (out.done) await this.store.addEvent({ kind: action === 'release' ? 'release' : 'mark', text: `${by} ${what} ${out.done} email${out.done === 1 ? '' : 's'} at once${out.moved ? ` (${out.moved} moved to Spam)` : ''}${out.released ? ` (${out.released} moved back to the Inbox)` : ''}.` });
        return out;
    }

    // Whether the service is getting Gmail's notifications at all, and its watches are renewed. Each
    // problem is alerted once a day: no notification for QUIET_HOURS for any watched mailbox (they may be
    // refused before reaching the service), ERRORS_ALERT errors or more in the last hour (0.5.29), or watches
    // ending within a day (the daily re-read failing). The hourly job runs it.
    // (Counted, not read: three small queries, not 10,000 documents an hour.)
    async health() {
        const now = this.now();
        const sum = await this.store.mailboxSummary(now + DAY);
        const out = { watched: sum.watched };
        if (!sum.watched) return out;
        const once = async (name, kind, text) => {
            if (now - (Number(await this.store.getState(name)) || 0) < DAY) return;
            await this.store.setState(name, now);
            await this.alert(kind, text);
        };
        const last = sum.lastNotification || 0;
        const since = last || Number(await this.store.getState('installedAt')) || now;
        out.lastNotification = last || null;
        if (now - since > this.cfg.quietHours * HOUR) {
            out.quiet = true;
            await once('quietAlertAt', 'quiet', `No notification from Gmail for ${Math.round((now - since) / HOUR)} hours, for any of the ${sum.watched} watched mailboxes. Gmail's notifications may be refused before they reach the service: docs/INSTALL.md, Troubleshooting, "The jobs and notifications are refused".`);
        }
        // Many errors in the last hour (0.5.29): something stopped working (Firestore, Gmail, the model…).
        try {
            const errs = (await this.store.listEvents(now - HOUR)).filter(e => e.kind === 'error').length;
            out.errorsLastHour = errs;
            if (errs >= ERRORS_ALERT) await this.alertDaily('errors', `${errs} errors in the last hour: something may have stopped working. Health → Activity → Errors and gaps says what failed; Health → Service status, and bash deploy/doctor.sh, check the rest.`);
        } catch (e) { /* the next hour */ }
        out.expiring = sum.ending;
        if (out.expiring) await once('expiringAlertAt', 'watch-expiring', `${out.expiring} mailbox watches end within a day and weren't renewed: the daily re-read of the group (spruce-renew-watches) may be failing. Settings → Mailboxes says when it last reached the service.`);
        return out;
    }
}

module.exports = { Service, ownSentCopy, campaignOf, senderHash, recordKey, dayOf, POLICY_KEYS, policyValue, STAT_FLUSH_MS, Slots, EMAIL_SLOTS, LARGE_SLOTS };
