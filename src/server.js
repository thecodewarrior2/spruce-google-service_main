'use strict';
// The HTTP service (Cloud Run). One image, two services (ROLE): the worker answers /pubsub/push and /tasks/*
// only, the dashboard (admin) everything else; ROLE=all (demo mode, a computer of your own) answers both.
//   POST /pubsub/push              Gmail notifications, from Pub/Sub (OIDC-verified)
//   POST /tasks/renew-watches      daily, from Cloud Scheduler (OIDC-verified): the directory read again, watches renewed
//   POST /tasks/sync-feeds         hourly, from Cloud Scheduler (spruce-sync-feeds): the health check, the phishing
//                                  lists (downloaded once for everyone), re-checks, the look-alike watch, the weekly
//                                  summary and the cleanup (pipeline.js syncFeeds)
//   POST /tasks/purge              records past RETENTION_DAYS deleted (the hourly sync-feeds does it since
//                                  0.4.1; kept for an older installation's daily job)
//   POST /tasks/stop-watches       by hand (deploy/stop.sh, through a one-off Cloud Scheduler job), to switch the
//                                  service off: every mailbox watch is stopped (pipeline.js stopAll)
//   GET  /healthz                  for Cloud Run
//   /api/*  and  /                 the dashboard, behind Identity-Aware Proxy: ADMIN_EMAILS / ADMIN_GROUP, and
//                                  MODERATOR_GROUP for the review routes only (MODERATOR_ROUTES). POSTs need the
//                                  x-requested-with: spruce-dashboard header. By page (the `api` table below):
//     Today, Review            GET overview, pending, review; POST mark, unclear, rescan, bulk, release, resume
//     Threats                  GET campaigns, campaign, rechecked, lookalikes; POST campaign/confirm,
//                              campaign/release, campaign/find, rechecked/seen, lookalikes/mark
//     Mail                     GET messages, message, users, export.csv; POST check, message/context
//     Health                   GET status, readiness, health, dmarc, reputation, activity, activity.csv;
//                              POST training-export
//     Settings                 GET settings, mailboxes, scope-preview, clicks, user-reports, phish-training, digest/preview,
//                              update; POST policy, renew-watches (runs the Cloud Scheduler job: src/scheduler.js),
//                              lists/recheck, keys/save, keys/remove, safe-browsing/key, safe-browsing/remove,
//                              clicks, clicks/test, user-reports, user-reports/test, phish-training/rule, …/rule/edit, …/rule/remove,
//                              phish-training/domains, digest, digest/send, update, update/check,
//                              training-export/allow, settings-backup/export, settings-backup/preview, settings-backup/import
//     Every page, Help         GET session, help
//   GET  /*                        the dashboard's files (public/)
const http = require('http');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { loadConfig, configProblems } = require('./config');
const { createStore } = require('./store');
const { Service, POLICY_KEYS, STAT_FLUSH_MS } = require('./pipeline');
const { verifyPush, verifyTask, verifyAdmin, adminGroupCheck } = require('./auth/verify');
const { createDmarcCheck } = require('./dashboard/dmarc');
const { createReputation } = require('./dashboard/reputation');
const { RecordCache, EventCache } = require('./dashboard/cache');
const VERSION = require('../package.json').version;
const A = require('./dashboard/aggregate');
const spruce = require('./engine/spruce');
const training = require('./training');
const { createReleases, parseChangelog, modelSourceOf } = require('./releases');
const repos = require('./repos');
const { updateInfo, startUpdate, checkNow } = require('./update');
const { suspiciousWhy, rulesOnlyVerified, strictKinds } = require('./policy');

const PUBLIC = path.resolve(__dirname, '..', 'public');
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json' };
const SECURITY_HEADERS = {
    'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'x-frame-options': 'DENY', 'cache-control': 'no-store'
};

// (0.6.7) A text answer over GZIP_FROM bytes is sent compressed when the browser accepts it (Messages' list was
// about 85 KB at every refresh; the dashboard's script about 200 KB at every load).
const GZIP_FROM = 8 * 1024;
function send(res, status, body, type = 'application/json', extra = {}) {
    let out = type === 'application/json' ? JSON.stringify(body) : body;
    const headers = Object.assign({ 'content-type': type }, SECURITY_HEADERS, extra);
    const accepts = /\bgzip\b/.test(String((res.req && res.req.headers && res.req.headers['accept-encoding']) || ''));
    if (accepts && /^(application\/json|text\/|image\/svg)/.test(type) && out && Buffer.byteLength(out) >= GZIP_FROM) {
        out = zlib.gzipSync(out, { level: 6 });
        Object.assign(headers, { 'content-encoding': 'gzip', vary: 'accept-encoding' });
    }
    res.writeHead(status, headers);
    res.end(out);
}
async function readBody(req, max = 1024 * 1024) {
    let size = 0; const chunks = [];
    for await (const c of req) { size += c.length; if (size > max) throw Object.assign(new Error('too large'), { status: 413 }); chunks.push(c); }
    const text = Buffer.concat(chunks).toString('utf8');
    try { return text ? JSON.parse(text) : {}; } catch (e) { throw Object.assign(new Error('not JSON'), { status: 400 }); }
}

// How long the dashboard keeps today's counters before reading them again (pages refresh every 30 s).
const STATS_TODAY_MS = 15 * 1000;
// How long the mailboxes in numbers (and the worker's AI engine report) are kept before reading them again.
const MAILBOXES_KEPT_MS = 60 * 1000;
// The dashboard's view of a record in a list (Messages): what an admin needs, nothing of the email's text
// beyond the subject (which can be turned off: STORE_SUBJECTS); an email's own page reads the whole record.
const brief = (r) => ({ key: r.key, user: r.user, processedAt: r.processedAt, sender: r.sender, subject: r.subject, campaign: r.campaign,
    status: r.status, score: r.score, ai: r.ai ? Math.round((r.ai.probability || 0) * 1000) / 1000 : null, aiSpam: r.ai && typeof r.ai.spam === 'number' ? Math.round(r.ai.spam * 1000) / 1000 : null, action: r.action, trigger: r.trigger, state: r.state, mode: r.mode || null, movedAt: r.movedAt || null, spam: !!r.spam, releasedByUser: !!r.releasedByUser, falseAlarm: r.falseAlarm, unclear: !!r.unclear,
    // (0.6.60) reported by its reader with Gmail's Report phishing (Settings → User reports)
    userReported: r.userReported ? { at: r.userReported.at || null } : undefined,
    // found after delivery (0.5.35): the Messages list marks it
    recheck: r.recheck ? { at: r.recheck.at, outcome: r.recheck.outcome, opened: !!(r.recheck.opened || (r.recheck.clicks && r.recheck.clicks.opened)), clicked: !!(r.recheck.clicks && r.recheck.clicks.clicked) } : null });

// Records from before 0.5.12 said only "suspicious, below the move rules": shown with what made them
// suspicious (the rule checks' score, the AI's), from the record itself, with today's thresholds.
const OLD_WHY = 'suspicious, below the move rules';
function withPlainWhy(r, cfg) {
    if (typeof r.why !== 'string' || !r.why.startsWith(OLD_WHY)) return r;
    return Object.assign({}, r, { why: suspiciousWhy(r, cfg) + r.why.slice(OLD_WHY.length) });
}

// The group re-read from the dashboard: at most once a minute, and its last run remembered for 15 s
// (Settings → Mailboxes, Health → Service status and Readiness refresh every 30 s in each open dashboard).
const RENEW_GAP_MS = 60 * 1000, RENEW_STATUS_MS = 15 * 1000;
// "Check an email": the largest email accepted (as pasted or uploaded).
const CHECK_MAX_BYTES = 10 * 1024 * 1024;
// Changing the policy on the dashboard needs the Google Cloud project ID (in demo mode: this one), and a
// few wrong ones in a row lock it for a while.
const DEMO_PROJECT = 'demo-project';
const POLICY_TRIES = 5, POLICY_LOCK_MS = 10 * 60 * 1000;
// What a policy change is for, in Activity's words (a wrong project ID, 0.5.30).
const POLICY_WHAT = { mode: 'the mode', aiThreshold: 'the AI move threshold', aiSuspicious: 'the AI suspicious line', aiScansInside: 'whether the AI reads inside mail',
    aiMovesInside: 'whether the Let the AI alone move staff email', safeBrowsing: 'Google Safe Browsing (on or off)', spamhaus: 'Spamhaus (on or off)', abusech: 'abuse.ch (on or off)', suspiciousLabel: 'the Suspicious label', recheck: 're-checking delivered mail', brakePerHour: 'the brake', timeZone: 'the time zone',
    strictSpam: 'Skip review', allowDomains: 'the allowlisted domains', allowAddresses: 'the allowlisted addresses', allowLinkDomains: 'the allowed link domains', releasesRepo: 'the release repository', modelRepo: 'the model repository', retentionDays: 'how long records are kept', watchScope: 'who is checked (the pilot or the whole domain)' };
// The project ID a policy change must be confirmed with ('' when the dashboard doesn't know it).
const expectedProject = (cfg) => cfg.project || (cfg.demo ? DEMO_PROJECT : '');

// (0.6.68) Review's queues: src/review-queues.js decides each email's one queue (or none), in one order, for Review's tabs,
// the pending count and the answers that also answer other waiting emails.
const RQ = require('./review-queues');
const Backup = require('./settings-backup');
// What Review lists from: the recent records, with the Sender lists' test (pipeline.js senderListTest) that review-queues.js
// applies (a reader's report stays listed even from a sender on a list).
async function reviewRecords(service, cache, sinceMs) {
    const records = await cache.list(sinceMs);
    const listed = await service.senderListTest().catch(() => () => null);
    return { records, listed };
}
// A review queue as items: the copies of one campaign together (in the queue's order, where its first copy
// is), each with its keys, recipients and senders (at most 2000 of each), and what the list shows of it
// (src/dashboard/aggregate.js, shared with the clickable mockup).
const reviewGroups = A.reviewGroups;
// (0.6.1) What a moderator (MODERATOR_GROUP) may use: Today, Review, Threats → Campaigns and Re-checked, Mail
// (Messages, an email's page, Check an email, Users) and Help; the review answers: phishing, false alarm (which moves
// one in Spam back to the Inbox), ignore and re-scan, one at a time or ticked together; reading an email from Gmail
// to decide (Show the email); and confirming, dismissing or searching for a whole campaign. Never Health, Settings,
// Look-alikes, the CSV export, the brake, or moving back an email nobody marked a false alarm.
const MODERATOR_ROUTES = new Set(['GET /api/session', 'GET /api/overview', 'GET /api/pending', 'GET /api/review', 'GET /api/message', 'GET /api/messages',
    'GET /api/campaigns', 'GET /api/campaign', 'GET /api/users', 'GET /api/rechecked', 'GET /api/help', 'GET /api/remembered',
    'POST /api/mark', 'POST /api/unclear', 'POST /api/undo', 'POST /api/campaign/answer', 'POST /api/rescan', 'POST /api/check', 'POST /api/bulk',
    'POST /api/campaign/confirm', 'POST /api/campaign/release', 'POST /api/campaign/find', 'POST /api/message/context']);
const MODERATOR_BULK = ['false-alarm', 'phishing', 'spam', 'unclear'];
function moderatorMay(route, action) {
    if (!MODERATOR_ROUTES.has(route)) return false;
    return route !== 'POST /api/bulk' || MODERATOR_BULK.includes(action);
}
// A user took back an email the rule checks flagged (a score of 5 or more, not moved by the AI alone), and no
// admin has looked yet.
const rescueToCheck = (r) => r.state === 'released' && r.releasedByUser && !r.markedBy && r.score >= 5 && r.trigger !== 'ai';

// Demo mode reads no GitHub: a made-up newer version, then this version's own changelog.
function demoReleases({ manual = false } = {}) {
    const file = path.resolve(__dirname, '..', 'CHANGELOG.md');
    const own = fs.existsSync(file) ? parseChangelog(fs.readFileSync(file, 'utf8')) : [];
    const PKG = require('../package.json');
    let model = null, modelSource = null;
    try { const v = JSON.parse(fs.readFileSync(path.resolve(__dirname, '..', 'vendor', 'spruce', 'VENDOR.json'), 'utf8')); model = v.model; modelSource = modelSourceOf(v); } catch (e) { /* none */ }
    return { CACHE_MS: 10 * 60 * 1000, newest: async () => ({ repo: 'demo (GitHub not read)', commit: '0'.repeat(40), date: new Date().toISOString(), checkedAt: Date.now(), version: '9.9.9', installLevel: (Number(PKG.installLevel) || 0) + (manual ? 1 : 0), model, modelSource,
        changelog: [{ version: '9.9.9', title: manual ? 'A made-up newer version that changes the installation (demo mode)' : 'A made-up newer version (demo mode)', body: '- Demo mode doesn\'t read GitHub: this entry is made up, so you can try the page.\n- The real page shows spruce-google-service_main\'s changelog: everything newer than the version installed, then the rest.' }, ...own] }) };
}

// The Help tab (0.5.46): the installed version's own docs, from files in the image, only these, and only these
// sections of them ('': what comes before the first section). Read once.
const HELP_DOCS = {
    howitworks: { title: 'How it works', file: 'README.md', sections: ['', 'How it decides'] },
    dashboard: { title: 'The dashboard', file: 'README.md', sections: ['The dashboard'] },
    alerts: { title: 'Alerts', file: 'docs/ALERTS.md' },
    privacy: { title: 'Your privacy', file: 'docs/PRIVACY.md' },
    workspace: { title: 'Google Workspace settings', file: 'docs/WORKSPACE.md' },
    install: { title: 'Install, upgrade and troubleshooting', file: 'docs/INSTALL.md' },
    settings: { title: 'Settings reference', file: 'docs/DEPLOY.md', sections: ['Settings (environment variables)'] },
    costs: { title: 'Costs', file: 'docs/COSTS.md' },
    architecture: { title: 'Architecture deep dive', file: 'docs/ARCHITECTURE.md' }
};
const helpCache = new Map();
function helpDoc(id) {
    const d = HELP_DOCS[id];
    if (!d) return null;
    if (helpCache.has(id)) return helpCache.get(id);
    let text;
    try { text = fs.readFileSync(path.resolve(__dirname, '..', d.file), 'utf8'); }
    catch (e) { return { error: 'This installation\'s image doesn\'t have its docs (an image built before 0.5.46). They are in the repository: ' + d.file + '.', status: 404 }; }
    if (d.sections) {
        const parts = text.split(/^## /m);
        const head = parts[0].replace(/^# .*\n/, '').replace(/\*\*Two repositories\.\*\*[\s\S]*?\n\n/, '');
        text = d.sections.map(name => (name === '' ? head : (() => { const p = parts.slice(1).find(x => x.split('\n')[0].trim() === name); return p ? `## ${p}` : ''; })())).join('\n\n');
    } else text = text.replace(/^# .*\n/, '');
    const out = { id, title: d.title, source: d.file, markdown: text.trim() };
    helpCache.set(id, out);
    return out;
}

function createApp({ cfg, store, service, scheduler = null, cloudrun = null, releases = null }) {
    // (0.6.9) The approved versions from the release repository set now (settings.env or the dashboard): a new
    // reader when it changes.
    let releasesSource = null;
    if (!releases && !cfg.demo) {
        let cur = null;
        const now = () => { if (!cur || cur.repoSet !== cfg.releasesRepo) { cur = createReleases({ repo: cfg.releasesRepo }); cur.repoSet = cfg.releasesRepo; } return cur; };
        releasesSource = { reset: () => { cur = null; } };
        releases = { newest: (o) => now().newest(o), get CACHE_MS() { return now().CACHE_MS; }, get repo() { return now().repo; } };
    }
    releases = releases || demoReleases();
    // The hourly job looks for an approved version that needs a manual install (0.5.24), with these.
    if (service && typeof service === 'object' && !cfg.demo) { if (!service.releases) service.releases = releases; if (!service.cloudrun) service.cloudrun = cloudrun; }
    // A lookup service that stopped working is an alert, at most once a day (0.5.28).
    if (service && service.intel && typeof service.alertDaily === 'function') {
        if (service.intel.threats && service.intel.threats.setAlert) service.intel.threats.setAlert((name, text) => service.alertDaily(`${name}-down`, text));
        if (service.intel.sbKey && service.intel.sbKey.setAlert) service.intel.sbKey.setAlert((text) => service.alertDaily('safe-browsing-key', text));
        // Spamhaus refusing the key or the lookups (0.5.37): emailed at most once a day. (abuse.ch refusing its
        // key is a list that missed its download: the list-download alert.)
        if (service.intel.keys && service.intel.keys.spamhaus) service.intel.keys.spamhaus.setAlert((text) => service.alertDaily('spamhaus-key', text));
    }
    // The dashboard's copy of the records (src/dashboard/cache.js): the last 32 days at first, older records
    // when a page shows them (Last 90 days, plus the day before that `load` reads: 92), never past how long
    // records are kept (RETENTION_DAYS, or Settings → Policy: the copy forgets them too).
    const cache = new RecordCache(store, { keepDays: () => Math.min(92, cfg.retentionDays || 35) });
    const events = new EventCache(store);   // (0.6.7) Activity's events, read once and then only the new ones
    const eventsSince = (sinceMs, limit) => events.list(sinceMs, { limit });
    // (0.6.7) Answers shared by every open dashboard for a few seconds (what several pages and the pending badge
    // ask in the same refresh); a change made on the dashboard (any POST) clears them.
    const shortCache = new Map();
    const shortLived = (key, ms, fn) => {
        const hit = shortCache.get(key);
        if (hit && Date.now() - hit.at < ms) return hit.p;
        const p = Promise.resolve().then(fn);
        shortCache.set(key, { at: Date.now(), p });
        p.catch(() => { if (shortCache.get(key) && shortCache.get(key).p === p) shortCache.delete(key); });
        return p;
    };
    let statusCache = null; const STATUS_CACHE_MS = 60 * 1000;   // (Health → Service status: see GET /api/status)
    // The mailboxes in numbers (how many watched, the latest notification, watches ending within a day):
    // three small queries, kept a minute, for Health → Service status, Health → Readiness and Settings, which
    // open pages fetch every 30 s. (Reading every mailbox's document there cost 10,000 reads a page at 10,000
    // mailboxes.) Only Settings → Mailboxes lists them, a page at a time (GET /api/mailboxes).
    let mailboxInfo = null;
    const mailboxes = async () => {
        if (!mailboxInfo || Date.now() - mailboxInfo.at > MAILBOXES_KEPT_MS) mailboxInfo = { at: Date.now(), v: await store.mailboxSummary(Date.now() + A.DAY) };
        return mailboxInfo.v;
    };
    // The daily counters (stats/{day}~{shard}): a past day no longer changes, so each instance reads it
    // once; today is read again after STATS_TODAY_MS. (Ten minutes after midnight yesterday still counts as
    // today: instances write what they added up every few seconds. clear-data.sh restarts the dashboard.)
    const pastStats = new Map(); let todayStats = null;
    const statsFor = async (fromDay, toDay) => {
        const now = Date.now(), today = A.dayOf(now), settled = A.dayOf(now - 10 * 60 * 1000) < today ? A.dayOf(now - A.DAY) : today;
        const days = [];
        for (let d = fromDay; d <= toDay; d = A.addDays(d, 1)) days.push(d);
        const missing = days.filter(d => d < settled && !pastStats.has(d));
        if (missing.length) {
            const rows = await store.getStats(missing[0], missing[missing.length - 1]);
            const got = new Map(rows.map(r => [r.day, r]));
            for (const d of missing) pastStats.set(d, got.get(d) || null);
        }
        const recent = days.filter(d => d >= settled);
        if (recent.length && (!todayStats || todayStats.from !== recent[0] || now - todayStats.at > STATS_TODAY_MS)) {
            todayStats = { from: recent[0], at: now, rows: await store.getStats(recent[0], recent[recent.length - 1] > today ? recent[recent.length - 1] : today) };
        }
        const live = new Map(((todayStats && todayStats.rows) || []).map(r => [r.day, r]));
        return days.map(d => (d >= settled ? live.get(d) : pastStats.get(d))).filter(Boolean);
    };
    let renewAskedAt = 0, renewStatus = null, renewStatusAt = 0;
    const canRenew = () => !!(scheduler && cfg.renewJob);
    // The renew-watches job's last run (Cloud Scheduler: when, and whether it reached the worker), asked at
    // most every RENEW_STATUS_MS; null when the job isn't known here (demo mode makes one up).
    async function lastRenew() {
        if (cfg.demo && !canRenew()) return { at: Date.now() - 15 * 60 * 60 * 1000, code: 0 };
        if (!canRenew()) return null;
        if (Date.now() - renewStatusAt > RENEW_STATUS_MS) {
            renewStatus = await scheduler.lastRun(cfg.renewJob).catch(e => ({ error: String(e.message).slice(0, 200) }));
            renewStatusAt = Date.now();
        }
        return renewStatus;
    }
    const groupCheck = cfg.adminGroups.length && service.gmail && service.gmail.hasMember ? adminGroupCheck(cfg, service.gmail) : null;
    // Health → DMARC & reputation (0.6.1): your domains' DMARC and SPF records, read through Cloudflare's resolver (made up in demo mode).
    const dmarcCheck = createDmarcCheck({ http: service.intel && service.intel.http, demo: !!cfg.demo });
    // ... and whether they are on a blocklist or in the downloaded phishing lists (made up in demo mode).
    const reputation = createReputation({ cfg, intel: service.intel, store, demo: !!cfg.demo });
    // (0.6.1) Who is in MODERATOR_GROUP, checked like ADMIN_GROUP (src/auth/verify.js; an admin stays an admin).
    const moderatorCheck = (cfg.moderatorGroups || []).length && service.gmail && service.gmail.hasMember ? adminGroupCheck(cfg, service.gmail, () => Date.now(), cfg.moderatorGroups) : null;
    // A page's period (?days=, 1 to 90, 30 by default): its start, and its number of days (nDays below).
    const since = (q) => Date.now() - Math.min(90, Math.max(1, Number(q.get('days')) || 30)) * A.DAY;
    // Activity's period: up to how long it is kept (AUDIT_DAYS); its kind and words to look for.
    const activityFor = async (q) => {
        const days = Math.min(cfg.auditDays || 365, Math.max(1, Math.round(Number(q.get('days')) || 30)));
        const words = String(q.get('q') || '').trim().toLowerCase().slice(0, 200);
        let events = A.activity(await eventsSince(Date.now() - days * A.DAY, 10000), String(q.get('kind') || ''));
        if (words) events = events.filter(e => `${e.text || ''} ${e.user || ''} ${e.kind || ''} ${e.by || ''}`.toLowerCase().includes(words));
        return { events, days };
    };
    const nDays = (q) => Math.min(90, Math.max(1, Number(q.get('days')) || 30));
    // A page's records (all of its period: the cache holds slim copies of every one) and daily counters.
    const load = async (q) => ({ records: await cache.list(since(q) - A.DAY), stats: await statsFor(A.dayOf(since(q)), A.dayOf(Date.now())) });

    // The brake, and how many emails it holds (still in the Inbox, recorded since it came on). The brake and the
    // held campaigns are read at most every 15 s (0.6.7, shortLived), shared with GET /api/pending.
    // A brake that is on (state: 'brake', or (0.6.63) 'spamBrake' with held 'spam-brake'), with the mail it left in the Inbox since.
    async function brakeInfo(records, state = 'brake', heldTag = 'brake') {
        const b = await shortLived(state, 15000, () => store.getState(state));
        if (!b) return null;
        return Object.assign({}, b, { held: records.filter(r => r.held === heldTag && r.state === 'inbox' && r.processedAt >= b.at).length });
    }
    // Campaigns held on weak evidence, waiting for an admin's decision.
    async function heldCampaigns(records) {
        const held = (await shortLived('held', 15000, () => store.listHeldCampaigns())).filter(c => !c.decision);
        return held.map(c => ({ campaign: c.key, label: c.label, heldAt: c.heldAt, held: records.filter(r => r.campaign === c.key && r.held === 'campaign' && r.state === 'inbox').length }))
            .sort((a, b) => b.held - a.held).slice(0, 20);
    }
    let digestSentAt = 0;   // the weekly summary's "Send one now": at most once a minute (this instance)
    // The worker's AI engine, as its newest instance reported it when it started (state/engine-worker), kept
    // a minute like the mailboxes.
    let workerEngine = null;
    const workerEngineInfo = async () => {
        if (!workerEngine || Date.now() - workerEngine.at > MAILBOXES_KEPT_MS) workerEngine = { at: Date.now(), v: await store.getState('engine-worker') };
        return workerEngine.v;
    };
    const pc = (x) => `${Math.round(x * 1000) / 10}%`;
    const ago = (ms) => { const m = Math.max(1, Math.round(ms / 60000)); return m < 120 ? `${m} minute${m === 1 ? '' : 's'} ago` : m < 48 * 60 ? `${Math.round(m / 60)} hours ago` : `${Math.round(m / 1440)} days ago`; };
    const checkWords = (c) => (c && typeof c.phishing === 'number' ? `self-check: a made-up phishing email ${pc(c.phishing)}, a made-up genuine one ${pc(c.genuine)}` : 'no self-check');
    // Health → Service status's checks: [{ id, ok (true, false, or null: couldn't check), text, fix }].
    async function statusChecks() {
        const now = Date.now(), out = [];
        // link (0.6.54): the dashboard page the fix names, opened by clicking it.
        const add = (id, ok, text, fix, link) => out.push(Object.assign({ id, ok, text, fix: ok === true ? null : fix || null }, ok !== true && link ? { link } : {}));
        // The AI model: loaded here (the dashboard: Check an email), and in the worker (every email).
        const ms = spruce.load().model.status();
        const loadFix = 'Until it loads, emails are judged by the rule checks alone. Look in the service\'s logs (Cloud Run → Logs) for "the AI model could not be loaded", then run bash deploy/install.sh again.';
        if (ms.state === 'ready' && ms.check) add('model', ms.check.ok, ms.check.ok ? `The AI model ${ms.model} is loaded in the dashboard, in the native engine (${ms.runtime}, ${ms.optimization} optimization, ${ms.threads} thread), in ${ms.loadMs} ms; ${checkWords(ms.check)}.`
            : `The AI model ${ms.model} is loaded in the dashboard, but its self-check failed (${ms.check.error || checkWords(ms.check)}).`, loadFix);
        else if (ms.state === 'failed') add('model', false, `The AI model ${ms.model} couldn't be loaded in the dashboard: ${ms.error}`, loadFix);
        else add('model', null, `The AI model ${ms.model} is still loading in the dashboard (${ms.state}).`, 'Reload this page in a few seconds.');
        const we = await workerEngineInfo().catch(() => null);
        const newest = (await cache.list(now - 7 * A.DAY).catch(() => [])).find(r => r.ai && typeof r.ai.probability === 'number');
        const scored = newest ? ` The newest email it scored (${ago(now - newest.processedAt)}) was scored by ${newest.ai.model || 'an unknown model'}.` : '';
        if (!we) add('model-worker', null, `The worker hasn't reported its AI engine yet: each worker instance does when it starts (after this version is deployed, at its first email or job).${scored}`, 'Send a test email to a watched mailbox, then reload this page.');
        else if (!we.ok) add('model-worker', false, `The worker couldn't load the AI model ${we.model} (${new Date(we.at).toISOString().slice(0, 16).replace('T', ' ')} UTC): ${we.error || (we.check && we.check.error) || checkWords(we.check)}.${scored}`, loadFix);
        else if (we.model !== ms.model) add('model-worker', false, `The worker runs the AI model ${we.model}, the dashboard ${ms.model}.${scored}`, 'Run bash deploy/install.sh (or upgrade.sh), so both run the same build.');
        else add('model-worker', true, `The worker loaded ${we.model} in the native engine (${we.runtime}) ${ago(now - we.at)} (version ${we.version}${we.revision ? `, ${we.revision}` : ''}), in ${we.loadMs} ms; ${checkWords(we.check)}.${scored}`);
        // (0.6.2) The domains the worker counts as the organization's, against the dashboard's: mail from a domain
        // only the dashboard has is "outside" to the worker, and read by the AI (a second domain added to
        // settings.env, but the worker not updated since).
        const mine = [...(cfg.orgDomains || [])].map(d => String(d).toLowerCase()).sort();
        if (we && Array.isArray(we.orgDomains)) {
            const theirs = we.orgDomains.map(d => String(d).toLowerCase()).sort();
            const missing = mine.filter(d => !theirs.includes(d)), extra = theirs.filter(d => !mine.includes(d));
            add('org-domains', !missing.length && !extra.length, !missing.length && !extra.length ? `The worker counts mail from ${mine.join(', ') || 'no domain'} as the organization's (when Gmail's DMARC check passes for it), as the dashboard does.`
                : `The worker counts only ${theirs.join(', ') || 'no domain'} as the organization's; the dashboard has ${mine.join(', ')}.${missing.length ? ` Mail from ${missing.join(', ')} is judged as mail from outside, and read by the AI.` : ''}`,
                'Run bash deploy/install.sh from Cloud Shell, so both services have ORG_DOMAINS from deploy/settings.env; then Re-scan the emails judged meanwhile.');
        } else if (we) add('org-domains', null, `The worker (version ${we.version || 'unknown'}) doesn't say which domains it counts as the organization's: versions before 0.6.2 don't. The dashboard has ${mine.join(', ')}.`,
            'Update both services (Settings → Update, or bash deploy/install.sh); the worker says so at its next start.');
        const project = cfg.project || (cfg.demo ? 'demo' : ''), region = cfg.region || (cfg.demo ? 'demo' : '');
        if (cloudrun && project && region) {
            try {
                const w = await cloudrun.service(project, region, 'spruce-worker');
                add('iap', !w.iap, w.iap ? 'Identity-Aware Proxy is ON for spruce-worker: Gmail\'s notifications and the scheduled jobs are refused.' : 'Identity-Aware Proxy is off for spruce-worker, as it must be.',
                    'Run bash deploy/install.sh (it turns it off), or: gcloud beta run services update spruce-worker --region=REGION --no-iap');
                const wv = ((w.image.split(':')[1] || '').split('-')[0]) || '';
                add('version', wv === VERSION, wv === VERSION ? `Both services run ${VERSION}.` : `The worker runs ${wv || 'an unknown build'}, the dashboard ${VERSION}.`, 'Run bash deploy/install.sh (or upgrade.sh), so both run the same build.');
                const inv = await cloudrun.invokers(project, region, 'spruce-worker');
                const okInv = inv.some(m => /^serviceAccount:spruce-invoker@/.test(m));
                add('invoker', okInv, okInv ? 'spruce-invoker may call the worker (Pub/Sub and the scheduled jobs sign in as it).' : 'spruce-invoker may not call the worker: notifications and jobs are refused.', 'Run bash deploy/install.sh (it grants roles/run.invoker to spruce-invoker).');
            } catch (e) { add('cloudrun', null, `Couldn't read the worker's settings: ${String(e.message).slice(0, 160)}`, 'The service account needs the Cloud Run Viewer role: run bash deploy/install.sh again.'); }
        } else add('cloudrun', null, 'The worker\'s settings aren\'t checked here (GOOGLE_CLOUD_PROJECT and CLOUD_RUN_REGION aren\'t set).', 'Run bash deploy/install.sh again.');
        const renew = await lastRenew();
        if (renew && renew.at) add('renew', !renew.code, renew.code ? `The last re-read of the group (${new Date(renew.at).toISOString().slice(0, 16).replace('T', ' ')} UTC) didn't reach the worker.` : 'The last re-read of the group reached the worker.',
            'docs/INSTALL.md, Troubleshooting, "The jobs and notifications are refused" (or run bash deploy/doctor.sh).');
        else add('renew', null, renew && renew.error ? `Couldn't read the re-read job: ${renew.error}` : 'The re-read job isn\'t known here (RENEW_JOB).', 'Run bash deploy/install.sh again.');
        // The hourly job: its name is the renew job's with spruce-sync-feeds in place of spruce-renew-watches
        // (install.sh makes both in the same project and region); late after 2 hours.
        if (canRenew()) {
            const sync = await scheduler.lastRun(cfg.renewJob.replace(/spruce-renew-watches$/, 'spruce-sync-feeds')).catch(e => ({ error: e.message }));
            if (sync.error) add('hourly', null, `Couldn't read the hourly job: ${String(sync.error).slice(0, 160)}`);
            else add('hourly', !!sync.at && !sync.code && now - sync.at < 2 * 3600 * 1000, sync.at ? `The hourly job (health check, phishing lists, weekly summary, cleanup) last ran ${Math.round((now - sync.at) / 60000)} minutes ago${sync.code ? ', and didn\'t reach the worker' : ''}.` : 'The hourly job hasn\'t run yet.',
                'Check spruce-sync-feeds in Cloud Scheduler, or run bash deploy/doctor.sh.');
        }
        // The colleague-name check (the directory's names, as one-way hashes, against outside senders' names).
        const names = await store.getState('colleagueNames').catch(() => null);
        const namesFix = 'Give DIRECTORY_ADMIN the Users → Read privilege (its admin role, Admin API privileges) and add https://www.googleapis.com/auth/admin.directory.user.readonly to the domain-wide delegation entry (docs/INSTALL.md, "The colleague-name check"). It is read again within an hour.';
        if (!cfg.colleagueNames) add('colleague-names', null, 'The colleague-name check is off (COLLEAGUE_NAMES=off).', 'Remove COLLEAGUE_NAMES=off from both services\' settings (docs/DEPLOY.md) to turn it on.');
        else if (!cfg.directoryAdmin) add('colleague-names', null, 'The colleague-name check is off: DIRECTORY_ADMIN isn\'t set, so the directory\'s names can\'t be read.', 'Set DIRECTORY_ADMIN in deploy/settings.env and run bash deploy/install.sh.');
        else if (!names) add('colleague-names', null, 'The colleague-name check hasn\'t read the directory yet: the worker does at its first email.', null);
        else if (names.error) add('colleague-names', false, `The colleague-name check couldn't read the directory's names (${ago(now - names.at)}): ${names.error}${names.names ? ` It uses the ${names.names} it read before.` : ''}`, namesFix);
        else add('colleague-names', true, `The colleague-name check knows ${names.names} names from the directory (read ${ago(now - names.at)}): an outside sender using one of them is a sign.`, null);
        const mb = await mailboxes();
        const last = mb.lastNotification || 0;
        add('notifications', mb.watched > 0 && !!last && now - last < cfg.quietHours * 3600 * 1000,
            !mb.watched ? 'No mailbox is watched.' : last ? `Gmail's last notification: ${Math.round((now - last) / 60000)} minutes ago, for ${mb.watched} watched mailboxes.` : 'No notification from Gmail yet.',
            !mb.watched ? 'Settings → Mailboxes → Read the directory again now, then the list below it.' : 'Send a test email to a watched mailbox; if nothing comes, run bash deploy/doctor.sh.');
        const expiring = mb.ending;
        add('watches', !expiring, expiring ? `${expiring} mailbox watches end within a day.` : 'Every watch is renewed in time.', 'Settings → Mailboxes → Read the directory again now.');
        if (service.intel && service.intel.feeds) {
            const lists = await service.intel.feeds.status().catch(() => []);
            const oldest = Math.min(...lists.map(l => l.updated || 0));
            const missed = lists.filter(l => l.missed);
            add('lists', lists.length > 0 && !!oldest && !missed.length,
                missed.length ? `${missed.map(l => l.name).join(', ')} missed ${missed.length === 1 ? 'its' : 'their'} download${missed.some(l => l.error) ? ` (${missed.filter(l => l.error).map(l => l.error).join('; ')})` : ''}; the previous copy is used meanwhile.`
                    : lists.length && oldest ? `The phishing lists were updated ${Math.round((now - oldest) / 3600000)} hours ago at the oldest.` : 'The phishing lists haven\'t been downloaded yet.',
                'Settings → About: each list\'s state, and Re-check. Activity → Errors shows every failed download.');
        }
        // Google Safe Browsing (0.5.23): off is a choice; on, its key must work.
        if (cfg.safeBrowsing) {
            const sb = await safeBrowsingInfo();
            const h = sb.health;
            if (!sb.working) add('safe-browsing', false, 'Google Safe Browsing is on, but no API key can be used: links aren\'t looked up with Google.', 'Settings → Safe Browsing: save a key (or turn it off).');
            else if (h && !h.ok) add('safe-browsing', false, `Google Safe Browsing is on, but Google refused the last lookups (${h.error}).`, 'Settings → Safe Browsing: check the key, or save a new one.');
            else add('safe-browsing', true, 'Google Safe Browsing is on, and its key works.', null);
        }
        // (install.sh always sets it, to the admin group by default: empty means ALERT_EMAIL=off, a choice)
        add('alerts', true, cfg.alertEmail ? `Alerts are emailed to ${cfg.alertEmail}.` : 'Alerts aren\'t emailed (ALERT_EMAIL=off): they show in Health → Activity.');
        const errors = (await eventsSince(now - 24 * 3600 * 1000, 50000)).filter(e => e.kind === 'error').length;
        add('errors', errors === 0, errors ? `${errors} errors in the last day.` : 'No errors in the last day.', 'Health → Activity → Errors and gaps.', '#/activity?days=7&kind=error');
        const brake = await store.getState('brake');
        add('brake', !brake, brake ? 'The domain-wide brake is on: nothing is moved.' : 'The domain-wide brake is off.', 'Today → Resume.');
        return out;
    }
    const ACTIONS_GAP_MS = 5000;   // once()'s default: the same action (a campaign's, a key's…) at most every 5 s (no double clicks)
    const RESCAN_GAP_MS = 30 * 1000, rescanning = new Set();   // (0.6.6) re-scans: see POST /api/rescan
    const lastAction = new Map();
    let exporting = false;   // one retraining export at a time (it reads up to 100 emails from Gmail)
    // Wrong project IDs (and email addresses) typed per admin, on any change that asks for them (the policy, Update,
    // the keys, Phishing training, Look-alikes, Link clicks: projectCheck): five in 10 minutes lock them all.
    const wrongIds = new Map();
    const lockedNoted = new Map();
    const wrong = {
        locked: (who) => (wrongIds.get(who) || []).filter(t => Date.now() - t < POLICY_LOCK_MS).length >= POLICY_TRIES,
        // A wrong project ID or email address (0.5.30): each try noted in What admins did, with what it was for
        // (never what was typed: someone could paste something private by mistake). Not emailed; the fifth
        // within POLICY_LOCK_MS locks changes from that account, and that is an alert (0.5.29): it may not have
        // been them.
        add: async (who, what = 'a setting', mistake = 'Google Cloud project ID') => {
            const tries = [...(wrongIds.get(who) || []).filter(t => Date.now() - t < POLICY_LOCK_MS), Date.now()];
            wrongIds.set(who, tries);
            const mins = Math.round(POLICY_LOCK_MS / 60000);
            await store.addEvent({ kind: 'denied', admin: true, by: who, text: `${who} typed a wrong ${mistake} to change ${what} (try ${tries.length} of ${POLICY_TRIES} within ${mins} minutes): nothing was changed.${tries.length === POLICY_TRIES ? ` Changes from this account are locked for ${mins} minutes.` : ''}` }).catch(() => {});
            if (tries.length === POLICY_TRIES && service && service.alert) await service.alert('lockout', `${who} typed a wrong Google Cloud project ID or email address ${POLICY_TRIES} times within ${mins} minutes: changes from that account are locked for ${mins} minutes. If it wasn't them, someone may be using their signed-in session: ask them, and sign them out of Google (Admin console → Users → Sign out). Health → Activity → What admins did lists each try.`).catch(() => {});
        },
        // A try while locked (0.5.30): noted once per lock, so repeated tries can't flood Activity.
        lockedTry: async (who, what = 'a setting') => {
            const lock = (wrongIds.get(who) || [])[0];
            if (lockedNoted.get(who) === lock) return;
            lockedNoted.set(who, lock);
            await store.addEvent({ kind: 'denied', admin: true, by: who, text: `${who} tried to change ${what} while locked after ${POLICY_TRIES} wrong entries: refused (more tries during this lock aren't noted).` }).catch(() => {});
        },
        clear: (who) => wrongIds.delete(who)
    };
    // Who opened the dashboard (0.5.29): once a day per admin or moderator (the organization's day), in What admins
    // did; the last 26 hours of events are looked at first, so another instance's note isn't repeated.
    const opened = new Map();
    async function noteOpened(email, role = 'admin') {
        const day = A.dayIn(Date.now(), cfg.timeZone);
        if (!email || opened.get(email) === day) return;
        opened.set(email, day);
        const today = await eventsSince(Date.now() - 26 * 3600 * 1000, 2000);
        if (today.some(e => e.kind === 'signin' && e.by === email && A.dayIn(e.at, cfg.timeZone) === day)) return;
        await store.addEvent({ kind: 'signin', by: email, admin: true, text: `${email} opened the dashboard${role === 'moderator' ? ' (as a moderator)' : ''}.` });
    }
    // true the first time key is asked, then false until gap has passed (per instance: a double click, two admins).
    const once = (key, gap = ACTIONS_GAP_MS) => { const t = lastAction.get(key) || 0; if (Date.now() - t < gap) return false; lastAction.set(key, Date.now()); return true; };
    // Google Safe Browsing (0.5.23): the key's state (src/intel/sbkey.js), never the key itself.
    const sbKey = () => (service.intel && service.intel.sbKey) || null;
    // The optional services' keys (0.5.37): service.intel.keys.spamhaus, .abusech (src/intel/apikey.js).
    const apiKey = (id) => (service.intel && service.intel.keys && service.intel.keys[id]) || null;
    const backupKeys = () => ({ safeBrowsing: sbKey(), spamhaus: apiKey('spamhaus'), abusech: apiKey('abusech') });
    const safeBrowsingOn = async () => !!cfg.safeBrowsing && !!sbKey() && !!(await sbKey().get().catch(() => null));
    const safeBrowsingInfo = async () => {
        const k = sbKey();
        if (!k) return { available: false, on: !!cfg.safeBrowsing, saved: null, envKey: !!cfg.safeBrowsingKey, health: null };
        return Object.assign(await k.status(), { on: !!cfg.safeBrowsing, working: await safeBrowsingOn() });
    };
    // The project ID typed in for a change (as for the policy): null when right, else the answer to give.
    const projectCheck = async (admin, body, what) => {
        const expected = expectedProject(cfg);
        if (!expected) return { error: 'This dashboard doesn\'t know its Google Cloud project (GOOGLE_CLOUD_PROJECT). Upgrade from Cloud Shell once (bash deploy/update.sh (or, from an unzipped new version, bash deploy/upgrade.sh)), then try again.', status: 409 };
        if (wrong.locked(admin.email)) { await wrong.lockedTry(admin.email, what); return { error: 'Too many wrong project IDs. Try again in 10 minutes.', status: 429 }; }
        if (String(body.projectId || '').trim().toLowerCase() !== expected.toLowerCase()) { await wrong.add(admin.email, what); return { error: 'That isn\'t the Google Cloud project ID of this service. Nothing was changed.', status: 403 }; }
        wrong.clear(admin.email);
        return null;
    };
    // Settings → Spamhaus, Settings → abuse.ch: each one's key state (never the key) and on or off; Spamhaus's
    // lookups today against its daily limit, abuse.ch's list downloads.
    const optionalInfo = async () => {
        const out = {};
        for (const id of ['spamhaus', 'abusech']) {
            const k = apiKey(id);
            out[id] = Object.assign(k ? await k.status() : { available: false, saved: null, health: null }, { on: !!cfg[id] });
        }
        if (service.intel && service.intel.spamhaus) out.spamhaus.quota = await service.intel.spamhaus.quota().catch(() => null);
        out.spamhaus.dailyMax = cfg.spamhausDailyMax;
        // abuse.ch's lists: how their downloads went
        out.abusech.lists = service.intel && service.intel.feeds ? (await service.intel.feeds.status().catch(() => [])).filter(l => l.optional) : [];
        return out;
    };
    // The phishing lists that missed their download, for the overview: [{ id, name, missed, error, failedSince, updated }].
    const missedLists = async () => {
        if (!service.intel || !service.intel.feeds) return [];
        const lists = await service.intel.feeds.status().catch(() => []);
        return lists.filter(l => l.missed).map(l => ({ id: l.id, name: l.name, missed: l.missed, error: l.error, failedSince: l.failedSince, updated: l.updated }));
    };

    // The dashboard's routes: (query, body, admin) → an answer; { error, status } for a refusal.
    const api = {
        // Today: the period's numbers, the chart, top reasons and campaigns, the last week's alerts, and the banners.
        'GET /api/overview': async (q) => {
            const { records, stats } = await load(q);
            const n = nDays(q), now = Date.now();
            return { summary: A.summary(records, stats, now, n), trend: A.trend(records, stats, now, n), topReasons: A.topReasons(records, now, n).slice(0, 8),
                     campaigns: A.campaigns(records, now, n).slice(0, 5), alerts: await eventsSince(now - 7 * A.DAY, 10),
                     brake: await brakeInfo(records), spamBrake: await brakeInfo(records, 'spamBrake', 'spam-brake'), heldCampaigns: await heldCampaigns(records), mode: cfg.mode, aiThreshold: cfg.aiThreshold,
                     // The phishing lists that missed their download (0.5.22): the overview's banner.
                     missedLists: await missedLists(),
                     // Phishing found after delivery, not yet marked seen (0.5.35): the overview's banner.
                     rechecked: A.recheckAlert(records, now, await store.getState('recheckSeenAt'), (await store.getState('recheckSeenCampaigns')) || {}),
                     // New look-alikes of your domain an admin hasn't marked (0.5.36): the overview's banner.
                     lookalikes: Object.values(((await store.getState('lookalikeWatch')) || {}).found || {}).filter(e => e.status === 'new' && !e.gone).map(e => e.domain),
                     // (0.6.30) Allow-list domains the 30-day check flagged: the overview's banner.
                     allowReview: Object.entries(((await store.getState('allowWatch')) || {}).domains || {}).filter(([, v]) => v && v.review).map(([d, v]) => ({ domain: d, suspended: !!v.review.suspended })),
                     // (0.6.70) Re-checking delivered mail: what waits and how far it got (pipeline.js recheckStatus), read at most every 15 s.
                     recheck: service.recheckStatus ? await shortLived('recheck-status', 15000, () => service.recheckStatus()) : null };
        },
        // Settings → Phishing training (0.5.44): the rules (never a secret value: only whether one is set) and link
        // domains, what matched lately, the last 7 days' count; changes with the project ID.
        'GET /api/phish-training': async () => {
            const st = Object.assign({ rules: [], domains: [] }, await store.getState('phishTraining'));
            const now = Date.now();
            const days = await statsFor(A.dayOf(now - 6 * A.DAY), A.dayOf(now));
            return { rules: st.rules.map(r => ({ id: r.id, name: r.name, header: r.headerShown || r.header, hasValue: !!r.valueHash, ips: r.ips || [] })), domains: st.domains, by: st.by || null, at: st.at || null,
                     presets: require('./simulations').PRESETS, seen: (await store.getState('phishTrainingSeen')) || {}, missed: (await store.getState('phishTrainingMissed')) || {},
                     week: days.reduce((n, d) => n + (Number(d.training) || 0), 0), today: Number(((days.find(d => d.day === A.dayOf(now)) || {}).training) || 0),
                     projectKnown: !!expectedProject(cfg), demoProjectId: cfg.demo ? DEMO_PROJECT : null };
        },
        'POST /api/phish-training/rule': async (q, body, admin) => {
            const bad = await projectCheck(admin, body, 'a phishing-training rule');
            if (bad) return bad;
            return service.addTrainingRule({ name: body.name, header: body.header, value: body.value, ips: body.ips }, admin.email);
        },
        'POST /api/phish-training/rule/edit': async (q, body, admin) => {
            const bad = await projectCheck(admin, body, 'a phishing-training rule (edit it)');
            if (bad) return bad;
            return service.editTrainingRule(String(body.id || ''), { name: body.name, header: body.header, value: body.value, clearValue: body.clearValue === true, ips: body.ips }, admin.email);
        },
        'POST /api/phish-training/rule/remove': async (q, body, admin) => {
            const bad = await projectCheck(admin, body, 'a phishing-training rule (remove it)');
            if (bad) return bad;
            return service.removeTrainingRule(String(body.id || ''), admin.email);
        },
        'POST /api/phish-training/domains': async (q, body, admin) => {
            const bad = await projectCheck(admin, body, 'the phishing-training link domains');
            if (bad) return bad;
            return service.setTrainingDomains(body.domains, admin.email);
        },
        // Help (0.5.46): one of the docs above, as Markdown (the page renders it as text, never HTML).
        'GET /api/help': async (q) => helpDoc(String(q.get('doc') || 'howitworks')) || { error: 'There is no such help page.', status: 404 },
        // Threats → Look-alikes (0.5.36): the watch's state and what it found; an admin's mark on one (with the
        // project ID: "ours" or "harmless" takes a sign away).
        'GET /api/lookalikes': async () => {
            const w = (await store.getState('lookalikeWatch')) || {};
            const found = Object.values(w.found || {}).sort((a, b) => (b.status === 'new') - (a.status === 'new') || (b.first || 0) - (a.first || 0));
            return { on: !!cfg.lookalikeWatch, orgDomains: cfg.orgDomains, candidates: w.candidates || null, cursor: w.cursor || 0, passes: w.passes || 0, baselineDone: !!w.baselineDone,
                     passStartedAt: w.passStartedAt || null, lastPassAt: w.lastPassAt || null, found, projectKnown: !!expectedProject(cfg), demoProjectId: cfg.demo ? DEMO_PROJECT : null };
        },
        'POST /api/lookalikes/mark': async (q, body, admin) => {
            const bad = await projectCheck(admin, body, `the look-alike ${String(body.domain || '').slice(0, 80)}`);
            if (bad) return bad;
            return service.markLookalike(String(body.domain || ''), String(body.status || ''), admin.email);
        },
        // Threats → Re-checked (0.5.35): the emails found after delivery, by campaign, with every copy; whether
        // re-checking is on, and Link clicks.
        'GET /api/rechecked': async (q) => {
            const { records } = await load(q);
            const cl = await service.clickLogs();
            const seen = { at: await store.getState('recheckSeenAt'), campaigns: (await store.getState('recheckSeenCampaigns')) || {} };
            return { groups: A.rechecked(records, Date.now(), nDays(q), seen), recheck: !!cfg.recheck, recheckDays: cfg.recheckDays, mode: cfg.mode,
                     clickLogs: { on: !!cl.on, admin: cfg.directoryAdmin || '' }, seenAt: await store.getState('recheckSeenAt'), queued: ((await store.getState('recheckQueue')) || []).length,
                     // (0.5.51) Re-checks after an update that changed the checks, and the last such update.
                     afterUpdateHours: cfg.recheck ? cfg.recheckAfterUpdateHours : 0, afterUpdateMax: cfg.recheckAfterUpdateMax,
                     updateSweep: (({ version, queued, max, startedAt, doneAt } = {}) => version ? { version, queued, max, startedAt, doneAt: doneAt || null } : null)((await store.getState('updateRecheck')) || {}) };
        },
        // "Mark as seen": the listings leave Re-checked and the banners on Today and Messages go, until something new
        // is found. All of them, or (0.6.17) one listing: body.campaign. Entries over 30 days old are dropped.
        'POST /api/rechecked/seen': async (q, body, admin) => {
            const now = Date.now(), campaign = typeof body.campaign === 'string' ? body.campaign.slice(0, 200) : '';
            if (!campaign) {
                await store.setState('recheckSeenAt', now);
                await store.setState('recheckSeenCampaigns', {});
                await service.adminNotice('rechecked', `${admin.email} marked the re-checked mail as seen.`);
                return { seenAt: now };
            }
            const kept = Object.fromEntries(Object.entries((await store.getState('recheckSeenCampaigns')) || {}).filter(([, at]) => now - at < 30 * 86400000).slice(-500));
            kept[campaign] = now;
            await store.setState('recheckSeenCampaigns', kept);
            await service.adminNotice('rechecked', `${admin.email} marked one re-checked email as seen.`);
            return { campaign, seenAt: now };
        },
        // Settings → Link clicks (0.5.35; off by default): Gmail's logs for the re-checked mail.
        'GET /api/clicks': async () => ({ clickLogs: await service.clickLogs(), health: await store.getState('clickLogsHealth'), test: await store.getState('clickLogsTest'),
            projectKnown: !!expectedProject(cfg), demoProjectId: cfg.demo ? DEMO_PROJECT : null, directoryAdmin: cfg.directoryAdmin || '' }),
        'POST /api/clicks': async (q, body, admin) => {
            const on = body.on === true;
            const bad = await projectCheck(admin, body, `Link clicks (turn ${on ? 'on' : 'off'})`);
            if (bad) return bad;
            return service.setClickLogs(on, admin.email);
        },
        'POST /api/clicks/test': async (q, body, admin) => {
            if (!once(`clicks-test|${admin.email}`, 10 * 1000)) return { error: 'Tested less than 10 seconds ago.', status: 429 };
            return service.testClickLogs(admin.email);
        },
        // (0.6.60) Settings → User reports (off by default): Gmail's "Report phishing" reports, read from the Alert Center.
        'GET /api/user-reports': async () => ({ userReports: await service.userReports(), health: await store.getState('userReportsHealth'), test: await store.getState('userReportsTest'),
            projectKnown: !!expectedProject(cfg), demoProjectId: cfg.demo ? DEMO_PROJECT : null, directoryAdmin: cfg.directoryAdmin || '' }),
        'POST /api/user-reports': async (q, body, admin) => {
            const on = body.on === true;
            const bad = await projectCheck(admin, body, `User reports (turn ${on ? 'on' : 'off'})`);
            if (bad) return bad;
            return service.setUserReports(on, admin.email);
        },
        'POST /api/user-reports/test': async (q, body, admin) => {
            if (!once(`user-reports-test|${admin.email}`, 10 * 1000)) return { error: 'Tested less than 10 seconds ago.', status: 429 };
            return service.testUserReports(admin.email);
        },
        // Threats → Campaigns, Mail → Users and Mail → Messages (the newest 500 shown; the filters as the CSV's).
        'GET /api/campaigns': async (q) => { const { records } = await load(q); return { campaigns: A.campaigns(records, Date.now(), nDays(q)) }; },
        'GET /api/users': async (q) => { const { records } = await load(q); return { users: A.users(records, Date.now(), nDays(q)) }; },
        'GET /api/messages': async (q) => {
            const { records } = await load(q);
            const list = A.filterRecords(records, { user: q.get('user') || '', campaign: q.get('campaign') || '', action: q.get('action') || '', state: q.get('state') || '', q: q.get('q') || '', since: since(q) });
            return { total: list.length, messages: list.slice(0, 500).map(brief), rechecked: A.recheckAlert(records, Date.now(), await store.getState('recheckSeenAt'), (await store.getState('recheckSeenCampaigns')) || {}) };
        },
        // An email's record, with the mode now (whether confirming it as phishing also moves it).
        'GET /api/message': async (q) => { const r = await store.getRecord(String(q.get('key') || '')); return r ? { message: Object.assign(withPlainWhy(r, cfg), r.sender && r.sender.address ? { spamKey: service.spamListKey(r.sender.address) } : {}), mode: cfg.mode } : { error: 'not found', status: 404 }; },
        // Health → Model health: the AI's scores and how its moves were undone, the model in use, the threshold.
        'GET /api/health': async (q) => {
            const { records } = await load(q);
            const tx = (await store.getState('trainingExport')) || {};
            const E = spruce.load();
            return Object.assign(A.modelHealth(records, Date.now(), nDays(q), { orgDomains: cfg.orgDomains, aiSuspicious: cfg.aiSuspicious, aiThreshold: cfg.aiThreshold }), { current: `${E.modelInfo.name} ${E.modelInfo.version}`, threshold: cfg.aiThreshold, trainingExport: !!tx.enabled });
        },
        // (0.5.53) Settings → Mailboxes: how many mailboxes the pilot and the whole domain would watch (the directory,
        // read at most every 10 minutes), and the mailboxes watched, a page at a time: by address after `after`, or
        // starting with `q`; 100 a page (10,000 mailboxes aren't sent at once).
        'GET /api/scope-preview': async () => {
            if (cfg.demo) return { domain: 4200, pilot: 42, domainError: '', pilotError: '', watched: (await mailboxes()).watched, scope: cfg.watchScope, demo: true };
            return service.scopePreview();
        },
        'GET /api/mailboxes': async (q) => {
            const limit = Math.min(200, Math.max(10, Number(q.get('limit')) || 100));
            const page = await store.listWatchedPage({ after: String(q.get('after') || '').toLowerCase().slice(0, 320), prefix: String(q.get('q') || '').trim().toLowerCase().slice(0, 320), limit });
            const mb = await mailboxes();
            return { mailboxes: page.items.map(u => ({ email: u.email, lastNotification: u.lastNotification || null, watchExpiration: u.watchExpiration || null })), next: page.next, watched: mb.watched,
                     ending: mb.ending == null ? null : mb.ending, scope: cfg.watchScope, left: ((await store.getState('watchLeft')) || {}).left || 0 };
        },
        // Health → DMARC & reputation (0.6.1, admins only): the DMARC and SPF records; ?fresh=1 reads them again now
        // (at most every 30 s).
        'GET /api/dmarc': async (q) => ({ domains: await dmarcCheck(cfg.orgDomains, { fresh: !!(q && q.get && q.get('fresh')) && once('dmarc-fresh', 30 * 1000) }) }),
        // Health → DMARC & reputation (0.6.1, admins only): blocklists and the downloaded lists; ?fresh=1 reads again (at most every 30 s).
        'GET /api/reputation': async (q) => ({ domains: await reputation(cfg.orgDomains, { fresh: !!(q && q.get && q.get('fresh')) && once('reputation-fresh', 30 * 1000) }) }),
        // (0.6.1) Who is signed in, as what (added to every answer below), and what every page's frame needs (the
        // menu, the footer, About & credits): the only settings a moderator reads.
        'GET /api/session': async () => {
            const E = spruce.load();
            return { mode: cfg.mode, orgDomains: cfg.orgDomains, retentionDays: cfg.retentionDays, model: E.modelInfo, version: VERSION, donateButton: cfg.donateButton, timeZone: cfg.timeZone };
        },
        'GET /api/settings': async (q) => {
            const E = spruce.load();
            const renew = { available: canRenew() || cfg.demo, last: await lastRenew() };
            const digest = Object.assign({ enabled: false }, await store.getState('digest'));
            const trainingExport = Object.assign({ enabled: false }, await store.getState('trainingExport'));
            const policy = service.policyInfo ? service.policyInfo() : null;
            const mb = await mailboxes();
            // (the list, only with ?mailboxes=1, at most 500: Settings → Mailboxes reads GET /api/mailboxes since 0.5.53)
            const listed = q && q.get && q.get('mailboxes') ? await store.listWatched(500) : null;
            return { mode: cfg.mode, aiThreshold: cfg.aiThreshold, aiSuspicious: cfg.aiSuspicious, moveOnRules: cfg.moveOnRules, aiMovesInside: cfg.aiMovesInside, aiScansInside: cfg.aiScansInside, strictSpam: cfg.strictSpam || [], suspiciousLabel: cfg.suspiciousLabel, suspiciousLabelName: cfg.suspiciousLabelName, recheck: cfg.recheck, recheckDays: cfg.recheckDays, recheckAfterUpdateHours: cfg.recheck ? cfg.recheckAfterUpdateHours : 0, brakePerHour: cfg.brakePerHour,
                     brakeLimit: await service.brakeLimit(), spamBrakePerHour: cfg.spamBrakePerHour || 0, campaignHoldAfter: cfg.campaignHoldAfter, alertEmail: cfg.alertEmail || '',
                     orgDomains: cfg.orgDomains, pilotGroups: cfg.pilotGroups, pilotOu: cfg.pilotOu, pilotUsers: cfg.pilotUsers.length, watchScope: cfg.watchScope, allowDomains: cfg.allowDomains, allowLinkDomains: cfg.allowLinkDomains || [], allowAddresses: cfg.allowAddresses.length,
                     retentionDays: cfg.retentionDays, storeSubjects: cfg.storeSubjects, storeAiQuotes: cfg.storeAiQuotes, movedLabel: cfg.movedLabel,
                     model: E.modelInfo, engine: E.vendor, watched: mb.watched, demo: cfg.demo,
                     // Each watched mailbox, and when Gmail last said it changed: none since the watch
                     // started means no notifications arrive for it.
                     mailboxes: listed && listed.map(u => ({ email: u.email, lastNotification: u.lastNotification || null, watchExpiration: u.watchExpiration || null })),
                     renew, digest, trainingExport, timeZone: cfg.timeZone, version: VERSION, donateButton: cfg.donateButton,
                     policy, projectKnown: !!expectedProject(cfg), demoProjectId: cfg.demo ? DEMO_PROJECT : null,
                     checks: { cloudflare: cfg.cloudflareThreats, safeBrowsing: await safeBrowsingOn(), phishingLists: cfg.phishingLists, siteAge: cfg.siteAge },
                     // Settings → Safe Browsing (0.5.23): on or off, whether a key is saved (who, when), how the lookups go. Never the key.
                     safeBrowsing: await safeBrowsingInfo(),
                     // Settings → Spamhaus, Settings → abuse.ch (0.5.37): on or off, a key saved (who, when; never the key), how it goes.
                     optional: await optionalInfo(),
                     lists: service.intel && service.intel.feeds ? await service.intel.feeds.status() : [] };
        },
        // Settings → About's Re-check (0.5.22): the lists that missed their download, or aren't up to date, are
        // downloaded again now. At most once a minute (two admins, or a double click).
        'POST /api/lists/recheck': async (q, body, admin) => {
            if (!once('lists-recheck', 60 * 1000)) return { error: 'The lists were re-checked less than a minute ago.', status: 429 };
            return service.recheckLists(admin.email);
        },
        // Settings → Spamhaus, Settings → abuse.ch (0.5.37): as the Safe Browsing key below: tested first, kept in
        // Secret Manager only (never answered back or logged), optionally turning the service on; or removed (every
        // version destroyed, the service turned off). The project ID typed in.
        'POST /api/keys/save': async (q, body, admin) => {
            const id = String(body.id || '');
            if (!['spamhaus', 'abusech'].includes(id) || !apiKey(id)) return { error: 'That service isn\'t available here.', status: 409 };
            const name = apiKey(id).label;
            const bad = await projectCheck(admin, body, `the ${name} key`);
            if (bad) return bad;
            let saved;
            try { saved = await apiKey(id).save(String(body.apiKey || ''), admin.email); }
            catch (e) { if (e.status) return { error: `${e.message} Nothing was saved.`, status: e.status }; throw e; }
            await service.adminNotice('settings', `${admin.email} saved a ${name} key${saved.tested ? ` (${name} accepted it)` : ''}.`);
            let turnedOn = false;
            if (body.turnOn === true && !cfg[id]) { await service.setPolicy(id, true, admin.email); turnedOn = true; }
            return { saved: true, tested: saved.tested, turnedOn };
        },
        'POST /api/keys/remove': async (q, body, admin) => {
            const id = String(body.id || '');
            if (!['spamhaus', 'abusech'].includes(id) || !apiKey(id)) return { error: 'That service isn\'t available here.', status: 409 };
            const name = apiKey(id).label;
            const bad = await projectCheck(admin, body, `the ${name} key (remove it)`);
            if (bad) return bad;
            if (cfg[id]) await service.setPolicy(id, false, admin.email);
            try { await apiKey(id).remove(admin.email); }
            catch (e) { if (e.status) return { error: e.message, status: e.status }; throw e; }
            await service.adminNotice('settings', `${admin.email} removed the ${name} key (every copy destroyed); ${name} is off.`);
            return { removed: true };
        },
        // Settings → Safe Browsing (0.5.23): an admin saves an API key (tested with Google first, kept in Secret
        // Manager only, never answered back or logged), optionally turning Safe Browsing on; or removes it (every
        // version destroyed, Safe Browsing turned off). The project ID typed in, as for the policy.
        'POST /api/safe-browsing/key': async (q, body, admin) => {
            if (!sbKey()) return { error: 'Safe Browsing isn\'t available here.', status: 409 };
            const bad = await projectCheck(admin, body, 'the Safe Browsing key');
            if (bad) return bad;
            if (!once(`sb-key:${admin.email}`)) return { error: 'Saved a moment ago.', status: 429 };
            const key = String(body.apiKey || '').trim();
            if (!key) return { error: 'Paste the API key. Nothing was changed.', status: 400 };
            let saved;
            try { saved = await sbKey().save(key, admin.email); }
            catch (e) { if (e.status) return { error: `${e.message} Nothing was changed.`, status: e.status }; throw new Error('saving the Safe Browsing key failed: ' + String(e.message || '').slice(0, 200)); }
            await service.adminNotice('settings', `${admin.email} saved a new Google Safe Browsing API key on the dashboard (confirmed with the project ID${saved.tested ? '; Google accepted it' : ''}). It is kept in Secret Manager; older keys there were destroyed.`);
            let turnedOn = false;
            if (body.turnOn === true && !cfg.safeBrowsing) { await service.setPolicy('safeBrowsing', true, admin.email); turnedOn = true; }
            return { saved: true, tested: saved.tested, turnedOn, safeBrowsing: await safeBrowsingInfo() };
        },
        'POST /api/safe-browsing/remove': async (q, body, admin) => {
            if (!sbKey()) return { error: 'Safe Browsing isn\'t available here.', status: 409 };
            const bad = await projectCheck(admin, body, 'the Safe Browsing key (remove it)');
            if (bad) return bad;
            if (!once(`sb-key:${admin.email}`)) return { error: 'Changed a moment ago.', status: 429 };
            if (cfg.safeBrowsing) await service.setPolicy('safeBrowsing', false, admin.email);
            try { await sbKey().remove(admin.email); }
            catch (e) { if (e.status) return { error: `${e.message} Nothing was changed.`, status: e.status }; throw new Error('removing the Safe Browsing key failed: ' + String(e.message || '').slice(0, 200)); }
            await service.adminNotice('settings', `${admin.email} removed the Google Safe Browsing API key on the dashboard (confirmed with the project ID): every copy in Secret Manager was destroyed, and Safe Browsing is off.`);
            return { removed: true, safeBrowsing: await safeBrowsingInfo() };
        },
        // Move one email back to the Inbox (admins only: a moderator marks it a false alarm instead).
        'POST /api/release': async (q, body, admin) => service.release(String(body.key || ''), admin.email),
        // move: phishing still in the Inbox is moved to Spam too (enforce mode).
        // (0.6.35) addSender: "Also send future mail from this sender straight to Spam" (admins only: it skips the checks).
        'POST /api/mark': async (q, body, admin) => {
            const out = await service.mark(String(body.key || ''), body.falseAlarm === true, admin.email, { move: body.move === true, spam: body.spam === true, addSender: body.addSender === true && admin.role !== 'moderator' });
            // (0.6.40) Spam: the same sender's other emails waiting for review are answered Spam too.
            if (out && out.record && body.spam === true && body.falseAlarm !== true) { out.sameSender = await service.answerSameSender([String(body.key)], admin.email, await cache.list(Date.now() - 35 * A.DAY)); cache.stale(); }
            return out;
        },
        // (0.6.26) Spam several people took back out of Spam: the list, and an admin's "keep moving it" (or undoing it).
        'GET /api/spam-rescued': async () => ({ list: await service.spamRescuedList() }),
        // (0.6.52) Review → Promotional: one answer for a company's waiting emails, Spam (with addSender: their senders on Spam
        // senders, by the usual rule) or Keep (Promotional senders kept). Admins only. undo: a Keep answer taken back.
        'POST /api/promotional': async (q, body, admin) => {
            const company = String(body.company || '').toLowerCase();
            if (body.undo === 'keep') return service.removePromoKept(company, admin.email, { undoKeys: Array.isArray(body.keys) ? body.keys.map(String).slice(0, 2000) : [] }).then(r => { cache.stale(); return r; });
            const out = await service.answerPromotional(company, String(body.answer || ''), admin.email, { addSender: body.addSender === true, records: await cache.list(Date.now() - 35 * A.DAY) });
            if (!out.error) cache.stale();
            return out;
        },
        'GET /api/promotional-kept': async () => ({ list: await service.promoKeptList() }),
        // (0.6.56) Remembered Not phishing answers: the list (moderators see it), and an admin removes one.
        'GET /api/remembered': async () => ({ list: await service.rememberedList() }),
        'POST /api/remembered': async (q, body, admin) => service.forgetAnswer(String(body.id || ''), admin.email).then(r => { cache.stale(); return r; }),
        'POST /api/promotional-kept': async (q, body, admin) => service.removePromoKept(String(body.company || ''), admin.email).then(r => { cache.stale(); return r; }),
        'POST /api/spam-rescued': async (q, body, admin) => service.setSpamKeep(String(body.sender || ''), body.keep === true, admin.email),
        // (0.6.29) Brand senders the reviewers confirmed (a false alarm on a brand's name from another verified domain).
        // (0.6.30) The allow lists' 30-day check: the domains waiting for review; "Still trusted" (with the project ID for a
        // suspended one, as for any allowlist change), optionally releasing the emails held back while it was suspended.
        'GET /api/allow-watch': async () => service.allowReviewList(),
        'POST /api/allow-watch': async (q, body, admin) => {
            const domain = String(body.domain || '').toLowerCase();
            const row = (await service.allowReviewList()).review.find(r => r.domain === domain);
            if (!row) return { error: 'That domain isn\'t waiting for review.', status: 404 };
            if (row.suspended) { const bad = await projectCheck(admin, body, `trusting ${domain} again after its 30-day check`); if (bad) return bad; }
            return service.resolveAllowReview(domain, admin.email, { release: body.release === true });
        },
        // (0.6.35) Spam senders: their verified mail goes straight to Spam. Admins add (a domain, or an address at a personal
        // provider) and remove them; Review's Spam answer can add one too.
        'GET /api/spam-senders': async () => ({ list: await service.spamSenderList() }),
        // (0.6.59) Spam learning: when it last ran, and an admin starts it (the days, agreed to) or stops it.
        'GET /api/spam-learning': async () => ({ info: await service.spamLearningInfo() }),
        'POST /api/spam-learning': async (q, body, admin) => {
            if (body.stop) return service.stopSpamLearning(admin.email);
            if (body.agree !== true) return { error: 'Tick the box to agree: promotional mail will be moved to Spam. Nothing was changed.', status: 400 };
            // (0.6.66) It can move all promotional mail for weeks: confirmed with the project ID, as every such setting is.
            const bad = await projectCheck(admin, body, 'Spam learning (start)');
            if (bad) return bad;
            return service.startSpamLearning(body.days, admin.email);
        },
        'POST /api/spam-senders': async (q, body, admin) => (body.remove ? service.removeSpamSender(String(body.key || ''), admin.email) : service.addSpamSender(String(body.sender || ''), admin.email, { from: 'page' })),
        // (0.6.49) Company domains: proven by public records (read-only), and confirmed by an admin from a registry's own page.
        'GET /api/company-domains': async () => service.companyDomainList(),
        'POST /api/company-domains': async (q, body, admin) => (body.remove ? service.removeConfirmedDomain(String(body.domain || ''), admin.email)
            : service.addConfirmedDomain(String(body.domain || ''), String(body.name || ''), String(body.note || ''), admin.email)),
        'GET /api/brand-senders': async () => ({ list: await service.brandSenderList() }),
        'POST /api/brand-senders': async (q, body, admin) => service.removeBrandSender(String(body.key || ''), admin.email),
        // (0.5.60) Ignore, treat as suspicious: reviewed, left as it is, not used for retraining.
        'POST /api/unclear': async (q, body, admin) => service.setAside(String(body.key || ''), admin.email),
        // (0.6.39) Undo an answer: one email (key) or several (keys, at most 500).
        'POST /api/undo': async (q, body, admin) => (Array.isArray(body.keys) ? service.undoMany([...new Set(body.keys.map(String))].slice(0, 500), admin.email) : service.undoAnswer(String(body.key || ''), admin.email)),
        // (0.6.39) Spam or Not sure for every copy of a campaign (as Confirm and False alarm do).
        'POST /api/campaign/answer': async (q, body, admin) => {
            const out = await service.answerCampaign(String(body.key || ''), String(body.action || ''), admin.email, { addSender: body.addSender === true && admin.role !== 'moderator' });
            if (body.action === 'spam' && out && out.done) { out.sameSender = await service.answerSameSender(out.keys, admin.email, await cache.list(Date.now() - 35 * A.DAY)); cache.stale(); }
            return out;
        },
        // Re-scan one email (Review, Messages): judged again now, recorded beside the on-arrival result, never
        // moved. One email again only 30 s after its last re-scan (kept on its record, so every instance knows),
        // and 2 at a time per instance (pipeline.js rescan).
        'POST /api/rescan': async (q, body, admin) => {
            const key = String(body.key || '');
            if (!key) return { error: 'Choose an email.', status: 400 };
            // (0.6.6) One re-scan of an email at a time here, and not again within 30 s of the last one asked
            // (pipeline.js also refuses within 30 s of the last one done, on every instance, and runs 2 at once).
            if (rescanning.has(key)) return { error: 'This email is being re-scanned now: wait for it to finish.', status: 409 };
            if (!once(`rescan:${key}`, RESCAN_GAP_MS)) return { error: 'This email was re-scanned a moment ago: try again in 30 seconds.', status: 429 };
            rescanning.add(key);
            try { return await service.rescan(key, admin.email); }
            catch (e) { if (e.status) return { error: e.message, status: e.status }; throw e; }
            finally { rescanning.delete(key); }
        },
        // "Show the email" (0.6.6; "Show more" on the AI opinion before): the email itself, then what the model reads
        // of it, sentence by sentence (read from Gmail now; nothing stored; Activity notes it; pipeline.js aiContext).
        // At most every 5 s per email and admin.
        'POST /api/message/context': async (q, body, admin) => {
            const key = String(body.key || '');
            if (!key) return { error: 'Choose an email.', status: 400 };
            if (!once(`context:${key}|${admin.email}`)) return { error: 'Opened a moment ago.', status: 429 };
            try { return await service.aiContext(key, admin.email); }
            catch (e) { if (e.status) return { error: e.message, status: e.status }; throw e; }
        },
        // Resume moving; with moveHeld, the emails the brake held are moved now too.
        'POST /api/resume': async (q, body, admin) => service.resume(admin.email, { moveHeld: body.moveHeld === true, spam: body.spam === true }),
        // A campaign: what the brakes and admins decided, and how many copies are where.
        'GET /api/campaign': async (q) => {
            const key = String(q.get('key') || '');
            // (0.6.7) From the dashboard's copy of the records (every page of Messages filtered to a campaign asks this
            // at each refresh; it read every copy from Firestore, 10,000 reads for a 10,000-copy campaign).
            const recs = (await cache.list(Date.now() - 90 * A.DAY)).filter(r => r.campaign === key);
            if (!recs.length) return { error: 'not found', status: 404 };
            const st = (await store.getCampaign(key)) || {};
            const count = (f) => recs.filter(f).length;
            return { campaign: { key, label: recs[0].campaignLabel, decision: st.decision || null, decidedBy: st.decidedBy || null, decidedAt: st.decidedAt || null, heldAt: st.heldAt || null,
                copies: recs.length, moved: count(r => r.state === 'moved'), held: count(r => r.held === 'campaign' && r.state === 'inbox'), recorded: count(r => r.state === 'inbox'),
                released: count(r => r.state === 'released'), strong: count(r => r.evidence === 'strong'), holdAfter: cfg.campaignHoldAfter } };
        },
        'POST /api/campaign/confirm': async (q, body, admin) => {
            const key = String(body.key || '');
            if (!once(`confirm|${key}`)) return { error: 'already under way', status: 429 };
            return service.confirmCampaign(key, admin.email, { search: body.search === true });
        },
        'POST /api/campaign/release': async (q, body, admin) => {
            const key = String(body.key || '');
            if (!once(`release|${key}`)) return { error: 'already under way', status: 429 };
            return service.releaseCampaign(key, admin.email);
        },
        'POST /api/campaign/find': async (q, body, admin) => {
            const key = String(body.key || '');
            if (!once(`find|${key}`)) return { error: 'already under way', status: 429 };
            const found = await service.findCopies(key, admin.email);
            await store.addEvent({ kind: 'campaign', campaign: key, text: `${admin.email} searched ${found.searched} mailboxes for copies of a campaign: ${found.found} found${found.moved ? `, ${found.moved} moved to Spam` : ''}.` });
            return { found };
        },
        // The records shown on Messages (same filters), as a CSV file.
        'GET /api/export.csv': async (q, body, admin) => {
            const { records } = await load(q);
            const list = A.filterRecords(records, { user: q.get('user') || '', campaign: q.get('campaign') || '', action: q.get('action') || '', state: q.get('state') || '', q: q.get('q') || '', since: since(q) });
            // (recorded: it holds every listed email's sender, subject and mailbox, 0.5.29)
            if (admin && service.adminNotice) await service.adminNotice('export', `${admin.email} downloaded ${list.length} email record${list.length === 1 ? '' : 's'} as CSV (Mail → Messages, last ${nDays(q)} days${['user', 'campaign', 'action', 'state', 'q'].some(k => q.get(k)) ? ', filtered' : ''}).`);
            return { csv: A.toCsv(list), filename: `spruce-messages-${A.dayOf(Date.now())}.csv` };
        },
        // "Check an email": what the service would decide for a pasted email, and why. Nothing of it is
        // stored; Activity notes who checked one, and the sender's domain.
        'POST /api/check': async (q, body, admin) => {
            const raw = typeof body.raw === 'string' ? body.raw : '';
            if (!raw.trim()) return { error: 'Paste the email\'s original (in Gmail: Show original), or choose an .eml file.', status: 400 };
            if (Buffer.byteLength(raw) > CHECK_MAX_BYTES) return { error: 'That email is over 10 MB.', status: 413 };
            const result = await service.checkPasted(raw, { by: admin.email });
            await store.addEvent({ kind: 'check', text: `${admin.email} checked a pasted email from ${result.sender.domain || 'an unknown sender'}.` });
            return { result };
        },
        // The review queues: emails moved or "would move" nobody has reviewed, oldest first; or, with
        // queue=suspicious, suspicious emails not moved, newest first (still in the Inbox: the newest can
        // still be moved before they are opened). counts: both queues, in emails.
        // groups: the copies of one campaign (the same email to many people) are one item, decided together:
        // its keys, who received it and who sent it. An email of no campaign is an item of its own.
        'GET /api/review': async (q) => {
            const { records, listed } = await reviewRecords(service, cache, since(q));
            const queue = RQ.QUEUES.includes(q.get('queue')) ? q.get('queue') : 'moved';
            // One email in one tab (review-queues.js): an email with any copy in the moved tab is only there, with its
            // suspicious copies too, so one answer covers every copy (0.6.39); the suspicious tab holds the rest.
            const Q = RQ.queuesOf(records, { cfg, listed });
            const counts = { moved: Q.moved.length, suspicious: Q.suspicious.length, promotional: Q.promotional.length, reported: Q.reported.length };
            // (0.6.61) The Reported tab is shown only while Settings → User reports is on, or while reports still wait.
            const reportedOn = service.userReportsOn ? await service.userReportsOn() : false;
            if (queue === 'promotional') return { queue, total: Q.promotional.length, companies: A.promoGroups(Q.promotional).slice(0, 1000), mode: cfg.mode, counts, reportedOn };
            const list = queue === 'reported' ? Q.reported.sort((a, b) => (b.userReported.at || 0) - (a.userReported.at || 0))
                : queue === 'suspicious' ? Q.suspicious.sort((a, b) => b.processedAt - a.processedAt)
                : Q.moved.sort((a, b) => a.processedAt - b.processedAt);
            return { queue, total: list.length, groups: reviewGroups(list).slice(0, 1000), keys: list.slice(0, 1000).map(r => r.key), mode: cfg.mode, counts, reportedOn };
        },
        // Several emails at once: release, false-alarm, phishing or unclear (ignore, treat as suspicious), at most
        // 500. Moderators: not release (moderatorMay).
        'POST /api/bulk': async (q, body, admin) => {
            const keys = Array.isArray(body.keys) ? [...new Set(body.keys.map(String))].slice(0, 500) : [];
            if (!['release', 'false-alarm', 'phishing', 'spam', 'unclear'].includes(body.action) || !keys.length) return { error: 'Choose emails and what to do with them.', status: 400 };
            const out = await service.bulk(keys, body.action, admin.email, { addSender: body.addSender === true && admin.role !== 'moderator' });
            if (body.action === 'spam' && out.done) { out.sameSender = await service.answerSameSender(keys, admin.email, await cache.list(Date.now() - 35 * A.DAY)); cache.stale(); }
            return out;
        },
        // What needs an admin (the browser tab's title shows the count): the brake, held campaigns, users
        // who took flagged mail back; and how many emails wait for review.
        // (0.6.50) ?days: the period the dashboard shows (Review's count follows it, as Review does); older: the emails
        // still waiting from before it (within 90 days), so an empty Review can say where they are.
        'GET /api/pending': async (q) => {
            const n = nDays(q), from = Date.now() - n * A.DAY;
            const { records: all, listed } = await reviewRecords(service, cache, Date.now() - 90 * A.DAY);
            const records = all.filter(r => (r.processedAt || 0) >= from);
            // (0.6.68) Each record classified once (review-queues.js), for the period shown and the last 90 days.
            const base = new Map();
            const Q = RQ.queuesOf(records, { cfg, listed, base }), QA = RQ.queuesOf(all, { cfg, listed, base });
            const brake = !!(await shortLived('brake', 15000, () => store.getState('brake')));
            const spamBrake = !!(await shortLived('spamBrake', 15000, () => store.getState('spamBrake')));
            const held = (await shortLived('held', 15000, () => store.listHeldCampaigns())).filter(c => !c.decision).length;
            const rescues = records.filter(rescueToCheck).length;
            const suspicious = Q.suspicious.length, suspiciousAll = QA.suspicious.length;
            const olderMoved = Math.max(0, QA.moved.length - Q.moved.length);
            const reported = Q.reported.length;
            const reportedOn = service.userReportsOn ? await service.userReportsOn() : false;
            return { brake, held, rescues, days: n, unreviewed: Q.moved.length, suspicious, promotional: Q.promotional.length, reported, reportedOn, older: olderMoved + Math.max(0, suspiciousAll - suspicious), olderMoved,
                spamBrake, total: (brake ? 1 : 0) + (spamBrake ? 1 : 0) + held + rescues + reported };
        },
        // Health → Service status: what troubleshooting needs, checked in one place (statusChecks).
        // (0.6.7) Shared by every open dashboard for a minute: each look asks Cloud Run, Cloud Scheduler and the lists.
        // ?fresh=1 checks again now (at most every 5 s).
        'GET /api/status': async (q) => {
            const fresh = q.get('fresh') === '1' && once('status-fresh', 5000);
            if (fresh || !statusCache || Date.now() - statusCache.at > STATUS_CACHE_MS) statusCache = { at: Date.now(), p: statusChecks().catch((e) => { statusCache = null; throw e; }) };
            return { checks: await statusCache.p };
        },
        // The weekly summary email: on or off (off by default), a preview, and one now.
        // (0.6.7) At most one preview a minute, shared: each reads the week's records and every mailbox.
        'GET /api/digest/preview': async () => ({ preview: await shortLived('digest-preview', 60 * 1000, () => service.digestContent()) }),
        'POST /api/digest': async (q, body, admin) => service.setDigest(body.enabled === true, admin.email),
        'POST /api/digest/send': async (q, body, admin) => {
            if (Date.now() - digestSentAt < 60 * 1000) return { error: 'Sent less than a minute ago.', status: 429 };
            digestSentAt = Date.now();
            if (cfg.demo) return { sent: 0, to: [], failed: [], demo: true };
            try { return await service.sendDigest({ by: admin.email }); } catch (e) { return { error: `Couldn't send it: ${String(e.message).slice(0, 200)}`, status: 502 }; }
        },
        // A policy setting changed on the dashboard (POLICY_KEYS, src/config.js: the mode, the AI lines, the
        // brake, the time zone, the allowlists, the optional services, who is checked…). Needs the project ID
        // typed in (five wrong ones lock the account: `wrong`); switching to enforce mode, or letting the AI alone
        // move inside mail, also needs the agreement ticked.
        'POST /api/policy': async (q, body, admin) => {
            const key = String(body.key || '');
            if (!POLICY_KEYS.includes(key)) return { error: 'Choose a setting to change.', status: 400 };
            const expected = expectedProject(cfg);
            if (!expected) return { error: 'This dashboard doesn\'t know its Google Cloud project (GOOGLE_CLOUD_PROJECT). Upgrade from Cloud Shell once (bash deploy/update.sh (or, from an unzipped new version, bash deploy/upgrade.sh)), then try again.', status: 409 };
            const what = POLICY_WHAT[key] || `the setting ${key}`;
            if (wrong.locked(admin.email)) { await wrong.lockedTry(admin.email, what); return { error: 'Too many wrong project IDs. Try again in 10 minutes.', status: 429 }; }
            if (String(body.projectId || '').trim().toLowerCase() !== expected.toLowerCase()) {
                await wrong.add(admin.email, what);
                return { error: 'That isn\'t the Google Cloud project ID of this service. Nothing was changed.', status: 403 };
            }
            wrong.clear(admin.email);
            // (0.6.9) Where updates and the AI model come from decides what code runs in this project: ticked, and the
            // admin's own address typed too; the change is an alert (emailed), never a quiet one.
            if ((key === 'releasesRepo' || key === 'modelRepo') && (body.agree !== true || String(body.adminEmail || '').trim().toLowerCase() !== String(admin.email || '').toLowerCase()))
                return { error: 'Tick the box and type your own admin address (the one you are signed in with) to change where updates come from. Nothing was changed.', status: 400 };
            if (key === 'mode' && body.value === 'enforce' && cfg.mode !== 'enforce' && body.agree !== true) return { error: 'Tick "I agree" to switch to enforce mode. Nothing was changed.', status: 400 };
            // The AI alone moving colleagues' mail is a step away from the cautious default: agreed to, too.
            if (key === 'aiMovesInside' && /^(true|on|yes|1)$/i.test(String(body.value)) && !cfg.aiMovesInside && body.agree !== true) return { error: 'Tick "I agree" to let the AI alone move mail from inside. Nothing was changed.', status: 400 };
            // (0.6.65) Skip review: turning any item on moves mail without review, so it is agreed to, ticked.
            if (key === 'strictSpam') {
                const was = cfg.strictSpam || [], now = strictKinds(body.value);
                if (now.some(k => !was.includes(k)) && body.agree !== true) return { error: 'Tick "I agree" to send this mail to Spam without review. Nothing was changed.', status: 400 };
            }
            // (0.5.53) Who is checked (the pilot or the whole domain): ticked, and the signed-in admin's own address typed
            // too, both ways. The whole domain only when its mailboxes can be read from the directory.
            if (key === 'watchScope') {
                if (body.agree !== true) return { error: 'Tick the box to confirm who will be checked. Nothing was changed.', status: 400 };
                if (String(body.adminEmail || '').trim().toLowerCase() !== String(admin.email || '').toLowerCase()) return { error: 'Type your own admin address (the one you are signed in with) to confirm. Nothing was changed.', status: 403 };
                if (body.value === 'domain' && cfg.watchScope !== 'domain' && !cfg.demo) {
                    const p = await service.scopePreview({ force: true });
                    if (p.domain === null) return { error: `The directory's mailboxes couldn't be read: ${p.domainError} Nothing was changed.`, status: 409 };
                    if (!p.domain) return { error: `The directory has no active mailbox in ${cfg.orgDomains.join(', ')}. Nothing was changed.`, status: 409 };
                }
            }
            // Safe Browsing on needs a key that can be used.
            if (key === 'safeBrowsing' && /^(true|on|yes|1)$/i.test(String(body.value)) && !(sbKey() && await sbKey().get().catch(() => null))) return { error: 'Save an API key first (Settings → Safe Browsing). Nothing was changed.', status: 400 };
            // Spamhaus and abuse.ch on (0.5.37) need their key saved first.
            if ((key === 'spamhaus' || key === 'abusech') && /^(true|on|yes|1)$/i.test(String(body.value)) && !(apiKey(key) && await apiKey(key).get().catch(() => null))) return { error: `Save a key first (Settings → ${key === 'spamhaus' ? 'Spamhaus' : 'abuse.ch'}). Nothing was changed.`, status: 400 };
            try {
                const changed = await service.setPolicy(key, body.value, admin.email);
                // (0.5.53) A new scope: the directory read again now (the renew-watches job), not at night.
                if ((key === 'releasesRepo' || key === 'modelRepo') && !changed.unchanged) {
                    await service.alert('repos', `${admin.email} changed ${key === 'releasesRepo' ? 'the release repository (where updates come from)' : 'the model repository (where the AI model is downloaded from)'} on the dashboard: from ${repos.shown(changed.before) || 'not set'} to ${repos.shown(changed.value) || 'not set'}. If nobody in your team did this, set it back (Settings → Update → Repositories) and check who has access to the dashboard.`, { by: admin.email });
                    if (key === 'releasesRepo' && releasesSource && releasesSource.reset) releasesSource.reset();
                }
                if (key === 'watchScope' && !changed.unchanged) {
                    service.scopeCache = null;
                    if (canRenew()) { try { await scheduler.run(cfg.renewJob); renewAskedAt = Date.now(); renewStatusAt = 0; } catch (e) { /* the hourly job continues it anyway */ } }
                }
                return { changed, policy: service.policyInfo() };
            }
            catch (e) { if (e.status) return { error: `${e.message} Nothing was changed.`, status: e.status }; throw e; }
        },
        // Settings → Update: the approved versions (spruce-google-service_main) and their changes; the button.
        // (demo mode: ?manual=1 shows a made-up approved version that needs a manual install)
        // (0.6.9) With the two repositories (Settings → Update → Repositories): each one's value, settings.env's, and who changed it here.
        'GET /api/update': async (q) => Object.assign(await updateInfo({ cfg, store, releases: cfg.demo && q && q.get && q.get('manual') ? demoReleases({ manual: true }) : releases, cloudrun,
            alert: (t) => service.alert('update-manual', t) }), { repos: (() => { const p = service.policyInfo ? service.policyInfo() : {}; return { releasesRepo: p.releasesRepo || { value: cfg.releasesRepo }, modelRepo: p.modelRepo || { value: cfg.modelRepo } }; })(),
            projectKnown: !!expectedProject(cfg) }),
        'POST /api/update': async (q, body, admin) => startUpdate({ cfg, store, releases, scheduler, service, admin, body, expectedProject, wrong, cloudrun }),
        // Check again (0.5.38): GitHub asked now, at most once a minute for the whole dashboard (src/update.js).
        'POST /api/update/check': async (q, body, admin) => checkNow({ cfg, store, releases: cfg.demo && body && body.manual ? demoReleases({ manual: true }) : releases, cloudrun, admin: admin.email,
            alert: (t) => service.alert('update-manual', t) }),
        // The retraining export (docs/RETRAINING.md): allowed or not (Settings → Retraining, off by default), and
        // the download (Health → Retraining examples): the marked emails read from Gmail again, one download at a
        // time (`exporting`).
        'POST /api/training-export/allow': async (q, body, admin) => service.setTrainingExport(body.enabled === true, admin.email),
        'POST /api/training-export': async (q, body, admin) => {
            if (!((await store.getState('trainingExport')) || {}).enabled) return { error: 'The retraining export is off. An admin can allow it in Settings → Retraining.', status: 403 };
            if (exporting) return { error: 'A download is already being made. Try again in a minute.', status: 429 };
            exporting = true;
            try {
                const days = Math.min(Math.max(Math.round(Number(body.days) || 90), 1), cfg.retentionDays || 365);
                const out = await service.trainingExport({ days, falseAlarms: body.falseAlarms === true, by: admin.email });
                const c = out.counts;
                if (!out.rows.length) {
                    return { error: c.candidates ? `None of the ${c.candidates} marked emails could be read (${c.gone} no longer in a mailbox${c.failed ? `, ${c.failed} failed` : ''}).`
                        : `No emails an admin marked in the last ${days} days${body.falseAlarms === true ? '' : ' as phishing (tick "Include false alarms" for those)'}.`, status: 404 };
                }
                return { download: { body: training.toJsonl(out.rows), type: 'application/x-ndjson; charset=utf-8', filename: `spruce-retraining-${A.dayOf(Date.now())}.jsonl`,
                    headers: { 'x-spruce-examples': String(out.rows.length), 'x-spruce-phishing': String(c.phishing), 'x-spruce-genuine': String(c.genuine),
                        'x-spruce-gone': String(c.gone), 'x-spruce-failed': String(c.failed), 'x-spruce-not-reached': String(c.notReached), 'x-spruce-conflicting': String(c.conflicting), 'x-spruce-not-english': String(c.notEnglish || 0) } } };
            } finally { exporting = false; }
        },
        // Health → Activity: everything for the period, by kind (alert, admin, error, watch: aggregate.js activity).
        // (adminAction: an admin's own change, emailed like an alert but not one: shown as "emailed", 0.5.28)
        // Activity (0.5.29): any period it is kept for (AUDIT_DAYS), a kind, words to look for; the newest 500
        // shown, and all of them (up to 10,000) as CSV, which is recorded.
        // (0.6.72) Settings → Backup (src/settings-backup.js): every saved setting in one file, and its import. Admins only.
        // The API keys only when ticked, encrypted with the admin's passphrase, and with the project ID typed; an import
        // with the project ID typed, checked first (preview), each ticked section applied through the usual checks.
        'POST /api/settings-backup/export': async (q, body, admin) => {
            const includeKeys = body.includeKeys === true;
            if (includeKeys) {
                const bad = await projectCheck(admin, body, 'a settings export with the API keys');
                if (bad) return bad;
                if (String(body.passphrase || '').length < Backup.PASSPHRASE_MIN) return { error: `The passphrase needs at least ${Backup.PASSPHRASE_MIN} characters. Nothing was exported.`, status: 400 };
                if (String(body.passphrase) !== String(body.passphrase2 || '')) return { error: 'The two passphrases aren\'t the same. Nothing was exported.', status: 400 };
            }
            if (!once(`backup-export:${admin.email}`, 5000)) return { error: 'Exported a moment ago: try again in a few seconds.', status: 429 };
            const file = await Backup.exportSettings({ service, store, cfg, keys: backupKeys(), by: admin.email, includeKeys, passphrase: String(body.passphrase || ''), version: VERSION });
            const names = file.keys ? file.keys.names.map(n => ({ safeBrowsing: 'Safe Browsing', spamhaus: 'Spamhaus', abusech: 'abuse.ch' }[n])) : [];
            if (includeKeys) await service.alert('settings-export', `${admin.email} exported the settings with the API keys${names.length ? ` (${names.join(', ')})` : ' (none saved)'}, encrypted with a passphrase they typed (confirmed with the project ID).`);
            else await service.adminNotice('settings', `${admin.email} exported the settings (no API keys).`);
            return { file, name: `spruce-settings-${new Date().toISOString().slice(0, 10)}${includeKeys ? '-with-keys' : ''}.json` };
        },
        'POST /api/settings-backup/preview': async (q, body) => {
            try { return { preview: await Backup.previewImport(Backup.parseFile(body.file), { service, store, cfg }) }; }
            catch (e) { if (e.status) return { error: e.message, status: e.status }; throw e; }
        },
        'POST /api/settings-backup/import': async (q, body, admin) => {
            const bad = await projectCheck(admin, body, 'a settings import');
            if (bad) return bad;
            const sections = (Array.isArray(body.sections) ? body.sections : []).map(String).filter(x => Backup.SECTION_IDS.includes(x));
            if (!sections.length) return { error: 'Tick at least one section to import. Nothing was changed.', status: 400 };
            if (!once(`backup-import:${admin.email}`, 10000)) return { error: 'Imported a moment ago: try again in a few seconds.', status: 429 };
            let f;
            try { f = Backup.parseFile(body.file); } catch (e) { if (e.status) return { error: `${e.message} Nothing was changed.`, status: e.status }; throw e; }
            if (sections.includes('keys') && f.keys && String(body.passphrase || '').length === 0) return { error: 'Type the passphrase the file was made with, or untick API keys. Nothing was changed.', status: 400 };
            const out = await Backup.applyImport(f, { service, store, cfg, keys: backupKeys(), by: admin.email, sections, passphrase: String(body.passphrase || '') });
            cache.stale();
            const label = Object.fromEntries(Backup.SECTIONS.map(x => [x.id, x.label]));
            const said = out.done.map(d => `${label[d.id]}${d.error ? ` (failed: ${d.error})` : ''}`).join(', ');
            await service.alert('settings-import', `${admin.email} imported settings from a file made ${f.exportedAt ? f.exportedAt.slice(0, 10) : 'on an unknown day'}${f.exportedBy ? ` by ${f.exportedBy}` : ''}: ${said || 'nothing'} (confirmed with the project ID).`);
            return out;
        },
        'GET /api/activity': async (q) => {
            const { events, days } = await activityFor(q);
            return { events: events.slice(0, 500).map(e => Object.assign({}, e, { adminAction: A.isAdminAction(e) })), total: events.length, days, maxDays: cfg.auditDays };
        },
        'GET /api/activity.csv': async (q, body, admin) => {
            const { events, days } = await activityFor(q);
            if (admin && service.adminNotice) await service.adminNotice('export', `${admin.email} downloaded ${events.length} Activity entr${events.length === 1 ? 'y' : 'ies'} as CSV (last ${days} days${q.get('kind') || q.get('q') ? ', filtered' : ''}).`);
            return { csv: A.activityCsv(events), filename: `spruce-activity-${A.dayOf(Date.now())}.csv` };
        },
        // Health → Readiness: "Ready for enforce mode?" (aggregate.js readiness).
        'GET /api/readiness': async (q) => {
            const { records } = await load(q);
            const mb = await mailboxes();
            return { readiness: A.readiness(records, { now: Date.now(), days: nDays(q), mode: cfg.mode, installedAt: await store.getState('installedAt'),
                brakeLimit: await service.brakeLimit(), holdAfter: cfg.campaignHoldAfter, watched: mb.watched,
                lastNotification: mb.lastNotification, quietHours: cfg.quietHours, renew: await lastRenew() }) };
        },
        // Settings → Mailboxes' "Read the directory again now" ("Update group membership now" before 0.5.53): runs the
        // daily re-read job at once (it calls the worker; the dashboard doesn't). Noted in Activity, with who asked.
        'POST /api/renew-watches': async (q, body, admin) => {
            if (Date.now() - renewAskedAt < RENEW_GAP_MS) return { error: 'Asked less than a minute ago. The list updates once that re-read has run.', status: 429 };
            if (canRenew()) {
                try { await scheduler.run(cfg.renewJob); }
                catch (e) { return { error: `Couldn't start the re-read: ${e.message}`, status: 502 }; }
                renewAskedAt = Date.now(); renewStatusAt = 0;
                await store.addEvent({ kind: 'watch-asked', text: `${admin.email} asked for the directory (who is checked) to be read again.` });
                return { ok: true };
            }
            if (cfg.demo) {
                renewAskedAt = Date.now();
                await store.addEvent({ kind: 'watch-asked', text: `${admin.email} asked for the directory (who is checked) to be read again (demo: nothing is read).` });
                return { ok: true };
            }
            return { error: 'Not set up here: RENEW_JOB isn\'t set. Run deploy/install.sh again (docs/DEPLOY.md).', status: 503 };
        }
    };

    return async function handle(req, res) {
        const url = new URL(req.url, 'http://local');
        const route = `${req.method} ${url.pathname}`;
        A.setTimeZone(cfg.timeZone);   // (the days the dashboard counts in: the organization's, 0.5.27)
        try {
            if (route === 'GET /healthz') return send(res, 200, { ok: true, role: cfg.role });
            const workerRoute = url.pathname === '/pubsub/push' || url.pathname.startsWith('/tasks/');
            if ((workerRoute && cfg.role === 'admin') || (!workerRoute && cfg.role === 'worker')) return send(res, 404, { error: 'not found' });
            if (route === 'POST /pubsub/push') {
                const v = await verifyPush(req, cfg);
                if (!v.ok) return send(res, 403, { error: v.why });
                const body = await readBody(req);
                let note;
                try { note = JSON.parse(Buffer.from(String((body.message && body.message.data) || ''), 'base64').toString('utf8')); } catch (e) { return send(res, 204, ''); }
                // Something left to do (a failed try, a message another instance is still on): Pub/Sub
                // delivers the notification again later (the subscription's retry delay), and it is tried again.
                let out;
                try { out = await service.handleNotification(note); }
                catch (e) { if (service.gmailTrouble) await service.gmailTrouble(e, String((note && note.emailAddress) || 'a mailbox')); throw e; }   // (0.5.29)
                return out && out.held ? send(res, 503, { retry: 'later' }) : send(res, 204, '');
            }
            const TASKS = { 'POST /tasks/renew-watches': () => service.renewWatches(), 'POST /tasks/purge': async () => ({ deleted: await service.purge() }), 'POST /tasks/stop-watches': () => service.stopAll(), 'POST /tasks/sync-feeds': () => service.syncFeeds() };
            if (TASKS[route]) {
                const v = await verifyTask(req, cfg);
                if (!v.ok) return send(res, 403, { error: v.why });
                return send(res, 200, await TASKS[route]());
            }
            // Everything else is the dashboard: admins, and moderators for the review routes (checked below).
            const admin = await verifyAdmin(req, cfg, groupCheck, moderatorCheck);
            if (!admin.ok) return send(res, admin.status || 403, { error: admin.why });
            await noteOpened(admin.email, admin.role).catch(() => {});
            if (api[route]) {
                // (0.6.1) A moderator may use only the review pages' routes; the rest is refused here, whatever the page shows.
                const forModerators = { error: 'This is for the service\'s administrators: moderators can review emails, not change settings or see Health.', role: admin.role };
                if (admin.role === 'moderator' && !MODERATOR_ROUTES.has(route)) return send(res, 403, forModerators);
                if (req.method === 'POST' && req.headers['x-requested-with'] !== 'spruce-dashboard') return send(res, 403, { error: 'missing request header' });
                // The policy settings changed on the dashboard (at most every 30 s), before anything reads them.
                if (service.refreshPolicy) await service.refreshPolicy();
                // (a pasted email for "Check an email" can be large: its attachments come with it)
                const body = req.method === 'POST' ? await readBody(req, route === 'POST /api/check' ? CHECK_MAX_BYTES * 2 : /^POST \/api\/settings-backup\/(preview|import)$/.test(route) ? Backup.MAX_FILE_BYTES * 2 + 64 * 1024 : 64 * 1024) : {};
                if (admin.role === 'moderator' && !moderatorMay(route, body && body.action)) return send(res, 403, forModerators);
                const out = await api[route](url.searchParams, body, admin);
                // (0.6.7) A change made on the dashboard: the records, events and short-lived answers are read again.
                if (req.method === 'POST') { cache.stale(); events.stale(); statusCache = null; shortCache.clear(); }
                if (out && typeof out.csv === 'string') return send(res, 200, out.csv, 'text/csv; charset=utf-8', { 'content-disposition': `attachment; filename="${out.filename}"` });
                if (out && out.download) return send(res, 200, out.download.body, out.download.type, Object.assign({ 'content-disposition': `attachment; filename="${out.download.filename}"` }, out.download.headers));
                // A route's status is the HTTP status code only when it is one (a field of that name holding
                // anything else, such as an update's progress, broke Settings → Update in 0.3.9 to 0.3.11).
                const code = out && Number.isInteger(out.status) && out.status >= 100 && out.status <= 599 ? out.status : (out && out.error ? 400 : 200);
                return send(res, code, Object.assign({ admin: admin.email, role: admin.role || 'admin', demo: cfg.demo, aiThreshold: cfg.aiThreshold, aiSuspicious: cfg.aiSuspicious, aiMovesInside: cfg.aiMovesInside }, out));
            }
            // The dashboard's own files (public/), never a path outside it.
            if (req.method === 'GET') {
                const rel = url.pathname === '/' ? 'index.html' : url.pathname.replace(/^\/+/, '');
                const file = path.resolve(PUBLIC, rel);
                if (!file.startsWith(PUBLIC + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) return send(res, 404, { error: 'not found' });
                return send(res, 200, fs.readFileSync(file), TYPES[path.extname(file)] || 'application/octet-stream');
            }
            return send(res, 404, { error: 'not found' });
        } catch (e) {
            console.error(route, e);
            return send(res, e.status || 500, { error: e.status ? e.message : 'internal error' });
        }
    };
}

async function main() {
    // Demo mode: the made-up district's domain when ORG_DOMAINS isn't set, as its emails were judged with
    // (Check an email and Re-scan then see "your organization" as the records do).
    const cfg = loadConfig(/^(1|true|yes|on)$/i.test(String(process.env.DEMO || '')) && !process.env.ORG_DOMAINS ? Object.assign({}, process.env, { ORG_DOMAINS: require('./demo/seed').ORG, DIRECTORY_ADMIN: process.env.DIRECTORY_ADMIN || `spruce-directory@${require('./demo/seed').ORG}` }) : process.env);
    const problems = configProblems(cfg);
    if (problems.length) { console.error('Not started; fix the configuration:\n - ' + problems.join('\n - ')); process.exit(1); }
    let store, gmail, intel = null;
    if (cfg.demo) {
        const { buildDemo, directoryNames } = require('./demo/seed');
        let raws, staff;
        ({ store, intel, raws, staff } = await buildDemo({ cfg, now: Date.now() }));
        gmail = { labelId: async (u, n) => `Label_${n}`, modify: async () => ({}), labels: async () => ['INBOX'], search: async () => ({ ids: [], next: null }), headers: async () => ({}),
            // the made-up directory, for the colleague-name check
            userNames: async () => directoryNames(staff),
            // the made-up emails themselves, for Re-scan, Show the email and the retraining export
            raw: async (u, id) => { const b = raws.get(id); if (!b) throw Object.assign(new Error('not found'), { status: 404 }); return { id, threadId: `t-${id}`, labelIds: ['INBOX'], historyId: null, internalDate: Date.now(), raw: b }; },
            // Settings → Link clicks's Test: a made-up day of an admin's Gmail log (0.5.35)
            gmailEvents: async () => require('./demo/seed').demoLogEvents(Date.now()),
            // Settings → User reports's Test: one made-up "User reported phishing" alert (0.6.60)
            alerts: async () => [{ alertId: 'demo-alert-1', createTime: new Date(Date.now() - 3 * 3600e3).toISOString(), type: 'User reported phishing', source: 'Gmail phishing',
                data: { '@type': 'type.googleapis.com/google.apps.alertcenter.type.MailPhishing', messages: [{ recipient: `reader@${require('./demo/seed').ORG}`, messageId: 'demo-1@paystub-viewer.example' }] } }] };
        console.log('DEMO mode: made-up data, no Google access.');
    } else {
        const { DelegatedAuth } = require('./gmail/auth');
        const { GmailClient } = require('./gmail/client');
        store = createStore(cfg);
        // AUDIT_LOG (0.5.29, off by default): each Activity entry also as a log line, which install.sh routes to
        // a log bucket kept a year (spruce-audit). No email text: what the entry says.
        if (cfg.auditLog) store.onEvent = (e) => console.log(JSON.stringify({ severity: e.alert ? 'WARNING' : 'NOTICE', spruceAudit: e.kind || 'event', message: String(e.text || ''), alert: !!e.alert, admin: !!e.admin, mailbox: e.user || undefined, by: e.by || undefined }));
        gmail = new GmailClient(new DelegatedAuth(cfg));
        // The network checks: where mail is judged (the worker), and for "Check an email" (the dashboard).
        intel = require('./intel').createIntel({ cfg, store, engine: spruce.load(), version: require('../package.json').version });
    }
    spruce.load();
    // (the day's counters added up and written every few seconds; written when the instance stops, below)
    const service = new Service({ cfg, store, gmail, intel, statFlushMs: cfg.demo ? 0 : STAT_FLUSH_MS });
    // The AI engine started now (about 100 ms), not on the first email; the worker notes how it went.
    reportEngine({ cfg, store }).catch((e) => console.error('noting the AI engine\'s status:', e));
    // The dashboard can start the group re-read job and the update job (Cloud Scheduler); the worker doesn't need to.
    const scheduler = !cfg.demo && cfg.role !== 'worker' && (cfg.renewJob || cfg.updateJob) ? require('./scheduler').createScheduler() : null;
    // Health → Service status and Settings → Update read the worker's Cloud Run settings (a stand-in in demo mode).
    // (the worker too, from 0.5.24: the installation's level, for the hourly look for a manual install)
    const cloudrun = cfg.demo ? { service: async () => ({ iap: false, image: `demo:${VERSION}-demo`, url: '', labels: {} }), invokers: async () => ['serviceAccount:spruce-invoker@demo.iam.gserviceaccount.com'] }
        : require('./cloudrun').createCloudRun();
    http.createServer(createApp({ cfg, store, service, scheduler, cloudrun })).listen(cfg.port, () => console.log(`Listening on ${cfg.port} (${cfg.role}, ${cfg.mode} mode).`));
    // Cloud Run stops an instance with SIGTERM and 10 seconds' grace: the counters it added up are written.
    process.on('SIGTERM', () => {
        setTimeout(() => process.exit(0), 8000).unref();
        service.flushStats().catch(() => {}).finally(() => process.exit(0));
    });
}

// Loads the AI model and runs its self-check; a worker (or the one instance, ROLE=all) then notes the result
// in Firestore (state/engine-worker: one write per instance start), for Health → Service status.
async function reportEngine({ cfg, store }) {
    const m = spruce.load().model;
    try { await m.ready(); await m.selfCheck(); } catch (e) { console.error('the AI model could not be loaded:', e); }
    const st = m.status();
    if (cfg.role === 'admin') return st;
    const ok = st.state === 'ready' && !!(st.check && st.check.ok);
    // (0.6.2) With the domains it counts as the organization's (ORG_DOMAINS as the worker has it), for Service status.
    await store.setState('engine-worker', Object.assign({}, st, { ok, at: Date.now(), version: VERSION, revision: process.env.K_REVISION || '', orgDomains: [...(cfg.orgDomains || [])] }));
    // The AI model not working is an alert (0.5.28), once a day whichever instance starts.
    if (!ok && await store.setStateIfUnset(`alert-ai-model-${new Date().toISOString().slice(0, 10)}`, { at: Date.now() })) {
        const text = `The AI model doesn't work in the worker (${st.state}${st.error ? `: ${String(st.error).slice(0, 160)}` : st.check && !st.check.ok ? ': its self-check failed' : ''}): emails are judged by the rule checks alone meanwhile. Health → Service status shows it; installing the version again (bash deploy/update.sh) usually fixes it.`;
        await store.addEvent({ kind: 'ai-model', text, alert: true });
        console.warn(JSON.stringify({ severity: 'WARNING', spruceAlert: 'ai-model', message: text }));
    }
    return st;
}

if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });
module.exports = { reviewGroups, createApp, expectedProject, reportEngine, moderatorMay, MODERATOR_ROUTES };
