'use strict';
// (0.6.30) The allow lists' 30-day reputation check. Every domain on an allow list (allowlisted senders and addresses,
// allowed link domains, brand senders the reviewers confirmed, senders whose spam people took back) is looked up
// once when it is first seen, then again every 30 days: its registration (RDAP: when it was registered, when it
// expires, its registrar and name servers) and its reputation (Cloudflare's malware and phishing blocks, the
// phishing lists, Spamhaus's DBL when it is on). A change flags it for review: Settings → Sender lists, Today's Needs
// attention, Activity, and an email to every admin (ADMIN_EMAILS and the members of ADMIN_GROUP). A change that
// means the domain may have lapsed or changed hands (registered again, expired, gone, or now blocked or listed)
// also SUSPENDS it: it isn't trusted until an admin answers. A new registrar or new name servers only flag it
// (companies move their DNS). An admin answers "Still trusted" (a new snapshot is taken; for a suspended one with
// the project ID, as for any allowlist change), and can release the emails held back while it was suspended.
// Nothing about the email is sent anywhere: only the domain names, to their registries and the reputation services.
const DAY = 24 * 60 * 60 * 1000;
const CHECK_EVERY_MS = 30 * DAY;
const PER_RUN = 20;
const SUSPEND = new Set(['registered-again', 'gone', 'expired', 'blocked', 'listed', 'spamhaus']);
const LIST_NAMES = { allowDomains: 'Trusted senders', allowAddresses: 'Trusted senders (addresses)', allowLinkDomains: 'Link sites',
    brandSenders: 'Brand senders', spamRescued: 'Spam people took back', spamSenders: 'Spam senders' };

const day = (t) => new Date(t).toISOString().slice(0, 10);

// What changed between two snapshots: [{ kind, text, suspend }]. Something unknown on either side is no change.
function compareSnapshots(was, now, at = Date.now()) {
    const out = [];
    const add = (kind, text) => out.push({ kind, text, suspend: SUSPEND.has(kind) });
    if (was.exists !== false && now.exists === false) add('gone', 'the registry no longer has the domain: it lapsed or was deleted');
    if (now.exists !== false) {
        if (typeof was.created === 'number' && typeof now.created === 'number' && now.created > was.created + 2 * DAY)
            add('registered-again', `it was registered again on ${day(now.created)} (it had been registered since ${day(was.created)}): the domain lapsed and someone registered it anew`);
        if (typeof now.expires === 'number' && now.expires < at) add('expired', `its registration expired on ${day(now.expires)}`);
        if (was.registrar && now.registrar && was.registrar.toLowerCase() !== now.registrar.toLowerCase())
            add('registrar', `its registrar changed from ${was.registrar} to ${now.registrar}`);
        const a = new Set(was.ns || []), b = now.ns || [];
        if (a.size && b.length && !b.some(x => a.has(x))) add('nameservers', `all its name servers changed (${[...a].slice(0, 2).join(', ')} → ${b.slice(0, 2).join(', ')})`);
    }
    if (!was.blocked && now.blocked) add('blocked', `Cloudflare now blocks it as ${now.blocked}`);
    if (!was.listed && now.listed) add('listed', `it is now on a phishing list (${now.listed})`);
    if (!was.spamhaus && now.spamhaus) add('spamhaus', `it is now on Spamhaus's Domain Blocklist (${now.spamhaus})`);
    return out;
}

function install(Service, { isAllowed }) {
    Object.assign(Service.prototype, {
        // Every domain on an allow list → the lists it is on. Personal mail providers' and the organization's own
        // domains are skipped (an address there is one mailbox, not the domain's reputation).
        async allowWatchItems() {
            const E = require('./engine/spruce').load();
            const own = (d) => this.cfg.orgDomains.some(o => d === o || d.endsWith('.' + o));
            const out = new Map();
            const put = (domain, list) => {
                const d = String(domain || '').toLowerCase().replace(/\.$/, '');
                if (!d || !/\./.test(d) || own(d) || E.isPersonalMailDomain(d)) return;
                if (!out.has(d)) out.set(d, new Set());
                out.get(d).add(list);
            };
            for (const d of this.cfg.allowDomains || []) put(d, 'allowDomains');
            for (const a of this.cfg.allowAddresses || []) put(String(a).split('@')[1], 'allowAddresses');
            for (const d of this.cfg.allowLinkDomains || []) put(d, 'allowLinkDomains');
            for (const v of Object.values((await this.store.getState('brandSenders')) || {})) if (v && v.domain) put(v.domain, 'brandSenders');
            for (const [k, v] of Object.entries((await this.store.getState('spamRescued')) || {})) if (v && v.shared && !k.includes('@')) put(k, 'spamRescued');
            for (const k of Object.keys((await this.store.getState('spamSenders')) || {})) if (!k.includes('@')) put(k, 'spamSenders');   // (0.6.35)
            return out;
        },
        // A domain's registration and reputation now.
        async allowSnapshot(domain) {
            const i = this.intel || {};
            const [rec, cf, listed, sh] = await Promise.all([
                i.rdap && i.rdap.record ? i.rdap.record(domain).catch(() => null) : null,
                i.threats ? i.threats.checkHosts([domain]).catch(() => new Map()) : new Map(),
                i.feeds ? i.feeds.domainHit(domain).catch(() => null) : null,
                i.spamhaus ? i.spamhaus.checkDomains([domain]).catch(() => new Map()) : new Map()]);
            const c = cf && cf.get ? cf.get(domain) : null, s = sh && sh.get ? sh.get(domain) : null;
            return Object.assign({ at: this.now(), blocked: c && c.verdict === 'unsafe' ? (c.reason || 'malware or phishing') : '',
                listed: listed ? String(listed.name || listed.list || listed) : '', spamhaus: s && s.dbl && s.dbl.severity === 'danger' ? (s.dbl.list || 'DBL') : '' },
                rec || { exists: null, created: null, expires: null, registrar: '', ns: [] });
        },
        async allowWatchState() { return Object.assign({ domains: {} }, (await this.store.getState('allowWatch')) || {}); },
        // The domains suspended now (an instance remembers them for a minute).
        async allowSuspendedSet() {
            if (this._allowSuspended && this.now() - this._allowSuspended.at < 60000) return this._allowSuspended.set;
            const st = await this.allowWatchState();
            const set = new Set(Object.entries(st.domains).filter(([, v]) => v && v.review && v.review.suspended).map(([d]) => d));
            this._allowSuspended = { at: this.now(), set };
            return set;
        },
        async allowSuspendedFor(domain) {
            const d = String(domain || '').toLowerCase();
            if (!d) return null;
            for (const x of await this.allowSuspendedSet()) if (d === x || d.endsWith('.' + x)) return x;
            return null;
        },
        // isAllowed, unless the address's domain is suspended. { allowed, suspended: the suspended domain or null }.
        async allowedNow(address) {
            if (!isAllowed(this.cfg, address)) return { allowed: false, suspended: null };
            const s = await this.allowSuspendedFor(String(address || '').toLowerCase().split('@')[1] || '');
            return { allowed: !s, suspended: s };
        },
        async allowLinkDomainsNow() {
            const set = await this.allowSuspendedSet();
            return set.size ? (this.cfg.allowLinkDomains || []).filter(d => !set.has(String(d).toLowerCase())) : this.cfg.allowLinkDomains;
        },
        // The hourly job: the domains due (never looked up, or 30 days since), at most PER_RUN, within budgetMs.
        async checkAllowlists({ budgetMs = 20000 } = {}) {
            const started = Date.now();
            const items = await this.allowWatchItems();
            const st = await this.allowWatchState();
            let changed = false;
            for (const d of Object.keys(st.domains)) if (!items.has(d)) { delete st.domains[d]; changed = true; }   // no longer on any list
            const due = [...items.keys()].filter(d => { const e = st.domains[d]; return !e || !e.snap || (!e.review && this.now() - (e.checkedAt || 0) >= CHECK_EVERY_MS); })
                .sort((a, b) => ((st.domains[a] && st.domains[a].checkedAt) || 0) - ((st.domains[b] && st.domains[b].checkedAt) || 0)).slice(0, PER_RUN);
            const out = { checked: 0, flagged: [], suspended: [] };
            for (const d of due) {
                if (Date.now() - started > budgetMs) break;
                const snap = await this.allowSnapshot(d);
                const e = st.domains[d] = Object.assign({ first: this.now() }, st.domains[d], { lists: [...items.get(d)], checkedAt: this.now() });
                out.checked++; changed = true;
                if (!e.snap) { e.snap = snap; continue; }
                const changes = compareSnapshots(e.snap, snap, this.now());
                if (!changes.length) { e.snap = Object.assign({}, e.snap, { at: snap.at }); continue; }
                const suspended = changes.some(c => c.suspend);
                e.review = { at: this.now(), changes, suspended, now: snap };
                out.flagged.push(d); if (suspended) out.suspended.push(d);
                await this.allowReviewAlert(d, e);
            }
            for (const [d, lists] of items) if (st.domains[d] && st.domains[d].lists.join() !== [...lists].join()) { st.domains[d].lists = [...lists]; changed = true; }
            if (changed) { await this.store.setState('allowWatch', st); this._allowSuspended = null; }
            return out;
        },
        // Activity (an alert, also a log line Cloud Monitoring emails to ALERT_EMAIL) and an email to every admin.
        async allowReviewAlert(d, e) {
            const lists = e.lists.map(l => LIST_NAMES[l] || l).join(', ');
            const what = e.review.changes.map(c => c.text).join('; ');
            const text = `${d} (on ${lists}) needs review: ${what}. ${e.review.suspended ? 'It may have lapsed or changed hands, so it is suspended: its list doesn\'t count for it until an admin answers in Settings → Sender lists ("Keep it on the list", or remove it).' : 'Its list still counts for it; check it in Settings → Sender lists ("Keep it on the list", or remove it).'}`;
            await this.alert('allowlist-review', text, { domain: d });
            await this.adminMail(`S.P.R.U.C.E: ${d} on your Sender lists needs review${e.review.suspended ? ' (suspended)' : ''}`,
                `${text}\n\nEvery domain on your Sender lists is checked every 30 days: a domain whose registration or reputation changed may have expired and been registered by someone else, or been sold.${this.cfg.dashboardUrl ? `\n\nSettings → Sender lists: ${this.cfg.dashboardUrl}#/allowlist` : ''}\n`)
                .catch(err => this.log.error('allowlist review mail:', err));
        },
        // An email in every admin's Inbox (as the weekly summary is sent).
        async adminMail(subject, text) {
            const to = await this.digestRecipients();
            const org = this.cfg.orgDomains[0] || 'localhost';
            const from = `"S.P.R.U.C.E Mail Protection Service" <${this.cfg.directoryAdmin || `no-reply@${org}`}>`;
            const { mime } = require('./digest');
            const crypto = require('crypto');
            let sent = 0;
            for (const user of to) {
                try {
                    const raw = mime({ from, to: user, subject, text, date: new Date(this.now()), messageId: `<spruce-alert-${this.now()}-${crypto.randomBytes(6).toString('hex')}@${org}>` });
                    const r = await this.gmail.insert(user, raw, ['INBOX', 'UNREAD']);
                    if (r && r.id) await this.store.markSeen(user, r.id);
                    sent++;
                } catch (err) { this.log.error(`alert mail to ${user}:`, err); }
            }
            return { sent, to };
        },
        // Settings → Sender lists: the domains waiting for review, with the emails held back while suspended.
        async allowReviewList() {
            const st = await this.allowWatchState();
            const rows = Object.entries(st.domains).filter(([, v]) => v && v.review);
            const out = [];
            for (const [domain, v] of rows) {
                const held = (await this.store.listRecords({ sinceMs: v.review.at, limit: 5000 })).filter(r => r.allowSuspended === domain);
                out.push({ domain, lists: v.lists.map(l => LIST_NAMES[l] || l), at: v.review.at, changes: v.review.changes, suspended: !!v.review.suspended,
                    emails: held.length, moved: held.filter(r => r.state === 'moved').length });
            }
            return { review: out.sort((a, b) => b.at - a.at), watched: Object.keys(st.domains).length };
        },
        // "Still trusted": a new snapshot, the review closed; release: the emails held back while it was suspended
        // are answered as false alarms (those in Spam go back to the Inbox).
        async resolveAllowReview(domain, by, { release = false } = {}) {
            const d = String(domain || '').toLowerCase();
            const st = await this.allowWatchState();
            const e = st.domains[d];
            if (!e || !e.review) return { error: 'That domain isn\'t waiting for review.', status: 404 };
            const was = e.review;
            e.snap = await this.allowSnapshot(d);
            e.checkedAt = this.now(); e.review = null; e.trustedBy = by; e.trustedAt = this.now();
            await this.store.setState('allowWatch', st);
            this._allowSuspended = null;
            let released = 0, answered = 0;
            if (release) {
                const held = (await this.store.listRecords({ sinceMs: was.at, limit: 5000 })).filter(r => r.allowSuspended === d && r.falseAlarm !== true);
                for (const r of held) { const m = await this.mark(r.key, true, by, { quiet: true }); if (!m.error) { answered++; if (m.released) released++; } }
            }
            await this.store.addEvent({ kind: 'settings', text: `${by} checked ${d} after its 30-day check (${was.changes.map(c => c.kind).join(', ')}) and kept it trusted${was.suspended ? ': it is no longer suspended' : ''}.${release ? ` ${answered} email${answered === 1 ? '' : 's'} held back while it was suspended answered as false alarms, ${released} moved back to the Inbox.` : ''}` });
            return Object.assign({ ok: true, answered, released }, await this.allowReviewList());
        }
    });
}

module.exports = { install, compareSnapshots, CHECK_EVERY_MS, PER_RUN, LIST_NAMES };
