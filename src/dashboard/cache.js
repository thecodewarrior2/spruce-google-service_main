'use strict';
// The dashboard's copy of the records (one per dashboard instance). The first use reads the records of
// the last startDays (32: the 30 days Today and the other pages show first, from the midnight
// before, with a day to spare); a page that shows
// more (Last 90 days) has the older ones read then, up to the retention period, and they are forgotten
// again after OLDER_KEPT_MS without such a page. After that, only records saved or changed since (each
// one has updatedAt), at most every refreshMs (from a minute before the newest change seen, so a record
// saved in the same millisecond, or by an instance whose clock is a little behind, isn't missed; seen
// twice is harmless). Without it, every page of every open dashboard (they update themselves every 30 s)
// read up to 20,000 records from Firestore, which a district's dashboard left open would pay for.
const DAY = 24 * 60 * 60 * 1000;
const OVERLAP_MS = 60 * 1000;
// (0.6.7) The records changed since the last look, read CHANGED_PAGE at a time from exactly where the last page
// ended (by updatedAt, then the document's id), at most CHANGED_PAGES pages per look. Before, a minute with more
// than 5,000 changes (a campaign to most of a district, or a whole campaign released) left the cache reading the
// same 5,000 records every 15 s, the newer ones never.
const CHANGED_PAGE = 5000, CHANGED_PAGES = 20;
const PAGE = 10000;                       // records read at a time when the cache starts
const OLDER_KEPT_MS = 60 * 60 * 1000;     // records older than startDays, kept this long after a page last used them
const INTERNED = 200000;                  // distinct strings shared between records (then started again)

// What the dashboard's pages use of a record (src/dashboard/aggregate.js, the lists, the CSV, the review
// queues), and nothing else: an email's own page reads the whole record from the store. The signs kept are
// those that count for "top reasons" (weight 2 or more). Strings that repeat (a campaign's sender, subject
// and signs) are shared, not copied. About a fifth of a full record's memory: a district's 60 days
// (180,000 records) fit in the dashboard's memory.
function slimmer() {
    const pool = new Map();
    const I = (v) => {
        if (typeof v !== 'string') return v;
        const hit = pool.get(v);
        if (hit !== undefined) return hit;
        if (pool.size >= INTERNED) pool.clear();
        pool.set(v, v);
        return v;
    };
    return (r) => Object.freeze({
        key: r.key, user: I(r.user), messageId: r.messageId, rfc822MessageId: r.rfc822MessageId, threadId: r.threadId,
        processedAt: r.processedAt, receivedAt: r.receivedAt, updatedAt: r.updatedAt,
        sender: r.sender ? Object.freeze({ name: I(r.sender.name), address: I(r.sender.address), domain: I(r.sender.domain) }) : r.sender,
        subject: I(r.subject), campaign: I(r.campaign), campaignLabel: I(r.campaignLabel),
        status: I(r.status), score: r.score, evidence: I(r.evidence), action: I(r.action), trigger: I(r.trigger), why: I(r.why), mode: I(r.mode),
        ai: r.ai ? Object.freeze({ probability: r.ai.probability, model: I(r.ai.model) }) : r.ai,
        signals: Object.freeze((r.signals || []).filter(x => x && x.weight >= 2).map(x => Object.freeze({ kind: I(x.kind), text: I(x.text), weight: x.weight }))),
        state: I(r.state), held: I(r.held), braked: r.braked, userPlaced: r.userPlaced, ownAddressUnverified: r.ownAddressUnverified,
        releasedBy: I(r.releasedBy), releasedAt: r.releasedAt, releasedByUser: r.releasedByUser, falseAlarm: r.falseAlarm, unclear: r.unclear, markedBy: I(r.markedBy),
        heldMovedBy: I(r.heldMovedBy), heldMovedAt: r.heldMovedAt, inside: r.inside,
        // (0.6.44) The sender check (Review's tag and filter, the Sender lists' and the suspicious line's tests: 0.6.40),
        // a Spam answer and when an answer was given (Re-checked's "answered", 0.6.43), and why it went to Spam.
        auth: r.auth ? Object.freeze({ dmarc: I(r.auth.dmarc), headerFrom: I(r.auth.headerFrom) }) : r.auth, spam: r.spam, spamSender: I(r.spamSender),
        platformNote: r.platformNote, undo: r.undo && r.undo.at ? Object.freeze({ at: r.undo.at }) : null,
        // Re-checked after delivery (0.5.35): what was found, when, and what Gmail's logs say.
        recheck: r.recheck ? Object.freeze({ at: r.recheck.at, source: I(r.recheck.source), site: I(r.recheck.site), list: I(r.recheck.list), round: r.recheck.round, version: I(r.recheck.version),
            before: I(r.recheck.before), outcome: I(r.recheck.outcome), where: I(r.recheck.where), opened: r.recheck.opened, movedAt: r.recheck.movedAt,
            clicks: r.recheck.clicks ? Object.freeze(Object.assign({}, r.recheck.clicks)) : null }) : null
    });
}

class RecordCache {
    // keepDays: how far back records are kept (a number, or a function for a setting that can change:
    // Settings → Policy, how long records are kept). startDays: what the first use reads.
    constructor(store, { keepDays = 90, startDays = 32, refreshMs = 15000, now = () => Date.now() } = {}) {
        this.store = store; this.keepDays = keepDays; this.startMs = startDays * DAY; this.refreshMs = refreshMs; this.now = now;
        this.byKey = new Map(); this.cursor = 0; this.loadedAt = 0; this.loading = null; this.slim = slimmer();
        this.from = Infinity;     // every record processed since this is held (Infinity: none read yet)
        this.olderUsedAt = 0; this.extending = null;
    }
    get keepMs() { return (typeof this.keepDays === 'function' ? this.keepDays() : this.keepDays) * DAY; }
    // Every record processed from sinceMs to before untilMs, PAGE at a time (newest first).
    async readAll(sinceMs, untilMs = Number.MAX_SAFE_INTEGER) {
        const rows = [];
        let until = untilMs;
        for (;;) {
            const page = await this.store.listRecords({ sinceMs, untilMs: until, limit: PAGE });
            rows.push(...page);
            if (page.length < PAGE) return rows;
            const last = page[page.length - 1].processedAt;
            if (!(last < until)) return rows;        // (more than PAGE in one millisecond: never in practice)
            until = last + 1;                        // (the last millisecond is read again; kept once, by key)
        }
    }
    // The records changed since sinceMs (oldest first), every page of them.
    async readChanged(sinceMs) {
        const rows = [];
        let after = null;
        for (let i = 0; i < CHANGED_PAGES; i++) {
            const page = await this.store.listRecordsChangedSince(sinceMs, CHANGED_PAGE, after);
            rows.push(...page);
            if (page.length < CHANGED_PAGE) break;
            const last = page[page.length - 1];
            after = { updatedAt: last.updatedAt || last.processedAt || 0, id: last.key };
        }
        return rows;
    }
    // The first use reads the start period whole; each later one only the records changed since the newest
    // change seen (cursor), at most every refreshMs. Concurrent calls share one read (loading).
    async refresh(force = false) {
        if (this.loading) return this.loading;
        if (!force && this.loadedAt && this.now() - this.loadedAt < this.refreshMs) return;
        this.loading = (async () => {
            const first = !this.loadedAt;
            const at = this.now(), keepMs = this.keepMs;
            const from = at - Math.min(this.startMs, keepMs);
            const rows = first ? await this.readAll(from)
                : await this.readChanged(this.cursor - OVERLAP_MS);
            if (first) this.from = from;
            for (const r of rows) {
                if (r.processedAt >= this.from) this.byKey.set(r.key, this.slim(r));   // (an older one changed: read when a page needs it)
                this.cursor = Math.max(this.cursor, r.updatedAt || r.processedAt || 0);
            }
            // (no record at all yet: changes are looked for from now on)
            if (first && !rows.length) this.cursor = at - 1;
            // Past the retention period (it may have been shortened); and the older part, when no page has
            // needed it for OLDER_KEPT_MS.
            let floor = at - keepMs;
            if (this.from < at - this.startMs && at - this.olderUsedAt > OLDER_KEPT_MS) floor = Math.max(floor, at - this.startMs);
            if (this.from < floor) {
                for (const [k, r] of this.byKey) if (r.processedAt < floor) this.byKey.delete(k);
                this.from = floor;
            }
            this.loadedAt = at;
        })().finally(() => { this.loading = null; });
        return this.loading;
    }
    // The records from sinceMs to the oldest held, read when a page first shows a longer period.
    async extend(sinceMs) {
        while (this.extending) await this.extending;
        if (sinceMs >= this.from) return;
        this.extending = (async () => {
            const until = this.from;
            const rows = await this.readAll(sinceMs, until);
            for (const r of rows) if (!this.byKey.has(r.key)) this.byKey.set(r.key, this.slim(r));
            this.from = Math.min(this.from, sinceMs);
        })().finally(() => { this.extending = null; });
        return this.extending;
    }
    // Records processed since sinceMs (within the retention period), newest first (as store.listRecords):
    // the cache's own (frozen) slim records, not copies: the pages only read them.
    async list(sinceMs = 0, limit = Infinity) {
        await this.refresh();
        const at = this.now(), s = Math.max(sinceMs, at - this.keepMs);
        if (s < at - this.startMs) this.olderUsedAt = at;
        if (s < this.from) await this.extend(s);
        const out = [];
        for (const r of this.byKey.values()) if (r.processedAt >= s) out.push(r);
        out.sort((a, b) => b.processedAt - a.processedAt);
        return out.length > limit ? out.slice(0, limit) : out;
    }
    // After the dashboard itself changed records (a release, a mark): seen at the next look, not 15 s later.
    stale() { this.loadedAt = Math.min(this.loadedAt, 1); }
}

// (0.6.7) The dashboard's copy of Activity's events (they are only ever added, never changed): read once for the
// period a page first asks for, then only the newer ones, at most every refreshMs. Before, Activity read up to
// 10,000 events on every live refresh of every open dashboard (every 30 s), Today 500 to show 10, Service
// status 500 to count the errors, and each admin's first visit of the day 2,000.
const EVENT_OVERLAP_MS = 30 * 1000;
class EventCache {
    constructor(store, { refreshMs = 15000, maxEvents = 50000, now = () => Date.now() } = {}) {
        this.store = store; this.refreshMs = refreshMs; this.maxEvents = maxEvents; this.now = now;
        this.events = []; this.seen = new Set(); this.from = Infinity; this.newest = 0; this.loadedAt = 0;
        this.loading = null; this.extending = null;
    }
    // An event's identity (events have no id here): two reads that overlap keep it once.
    static sig(e) { return `${e.at}|${e.kind || ''}|${e.by || ''}|${e.user || ''}|${e.text || ''}`; }
    // New events in, newest first; past maxEvents the oldest are dropped, and the period held (from) starts later.
    add(rows) {
        let added = 0;
        for (const e of rows) {
            const k = EventCache.sig(e);
            if (this.seen.has(k)) continue;
            this.seen.add(k); this.events.push(Object.freeze(e)); added++;
            if (e.at > this.newest) this.newest = e.at;
        }
        if (!added) return;
        this.events.sort((a, b) => b.at - a.at);
        if (this.events.length > this.maxEvents) {
            for (const e of this.events.splice(this.maxEvents)) this.seen.delete(EventCache.sig(e));
            this.from = this.events[this.events.length - 1].at;
        }
    }
    // The events added since the newest held (from EVENT_OVERLAP_MS before it: another instance's event can carry
    // an earlier time), at most every refreshMs; nothing before the first read (extend makes it).
    async refresh(force = false) {
        if (this.loading) return this.loading;
        if (this.from === Infinity || (!force && this.now() - this.loadedAt < this.refreshMs)) return;
        this.loading = (async () => {
            const at = this.now();
            // Newest first, a page at a time down to where the last look ended (more than a page of events between two
            // looks: none skipped; the page's last millisecond is read again, kept once).
            const since = Math.max(this.from, this.newest - EVENT_OVERLAP_MS);
            let until = null;
            for (let i = 0; i < 20; i++) {
                const page = await this.store.listEvents(since, until === null ? { limit: 5000 } : { limit: 5000, untilMs: until });
                this.add(page);
                if (page.length < 5000) break;
                const last = page[page.length - 1].at;
                if (until !== null && last + 1 >= until) break;     // (more than a page in one millisecond: never in practice)
                until = last + 1;
            }
            this.loadedAt = at;
        })().finally(() => { this.loading = null; });
        return this.loading;
    }
    // The events from sinceMs to the oldest held: the first read, or a page asking for a longer period. When
    // maxEvents are already held, the period held isn't lowered (the older events didn't fit).
    async extend(sinceMs) {
        while (this.extending) await this.extending;
        if (sinceMs >= this.from) return;
        this.extending = (async () => {
            const at = this.now(), first = this.from === Infinity;
            this.add(await this.store.listEvents(sinceMs, first ? { limit: this.maxEvents } : { limit: this.maxEvents, untilMs: this.from }));
            if (this.events.length < this.maxEvents) this.from = Math.min(this.from, sinceMs);
            if (first) this.loadedAt = at;
        })().finally(() => { this.extending = null; });
        return this.extending;
    }
    // The events since sinceMs, newest first, at most limit (as store.listEvents; the cache's own frozen events).
    async list(sinceMs = 0, { limit = Infinity } = {}) {
        if (sinceMs < this.from) await this.extend(sinceMs);
        await this.refresh();
        const out = [];
        for (const e of this.events) { if (e.at < sinceMs || out.length >= limit) break; out.push(e); }
        return out;
    }
    // After the dashboard itself added events: seen at the next look.
    stale() { this.loadedAt = 0; }
}

module.exports = { RecordCache, EventCache, slimmer, OLDER_KEPT_MS };
