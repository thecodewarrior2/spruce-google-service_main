'use strict';
// (0.6.98) A sender's history from Gmail itself: the service knows a sender only from its own install, so on a new install
// (and for a sender it first saw in its learning period) it asks the reader's mailbox, which goes back as far as the
// mailbox does: has it older mail from this sender (over a day, a month, a year old), about how much, and has anyone in
// the organization written to them (Sent). Only for an outside sender Gmail confirmed (DMARC): a forged address never
// borrows the real sender's history.
//
// Cached for the whole organization, by a one-way hash of the sender (counts and yes/no only, never an address or mail):
// in memory (MEM_MAX entries, MEM_MS) and in the shared store (a known sender KNOWN_MS, an unknown one UNKNOWN_MS, as
// new mail can come any day), so most emails cost no Gmail call; a lookup gives up after BUDGET_MS (then: unknown).
const DAY = 24 * 3600 * 1000;
const KNOWN_MS = 30 * DAY, UNKNOWN_MS = DAY, MEM_MS = 3600 * 1000, MEM_MAX = 5000, BUDGET_MS = 2500, DEEP_DAYS = 30;

class MailboxHistory {
    constructor({ gmail, store, now = () => Date.now(), log = console }) {
        this.gmail = gmail; this.store = store; this.now = now; this.log = log;
        this.mem = new Map(); this.inFlight = new Map();
    }
    // { received: about how many earlier emails, ageDays: 0 | 1 | 30 | 365 (the oldest found is over that old), wrote: bool,
    //   deep: the mailbox asked holds mail over DEEP_DAYS old (so "nothing found" means something), at } or null (couldn't
    //   tell). key: the sender's hash (pipeline.js senderHash); box: the mailbox's hash.
    // A sender found anywhere is known to the whole organization (cached for it); "nothing found" is one mailbox's answer
    // (cached for that mailbox only): another may have years of mail from the same sender.
    async of(user, address, key, box = '') {
        if (!this.gmail || typeof this.gmail.searchCount !== 'function' || !address || !key) return null;
        const memKey = `${key}|${box}`;
        const m = this.mem.get(key) || this.mem.get(memKey);
        if (m && this.now() - m.memAt < MEM_MS) return m.value;
        if (this.inFlight.has(memKey)) return this.inFlight.get(memKey);
        const p = (async () => {
            let v = (await this.store.getCached('mbhist', key).catch(() => null)) || (box ? await this.store.getCached('mbneg', `${key}|${box}`).catch(() => null) : null);
            if (!v) {
                v = await this.lookup(user, address, box).catch((e) => { this.log.warn && this.log.warn(JSON.stringify({ message: `Gmail history lookup: ${String(e && e.message || e).slice(0, 200)}` })); return null; });
                if (v && (v.received || v.wrote)) await this.store.setCached('mbhist', key, v, KNOWN_MS).catch(() => {});
                else if (v && box) await this.store.setCached('mbneg', `${key}|${box}`, v, UNKNOWN_MS).catch(() => {});
            }
            if (v) { this.mem.set(v.received || v.wrote ? key : memKey, { value: v, memAt: this.now() }); if (this.mem.size > MEM_MAX) this.mem.delete(this.mem.keys().next().value); }
            return v;
        })().finally(() => this.inFlight.delete(memKey));
        this.inFlight.set(memKey, p);
        return p;
    }
    // Whether a mailbox holds mail over DEEP_DAYS old: a new Google Workspace, a new hire's mailbox, has none, and there
    // "nothing from this sender" says nothing. Cached per mailbox (holds old mail: 30 days; not yet: a day).
    async deep(user, box) {
        const c = box ? await this.store.getCached('mbdeep', box).catch(() => null) : null;
        if (c && typeof c.deep === 'boolean') return c.deep;
        const r = await this.gmail.searchCount(user, `older_than:${DEEP_DAYS}d`);
        if (box) await this.store.setCached('mbdeep', box, { deep: !!r.any }, r.any ? KNOWN_MS : UNKNOWN_MS).catch(() => {});
        return !!r.any;
    }
    async lookup(user, address, box) {
        const a = String(address).replace(/["\\\s]/g, '');
        const late = new Promise((res) => { const t = setTimeout(() => res(null), BUDGET_MS); if (t.unref) t.unref(); });
        const run = (async () => {
            const q = (s) => this.gmail.searchCount(user, s);
            // Older than a day: never this email itself. Then a month, then a year, only as far as needed.
            const [day, wrote] = await Promise.all([q(`from:${a} older_than:1d`), q(`in:sent to:${a}`)]);
            let ageDays = 0;
            if (day.any) {
                ageDays = 1;
                if ((await q(`from:${a} older_than:30d`)).any) ageDays = (await q(`from:${a} older_than:1y`)).any ? 365 : 30;
            }
            const known = day.any || wrote.any;
            return { received: day.any ? Math.max(1, day.estimate) : 0, ageDays, wrote: !!wrote.any, deep: known ? true : await this.deep(user, box), at: this.now() };
        })();
        return Promise.race([run, late]);
    }
}

// Whether the answer says the sender is new: nothing found, in a mailbox old enough for that to mean something.
const newSender = (h) => !!h && !h.received && !h.wrote && h.deep === true;

// The history the AI is given from it (context-facts.js historyOf's shape), or null.
function historyFromGmail(h) {
    if (!h) return null;
    if (!h.received && !h.wrote) return newSender(h) ? { first: true } : null;   // (a new mailbox: unknown, not "first")
    return { days: h.ageDays || 0, emails: h.received || 0 };
}

module.exports = { MailboxHistory, historyFromGmail, newSender, KNOWN_MS, UNKNOWN_MS, DEEP_DAYS };
