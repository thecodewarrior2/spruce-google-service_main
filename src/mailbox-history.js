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
const KNOWN_MS = 30 * DAY, UNKNOWN_MS = DAY, MEM_MS = 3600 * 1000, MEM_MAX = 5000, BUDGET_MS = 2500;

class MailboxHistory {
    constructor({ gmail, store, now = () => Date.now(), log = console }) {
        this.gmail = gmail; this.store = store; this.now = now; this.log = log;
        this.mem = new Map(); this.inFlight = new Map();
    }
    // { received: about how many earlier emails, ageDays: 0 | 1 | 30 | 365 (the oldest found is over that old), wrote: bool,
    //   at } or null (couldn't tell). key: the sender's hash (pipeline.js senderHash).
    async of(user, address, key) {
        if (!this.gmail || typeof this.gmail.searchCount !== 'function' || !address || !key) return null;
        const m = this.mem.get(key);
        if (m && this.now() - m.memAt < MEM_MS) return m.value;
        if (this.inFlight.has(key)) return this.inFlight.get(key);
        const p = (async () => {
            let v = await this.store.getCached('mbhist', key).catch(() => null);
            if (!v) {
                v = await this.lookup(user, address).catch((e) => { this.log.warn && this.log.warn(JSON.stringify({ message: `Gmail history lookup: ${String(e && e.message || e).slice(0, 200)}` })); return null; });
                if (v) await this.store.setCached('mbhist', key, v, v.received || v.wrote ? KNOWN_MS : UNKNOWN_MS).catch(() => {});
            }
            if (v) { this.mem.set(key, { value: v, memAt: this.now() }); if (this.mem.size > MEM_MAX) this.mem.delete(this.mem.keys().next().value); }
            return v;
        })().finally(() => this.inFlight.delete(key));
        this.inFlight.set(key, p);
        return p;
    }
    async lookup(user, address) {
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
            return { received: day.any ? Math.max(1, day.estimate) : 0, ageDays, wrote: !!wrote.any, at: this.now() };
        })();
        return Promise.race([run, late]);
    }
}

// The history the AI is given from it (context-facts.js historyOf's shape), or null.
function historyFromGmail(h) {
    if (!h) return null;
    if (!h.received && !h.wrote) return { first: true };
    return { days: h.ageDays || 0, emails: h.received || 0 };
}

module.exports = { MailboxHistory, historyFromGmail, KNOWN_MS, UNKNOWN_MS };
