'use strict';
// (0.6.68) Which of Review's queues each recorded email belongs to: one place, in one order, so an email is in exactly one
// queue (or none) by construction, and every reader (Review's tabs, the pending count, the browser tab's title, an answer
// that also answers other waiting emails) agrees. Before, each queue was its own filter, kept apart by excluding the others
// by hand, with copies in pipeline.js that drifted.
//
// The order (the first that applies wins):
//   1. answered by an admin or a moderator (markedBy)                                   → none
//   2. reported by its reader with Gmail's Report phishing (Settings → User reports)     → 'reported'
//      (even from a sender on a Sender list: a trusted sender's account can be taken over)
//   3. from a sender on a Sender list (Trusted, Spam or Brand senders: listed())         → none
//   4. moved, or would be moved, by the checks (not a copy an admin's search found)      → 'moved'
//   5. suspicious, still in the Inbox (not a rules-only flag from a sender Gmail confirmed: policy.js rulesOnlyVerified)
//                                                                                        → 'suspicious'
//   6. promotional, still in the Inbox, its company not kept                             → 'promotional'
// Then, within the records being listed together, a suspicious copy of a campaign that has a moved copy is in 'moved' too:
// one email, one tab, so one answer covers every copy (0.6.39).
const { rulesOnlyVerified } = require('./policy');

const QUEUES = ['moved', 'suspicious', 'promotional', 'reported'];

// One record's own queue (steps 1-6), or null. listed: the Sender lists' test (pipeline.js senderListTest), or none.
function baseQueueOf(r, { cfg = {}, listed = null } = {}) {
    if (!r || r.markedBy) return null;
    if (r.userReported) return 'reported';
    if (listed && listed(r)) return null;
    if ((r.action === 'move' || r.action === 'would-move') && r.trigger !== 'admin') return 'moved';
    if (r.action === 'flag' && r.state === 'inbox') return rulesOnlyVerified(r, cfg) ? null : 'suspicious';
    if (r.action === 'promo' && r.state === 'inbox' && !r.promoKept) return 'promotional';
    return null;
}

// The queues of records listed together: { moved, suspicious, promotional, reported } (arrays in the records' order) and
// of (key → queue). base: a Map record → base queue shared between calls over the same records (the pending count
// classifies the dashboard's period and the last 90 days: each record is classified once).
function queuesOf(records, { cfg = {}, listed = null, base = null } = {}) {
    const memo = base || new Map();
    const own = (r) => { if (!memo.has(r)) memo.set(r, baseQueueOf(r, { cfg, listed })); return memo.get(r); };
    const movedCampaigns = new Set();
    for (const r of records) if (own(r) === 'moved' && r.campaign) movedCampaigns.add(r.campaign);
    const out = { moved: [], suspicious: [], promotional: [], reported: [], of: new Map() };
    for (const r of records) {
        let q = own(r);
        if (q === 'suspicious' && r.campaign && movedCampaigns.has(r.campaign)) q = 'moved';
        if (!q) continue;
        out[q].push(r);
        out.of.set(r.key, q);
    }
    return out;
}

// Whether an email is still waiting for an answer at all (nobody answered it, its reader didn't report it): what an answer
// that also answers other waiting emails (a Spam answer for the same address, a company's Promotional answer) may touch.
// A reported email waits in Review → Reported, for an answer of its own.
const waitingForAnswer = (r) => !!r && !r.markedBy && !r.userReported;

module.exports = { QUEUES, baseQueueOf, queuesOf, waitingForAnswer };
