'use strict';
// (0.6.77) How long each step of checking an email takes, and where each lookup's answer came from, on this instance:
// Today's re-check card shows the slowest steps of the last run (pipeline.js runRechecks), so a slow re-check says where
// its time went. Step names are plain words; nothing about any email is kept (no address, no domain), only counts and
// milliseconds. The counts are the instance's, so mail arriving while re-checks run is counted too.
const steps = new Map();   // name → { n, ms, maxMs, memory, store, network }

// One step done: how long it took, and (for a lookup) where its answer came from: 'memory', 'store' or 'network'.
function note(name, ms, from = null) {
    const s = steps.get(name) || { n: 0, ms: 0, maxMs: 0, memory: 0, store: 0, network: 0 };
    s.n++; s.ms += ms; s.maxMs = Math.max(s.maxMs, ms);
    if (from && from in s) s[from]++;
    steps.set(name, s);
}
// fn timed as one step (its answer returned; an error is still timed, then thrown).
async function timed(name, fn) {
    const t0 = Date.now();
    try { return await fn(); } finally { note(name, Date.now() - t0); }
}
const snapshot = () => new Map([...steps].map(([k, v]) => [k, Object.assign({}, v)]));
// What happened since a snapshot: [{ step, n, avgMs, totalMs, maxMs, memory, store, network }], the most time first.
// (maxMs is the instance's largest so far, not only since the snapshot.)
function since(snap, max = 8) {
    const out = [];
    for (const [k, v] of steps) {
        const b = (snap && snap.get(k)) || { n: 0, ms: 0, memory: 0, store: 0, network: 0 };
        const n = v.n - b.n;
        if (n <= 0) continue;
        out.push({ step: k, n, totalMs: v.ms - b.ms, avgMs: Math.round((v.ms - b.ms) / n), maxMs: v.maxMs, memory: v.memory - b.memory, store: v.store - b.store, network: v.network - b.network });
    }
    return out.sort((a, b) => b.totalMs - a.totalMs).slice(0, max);
}
const reset = () => steps.clear();

module.exports = { note, timed, snapshot, since, reset };
