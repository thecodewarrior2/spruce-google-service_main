'use strict';
// (0.6.48) The domains public records proved a company's (src/intel/ownership.js), kept for every instance: the link
// checks' company index (vendor/spruce/shared.js learnCompanyDomains) instead of a hand-kept list. In the shared store
// (state provenDomains: domain → { name, state, at }), each entry for KEEP_MS after it was last proven (the ownership
// answers themselves are refreshed after 50 days); read at start and every RELOAD_MS, so what one instance proves the
// others use too. At most MAX entries, the oldest dropped.
const KEEP_MS = 60 * 24 * 60 * 60 * 1000, RELOAD_MS = 30 * 60 * 1000, WRITE_AFTER_MS = 5000, MAX = 5000;

function createCompanyIndex({ store, engine: E, now = () => Date.now(), log = console }) {
    let pending = new Map(), timer = null;
    const fresh = (all) => Object.entries(all || {}).filter(([, v]) => v && v.name && now() - (Number(v.at) || 0) < KEEP_MS);
    async function load() {
        const all = (await store.getState('provenDomains').catch(() => null)) || {};
        const list = fresh(all).map(([domain, v]) => ({ domain, name: v.name, state: v.state }));
        E.learnCompanyDomains(list.concat([...pending.entries()].map(([domain, v]) => ({ domain, name: v.name, state: v.state }))), true);
        return list.length;
    }
    async function write() {
        timer = null;
        const add = pending;
        pending = new Map();
        try {
            const all = Object.fromEntries(fresh((await store.getState('provenDomains')) || {}));
            for (const [d, v] of add) if (!all[d] || all[d].state !== 'owned' || v.state === 'owned') all[d] = v;
            const keys = Object.keys(all).sort((a, b) => (all[b].at || 0) - (all[a].at || 0));
            for (const k of keys.slice(MAX)) delete all[k];
            await store.setState('provenDomains', all);
        } catch (e) { log.error('proven domains:', e); for (const [d, v] of add) if (!pending.has(d)) pending.set(d, v); }
    }
    // A domain proven (or likely) the company's: in the index now, in the store shortly (one write for many).
    function learn(domain, name, state) {
        E.learnCompanyDomains([{ domain, name, state }]);
        const had = pending.get(domain);
        if (!had || had.state !== 'owned' || state === 'owned') pending.set(domain, { name, state, at: now() });
        if (!timer) { timer = setTimeout(() => { write(); }, WRITE_AFTER_MS); if (timer.unref) timer.unref(); }
    }
    function start() {
        load().catch(e => log.error('proven domains:', e));
        const t = setInterval(() => load().catch(() => {}), RELOAD_MS);
        if (t.unref) t.unref();
    }
    return { learn, load, write, start };
}

module.exports = { createCompanyIndex };
