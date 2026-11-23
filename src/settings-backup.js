'use strict';
// (0.6.72) Settings → Backup: every setting an admin saved on the dashboard, in one file to keep or to move to another
// installation, and an import that puts it back. What is in it (SECTIONS): the policy (with Trusted senders and the
// allowed link domains), the Sender lists (Spam senders and the ones taken off it, Brand senders, Company domains,
// proven companies, Promotional senders kept, spam people took back), the remembered answers, the phishing-training
// rules, the admins' marks on look-alikes, and the switches (weekly summary, Link clicks, User reports, the retraining
// export). Not in it: what the service found and did (the emails' records, Activity, the statistics, the queues, the
// brakes, mailbox watches), deploy/settings.env (the installation's own file, kept by install.sh) and the AI model.
//
// The API keys (Safe Browsing, Spamhaus, abuse.ch) are in it only when the admin ticks it, and then only encrypted with
// a passphrase they type (AES-256-GCM, the key from scrypt): the file never holds a key in the clear, the passphrase is
// never kept, and without it the keys can't be read (everything else still imports).
//
// An import is checked first (preview: what each section would change), then applied section by section as the admin
// ticks them. Each section becomes what the file holds. The policy goes through the Policy page's own checks
// (pipeline.js setPolicy), and a change that page asks the admin to agree to (enforce mode, the AI alone moving staff
// email, Skip review, who is checked, where updates and the model come from) is never made by an import: it is listed,
// to be made on its page.
const crypto = require('crypto');

const FORMAT = 'spruce-settings';
const FORMAT_VERSION = 1;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_ENTRIES = 50000;
const STATE_MAX_BYTES = 900 * 1024;           // one Firestore document holds 1 MiB
const PASSPHRASE_MIN = 12;
const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

// The sections, in the order the page shows them. states: the state documents a section is made of (maps of entries).
const SECTIONS = [
    { id: 'policy', label: 'Policy', what: 'the mode, the AI lines, the optional services on or off, Trusted senders, the allowed link domains, how long records are kept, Skip review, who is checked, where updates come from' },
    { id: 'senders', label: 'Sender lists', what: 'Spam senders (and the ones taken off it), Brand senders, Company domains, proven companies, Promotional senders kept, spam people took back',
        states: ['spamSenders', 'spamSendersRemoved', 'brandSenders', 'confirmedDomains', 'provenDomains', 'promoKept', 'spamRescued'] },
    { id: 'remembered', label: 'Remembered answers', what: 'the answers kept for the same email sent again', states: ['rememberedSafe'] },
    { id: 'phishTraining', label: 'Phishing training', what: 'the rules that recognize your phishing-training emails, and their link domains', states: ['phishTraining'] },
    { id: 'lookalikes', label: 'Look-alike marks', what: 'the look-alikes of your domain an admin marked (yours, harmless, a threat)' },
    { id: 'switches', label: 'Switches', what: 'the weekly summary, Link clicks, User reports, the retraining export' },
    { id: 'keys', label: 'API keys', what: 'the Safe Browsing, Spamhaus and abuse.ch keys, encrypted with your passphrase' }
];
const SECTION_IDS = SECTIONS.map(s => s.id);
const KEY_IDS = ['safeBrowsing', 'spamhaus', 'abusech'];
const KEY_LABELS = { safeBrowsing: 'Google Safe Browsing', spamhaus: 'Spamhaus', abusech: 'abuse.ch' };
const SWITCHES = ['digest', 'clickLogs', 'userReports', 'trainingExport'];
const SWITCH_LABELS = { digest: 'Weekly summary email', clickLogs: 'Link clicks', userReports: 'User reports', trainingExport: 'Retraining export' };

// The policy changes an import never makes: the Policy page asks for an agreement (or the admin's own address) first.
// Each: (file's value, current value) → why it waits, or null when the change may be made.
const GATED = {
    mode: (v, cur) => (v === 'enforce' && cur !== 'enforce' ? 'switching to enforce mode is agreed to on the Policy page' : null),
    aiMovesInside: (v, cur) => (v === true && cur !== true ? 'letting the AI alone move staff email is agreed to on the Policy page' : null),
    strictSpam: (v, cur) => ((Array.isArray(v) ? v : []).some(k => !(cur || []).includes(k)) ? 'Skip review (mail sent to Spam without review) is agreed to on the Policy page' : null),
    watchScope: (v, cur) => (v !== cur ? 'who is checked is confirmed with your own address on the Policy page' : null),
    releasesRepo: (v, cur) => (v !== cur ? 'where updates come from is confirmed with your own address on Settings → Update' : null),
    modelRepo: (v, cur) => (v !== cur ? 'where the AI model comes from is confirmed with your own address on Settings → Update' : null)
};

const isMap = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const same = (a, b) => JSON.stringify(a === undefined ? null : a) === JSON.stringify(b === undefined ? null : b);

// --- The keys' encryption ------------------------------------------------------------------------------------------
function encryptKeys(keys, passphrase) {
    if (String(passphrase || '').length < PASSPHRASE_MIN) throw Object.assign(new Error(`The passphrase needs at least ${PASSPHRASE_MIN} characters.`), { status: 400 });
    const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
    const key = crypto.scryptSync(String(passphrase), salt, 32, SCRYPT);
    const c = crypto.createCipheriv('aes-256-gcm', key, iv);
    c.setAAD(Buffer.from(`${FORMAT}/${FORMAT_VERSION}/keys`));
    const data = Buffer.concat([c.update(JSON.stringify(keys), 'utf8'), c.final()]);
    return { cipher: 'aes-256-gcm', kdf: 'scrypt', N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, salt: salt.toString('base64'), iv: iv.toString('base64'),
        tag: c.getAuthTag().toString('base64'), data: data.toString('base64'), names: Object.keys(keys) };
}
function decryptKeys(box, passphrase) {
    if (!box || box.cipher !== 'aes-256-gcm' || box.kdf !== 'scrypt') throw Object.assign(new Error('The file\'s keys are in a form this version can\'t read.'), { status: 400 });
    const N = Number(box.N), r = Number(box.r), p = Number(box.p);
    if (![1 << 14, 1 << 15, 1 << 16, 1 << 17].includes(N) || r !== 8 || p !== 1) throw Object.assign(new Error('The file\'s keys are in a form this version can\'t read.'), { status: 400 });
    try {
        const key = crypto.scryptSync(String(passphrase || ''), Buffer.from(box.salt, 'base64'), 32, { N, r, p, maxmem: 256 * 1024 * 1024 });
        const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(box.iv, 'base64'));
        d.setAAD(Buffer.from(`${FORMAT}/${FORMAT_VERSION}/keys`));
        d.setAuthTag(Buffer.from(box.tag, 'base64'));
        const out = JSON.parse(Buffer.concat([d.update(Buffer.from(box.data, 'base64')), d.final()]).toString('utf8'));
        if (!isMap(out)) throw new Error('not a map');
        return Object.fromEntries(Object.entries(out).filter(([k, v]) => KEY_IDS.includes(k) && typeof v === 'string' && v.length <= 400));
    } catch (e) {
        throw Object.assign(new Error('That passphrase doesn\'t open the file\'s keys (or the file was changed).'), { status: 400 });
    }
}

// --- Export --------------------------------------------------------------------------------------------------------
// keys: { safeBrowsing, spamhaus, abusech } → the key object (src/intel: get()) or null.
async function exportSettings({ service, store, cfg, keys = {}, by, includeKeys = false, passphrase = '', version = '', now = Date.now() }) {
    const policyKeys = service.policyKeys ? service.policyKeys() : [];
    if (service.refreshPolicy) await service.refreshPolicy({ force: true });
    const policy = Object.fromEntries(policyKeys.map(k => [k, cfg[k] === undefined ? null : cfg[k]]));
    const sections = { policy };
    for (const s of SECTIONS) if (s.states) {
        sections[s.id] = {};
        for (const name of s.states) sections[s.id][name] = (await store.getState(name)) || {};
    }
    const watch = (await store.getState('lookalikeWatch')) || {};
    sections.lookalikes = Object.fromEntries(Object.entries(watch.found || {}).filter(([, e]) => e && ['ours', 'harmless', 'threat'].includes(e.status))
        .map(([d, e]) => [d, { domain: e.domain || d, status: e.status, by: e.by || '', at: e.at || null, firstStatus: e.firstStatus || null }]));
    const sw = {};
    const digest = (await store.getState('digest')) || {};
    sw.digest = { on: !!digest.enabled };
    sw.clickLogs = { on: !!((await store.getState('clickLogs')) || {}).on };
    sw.userReports = { on: !!((await store.getState('userReports')) || {}).on };
    sw.trainingExport = { on: !!((await store.getState('trainingExport')) || {}).enabled };
    sections.switches = sw;
    let keysOut = null;
    if (includeKeys) {
        const plain = {};
        for (const id of KEY_IDS) { const k = keys[id]; const v = k ? await k.get().catch(() => null) : null; if (v) plain[id] = v; }
        keysOut = encryptKeys(plain, passphrase);
    }
    return { format: FORMAT, formatVersion: FORMAT_VERSION, version, exportedAt: new Date(now).toISOString(), exportedBy: by, orgDomains: cfg.orgDomains || [],
        note: 'S.P.R.U.C.E Mail Protection Service settings (Settings → Backup). It holds the district\'s settings and Sender lists: keep it as you would the dashboard itself.'
            + (keysOut ? ' The API keys in it are encrypted with the passphrase typed when it was made.' : ' It holds no API keys.'),
        sections, keys: keysOut };
}

// --- Reading a file -----------------------------------------------------------------------------------------------
// The file's text → its contents, checked: the format, every section's shape and size. Throws { status: 400 } with why.
function parseFile(text) {
    const bad = (why) => Object.assign(new Error(why), { status: 400 });
    if (typeof text !== 'string' || !text.trim()) throw bad('Choose a settings file (Settings → Backup → Export makes one).');
    if (Buffer.byteLength(text) > MAX_FILE_BYTES) throw bad('That file is over 8 MB: it isn\'t a settings file.');
    let f;
    try { f = JSON.parse(text); } catch (e) { throw bad('That file isn\'t a settings file (it isn\'t JSON).'); }
    if (!isMap(f) || f.format !== FORMAT) throw bad('That file isn\'t a settings file of this service.');
    if (f.formatVersion !== FORMAT_VERSION) throw bad(`That settings file is of a newer kind (${f.formatVersion}): update this service first.`);
    const s = f.sections;
    if (!isMap(s)) throw bad('The file has no settings in it.');
    if (s.policy !== undefined && !isMap(s.policy)) throw bad('The file\'s policy isn\'t readable.');
    for (const sec of SECTIONS) if (sec.states && s[sec.id] !== undefined) {
        if (!isMap(s[sec.id])) throw bad(`The file's ${sec.label} aren't readable.`);
        for (const name of Object.keys(s[sec.id])) {
            if (!sec.states.includes(name)) throw bad(`The file's ${sec.label} hold something this version doesn't know (${String(name).slice(0, 40)}).`);
            const m = s[sec.id][name];
            if (!isMap(m)) throw bad(`The file's ${sec.label} (${name}) aren't readable.`);
            const n = Object.keys(m).length;
            if (n > MAX_ENTRIES) throw bad(`The file's ${sec.label} (${name}) have ${n} entries: more than this service keeps.`);
            if (name !== 'phishTraining' && Object.entries(m).some(([k, v]) => k.length > 400 || !isMap(v))) throw bad(`The file's ${sec.label} (${name}) aren't readable.`);
            if (Buffer.byteLength(JSON.stringify(m)) > STATE_MAX_BYTES) throw bad(`The file's ${sec.label} (${name}) are too big to save.`);
        }
    }
    const pt = s.phishTraining && s.phishTraining.phishTraining;
    if (pt && Object.keys(pt).length) {
        if (!Array.isArray(pt.rules || []) || (pt.rules || []).length > 50 || !(pt.rules || []).every(r => isMap(r) && typeof r.id === 'string' && typeof r.name === 'string')) throw bad('The file\'s phishing-training rules aren\'t readable.');
        if (!Array.isArray(pt.domains || []) || (pt.domains || []).length > 500 || !(pt.domains || []).every(d => typeof d === 'string' && d.length <= 253)) throw bad('The file\'s phishing-training domains aren\'t readable.');
    }
    if (s.lookalikes !== undefined && (!isMap(s.lookalikes) || Object.values(s.lookalikes).some(e => !isMap(e) || !['ours', 'harmless', 'threat'].includes(e.status)))) throw bad('The file\'s look-alike marks aren\'t readable.');
    if (s.switches !== undefined && (!isMap(s.switches) || Object.keys(s.switches).some(k => !SWITCHES.includes(k)))) throw bad('The file\'s switches aren\'t readable.');
    if (f.keys !== null && f.keys !== undefined && (!isMap(f.keys) || typeof f.keys.data !== 'string')) throw bad('The file\'s keys aren\'t readable.');
    return f;
}

// --- Preview: what each section would change -----------------------------------------------------------------------
async function previewImport(f, { service, store, cfg, now = Date.now() }) {
    const s = f.sections, out = [];
    if (service.refreshPolicy) await service.refreshPolicy({ force: true });
    if (s.policy) {
        const changes = [], waits = [], unknown = [];
        const known = service.policyKeys ? service.policyKeys() : [];
        for (const [k, v] of Object.entries(s.policy)) {
            if (!known.includes(k)) { unknown.push(k); continue; }
            if (same(cfg[k], v)) continue;
            const why = GATED[k] && GATED[k](v, cfg[k]);
            (why ? waits : changes).push({ key: k, from: cfg[k], to: v, why: why || undefined });
        }
        out.push({ id: 'policy', label: 'Policy', changes, waits, unknown, changed: changes.length > 0 });
    }
    for (const sec of SECTIONS) if (sec.states && s[sec.id]) {
        const parts = [];
        for (const name of sec.states) {
            if (!(name in s[sec.id])) continue;
            const cur = (await store.getState(name)) || {}, next = s[sec.id][name];
            const added = Object.keys(next).filter(k => !(k in cur)).length, removed = Object.keys(cur).filter(k => !(k in next)).length;
            const changed = Object.keys(next).filter(k => k in cur && !same(cur[k], next[k])).length;
            parts.push(Object.assign({ name, entries: Object.keys(next).length, added, removed, changed },
                name === 'phishTraining' ? { rules: (next.rules || []).length, domains: (next.domains || []).length, added: 0, removed: 0, changed: same(cur.rules || [], next.rules || []) && same(cur.domains || [], next.domains || []) ? 0 : 1 } : {}));
        }
        out.push({ id: sec.id, label: sec.label, parts, changed: parts.some(p => p.added || p.removed || p.changed) });
    }
    if (s.lookalikes) {
        const found = (((await store.getState('lookalikeWatch')) || {}).found) || {};
        const marks = Object.values(s.lookalikes).map(e => ({ domain: String(e.domain || '').toLowerCase(), status: e.status, from: (found[String(e.domain || '').toLowerCase()] || {}).status || null }))
            .filter(m => m.domain && m.from !== m.status);
        out.push({ id: 'lookalikes', label: 'Look-alike marks', marks, changed: marks.length > 0 });
    }
    if (s.switches) {
        const cur = {
            digest: !!((await store.getState('digest')) || {}).enabled, clickLogs: !!((await store.getState('clickLogs')) || {}).on,
            userReports: !!((await store.getState('userReports')) || {}).on, trainingExport: !!((await store.getState('trainingExport')) || {}).enabled
        };
        const changes = Object.entries(s.switches).filter(([k, v]) => isMap(v) && !!v.on !== cur[k]).map(([k, v]) => ({ key: k, label: SWITCH_LABELS[k], to: !!v.on }));
        out.push({ id: 'switches', label: 'Switches', changes, changed: changes.length > 0 });
    }
    if (f.keys) out.push({ id: 'keys', label: 'API keys', names: (f.keys.names || []).filter(n => KEY_IDS.includes(n)).map(n => KEY_LABELS[n]), changed: true, needsPassphrase: true });
    return { version: f.version || '', exportedAt: f.exportedAt || null, exportedBy: f.exportedBy || '', orgDomains: Array.isArray(f.orgDomains) ? f.orgDomains : [],
        otherDistrict: Array.isArray(f.orgDomains) && f.orgDomains.length > 0 && !f.orgDomains.some(d => (cfg.orgDomains || []).includes(d)), sections: out };
}

// --- Apply ---------------------------------------------------------------------------------------------------------
// sections: the ids the admin ticked. keys: as for exportSettings, with save(value, by). Returns what was done, section by
// section; a section that fails says why and the others still apply.
async function applyImport(f, { service, store, cfg, keys = {}, by, sections = [], passphrase = '', now = Date.now() }) {
    const s = f.sections, done = [], who = `${by} (import)`;
    const want = (id) => sections.includes(id);
    const step = async (id, fn) => { try { done.push(Object.assign({ id }, await fn())); } catch (e) { done.push({ id, error: String((e && e.message) || e).slice(0, 300) }); } };
    // Keys first: Safe Browsing, Spamhaus and abuse.ch can be turned on by the policy only with a key saved.
    if (want('keys') && f.keys) await step('keys', async () => {
        const plain = decryptKeys(f.keys, passphrase);
        const saved = [], failed = [];
        for (const [id, v] of Object.entries(plain)) {
            const k = keys[id];
            if (!k || !k.save) { failed.push(`${KEY_LABELS[id]}: not available here`); continue; }
            try { await k.save(v, who); saved.push(KEY_LABELS[id]); } catch (e) { failed.push(`${KEY_LABELS[id]}: ${String(e.message || e).slice(0, 160)}`); }
        }
        return { saved, failed };
    });
    if (want('policy') && s.policy) await step('policy', async () => {
        await service.refreshPolicy({ force: true });
        const known = service.policyKeys(), changed = [], waits = [], failed = [];
        for (const [k, v] of Object.entries(s.policy)) {
            if (!known.includes(k) || same(cfg[k], v)) continue;
            const why = GATED[k] && GATED[k](v, cfg[k]);
            if (why) { waits.push({ key: k, why }); continue; }
            if (KEY_IDS.includes(k) && v === true) {
                const key = keys[k];
                if (!(key && await key.get().catch(() => null))) { waits.push({ key: k, why: `turning ${KEY_LABELS[k]} on needs its key saved first` }); continue; }
            }
            try { const r = await service.setPolicy(k, v, who); if (!r.unchanged) changed.push(k); } catch (e) { failed.push(`${k}: ${String(e.message || e).slice(0, 160)}`); }
        }
        return { changed, waits, failed };
    });
    for (const sec of SECTIONS) if (sec.states && want(sec.id) && s[sec.id]) await step(sec.id, async () => {
        const written = [];
        for (const name of sec.states) if (name in s[sec.id]) { await store.setState(name, s[sec.id][name]); written.push(name); }
        return { written };
    });
    if (want('lookalikes') && s.lookalikes) await step('lookalikes', async () => {
        const w = (await store.getState('lookalikeWatch')) || {};
        w.found = w.found || {};
        let marked = 0;
        for (const e of Object.values(s.lookalikes)) {
            const d = String(e.domain || '').toLowerCase();
            if (!d || d.length > 253) continue;
            const cur = w.found[d];
            if (cur && cur.status === e.status) continue;
            // (a domain this installation's watch hasn't found: kept with the mark, as the watch would keep it)
            w.found[d] = Object.assign({}, cur || { domain: d, first: now, firstStatus: 'baseline' }, { status: e.status, by: who, at: now });
            marked++;
        }
        if (marked) { await store.setState('lookalikeWatch', w); service.lookalikeCache = null; }
        return { marked };
    });
    if (want('switches') && s.switches) await step('switches', async () => {
        const turned = [], failed = [];
        const set = { digest: (on) => service.setDigest(on, who), clickLogs: (on) => service.setClickLogs(on, who), userReports: (on) => service.setUserReports(on, who), trainingExport: (on) => service.setTrainingExport(on, who) };
        const cur = { digest: !!((await store.getState('digest')) || {}).enabled, clickLogs: !!((await store.getState('clickLogs')) || {}).on,
            userReports: !!((await store.getState('userReports')) || {}).on, trainingExport: !!((await store.getState('trainingExport')) || {}).enabled };
        for (const [k, v] of Object.entries(s.switches)) {
            if (!isMap(v) || !!v.on === cur[k] || !set[k]) continue;
            const r = await set[k](!!v.on);
            if (r && r.error) failed.push(`${SWITCH_LABELS[k]}: ${r.error}`); else turned.push(`${SWITCH_LABELS[k]} ${v.on ? 'on' : 'off'}`);
        }
        return { turned, failed };
    });
    if (service.forgetSettingsCaches) service.forgetSettingsCaches();
    return { done };
}

module.exports = { FORMAT, FORMAT_VERSION, SECTIONS, SECTION_IDS, KEY_IDS, PASSPHRASE_MIN, MAX_FILE_BYTES, GATED, encryptKeys, decryptKeys, exportSettings, parseFile, previewImport, applyImport };
