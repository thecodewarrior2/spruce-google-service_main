'use strict';
// 0.6.55: the AI's spam answer (phish-tiny 0.26.0 on: output spam_logits). Spam is a business's bulk marketing, wanted or
// not (an email can't show whether its reader signed up). From a sender Gmail couldn't confirm (DMARC), with nothing else
// suspicious, an answer at or over the move line is moved as spam by the spam rules; from a confirmed sender it is never
// moved for that, only listed in Review → Promotional. Every sender, address and email here is made up.
const test = require('node:test');
const assert = require('node:assert');
const { loadConfig } = require('../src/config');
const { Service } = require('../src/pipeline');
const { MemoryStore } = require('../src/store/memory');
const { readMessage } = require('../src/engine/mime');
const { decide, aiSpamOf } = require('../src/policy');
const { aiMarketingSign } = require('../src/promotional');
const { Model, spamOf } = require('../src/engine/model');
const E = require('../src/engine/spruce').load();

const ORG = 'maple-schools.example';
const PAT = `pat.fakewell@${ORG}`;
const cfg = (extra = {}) => loadConfig(Object.assign({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: PAT, MODE: 'enforce' }, extra));
const result = (over = {}) => Object.assign({ status: 'clean', score: 0, inside: false, verified: false, ai: { probability: 0.02, spam: 0.97, model: 'phish-tiny test' } }, over);

test('the policy: the AI\'s spam answer moves unverified outside mail as spam, nothing else', () => {
    const c = cfg();
    const d = decide(result(), c);
    assert.deepEqual([d.action, d.trigger], ['move', 'spam']);
    assert.match(d.why, /^spam: the AI was 97% sure it is spam \(bulk marketing; moved from 90%\), Gmail couldn't confirm the sender/);
    assert.equal(decide(result(), cfg({ MODE: 'monitor' })).action, 'would-move', 'monitor mode: nothing moved');
    assert.equal(decide(result(), c, { brake: true }).action, 'would-move', 'the brake');
    assert.equal(decide(result({ verified: true }), c).action, 'none', 'a confirmed sender: never moved for this (Review → Promotional instead)');
    assert.equal(decide(result({ inside: true }), c).action, 'none', 'never from inside');
    assert.equal(decide(result({ ai: { probability: 0.02, spam: 0.85 } }), c).action, 'none', 'under the move line');
    assert.equal(decide(result({ ai: { probability: 0.02, spam: null } }), c).action, 'none', 'a model without a spam answer');
    assert.equal(decide(result({ status: 'caution', score: 3 }), c).action, 'flag', 'something else suspicious: judged as before, not as spam');
    assert.equal(aiSpamOf(result({ ai: { probability: 0.7, spam: 0.95 } }), c), null, 'the phishing answer over the suspicious line');
    assert.equal(decide(result(), cfg({ MOVE_ON_RULES: 'off' })).action, 'none', 'the spam rules\' switch (MOVE_ON_RULES)');
    const phish = decide(result({ ai: { probability: 0.97, spam: 0.02 } }), c);
    assert.deepEqual([phish.action, phish.trigger], ['move', 'ai'], 'phishing stays phishing');
});

test('a confirmed sender\'s marketing is a promotional sign, under the same line', () => {
    const c = cfg();
    assert.equal(aiMarketingSign({ probability: 0.01, spam: 0.96 }, c), 'the AI read it as a business\'s bulk marketing (96% spam)');
    assert.equal(aiMarketingSign({ probability: 0.01, spam: 0.5 }, c), '');
    assert.equal(aiMarketingSign({ probability: 0.8, spam: 0.19 }, c), '');
    assert.equal(aiMarketingSign({ probability: 0.01, spam: null }, c), '');
});

test('the model runner reads spam_logits when the model has a spam answer', async () => {
    const ort = (out) => ({ Tensor: class { constructor(type, data, dims) { Object.assign(this, { type, data, dims }); } },
        InferenceSession: { create: async () => ({ run: async (feeds) => { const B = feeds.input_ids.dims[0]; const rep = (a) => ({ data: Float32Array.from({ length: B * 2 }, (_, i) => a[i % 2]) }); return Object.fromEntries(Object.entries(out).map(([k, v]) => [k, rep(v)])); } }) } });
    const base = { name: 'phish-tiny', version: 'test', config: { maxLen: 16, headTokens: 0 } };
    const opts = { file: 'model.onnx', tokenizer: { encode: () => [101, 2000, 102] }, modelInputParts: () => ({ head: 'subject: sale.', sentences: ['Thirty percent off this weekend.'] }) };
    const withSpam = new Model(Object.assign({}, opts, { manifest: Object.assign({ spam: { output: 'spam_logits' } }, base), ort: ort({ logits: [0, -3], spam_logits: [0, 3] }) }));
    const r = await withSpam.analyze({});
    const p = 1 / (1 + Math.exp(3)), s = (1 - p) / (1 + Math.exp(-3));
    assert.ok(Math.abs(r.probability - p) < 1e-6 && Math.abs(r.spam - s) < 1e-6, `${r.probability} ${r.spam}`);
    assert.ok(Math.abs(r.spam - spamOf(p, 3)) < 1e-12);
    assert.equal((await withSpam.analyze({})).spam, r.spam, 'remembered with the phishing answer');
    assert.equal((await withSpam.reading({ bodyText: 'Thirty percent off this weekend.' })).spam, r.spam, 'the "show more" reading says it too');
    const older = new Model(Object.assign({}, opts, { manifest: base, ort: ort({ logits: [0, -3] }) }));
    assert.equal((await older.analyze({})).spam, null, 'an older model: no spam answer');
});

// The whole pipeline, with the engine's model answering as a spam-answer model would.
const raw = (to, { from = 'offers@deals-blast.example', dmarc = 'none', n }) => Buffer.from([
    `From: "Madeup Savings Club" <${from}>`, `To: ${to}`, `Subject: Weekend savings, part ${n}`, `Message-ID: <s${n}@deals-blast.example>`,
    `Authentication-Results: mx.google.com; spf=${dmarc === 'pass' ? 'pass' : 'none'}; dkim=${dmarc === 'pass' ? 'pass' : 'none'}; dmarc=${dmarc} header.from=${from.split('@')[1]}`,
    'Content-Type: text/plain', '', 'Thirty percent off headphones this weekend. Shop the sale on our site.'].join('\r\n'));
test('the pipeline: unverified marketing moved as spam; a confirmed company\'s listed in Review → Promotional', async (t) => {
    const was = E.model.analyze;
    E.model.analyze = async () => ({ probability: 0.02, spam: 0.97, reasons: [], model: 'phish-tiny', version: 'test' });
    t.after(() => { E.model.analyze = was; });
    let n = 0;
    const make = (mode) => {
        const modified = [];
        const svc = new Service({ cfg: cfg({ MODE: mode }), store: new MemoryStore(),
            gmail: { labelId: async (u, nm) => `L_${nm}`, labels: async () => ['INBOX'], modify: async (u, id, add) => { modified.push({ add }); return {}; } }, log: { error() {}, warn() {} } });
        svc.modified = modified;
        return svc;
    };
    const judge = async (svc, opts = {}) => { n++; return svc.judge(PAT, { id: `m${n}`, threadId: `t${n}`, internalDate: Date.now(), labelIds: ['INBOX'] }, await readMessage(raw(PAT, Object.assign({ n }, opts)))); };
    const svc = make('enforce');
    const moved = await judge(svc);
    assert.deepEqual([moved.action, moved.trigger], ['move', 'spam'], moved.why);
    const rec = await svc.store.getRecord(moved.key);
    assert.equal(rec.ai.spam, 0.97, 'kept on the record (the dashboard shows it)');
    assert.ok(svc.modified.some(m => m.add.includes('SPAM')));
    const monitor = make('monitor');
    assert.equal((await judge(monitor)).action, 'would-move');
    const confirmed = await judge(make('enforce'), { from: 'news@bigstore.example', dmarc: 'pass' });
    assert.deepEqual([confirmed.action, confirmed.trigger], ['promo', 'promotional'], confirmed.why);
    assert.match(confirmed.why, /the AI read it as a business's bulk marketing \(97% spam\)/);
});
