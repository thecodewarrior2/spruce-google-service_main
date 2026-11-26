'use strict';
// 0.6.52: Promotional mail (src/promotional.js): Gmail's Promotions category, or a one-click unsubscribe the sender signed,
// from a verified outside sender the checks found nothing in. Never moved for that: listed in Review → Promotional, where
// an admin answers once per company (Spam, or Keep). Every sender, address and email here is made up.
const test = require('node:test');
const assert = require('node:assert');
const { loadConfig } = require('../src/config');
const { Service } = require('../src/pipeline');
const { MemoryStore } = require('../src/store/memory');
const { readMessage } = require('../src/engine/mime');
const { promotionalSigns, oneClickSigned } = require('../src/promotional');

const ORG = 'maple-schools.example';
const [PAT, SAM] = ['pat.fakewell', 'sam.testwood'].map(u => `${u}@${ORG}`);
const ADMIN = `it.madeup@${ORG}`;
let n = 0;
// A store's newsletter: signed one-click unsubscribe (both headers in the DKIM signature of the From's organization) unless
// told otherwise.
const raw = (to, { from = 'deals@em.bigstore.example', dmarc = 'pass', dkimDomain = 'bigstore.example', oneClick = true, signed = true, subject } = {}) => Buffer.from([
    `From: "Bigstore Weekly Deals" <${from}>`, `To: ${to}`, `Subject: ${subject || `Weekend sale, part ${++n}`}`, `Message-ID: <p${n}@em.bigstore.example>`,
    `DKIM-Signature: v=1; a=rsa-sha256; d=${dkimDomain}; s=k1; h=from:to:subject${signed ? ':list-unsubscribe:list-unsubscribe-post' : ''}; bh=x; b=y`,
    `Authentication-Results: mx.google.com; dkim=${dmarc === 'pass' ? 'pass' : 'none'} header.i=@${dkimDomain}; spf=pass; dmarc=${dmarc} header.from=${from.split('@')[1]}`,
    'List-Unsubscribe: <https://em.bigstore.example/u/abc>, <mailto:u@em.bigstore.example>',
    ...(oneClick ? ['List-Unsubscribe-Post: List-Unsubscribe=One-Click'] : []),
    'Content-Type: text/plain', '', 'Thirty percent off headphones this weekend. Shop the sale on our site.'].join('\r\n'));
const make = (mode = 'enforce', extra = {}) => {
    const modified = [];
    const svc = new Service({ cfg: loadConfig(Object.assign({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: [PAT, SAM].join(','), MODE: mode }, extra)), store: new MemoryStore(),
        gmail: { labelId: async (u, nm) => `L_${nm}`, labels: async () => ['INBOX'], modify: async (u, id, add, remove) => { modified.push({ u, id, add, remove }); return {}; } }, log: { error() {}, warn() {} } });
    svc.modified = modified;
    return svc;
};
const judge = async (svc, user, opts = {}, labelIds = ['INBOX']) => svc.judge(user, { id: `m${n}-${user}`, threadId: `t${n}`, internalDate: Date.now(), labelIds }, await readMessage(raw(user, opts)));

test('the signs: a signed one-click unsubscribe, or Gmail\'s Promotions category; nothing else counts', async () => {
    const facts = async (opts) => readMessage(raw(PAT, opts));
    assert.equal(oneClickSigned(await facts()), true);
    assert.equal(oneClickSigned(await facts({ oneClick: false })), false, 'List-Unsubscribe alone: any list mail, receipts too');
    assert.equal(oneClickSigned(await facts({ signed: false })), false, 'not under the signature: anyone could add it');
    assert.equal(oneClickSigned(await facts({ dkimDomain: 'mailer-platform.example' })), false, 'signed only by the platform, not the company');
    assert.equal(oneClickSigned(await facts({ dmarc: 'fail' })), false, 'DKIM not passing');
    assert.deepEqual(promotionalSigns(await facts({ oneClick: false }), ['INBOX', 'CATEGORY_PROMOTIONS']), ['Gmail put it in its Promotions category']);
    assert.deepEqual(promotionalSigns(await facts({ oneClick: false }), ['INBOX', 'CATEGORY_UPDATES']), []);
});

test('promotional mail is recorded for Review, never moved; labeled in enforce mode only; filed under the company, not the platform', async () => {
    const svc = make();
    const r = await judge(svc, PAT);
    assert.deepEqual([r.action, r.trigger, r.state], ['promo', 'promotional', 'inbox']);
    const rec = await svc.store.getRecord(r.key);
    assert.equal(rec.promotional.company, 'bigstore.example', 'the From address\'s organization');
    assert.match(rec.why, /one-click unsubscribe/);
    assert.ok(svc.modified.some(m => m.add.includes('L_SPRUCE/Promotional')), 'its label');
    assert.ok(!svc.modified.some(m => m.add.includes('SPAM')), 'never moved for being promotional');
    const monitor = make('monitor');
    assert.equal((await judge(monitor, PAT)).action, 'promo');
    assert.equal(monitor.modified.length, 0, 'monitor mode leaves mailboxes untouched');
    assert.equal((await judge(make('enforce', { PROMOTIONAL: 'off' }), PAT)).action, 'none', 'turned off');
});

test('not for forged, inside, allowlisted or taken-back senders; Gmail\'s category alone is enough', async () => {
    const svc = make('enforce', { ALLOW_ADDRESSES: 'news@trusted-store.example' });
    assert.notEqual((await judge(svc, PAT, { dmarc: 'fail' })).action, 'promo', 'unverified: judged as usual');
    assert.equal((await judge(svc, PAT, { from: `news@${ORG}`, dkimDomain: ORG })).action, 'none', 'staff newsletters are never promotional');
    assert.equal((await judge(svc, PAT, { from: 'news@trusted-store.example', dkimDomain: 'trusted-store.example' })).action, 'none', 'allowlisted');
    await svc.rememberSpamRescue(SAM, 'deals@em.bigstore.example');
    assert.equal((await judge(svc, SAM)).action, 'none', 'Sam took this company\'s spam back out of Spam');
    assert.equal((await judge(svc, PAT, { oneClick: false }, ['INBOX', 'CATEGORY_PROMOTIONS'])).action, 'promo');
    assert.equal((await judge(svc, PAT, { oneClick: false }, ['INBOX'])).action, 'none', 'neither sign');
});

test('Keep: the company leaves Review and its later mail isn\'t listed; removing it lists it again', async () => {
    const svc = make();
    const a = await judge(svc, PAT), b = await judge(svc, SAM, { from: 'news@bigstore.example' });
    const other = await judge(svc, PAT, { from: 'deals@shop.otherstore.example', dkimDomain: 'otherstore.example' });
    assert.equal((await svc.promoWaiting('bigstore.example')).length, 2, 'two addresses, one company');
    const out = await svc.answerPromotional('bigstore.example', 'keep', ADMIN);
    assert.equal(out.done, 2);
    assert.ok((await svc.store.getRecord(a.key)).promoKept && (await svc.store.getRecord(b.key)).promoKept);
    assert.ok(!(await svc.store.getRecord(other.key)).promoKept, 'another company: still waiting');
    assert.deepEqual((await svc.promoKeptList()).map(x => x.company), ['bigstore.example']);
    assert.equal((await judge(svc, PAT)).action, 'none', 'kept: not listed again');
    await svc.removePromoKept('bigstore.example', ADMIN, { undoKeys: out.keys });
    assert.ok(!(await svc.store.getRecord(a.key)).promoKept, 'Undo: back in Review');
    assert.equal((await judge(svc, PAT)).action, 'promo');
    assert.equal((await svc.answerPromotional('', 'keep', ADMIN)).status, 400);
});

test('Spam: each waiting email answered Spam (moved in enforce mode), its sender on Spam senders by the usual rule; later mail goes to Spam', async () => {
    const svc = make();
    const a = await judge(svc, PAT);
    const out = await svc.answerPromotional('bigstore.example', 'spam', ADMIN, { addSender: true });
    assert.equal(out.done, 1);
    assert.equal(out.moved, 1);
    const rec = await svc.store.getRecord(a.key);
    assert.deepEqual([rec.state, rec.spam, rec.falseAlarm, rec.markedBy], ['moved', true, false, ADMIN]);
    assert.deepEqual(out.spamSendersAdded, ['em.bigstore.example'], 'the mailing subdomain, not the whole company: its receipts stay checked');
    const later = await judge(svc, SAM);
    assert.deepEqual([later.action, later.trigger], ['move', 'spam']);
    // (0.6.90) Its promotional mail from its other addresses goes to Spam too (the company was answered); a receipt (no
    // unsubscribe marker, not in Promotions) from its main domain is still checked as usual.
    const receipt = await judge(svc, SAM, { from: 'receipts@bigstore.example', oneClick: false, subject: 'Your order receipt' });
    assert.ok(!['move', 'would-move'].includes(receipt.action), `a receipt: checked as usual (${receipt.action})`);
});

test('0.6.90: a company answered Spam in Review → Promotional: its promotional mail from any of its addresses goes to Spam, not back to Review', async () => {
    const svc = make();
    await judge(svc, PAT, { from: 'news@bigstore.example' });
    const out = await svc.answerPromotional('bigstore.example', 'spam', ADMIN, { addSender: true });
    assert.equal(out.promoSpamAdded, true);
    assert.deepEqual(out.spamSendersAdded, ['news@bigstore.example'], 'Spam senders: only the address answered');
    assert.deepEqual((await svc.promoSpamList()).map(x => x.company), ['bigstore.example']);
    // Another address and a mailing subdomain of the same company: straight to Spam, as spam; not listed in Review.
    for (const from of ['offers@bigstore.example', 'deals@em.bigstore.example']) {
        const r = await judge(svc, SAM, { from, dkimDomain: 'bigstore.example' });
        assert.deepEqual([r.action, r.trigger], ['move', 'spam'], from);
        const rec = await svc.store.getRecord(r.key);
        assert.equal(rec.promoSpam, 'bigstore.example');
        assert.match(rec.why, /answered Spam in Review → Promotional/);
        assert.equal((await svc.senderListTest())(rec), 'Promotional senders sent to Spam', 'not waiting in Review → Moved');
    }
    assert.equal((await svc.promoWaiting('bigstore.example')).length, 0, 'nothing back in Review → Promotional');
    // A forged copy is judged as usual; another company is untouched.
    assert.notEqual((await judge(svc, SAM, { from: 'offers@bigstore.example', dmarc: 'fail' })).trigger, 'spam');
    assert.equal((await judge(svc, SAM, { from: 'news@otherstore.example', dkimDomain: 'otherstore.example' })).action, 'promo');
    // Someone who takes it back out of Spam keeps getting it (as with Spam senders).
    const r = await judge(svc, PAT, { from: 'offers@bigstore.example' });
    await svc.rememberSpamRescue(PAT, 'offers@bigstore.example');
    assert.notEqual((await judge(svc, PAT, { from: 'hello@bigstore.example' })).trigger, 'spam', 'Pat took it back');
    assert.ok(r.key);
    // Monitor mode: recorded as would move. Removed: listed in Review again.
    const mon = make('monitor');
    await judge(mon, PAT, { from: 'news@bigstore.example' });
    await mon.answerPromotional('bigstore.example', 'spam', ADMIN, { addSender: true });
    assert.equal((await judge(mon, SAM, { from: 'offers@bigstore.example' })).action, 'would-move');
    assert.deepEqual((await mon.removePromoSpam('bigstore.example', ADMIN)).list, []);
    assert.equal((await judge(mon, SAM, { from: 'offers2@bigstore.example' })).action, 'promo', 'removed: listed in Review again');
    // Keep takes a company off the list; Spam without the box doesn't add it.
    await mon.answerPromotional('bigstore.example', 'spam', ADMIN, { addSender: true });
    await judge(mon, SAM, { from: 'offers3@bigstore.example' });
    await mon.answerPromotional('bigstore.example', 'keep', ADMIN);
    assert.deepEqual(await mon.promoSpamList(), [], 'Keep: off the list');
    const plain = make();
    await judge(plain, PAT, { from: 'news@bigstore.example' });
    assert.equal((await plain.answerPromotional('bigstore.example', 'spam', ADMIN, { addSender: false })).promoSpamAdded, false);
    assert.deepEqual(await plain.promoSpamList(), []);
});

test('0.6.90: companies answered Spam before the update (their sender put on Spam senders) are added once, from the records', async () => {
    const svc = make();
    const a = await judge(svc, PAT, { from: 'news@bigstore.example' });
    const b = await judge(svc, PAT, { from: 'news@otherstore.example', dkimDomain: 'otherstore.example' });
    await svc.mark(a.key, false, ADMIN, { move: true, spam: true, addSender: true });   // as before 0.6.90: the address only
    await svc.mark(b.key, false, ADMIN, { move: true, spam: true, addSender: false });  // the box not ticked: not added
    await svc.store.setState('promoSpam', null); svc._promoSpam = null;
    assert.deepEqual((await svc.promoSpamList()).map(x => [x.company, x.from]), [['bigstore.example', 'earlier']]);
    assert.deepEqual([(await judge(svc, SAM, { from: 'offers@bigstore.example' })).trigger], ['spam']);
});

test('0.6.59: Spam learning: for the days chosen, promotional mail goes to Spam and its sender to Spam senders; taking it back out trusts the sender again', async () => {
    const svc = make();
    assert.equal((await svc.spamLearningInfo()).active, false, 'off until an admin starts it');
    assert.equal((await svc.startSpamLearning(0, ADMIN)).status, 400);
    assert.equal((await svc.startSpamLearning(31, ADMIN)).status, 400);
    const started = await svc.startSpamLearning(7, ADMIN);
    assert.equal(started.info.active, true);
    assert.equal(started.info.endsAt - started.info.startedAt, 7 * 24 * 3600e3);
    // A promotional email: moved as spam, its sender learned.
    const r = await judge(svc, PAT);
    assert.deepEqual([r.action, r.trigger], ['move', 'spam'], r.why);
    assert.match(r.why, /spam learning \(Settings → Sender lists → Spam learning, until \d{4}-\d\d-\d\d\): promotional/);
    const list = await svc.spamSenderList();
    assert.deepEqual(list.map(x => [x.key, x.from]), [['em.bigstore.example', 'learning']]);
    assert.equal((await svc.spamLearningInfo()).learned, 1);
    // Its next email to someone else: moved by Spam senders.
    const next = await judge(svc, SAM);
    assert.deepEqual([next.action, next.trigger], ['move', 'spam']);
    assert.match(next.why, /is on Settings → Sender lists → Spam senders \(added by Spam learning\)/);
    // The reader takes it back out of Spam: trusted again for them.
    await svc.store.updateRecord(r.key, { state: 'moved', readHistoryId: '100' });
    await svc.userReleased(PAT, r.messageId, { at: '200' });
    assert.notEqual((await judge(svc, PAT)).trigger, 'spam', 'not moved as spam for the person who took it back');
    // (0.6.66) An admin takes it off Spam senders: learning never adds it back.
    await svc.removeSpamSender('em.bigstore.example', ADMIN);
    const back = await judge(svc, SAM, { subject: 'Another sale' });
    assert.notEqual(back.trigger, 'spam', 'not learned again after an admin removed it');
    assert.equal((await svc.spamSenderList()).length, 0);
    await svc.addSpamSender('em.bigstore.example', ADMIN);   // an admin adding it again: on the list as before
    // A forged copy, inside mail, and monitor mode.
    assert.notEqual((await judge(svc, SAM, { dmarc: 'fail', from: 'deals@em.otherstore.example', dkimDomain: 'otherstore.example' })).trigger, 'spam', 'a sender Gmail couldn\'t confirm isn\'t learned');
    const mon = make('monitor');
    await mon.startSpamLearning(3, ADMIN);
    const m = await judge(mon, PAT);
    assert.equal(m.action, 'would-move');
    assert.match(m.why, /monitor mode: nothing is moved, and em\.bigstore\.example would be added to Spam senders/);
    assert.equal(mon.modified.length, 0, 'monitor mode moves nothing');
    assert.deepEqual(await mon.spamSenderList(), [], '(0.6.66) and adds nothing to Spam senders');
    assert.deepEqual([(await mon.spamLearningInfo()).learned, (await mon.spamLearningInfo()).wouldLearn], [0, 1]);
    // (0.6.66) An email an admin marked safe (its remembered answer) isn't learned.
    const safe = make();
    await safe.startSpamLearning(3, ADMIN);
    const first = await judge(safe, PAT, { from: 'deals@em.fourthstore.example', dkimDomain: 'fourthstore.example', subject: 'Same sale' });
    await safe.store.setState('rememberedSafe', { [first.fingerprint || (await safe.store.getRecord(first.key)).fingerprint]: { sender: 'deals@em.fourthstore.example', label: 'x', by: ADMIN, at: Date.now(), last: Date.now(), hits: 0 } });
    await safe.removeSpamSender('em.fourthstore.example', ADMIN);
    await safe.store.setState('spamSendersRemoved', {});
    safe._remembered = null;
    const again = await judge(safe, SAM, { from: 'deals@em.fourthstore.example', dkimDomain: 'fourthstore.example', subject: 'Same sale' });
    assert.notEqual(again.trigger, 'spam', 'an identical email an admin marked safe isn\'t learned');
    // Stopped: when it last ran is kept; the senders learned stay.
    const stopped = await svc.stopSpamLearning(ADMIN);
    assert.equal(stopped.info.active, false);
    assert.ok(stopped.info.endedAt >= stopped.info.startedAt);
    assert.equal(stopped.info.stoppedBy, ADMIN);
    assert.equal((await svc.stopSpamLearning(ADMIN)).status, 409);
    assert.equal((await judge(svc, SAM, { from: 'deals@em.thirdstore.example', dkimDomain: 'thirdstore.example' })).action, 'promo', 'after it ends, promotional mail is promotional again');
});

test('0.6.66: starting Spam learning on the dashboard needs the agreement and the project ID; stopping it doesn\'t', async () => {
    const http = require('http');
    const { createApp } = require('../src/server');
    const cfg = loadConfig({ DEMO: '1', MODE: 'monitor', ORG_DOMAINS: ORG });
    const store = new MemoryStore();
    const svc = new Service({ cfg, store, gmail: { labelId: async () => 'L', modify: async () => ({}) }, log: { error() {}, warn() {} } });
    const srv = http.createServer(createApp({ cfg, store, service: svc }));
    await new Promise(r => srv.listen(0, r));
    const post = async (body) => { const res = await fetch(`http://127.0.0.1:${srv.address().port}/api/spam-learning`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-requested-with': 'spruce-dashboard' }, body: JSON.stringify(body) }); return { status: res.status, body: await res.json() }; };
    try {
        assert.equal((await post({ days: 3, agree: true })).status, 403, 'no project ID');
        assert.equal((await post({ days: 3, agree: true, projectId: 'another-project' })).status, 403, 'a wrong one');
        assert.equal((await svc.spamLearningInfo()).active, false, 'nothing started');
        assert.equal((await post({ days: 3, projectId: 'demo-project' })).status, 400, 'no agreement');
        const ok = await post({ days: 3, agree: true, projectId: 'demo-project' });
        assert.equal(ok.status, 200, JSON.stringify(ok.body));
        assert.equal(ok.body.info.active, true);
        assert.equal((await post({ stop: true })).status, 200, 'stopping needs neither');
    } finally { await new Promise(r => srv.close(r)); }
});
