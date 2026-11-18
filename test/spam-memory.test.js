'use strict';
// 0.6.26: spam someone took back out of Spam is remembered for them (that sender's spam isn't moved for them again);
// when 3 people took back the same sender's, for no one, until an admin keeps moving it. Phishing is never affected.
// An admin's "Spam" verdict, and the retraining export's class. Every person, address and email here is made up.
const test = require('node:test');
const assert = require('node:assert');
const { loadConfig } = require('../src/config');
const { Service } = require('../src/pipeline');
const { MemoryStore } = require('../src/store/memory');
const { readMessage } = require('../src/engine/mime');
const T = require('../src/training');

const ORG = 'maple-schools.example';
const [PAT, SAM, AVERY, RILEY] = ['pat.fakewell', 'sam.testwood', 'avery.mockwell', 'riley.exemplar'].map(u => `${u}@${ORG}`);
const FILLER = `<div style="height:3000px"></div><p>${'Unrelated filler text from an old forum post about garden tools. '.repeat(6)}</p>`;
const padded = (to, { dmarc = 'pass', from = 'Lakeview Garden Club <news@mail.lakeviewgardens.example>' } = {}) => Buffer.from([`From: ${from}`, `To: ${to}`,
    'Subject: Big spring sale', `Message-ID: <s${Math.random().toString(36).slice(2)}@lakeviewgardens.example>`, 'List-Unsubscribe: <https://lakeviewgardens.example/u>',
    `Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=${dmarc} header.from=mail.lakeviewgardens.example`, 'Content-Type: text/html; charset=utf-8', '',
    `<p>Big spring sale, 40% off everything.</p>${FILLER}`].join('\r\n'));
const make = () => {
    const cfg = loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: [PAT, SAM, AVERY, RILEY].join(','), MODE: 'monitor' });
    const svc = new Service({ cfg, store: new MemoryStore(), gmail: { labelId: async (u, n) => `L_${n}`, modify: async () => ({}) }, log: { error() {}, warn() {} } });
    return svc;
};
let n = 0;
const judge = async (svc, user, opts) => svc.judge(user, { id: `m${++n}`, threadId: `t${n}`, internalDate: Date.now() }, await readMessage(padded(user, opts)));

test('spam someone took back is remembered for them only; a sender is its organization\'s domain, or a personal address', async () => {
    const svc = make();
    assert.equal(svc.spamSenderKey('news@mail.lakeviewgardens.example'), 'lakeviewgardens.example');
    assert.equal(svc.spamSenderKey('dana.madeup.1985@gmail.com'), 'dana.madeup.1985@gmail.com', 'a personal account is one person, not everyone at gmail.com');
    const first = await judge(svc, PAT);
    assert.deepEqual([first.action, first.trigger], ['would-move', 'spam']);
    await svc.rememberSpamRescue(PAT, 'news@mail.lakeviewgardens.example');
    assert.equal((await judge(svc, PAT)).action, 'none', 'not moved as spam for the person who took it back');
    assert.deepEqual([(await judge(svc, SAM)).action], ['would-move'], 'still moved for everyone else');
    const forged = await judge(svc, PAT, { dmarc: 'fail' });
    assert.notEqual(forged.action, 'none', 'a forged copy (DMARC failing) isn\'t covered by the memory');
});

test('a user moving the service\'s spam back to the Inbox remembers it; phishing moved back doesn\'t', async () => {
    const svc = make();
    const rec = await judge(svc, PAT);
    await svc.store.updateRecord(rec.key, { state: 'moved', readHistoryId: '100' });
    await svc.userReleased(PAT, rec.messageId, { at: '200' });
    assert.ok(await svc.spamKept(PAT, 'news@mail.lakeviewgardens.example'));
    const phish = await judge(svc, SAM);
    await svc.store.updateRecord(phish.key, { state: 'moved', readHistoryId: '100', trigger: 'rules' });
    await svc.userReleased(SAM, phish.messageId, { at: '200' });
    assert.equal(await svc.spamKept(SAM, 'news@mail.lakeviewgardens.example'), null, 'a rescue of mail moved as phishing teaches nothing');
});

test('3 people took back the same sender\'s spam: not moved for anyone, listed for admins; "keep moving it" undoes that for the others', async () => {
    const svc = make();
    for (const u of [PAT, SAM]) await svc.rememberSpamRescue(u, 'news@mail.lakeviewgardens.example');
    assert.deepEqual(await svc.spamRescuedList(), [], 'two people: not yet');
    assert.equal((await judge(svc, RILEY)).action, 'would-move');
    await svc.rememberSpamRescue(AVERY, 'offers@lakeviewgardens.example');
    const list = await svc.spamRescuedList();
    assert.deepEqual(list.map(x => [x.sender, x.people, x.keep]), [['lakeviewgardens.example', 3, false]]);
    assert.ok((await svc.store.listEvents()).some(e => e.kind === 'spam-rescued' && /3 people took mail from lakeviewgardens\.example back out of Spam/.test(e.text)));
    assert.equal((await judge(svc, RILEY)).action, 'none', 'not moved as spam for anyone now');
    const kept = await svc.setSpamKeep('lakeviewgardens.example', true, `it.head@${ORG}`);
    assert.equal(kept.list[0].keep, true);
    assert.equal((await judge(svc, RILEY)).action, 'would-move', 'moved again for the others');
    assert.equal((await judge(svc, PAT)).action, 'none', 'each person who took some back still keeps theirs');
    assert.equal((await svc.setSpamKeep('nobody.example', true, 'x')).status, 404);
});

test('an admin\'s "Spam" verdict: confirmed, not a false alarm, marked spam; the export\'s class', async () => {
    const svc = make();
    const rec = await judge(svc, PAT);
    const out = await svc.mark(rec.key, false, `it.head@${ORG}`, { spam: true });
    assert.deepEqual([out.record.falseAlarm, out.record.spam], [false, true]);
    const ph = await svc.mark(rec.key, false, `it.head@${ORG}`);
    assert.equal(ph.record.spam, false, 'marked phishing afterwards: not spam');
    assert.equal(T.classOf({ spam: true }, 1), 'spam');
    assert.equal(T.classOf({ spam: false }, 1), 'phishing');
    assert.equal(T.classOf({}, 1), 'phishing or spam', 'marked before 0.6.26: either');
    assert.equal(T.classOf({ spam: true }, 0), 'genuine');
    assert.match(T.noteFor({ spam: true, action: 'move', trigger: 'spam', score: 0 }, 1), /^Confirmed as spam by an admin/);
    assert.deepEqual(T.problems({ label: 0, class: 'spam', facts: { subject: 'x', senderAddress: 'a@b.example', bodyText: 'x' } }), ['class and label disagree: genuine is label 0, spam and phishing label 1']);
});
