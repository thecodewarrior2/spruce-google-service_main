'use strict';
// 0.6.94: another staff member's name on a staff account (src/staff-names.js): mail from inside (your domains, Gmail
// confirmed the sender) signed with someone else's name in the directory. Every person and address here is made up.
const test = require('node:test');
const assert = require('node:assert');
const S = require('../src/staff-names');
const { loadConfig } = require('../src/config');
const { Service } = require('../src/pipeline');
const { MemoryStore } = require('../src/store/memory');
const { readMessage } = require('../src/engine/mime');

const ORG = 'maple-schools.example';
const PAT = `pat.fakewell@${ORG}`, SAM = `sam.testwood@${ORG}`, LEE = `lee.madeup@${ORG}`;
const DIRECTORY = [
    { name: 'Pat Fakewell', email: PAT, aliases: [`principal@${ORG}`] },
    { name: 'Sam Testwood', email: SAM, aliases: [] },
    { name: 'Lee Madeup', email: LEE, aliases: [] },
    { name: 'Dana Samplefield', email: `dana.samplefield@${ORG}` },
    { name: 'Dana Samplefield', email: `dana.samplefield2@${ORG}` },   // two staff with one name
    { name: 'Notifications', email: `noreply@${ORG}` }];               // a system account (no person's name)

test('names compared loosely: order, case, accents, titles, initials and brackets don\'t count; a role name isn\'t a person', () => {
    const k = S.staffNameKey;
    for (const n of ['Pat Fakewell', 'Fakewell, Pat', 'Dr. Pat Q. Fakewell', 'PAT FAKEWELL (Principal)', 'Pat Fakewell via Staff']) assert.equal(k(n), 'fakewell pat', n);
    assert.equal(k('Josë Madeup'), k('Jose Madeup'), 'accents');
    for (const n of ['Payroll', 'IT', 'P. Fakewell', '']) assert.equal(k(n), '', n);
});

test('the sign: someone else\'s name on a staff account; quiet for the owner\'s own name, aliases, groups, unknown names, same-name staff, allowed accounts, outside mail', () => {
    const staff = S.staffDirectory(DIRECTORY);
    const sign = (name, address, o = {}) => S.insideNameSigns({ name, address }, Object.assign({ inside: true, staff }, o));
    const s = sign('Pat Fakewell', SAM);
    assert.deepEqual(s.map(x => [x.kind, x.weight, x.address]), [['inside-name-mismatch', 3, SAM]]);
    assert.match(s[0].text, /“Pat Fakewell”, the name of someone in your organization, but it comes from another staff member's account \(sam\.testwood@/);
    assert.deepEqual(sign('Pat Fakewell', PAT), [], 'their own account');
    assert.deepEqual(sign('Dr. Pat Fakewell', `principal@${ORG}`), [], 'their own alias, with a title');
    assert.deepEqual(sign('Pat Fakewell', `staff-list@${ORG}`), [], 'a group or an address the directory doesn\'t have');
    assert.deepEqual(sign('Coach Pat', SAM), [], 'a name that is nobody\'s');
    assert.deepEqual(sign('Payroll', SAM), [], 'a role');
    assert.deepEqual(sign('Dana Samplefield', `dana.samplefield2@${ORG}`), [], 'two staff with the same name');
    assert.deepEqual(sign('Pat Fakewell', SAM, { allowed: new Set([SAM]) }), [], 'an account an admin allowed');
    assert.deepEqual(sign('Pat Fakewell', SAM, { inside: false }), [], 'not confirmed as yours (forged inside addresses have their own sign)');
    assert.deepEqual(S.insideNameSigns({ name: 'Pat Fakewell', address: SAM }, { inside: true, staff: null }), [], 'directory not read');
    assert.deepEqual(sign('Lee Madeup', `noreply@${ORG}`), [], 'a system account (its directory name is no person\'s): school systems send as staff from such accounts');
    assert.match(sign('Lee Madeup', SAM, { share: 'Google Drive' })[0].text, /^Google Drive sent it for “Lee Madeup”/);
});

test('the service: flagged for Review (never moved on it alone); Mark safe allows the account; Undo takes that back', async () => {
    const store = new MemoryStore();
    const cfg = loadConfig({ STORE: 'memory', ORG_DOMAINS: ORG, PILOT_USERS: LEE, MODE: 'enforce', DIRECTORY_ADMIN: `it.madeup@${ORG}` });
    const gmail = { modify: async () => ({}), labelId: async (u, l) => `L_${l}`, userNames: async () => DIRECTORY };
    const svc = new Service({ cfg, store, gmail, log: { error() {}, warn() {} } });
    let n = 0;
    const mail = (name, from) => Buffer.from([`From: "${name}" <${from}>`, `To: ${LEE}`, 'Subject: Quick favor', `Message-ID: <s${++n}@${ORG}>`,
        `Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=${ORG}; dkim=pass header.i=@${ORG}; dmarc=pass header.from=${ORG}`, 'Content-Type: text/plain', '',
        'Are you at your desk? I need you to take care of something for me today.'].join('\r\n'));
    const judge = async (name, from) => svc.judge(LEE, { id: `m${n}`, threadId: `t${n}`, labelIds: ['INBOX'], internalDate: Date.now() }, await readMessage(mail(name, from)));
    await svc.colleagueNames();
    const r = await judge('Pat Fakewell', SAM);
    const rec = await store.getRecord(r.key);
    assert.ok(rec && rec.signals.some(x => x.kind === 'inside-name-mismatch'), JSON.stringify(rec && rec.signals));
    assert.notEqual(rec.action, 'move', 'not moved on it alone');
    assert.equal((await judge('Pat Fakewell', PAT)).action, 'none', 'Pat\'s own account');
    // A shared office account that signs as staff: Mark safe allows it.
    const m = await svc.mark(rec.key, true, `it.madeup@${ORG}`);
    assert.ok(m.record);
    assert.deepEqual((await svc.staffNameSenderList()).map(x => x.company), [SAM]);
    const again = await judge('Pat Fakewell', SAM);
    const rec2 = again.key ? await store.getRecord(again.key) : null;
    assert.ok(!rec2 || !rec2.signals.some(x => x.kind === 'inside-name-mismatch'), 'allowed: not counted again');
    await svc.undoAnswer(rec.key, `it.madeup@${ORG}`);
    assert.deepEqual(await svc.staffNameSenderList(), [], 'Undo: checked again');
});
