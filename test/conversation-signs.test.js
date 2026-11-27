'use strict';
// 0.6.99: a long conversation isn't a padded subject, and a staff or student name on a personal account the reader writes
// back and forth with counts little. Every person and address here is made up.
const test = require('node:test');
const assert = require('node:assert');
const E = require('../src/engine/spruce').load();
const { analyze } = require('../src/engine/analyze');
const { readMessage } = require('../src/engine/mime');

const ORG = 'maple-schools.example', READER = `rowan.testwood@${ORG}`;
const padded = (r) => E.headerAnomalies(r, READER, E.gmailReceiver).filter(s => /padded|filler/.test(s.text));
const raw = (subject, extra = []) => [...extra, 'From: "Jordan Exampleton" <jordan.exampleton.office@gmail.com>', `To: ${READER}`, `Subject: ${subject}`,
    'Message-ID: <c1@mail.gmail.com>', 'In-Reply-To: <c0@maple-schools.example>', 'References: <c0@maple-schools.example>',
    'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=gmail.com; dkim=pass header.i=@gmail.com; dmarc=pass header.from=gmail.com',
    'Content-Type: text/plain', '', 'lol ok see you at practice tomorrow'].join('\r\n');

test('a long conversation\'s "[EXTERNAL] Re:" prefixes aren\'t padding; a padded subject still is', () => {
    const long = `${'[EXTERNAL] Re: '.repeat(30)}project`;
    assert.ok(long.length > 300);
    assert.deepEqual(padded(raw(long)), [], 'thirty replies through a tagging rule');
    assert.equal(padded(raw(`Your account ${' '.repeat(80)}notice`)).length, 1, 'blank space');
    assert.equal(padded(raw(`${'Re: '.repeat(3)}${'A'.repeat(310)}`)).length, 1, 'a long subject under the prefixes');
});

test('a colleague\'s or student\'s name on a personal account counts 1 when the reader writes back and forth with it; 3 with a request', async () => {
    const colleagues = new Set([E.colleagueNameHash('Jordan Exampleton')]);
    const ctx = (thread, extra = {}) => Object.assign({ mailbox: READER, orgDomains: [ORG], colleagues, threadSize: 12,
        extraFacts: { category: 'primary', thread, recipients: 1 } }, extra);
    const sign = async (r, c) => (await analyze(await readMessage(r), c)).signals.find(s => s.kind === 'sender-colleague-name');
    const subject = `${'[EXTERNAL] Re: '.repeat(20)}project`;
    const talking = await sign(raw(subject), ctx({ reply: true, size: 12, readerWrote: true }));
    assert.equal(talking.weight, 1);
    assert.match(talking.text, /written back in this conversation/);
    assert.equal((await sign(raw(subject), ctx({ reply: true, size: 1, readerWrote: false }))).weight, 2, 'a first approach: 2, as before');
    assert.equal((await sign(raw(subject), ctx(null, { gmailHistory: { received: 5, ageDays: 30, wrote: true } }))).weight, 1, 'your organization wrote to this address before');
    const asking = raw(subject).replace('lol ok see you at practice tomorrow', 'Are you at your desk? I need a quick favor, can you buy gift cards for me today');
    assert.equal((await sign(asking, ctx({ reply: true, size: 12, readerWrote: true }))).weight, 3, 'asking what impersonators ask: 3, conversation or not');
});
