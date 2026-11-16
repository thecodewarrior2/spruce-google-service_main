'use strict';
// The engine: the extension's checks and model on raw emails. All emails here are made up.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { readHtml } = require('../src/engine/html');
const { readMessage, receiverAuth } = require('../src/engine/mime');
const { analyze } = require('../src/engine/analyze');

const fixture = (f) => fs.readFileSync(path.join(__dirname, 'fixtures', f));
const CTX = { mailbox: 'reader@maple-schools.example', orgDomains: ['maple-schools.example'] };

test('a fake storage notice (DMARC fail, sender named after the reader, filler after a blank gap) is flagged and the AI agrees', async () => {
    const facts = await readMessage(fixture('phish-storage.eml'));
    assert.deepEqual(facts.layout, ['text after a large blank gap']);
    assert.equal(facts.auth.dmarc, 'fail');
    assert.doesNotMatch(facts.visibleText, /regalia/, 'the filler is not part of what the reader sees');
    const r = await analyze(facts, Object.assign({ firstTime: true }, CTX));
    assert.equal(r.status, 'flagged');
    assert.ok(r.score >= 5, String(r.score));
    for (const kind of ['hidden-filler', 'outside-org', 'first-time']) assert.ok(r.signals.some(s => s.kind === kind), kind);
    assert.ok(r.signals.some(s => /DMARC/.test(s.text)));
    assert.ok(r.signals.some(s => /your own mailbox name/.test(s.text)));
    assert.ok(r.ai.probability > 0.85, String(r.ai.probability));
});

test('a genuine newsletter (DMARC pass, hidden preheader, its own links) stays clean', async () => {
    const r = await analyze(await readMessage(fixture('genuine-newsletter.eml')), CTX);
    assert.equal(r.status, 'clean');
    assert.ok(r.ai.probability < 0.5, String(r.ai.probability));
    assert.ok(!r.signals.some(s => s.weight >= 3), JSON.stringify(r.signals));
});

test('only the receiving server\'s own verification results count (a sender can add its own header)', () => {
    const head = 'Authentication-Results: evil.example; dmarc=pass header.from=bank.example\r\nAuthentication-Results: mx.google.com;\r\n dkim=none; spf=fail smtp.mailfrom=x@evil.example; dmarc=fail header.from=bank.example';
    assert.deepEqual(receiverAuth(head), { dmarc: 'fail', spf: 'fail', dkim: 'none', arc: null, headerFrom: 'bank.example', dkimDomains: [] });
    assert.equal(receiverAuth('Authentication-Results: evil.example; dmarc=pass'), null);
    // The verified signers (0.5.19): the receiver's own passing DKIM results only.
    const signed = 'Authentication-Results: evil.example; dkim=pass header.i=@mail.beehiiv.com\r\nAuthentication-Results: mx.google.com;\r\n dkim=pass header.i=@news.sender.example header.s=s1;\r\n dkim=fail header.d=other.example; dmarc=pass header.from=news.sender.example';
    assert.deepEqual(receiverAuth(signed).dkimDomains, ['news.sender.example']);
});

test('HTML reading: hidden text, filler after a gap, pictures only, quoted history, links', () => {
    const r = readHtml(`<div style="display:none">Preheader text that hides here</div><p>Hello <b>there</b>.</p>
        <p style="font-size:0px">tiny hidden words</p><p style="opacity:0">invisible</p><span hidden>gone</span>
        <a href="https://a.example/x">Visible link</a><a href="javascript:alert(1)">Click</a>
        <blockquote>On Monday someone wrote: old text <a href="https://quoted.example/">old link</a></blockquote>
        <style>p { color: red }</style><script>evil()</script>`);
    assert.match(r.visibleText, /Hello there\./);
    for (const t of ['Preheader', 'tiny hidden', 'invisible', 'gone', 'old text', 'evil', 'color: red']) assert.doesNotMatch(r.visibleText, new RegExp(t), t);
    assert.match(r.hiddenText, /tiny hidden words/);
    assert.match(r.quotedText, /old text/);
    assert.deepEqual(r.links.map(l => l.href), ['https://a.example/x', 'javascript:alert(1)'], 'links in quoted history are not judged');
    assert.deepEqual(r.layout, []);
    const gap = readHtml(`<p>Short lure.</p><div style="height:3000px"></div><p>${'Unrelated filler text from an old forum post. '.repeat(6)}</p>`);
    assert.deepEqual(gap.layout, ['text after a large blank gap']);
    assert.equal(gap.visibleText, 'Short lure.');
    assert.deepEqual(readHtml(`<p>Lure.</p><div style="height:3000px"></div><p>Short.</p>`).layout, [], 'too little after the gap to be filler');
    assert.deepEqual(readHtml(`<table><tr><td height="1200">Real content in a tall cell</td></tr></table>`).layout, [], 'a tall cell with text is not a spacer');
    const pics = readHtml(`<span style="display:none">Apply today for a card!</span><a href="https://x.example/"><img src="a.jpg" width="600"></a><img src="p.gif" width="1" height="1">`);
    assert.deepEqual(pics.layout, ['images only']);
    assert.match(pics.visibleText, /Apply today for a card!/, 'the hidden preheader is what a picture-only email says');
    assert.equal(pics.pictures, 1, 'a tracking pixel is not a picture');
});

test('a link that runs code counts as dangerous; a look-alike domain too', async () => {
    const facts = await readMessage(Buffer.from([
        'From: "PayPal" <service@paypa1-secure.example>', 'To: reader@maple-schools.example', 'Subject: Account limited',
        'Authentication-Results: mx.google.com; dmarc=none header.from=paypa1-secure.example', 'Content-Type: text/html', '',
        '<p>Your account is limited.</p><a href="https://paypa1.com/verify">Restore access</a> <a href="javascript:steal()">Details</a>'].join('\r\n')));
    const r = await analyze(facts, CTX);
    assert.equal(r.status, 'flagged');
    const links = r.signals.find(s => s.kind === 'dangerous-links');
    assert.ok(links && links.weight === 5, JSON.stringify(r.signals));
    assert.ok(r.links.some(l => /look-alike/.test(l.reason)));
    assert.ok(r.links.some(l => /runs code/.test(l.reason)));
});

test('look-alike domains (0.5.6): a brand\'s own top-level domain and the word "cloud" aren\'t look-alikes; real ones still are', () => {
    const E = require('../src/engine/spruce').load();
    const finding = (host) => { const r = E.detectLinkProblem('Open', `https://${host}/x`, `https://${host}/x`, [], {}); return r && /look-alike/.test(String(r)) ? String(r) : null; };
    // Microsoft 365 under .microsoft (only Microsoft registers there), other brands' own TLDs, and the plain word.
    for (const h of ['bookings.cloud.microsoft', 'forms.cloud.microsoft', 'teams.cloud.microsoft', 'outlook.cloud.microsoft', 'blog.google', 'cloud.com', 'www.cloud.com', 'soundcloud.com', 'mycloud.com']) {
        assert.equal(finding(h), null, h);
    }
    // Still found: look-alike characters, one letter (other than the plain word), the brand's name with sign-in words, "brand.com." in front.
    for (const [h, re] of [['icl0ud.com', /imitates icloud\.com with look-alike characters/], ['lcloud.com', /one letter away from icloud\.com/], ['iclouds.com', /one letter away from icloud\.com/],
        ['icloud-login.com', /uses the name "icloud"/], ['icloud.com.verify-id.com', /starts with "icloud\.com"/], ['micros0ft.com', /imitates microsoft\.com/],
        ['rnicrosoft.com', /imitates microsoft\.com/], ['paypa1.com', /imitates paypal\.com/], ['microsoft-login.com', /uses the name "microsoft"/]]) {
        assert.match(finding(h) || '', re, h);
    }
});

test('allowlisted senders are "trusted": never escalated, whatever the checks find', async () => {
    const r = await analyze(await readMessage(fixture('phish-storage.eml')), Object.assign({ trusted: true }, CTX));
    assert.equal(r.status, 'trusted');
});

test('the model (0.4.0): a pass\'s answer is remembered by a hash of its input, so identical copies cost one pass; the answer is the same', async () => {
    const E = require('../src/engine/spruce').load();
    const session = await E.model.ready();
    let runs = 0;
    const run = session.run.bind(session);
    session.run = (...a) => { runs++; return run(...a); };
    try {
        const text = 'from: billing@harbor-supply-invoices.example text: Our bank details have changed; please update the account number on file and pay today. ' + Math.random();
        const a = await E.model.margin(text), b = await E.model.margin(text);
        assert.equal(runs, 1, 'the second copy costs no pass');
        assert.equal(a, b);
        await E.model.margin(text + ' (another one)');
        assert.equal(runs, 2);
    } finally { session.run = run; }
});

// (0.5.57) An email longer than the service reads (html.js MAX_TEXT): its first HEAD_TEXT and its last TAIL_TEXT
// characters, in HTML and in plain text, so its ending reaches the checks and the model.
test('a very long email keeps its start and its end, in HTML and in plain text', async () => {
    const H = require('../src/engine/html');
    const filler = 'The library is open late this week for families. '.repeat(1200);
    const ask = 'Reply to my personal email before Friday to hold the items.';
    const html = readHtml(`<div><p>Opening note about the estate sale.</p><p>${filler}</p><p>${ask}</p></div>`);
    assert.ok(html.visibleText.startsWith('Opening note about the estate sale.') && html.visibleText.endsWith(ask), 'HTML: start and end');
    assert.ok(html.visibleText.length <= H.MAX_TEXT, String(html.visibleText.length));
    const one = readHtml(`<p>Opening note.${filler}${ask}</p>`);
    assert.ok(one.visibleText.endsWith(ask) && one.visibleText.length <= H.MAX_TEXT, 'one long text node');
    const raw = ['From: "Pat" <pat@freemail.example>', 'To: jordan@maple-schools.example', 'Subject: Estate sale', 'Content-Type: text/plain', '', `Opening note about the estate sale. ${filler}${ask}`].join('\r\n');
    const facts = await readMessage(Buffer.from(raw));
    assert.ok(facts.visibleText.startsWith('Opening note') && facts.visibleText.endsWith(ask) && facts.visibleText.length <= H.MAX_TEXT, 'plain text: start and end');
    const r = await analyze(facts, { mailbox: 'jordan@maple-schools.example', orgDomains: ['maple-schools.example'], keepAiFacts: true });
    assert.ok(r.aiFacts.bodyText.endsWith(ask), 'the model is given the end');
    const short = readHtml('<p>Short note.</p>');
    assert.equal(short.visibleText, 'Short note.');
});

// (0.5.55) A text longer than the model reads: with model.json config.headTokens (phish-tiny 0.20.0) its start and
// its end, else its start, as the model was trained (TinyPhishLLM's cut_ids).
test('the tokenizer cuts a long text to its start and its end when the model says so (headTokens), else to its start', () => {
    const E = require('../src/engine/spruce').load();
    const tok = E.model.tok;
    const text = 'Made-up notice for maple-schools.example staff. ' + Array.from({ length: 60 }, (_, k) => `Item ${k + 1} is available for ${(k + 1) * 10} dollars.`).join(' ') + ' Reply to the front office before Friday.';
    const all = tok.encode(text, 100000);
    assert.ok(all.length > 300, 'the sample is longer than the model reads');
    const pieces = all.slice(1, -1);
    assert.deepEqual(tok.encode(text, 256), [all[0], ...pieces.slice(0, 254), all[all.length - 1]], 'start only');
    assert.deepEqual(tok.encode(text, 256, 128), [all[0], ...pieces.slice(0, 128), ...pieces.slice(pieces.length - 126), all[all.length - 1]], 'start and end');
    assert.deepEqual(tok.encode('Short text.', 256, 128), tok.encode('Short text.', 256), 'a short text is not cut');
});

// The reference: 400 made-up inputs, their token ids, and the model's answers as TinyPhishLLM's
// training/export-onnx.py computes them from model.bin in numpy, without ONNX (for phish-tiny 0.11.0 they
// agreed with the JavaScript engine of 0.4.1 to 1.2e-6). It comes with the model (tools/sync-model.js).
test('the native engine (0.5.0): the same answers as an independent computation of the model, on 400 made-up inputs; one at a time or in a batch', async () => {
    const E = require('../src/engine/spruce').load();
    const ref = require('./fixtures/model-reference.json');
    assert.equal(ref.model, E.modelInfo.version, 'the reference is for this model (a new model comes with its own: node tools/sync-model.js <TinyPhishLLM folder>)');
    ref.cases.forEach((c, i) => assert.deepEqual(E.model.tok.encode(c.text, E.model.cfg.maxLen, E.model.cfg.headTokens || 0), c.ids, `case ${i}: the tokenizer's ids`));
    const { Model } = require('../src/engine/model');
    // (a fresh model: nothing remembered from the other tests)
    const fresh = new Model({ file: E.model.file, manifest: E.model.meta, tokenizer: E.model.tok, modelInputParts: E.model.parts });
    const one = [];
    for (const c of ref.cases) one.push(await fresh.margin(c.text));
    let worst = 0, flips = 0;
    ref.cases.forEach((c, i) => {
        worst = Math.max(worst, Math.abs(one[i] - c.margin));
        const p0 = 1 / (1 + Math.exp(-c.margin)), p1 = 1 / (1 + Math.exp(-one[i]));
        for (const line of [0.5, 0.65, 0.9]) if ((p0 >= line) !== (p1 >= line)) flips++;
    });
    assert.ok(worst < 1e-4, `largest difference ${worst}`);
    assert.equal(flips, 0, 'no email changes side of the 50%, 65% or 90% line');
    // In one batch (padded): the same as one at a time.
    const batched = new Model({ file: E.model.file, manifest: E.model.meta, tokenizer: E.model.tok, modelInputParts: E.model.parts });
    const all = await batched.margins_(ref.cases.slice(0, 64).map(c => c.text));
    all.forEach((m, i) => assert.ok(Math.abs(m - one[i]) < 1e-4, `case ${i}: ${m} vs ${one[i]}`));
});

// Input format 2 (phish-tiny 0.16.0): the model's facts carry what the sender checks found (a format-1
// model leaves them out, so what it reads is unchanged).
test('the AI facts (input format 2): who the sender claims to be, other Reply-To domains, attachment kinds without names', async () => {
    const raw = ['From: "PayPal Service" <service@paypal-review.example>', 'Reply-To: "Help" <madeup.help@freemail.example>, <desk@mail.paypal-review.example>',
        'To: <reader@maple-schools.example>', 'Subject: Your account is limited', 'Authentication-Results: mx.google.com; dkim=fail header.d=paypal-review.example; spf=softfail; dmarc=fail header.from=paypal-review.example',
        'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="b"', '', '--b', 'Content-Type: text/plain', '', 'Open the attached statement to restore access.',
        '--b', 'Content-Type: text/html; name="Jane Doe Statement.pdf.html"', 'Content-Disposition: attachment; filename="Jane Doe Statement.pdf.html"', '', '<p>x</p>', '--b--', ''].join('\r\n');
    const facts = await readMessage(Buffer.from(raw));
    const r = await analyze(facts, Object.assign({ keepAiFacts: true, readAttachments: false }, CTX));
    assert.deepEqual(r.aiFacts.identity, { brand: 'PayPal', owner: 'no' });
    assert.deepEqual(r.aiFacts.replyTo, ['freemail.example']);
    assert.deepEqual(r.aiFacts.attachments, [{ name: 'file.pdf.html', type: 'text/html' }]);
    assert.equal(r.aiFacts.auth.spf, 'softfail');
    assert.equal(r.aiFacts.auth.dkim, 'fail');
    assert.ok(!JSON.stringify(r.aiFacts).includes('Jane'), 'no file name');
    // The organization's own staff aren't judged by a brand their name mentions.
    const staff = await readMessage(Buffer.from(['From: "Microsoft 365 Support" <it@maple-schools.example>', 'To: <reader@maple-schools.example>', 'Subject: Password policy',
        'Authentication-Results: mx.google.com; dmarc=pass header.from=maple-schools.example', 'Content-Type: text/plain', '', 'Passwords change on July 1.'].join('\r\n')));
    assert.equal((await analyze(staff, Object.assign({ keepAiFacts: true, aiInside: true }, CTX))).aiFacts.identity, null);
});
