'use strict';
// A raw email (RFC 822, as the Gmail API returns it with format=raw) → the facts the checks and the
// model use: sender, subject, the receiving server's verification results (with a DMARC result worked out
// when Gmail wrote none for the organization's own domains: deriveDmarc, 0.6.3), links, the text a person
// sees, how the email hides text, the people in its address lines, and the attachments (their names and
// types, and the files themselves in memory for the attachment checks, 0.5.34).
const { simpleParser } = require('mailparser');
const { readHtml, headTail } = require('./html');

const MAX_RAW = 2 * 1024 * 1024;   // headerAnomalies reads at most this much of the message (the parser reads it all)

// The receiving server's own verdict (Gmail writes "Authentication-Results: mx.google.com; …" on
// arrival). Results written by anyone else (the sender can add their own) are ignored. Returns { dmarc, spf,
// dkim, arc, headerFrom, dkimDomains, spfDomain } from the first such line, or null.
function receiverAuth(rawHead, receiverHost = 'mx.google.com') {
    const lines = String(rawHead || '').replace(/\r\n/g, '\n').replace(/\n[ \t]+/g, ' ').split('\n');
    for (const line of lines) {
        const m = /^authentication-results:\s*(.*)$/i.exec(line);
        if (!m) continue;
        const v = m[1];
        if (v.split(';')[0].trim().toLowerCase() !== receiverHost) continue;
        const get = (k) => { const r = new RegExp(`\\b${k}=([a-z]+)`, 'i').exec(v); return r ? r[1].toLowerCase() : null; };
        const from = /header\.from=([^\s;]+)/i.exec(v);
        // Every domain whose DKIM signature the receiver verified (header.i=@mail.beehiiv.com or header.d=…):
        // a third party among them is the service that sent the email (0.5.19).
        const dkimDomains = [...new Set([...v.matchAll(/dkim=pass\b[^;]*?\bheader\.[id]=@?([A-Za-z0-9.-]+\.[A-Za-z]{2,})/gi)].map(m => m[1].toLowerCase()))];
        const mailFrom = /smtp\.mailfrom=(?:[^\s;@]*@)?([A-Za-z0-9.-]+\.[A-Za-z]{2,})/i.exec(v);
        return { dmarc: get('dmarc'), spf: get('spf'), dkim: get('dkim'), arc: get('arc'), headerFrom: from ? from[1].toLowerCase() : null, dkimDomains,
            spfDomain: mailFrom ? mailFrom[1].toLowerCase() : null };
    }
    return null;
}

// (0.6.3) Gmail sometimes writes no DMARC result at all (seen on mail between two accounts of the same Google
// Workspace: "dkim=pass header.i=@…; spf=pass smtp.mailfrom=…", no "dmarc="). DMARC passes when SPF or DKIM passed
// for the From address's own domain (the same registrable domain: "aligned", RFC 7489); so, with no result written,
// it is worked out from the results Gmail did verify, and marked as worked out (derived). A result Gmail wrote is
// never changed: "dmarc=fail" stays a failure. Only for the organization's own domains (ownDomains): the only mail
// seen without one, and the only mail the result makes "inside"; other senders keep what Gmail wrote.
function deriveDmarc(auth, senderAddress, ownDomains = []) {
    if (!auth || auth.dmarc) return auth;
    const domain = String(senderAddress || '').toLowerCase().split('@')[1] || '';
    if (!domain || !(ownDomains || []).some(d => { d = String(d).toLowerCase(); return domain === d || domain.endsWith('.' + d); })) return auth;
    const E = require('./spruce').load();
    const org = (d) => E.registrableDomain(d) || d;
    const aligned = (d) => !!d && org(d) === org(domain);
    const by = (auth.dkim === 'pass' && (auth.dkimDomains || []).some(aligned)) ? 'DKIM' : auth.spf === 'pass' && aligned(auth.spfDomain) ? 'SPF' : '';
    return by ? Object.assign({}, auth, { dmarc: 'pass', headerFrom: domain, derived: by }) : auth;
}

function textToHtmlish(text) {
    // Plain-text emails: the text is what a person sees (cut as html.js cuts it); links are the web addresses
    // in it (at most 300).
    return { visibleText: headTail(text), hiddenText: '', quotedText: '', preheader: '', layout: [], pictures: 0,
             links: [...String(text || '').matchAll(/\bhttps?:\/\/[^\s<>"')\]]+/gi)].slice(0, 300).map(m => ({ text: m[0], href: m[0], hidden: false, afterGap: false })) };
}

// raw: Buffer or string. Returns the facts, or throws for a message that can't be parsed at all.
// ownDomains (0.6.3): the organization's own domains, for deriveDmarc.
async function readMessage(raw, { ownDomains = [] } = {}) {
    const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(String(raw || ''), 'utf8');
    const text = buf.subarray(0, MAX_RAW).toString('utf8');
    const headEnd = text.search(/\r?\n\r?\n/);
    const rawHead = headEnd >= 0 ? text.slice(0, headEnd) : text;
    const mail = await simpleParser(buf, { skipImageLinks: true, skipTextToHtml: true, skipTextLinks: true, maxHtmlLengthToParse: 2 * 1024 * 1024 });
    const from = (mail.from && mail.from.value && mail.from.value[0]) || {};
    const read = mail.html ? readHtml(mail.html) : textToHtmlish(mail.text);
    // Plain-text part as well: some phishing puts different text there than in the HTML.
    if (mail.html && mail.text && !read.visibleText.trim()) read.visibleText = headTail(mail.text);
    const to = [].concat(mail.to || []).flatMap(t => (t && t.value) || []).map(v => String(v.address || '').toLowerCase()).filter(Boolean);
    // The people the email names in its headers (display names and addresses), for the retraining
    // export's removal of names (src/training.js); never stored.
    const named = (field) => [].concat(field || []).flatMap(t => (t && t.value) || []).map(v => ({ name: String(v.name || ''), address: String(v.address || '').toLowerCase() })).filter(p => p.name || p.address);
    const people = { to: named(mail.to), cc: named(mail.cc), replyTo: named(mail.replyTo) };
    return {
        rawForHeaders: text,                                   // for headerAnomalies (headers + the start of the body)
        rawHead,
        messageIdHeader: mail.messageId || '',
        date: mail.date ? mail.date.getTime() : null,
        subject: String(mail.subject || ''),
        senderName: String(from.name || ''),
        senderAddress: String(from.address || '').toLowerCase(),
        replyTo: ((mail.replyTo && mail.replyTo.value) || []).map(v => String(v.address || '').toLowerCase()).filter(Boolean),
        // The email(s) this one answers, by Message-ID (0.5.33: a fake reply chain names none).
        inReplyTo: mail.inReplyTo ? String(mail.inReplyTo).slice(0, 1000) : '',
        references: [].concat(mail.references || []).map(String).slice(0, 50),
        to,
        people,
        auth: deriveDmarc(receiverAuth(rawHead), from.address, ownDomains),
        visibleText: read.visibleText,
        hiddenText: read.hiddenText,
        quotedText: read.quotedText,
        layout: read.layout,
        pictures: read.pictures,
        links: read.links,
        // (Not the AMP version of the body, text/x-amp-html, that Google's share and comment notifications carry
        // beside the HTML one: it is the email itself, not a file, 0.5.22.)
        attachments: (mail.attachments || []).filter(a => !(String(a.contentType || '').toLowerCase() === 'text/x-amp-html' && !a.filename))
            .map(a => ({ name: String(a.filename || ''), type: String(a.contentType || ''), size: a.size || 0 })),
        // The files themselves, for the attachment checks (0.5.34): in memory only, never stored. Pictures
        // inside the email (inline) too: a QR code is often one of those.
        attachmentFiles: (mail.attachments || []).filter(a => !(String(a.contentType || '').toLowerCase() === 'text/x-amp-html' && !a.filename))
            .map(a => ({ name: String(a.filename || ''), type: String(a.contentType || ''), size: a.size || 0, content: a.content, inline: !!a.related || a.contentDisposition === 'inline' }))
    };
}

module.exports = { readMessage, receiverAuth, deriveDmarc };
