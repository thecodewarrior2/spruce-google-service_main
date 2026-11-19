'use strict';
// (0.6.52) Promotional mail: marketing and subscribed mail (newsletters, sales, offers), told apart from other mail by
// what Gmail and the sender's own signed headers say, with no list of marketing platforms for anyone to keep:
//   - Gmail put it in its Promotions category: the Gmail API's CATEGORY_PROMOTIONS label ("the messages that are displayed
//     in the Promotions tab", Google's own classifier);
//   - the sender signed a one-click unsubscribe (RFC 8058): a List-Unsubscribe header and List-Unsubscribe-Post:
//     List-Unsubscribe=One-Click, both under a DKIM signature of the sender's own organization, with Gmail's DKIM check
//     passing. Gmail and Yahoo require it of bulk senders for marketing and subscribed mail only, not for receipts,
//     password resets or reservations (Google's sender FAQ), and the signature means a forwarded or forged copy can't
//     carry it over.
// Promotional mail is never moved for that: the pipeline records it for Review → Promotional, where an admin answers once
// per company (Spam: Spam senders; Keep: not asked again). Only verified mail from outside counts (the pipeline's
// promotionalOf): the company it is filed under is the From address's organization (spamSenderKey), never the
// platform that sent it, so one company's answer never covers the platform's other customers.
const { sameOrgDomain } = require('./engine/analyze');

// The headers' values by lower-case name, folded lines joined (only the header block).
function headerValues(raw) {
    const block = String(raw || '').split(/\r?\n\r?\n/)[0] || '';
    const out = {};
    for (const line of block.replace(/\r?\n[ \t]+/g, ' ').split(/\r?\n/)) {
        const m = /^([!-9;-~]+)[ \t]*:[ \t]*(.*)$/.exec(line);
        if (m) (out[m[1].toLowerCase()] = out[m[1].toLowerCase()] || []).push(m[2]);
    }
    return out;
}

// A DKIM-Signature header's tags (d=, h=, …), spaces taken out of their values.
function dkimTags(value) {
    const tags = {};
    for (const part of String(value || '').split(';')) {
        const m = /^\s*([a-z]+)\s*=\s*([\s\S]*?)\s*$/i.exec(part);
        if (m) tags[m[1].toLowerCase()] = m[2].replace(/\s+/g, '');
    }
    return tags;
}

// Whether the sender signed a one-click unsubscribe: both headers present, and a DKIM signature of the From address's
// organization that covers both, with Gmail's DKIM check passing. (Gmail's result doesn't say which signature passed;
// the pipeline also needs DMARC passing, which an aligned signature or SPF must have made.)
function oneClickSigned(facts) {
    const H = headerValues(facts && facts.rawForHeaders);
    if (!(H['list-unsubscribe'] || []).length) return false;
    if (!(H['list-unsubscribe-post'] || []).some(v => /list-unsubscribe\s*=\s*one-click/i.test(v))) return false;
    if (!facts.auth || facts.auth.dkim !== 'pass') return false;
    const from = String(facts.senderAddress || '').toLowerCase().split('@')[1] || '';
    if (!from) return false;
    return (H['dkim-signature'] || []).some(v => {
        const t = dkimTags(v);
        const signed = String(t.h || '').toLowerCase().split(':');
        return !!t.d && sameOrgDomain(t.d.toLowerCase(), from) && signed.includes('list-unsubscribe') && signed.includes('list-unsubscribe-post');
    });
}

// What makes an email promotional, in plain words ([] when nothing does). labelIds: Gmail's labels on the message.
function promotionalSigns(facts, labelIds) {
    const out = [];
    if ((labelIds || []).includes('CATEGORY_PROMOTIONS')) out.push('Gmail put it in its Promotions category');
    if (oneClickSigned(facts)) out.push('the sender signed a one-click unsubscribe, which bulk senders must add to marketing mail');
    return out;
}

module.exports = { promotionalSigns, oneClickSigned, headerValues, dkimTags };
