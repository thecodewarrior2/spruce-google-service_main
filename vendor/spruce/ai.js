// ai.js — EXPERIMENT (branch llm_testing): the extension's own small language model reads an opened
// email and gives its opinion on whether it is phishing, and which sentences made it think so.
//
// The model (models/phish-tiny/) is an ELECTRA-small classifier since phish-tiny 0.18.0 (12 layers, 13.5 million
// parameters, about 14 MB with 8-bit weights; the BERT-tiny model before it is kept in TinyPhishLLM as
// phish-tiny-old and not used) that WE train, in TinyPhishLLM (the model's own repository, shared with the
// extension; tools/sync-model.js brings it here): its training/ generates the training emails, fine-tunes the
// model and exports it. In this service it runs in the native engine (src/engine/model.js, ONNX Runtime,
// nothing sent anywhere); this file builds its input and splits it into tokens.
//
// Ground rules, enforced here and in the callers:
//   - ADVISORY ONLY. The model's opinion can add a warning, never remove one: it never makes an email or
//     link "safe", never clears a flag and never moves anything to Spam (aiAdvice).
//   - ON THIS COMPUTER ONLY. Each opened email is analyzed as it opens (aiAutoAnalyze, on by default),
//     or only when the person clicks "Ask the AI"; nothing is sent anywhere or stored.
//   - LESS PERSONAL DATA. Addresses keep only their domain, phone numbers and long numbers are replaced
//     (redactForAi) before the text reaches the model, as in training.
//   - TEXT THAT VOUCHES FOR ITSELF counts toward phishing (selfVouchingSigns in shared.js; the training
//     data teaches the model the same).
// Loaded after shared.js (registrableDomain, selfVouchingSigns, isSharedMailbox).

// ---------------------------------------------------------------------------------------------------
// The model's input: one text built from the email's facts. TinyPhishLLM's training/make-dataset.js builds its
// training emails with this same function, so training and use always see the same format.
// facts: { subject, senderName, senderAddress, auth: { dmarc } | null,
//          links: [{ text, host, destHost, finding }], bodyText,
//          org: 'inside' | 'outside' | undefined (the user's own organization, when the account has one),
//          recipient: the reader's own mailbox name (the part before @), replaced by "your name" wherever
//                     it appears, so the model sees the trick ("READER! Apply…", a sender named after
//                     you) without ever seeing the name,
//          layout: ['images only' | 'text after a large blank gap'] (how the email hides its text),
//          mailChecks: kinds of headerAnomalies findings (AI_MAIL_CHECKS),
//          --- format 2 (phish-tiny 0.16.0): the facts a program's own checks already found, so the model
//          judges the words in context ---
//          auth: also { spf, dkim }: said only when they fail,
//          identity: { brand, owner, lookalike, colleague } who the sender's name claims to be and whether
//                    the domain is theirs, from the program's own sender checks (aiSenderIdentity):
//                    brand: the brand or agency the name claims ('' none); owner: 'yes' (the domain is
//                    the brand's) | 'no' | 'unsure' (not known to be) | 'personal' (a free mailbox);
//                    lookalike: the domain imitates a well-known brand; colleague: the name is someone
//                    in the organization's, on an outside address,
//          replyTo: addresses (or domains) replies go to; only those not the sender's own domain count,
//          attachments: [{ name, type }] (file name and MIME type; only their kind is said, never the name) }
// Capitals (a subject or text written in capitals) are found here, from the text itself: the model's
// tokenizer reads lower case, so it can't see them otherwise.
// ---------------------------------------------------------------------------------------------------
const AI_MAX_LINKS = 8;

const AI_EMAIL_RE = /\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b/g;
const AI_PHONE_RE = /(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{3}\)[\s.-]?|\b\d{3}[\s.-])\d{3}[\s.-]\d{4}\b/g;
const AI_LONG_NUMBER_RE = /\b\d[\d -]{5,}\d\b/g;

// Email addresses keep their domain (where mail comes from matters, who it is for doesn't); phone
// numbers and long numbers (accounts, cards, codes) are replaced by what they are.
function redactForAi(text) {
    return String(text || '')
        .replace(AI_EMAIL_RE, (m, local, domain) => `address at ${domain.toLowerCase()}`)
        .replace(AI_PHONE_RE, 'phone number')
        .replace(AI_LONG_NUMBER_RE, 'number');
}

// Tags that mail systems add to EVERY outside email ("[EXTERNAL] …", "EXT: …", "CAUTION: …"): they say
// nothing about phishing (both kinds carry them), so the model never sees them.
function stripExternalTag(subject) {
    let s = String(subject || '');
    for (let i = 0; i < 3; i++) s = s.replace(/^\s*(\[\s*(external|ext|caution|warning|outside sender|non-district|external sender)[^\]]{0,30}\]|\*{0,3}\s*(external|ext|caution)\s*\*{0,3}\s*:)\s*/i, '');
    return s.trim();
}

// What a mail system along the way already found in the headers (headerAnomalies kinds), in words.
const AI_MAIL_CHECKS = Object.freeze({
    'spam-flag': 'already marked as spam by a mail system', 'local-tool': 'sent with a home-made bulk-mail tool',
    'broken-to': 'broken to address', 'placeholders': 'unfilled template placeholders', 'markup': 'web code in address lines',
    'forged-received': 'forged delivery records', 'duplicate-headers': 'repeated headers', 'fake-signature': 'fake signature'
});
const AI_LAYOUTS = new Set(['images only', 'text after a large blank gap']);

// Format 2: the input format's version (model.json's inputFormat says which one a model reads).
const AI_INPUT_FORMAT = 2;

// Who the sender claims to be, in words (identity, from the program's sender checks).
const AI_IDENTITY_OWNER = Object.freeze({ yes: (b) => `the domain is ${b}'s`, no: (b) => `the domain is not ${b}'s`,
    unsure: (b) => `the domain is not known to be ${b}'s`, personal: () => 'sent from a personal mailbox' });
function identityLine(id) {
    if (!id || typeof id !== 'object') return '';
    const parts = [];
    const brand = String(id.brand || '').replace(/[^A-Za-z0-9&.' -]+/g, '').replace(/\s+/g, ' ').trim().slice(0, 40).trim();
    if (brand && AI_IDENTITY_OWNER[id.owner]) parts.push(`name claims ${brand}; ${AI_IDENTITY_OWNER[id.owner](brand)}`);
    if (id.lookalike) parts.push('the domain imitates a well-known brand');
    if (id.colleague) parts.push('the name is a colleague\'s but the address is outside');
    return parts.length ? `identity: ${parts.join('; ')}.` : '';
}

// Where replies go, when that isn't the sender's own domain (or one of its subdomains).
function replyToLine(replyTo, senderDomain) {
    const own = String(senderDomain || '').toLowerCase();
    const same = (d) => d === own || d.endsWith('.' + own) || own.endsWith('.' + d);
    const domains = [...new Set([].concat(replyTo || []).map(a => String(a || '').toLowerCase().trim().split('@').pop())
        .filter(d => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d) && !same(d)))].slice(0, 2);
    return domains.length ? `reply-to: goes to ${domains.join(', ')} (not the sender's domain).` : '';
}

// What kind of files are attached, from the file name's ending and the MIME type (never the name itself).
const AI_ATTACHMENT_KINDS = [
    ['program or script', /\.(exe|scr|com|bat|cmd|msi|js|jse|vbs|vbe|wsf|wsh|ps1|lnk|jar|hta|cpl|reg|apk|appx|msix)$/, /x-msdownload|x-msdos|x-executable|javascript|x-sh\b|java-archive|x-ms-shortcut|hta/],
    ['disk image', /\.(iso|img|vhdx?|dmg)$/, /iso9660|x-raw-disk|apple-diskimage/],
    ['archive', /\.(zip|rar|7z|gz|tgz|tar|cab|ace|arj|xz|bz2|z)$/, /zip|rar|7z|compressed|x-tar|gzip|x-xz|bzip/],
    ['macro document', /\.(docm|dotm|xlsm|xltm|xlsb|xlam|pptm|potm|ppsm)$/, /macroenabled/],
    ['web page', /\.(html?|shtml|xhtml|svgz?|mht|mhtml)$/, /html|svg|multipart\/related/],
    ['calendar invite', /\.ics$/, /calendar/],
    ['pdf', /\.pdf$/, /pdf/],
    ['spreadsheet', /\.(xlsx?|ods|csv|numbers)$/, /spreadsheet|ms-excel|csv/],
    ['document', /\.(docx?|dotx|odt|rtf|txt|pptx?|odp|pages|key)$/, /msword|wordprocessing|presentation|powerpoint|opendocument|rtf|text\/plain/],
    ['picture', /\.(png|jpe?g|gif|bmp|webp|heic|tiff?)$/, /^image\//],
    ['audio or video', /\.(mp3|wav|m4a|ogg|mp4|mov|avi|wmv|webm)$/, /^(audio|video)\//]
];
function attachmentKind(name, type) {
    const n = String(name || '').toLowerCase().replace(/[\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '').trim(), t = String(type || '').toLowerCase();
    for (const [kind, ext, mime] of AI_ATTACHMENT_KINDS) if (ext.test(n)) return kind;
    for (const [kind, ext, mime] of AI_ATTACHMENT_KINDS) if (t && mime.test(t)) return kind;
    return 'other file';
}
function attachmentsLine(attachments) {
    const kinds = [];
    for (const a of [].concat(attachments || []).slice(0, 20)) {
        if (!a || typeof a !== 'object') continue;
        const raw = String(a.name || '');
        kinds.push(attachmentKind(raw, a.type));
        // A name that hides its real type: text-direction characters, or a harmless ending before the real one
        // ("invoice.pdf.exe", "scan.pdf      .html").
        if (/[\u202a-\u202e\u2066-\u2069]/.test(raw) || /\.(pdf|docx?|xlsx?|jpe?g|png|txt)\s*\.[a-z0-9]{2,5}$/i.test(raw.trim())) kinds.push('a file name that hides its type');
    }
    const unique = [...new Set(kinds)].slice(0, 4);
    return unique.length ? `attachments: ${unique.join('; ')}.` : '';
}

// Text written in capitals (the tokenizer reads lower case, so the model is told).
function capitalsLayout(subject, body) {
    const ratio = (t) => { const letters = String(t || '').match(/\p{L}/gu) || []; const up = String(t || '').match(/\p{Lu}/gu) || []; return { n: letters.length, r: letters.length ? up.length / letters.length : 0 }; };
    const out = [], s = ratio(subject), b = ratio(body);
    if (s.n >= 8 && s.r > 0.8) out.push('subject in capitals');
    if (b.n >= 40 && b.r > 0.6) out.push('text mostly in capitals');
    return out;
}

// The reader's own mailbox name, wherever it appears, becomes "your name" (whole words only, and only
// names of 3 or more letters, so "al" in "also" stays).
function maskRecipient(text, recipient) {
    const r = String(recipient || '').trim().toLowerCase();
    if (r.length < 3) return String(text || '');
    const esc = r.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return String(text || '').replace(new RegExp(`(^|[^\\p{L}\\p{N}])${esc}(?=$|[^\\p{L}\\p{N}])`, 'giu'), '$1your name');
}

// format: the input format to build (AI_INPUT_FORMAT unless a program runs an older model; 1 has none of
// format 2's lines).
function modelInputParts(facts, format = AI_INPUT_FORMAT) {
    const f = facts || {};
    const v2 = format >= 2;
    const mask = (t) => maskRecipient(redactForAi(t), f.recipient);
    const addr = String(f.senderAddress || '').toLowerCase();
    const domain = addr.split('@')[1] || 'unknown';
    const head = [];
    head.push(`subject: ${mask(stripExternalTag(f.subject) || 'none').slice(0, 160)}.`);
    const where = f.org === 'inside' ? ' (your organization)' : f.org === 'outside' ? ' (outside your organization)' : '';
    head.push(`from: "${mask(f.senderName || '').slice(0, 80)}" at ${domain}${where}${typeof isSharedMailbox === 'function' && isSharedMailbox(addr) ? ' (shared mailbox)' : ''}.`);
    const checks = [...new Set((f.mailChecks || []).map(k => AI_MAIL_CHECKS[k]).filter(Boolean))].slice(0, 4);
    const idLine = v2 ? identityLine(f.identity) : '';
    if (idLine) head.push(idLine);
    // SPF and DKIM are said only when they fail (DMARC already sums up a pass).
    const fails = [];
    if (v2) {
        if (f.auth && /^(fail|softfail|permerror)$/.test(String(f.auth.spf || '').toLowerCase())) fails.push(`spf ${String(f.auth.spf).toLowerCase()}`);
        if (f.auth && /^(fail|permerror)$/.test(String(f.auth.dkim || '').toLowerCase())) fails.push(`dkim ${String(f.auth.dkim).toLowerCase()}`);
    }
    head.push(`sender check: ${f.auth && f.auth.dmarc ? `dmarc ${f.auth.dmarc}` : 'unknown'}${fails.length ? `; ${fails.join('; ')}` : ''}${checks.length ? `; ${checks.join('; ')}` : ''}.`);
    const rtLine = v2 ? replyToLine(f.replyTo, domain) : '';
    if (rtLine) head.push(rtLine);
    const links = (f.links || []).slice(0, AI_MAX_LINKS).map(l => {
        const text = mask(String(l.text || '').trim()).slice(0, 40) || 'image';
        const dest = l.destHost && l.destHost !== l.host ? `${l.host} then ${l.destHost}` : (l.host || 'unknown');
        return `"${text}" goes to ${dest}${l.finding ? ` (warning: ${redactForAi(l.finding).slice(0, 80)})` : ''}`;
    });
    head.push(links.length ? `links: ${links.join('; ')}.` : 'links: none.');
    const attLine = v2 ? attachmentsLine(f.attachments) : '';
    if (attLine) head.push(attLine);
    const layout = [...new Set([...(f.layout || []).filter(x => AI_LAYOUTS.has(x)), ...(v2 ? capitalsLayout(stripExternalTag(f.subject), f.bodyText) : [])])];
    if (layout.length) head.push(`layout: ${layout.join('; ')}.`);
    const body = mask(String(f.bodyText || '')).replace(/\s+/g, ' ').trim();
    return { head: head.join(' '), sentences: splitSentences(body) };
}

// Sentences (and line-like fragments), for the explanation; kept in order.
function splitSentences(text) {
    // Only at an end mark followed by a space, so addresses (www.example.com) and numbers stay whole.
    return String(text || '').split(/(?<=[.!?])\s+/).map(s => s.trim()).filter(s => s.length > 1).slice(0, 60);
}

function modelInputText(facts, format = AI_INPUT_FORMAT) {
    const p = modelInputParts(facts, format);
    return `${p.head} text: ${p.sentences.join(' ')}`;
}

// ---------------------------------------------------------------------------------------------------
// WordPiece tokenizer, as BERT's uncased tokenizer (lower case, accents removed, punctuation split).
// ---------------------------------------------------------------------------------------------------
function isBertPunct(ch) {
    const c = ch.codePointAt(0);
    if ((c >= 33 && c <= 47) || (c >= 58 && c <= 64) || (c >= 91 && c <= 96) || (c >= 123 && c <= 126)) return true;
    return /\p{P}/u.test(ch);
}

class WordPiece {
    constructor(vocabText) {
        this.vocab = new Map();
        String(vocabText).split('\n').forEach((t, i) => { const w = t.replace(/\r$/, ''); if (w && !this.vocab.has(w)) this.vocab.set(w, i); });
        this.unk = this.vocab.get('[UNK]'); this.cls = this.vocab.get('[CLS]'); this.sep = this.vocab.get('[SEP]');
    }
    basic(text) {
        let t = '';
        for (const ch of String(text)) {
            const c = ch.codePointAt(0);
            if (c === 0 || c === 0xfffd || (/\p{Cc}|\p{Cf}/u.test(ch) && !/[\t\n\r]/.test(ch))) continue;
            // CJK ideographs become words of their own, as in BERT
            if ((c >= 0x4E00 && c <= 0x9FFF) || (c >= 0x3400 && c <= 0x4DBF) || (c >= 0x20000 && c <= 0x2A6DF) || (c >= 0xF900 && c <= 0xFAFF)) { t += ` ${ch} `; continue; }
            t += /\s/.test(ch) ? ' ' : ch;
        }
        t = t.toLowerCase().normalize('NFD').replace(/\p{Mn}/gu, '');
        const out = [];
        for (const word of t.split(/\s+/).filter(Boolean)) {
            let cur = '';
            for (const ch of word) {
                if (isBertPunct(ch)) { if (cur) out.push(cur); out.push(ch); cur = ''; } else cur += ch;
            }
            if (cur) out.push(cur);
        }
        return out;
    }
    wordpiece(word) {
        if ([...word].length > 100) return [this.unk];
        const ids = [];
        let start = 0;
        while (start < word.length) {
            let end = word.length, found = null;
            while (start < end) {
                const piece = (start > 0 ? '##' : '') + word.slice(start, end);
                if (this.vocab.has(piece)) { found = this.vocab.get(piece); break; }
                end--;
            }
            if (found === null) return [this.unk];
            ids.push(found);
            start = end;
        }
        return ids;
    }
    // [CLS], the text's word pieces, [SEP], at most maxLen. A longer text keeps its first maxLen - 2 pieces, or,
    // with head (model.json config.headTokens, phish-tiny 0.20.0 and later), its first `head` and its last
    // maxLen - 2 - head, so that what a long email asks at its end is read too (training's cut_ids does the same).
    encode(text, maxLen, head = 0) {
        const room = maxLen - 2, pieces = [];
        for (const w of this.basic(text)) {
            for (const id of this.wordpiece(w)) { pieces.push(id); if (!head && pieces.length >= room) break; }
            if (!head && pieces.length >= room) break;
        }
        const kept = pieces.length <= room ? pieces : head ? pieces.slice(0, head).concat(pieces.slice(pieces.length - (room - head))) : pieces.slice(0, room);
        return [this.cls, ...kept, this.sep];
    }
}

// ---------------------------------------------------------------------------------------------------
// The network itself runs in the native engine since 0.5.0 (src/engine/model.js: ONNX Runtime, the model
// file models/phish-tiny/model.onnx made by TinyPhishLLM's training/export-onnx.py). This file keeps what comes before it:
// the input text (modelInputParts) and the tokenizer (WordPiece), the same as in training.
// ---------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------
// What the person is told. Never "safe": a low probability is "no strong signs found", and when the
// extension's own checks warn, they are named as the ones to trust. Text that vouches for itself is
// a warning however the model scored it. Returns { level: 'danger'|'caution'|'info', headline, note }.
// ---------------------------------------------------------------------------------------------------
function aiAdvice(result, extensionStatus, vouching) {
    const ownWarns = extensionStatus === 'flagged' || extensionStatus === 'caution';
    const keepOwn = ownWarns ? 'The extension\'s own checks also warn about this email; they rest on verified facts, so trust them over the model.' : '';
    const pct = Math.min(99, Math.round(((result && result.probability) || 0) * 100));   // no model is ever 100% sure
    const v = (vouching || []).sort((a, b) => b.weight - a.weight)[0];
    if (v && v.weight >= 5) return { level: 'danger', headline: 'This email tries to talk to AI tools and filters.', note: `${v.text} ${keepOwn}`.trim() };
    // A safety claim is only a small weight in the extension's own verdict: here it is mentioned when the
    // model warns anyway, and never makes a warning of its own.
    if (pct >= 85) return { level: 'danger', headline: `The model thinks this is likely phishing (${pct}%).`, note: `${v ? v.text + ' ' : ''}${keepOwn}`.trim() };
    if (pct >= 50) return { level: 'caution', headline: `The model finds this email suspicious (${pct}%).`, note: `${v ? v.text + ' ' : ''}${keepOwn}`.trim() };
    return { level: 'info', headline: `The model found no strong signs of phishing (${pct}%).`,
             note: keepOwn || 'That is an opinion, not a check: phishing can look ordinary. Still be careful with links, attachments and requests for money or passwords.' };
}

