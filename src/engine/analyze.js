'use strict';
// One email → the extension's verdict (the same signals and weights: caution at 3, flagged at 5) and
// the AI model's opinion. Nothing is stored here.
//
// Offline, as in the extension: its decoders unwrap gateway and tracker links, and
// detectLinkProblem/linkProblemSeverity find look-alike domains, mismatched link text, raw IP
// addresses and the like. With ctx.intel (src/intel; network.js applies it): Cloudflare Security DNS,
// Google Safe Browsing, the phishing lists, Spamhaus, registry dates and (0.5.64) whose a sender's domain
// is. Short links are NOT looked up (no unshorten.me or similar service): a short link is judged by its own
// host and what decodes offline.
// Also here: the links and QR codes in attachments (attachments.js), platform notifications and outside shares
// (notifications.js), fake reply chains (replychain.js), a colleague's name on an outside address
// (colleagueWithTitle, colleagueInContext), the look-alike watch's domains and mail dressed up as from inside.
const spruce = require('./spruce');
const { detectLanguage } = require('./language');
const N = require('./notifications');
const { fakeReplySigns } = require('./replychain');
const { readAttachments } = require('./attachments');
const { networkChecks } = require('./network');

const MAX_LINKS = 300;

function hostOf(u) { try { return new URL(u).hostname.toLowerCase(); } catch (e) { return ''; } }

// Each link (at most MAX_LINKS) as the extension judges it offline: code-running schemes (javascript:, data:…)
// are dangerous at once; web links are unwrapped (gateways, trackers) and checked for a problem, and a page on a
// cloud-storage site is a caution. Other schemes (mailto:, tel:) are skipped. network.js may flag them further.
async function judgeLinks(E, links) {
    const out = [];
    for (const l of links.slice(0, MAX_LINKS)) {
        const href = String(l.href || '');
        const scheme = (/^\s*([a-z][a-z0-9+.-]*):/i.exec(href) || [])[1];
        if (scheme && /^(javascript|vbscript|data|file)$/i.test(scheme)) {
            out.push({ text: l.text, url: href.slice(0, 200), finalUrl: '', severity: 'danger', reason: `link runs code or opens hidden content (${scheme.toLowerCase()}:)` });
            continue;
        }
        if (!/^https?:\/\//i.test(href)) continue;                         // mailto:, tel:, anchors
        let finalUrl = href;
        try { finalUrl = (await E.unwrapNestedUrl(href, false, { redirectorSet: new Set() })).unwrappedUrl || href; } catch (e) { /* kept as it is */ }
        let reason = null;
        try { reason = E.detectLinkProblem(l.text || '', href, finalUrl, E.builtinTrackers, {}); } catch (e) { reason = null; }
        let severity = reason ? E.linkProblemSeverity(reason) : null;
        if (!reason) { const cloud = E.cloudStoragePage(finalUrl); if (cloud) { reason = cloud.reason; severity = 'caution'; } }
        out.push({ text: l.text, url: href, finalUrl, severity, reason, hidden: !!l.hidden, from: l.from || undefined });
    }
    return out;
}

// The extension's emailContentSignals: links flagged dangerous (hidden links not counted). 5 when two or more,
// or every link, are dangerous; else 3.
// (0.6.25) The links sign has one weight however many links are flagged, set by the worst of them:
//   5  a link's site is blocked or on a phishing list (j.network), or the link is evidence on its own: code to run
//      (javascript:, data:), a look-alike of a brand's domain, or a name hidden before an "@" in its address;
//   3  a link's site has a low reputation: registered in the last 90 days, or on Spamhaus's lists (j.lowRep, network.js);
//   2  links flagged only by their own text (a well-known site's name on a link to another site), nothing known
//      against their sites: newsletters and marketing mail link through other companies' domains.
// Before 0.6.25: 3 for one dangerous link, 5 for two or more or when every link was.
const OWN_EVIDENCE_RE = /^look-alike domain|username\/password|^link runs code/;
function linkSignals(judged) {
    const web = judged.filter(j => !j.hidden);
    const danger = web.filter(j => j.severity === 'danger');
    if (!danger.length) return [];
    const bad = danger.filter(j => j.network || OWN_EVIDENCE_RE.test(String(j.reason || '')));
    const low = danger.filter(j => j.lowRep);
    const worst = bad.length ? bad : low.length ? low : danger;
    const weight = bad.length ? 5 : low.length ? 3 : 2;
    const why = [...new Set(worst.map(d => String(d.reason || '').replace(/\.$/, '')))].slice(0, 2).join('; ');
    const n = danger.length, total = web.length;
    const count = n === total ? (n === 1 ? 'Its only link is' : `All ${n} of its links are`) : `${n} of its ${total} links ${n === 1 ? 'is' : 'are'}`;
    const tail = bad.length ? '' : low.length ? ' Its site is new or has a low reputation.' : ' Nothing is known against the site (not blocked, listed or new), so it counts 2.';
    return [{ weight, kind: 'dangerous-links', text: `${count} flagged as dangerous${why ? ` (${why})` : ''}.${tail}` }];
}

// (0.5.64) Whose the sender's domain is (src/intel/ownership.js), only when the sender's name claims a brand
// whose known domains don't include it; null otherwise, on a failure, or after OWNERSHIP_WAIT_MS.
const OWNERSHIP_WAIT_MS = 6000;
async function senderOwnership(E, facts, intel) {
    if (!intel || !intel.ownership) return null;
    const domain = String(facts.senderAddress || '').toLowerCase().split('@')[1] || '';
    let claimed = null;
    try { claimed = E.displayNameBrand(facts.senderName, facts.senderAddress); } catch (e) { claimed = null; }
    if (!domain || !claimed || E.senderDomainOwnedBy(claimed, domain)) return null;
    let timer;
    const late = new Promise(r => { timer = setTimeout(() => r(null), OWNERSHIP_WAIT_MS); });
    try { return await Promise.race([intel.ownership.of(domain, claimed.name), late]); } catch (e) { return null; } finally { clearTimeout(timer); }
}

// Whether Gmail's own DMARC check passed for the sender's domain (the domain in From, which anyone can
// write). Only then does the address count for the allowlist or as "inside the organization". (0.6.3) For the
// organization's own domains, a pass worked out from Gmail's SPF or DKIM results when it wrote no DMARC result
// counts too (mime.js deriveDmarc).
// (0.6.51) The domain Gmail checked (header.from) is the sender's, or its organization's as DMARC itself compares them
// (relaxed alignment: Gmail can name crews.bank for mail from mail.crews.bank). Another organization's (a second From
// line written to fool the reader) is still no pass for the sender.
function sameOrgDomain(a, b) {
    const x = String(a || '').toLowerCase(), y = String(b || '').toLowerCase();
    if (!x || !y) return false;
    if (x === y) return true;
    const E = spruce.load();
    const rx = E.registrableDomain(x) || x, ry = E.registrableDomain(y) || y;
    return rx === ry;
}
// (0.6.65) The header signs Settings → Policy → Skip review reads (shared.js headerAnomalies).
const FORGED_HEADER_KINDS = new Set(['forged-message-id', 'forged-received', 'duplicate-headers']);
const SPAM_HEADER_KINDS = new Set(['spam-flag', 'placeholders', 'local-tool']);
function senderVerified(facts) {
    const a = facts && facts.auth;
    const domain = String((facts && facts.senderAddress) || '').toLowerCase().split('@')[1] || '';
    return !!(a && a.dmarc === 'pass' && domain && (!a.headerFrom || sameOrgDomain(a.headerFrom, domain)));
}

// facts: from mime.readMessage. ctx: { mailbox (the recipient's address), orgDomains: [..], trusted: bool,
// selfNameHash: the recipient's own name's colleagueNameHash (never counted as a colleague named), shareReach:
// how many of the organization's people the same outside account shared with this hour (pipeline.js),
// firstTime: bool (first email from this address anywhere in the organization, after the learning period),
// keepAiFacts: bool (the answer also has what the model read, for the retraining export),
// colleagues: Set of colleagueNameHash values (the organization's people), or null,
// aiInside: bool (the AI model also reads mail from inside the organization; off: the rules alone do),
// intel: src/intel (null: no network checks), allowLinkDomains: the allowed link domains (network.js, 0.5.73),
// threadSize: the Gmail thread's size (replychain.js), lookalikes: Map domain → 'strong' | 'weak' (the look-alike
// watch), readAttachments: false to skip the attachments,
// (0.6.85, for the AI's next input format: src/context-facts.js) extraFacts: what the pipeline knew before the checks
// (Gmail's category, the unsubscribe marker, the conversation, how many of your people got it), standingDoc: the sender's
// standing record (null: none; undefined: not read), firstSeenAt: when the address first wrote to the organization,
// readPictures: also read the words in pictures (OCR; the retraining export) }
async function analyze(facts, ctx = {}) {
    const E = spruce.load();
    const mailbox = String(ctx.mailbox || '').toLowerCase();
    const senderDomain = (facts.senderAddress.split('@')[1] || '').toLowerCase();
    // (0.5.59) The organization's domain an address is in (any of them), else its first: the checks that take one
    // domain (whether the sender is outside, a colleague's name on an outside address) read every domain the
    // organization has, not only the first (mail between two of its own domains was "outside").
    const ownOf = (address) => { const d = String(address || '').toLowerCase().split('@').pop(); return (d && (ctx.orgDomains || []).find(o => E.isOwnDomain(d, o))) || (ctx.orgDomains || [])[0] || ''; };
    const org = ownOf(facts.senderAddress);
    // An address in the organization's own domains (as the extension sees it, for the model); "inside"
    // for the policy only when DMARC passed: a forged staff address is mail from outside.
    const ownAddress = !!senderDomain && (ctx.orgDomains || []).some(d => E.isOwnDomain(senderDomain, d));
    const verified = senderVerified(facts);
    const inside = ownAddress && verified;
    // A platform's notification for a person, and a share from outside (notifications.js).
    const relay = N.platformNotification(facts, ctx.orgDomains || []);
    const share = N.shareSource(facts, ctx.orgDomains || []);
    // A notification's note (the sharer's own message) can be set apart as a quotation: the text checks read it.
    const bodyText = relay ? `${facts.visibleText}\n${facts.quotedText || ''}` : facts.visibleText;
    // Attachments and pictures (0.5.34): QR codes and links in them are checked like the email's own links.
    // (0.5.64) A sender's name claiming a brand whose domain list doesn't have the sender's domain ("Xoom, a PayPal
    // Service" from service.xoom.com): whose the domain is comes from public records (src/intel/ownership.js), as in
    // the extension; at most OWNERSHIP_WAIT_MS, else judged as before. (0.6.7) Started now, beside the other lookups
    // (it needs only the sender): it waited for them first, up to 6 s more for an email whose name claims a brand.
    const ownershipP = relay ? Promise.resolve(null) : senderOwnership(E, facts, ctx.trusted ? null : (ctx.intel || null)).catch(() => null);
    // (0.6.86) A model that reads input format 4 is given the words in the email's pictures when the email is only pictures
    // (html.js "images only", or almost no text and a picture attached): read here (OCR, src/engine/ocr.js), never stored.
    // Pictures the email only links to are never fetched (that would tell the sender it was read). A format-3 model: only
    // the retraining export reads pictures (readPictures).
    const modelFormat = (E.model && E.model.meta && E.model.meta.inputFormat) || 1;
    const pictureOnly = (facts.layout || []).includes('images only')
        || (String(facts.visibleText || '').replace(/\s+/g, '').length < 60 && (facts.attachmentFiles || []).some(a => /^image\/(png|jpe?g)/i.test(String(a.type || ''))));
    const readPictures = !!ctx.readPictures || (modelFormat >= 4 && pictureOnly && !(inside && !ctx.aiInside));
    const att = ctx.readAttachments === false ? { links: [], signals: [], found: [], skipped: 0 }
        : await readAttachments(facts.attachmentFiles || [], { outside: !inside, readPictures }).catch(() => ({ links: [], signals: [], found: [], skipped: 0 }));
    const judged = await judgeLinks(E, [...(facts.links || []), ...att.links]);
    // The network checks (they may flag links, so they come before the link signs are counted).
    // Allowlisted senders (ctx.trusted) are never moved, so their mail costs no lookups (nor the ownership one).
    const net = await networkChecks(E, ctx.trusted ? null : (ctx.intel || null), facts, judged, Object.assign({}, ctx, { orgDomains: ctx.orgDomains || [] }))
        .catch(() => ({ signals: [], checks: { failed: true } }));
    const allText = `${facts.subject}\n${facts.visibleText}\n${facts.hiddenText}`;
    const ownership = await ownershipP;
    const safe = (f) => { try { return f() || []; } catch (e) { return []; } };
    const safeOne = (f) => { try { return f(); } catch (e) { return null; } };
    const headerSigns = safe(() => E.headerAnomalies(facts.rawForHeaders, mailbox, E.gmailReceiver));
    const signals = [
        ...headerSigns,
        ...safe(() => E.displayNameAnomalies(facts.senderName)),
        // (0.5.49) A sender's name naming one platform, sent from another's domain (or from no platform's).
        ...safe(() => N.platformClaimSigns(E, facts)),
        // ctx.colleagues: one-way hashes of the organization's people's names (Service.colleagueNames).
        // A platform's notification for a person (Classroom, a Drive share, DocuSign…: notifications.js) is
        // judged by the person's own address, never by the platform's (0.5.16); any other email by its own.
        ...safe(() => (relay ? N.relaySigns(E, relay, ctx.colleagues || null) : E.nameAddressSigns(facts.senderName, facts.senderAddress, org, ctx.colleagues || null, ownership, { dmarc: (facts.auth && facts.auth.dmarc) || '', dmarcPassFor: facts.auth && facts.auth.dmarc === 'pass' ? (facts.auth.headerFrom || '') : '', brandSenders: ctx.brandSenders || null }))),
        // The same names in the other address lines: replies going to an outside address under a
        // colleague's name, a colleague copied in at an outside or look-alike address (0.5.14). A
        // notification's Reply-To is the person themselves.
        ...safe(() => E.colleagueLineSigns(addressLinePeople(facts), ctx.orgDomains || [], ctx.colleagues || null, (relay && relay.address) || facts.senderAddress)),
        // A colleague named in an outside share's subject or text ("Dana Madeup asked me to share…").
        ...safe(() => (share ? N.colleagueMentionSigns(E, { subject: facts.subject, text: bodyText,
            colleagues: ctx.colleagues || null, selfHash: ctx.selfNameHash || '', exclude: [relay ? relay.name : facts.senderName], orgDomains: ctx.orgDomains || [] }) : [])),
        ...(share ? N.shareLureSigns(`${facts.subject}\n${bodyText}`) : []),
        ...N.massShareSigns(share ? Number(ctx.shareReach) || 0 : 0),
        ...safe(() => E.ownNameSigns(facts.senderName, facts.senderAddress, mailbox)),
        ...insideSpoofSigns(E, facts, ctx.orgDomains || [], ownAddress, verified),
        ...safe(() => E.subjectScamSigns(facts.subject)),
        ...safe(() => E.bodyScamSigns(bodyText)),
        // (0.6.18) A security-software bill with a number to call, from a free mail account: the callback scam.
        ...safe(() => (relay ? [] : E.freeMailBillSigns(facts.subject, bodyText, facts.senderAddress, E.isPersonalMailDomain))),
        ...safe(() => E.selfVouchingSigns(allText)),
        ...safe(() => E.layoutSigns(facts.layout)),
        ...safe(() => E.highRiskRequestSigns(bodyText)),
        // "RE:" from outside or a new sender, answering nothing this mailbox has (0.5.33). Not a platform's
        // notification (a share is never a reply). ctx.threadSize: the Gmail thread's size (pipeline.js).
        ...safe(() => (relay ? [] : fakeReplySigns(facts, { threadSize: ctx.threadSize == null ? null : Number(ctx.threadSize), outside: !inside, firstTime: !!ctx.firstTime }))),
        // Outside, and first time: for a notification, the person's (none when the notification doesn't say who).
        ...safe(() => (relay ? (relay.address ? E.senderContextSigns(relay.address, ownOf(relay.address), !!ctx.firstTime) : []) : E.senderContextSigns(facts.senderAddress, org, !!ctx.firstTime))),
        ...linkSignals(judged),
        ...att.signals,
        ...net.signals,
        // A look-alike of the organization's domain that the look-alike watch found registered (0.5.36):
        // ctx.lookalikes, domain → 'strong' (new, or marked a threat) or 'weak' (there before the watch).
        ...safe(() => watchedLookalikeSigns(E, facts, judged, ctx.lookalikes)),
        // (0.6.32) The organization's own domain written inside another domain, and a hidden decoy link.
        ...safe(() => orgDomainInsideSigns(E, facts, judged, ctx.orgDomains || [])),
        ...safe(() => hiddenDecoyLinkSigns(E, judged, facts, verified))
    ];
    // A colleague's name with a title or the organization's name added ("Misty Samplefield, Principal", "Misty
    // Samplefield - Maple Schools"), which impersonators write and the exact match misses (0.5.43).
    if (!relay) safe(() => colleagueWithTitle(E, facts, signals, ctx));
    // A colleague's name on an outside address counts only when the email claims to be from inside (0.5.43).
    safe(() => colleagueInContext(E, facts, signals, ctx, bodyText));
    // (0.6.19) A partner's name for a brand's program counts again when the sender's domain is new; signs that count
    // only together with others; and padded list mail, which is spam rather than phishing.
    safe(() => partnerNameInContext(signals));
    // (0.6.20) A brand's name on an established company's own domain that sends about the brand's product it runs.
    safe(() => establishedSenderInContext(E, facts, judged, signals, verified));
    const spam = safeOne(() => signsNeedingCompany(signals, facts, inside, { verified, senderAge: net.senderAge }));
    const base = { status: ctx.trusted ? 'trusted' : 'clean', reasons: [], move: false };
    const verdict = E.applyEmailSignals(base, signals) || base;
    // What confirms it from outside the email's own text: a link a security service blocks or a
    // phishing list has, a sender on a list or blocked, a brand-new look-alike sender domain, a sender or
    // reply address the look-alike watch found newly registered, or Gmail's DMARC check failing. Rules
    // (flagged) plus one of these is "strong" evidence (the brakes never hold it).
    const SENDER_CONFIRMS = new Set(['scam-sender-list', 'sender-domain-blocked', 'sender-domain-listed', 'young-lookalike-sender']);
    const WATCH_CONFIRMS = new Set(['watched-lookalike-sender', 'watched-lookalike-reply-to']);
    const confirmedBy = [
        signals.some(s => WATCH_CONFIRMS.has(s.kind)) ? 'the sender or the reply address is a newly registered look-alike of your domain' : '',
        judged.some(j => j.network && j.severity === 'danger') ? 'a link is blocked or on a phishing list' : '',
        net.signals.some(s => SENDER_CONFIRMS.has(s.kind)) ? 'the sender is on a list, blocked, or a new look-alike' : '',
        facts.auth && facts.auth.dmarc === 'fail' ? 'Gmail\'s DMARC check failed' : ''
    ].filter(Boolean);

    // The model reads what the extension gives it for an opened email (modelInputParts in ai.js).
    const aiFacts = {
        subject: facts.subject, senderName: facts.senderName, senderAddress: facts.senderAddress,
        org: (ctx.orgDomains || []).length ? (ownAddress ? 'inside' : 'outside') : undefined,
        auth: facts.auth ? { dmarc: facts.auth.dmarc, spf: facts.auth.spf || undefined, dkim: facts.auth.dkim || undefined } : null,
        // Input format 2 (phish-tiny 0.16.0; a format-1 model doesn't read them): what the sender checks found,
        // so the model judges the words in context. Who the sender's name claims to be and whether the domain
        // is theirs, a look-alike domain, a colleague's name on an outside address (the same checks as
        // nameAddressSigns); the Reply-To domains that aren't the sender's; the attached files' kinds (their
        // endings and types, never their names; pictures inside the email aren't attachments).
        identity: safeOne(() => E.aiSenderIdentity(facts.senderName, facts.senderAddress, { own: ctx.orgDomains || [], colleagues: ctx.colleagues || null, dmarcPassFor: facts.auth && facts.auth.dmarc === 'pass' ? (facts.auth.headerFrom || '') : '', brandSenders: ctx.brandSenders || null })),
        replyTo: safeOne(() => E.aiReplyToDomains(facts.replyTo || [], facts.senderAddress)) || [],
        attachments: safeOne(() => E.aiAttachmentFacts((facts.attachmentFiles || facts.attachments || []).filter(a => !a.inline))) || [],
        links: judged.filter(j => !j.hidden).slice(0, 8).map(j => ({ text: j.text, host: hostOf(j.url), destHost: j.finalUrl && hostOf(j.finalUrl) !== hostOf(j.url) ? hostOf(j.finalUrl) : '', finding: j.severity ? j.reason : '' })),
        // (0.5.55) At most 8,000 characters: a longer text keeps its first 6,000 and its last 2,000, since the model
        // (since phish-tiny 0.20.0) reads a long email's start and its end.
        bodyText: (t => t.length > 8000 ? `${t.slice(0, 6000)}\n${t.slice(-2000)}` : t)(String(facts.visibleText || '')),
        recipient: mailbox.split('@')[0] || '',
        layout: facts.layout || [],
        mailChecks: headerSigns.map(s => s.kind).filter(Boolean)
    };
    // (0.6.56) A Reply-To domain public records prove the sender's own company's (ownership.js sameOwner:
    // synchronyfinancial.com for synchronybank.com), from a sender Gmail confirmed: not "replies go elsewhere" for the AI;
    // one note. And a brand's name the rules accepted as that company writing about its own product
    // (establishedSenderInContext: "PayPal Credit" from the bank that issues it) isn't given to the AI as an imitation.
    if (verified && aiFacts.replyTo.length && ctx.intel && ctx.intel.ownership && ctx.intel.ownership.sameOwner) {
        const senderDom = String(facts.senderAddress || '').toLowerCase().split('@')[1] || '';
        const keep = [];
        for (const d of aiFacts.replyTo.slice(0, 3)) {
            let timer;
            const late = new Promise(r => { timer = setTimeout(() => r(null), OWNERSHIP_WAIT_MS); });
            const p = await Promise.race([ctx.intel.ownership.sameOwner(senderDom, d), late]).catch(() => null).finally(() => clearTimeout(timer));
            if (p && p.state === 'owned') signals.push({ weight: 0, kind: 'same-owner-reply-to', text: `Replies go to ${d}, which belongs to the same company as the sender's domain, as public records prove (${p.how}). Not counted.` });
            else keep.push(d);
        }
        aiFacts.replyTo = keep.concat(aiFacts.replyTo.slice(3));
    }
    // (0.6.85) What the service knows beyond the email's text (src/context-facts.js): for the next input format (format 4);
    // a format-3 model doesn't read aiFacts.extra, so nothing it decides changes. The documents' and pictures' words only go
    // to the retraining export (aiFacts, with keepAiFacts); the record keeps the rest (extraFacts: labels and counts).
    const linkUrls = [...new Set(judged.flatMap(j => [j.url, j.finalUrl]).filter(Boolean))].slice(0, 80);
    const extraFacts = safeOne(() => {
        const CF = require('../context-facts');
        // (what the caller already knew wins: the retraining export passes the facts as they were on arrival)
        const out = CF.checkFacts(E, facts, { linkUrls }, { standingDoc: ctx.standingDoc, firstSeenAt: ctx.firstSeenAt, now: ctx.now || Date.now(), senderAge: net.senderAge });
        for (const [k, v] of Object.entries(ctx.extraFacts || {})) if (v !== null && v !== undefined) out[k] = v;
        return CF.cleanContext(out);
    });
    aiFacts.extra = Object.assign({}, extraFacts || {}, ctx.keepAiFacts || modelFormat >= 4 ? { attachmentText: att.attachmentText || '', pictureText: att.pictureText || '' } : {});
    if (aiFacts.identity && signals.some(s => s && s.kind === 'brand-name-likely' && s.weight === 0 && /counts as that company writing about a product it runs/.test(String(s.text || '')))) aiFacts.identity = null;
    // The model was trained on English only: on an email clearly in another language its score means little,
    // so it gives none, and says why (the rule checks above don't depend on the language).
    const language = detectLanguage(`${facts.subject}\n${facts.visibleText}`);
    let ai = null;
    if (inside && !ctx.aiInside) {
        // Mail from inside the organization (your domains, DMARC passing) isn't read by the AI unless the
        // policy says so (AI_SCANS_INSIDE): the rules above (its links, headers and the rest) read it.
        ai = { probability: null, skipped: 'inside', model: `${E.modelInfo.name} ${E.modelInfo.version}` };
    } else if (providerBounce(E, facts, verified)) {
        // (0.6.22) A delivery report from a mail provider's own mail system: the AI reads its failure wording as a
        // lure. The rule checks read it as usual (the returned copy's links and attachments too).
        ai = { probability: null, skipped: 'bounce', model: `${E.modelInfo.name} ${E.modelInfo.version}` };
    } else if (!language.english) {
        ai = { probability: null, skipped: 'language', language: language.name, model: `${E.modelInfo.name} ${E.modelInfo.version}` };
    } else {
        try {
            const r = await E.model.analyze(aiFacts);
            // (0.6.55) spam: P(spam), a business's bulk marketing (wanted or not) that isn't phishing; null from a model
            // without a spam answer. The policy's spam rules read it (policy.js aiSpamOf).
            ai = { probability: r.probability, spam: typeof r.spam === 'number' ? r.spam : null, reasons: r.reasons.map(x => ({ sentence: x.sentence, facts: !!x.facts })), model: `${r.model} ${r.version}` };
        } catch (e) {
            ai = { probability: null, error: String(e && e.message || e), model: `${E.modelInfo.name} ${E.modelInfo.version}` };
        }
    }
    return {
        status: verdict.status,
        score: typeof verdict.score === 'number' ? verdict.score : signals.reduce((a, s) => a + (s.weight || 0), 0),
        signals: signals.map(s => ({ weight: s.weight, kind: s.kind || null, text: s.text })),
        links: judged.filter(j => j.severity).slice(0, 20).map(j => ({ url: j.url.slice(0, 300), finalUrl: String(j.finalUrl || '').slice(0, 300), severity: j.severity, reason: j.reason, from: j.from || undefined })),
        linkCount: judged.length,
        // Every link's address and where it leads (in memory only): the re-check index (src/recheck.js).
        linkUrls,
        // (0.6.85) The facts for the AI's next input format, never content (src/context-facts.js cleanContext).
        extraFacts: extraFacts || null,
        // What the attachment checks found (0.5.34): file names and what was in them (a host, a sign), no content.
        attachmentFindings: att.found, attachmentsSkipped: att.skipped || 0,
        checks: net.checks,
        inside,
        ownAddress,
        verified,
        // (0.6.40) A platform's notification (a share, an invitation): DMARC confirms the platform, not the person behind it.
        platformNote: relay ? true : undefined,
        confirmedBy,
        strong: verdict.status === 'flagged' && confirmedBy.length > 0,
        // (0.6.59; 0.6.65 Settings → Policy → Skip review) What policy.js strictWhy reads: Gmail's DMARC result for the sender
        // ('fail'; 'missing' when Gmail checked the email but confirmed no DMARC policy; null when it passed or Gmail's check
        // isn't there), forged headers (a forged message ID, Received lines copied from other emails, From or Subject
        // repeated), spam headers (another mail system's spam flag, a bulk mailer's unfilled placeholders, a home-made mailer
        // pointing at its own computer), the sender on a threat list or blocked, and a link flagged dangerous.
        strictSigns: {
            dmarc: !facts.auth ? null : facts.auth.dmarc === 'fail' ? 'fail' : facts.auth.dmarc === 'pass' ? null : 'missing',
            forgedHeaders: [...new Set(signals.filter(s => FORGED_HEADER_KINDS.has(s.kind)).map(s => s.kind))],
            spamHeaders: [...new Set(signals.filter(s => SPAM_HEADER_KINDS.has(s.kind)).map(s => s.kind))],
            senderListed: net.signals.some(s => s.kind === 'scam-sender-list' || s.kind === 'sender-domain-blocked' || s.kind === 'sender-domain-listed'),
            dangerousLinks: judged.some(j => j.severity === 'danger')
        },
        // (0.6.19) Spam, not phishing: moved to Spam by the policy (trigger 'spam') when nothing else is wrong.
        spam: spam || undefined,
        ai,
        language: { code: language.code, name: language.name, english: language.english },
        // Only for the retraining export (src/training.js), which takes the people out: never stored.
        aiFacts: ctx.keepAiFacts ? aiFacts : undefined
    };
}

// colleagueInContext: a colleague's name on an outside address (the engine's nameAddressSigns, 3) counts only
// when something in the email claims to be from inside the organization (0.5.43). People share names: a vendor's Misty
// Smith writing from her company's own address with a greeting is no impersonation. It counts when it is
// written from a personal email account, from an address imitating the organization's domain or a
// brand-new domain, with Gmail's sender check failing, with replies going elsewhere, with a title or the
// organization's name in the sender's name, or asking what an impersonator asks (a favor, a phone number,
// gift cards, payment or payroll details, codes or passwords). Otherwise it stays, with no weight, saying
// why it doesn't count. Changes signals in place.
const COLLEAGUE_SIGN = 'The sender uses the name of someone in your organization, but writes from an outside address';
const INSIDE_TITLE_RE = /\b(superintendent|principal|director|coordinator|supervisor|chief|cfo|ceo|coo|president|treasurer|business office|finance|payroll|human resources|hr|board (?:member|chair)|dean|head of|manager|administrator)\b/i;
const IMPERSONATOR_RE = /\b(are you (?:available|around|free|at your desk)|quick (?:favou?r|task|request|question)|i(?:'m| am) (?:in a meeting|on a call|in a conference|travel+ing|busy right now)|can'?t (?:talk|take (?:a )?calls?)|text me|(?:cell|mobile|personal) (?:phone )?(?:number|no\.?)|gift ?cards?|itunes cards?|google play cards?|direct deposit|payroll|bank (?:details|account|information)|wire (?:transfer|the funds)|w-?2s?|keep (?:this|it) (?:confidential|between us)|discreet)\b/i;
// colleagueWithTitle: when the exact name check found no colleague, the name before a title or the organization's
// name ("Misty Samplefield, Principal") is compared again; a colleague's adds the same sign (3), which
// colleagueInContext then weighs like any other.
function colleagueWithTitle(E, facts, signals, ctx) {
    if (!ctx.colleagues || !ctx.colleagues.size || signals.some(s => s && typeof s.text === 'string' && s.text.startsWith(COLLEAGUE_SIGN))) return;
    const name = String(facts.senderName || '').replace(/["']/g, '').trim();
    const domain = String(facts.senderAddress || '').split('@')[1] || '';
    if (!name || !domain || (ctx.orgDomains || []).some(o => E.isOwnDomain(domain.toLowerCase(), o))) return;
    // The name before " - ", " | ", " (", or before ", <a title>" (a comma alone is "Last, First").
    const parts = [name.split(/\s+[-–—|]\s+|\s*\(/)[0], name.replace(new RegExp(`,\\s*(?:${INSIDE_TITLE_RE.source.replace(/^\\b\(|\)\\b$/g, '')}).*$`, 'i'), '')]
        .map(x => x.trim()).filter(x => x && x !== name && x.split(/\s+/).length >= 2);
    if (parts.some(p => ctx.colleagues.has(E.colleagueNameHash(p)))) signals.push({ weight: 3, text: `${COLLEAGUE_SIGN} (${String(facts.senderAddress).slice(0, 120)}).` });
}
// (At most 3 of the reasons are named in the sign's text.)
function colleagueInContext(E, facts, signals, ctx, bodyText) {
    const i = signals.findIndex(s => s && typeof s.text === 'string' && s.text.startsWith(COLLEAGUE_SIGN));
    if (i < 0) return;
    const at = (a) => String(a || '').slice(String(a || '').lastIndexOf('@') + 1).toLowerCase();
    const address = String(facts.senderAddress || ''), domain = at(address);
    const org = (ctx.orgDomains || []).map(d => String(d).toLowerCase());
    const name = String(facts.senderName || '');
    const why = [];
    if (E.isPersonalMailDomain(domain)) why.push('from a personal email account');
    // One of the organization's own domains never imitates another of them (0.5.59).
    if (!org.some(o => E.isOwnDomain(domain, o)) && org.some(o => { try { return E.ownDomainLookalike(domain, o); } catch (e) { return false; } })) why.push('from an address imitating your organization\'s domain');
    if (signals.some(s => s && ['young-sender-domain', 'young-lookalike-sender', 'zrd-sender', 'watched-lookalike-sender', 'known-lookalike-sender'].includes(s.kind))) why.push('from a brand-new or look-alike domain');
    if (facts.auth && facts.auth.dmarc === 'fail') why.push('and Gmail\'s sender check failed for it');
    const reply = (facts.replyTo || []).find(a => at(a) && at(a) !== domain && !org.some(o => at(a) === o || at(a).endsWith(`.${o}`)));
    if (reply) why.push(`with replies going to another address (${reply})`);
    const orgWords = org.flatMap(o => String((E.registrableDomain(o) || o).split('.')[0]).split(/[-_]/)).filter(w => w.length >= 4);
    const lower = name.toLowerCase();
    if (INSIDE_TITLE_RE.test(name) || orgWords.some(w => lower.includes(w))) why.push(`with a title or your organization's name in the sender's name ("${name.trim().slice(0, 60)}")`);
    let asks = false;
    try { asks = E.highRiskRequestKinds(bodyText).length > 0; } catch (e) { asks = false; }
    if (asks || IMPERSONATOR_RE.test(`${facts.subject || ''}\n${bodyText || ''}`)) why.push('asking for what impersonators ask (a favor, a phone number, payment or payroll details, codes or passwords)');
    // (0.6.19) Only the domain resembling the organization's (a local group's domain with the town's name in it): it
    // counts only together with another warning sign (signsNeedingCompany).
    const lookalikeOnly = why.length === 1 && why[0] === 'from an address imitating your organization\'s domain';
    // (0.6.23) Only a personal email account (people write from their own Gmail too): 2, not 3. With a request, a
    // reply address elsewhere, a title, a failed sender check or a new or look-alike domain: 3, as before.
    const personalOnly = why.length === 1 && why[0] === 'from a personal email account';
    signals[i] = why.length
        ? Object.assign({}, signals[i], { kind: 'sender-colleague-name', weight: personalOnly ? 2 : 3, needsCompany: lookalikeOnly || undefined, text: `The sender uses the name of someone in your organization, but writes from an outside address (${address.slice(0, 120)}), ${why.slice(0, 3).join('; ')}.` })
        : Object.assign({}, signals[i], { kind: 'sender-name-shared', weight: 0, text: `The sender has the same name as someone in your organization, writing from ${domain}'s own address. Nothing in the email claims to be from inside your organization, so it doesn't count (people share names).` });
}

// (0.6.32) The organization's domain written inside another domain: maple-schools-example.gmail.net-login.example, or
// maple-schools.example.evil.example, in the sender's address, a reply address or a link the reader sees. Made to
// read as the organization's own at a glance, and registered by someone else: 5, whichever it is. The forms looked for:
// the whole domain with its dots as hyphens, run together, or followed by another ending; for a domain of three or more
// parts (a school district's name.k12.state.us), also without its last part (name-k12-state).
function orgDomainForms(own) {
    const out = [];
    for (const o of own) {
        const d = String(o || '').toLowerCase();
        if (!d.includes('.')) continue;
        const forms = [d.replace(/\./g, '-'), d.replace(/\./g, '')];
        const parts = d.split('.');
        if (parts.length >= 3) { const head = parts.slice(0, -1); forms.push(head.join('-'), head.join('')); }
        out.push({ own: d, forms: forms.filter(f => f.length >= 8), dotted: `${d}.` });
    }
    return out;
}
function orgDomainInsideSigns(E, facts, judged, own) {
    const forms = orgDomainForms(own);
    if (!forms.length) return [];
    const ours = (h) => own.some(o => h === o || h.endsWith(`.${o}`));
    // A known company's own domain (a school-software tenant named after the district: district-k12.lms.example) never
    // counts; in links only the full domain followed by another ending does (no real service writes it that way).
    const known = (reg) => { try { return !!((E.PROTECTED_DOMAINS && E.PROTECTED_DOMAINS.has(reg)) || (E.brandOfDomain && E.brandOfDomain(reg)) || (E.companyNameOf && E.companyNameOf(reg))); } catch (e) { return false; } };
    const inside = (host, { dottedOnly = false } = {}) => {
        const h = String(host || '').toLowerCase().replace(/\.$/, '');
        if (!h || ours(h)) return null;
        const reg = E.registrableDomain(h) || h;
        if (known(reg)) return null;
        for (const f of forms) {
            if (h.startsWith(f.dotted) || h.includes(`.${f.dotted}`)) return f.own;
            if (!dottedOnly && f.forms.some(x => h.split('.').some(label => label.includes(x)))) return f.own;
        }
        return null;
    };
    const domainOf = (a) => String(a || '').toLowerCase().split('@')[1] || '';
    const found = [];
    const sender = domainOf(facts.senderAddress);
    if (inside(sender)) found.push(['the sender\'s address', sender, inside(sender)]);
    for (const r of facts.replyTo || []) { const d = domainOf(r); if (d && inside(d)) { found.push(['the reply address', d, inside(d)]); break; } }
    for (const j of judged || []) {
        if (j.hidden) continue;
        let h = '';
        try { h = new URL(j.finalUrl || j.url).hostname; } catch (e) { h = ''; }
        if (h && inside(h, { dottedOnly: true })) { found.push(['a link', h, inside(h, { dottedOnly: true })]); break; }
    }
    if (!found.length) return [];
    const [where, host, o] = found[0];
    return [{ weight: 5, kind: 'org-domain-inside', text: `${where[0].toUpperCase()}${where.slice(1)} (${host}) writes your organization's domain (${o}) inside someone else's domain (${E.registrableDomain(host) || host}): made to look like yours at a glance.` }];
}
// (0.6.32) A hidden link with no text beside a visible link to the same site: a decoy for link scanners (they follow the
// hidden one; the reader clicks the visible one). Responsive newsletters hide whole blocks, but their links have text.
// (0.6.33) 5, flagged on its own. (0.6.34) Except to the sender's own site with Gmail's DMARC check passing: a brand's
// newsletter can hide an empty link to its own site (a cooking site's did): a note of no weight then. (0.6.41) 5 only to
// another site than the sender's.
function hiddenDecoyLinkSigns(E, judged, facts = {}, verified = false) {
    const reg = (u) => { try { const h = new URL(u).hostname.toLowerCase(); return E.registrableDomain(h) || h; } catch (e) { return ''; } };
    const web = (judged || []).filter(j => /^https?:\/\//i.test(String(j.url || '')));
    const visible = new Set(web.filter(j => !j.hidden && String(j.text || '').trim()).map(j => reg(j.url)).filter(Boolean));
    const decoy = web.find(j => j.hidden && !String(j.text || '').trim() && visible.has(reg(j.url)));
    if (!decoy) return [];
    const site = reg(decoy.url);
    const senderDomain = String(facts.senderAddress || '').toLowerCase().split('@')[1] || '';
    const senderReg = E.registrableDomain(senderDomain) || senderDomain;
    // (0.6.41) The full 5 only for a link to another site than the sender's. To the sender's own site: nothing when
    // Gmail's DMARC check passed for the sender's organization (Gmail can name the organization's domain, header.from
    // bookshop.example for mail from e.bookshop.example), else 2 (the failed sender check counts
    // on its own).
    if (site && site === senderReg) {
        const a = facts.auth || {};
        const hf = String(a.headerFrom || '').toLowerCase();
        const orgPass = verified || (a.dmarc === 'pass' && !!hf && (E.registrableDomain(hf) || hf) === senderReg);
        return orgPass ? [{ weight: 0, kind: 'hidden-decoy-link', text: `It hides an invisible, empty link to ${site} beside the visible one; that is the sender's own site and Gmail verified the sender, so it isn't counted (newsletters do this).` }]
            : [{ weight: 2, kind: 'hidden-decoy-link', text: `It hides an invisible, empty link to ${site} beside the visible one. That is the site the sender's address names, but Gmail couldn't confirm the sender, so it counts a little.` }];
    }
    // (0.6.82) A mailing service's own click tracker (Brevo's sendibm1.com, Klaviyo's…): the service wraps every link of the
    // email through it, the hidden one too, so the hidden link is its tracking, not a decoy. Nothing when Gmail confirmed the
    // sender, else 2 (anyone can send through a mailing service). Before, a district's verified newsletter sent with Brevo
    // was moved as phishing on this alone (5, with "first email" and "from outside").
    let tracker = null;
    try { tracker = E.emailTrackerProvider ? E.emailTrackerProvider(decoy.url) : null; } catch (e) { tracker = null; }
    if (tracker) {
        return verified ? [{ weight: 0, kind: 'hidden-decoy-link', text: `It hides an invisible, empty link to ${site}, the click tracking of the mailing service it was sent with (${tracker}); Gmail verified the sender, so it isn't counted.` }]
            : [{ weight: 2, kind: 'hidden-decoy-link', text: `It hides an invisible, empty link to ${site}, a mailing service's click tracking (${tracker}); Gmail couldn't confirm the sender, so it counts a little.` }];
    }
    return [{ weight: 5, kind: 'hidden-decoy-link', text: `It hides an invisible, empty link to ${site} beside the visible one: a trick to fool link scanners. It goes to another site than the sender's.` }];
}

// (0.6.19) Signs that count only together with another warning sign. Each alone, with only "it comes from outside"
// and "the first email from this sender" beside it, made ordinary mail suspicious:
//   - hidden-filler: text far below the message after a blank space; newsletters and marketing mail do it too;
//   - a colleague's name on an outside address whose only reason is that the domain resembles the organization's
//     (a local group's domain with the town's name in it: drugfreemaple.example for maple-schools.example);
//   - a colleague copied in at an outside or resembling address.
// Then they keep their text, with no weight, saying why. Hidden filler in list or marketing mail (a List-Unsubscribe or
// List-Id header, Precedence: bulk, or an unsubscribe link) with nothing else wrong is spam, not phishing: returned as
// { why } for the policy, which moves it to Spam (trigger 'spam'); never mail from inside the organization.
// (0.6.27) Nor from an established sender: Gmail verified it (DMARC passed) and its domain is at least a year old
// (ESTABLISHED_SENDER_DAYS; an unknown age doesn't count). Real newsletters pad their emails too, and spam rarely
// comes from a long-held domain that passes the sender check; the email is then left alone, saying why.
const NEEDS_COMPANY = new Set(['hidden-filler', 'colleague-copied-lookalike', 'colleague-copied-outside']);
const CONTEXT_ONLY = new Set(['outside-org', 'first-time']);
const ALONE_NOTE = ' Alone it isn\'t counted: nothing else in the email is suspicious.';
const ESTABLISHED_SENDER_DAYS = 365;
const ESTABLISHED_NOTE = ' Not moved as spam either: Gmail verified the sender, and its domain is more than a year old (newsletters do this too).';
function bulkMail(facts) {
    const raw = String(facts.rawForHeaders || '');
    const head = raw.split(/\r?\n\r?\n/)[0] || '';
    if (/^(list-unsubscribe|list-id)[ \t]*:/im.test(head) || /^precedence[ \t]*:[ \t]*(bulk|list)\b/im.test(head)) return true;
    return /\bunsubscribe\b|\bopt[- ]out\b|\bemail preferences\b/i.test(String(facts.visibleText || '').slice(-4000));
}
function signsNeedingCompany(signals, facts, inside, sender = {}) {
    const needs = (s) => !!s && (NEEDS_COMPANY.has(s.kind) || !!s.needsCompany);
    const held = signals.map((s, i) => [s, i]).filter(([s]) => needs(s) && (s.weight || 0) > 0);
    if (!held.length) return null;
    if (signals.some(s => s && !needs(s) && !CONTEXT_ONLY.has(s.kind) && (s.weight || 0) > 0)) return null;
    for (const [s, i] of held) signals[i] = Object.assign({}, s, { weight: 0, text: `${s.text}${ALONE_NOTE}` });
    if (!inside && held.some(([s]) => s.kind === 'hidden-filler') && bulkMail(facts)) {
        if (sender.verified && typeof sender.senderAge === 'number' && sender.senderAge >= ESTABLISHED_SENDER_DAYS) {
            const k = signals.findIndex(s => s && s.kind === 'hidden-filler');
            if (k >= 0) signals[k] = Object.assign({}, signals[k], { text: `${signals[k].text}${ESTABLISHED_NOTE}` });
            return null;
        }
        return { why: 'list or marketing mail that hides a block of unrelated text below the message (a spam trick), with nothing else suspicious' };
    }
    return null;
}
// (0.6.19) A brand's program run by a partner (the engine's brand-partner-name, no weight) whose domain is new or on a
// list: an imitation after all; it counts as the brand's name on another address (5).
const YOUNG_OR_LISTED = new Set(['young-sender-domain', 'young-lookalike-sender', 'zrd-sender', 'sender-domain-listed', 'sender-domain-blocked', 'sender-domain-reported', 'scam-sender-list']);
function partnerNameInContext(signals) {
    const i = signals.findIndex(s => s && s.kind === 'brand-partner-name');
    if (i < 0 || !signals.some(s => s && YOUNG_OR_LISTED.has(s.kind))) return;
    signals[i] = Object.assign({}, signals[i], { weight: 5, text: signals[i].text.replace(/, not ([^.]+) itself\.$/, ', but the sender\'s domain is new or listed, so it counts as $1\'s name on another address.') });
}

// (0.6.20) A brand's name from a domain whose public records show an established company (a corporate registrar
// and one more link: ownership.js 'likely') that isn't the brand's own: the company that runs a product carrying the
// brand's name (a bank issuing a card in the brand's name, "Brand Credit" from the bank's mail domain). Not counted
// when Gmail's DMARC check passed for that domain, every link the reader sees goes back to the sender's own domain,
// no link is flagged, and the domain isn't new or on a list: whoever it is, it is the company writing from and
// linking to its own long-held domain, not someone borrowing the brand to send the reader elsewhere.
function establishedSenderInContext(E, facts, judged, signals, verified) {
    const i = signals.findIndex(s => s && s.kind === 'brand-name-likely');
    if (i < 0) return;
    // (0.6.46) Its domain new or on a list: the full caution again (3), whatever the sender check says.
    if (signals.some(s => s && YOUNG_OR_LISTED.has(s.kind))) { if (signals[i].weight < 3) signals[i] = Object.assign({}, signals[i], { weight: 3 }); return; }
    if (!verified) return;
    const regOf = (h) => { const x = String(h || '').toLowerCase(); try { return E.registrableDomain(x) || x; } catch (e) { return x; } };
    const sender = regOf(String(facts.senderAddress || '').split('@').pop());
    const hostOf = (u) => { try { return new URL(u).hostname; } catch (e) { return ''; } };
    const web = (judged || []).filter(j => !j.hidden && /^https?:/i.test(String(j.finalUrl || j.url || '')));
    if (!sender || web.some(j => j.severity || regOf(hostOf(j.finalUrl || j.url)) !== sender)) return;
    const s = signals[i];
    signals[i] = Object.assign({}, s, { weight: 0, text: s.text.replace(/\. Make sure it's really who you expect\.$/, `. It passed its sender check and every link goes back to ${sender}, so it counts as that company writing about a product it runs, not an imitation.`) });
}

// (0.6.22) A delivery report ("Delivery Status Notification (Failure)", "Undeliverable") from a big mail provider's
// own mail system: its mailer-daemon or postmaster address at the provider's domain, Gmail's DMARC check passing for
// that domain, and the email a delivery report as mail systems write them (Content-Type multipart/report;
// report-type=delivery-status, RFC 3464). The AI doesn't score it: it reads "failure", "couldn't be delivered" and a
// returned message as a lure. The rule checks still read it, the returned copy included.
const BOUNCE_PROVIDERS = new Set(['google.com', 'googlemail.com', 'gmail.com', 'outlook.com', 'hotmail.com', 'live.com', 'yahoo.com', 'aol.com', 'icloud.com', 'me.com']);
function providerBounce(E, facts, verified) {
    if (!verified) return false;
    const address = String(facts.senderAddress || '').toLowerCase();
    const local = address.split('@')[0], domain = address.split('@').pop();
    let reg = domain;
    try { reg = E.registrableDomain(domain) || domain; } catch (e) { reg = domain; }
    if (!/^(mailer-daemon|postmaster)$/.test(local) || !BOUNCE_PROVIDERS.has(reg)) return false;
    const head = String(facts.rawHead || '').replace(/\r?\n[ \t]+/g, ' ');
    const type = (/^content-type:\s*([^\r\n]*)/mi.exec(head) || [])[1] || '';
    return /^\s*multipart\/report\b/i.test(type) && /report-type\s*=\s*"?delivery-status\b/i.test(type);
}

// Mail from, replying to, or linking to a domain the look-alike watch found (src/lookalike.js): new or
// marked a threat (strong): the sender 5, the reply address 5, a link 4; there before the watch began and
// not reviewed (weak): 3, 3, 2. The organization's own domains never count.
function watchedLookalikeSigns(E, facts, judged, lookalikes) {
    if (!lookalikes || !lookalikes.size) return [];
    const regOf = (h) => { const x = String(h || '').toLowerCase(); try { return E.registrableDomain(x) || x; } catch (e) { return x; } };
    const at = (a) => String(a || '').slice(String(a || '').lastIndexOf('@') + 1).toLowerCase();
    const out = [];
    const sender = regOf(at(facts.senderAddress));
    const sw = lookalikes.get(sender);
    if (sw) out.push(sw === 'strong'
        ? { weight: 5, kind: 'watched-lookalike-sender', text: `The sender's domain ${sender} imitates your organization's, and was registered recently (the look-alike watch found it; Threats → Look-alikes).` }
        : { weight: 3, kind: 'known-lookalike-sender', text: `The sender's domain ${sender} imitates your organization's (the look-alike watch lists it; it was there before the watch began).` });
    const reply = (facts.replyTo || []).map(a => regOf(at(a))).find(d => d && d !== sender && lookalikes.get(d));
    if (reply) out.push(lookalikes.get(reply) === 'strong'
        ? { weight: 5, kind: 'watched-lookalike-reply-to', text: `Replies go to ${reply}, a recently registered imitation of your organization's domain (the look-alike watch found it).` }
        : { weight: 3, kind: 'known-lookalike-reply-to', text: `Replies go to ${reply}, an imitation of your organization's domain (the look-alike watch lists it).` });
    const link = (judged || []).map(j => regOf(hostOf(j.finalUrl || j.url))).find(d => d && d !== sender && lookalikes.get(d));
    if (link) out.push(lookalikes.get(link) === 'strong'
        ? { weight: 4, kind: 'watched-lookalike-link', text: `A link goes to ${link}, a recently registered imitation of your organization's domain (the look-alike watch found it).` }
        : { weight: 2, kind: 'known-lookalike-link', text: `A link goes to ${link}, an imitation of your organization's domain (the look-alike watch lists it).` });
    return out;
}

// The people in an email's Reply-To, Cc and To lines (name and address each, as the mail parser read
// them, a list person by person), for colleagueLineSigns.
function addressLinePeople(facts) {
    const p = facts.people || {};
    const line = (name, list) => (list || []).slice(0, 30).map(x => ({ line: name, name: x.name, address: x.address }));
    return [...line('reply-to', p.replyTo), ...line('cc', p.cc), ...line('to', p.to)];
}

// Signs of mail dressed up as coming from inside the organization:
//   - its From address is in your domains, but Gmail's DMARC check failed for it: someone else wrote it
//     (the DMARC failure is a sign of its own too; this one says it imitates a colleague's address): 2;
//   - the sender's name shows an address of yours ("it@maple-schools.example" <x@elsewhere.example>) on an outside
//     address: 3.
// Mail from inside that passed DMARC gets neither.
function insideSpoofSigns(E, facts, orgDomains, ownAddress, verified) {
    if (!orgDomains.length) return [];
    const out = [];
    const isOwn = (d) => orgDomains.some(o => E.isOwnDomain(String(d || '').toLowerCase(), o));
    if (ownAddress && !verified && facts.auth && facts.auth.dmarc === 'fail') {
        out.push({ weight: 2, kind: 'spoofed-inside', text: `It claims to come from inside your organization (${facts.senderAddress}), but Gmail's sender check (DMARC) failed: it wasn't sent by your domain.` });
    }
    const named = (String(facts.senderName || '').match(/[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)/g) || []).filter(a => isOwn(a.split('@')[1]));
    if (named.length && !ownAddress) {
        out.push({ weight: 3, kind: 'inside-name-outside-address', text: `The sender's name shows an address of your organization (${named[0].toLowerCase()}), but it comes from outside (${facts.senderAddress}).` });
    }
    return out;
}

// What the model read of an email (analyze's aiFacts), sentence by sentence (Model.reading).
async function aiReading(aiFacts, max = 40) {
    return spruce.load().model.reading(aiFacts, max);
}

module.exports = { analyze, aiReading, judgeLinks, linkSignals, senderVerified, sameOrgDomain, platformNotification: N.platformNotification, shareSource: N.shareSource };
