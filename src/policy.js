'use strict';
// What happens to an analyzed email.
//
//   move        to Spam (and the "SPRUCE/Moved" label): the extension's verdict is "flagged" (as the
//               extension moves flagged email; MOVE_ON_RULES, on by default), or the AI model's score is at or
//               above the threshold (90% by default) for a sender outside the organization (inside too with
//               AI_MOVES_INSIDE). trigger: 'rules', 'ai' or 'rules+ai'; 'spam' (0.6.19) for list or marketing
//               mail padded with hidden filler and nothing else suspicious: spam, not phishing; or (0.6.55) the AI's
//               spam answer at or above the threshold for an unverified sender outside, nothing else suspicious.
//   would-move  the same, in monitor mode or while the brake is on (braked): recorded, nothing moved. (The
//               campaign hold and an admin's decision on a campaign come after this: pipeline.js.)
//   flag        suspicious but not moved (amber verdict, an AI score of cfg.aiSuspicious or more below the
//               threshold, or a high one the policy doesn't act on, such as an inside sender): recorded.
//   (The suspicious line is never above the move threshold: config.js and pipeline.js policyValue.)
//   none        nothing to record.
//
// Never moved, whatever the checks say: allowlisted senders and domains ("trusted"). Mail from inside
// the organization is moved only by the rules (a compromised staff account trips them too), not by the
// AI score alone, unless AI_MOVES_INSIDE is set. Both rely on the From address, so both need Gmail's
// DMARC check to have passed for it (engine/analyze.js senderVerified): a forged allowlisted or staff
// address is judged like any other mail from outside.
// From this AI score an email counts as suspicious (recorded, not moved, below the move threshold): the
// default of AI_SUSPICIOUS_THRESHOLD (cfg.aiSuspicious; Settings → Policy).
const AI_SUSPICIOUS = 0.65;

// Whether an address is allowlisted: the exact address, or its domain or a parent domain (ALLOW_ADDRESSES,
// ALLOW_DOMAINS, Settings → Sender lists). Only the address: whether DMARC passed is the caller's to check.
function isAllowed(cfg, address) {
    const a = String(address || '').toLowerCase();
    const d = a.split('@')[1] || '';
    return cfg.allowAddresses.includes(a) || cfg.allowDomains.some(x => d === x || d.endsWith('.' + x));
}

// What made an email suspicious (and not moved), said plainly: the rule checks' score (or a link check's
// verdict), the AI's score, or both. Also used by the dashboard for records from before 0.5.12, which only
// said "suspicious, below the move rules" (server.js withPlainWhy).
function suspiciousWhy(result, cfg) {
    const p = result.ai && typeof result.ai.probability === 'number' ? result.ai.probability : null;
    const line = typeof cfg.aiSuspicious === 'number' ? cfg.aiSuspicious : AI_SUSPICIOUS;
    const pct = (x) => `${Math.round(x * 100)}%`;
    const parts = [];
    if (result.status === 'caution' || result.status === 'flagged') {
        const off = result.status === 'flagged' && !cfg.moveOnRules ? '; moving on the rules is off (MOVE_ON_RULES)' : '';
        parts.push(result.score >= 3 ? `the rule checks scored it ${result.score} (suspicious from 3, moved from 5)${off}`
            : `a link check found ${result.status === 'flagged' ? 'a dangerous' : 'a suspicious'} link${off}`);
    }
    if (p !== null && p >= cfg.aiThreshold && result.inside && !cfg.aiMovesInside) {
        parts.push(`the AI scored it ${pct(p)}, but the sender is inside the organization and "Let the AI alone move staff email" is off, so the AI score alone doesn't move it`);
    } else if (p !== null && p >= line) {
        parts.push(`the AI scored it ${pct(p)} (suspicious from ${pct(line)}, moved from ${pct(cfg.aiThreshold)})`);
    }
    return parts.join(', and ') || 'suspicious';
}

// (0.6.40) The rule checks alone don't make mail from a verified outside sender suspicious: when Gmail confirmed the sender
// (DMARC) and the AI scored it under the suspicious line, a rules score of 3 or 4 is too weak to ask a reviewer about
// (newsletters and notices trip it). It is still recorded when the rules move it (5 or more), or the AI agrees. A link
// check's verdict (a threat list), staff mail (which the AI doesn't read by default) and a platform's notification (a
// share: DMARC confirms the platform, not the person who shared) are as before.
// Works on an analysis (verified) and on a stored record (its auth, for records from before).
function rulesOnlyVerified(r, cfg) {
    if (!r || r.status !== 'caution' || r.inside || r.platformNote || !(r.score >= 3)) return false;
    const domain = String((r.sender && r.sender.address) || '').toLowerCase().split('@')[1] || '';
    const verified = r.verified !== undefined ? !!r.verified : !!(r.auth && r.auth.dmarc === 'pass' && domain && (!r.auth.headerFrom || require('./engine/analyze').sameOrgDomain(r.auth.headerFrom, domain)));
    if (!verified) return false;
    const p = r.ai && typeof r.ai.probability === 'number' ? r.ai.probability : null;
    const line = typeof cfg.aiSuspicious === 'number' ? cfg.aiSuspicious : AI_SUSPICIOUS;
    return p === null || p < line;
}

// (0.6.55) The AI's spam answer (phish-tiny 0.26.0 on; ai.spam): how sure it is that the email is a business's bulk
// marketing, wanted or not, and not phishing. An email can't show whether its reader signed up, so the answer alone never
// moves mail from a sender Gmail verified (DMARC): that company's marketing goes to Review → Promotional instead
// (pipeline.js promotionalOf), where an admin answers once per company. From an unverified sender outside the
// organization, with nothing else suspicious (the rule checks clean, the phishing answer under the suspicious line), an
// answer at or above the move threshold (AI_MOVE_THRESHOLD) is spam: { why } for the spam rules (moved like padded list
// mail: MOVE_ON_RULES, monitor mode, the brake), else null. Never for mail Gmail put in its Promotions tab
// (result.gmailPromotions, the pipeline's from the message's labels): it is already out of the main inbox, and a small
// business without DMARC sends there too; the spam answer is for unconfirmed marketing Gmail left in the main inbox.
function aiSpamOf(result, cfg) {
    const ai = result && result.ai;
    const q = ai && typeof ai.spam === 'number' ? ai.spam : null;
    if (q === null || q < cfg.aiThreshold || result.inside || result.verified || result.gmailPromotions || result.status !== 'clean') return null;
    const p = typeof ai.probability === 'number' ? ai.probability : null;
    const line = typeof cfg.aiSuspicious === 'number' ? cfg.aiSuspicious : AI_SUSPICIOUS;
    if (p === null || p >= line) return null;
    return { why: `the AI was ${Math.min(99, Math.round(q * 100))}% sure it is spam (bulk marketing; moved from ${Math.round(cfg.aiThreshold * 100)}%), Gmail couldn't confirm the sender (DMARC), and nothing else is suspicious`, ai: true };
}

// (0.6.59; 0.6.65 Settings → Policy → Skip review) cfg.strictSpam, off by default (none chosen): an email from outside the
// organization with any chosen sign is moved to Spam without waiting for review, whatever the other checks find:
//   'forged-headers'  its headers were tampered with: a message ID claiming a mail program it didn't come through,
//                     Received lines copied from other emails, From or Subject repeated (0.6.59-0.6.64: 'forged-id');
//   'spam-headers'    a mail system on the way marked it spam, or a bulk mailer's placeholders or home-made tool show;
//   'sender-listed'   the sender's address or domain is on a threat list (phishing lists, Spamhaus, abuse.ch) or blocked;
//   'dmarc-fail'      the failed sender check: Gmail's DMARC check failed (the From address isn't the sending domain's);
//   'dmarc-missing'   Gmail checked the email but no DMARC policy confirmed the sender (many small businesses have none);
//   'dangerous-links' a link is on a phishing list, blocked by Safe Browsing, or flagged dangerous by the link checks.
// ('listed', 0.6.59-0.6.64, is both 'sender-listed' and 'dangerous-links'.) Never for Trusted senders Gmail confirmed
// (they aren't moved), nor for mail from inside (your domains, DMARC passing), which only the rules move. Monitor mode, the
// brake and a campaign's hold apply as to any move. The why, or null.
const STRICT_KINDS = ['forged-headers', 'spam-headers', 'sender-listed', 'dmarc-fail', 'dmarc-missing', 'dangerous-links'];
const STRICT_OLD = { 'forged-id': ['forged-headers'], listed: ['sender-listed', 'dangerous-links'] };
// A stored or typed list in today's names, in STRICT_KINDS' order; unknown names left out.
function strictKinds(list) {
    const items = (Array.isArray(list) ? list : String(list || '').split(/[\s,;]+/)).map(x => String(x).trim().toLowerCase()).filter(Boolean);
    const all = new Set(items.flatMap(x => STRICT_OLD[x] || [x]));
    return STRICT_KINDS.filter(k => all.has(k));
}
const HEADER_WORDS = { 'forged-message-id': 'a forged message ID', 'forged-received': 'Received lines copied from other emails', 'duplicate-headers': 'repeated headers',
    'spam-flag': 'a mail system on the way marked it spam', placeholders: 'a bulk mailer\'s unfilled placeholders', 'local-tool': 'a home-made bulk-mail tool' };
function strictWhy(result, cfg) {
    const on = strictKinds(cfg.strictSpam);
    const s = result && result.strictSigns;
    if (!on.length || !s || result.inside || result.status === 'trusted') return null;
    const why = [];
    if (on.includes('forged-headers') && (s.forgedHeaders || []).length) why.push(`forged headers (${s.forgedHeaders.map(k => HEADER_WORDS[k] || k).join(', ')})`);
    if (on.includes('spam-headers') && (s.spamHeaders || []).length) why.push(`spam headers (${s.spamHeaders.map(k => HEADER_WORDS[k] || k).join(', ')})`);
    if (on.includes('sender-listed') && s.senderListed) why.push('the sender is on a threat list or blocked');
    if (on.includes('dmarc-fail') && s.dmarc === 'fail') why.push('the sender check failed (Gmail\'s DMARC check)');
    if (on.includes('dmarc-missing') && s.dmarc === 'missing') why.push('no DMARC policy confirmed the sender');
    if (on.includes('dangerous-links') && s.dangerousLinks) why.push('a link is flagged dangerous');
    return why.length ? why.join(', and ') : null;
}

// The action for an analyzed email ({ action, trigger, why, braked }); state.brake: the domain-wide brake is on.
function decide(result, cfg, state = {}) {
    if (result.status === 'trusted') return { action: 'none', trigger: null, why: 'the sender is on Trusted senders (Settings → Sender lists)' };
    const p = result.ai && typeof result.ai.probability === 'number' ? result.ai.probability : null;
    const ruleMove = cfg.moveOnRules && result.status === 'flagged';
    const aiHigh = p !== null && p >= cfg.aiThreshold;
    const aiMove = aiHigh && (!result.inside || cfg.aiMovesInside);
    // Why an allowlisted or staff address didn't count as one (said on the record).
    const notes = [result.allowlistedUnverified ? 'the sender is on Trusted senders, but Gmail couldn\'t confirm the sender is real (DMARC), so it was checked like any other' : '',
                   result.ownAddress && !result.inside ? 'the address is your organization\'s, but Gmail couldn\'t confirm the sender is real (DMARC), so it isn\'t treated as staff mail' : ''].filter(Boolean);
    const noted = (s) => [s, ...notes].filter(Boolean).join('; ');
    // (0.6.19) Spam, not phishing (analyze.js signsNeedingCompany): list or marketing mail padded with hidden filler,
    // nothing else suspicious. Moved to Spam like the rest (the user can take it back out), under the same switch as
    // the rules (MOVE_ON_RULES), monitor mode and the brake; never from inside the organization.
    // (0.6.55) Or the AI's spam answer for an unverified sender (aiSpamOf), by the same rules.
    const spamWhy = result.spam || aiSpamOf(result, cfg);
    const spamMove = !ruleMove && !aiMove && cfg.moveOnRules && !!spamWhy && !result.inside;
    // (0.6.59) Skip review (strictWhy; Straight to Spam before 0.6.65): moved by the policy's own choice, counted with the rules (trigger 'rules').
    const strict = !ruleMove && !aiMove && !spamMove ? strictWhy(result, cfg) : null;
    if (strict) {
        const why = noted(`straight to Spam, skipping review (Settings → Policy → Skip review): ${strict}`);
        if (cfg.mode !== 'enforce') return { action: 'would-move', trigger: 'rules', strict: true, why: `${why} (monitor mode: nothing is moved)` };
        if (state.brake) return { action: 'would-move', trigger: 'rules', strict: true, why: `${why} (not moved: the brake is on)`, braked: true };
        return { action: 'move', trigger: 'rules', strict: true, why };
    }
    if (!ruleMove && !aiMove && !spamMove) {
        const line = typeof cfg.aiSuspicious === 'number' ? cfg.aiSuspicious : AI_SUSPICIOUS;
        const byRules = (result.status === 'caution' && !rulesOnlyVerified(result, cfg)) || result.status === 'flagged';
        const byAi = p !== null && p >= line;
        const suspicious = byRules || aiHigh || byAi;
        return { action: suspicious ? 'flag' : 'none', trigger: null, why: noted(suspicious ? suspiciousWhy(result, cfg) : '') };
    }
    const trigger = ruleMove && aiMove ? 'rules+ai' : ruleMove ? 'rules' : aiMove ? 'ai' : 'spam';
    // (0.6.39) In plain words: what scored how much, and the level that moves.
    const why = spamMove ? noted(`spam: ${spamWhy.why}`) : noted([ruleMove ? `the rule checks scored it ${result.score} (moved from 5)` : '',
                       aiMove ? `the AI was ${Math.round(p * 100)}% sure it is phishing (moved from ${Math.round(cfg.aiThreshold * 100)}%)${result.inside ? ' (the sender is staff; "Let the AI alone move staff email" is on)' : ''}` : ''].filter(Boolean).join(' and '));
    if (cfg.mode !== 'enforce') return { action: 'would-move', trigger, why: `${why} (monitor mode: nothing is moved)` };
    if (state.brake) return { action: 'would-move', trigger, why: `${why} (not moved: the brake is on)`, braked: true };
    return { action: 'move', trigger, why };
}

module.exports = { decide, isAllowed, suspiciousWhy, rulesOnlyVerified, aiSpamOf, strictWhy, strictKinds, STRICT_KINDS, AI_SUSPICIOUS };
