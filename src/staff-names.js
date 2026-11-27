'use strict';
// (0.6.94) A staff member's name on another staff member's account: mail from inside the organization (your domains, Gmail
// confirmed the sender: DMARC) whose sender name is someone else's in the directory. An account taken over, or someone
// posing as a colleague ("John Doe" writing from sbob@…), writes like this; the name a reader sees is the only thing
// that changes, and Gmail lets anyone set it.
//
// The directory (Service.colleagueNames: each person's full name, primary address and aliases) is kept in memory as
// one-way hashes of names (staffNameHash) by address. Names are compared loosely, so a variant can't slip past: case,
// accents, punctuation, word order, titles (Dr., Mrs.), suffixes (Jr., III) and single initials don't count.
//
// Quiet when: the name is nobody's in the directory (a nickname, a role such as "Payroll", a group's name), the address
// isn't a person's (a group, a shared alias the directory doesn't list), the name is the address owner's own (two staff
// with the same name included), or an admin marked such an email safe from this account before (state staffNameSenders:
// a school system, a merge tool or a shared office account that sends under staff names).
const crypto = require('crypto');

const DROP = new Set(['mr', 'mrs', 'ms', 'miss', 'mx', 'dr', 'prof', 'rev', 'fr', 'jr', 'sr', 'ii', 'iii', 'iv']);
const VIA = /\s+via\s+\S.*$/i;   // "Dana Madeup via Google Docs", "Dana Madeup via Staff" (a group): the person's name is before "via"

function staffNameKey(name) {
    const words = String(name || '').normalize('NFKD').replace(/\p{M}+/gu, '').replace(VIA, '').toLowerCase()
        .replace(/[([{].*?[)\]}]/g, ' ').replace(/[^\p{L}\p{N}\s]+/gu, ' ').split(/\s+/)
        .filter(w => w && w.length > 1 && !DROP.has(w));
    return words.length >= 2 ? words.sort().join(' ') : '';
}
// A short one-way hash of the key (never kept readable).
function staffNameHash(name) {
    const key = staffNameKey(name);
    return key ? crypto.createHash('sha256').update(`spruce-staff|${key}`).digest('hex').slice(0, 16) : '';
}
// The directory as kept: { byEmail: Map(address or alias → name hash), names: Set(name hashes) }.
function staffDirectory(people) {
    const byEmail = new Map(), names = new Set();
    for (const p of people || []) {
        const h = staffNameHash(p && p.name);
        if (!h) continue;
        names.add(h);
        for (const a of [p.email, ...[].concat(p.aliases || [])]) if (a) byEmail.set(String(a).toLowerCase(), h);
    }
    return { byEmail, names };
}

// The sign for one email, or none. who: { name, address } (the From line, or the person a platform's share names);
// inside: the address is in your domains and Gmail confirmed it; staff: staffDirectory(); allowed: a Set of addresses
// an admin allowed (staffNameSenders); share: the platform's name when it is a share notification.
function insideNameSigns(who, { inside = false, staff = null, allowed = null, share = '' } = {}) {
    if (!inside || !staff || !staff.byEmail || !who || !who.name || !who.address) return [];
    const address = String(who.address).toLowerCase();
    if (allowed && allowed.has(address)) return [];
    const claimed = staffNameHash(who.name);
    if (!claimed || !staff.names.has(claimed)) return [];
    const own = staff.byEmail.get(address);
    if (!own || own === claimed) return [];
    const shown = String(who.name).replace(/\s+/g, ' ').trim().slice(0, 60);
    return [{ weight: 3, kind: 'inside-name-mismatch', address,
        text: `${share ? `${share} sent it for` : 'It is signed'} “${shown}”, the name of someone in your organization, but it comes from another staff member's account (${address}). An account taken over, or someone posing as a colleague, writes like this. If a school system or a shared account sends under staff names, Mark safe: its mail isn't checked for this again.` }];
}

module.exports = { staffNameKey, staffNameHash, staffDirectory, insideNameSigns };
