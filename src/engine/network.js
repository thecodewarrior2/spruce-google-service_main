'use strict';
// The checks that need the network (src/intel), applied to one email's links and sender:
//   - Cloudflare Security DNS: link hosts (where the link goes, and its own host) and the sender's domain;
//   - Google Safe Browsing, only when turned on (SAFE_BROWSING=true; off by default): the links (no "#…";
//     one-time links without their query);
//   - the phishing lists: link addresses and sites, the sender's domain and address. The organization's
//     own domains are matched by exact address only, never as a whole site or domain (as the
//     extension's senderDomainShared: one listing of a hacked school site must not flag all staff mail);
//   - registry dates: up to LINK_AGE_LOOKUPS unfamiliar link domains, and the sender's (registrable) domain;
//   - Spamhaus's DBL and ZRD (0.5.37; off by default): the sender's domain and link sites, at most 6 an email.
// (0.5.73) An allowed link domain (Settings → Sender lists, ctx.allowLinkDomains, and its subdomains) is matched
// against the phishing lists by exact address only, as the organization's own domains are: a listing of its
// whole domain (a newsletter's click tracker listed by mistake) is a note of no weight, a listing of the exact
// page still flags the link. Cloudflare, Safe Browsing, Spamhaus and where a link leads are checked as before.
// A link any of them flags becomes "dangerous" (analyze.js linkSignals, the extension's dangerous-links
// sign, then counts it); the sender's findings and the site ages become signs of their own. A lookup that
// fails or is slow leaves things "not checked".
// One exception (0.5.18), the reputation check: a link whose text shows another site (open.spotify.com)
// but which goes through the mail service that sent the email (mailers.js: the third party whose DKIM
// signature the receiver verified, such as beehiiv for link.mail.beehiiv.com; no list) becomes a warning
// instead of a danger, when Cloudflare and the phishing lists checked the service's domain and found
// nothing (nor did Safe Browsing, when on), and its registry date isn't recent. A lookup that didn't
// answer leaves it dangerous, as before.
const LINK_AGE_LOOKUPS = 3;
// (0.6.17) How long the proof that a link's domain is the sender's own company may take (cached 30 days after).
const OWN_LINK_WAIT_MS = 6000;
const YOUNG_SENDER_DAYS = 30, LOOKALIKE_YOUNG_DAYS = 90;

const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase(); } catch (e) { return ''; } };
const { sendingService, mismatchHost, companyWordOf, MAILER_MIN_AGE_DAYS } = require('./mailers');
// (0.6.25) A link site registered in the last 90 days has a low reputation (the engine's LINK_RECENT_DAYS).
const LOW_REPUTATION_DAYS = 90;
const { isShareLink } = require('./notifications');

// judged: the links as analyze.judgeLinks made them (mutated: severity, reason and network of flagged links,
// mailer of softened ones). Returns { signals: [...], checks: { … } } for the record (checks null without intel).
async function networkChecks(E, intel, facts, judged, ctx) {
    const checks = { cloudflare: 0, safeBrowsing: 0, lists: false, ages: 0, notChecked: 0 };
    if (!intel) return { signals: [], checks: null };
    const org = (ctx.orgDomains || []).map(d => d.toLowerCase());
    const ours = (h) => org.some(d => h === d || h.endsWith('.' + d));
    const senderDomain = (facts.senderAddress.split('@')[1] || '').toLowerCase();
    const personal = senderDomain && E.isPersonalMailDomain(senderDomain);
    const web = judged.filter(j => !j.hidden && /^https?:\/\//i.test(j.url));
    const linkHosts = new Set();
    for (const j of web) for (const h of [hostOf(j.url), hostOf(j.finalUrl)]) if (h && !ours(h)) linkHosts.add(h);
    const hosts = [...linkHosts];
    if (senderDomain && !ours(senderDomain) && !personal) hosts.push(senderDomain);

    // Site ages: unfamiliar link domains (not a protected brand's, ours or a personal mail service),
    // the ones about signing in or paying first; and the sender's domain.
    const signInOf = new Map();
    for (const j of web) {
        const reg = E.registrableDomain(hostOf(j.finalUrl || j.url));
        if (!reg || ours(reg) || E.PROTECTED_DOMAINS.has(reg) || E.isPersonalMailDomain(reg)) continue;
        signInOf.set(reg, !!signInOf.get(reg) || E.SIGNIN_INTENT_RE.test(`${j.text || ''} ${j.finalUrl || j.url}`));
    }
    // (A mail service's domain behind a "text shows another site" link first: its age is part of its reputation.)
    const mailerReg = new Set(web.map(j => mismatchHost(j.reason)).filter(h => h && sendingService(h, facts, E.registrableDomain)).map(h => E.registrableDomain(h)));
    // (0.6.19) And a domain behind a well-known brand's text: its age decides whether it is another established company's.
    const brandReg = new Set(web.filter(j => /\(a well-known brand\)/.test(String(j.reason || ''))).map(j => mismatchHost(j.reason)).filter(Boolean).map(h => E.registrableDomain(h)));
    const rank = (d) => (mailerReg.has(d) || brandReg.has(d) ? 2 : 0) + (signInOf.get(d) ? 1 : 0);
    const ageDomains = [...signInOf.keys()].sort((a, b) => rank(b) - rank(a)).slice(0, LINK_AGE_LOOKUPS);
    const senderReg = senderDomain && !personal && !ours(senderDomain) ? E.registrableDomain(senderDomain) : '';
    // (0.5.62) The organization's domain behind a sender's subdomain is looked up too: newsletters and no-reply
    // addresses often send from a name with no DNS records of its own (news.tv-station.example), and then the
    // organization's domain is what can be judged.
    if (senderReg && senderReg !== senderDomain) hosts.push(senderReg);
    const allowed = (ctx.allowLinkDomains || []).map(d => String(d).toLowerCase());
    const allowedLink = (h) => !!h && allowed.some(d => h === d || h.endsWith('.' + d));
    const listHit = (u) => intel.feeds.urlHit(u, { exactOnly: ours(hostOf(u)) || allowedLink(hostOf(u)) }).catch(() => null);
    // (What a list says of an allowed link domain's whole domain, for the note.)
    const allowedHits = intel.feeds ? Promise.all([...new Set(web.flatMap(j => [j.url, j.finalUrl]).filter(u => u && allowedLink(hostOf(u))))]
        .map(async u => ({ host: hostOf(u), list: await intel.feeds.urlHit(u).catch(() => null) }))) : Promise.resolve([]);
    // Spamhaus's DBL and ZRD (0.5.37; off by default): the sender's domain first, then the link sites (full
    // host names), the ones about signing in or paying first, at most 6 (src/intel/spamhaus.js; nothing when off).
    const shHosts = [...new Set(web.map(j => hostOf(j.finalUrl || j.url)).filter(h => h && signInOf.has(E.registrableDomain(h))))]
        .sort((a, b) => rank(E.registrableDomain(b)) - rank(E.registrableDomain(a)));
    const shDomains = [senderReg ? senderDomain : '', ...shHosts].filter(Boolean);

    const [hostResults, urlResults, ages, senderAge, senderOnList, senderDomainListed, linkListed, shResults, allowedListed] = await Promise.all([
        intel.threats ? intel.threats.checkHosts(hosts) : new Map(),
        intel.threats && (!intel.threats.enabled || intel.threats.enabled.safeBrowsing) ? intel.threats.checkUrls(web.map(j => ({ url: j.finalUrl && j.finalUrl !== j.url ? j.finalUrl : j.url, text: j.text })).concat(web.filter(j => j.finalUrl && j.finalUrl !== j.url).map(j => ({ url: j.url, text: j.text })))) : new Map(),
        intel.rdap ? Promise.all(ageDomains.map(async d => ({ domain: d, days: await intel.rdap.ageDays(d).catch(() => null), signIn: signInOf.get(d) }))) : [],
        intel.rdap && senderReg ? intel.rdap.ageDays(senderReg).catch(() => null) : null,
        intel.feeds && facts.senderAddress ? intel.feeds.addressHit(facts.senderAddress).catch(() => null) : null,
        intel.feeds && senderDomain && !personal && !ours(senderDomain) ? intel.feeds.domainHit(senderDomain).catch(() => null) : null,
        intel.feeds ? Promise.all(web.map(async j => [j, (await listHit(j.finalUrl || j.url)) || (j.finalUrl && j.finalUrl !== j.url ? await listHit(j.url) : null)])) : [],
        intel.spamhaus && shDomains.length ? intel.spamhaus.checkDomains(shDomains).catch(() => new Map()) : new Map(),
        allowedHits
    ]);
    checks.lists = !!intel.feeds;
    if (shResults.size) checks.spamhaus = shResults.size;
    const shOf = (u) => { const h = hostOf(u); return h ? shResults.get(h) : null; };

    // Links: the first finding that flags one makes it dangerous. A community report (a list whose confidence
    // is 'report', such as TweetFeed: 0.5.21) only marks it for caution, and counts as a sign below.
    const isReport = (name) => !!(intel.feeds && typeof intel.feeds.confidenceOf === 'function' && intel.feeds.confidenceOf(name) === 'report');
    const reported = [];
    for (const j of web) {
        const found = [];
        for (const h of [hostOf(j.finalUrl), hostOf(j.url)]) { const r = hostResults.get(h); if (r && r.verdict === 'unsafe') found.push(`${r.reason} (${h})`); }
        for (const u of [j.finalUrl, j.url]) { const r = u && urlResults.get(u); if (r && r.verdict === 'unsafe') found.push(r.reason); }
        const listed = (linkListed.find(([x]) => x === j) || [])[1];
        if (listed && !isReport(listed)) found.push(`listed as phishing by ${listed}`);
        const sh = shOf(j.finalUrl || j.url) || shOf(j.url);
        if (sh && sh.dbl && sh.dbl.severity === 'danger') found.push(`listed by Spamhaus's Domain Blocklist (${sh.dbl.list})`);
        if (found.length) { j.severity = 'danger'; j.reason = found[0]; j.network = true; }
        else if (listed) {
            reported.push({ j, by: listed });
            if (j.severity !== 'danger') { j.severity = 'caution'; j.reason = `reported as phishing or malware by ${listed}${j.reason ? `; ${j.reason}` : ''}`; j.network = true; }
        }
    }
    // The reputation check (0.5.18): a mismatched link through the service that sent the email, which the
    // lookups checked and found nothing against, and whose domain isn't new: a warning (caution), not a danger.
    const ageOf = new Map(ages.map(a => [a.domain, a.days]));
    const softened = [];
    for (const j of web) {
        if (j.severity !== 'danger' || j.network) continue;
        const host = mismatchHost(j.reason);
        const service = host && sendingService(host, facts, E.registrableDomain);
        if (!service) continue;
        const mailer = service.domain;
        const cf = hostResults.get(host), days = ageOf.get(E.registrableDomain(host));
        if (!cf || cf.verdict !== 'clean' || !intel.feeds || (typeof days === 'number' && days < MAILER_MIN_AGE_DAYS)) continue;
        const age = typeof days === 'number' ? `, registered ${days >= 730 ? `${Math.floor(days / 365)} years` : `${days} days`} ago` : '';
        j.severity = 'caution';
        j.reason = `${j.reason}, the click tracker of ${mailer}, the mail service that sent this email (its signature checked by Gmail; not blocked or listed as phishing${age}); where it leads isn't known until it's clicked`;
        j.mailer = mailer;
        softened.push({ mailer, host, text: (/^link text shows (\S+)/.exec(j.reason) || [])[1] || '' });
    }
    // (0.6.17) A link whose text shows another site but which goes to the sender's own domain, when that domain is
    // proven to be the company it is named after (email-lakeviewhotels.example, registered to Lakeview Hotels Group through a
    // corporate registrar; src/intel/ownership.js ofCompany) and Gmail's DMARC check passed for it, and nothing is found
    // against it: the company's own tracker, also behind a partner's text (a co-branded card), not a disguise. Not
    // dangerous; one note, no weight. A look-alike (email-paypa1.example) can't have that proof: it stays dangerous.
    const signals = [];
    const owned = [];
    const fromVerified = !!(facts.auth && facts.auth.dmarc === 'pass') && !!senderReg && E.registrableDomain(String(facts.auth.headerFrom || senderDomain).toLowerCase()) === senderReg;
    const ownCandidates = fromVerified && intel.ownership && intel.ownership.ofCompany ? web.filter(j => (j.severity === 'danger' || j.severity === 'caution') && !j.network && !j.mailer) : [];
    const proofs = new Map();
    for (const j of ownCandidates) {
        const host = mismatchHost(j.reason);
        const reg = host && E.registrableDomain(host);
        if (!reg || reg !== senderReg) continue;
        const cf = hostResults.get(host);
        if (!cf || cf.verdict !== 'clean') continue;
        const company = companyWordOf(reg);
        if (!company) continue;
        if (!proofs.has(reg)) {
            const text = (/^link text shows (\S+)/.exec(j.reason) || [])[1] || '';
            const textReg = E.registrableDomain(text.toLowerCase());
            const homes = [textReg && textReg.split('.')[0] === company ? textReg : '', `${company}.com`].filter(Boolean);
            let timer;
            const late = new Promise(r => { timer = setTimeout(() => r(null), OWN_LINK_WAIT_MS); });
            proofs.set(reg, Promise.race([intel.ownership.ofCompany(reg, company, homes), late]).catch(() => null).finally(() => clearTimeout(timer)));
        }
        const proof = await proofs.get(reg);
        if (!proof || proof.state !== 'owned') continue;
        owned.push({ host, reg, how: proof.how, text: (/^link text shows (\S+)/.exec(j.reason) || [])[1] || '' });
        j.severity = null;
        j.reason = `${j.reason}: the sender's own domain, proven to be ${company[0].toUpperCase()}${company.slice(1)}'s (${proof.how}); not counted`;
        j.ownBrand = reg;
    }
    // (0.6.19) A link whose text shows a well-known brand (paypal.com) but which goes to another established company's
    // own domain (a hotel chain's click tracker, in a co-branded offer): one brand's text on another brand's site,
    // not a disguise. Counted only when the email's sender passed Gmail's DMARC check, and the destination: is
    // proven by public records to be the company it is named after (ofCompany, as above), is clean at Cloudflare, is
    // at least MAILER_MIN_AGE_DAYS old, and is no platform where anyone can put a page (a file share, cloud storage,
    // a big platform of the protected list). Then it isn't dangerous: one note, no weight.
    const brandToBrand = [];
    const brandCandidates = fromVerified && intel.ownership && intel.ownership.ofCompany ? web.filter(j => j.severity === 'danger' && !j.network && !j.mailer && !j.ownBrand && /\(a well-known brand\)/.test(String(j.reason || ''))) : [];
    for (const j of brandCandidates) {
        const host = mismatchHost(j.reason);
        const reg = host && E.registrableDomain(host);
        if (!reg || reg === senderReg || E.isPersonalMailDomain(reg) || (E.PROTECTED_DOMAINS && E.PROTECTED_DOMAINS.has(reg))) continue;
        let hosted = false;
        try { hosted = !!E.cloudStoragePage(j.finalUrl || j.url) || isShareLink(j.finalUrl || j.url); } catch (e) { hosted = true; }
        if (hosted) continue;
        const cf = hostResults.get(host), days = ageOf.get(reg);
        if (!cf || cf.verdict !== 'clean' || typeof days !== 'number' || days < MAILER_MIN_AGE_DAYS) continue;
        const company = companyWordOf(reg);
        if (!company) continue;
        if (!proofs.has(reg)) {
            let timer;
            const late = new Promise(r => { timer = setTimeout(() => r(null), OWN_LINK_WAIT_MS); });
            proofs.set(reg, Promise.race([intel.ownership.ofCompany(reg, company, [`${company}.com`]), late]).catch(() => null).finally(() => clearTimeout(timer)));
        }
        const proof = await proofs.get(reg);
        if (!proof || proof.state !== 'owned') continue;
        const text = (/^link text shows (\S+)/.exec(j.reason) || [])[1] || '';
        brandToBrand.push({ reg, how: proof.how, text });
        j.severity = null;
        j.reason = `${j.reason}: another established company's own domain, proven to be ${company[0].toUpperCase()}${company.slice(1)}'s (${proof.how}); not counted`;
        j.brandToBrand = reg;
    }
    // (0.6.46) A link whose text shows one domain and which goes to another, where one of them is a well-known brand's own
    // (0.6.48: or neither, both proven the sender's company's) and public records prove the other is that brand's too (the ownership lookup, kept 60 days): the same company's
    // two domains (quickbooks.com text on an intuit.com link), not a disguise. Not counted; one note. No list by hand.
    const sameCompany = [];
    const sameCandidates = intel.ownership && intel.ownership.of ? web.filter(j => (j.severity === 'danger' || j.severity === 'caution') && !j.network && !j.mailer && !j.ownBrand && !j.brandToBrand) : [];
    for (const j of sameCandidates) {
        const host = mismatchHost(j.reason);
        const text = ((/^link text shows (\S+)/.exec(j.reason) || [])[1] || '').toLowerCase();
        const destReg = host && E.registrableDomain(host), textReg = text && E.registrableDomain(text);
        if (!destReg || !textReg || destReg === textReg) continue;
        const destBrand = E.brandOfDomain(destReg), textBrand = E.brandOfDomain(textReg);
        if (destBrand && textBrand) continue;           // both known: the link check already compared them
        // (0.6.48) One side a known company's: the other proven its. Neither: both proven the sender's company's (the
        // company its address or its name is), the common case of a company's own mail (outlook.com text, office.com link).
        const senderBrand = (() => { try { return E.brandOfDomain(senderReg) || ((E.displayNameBrand(facts.senderName, facts.senderAddress) || {}).name) || null; } catch (e) { return null; } })();
        const brand = destBrand || textBrand || senderBrand;
        if (!brand || !(E.SENDER_NAME_BRANDS || []).some(b => b.name === brand)) continue;
        const toProve = [textReg, destReg].filter(d => E.brandOfDomain(d) !== brand);
        const ask = (d) => {
            const key = `${d}|${brand}`;
            if (!proofs.has(key)) {
                let timer;
                const late = new Promise(r => { timer = setTimeout(() => r(null), OWN_LINK_WAIT_MS); });
                proofs.set(key, Promise.race([intel.ownership.of(d, brand, { link: true }), late]).catch(() => null).finally(() => clearTimeout(timer)));
            }
            return proofs.get(key);
        };
        const answers = await Promise.all(toProve.map(ask));
        // (0.6.48) Likely (a corporate registrar plus a link to the company) is enough for a link: not for a sender's name.
        if (!answers.length || answers.some(p => !p || (p.state !== 'owned' && p.state !== 'likely'))) continue;
        const proof = answers.find(p => p.state === 'owned') || answers[0];
        sameCompany.push({ text, dest: destReg, brand, how: proof.how });
        j.severity = null;
        j.reason = `${j.reason}: both ${brand}'s, as public records prove (${proof.how}); not counted`;
        j.sameCompany = brand;
    }
    // (0.6.56) A link whose text shows one domain and which goes to another, where one of the two is the sender's own domain
    // (Gmail confirmed the sender, DMARC), no brand table knows the company, and public records prove both domains the
    // same company's, whichever company it is (ownership.js sameOwner: optumrx.com text on an optum.com link, both
    // registered to their parent through a corporate registrar). Not a disguise: not counted; one note. Not for a site
    // where anyone can put a page, and not when the destination isn't clean at Cloudflare.
    const sameOwner = [];
    const ownerCandidates = fromVerified && intel.ownership && intel.ownership.sameOwner ? web.filter(j => (j.severity === 'danger' || j.severity === 'caution') && !j.network && !j.mailer && !j.ownBrand && !j.brandToBrand && !j.sameCompany) : [];
    for (const j of ownerCandidates) {
        const host = mismatchHost(j.reason);
        const text = ((/^link text shows (\S+)/.exec(j.reason) || [])[1] || '').toLowerCase();
        const destReg = host && E.registrableDomain(host), textReg = text && E.registrableDomain(text);
        if (!destReg || !textReg || destReg === textReg || (destReg !== senderReg && textReg !== senderReg)) continue;
        let hosted = false;
        try { hosted = !!E.cloudStoragePage(j.finalUrl || j.url) || isShareLink(j.finalUrl || j.url); } catch (e) { hosted = true; }
        const cf = hostResults.get(host);
        if (hosted || !cf || cf.verdict !== 'clean') continue;
        const key = `same|${[destReg, textReg].sort().join('|')}`;
        if (!proofs.has(key)) {
            let timer;
            const late = new Promise(r => { timer = setTimeout(() => r(null), OWN_LINK_WAIT_MS); });
            proofs.set(key, Promise.race([intel.ownership.sameOwner(textReg, destReg), late]).catch(() => null).finally(() => clearTimeout(timer)));
        }
        const proof = await proofs.get(key);
        if (!proof || proof.state !== 'owned') continue;
        sameOwner.push({ text, dest: destReg, how: proof.how });
        j.severity = null;
        j.reason = `${j.reason}: both the same company's, as public records prove (${proof.how}); not counted`;
        j.sameOwner = true;
    }
    if (sameOwner.length) {
        const c = sameOwner[0], n = sameOwner.length;
        signals.push({ weight: 0, kind: 'same-owner-link', text: `${n === 1 ? `A link shows ${c.text} but goes` : `${n} links show one site but go`} to ${c.dest}: both belong to the same company, as public records prove (${c.how}). Not counted.` });
    }
    if (sameCompany.length) {
        const c = sameCompany[0], n = sameCompany.length;
        signals.push({ weight: 0, kind: 'same-company-link', text: `${n === 1 ? `A link shows ${c.text} but goes` : `${n} links show one site but go`} to ${c.dest}: both are ${c.brand}'s, as public records prove (${c.how}). Not counted.` });
    }
    if (brandToBrand.length) {
        const b = brandToBrand[0], n = brandToBrand.length;
        signals.push({ weight: 0, kind: 'brand-to-brand-link', text: `${n === 1 ? `A link shows ${b.text} but goes` : `${n} links show a well-known brand but go`} to ${b.reg}, an established company's own domain (${b.how}; not blocked, not new), and Gmail's DMARC check passed for the sender: one company's offer on another's site, not a disguise. Not counted.` });
    }
    if (owned.length) {
        const o = owned[0], n = owned.length;
        signals.push({ weight: 0, kind: 'own-brand-link', text: `${n === 1 ? `A link shows ${o.text} but goes` : `${n} links show another site but go`} to the sender's own domain, ${o.reg}, which public records prove is the company it is named after (${o.how}), and Gmail's DMARC check passed for it: ${n === 1 ? 'its' : 'their'} text doesn't disguise where ${n === 1 ? 'it goes' : 'they go'}. Not counted.` });
    }
    for (const r of hostResults.values()) { if (r.verdict === 'unknown') checks.notChecked++; else if (r.by === 'Cloudflare Security' || r.by === 'Cloudflare') checks.cloudflare++; }
    for (const r of urlResults.values()) { if (r.verdict === 'unknown') checks.notChecked++; else checks.safeBrowsing++; }

    if (softened.length) {
        const s = softened[0], n = softened.length;
        signals.push({ weight: 1, kind: 'mailer-link', text: `${n === 1 ? `A link shows ${s.text} but goes` : `${n} links show another site but go`} through the click tracker of ${s.mailer} (${s.host}), the mail service that sent this email, with a clean reputation: where ${n === 1 ? 'it leads' : 'they lead'} isn't known until clicked. A warning: it takes other signs to move the email.` });
    }
    // (0.5.73) Listings of an allowed link domain's whole domain: not counted, said once.
    const passed = allowedListed.filter(x => x.list && !web.some(j => j.network && [hostOf(j.url), hostOf(j.finalUrl)].includes(x.host)));
    if (passed.length) {
        const hosts = [...new Set(passed.map(x => x.host))], lists = [...new Set(passed.map(x => x.list))];
        signals.push({ weight: 0, kind: 'allowed-link-domain', text: `${hosts.length === 1 ? `A link's site (${hosts[0]}) is` : `Links' sites (${hosts.slice(0, 3).join(', ')}) are`} on ${lists.join(' and ')}, but ${hosts.length === 1 ? 'it is an allowed link domain' : 'they are allowed link domains'} (Settings → Sender lists): a listing of the whole domain isn't counted. The other link checks still apply.` });
    }
    if (senderOnList) signals.push({ weight: 5, kind: 'scam-sender-list', text: `The sender's address is on a list of known scam senders (${senderOnList}).` });
    // Spamhaus (0.5.37): the sender's domain on the DBL (phishing, malware, botnet control: 5; low reputation: 2;
    // a legitimate site abused: 1), or first seen in the last 24 hours (ZRD: 3); a link site on the DBL as an
    // abused site for phishing, malware or botnet control (3), for spam or other abuse (2), or brand new (ZRD: 2).
    // (A link site listed for phishing, malware or botnet control made its link dangerous above.)
    const shSender = senderReg ? shResults.get(senderDomain) : null;
    if (shSender && shSender.dbl && shSender.dbl.severity === 'danger') signals.push({ weight: 5, kind: 'sender-domain-listed', text: `The sender's domain ${senderDomain} is on Spamhaus's Domain Blocklist (${shSender.dbl.list}).` });
    else if (shSender && shSender.dbl) signals.push({ weight: shSender.dbl.severity === 'spam' ? 2 : 1, kind: 'sender-domain-spam', text: `The sender's domain ${senderDomain} is on Spamhaus's Domain Blocklist (${shSender.dbl.list}).` });
    if (shSender && typeof shSender.zrdHours === 'number') signals.push({ weight: 3, kind: 'zrd-sender', text: `The sender's domain ${senderDomain} was first seen on the internet ${shSender.zrdHours <= 2 ? 'less than 2' : `about ${shSender.zrdHours}`} hours ago (Spamhaus's Zero Reputation Domains): phishing often comes from brand-new domains.` });
    const shLinks = [...shResults.entries()].filter(([d]) => d !== senderDomain);
    const shAbused = shLinks.find(([, r]) => r.dbl && r.dbl.severity === 'abused' && /phishing|malware|botnet/.test(r.dbl.list));
    if (shAbused) signals.push({ weight: 3, kind: 'spamhaus-abused-link', text: `A link goes to ${shAbused[0]}, ${shAbused[1].dbl.list}, says Spamhaus's Domain Blocklist.` });
    const shSpam = shLinks.find(([, r]) => r.dbl && (r.dbl.severity === 'spam' || (r.dbl.severity === 'abused' && !/phishing|malware|botnet/.test(r.dbl.list))));
    if (shSpam) signals.push({ weight: 2, kind: 'spamhaus-spam-link', text: `A link goes to ${shSpam[0]}, on Spamhaus's Domain Blocklist (${shSpam[1].dbl.list}).` });
    const shNew = shLinks.find(([, r]) => typeof r.zrdHours === 'number');
    if (shNew) signals.push({ weight: 2, kind: 'zrd-link', text: `A link goes to ${shNew[0]}, first seen on the internet ${shNew[1].zrdHours <= 2 ? 'less than 2' : `about ${shNew[1].zrdHours}`} hours ago (Spamhaus's Zero Reputation Domains).` });
    // The sender's domain: blocked by Cloudflare (5), else reported by a community list (2) or on a phishing
    // list (5).
    const sd = hostResults.get(senderDomain);
    if (sd && sd.verdict === 'unsafe') signals.push({ weight: 5, kind: 'sender-domain-blocked', text: `The sender's domain ${senderDomain} is blocked by Cloudflare Security as malware or phishing.` });
    else if (senderDomainListed && isReport(senderDomainListed)) signals.push({ weight: 2, kind: 'sender-domain-reported', text: `The sender's domain ${senderDomain} was reported as phishing or malware by ${senderDomainListed} (community reports).` });
    else if (senderDomainListed) signals.push({ weight: 5, kind: 'sender-domain-listed', text: `The sender's domain ${senderDomain} is listed as phishing by ${senderDomainListed}.` });
    if (reported.length) {
        const r = reported[0], host = hostOf(r.j.finalUrl || r.j.url);
        signals.push({ weight: 2, kind: 'reported-link', text: `${reported.length === 1 ? `A link's site (${host}) was` : `${reported.length} links' sites were`} reported as phishing or malware by ${r.by} in the last 30 days (community reports: a sign, not proof).` });
    }
    else if (sd && sd.verdict === 'nonexistent') {
        // (0.5.62) A subdomain with no DNS records of its own is not a made-up address when its organization's domain
        // exists (judged by that domain instead), nor when Gmail verified the sender (DMARC passed). Only a domain
        // whose organization's domain doesn't exist either is made up.
        const parent = senderReg && senderReg !== senderDomain ? hostResults.get(senderReg) : null;
        const verified = !!(facts.auth && facts.auth.dmarc === 'pass');
        if (parent && parent.verdict === 'unsafe') signals.push({ weight: 5, kind: 'sender-domain-blocked', text: `The sender's domain ${senderDomain} has no DNS records of its own, and its organization's domain ${senderReg} is blocked by Cloudflare Security as malware or phishing.` });
        else if (parent && parent.verdict !== 'nonexistent') signals.push({ weight: 0, kind: 'sender-subdomain-unlisted', text: `The sender's domain ${senderDomain} has no DNS records of its own, which is common for newsletter and no-reply addresses; its organization's domain ${senderReg} exists${parent.verdict === 'clean' ? ' and isn\'t blocked' : ''}, so it is judged by that domain.` });
        else if (verified) signals.push({ weight: 0, kind: 'sender-subdomain-unlisted', text: `The sender's domain ${senderDomain} has no DNS records the checks could find, but Gmail verified the sender (DMARC passed), so the address isn't made up.` });
        else signals.push({ weight: 3, kind: 'sender-domain-missing', text: `The sender's domain ${senderDomain} doesn't exist${senderReg && senderReg !== senderDomain ? `, nor does its organization's domain ${senderReg}` : ''}, so the address is made up.` });
    }
    // The sender's domain's age: under LOOKALIKE_YOUNG_DAYS and a look-alike of a brand, 5; under
    // YOUNG_SENDER_DAYS, 2.
    if (typeof senderAge === 'number') {
        checks.ages++;
        let look = null;
        try { look = E.lookalikeOf(senderDomain); } catch (e) { look = null; }
        if (look && senderAge < LOOKALIKE_YOUNG_DAYS) signals.push({ weight: 5, kind: 'young-lookalike-sender', text: `The sender's domain ${senderReg} ${look}, and was registered only ${senderAge} day${senderAge === 1 ? '' : 's'} ago: a look-alike address.` });
        else if (senderAge < YOUNG_SENDER_DAYS) signals.push({ weight: 2, kind: 'young-sender-domain', text: `The sender's domain ${senderReg} was registered only ${senderAge} day${senderAge === 1 ? '' : 's'} ago. Phishing often comes from brand-new domains.` });
    }
    // Link sites' ages (the engine's linkAgeSigns): a young site counts more when the email or the link is about
    // signing in or paying, or the sender is new or didn't pass DMARC (weakAuth).
    const known = ages.filter(a => typeof a.days === 'number');
    checks.ages += known.length;
    if (known.length) {
        let emailAsks = false;
        try { emailAsks = E.highRiskRequestKinds(facts.visibleText).length > 0 || E.SIGNIN_INTENT_RE.test(facts.subject || ''); } catch (e) { emailAsks = false; }
        const weakAuth = !!ctx.firstTime || !facts.auth || facts.auth.dmarc !== 'pass';
        try { signals.push(...E.linkAgeSigns(known, { emailAsks, weakAuth })); } catch (e) { /* no sign */ }
    }
    // (0.6.25) A link flagged only by its own text (a well-known site's name on a link to another site) counts fully
    // when its site has a low reputation: registered in the last LOW_REPUTATION_DAYS days, or on Spamhaus's lists
    // (DBL or ZRD). Marked here for analyze.js linkSignals; known bad links (blocked, listed) are j.network already.
    for (const j of web) {
        if (j.severity !== 'danger' || j.network) continue;
        const host = mismatchHost(j.reason) || hostOf(j.finalUrl || j.url);
        const days = host ? ageOf.get(E.registrableDomain(host)) : null;
        const sh = shOf(j.finalUrl || j.url) || shOf(j.url);
        if ((typeof days === 'number' && days >= 0 && days < LOW_REPUTATION_DAYS) || (sh && (sh.dbl || typeof sh.zrdHours === 'number'))) j.lowRep = true;
    }
    // (0.6.27) The sender's domain's age (days, or null when unknown), for analyze.js's spam exception.
    return { signals, checks, senderAge: typeof senderAge === 'number' ? senderAge : null };
}

module.exports = { networkChecks, LINK_AGE_LOOKUPS };
