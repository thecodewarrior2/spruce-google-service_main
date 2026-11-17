'use strict';
// Who may call what.
//   /pubsub/push   only Google Pub/Sub, with an OIDC token for PUSH_SERVICE_ACCOUNT and PUSH_AUDIENCE.
//   /tasks/*       only Cloud Scheduler, with an OIDC token for TASK_SERVICE_ACCOUNT.
//   the dashboard  only through Identity-Aware Proxy (its signed x-goog-iap-jwt-assertion header, for
//                  IAP_AUDIENCE), and only for the addresses in ADMIN_EMAILS or the members of ADMIN_GROUP
//                  (role admin), or the members of MODERATOR_GROUP (role moderator: the review pages only).
// Demo mode (fake data, no Google access) lets everyone in as "demo-admin" (DEMO_ROLE=moderator: as a moderator).
const { OAuth2Client } = require('google-auth-library');

const IAP_KEYS_URL = 'https://www.gstatic.com/iap/verify/public_key';
const client = new OAuth2Client();
let iapKeys = null, iapKeysAt = 0;

async function verifyOidc(req, cfg, serviceAccount, audience) {
    const h = String(req.headers.authorization || '');
    const m = /^Bearer\s+(.+)$/i.exec(h);
    if (!m) return { ok: false, why: 'no token' };
    try {
        const ticket = await client.verifyIdToken({ idToken: m[1], audience });
        const p = ticket.getPayload() || {};
        if (!p.email_verified || String(p.email || '').toLowerCase() !== serviceAccount) return { ok: false, why: `token for ${p.email || 'nobody'}` };
        return { ok: true, email: p.email };
    } catch (e) {
        return { ok: false, why: 'invalid token' };
    }
}

const verifyPush = (req, cfg) => (cfg.demo ? { ok: true, email: 'demo' } : verifyOidc(req, cfg, cfg.pushServiceAccount, cfg.pushAudience));
const verifyTask = (req, cfg) => (cfg.demo ? { ok: true, email: 'demo' } : verifyOidc(req, cfg, cfg.taskServiceAccount, cfg.pushAudience));

// Whether a signed-in address may use the dashboard, and as what: listed in ADMIN_EMAILS, or a member of
// ADMIN_GROUP (role admin); else a member of MODERATOR_GROUP (role moderator, 0.6.1). Groups count only for an
// account in the organization's own domains; checked with Google, remembered a few minutes. When the admin
// group can't be checked, the answer is no (503); when only the moderator group can't, the answer is no (403).
async function authorizeAdmin(email, cfg, groupCheck, moderatorCheck = null) {
    if (cfg.adminEmails.includes(email)) return { ok: true, email, role: 'admin' };
    const denied = { ok: false, status: 403, why: `${email} is not an administrator or moderator of this service` };
    if (!cfg.orgDomains.includes(email.split('@')[1])) return denied;
    if (cfg.adminGroups.length && groupCheck) {
        try { if (await groupCheck(email)) return { ok: true, email, role: 'admin' }; }
        catch (e) { return { ok: false, status: 503, why: `couldn't check the admin group: ${String(e.message).slice(0, 160)}` }; }
    }
    if ((cfg.moderatorGroups || []).length && moderatorCheck) {
        try { if (await moderatorCheck(email)) return { ok: true, email, role: 'moderator' }; }
        catch (e) { return Object.assign({}, denied, { why: `${denied.why} (couldn't check the moderator group: ${String(e.message).slice(0, 160)})` }); }
    }
    return denied;
}

// Group membership answers, remembered: yes for 5 minutes, no for 1 (so someone just added gets in soon).
function adminGroupCheck(cfg, gmail, now = () => Date.now(), groups = cfg.adminGroups) {
    const cache = new Map();
    return async (email) => {
        const hit = cache.get(email);
        if (hit && now() - hit.at < (hit.yes ? 5 : 1) * 60 * 1000) return hit.yes;
        let yes = false;
        for (const g of groups) if (await gmail.hasMember(cfg.directoryAdmin, g, email)) { yes = true; break; }
        cache.set(email, { yes, at: now() });
        if (cache.size > 1000) cache.delete(cache.keys().next().value);
        return yes;
    };
}

async function verifyAdmin(req, cfg, groupCheck, moderatorCheck = null) {
    if (cfg.demo) return cfg.demoRole === 'moderator' ? { ok: true, email: 'demo-moderator@example.org', role: 'moderator' } : { ok: true, email: 'demo-admin@example.org', role: 'admin' };
    const jwt = req.headers['x-goog-iap-jwt-assertion'];
    if (!jwt) return { ok: false, status: 401, why: 'not signed in through Identity-Aware Proxy' };
    let email;
    try {
        if (!iapKeys || Date.now() - iapKeysAt > 60 * 60 * 1000) { iapKeys = (await client.getIapPublicKeys()).pubkeys; iapKeysAt = Date.now(); }
        const ticket = await client.verifySignedJwtWithCertsAsync(String(jwt), iapKeys, cfg.iapAudience, ['https://cloud.google.com/iap']);
        email = String((ticket.getPayload() || {}).email || '').toLowerCase().replace(/^accounts\.google\.com:/, '');
    } catch (e) {
        return { ok: false, status: 401, why: 'invalid Identity-Aware Proxy signature' };
    }
    if (!email) return { ok: false, status: 401, why: 'no address in the Identity-Aware Proxy signature' };
    return authorizeAdmin(email, cfg, groupCheck, moderatorCheck);
}

module.exports = { verifyPush, verifyTask, verifyAdmin, authorizeAdmin, adminGroupCheck, IAP_KEYS_URL };
