'use strict';
// Settings, from environment variables (Cloud Run: --set-env-vars / Secret Manager). Every default is
// the cautious one: MONITOR mode (nothing is moved, only recorded), the AI alone never moves mail from
// inside the organization, and a brake stops moving if moves suddenly pile up.
// Lists: commas or semicolons (semicolons avoid gcloud's comma escaping in --set-env-vars).
const list = (v) => String(v || '').split(/[,;]/).map(s => s.trim().toLowerCase()).filter(Boolean);
const num = (v, d) => (v === undefined || v === '' || !Number.isFinite(Number(v)) ? d : Number(v));
const bool = (v, d) => (v === undefined || v === '' ? d : /^(1|true|yes|on)$/i.test(String(v)));

// The settings an admin can also change on the dashboard (Settings → Policy, Allowlist, Mailboxes, Safe Browsing,
// Spamhaus, abuse.ch). They read from a live
// copy that only setPolicyValues changes (src/pipeline.js: refreshPolicy, setPolicy); envPolicy keeps what
// the environment (deploy/settings.env) says. The rest of the configuration is frozen.
const POLICY_KEYS = ['mode', 'aiThreshold', 'aiSuspicious', 'aiScansInside', 'aiMovesInside', 'safeBrowsing', 'spamhaus', 'abusech', 'suspiciousLabel', 'recheck', 'brakePerHour', 'timeZone', 'allowDomains', 'allowAddresses', 'allowLinkDomains', 'retentionDays', 'watchScope', 'releasesRepo', 'modelRepo', 'strictSpam'];
function withLivePolicy(c) {
    const envPolicy = Object.freeze(Object.fromEntries(POLICY_KEYS.map(k => [k, c[k]])));
    const live = Object.assign({}, envPolicy);
    for (const k of POLICY_KEYS) Object.defineProperty(c, k, { get: () => live[k], enumerable: true });
    c.envPolicy = envPolicy;
    Object.defineProperty(c, 'setPolicyValues', { value: (values) => { for (const k of POLICY_KEYS) live[k] = Object.prototype.hasOwnProperty.call(values, k) ? values[k] : envPolicy[k]; } });
    return Object.freeze(c);
}

function loadConfig(env = process.env) {
    const demo = bool(env.DEMO, false);
    return withLivePolicy({
        demo,
        onCloudRun: !!env.K_SERVICE,                   // Cloud Run sets K_SERVICE
        // Two Cloud Run services from one image (docs/DEPLOY.md): 'worker' answers only Pub/Sub and
        // Cloud Scheduler (no dashboard); 'admin' is only the dashboard, behind Identity-Aware Proxy.
        // 'all' (both) is for demo mode and a computer of your own.
        role: ['worker', 'admin'].includes(env.ROLE) ? env.ROLE : 'all',
        port: num(env.PORT, 8080),
        // 'monitor': record what would be moved, move nothing. 'enforce': move to Spam.
        mode: env.MODE === 'enforce' ? 'enforce' : 'monitor',
        orgDomains: list(env.ORG_DOMAINS),
        // Which mailboxes are watched: the members of a group (a security group is best; groups inside it
        // count too), an organizational unit (with its sub-units), and/or a list of addresses.
        pilotGroups: list(env.PILOT_GROUP),
        pilotOu: env.PILOT_OU || '',
        pilotUsers: list(env.PILOT_USERS),
        // Who is checked (0.5.53; a policy setting, Settings → Mailboxes): 'pilot' (the default, always: PILOT_GROUP,
        // PILOT_OU, PILOT_USERS) or 'domain' (every active mailbox of ORG_DOMAINS, from the directory: needs the
        // Users → Read privilege and the admin.directory.user.readonly scope, as the colleague-name check does).
        watchScope: String(env.WATCH_SCOPE || '').trim().toLowerCase() === 'domain' ? 'domain' : 'pilot',
        // What moves an email: the extension's own verdict "flagged" (score 5 or more), and/or the AI
        // model's score at or above the threshold.
        moveOnRules: bool(env.MOVE_ON_RULES, true),
        aiThreshold: num(env.AI_MOVE_THRESHOLD, 0.9),
        // From this AI score an email is recorded as suspicious (when it isn't moved): at most the threshold.
        aiSuspicious: num(env.AI_SUSPICIOUS_THRESHOLD, 0.65),
        // Whether the AI score alone can move mail from inside the organization (as it moves outside mail at
        // the threshold): off by default, and then only the rules move inside mail (a staff account taken
        // over trips them). Settings → Policy too ("AI alone moves inside mail", with an agreement).
        aiMovesInside: bool(env.AI_MOVES_INSIDE, false),
        // (0.6.59; 0.6.65 Skip review) The signs that move outside mail to Spam without review (policy.js strictWhy): any of
        // forged-headers, spam-headers, sender-listed, dmarc-fail, dmarc-missing, dangerous-links (comma-separated; the
        // 0.6.59 names forged-id and listed still read). None by default. Settings → Policy → Skip review too.
        strictSpam: require('./policy').strictKinds(list(env.STRICT_SPAM)),
        // Whether the AI model reads mail from inside the organization (your domains, Gmail's DMARC check
        // passing): off by default; the rule checks (links, headers, the rest) read it either way, and a
        // forged inside address (DMARC not passing) is outside mail, read by the AI. Settings → Policy too.
        // AI_MOVES_INSIDE needs the AI to read it, so it turns this on as well.
        aiScansInside: bool(env.AI_SCANS_INSIDE, false),
        // Never moved, whatever the checks say.
        allowDomains: list(env.ALLOW_DOMAINS),
        allowAddresses: list(env.ALLOW_ADDRESSES),
        // (0.5.73) Link sites a phishing list's listing of the whole domain doesn't flag (a newsletter's click
        // tracker listed by mistake): only a listing of the exact page does, as for your own domains. Every
        // sender's mail; the other checks (Cloudflare, Safe Browsing, where a link leads) still apply.
        allowLinkDomains: list(env.ALLOW_LINK_DOMAINS),
        // The brakes (pipeline.js). The domain-wide one: more moves than this in an hour stops moving
        // until an admin resumes; 0 or unset = half the watched mailboxes, at least 100 (a misfire on
        // many unrelated emails, not one large campaign). The campaign one: copies of one campaign moved
        // on weaker evidence (no outside confirmation) beyond this are held until an admin confirms or
        // releases the campaign; strong evidence is never held.
        brakePerHour: num(env.BRAKE_PER_HOUR, 0),
        // (0.6.63) Spam's own brake: moves of spam an hour before only spam stops (0: the same number as the brake's, counted apart).
        spamBrakePerHour: num(env.SPAM_BRAKE_PER_HOUR, 0),
        campaignHoldAfter: num(env.CAMPAIGN_HOLD_AFTER, 25),
        // Alerts (logged for Cloud Monitoring to email; deploy/install.sh): a campaign moved this many
        // times, and no notification from Gmail for this many hours.
        campaignAlertAfter: num(env.CAMPAIGN_ALERT_AFTER, 50),
        quietHours: num(env.QUIET_HOURS, 12),
        alertEmail: env.ALERT_EMAIL || '',                // shown in Settings (deploy/install.sh sets up the alerts)
        // The district's time zone (an IANA name, e.g. America/New_York): the dashboard's days (0.5.27), the
        // scheduled jobs and the weekly summary (Monday from 7 AM) use it. UTC when unset. A policy setting.
        timeZone: env.TIME_ZONE || 'UTC',
        // The dashboard's address (in the weekly summary), and where the services run (Health → Service status,
        // Settings → Update).
        dashboardUrl: env.DASHBOARD_URL || '',
        project: env.GOOGLE_CLOUD_PROJECT || '',
        region: env.CLOUD_RUN_REGION || '',
        movedLabel: env.MOVED_LABEL || 'SPRUCE/Moved',
        releasedLabel: env.RELEASED_LABEL || 'SPRUCE/Moved back',   // (SPRUCE/Released before 0.3.7)
        monitorLabel: env.MONITOR_LABEL || '',            // '' = monitor mode leaves mailboxes untouched
        // Network checks (src/intel). Google Safe Browsing is OFF by default: an admin adds its API key and
        // turns it on in Settings → Safe Browsing (0.5.23: the key in Secret Manager, SAFE_BROWSING_SECRET,
        // which install.sh sets up; safeBrowsing is a policy setting). SAFE_BROWSING=true with SAFE_BROWSING_KEY
        // still works where the secret isn't set up.
        cloudflareThreats: bool(env.CLOUDFLARE_THREATS, true),
        safeBrowsing: bool(env.SAFE_BROWSING, false),
        safeBrowsingKey: env.SAFE_BROWSING_KEY || '',
        safeBrowsingSecret: env.SAFE_BROWSING_SECRET || '',
        // 0.5.37: two more optional services, off by default, each turned on on its Settings page with a key
        // kept in Secret Manager (install.sh makes the secrets): Spamhaus's free Data Query Service (the DBL and
        // ZRD domain lists, looked up per email, at most SPAMHAUS_DAILY_MAX lookups a day: its fair use is
        // 100,000), and abuse.ch (URLhaus and ThreatFox, downloaded like the phishing lists).
        spamhaus: bool(env.SPAMHAUS, false),
        spamhausSecret: env.SPAMHAUS_SECRET || '',
        spamhausDailyMax: Math.min(100000, Math.max(1000, Math.round(num(env.SPAMHAUS_DAILY_MAX, 90000)))),
        abusech: bool(env.ABUSECH, false),
        abusechSecret: env.ABUSECH_SECRET || '',
        // A Gmail label on emails that are suspicious but not moved, so their readers see it (0.5.33): OFF by
        // default; an admin turns it on in Settings → Policy (a policy setting).
        suspiciousLabel: bool(env.SUSPICIOUS_LABEL, false),
        // Delivered mail checked again (0.5.35; on by default, a policy setting): when a phishing list adds a
        // site or sender an email of the last RECHECK_DAYS days has, and suspicious mail an hour and a day
        // after it arrived.
        recheck: bool(env.RECHECK, true),
        // Help → About & credits shows a Donate button (0.5.46), as the extension does; DONATE_BUTTON=off hides it.
        donateButton: bool(env.DONATE_BUTTON, true),
        // The look-alike watch (0.5.36; on by default): look-alikes of ORG_DOMAINS asked of Cloudflare's public
        // DNS resolver, a pass a day; the new ones are alerts and strong signs in mail.
        lookalikeWatch: bool(env.LOOKALIKE_WATCH, true),
        recheckDays: Math.min(30, Math.max(1, Math.round(num(env.RECHECK_DAYS, 7)))),
        // After an update that changes how email is checked (package.json checksLevel raised, 0.5.51): the mail
        // delivered in the last RECHECK_AFTER_UPDATE_HOURS that is still in the Inbox is checked again, newest
        // first, at most RECHECK_AFTER_UPDATE_MAX emails (0 hours: none). Only with RECHECK on.
        recheckAfterUpdateHours: Math.min(72, Math.max(0, Math.round(num(env.RECHECK_AFTER_UPDATE_HOURS, 24)))),
        recheckAfterUpdateMax: Math.min(50000, Math.max(0, Math.round(num(env.RECHECK_AFTER_UPDATE_MAX, 5000)))),
        suspiciousLabelName: env.SUSPICIOUS_LABEL_NAME || 'SPRUCE/Suspicious',
        // (0.6.52) Promotional mail (src/promotional.js: Gmail's Promotions category, or a signed one-click unsubscribe) from a
        // verified outside sender the checks found nothing in: never moved for that, listed in Review → Promotional for an
        // admin to answer per company (on by default; PROMOTIONAL=off stops it). In enforce mode it gets this Gmail label,
        // so its reader sees it too ('' adds none).
        promotional: bool(env.PROMOTIONAL, true),
        promotionalLabelName: env.PROMOTIONAL_LABEL_NAME === undefined ? 'SPRUCE/Promotional' : env.PROMOTIONAL_LABEL_NAME,
        // Health → Activity (what admins did, alerts, errors) is kept this many days (0.5.29; the email records
        // RETENTION_DAYS). 30 to 1,825. It holds no email text: mailbox addresses, sender domains, admins.
        auditDays: Math.min(1825, Math.max(30, Math.round(num(env.AUDIT_DAYS, 365)))),
        // A copy of Activity in Cloud Logging, kept a year in its own log bucket (0.5.29): OFF by default (Google
        // charges for it, a little). install.sh sets AUDIT_LOG=true with the bucket.
        auditLog: bool(env.AUDIT_LOG, false),
        // Missed changes (Gmail's history for a mailbox ran out) that make an alert (0.5.31): this many within 24
        // hours across the organization, or for one mailbox within 7 days. 1 to 1,000.
        gapsAlertDay: Math.min(1000, Math.max(1, Math.round(num(env.GAPS_ALERT_DAY, 10)))),
        gapsAlertMailbox: Math.min(1000, Math.max(1, Math.round(num(env.GAPS_ALERT_MAILBOX, 3)))),
        phishingLists: bool(env.PHISHING_LISTS, true),
        siteAge: bool(env.SITE_AGE, true),
        // Records
        store: env.STORE || (demo ? 'memory' : 'firestore'),
        firestoreDatabase: env.FIRESTORE_DATABASE || '(default)',
        storeSubjects: bool(env.STORE_SUBJECTS, true),
        storeAiQuotes: bool(env.STORE_AI_QUOTES, true),
        // The colleague-name check: the directory's names (as one-way hashes, in memory) against outside
        // senders' names. Needs DIRECTORY_ADMIN with Users → Read and the admin.directory.user.readonly scope.
        colleagueNames: bool(env.COLLEAGUE_NAMES, true),
        // How long records are kept (days, 14 to 365; also on the dashboard, Settings → Policy). Each one
        // is deleted on its own date, the oldest first: never all at once.
        retentionDays: num(env.RETENTION_DAYS, 35),
        firstSeenLearningDays: num(env.FIRST_SEEN_LEARNING_DAYS, 14),
        // Google: the service account that acts for each mailbox (domain-wide delegation), the admin it
        // acts as to read the directory (the pilot group and OU, the whole domain, the admin and moderator
        // groups, colleagues' names), and the Pub/Sub topic Gmail notifies.
        delegatedServiceAccount: env.DELEGATED_SA || '',
        directoryAdmin: env.DIRECTORY_ADMIN || '',
        pubsubTopic: env.PUBSUB_TOPIC || '',
        // Who may call what: Pub/Sub push and Cloud Scheduler sign their requests (OIDC); the dashboard
        // sits behind Identity-Aware Proxy and only these admins may use it.
        pushAudience: env.PUSH_AUDIENCE || '',
        pushServiceAccount: (env.PUSH_SERVICE_ACCOUNT || '').toLowerCase(),
        taskServiceAccount: (env.TASK_SERVICE_ACCOUNT || env.PUSH_SERVICE_ACCOUNT || '').toLowerCase(),
        iapAudience: env.IAP_AUDIENCE || '',
        adminEmails: list(env.ADMIN_EMAILS),
        // A group whose members may use the dashboard too (read as DIRECTORY_ADMIN; groups inside it count).
        adminGroups: list(env.ADMIN_GROUP),
        // (0.6.1) Moderators: the members of this group (spruce-moderators@ORG by default, set by deploy/install.sh;
        // off = none) may use Today, Review, Threats → Campaigns and Re-checked, Mail and Help, answer the review
        // queue, and confirm, dismiss or search for a whole campaign; never Health, Settings, Look-alikes, the CSV
        // export, the brake, or moving back an email nobody marked a false alarm (src/server.js, MODERATOR_ROUTES).
        moderatorGroups: String(env.MODERATOR_GROUP || '').trim().toLowerCase() === 'off' ? [] : list(env.MODERATOR_GROUP),
        // Demo mode only: DEMO_ROLE=moderator shows the dashboard as a moderator sees it.
        demoRole: env.DEMO_ROLE === 'moderator' ? 'moderator' : 'admin',
        // The Cloud Scheduler job the dashboard's "Read the directory again now" runs
        // (projects/PROJECT/locations/REGION/jobs/spruce-renew-watches; deploy/install.sh sets it).
        renewJob: env.RENEW_JOB || '',
        // The job Settings → Update runs (projects/PROJECT/locations/REGION/jobs/spruce-update; install.sh
        // makes it), and where the approved versions are (src/releases.js).
        updateJob: env.UPDATE_JOB || '',
        // (0.6.9) Where this installation downloads from (src/repos.js): the approved versions (Settings → Update,
        // deploy/update.sh, the update job) and the AI model's files. No default: each installation names its own
        // (deploy/settings.env; also Settings → Update → Repositories).
        releasesRepo: String(env.RELEASES_REPO || '').trim(),
        modelRepo: String(env.MODEL_REPO || '').trim()
    });
}

// What is wrong with a configuration for real use (the server refuses to start with any of these).
function configProblems(c) {
    // Demo mode lets anyone into the dashboard (made-up data): never on Cloud Run.
    if (c.demo) return c.onCloudRun ? ['DEMO mode is for a computer of your own; it refuses to run on Cloud Run (it has no sign-in).'] : [];
    const p = [];
    const worker = c.role !== 'admin', admin = c.role !== 'worker';
    if (!c.orgDomains.length) p.push('ORG_DOMAINS is not set (your organization\'s own domains).');
    if (!c.delegatedServiceAccount) p.push('DELEGATED_SA is not set (the service account with domain-wide delegation).');
    if (worker) {
        if (c.safeBrowsing && !c.safeBrowsingKey && !c.safeBrowsingSecret) p.push('SAFE_BROWSING=true needs SAFE_BROWSING_KEY (an API key restricted to the Safe Browsing API, from Secret Manager).');
        if (c.watchScope !== 'domain' && !c.pilotGroups.length && !c.pilotOu && !c.pilotUsers.length) p.push('None of PILOT_GROUP, PILOT_OU or PILOT_USERS is set: no mailbox would be watched.');
        if (!c.pubsubTopic) p.push('PUBSUB_TOPIC is not set.');
        if (!c.pushAudience || !c.pushServiceAccount) p.push('PUSH_AUDIENCE and PUSH_SERVICE_ACCOUNT must be set, so only Pub/Sub and Cloud Scheduler can call the worker.');
        if ((c.pilotOu || c.pilotGroups.length || c.watchScope === 'domain') && !c.directoryAdmin) p.push('DIRECTORY_ADMIN is not set (an admin the service may act as to list the members of PILOT_GROUP or the users of PILOT_OU).');
    }
    if (admin) {
        if (!c.iapAudience) p.push('IAP_AUDIENCE is not set: the dashboard must sit behind Identity-Aware Proxy.');
        if (!c.adminEmails.length && !c.adminGroups.length) p.push('Neither ADMIN_EMAILS nor ADMIN_GROUP is set: nobody could use the dashboard.');
        if (c.adminGroups.length && !c.directoryAdmin) p.push('ADMIN_GROUP needs DIRECTORY_ADMIN (an admin the service may act as to check who is in the group).');
        if (c.moderatorGroups.length && !c.directoryAdmin) p.push('MODERATOR_GROUP needs DIRECTORY_ADMIN (an admin the service may act as to check who is in the group), or MODERATOR_GROUP=off.');
    }
    if (!(Number.isInteger(c.retentionDays) && c.retentionDays >= 14 && c.retentionDays <= 365)) p.push('RETENTION_DAYS must be a whole number of days from 14 to 365.');
    if (!(c.aiSuspicious >= 0.5 && c.aiSuspicious <= 1)) p.push('AI_SUSPICIOUS_THRESHOLD must be between 0.5 and 1.');
    if (!(c.aiThreshold > 0.5 && c.aiThreshold <= 1 && c.aiThreshold >= c.aiSuspicious)) p.push('AI_MOVE_THRESHOLD must be between AI_SUSPICIOUS_THRESHOLD (where an email counts as suspicious) and 1.');
    return p;
}

module.exports = { loadConfig, configProblems };
