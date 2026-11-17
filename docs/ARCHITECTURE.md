# Architecture

```
Gmail (each watched mailbox)
   │  users.watch → "this mailbox changed" (historyId)
   ▼
Pub/Sub topic gmail-spruce ──push (OIDC: spruce-invoker)──▶ spruce-worker (Cloud Run, ROLE=worker)
                                                               │ history.list → new Inbox message ids,
                                                               │   and the Inbox label added back (user rescues)
                                                               │ messages.get (raw)          ┐ as the mailbox's user:
                                                               │ engine: MIME → facts →       │ domain-wide delegation,
                                                               │   extension checks + model  │ token signed by IAM for
                                                               │ policy → move / record      │ spruce-delegate (no key)
                                                               │ messages.modify (Spam)      ┘
                                                               ▼
                                                           Firestore (records, counters, state)
                                                               ▲
Admins and moderators ──Identity-Aware Proxy──▶ spruce-admin (Cloud Run, ROLE=admin): dashboard + /api/*
                                                  move back → messages.modify (Inbox)
                                                  ──▶ cloudflare-dns.com (and Cloudflare Security,
                                                      Safe Browsing, Spamhaus when on), for Health →
                                                      DMARC & reputation: your own domains' names

Cloud Scheduler ──(OIDC)──▶ worker /tasks/renew-watches (daily; a watch lasts 7 days)
                           ──▶ worker /tasks/sync-feeds (hourly: the health check, the phishing lists
                                once a day for everyone, re-checks of delivered mail, the cleanup of what
                                TTL doesn't delete)

worker ──▶ security.cloudflare-dns.com    host names (blocked = 0.0.0.0)
       ··▶ safebrowsing.googleapis.com    OFF by default (Settings → Safe Browsing): link addresses, no #part;
                                          its API key in Secret Manager (spruce-safe-browsing-key)
       ──▶ registries (RDAP, via IANA)    domain names, at most once a month each
       ──▶ cloudflare-dns.com             the look-alike watch: look-alike names of ORG_DOMAINS, a pass a day
       ──▶ cloudflare-dns.com, RDAP       brand ownership (0.5.64): a domain whose sender's name claims a brand,
                                          and the brand's domains (DMARC records, name servers, registration)
       ··▶ *.dq.spamhaus.net (DNS)        OFF by default (Settings → Spamhaus): domain and host names, with the DQS key
       ··▶ urlhaus-api / threatfox-api    OFF by default (Settings → abuse.ch): the lists' downloads, with the key
                                          (both keys in Secret Manager: spruce-spamhaus-key, spruce-abusech-key)
       ◀── Firestore blobs/feed_*         the phishing lists, gzipped, shared by every instance
```

## An email, step by step

1. **Gmail says a mailbox changed.** Each watched mailbox has a Gmail watch (`users.watch`, renewed daily by the
   `spruce-renew-watches` job; a watch lasts 7 days). Gmail publishes `{ emailAddress, historyId }` to the
   Pub/Sub topic `gmail-spruce`, which pushes it to the worker's `/pubsub` with an OIDC token the worker
   verifies (`src/auth/verify.js`).
2. **What is new in that mailbox.** `handleNotification` reads the mailbox's history since its last position
   (`history.list`, `src/gmail/client.js`): messages added to the Inbox, and messages that got the Inbox label
   back (a user taking one out of Spam). The position only moves forward, once every message is done.
3. **One instance claims each message** (`seen/{user|id}` in Firestore, `store.claim`), reads it raw
   (`messages.get`, format raw) and skips what isn't new Inbox mail: sent mail, drafts, what Gmail already put
   in Spam, the service's own weekly summary. A mailbox owner's own sent copy (Gmail's SENT label, or from the
   owner's own address with nothing showing it was ever delivered) is never judged, on arrival, on the
   re-checks or on Re-scan (`ownSentCopy` in `src/pipeline.js`, 0.6.3).
4. **The message is read** (`src/engine/mime.js`): the headers and Gmail's own DMARC, SPF and DKIM results,
   the sender and the other address lines, the links (with their text), the text a person sees and how the
   email is laid out (hidden filler, image-only bodies), the attachments (kept in memory only). When Gmail
   wrote no DMARC result for one of the organization's own domains, it is worked out from the SPF and DKIM
   results Gmail verified, as DMARC defines it (`deriveDmarc`, 0.6.3); other senders keep what Gmail wrote.
5. **A phishing-training email** matching Settings → Phishing training (`src/simulations.js`, 0.5.44) is let
   through here: counted, nothing else.
6. **The checks** (`src/engine/analyze.js`, with the engine in `vendor/spruce/`) add up signs, each with a
   weight (below). The sum is the rules' score: 3 is amber (suspicious), 5 is flagged.
7. **The AI model** (phish-tiny, `src/engine/model.js`) scores the email from 0 to 100%, unless the sender is
   inside the organization (and "AI on inside mail" is off) or the email is clearly not in English.
   It is given the email's facts (`aiFacts` in `src/engine/analyze.js`): subject, sender, DMARC, links and what
   the link checks found, layout, header findings, the text; and, for the model's input format 2 (since
   phish-tiny 0.16.0; the current model, 0.22.0, reads format 3, which has them too; a format-1 model leaves them out), what the sender checks found: who the
   sender's name claims to be and whether the domain is theirs (`aiSenderIdentity`), Reply-To domains that
   aren't the sender's, the attached files' kinds (never their names) and failing SPF/DKIM. A long text is given as
   its first 6,000 and last 2,000 characters, and the model (since phish-tiny 0.20.0, `config.headTokens`) reads its
   first 192 and last 62 word pieces, because a long scam often asks at its end. Its text keeps 60 sentences of a
   longer one: since phish-tiny 0.21.0 (input format 3, 0.5.67) the first 40 and the last 20, so that end is the
   email's real ending (format 2 kept the first 60).
8. **The policy decides** (`src/policy.js`, `decide`): allowlisted and DMARC passing, nothing; the rules
   flagged it, or the AI scored it at the move threshold (90%; from outside, or inside with "AI alone moves
   inside mail"), move; a rules score of 3 or an AI score from the suspicious line (65%), suspicious; in
   monitor mode a move is recorded as "would move".
9. **The brakes** (`brakes`, below) may hold a move: an admin's decision on the campaign, the campaign
   pause on weak evidence, the domain-wide brake.
10. **It is carried out:** `messages.modify` adds `SPAM` and `SPRUCE/Moved` and takes `INBOX` off; in
    monitor mode `MONITOR_LABEL` if set; for a suspicious email, the Suspicious label when that setting is on.
11. **It is recorded** (`records/{user|id}`), only when something happened (moved, would move, suspicious):
    the sender, the subject (`STORE_SUBJECTS`), the signs, the flagged links, the AI score and its short
    quotes, the decision and why. The day's counters (`stats`) count every email.
12. **It is marked done** (`seen`), with, for an email left in the Inbox, up to 24 one-way hashes of its link
    sites and sender, to find it again when a phishing list later adds one (0.5.35, below).

## The checks

| Group | What it reads | Signs (weights) | Where |
|---|---|---|---|
| Headers | Gmail's DMARC, SPF and DKIM results; forged or spam headers | DMARC failing, a forged inside address, spam headers (2 to 5) | `headerAnomalies`, `insideSpoofSigns` |
| The sender's name | the display name against the address | a brand's name on another address (5), your own address in the name, a colleague's name from outside when the email claims to be from inside (3, 0.5.43) | `nameAddressSigns`, `colleagueInContext` |
| The other address lines | Reply-To, Cc, To | replies to an outside address under a colleague's name (3), a colleague copied in at an outside (1) or look-alike (3) address; since 0.6.19 only together with another warning sign | `colleagueLineSigns`, `signsNeedingCompany` |
| The words | the subject and the visible text | scam phrases, requests for passwords, codes, money or remote access, claims to be safe, a fake reply chain (2) | `subjectScamSigns`, `bodyScamSigns`, `highRiskRequestSigns`, `fakeReplySigns` |
| The layout | how the email is built | hidden filler after a blank gap (since 0.6.19 only with another warning sign; in list or marketing mail with nothing else wrong: spam, moved as such), an image-only body | `layoutSigns`, `signsNeedingCompany` |
| The sender | how new and how known | a new sender from outside, a young or look-alike domain, the look-alike watch's domains (2 to 5) | `senderContextSigns`, `src/engine/network.js`, `watchedLookalikeSigns` |
| The links | each link, unwrapped offline (redirects, security gateways, shorteners' known forms) | look-alike brand domains, text showing another site (not when it goes to the sender's own or another established company's proven domain, 0.6.17/0.6.19), hidden user names; then Cloudflare, Safe Browsing, the phishing lists (and abuse.ch's), site age, Spamhaus | `detectLinkProblem`, `src/engine/network.js` |
| Attachments | pictures, PDFs, Office files, web pages and SVGs sent as files, archives (in memory) | a QR code's or a document's links (checked like the email's), a sign-in form or script in a file (4 to 5), double extensions, programs, password-protected archives, macros (2 to 3) | `src/engine/attachments.js` |
| Platforms | Drive, Docs, Classroom, DocuSign… notifications | judged by the person behind them; mass shares from one outside account | `src/engine/notifications.js` |

What confirms a flag from outside the email (a blocked or listed link, a listed or blocked sender, a brand-new
look-alike domain, DMARC failing) makes it **strong evidence**: the campaign pause never holds it.

## What is stored where

Firestore, in your own project and region (`src/store/firestore.js`). Each document that expires carries
`expireAt`, and Firestore's TTL policies delete it then.

| Collection | Holds | Kept |
|---|---|---|
| `users` | each watched mailbox: its sync position, last notification, watch's end | while watched |
| `seen` | each message checked: claimed, done or failed; for one left in the Inbox, its re-check hashes and arrival time | `RETENTION_DAYS` |
| `records` | each email moved, would move or suspicious (above); an admin's or user's decisions; re-checks | `RETENTION_DAYS` |
| `stats` | the day's counters: checked, moved, would move, suspicious, moved back, training emails, errors | kept |
| `senders` | a 64-bit hash of each sender address and when it was first seen | kept |
| `campaigns` | the campaign pause and an admin's decision on a campaign | `RETENTION_DAYS` |
| `moveCounts` | the brake's hourly counters; the mass-share counters | 2 days |
| `events` | Activity: alerts, admins' actions, errors | `AUDIT_DAYS` |
| `blobs` | the phishing lists, gzipped, shared by every instance | replaced daily |
| `cache` | registry dates of domains; brand-ownership answers (0.5.64) | 30 days (an unknown answer: 1 day) |
| `state` | one document per setting or state: the policy changed on the dashboard (`policy-*`), the brake, the lists' health, each optional service's key metadata (never the key) and health, the re-check queue, the look-alike watch, the phishing-training rules (secret values as hashes), the last update, the weekly summary and retraining switches… | until changed |

Secrets (the Safe Browsing, Spamhaus and abuse.ch keys) are only in Secret Manager.

## The hourly job

Cloud Scheduler calls the worker's `/tasks/sync-feeds` every hour (`syncFeeds` in `src/pipeline.js`), within
the worker's 120-second request time. In order:

1. **The health check:** no notification from Gmail for `QUIET_HOURS`, watches about to end, errors in the
   hour; each an alert.
2. **The weekly summary**, on Monday from 7 AM, when it is on.
3. **The phishing lists:** downloaded once a day for everyone (and abuse.ch's, when on); a list that missed its
   download is tried again 3 hours later. A download with the same entries as the copy kept isn't written again
   (so the instances don't load it again), and still counts as downloaded (0.6.7). What a download adds is
   looked for in delivered mail (below).
4. **Re-checks:** suspicious mail an hour old (looked for up to 6 hours after it arrived) and a day old (up to
   30 hours) is queued (0.6.7), and (0.5.51) after an update that changes how email is checked, the next of the
   recent mail still in the Inbox; the queue is checked for up to 40 seconds (the rest the next hour).
5. **Link clicks** (when on): Gmail's logs for the re-checked mail, up to 15 seconds.
6. **The look-alike watch:** the next 80 look-alike names, up to 12 seconds (a pass a day).
7. **Updates:** an update from the dashboard that failed or stalled, an approved version that needs a manual
   install; each alerted once.
8. **Watches:** a renewal the daily job didn't finish (a whole domain) is continued. After `deploy/stop.sh`
   (0.6.7), Gmail is told to stop notifying for the mailboxes still left instead, and no watch is renewed
   while stopped.
9. **Cleanup** of what Firestore's TTL doesn't delete, with the time left (at most 30 seconds).

`spruce-renew-watches` runs daily: it reads the pilot group again and renews every watch. `deploy/stop.sh`
pauses it and calls `/tasks/stop-watches` (0.6.7): every mailbox stops counting as watched at once (its
notifications are ignored, `PILOT_USERS` too), then Gmail is told to stop notifying, 10 mailboxes at a time,
within the request's time; the hourly job finishes the rest. Any renewal (`install.sh`, the daily job, the
dashboard's "Read the directory again now") starts it again.

## Re-checking delivered mail

Phishing sites are often listed hours after their email arrived (0.5.35, `src/recheck.js`). A list's download
reports what it added since its previous copy; those entries are hashed the same way as the emails' link
sites and senders, and Firestore finds the `seen` markers holding any of them (`array-contains-any`, 30 at a
time). Each email found is read from Gmail again and checked in full, and the policy acts as on arrival
(through the brakes): moved, would move, or suspicious.

Since 0.5.51 the hashes also hold the sender's domain and its Reply-To domains (with the domains above
them; never a personal mailbox provider's or the organization's), so a look-alike of the district's domain
that the watch finds, or that an admin marks a threat, finds the mail from it, replying to it or linking to
it the same way. And an update that changes how email is checked re-checks recent mail: `package.json`'s
`checksLevel` is raised in a version that changes a rule, a sign, the AI model, how the lists are matched or
what the policy does (`src/checks-level.js`; `test/checks-level.test.js` keeps a fingerprint of the files that
judge email, so such a change can't go out without that decision: either the level raised or the change
recorded as cosmetic). The hourly job remembers the level it last ran (`state/checksLevel`); a higher one
starts a sweep (`state/updateRecheck`) of the `seen` markers of the mail delivered in the
`RECHECK_AFTER_UPDATE_HOURS` before this instance started (by `rx`, newest first, on its single-field index),
queued as the queue has room (1,500 an hour at most), up to `RECHECK_AFTER_UPDATE_MAX`. Mail that arrived
after the instance started was judged by the new version already and isn't taken. A version that changes
only the dashboard, wording or documentation keeps the level and re-checks nothing. An email its reader archived or deleted, or one an
admin decided on, is never moved. Threats → Re-checked lists them with who got each copy and whether they opened
it; with Link clicks on, Gmail's logs (Admin SDK Reports API) add who clicked a link in it.

## The look-alike watch

`src/lookalike.js` (0.5.36) makes a fixed list of look-alikes of `ORG_DOMAINS`: letters left out, doubled,
swapped or replaced by look-alikes, other endings, a district's usual forms (`name-k12.org`,
`nameschools.com`), a role added. Each hour the next 80 are asked of Cloudflare's public resolver (does the
name exist, with mail servers, with a website); a pass a day. The first pass takes stock; a name that
appears later, or one registered in the last 30 days, is an alert and a strong sign in mail from it, replies
to it and links to it. Admins mark each one: the district's own, harmless, or a threat.

## Optional services

All off by default, each turned on on its own Settings page with a key kept in Secret Manager:

- **Google Safe Browsing** (Lookup API v4): link addresses (no `#` part; one-time links without their query),
  the key in a header. Free for non-commercial use.
- **Spamhaus** (the free Data Query Service): the DBL and ZRD, by DNS, `<name>.<key>.dbl.dq.spamhaus.net`,
  through Cloud Run's resolver; at most `SPAMHAUS_DAILY_MAX` lookups a day for every instance together, each
  name once an hour; a refused lookup asked again (a new key takes up to an hour to sync across Spamhaus's
  servers).
- **abuse.ch**: URLhaus's 30-day export and ThreatFox's last 7 days, downloaded daily like the phishing lists.
- **Link clicks**: Gmail's log events, as an admin with the Reports privilege.

Their data is never exported for retraining: their terms don't allow it to train an AI model.

## Security

- **Who can reach what.** The dashboard (`spruce-admin`) is behind Identity-Aware Proxy, and the server checks
  every request's signed IAP header against `ADMIN_EMAILS` and `ADMIN_GROUP` too (`MODERATOR_GROUP`: the review
  pages' routes only, `MODERATOR_ROUTES` in `src/server.js`). The worker is private: only
  `spruce-invoker`'s OIDC tokens (Pub/Sub, Cloud Scheduler) are accepted, their audience and account checked.
- **No key files.** Domain-wide delegation tokens are signed by IAM (`iamcredentials.signJwt`) for
  `spruce-delegate`, last an hour and stay in memory.
- **Changes need the project ID.** Every policy change, key, mark or update asks for the Google Cloud project
  ID (and enforce mode, or letting the AI alone move inside mail, a ticked agreement). Each wrong answer is
  noted (never what was typed); five lock the admin out for 10 minutes and are an alert.
- **The dashboard can't deploy.** Settings → Update only starts the fixed `spruce-update` job, which builds
  an approved commit of the installation's release repository (`RELEASES_REPO`) and checks it again. (0.6.9) An
  admin can change that repository on the dashboard (Settings → Update → Repositories): the job's steps stay fixed and
  read it from the update request; the change needs the project ID, a ticked box and the admin's own address, and is
  an alert, because the release repository decides what code an update installs.
- **The page itself:** a strict Content Security Policy (no inline scripts, nothing from elsewhere), no
  framing, `no-store`; every change is a POST with a custom header, which a page on another site can't send.
- **Little kept.** No email bodies or attachments; subjects and the AI's quotes can be turned off; senders as
  hashes; secrets only in Secret Manager.

## Why these choices

- **After delivery (Gmail API), not in the mail path.** Nothing in mail routing changes, so the service
  can't delay or lose mail. The cost is a few seconds in which a new email is visible before it's moved.
  Real admin quarantine needs an inbound gateway; Google offers no API that puts messages there.
- **Two services, one image.** Pub/Sub and Scheduler can't sign in through Identity-Aware Proxy. So the
  worker is private (only `spruce-invoker` may call it) and has no dashboard, and the dashboard has no
  worker routes. The dashboard's "Read the directory again now" doesn't call the worker either: it asks
  Cloud Scheduler to run the daily `spruce-renew-watches` job at once (`src/scheduler.js`), which calls
  the worker as every day.
- **Updates from the dashboard, without giving it the right to deploy.** Settings → Update only records
  the request (a version and its exact commit) and runs the `spruce-update` job, whose build install.sh
  fixed. The build runs as `spruce-updater`, downloads the release repository the request names (else
  `settings.env`'s), takes its steps from there, passes the model repository to the image build, and checks
  everything again before building: a recent request, a commit on the release repository's main branch
  with that version, newer than what runs, and no higher `installLevel` than the one installed. So a
  dashboard admin, or someone who took over a dashboard session, can at most install an approved
  version that is newer, never their own code. A version that changes the installation (roles, jobs,
  settings) still needs `install.sh`, run by someone who can change the project.
- **The checks and the model, run as written for the browser.** `vendor/spruce/` began as the
  S.P.R.U.C.E+ extension's code; since 0.4.0 it is this project's own (changed here, with tests). It
  runs in a separate JavaScript context with a small stand-in for the browser, as the extension's own
  unit tests ran it.
- **No key files.** `spruce-run` asks IAM to sign each delegation token for `spruce-delegate`
  (`iamcredentials.signJwt`). Tokens last an hour and are kept in memory.
- **Safe to repeat.** Pub/Sub delivers at least once, and Gmail often sends several notifications for
  one email.
  - **One instance at a time judges a message.** It claims the message ID in Firestore first, and marks
    it done afterwards. A claim left by an instance that stopped is taken over after 5 minutes.
  - **A failed check is tried again, 3 times in all.** Until every message in a mailbox's notification is
    done, the mailbox's sync position stays where it was. The worker answers Pub/Sub with 503, and Pub/Sub
    delivers the notification again 30 s to 10 min later. After the third failed try the message is
    left where it is, with an alert, and the mailbox moves on.
  - **A move whose record failed isn't lost.** The next try sees the service's own `SPRUCE/Moved`
    label and writes the record without moving the email again.
  - **The sync position only moves forward,** whichever notification finishes last. History is read
    4,000 messages at a time; a longer backlog is read in parts, never skipped.
- **Brakes for a whole district** (`brakes` in `src/pipeline.js`). A move first passes:
  - **an admin's decision on the campaign** (a false alarm: not moved; confirmed: moved);
  - **the campaign pause**, for weak evidence only (no outside confirmation): past `CAMPAIGN_HOLD_AFTER`
    copies of one campaign, moving the rest pauses. Strong evidence never pauses;
  - **the domain-wide brake**, a last resort: a slot is reserved in the hour's count before each move, in
    up to 32 Firestore shards whose limits add up to the limit exactly.

  Copies not moved meanwhile stay in the Inbox like any other email, recorded as "would move" (`held` on
  the record), and can be moved later: on **Resume, and move those to Spam**, or when the campaign is
  confirmed (`moveHeld`). A single recorded email an admin confirms as phishing on Review (or its own
  page) is moved the same way (`moveRecord`), in enforce mode only and only while it is still in the
  Inbox: the service's rules never move a suspicious email, an admin's decision can. Nothing is ever
  withheld from a mailbox. The counters are spread so one busy
  campaign doesn't make every move wait for one Firestore document; the daily stats are spread too.
- **Alerts.** An alert is a problem the admins are emailed about (0.5.28; docs/ALERTS.md says what each means
  and what to do). The service logs each one as a
  structured line (`spruceAlert`, `message`) and adds it to Activity → Alerts; Cloud Monitoring emails them,
  and any failed Cloud Scheduler job, to `ALERT_EMAIL` (log-based alert policies made by `deploy/install.sh`).
  They are: a phishing list that missed its download; Cloudflare Security or Safe Browsing whose every
  lookup failed for 30 minutes, or Google refusing the Safe Browsing key; the AI model not working in the
  worker; Gmail refusing the service (domain-wide delegation removed), an email left unchecked after three
  tries, or 25 errors in an hour (0.5.29); missed changes (Gmail's history ran out) 10 times in 24 hours, or 3
  times in 7 days for one mailbox (0.5.31; `GAPS_ALERT_DAY`, `GAPS_ALERT_MAILBOX`); an admin's account locked after five wrong project IDs (0.5.29); no notification from Gmail for `QUIET_HOURS`, or watches about to end; the directory not readable;
  the brake; a campaign whose moving paused, a large campaign, a mass share from one outside account; a
  user taking a flagged email out of Spam or into the Inbox; an update from the dashboard that failed or
  never finished; an approved version that needs a manual install. A problem that lasts is emailed at most
  once a day. An admin's own change (a policy change, an update started, a Safe Browsing key) is not an
  alert: it is noted in Activity → What admins did, and not emailed. With `PUBSUB_BACKLOG_ALERT=on` (off by
  default: Google charges for it), Cloud Monitoring also emails when Gmail's notifications wait in Pub/Sub over
  30 minutes.
- **Audit trail (0.5.29).** Activity is kept `AUDIT_DAYS` (a year by default), apart from the email records;
  admins' downloads of the email list or of Activity, their first visit to the dashboard each day, and every
  wrong project ID or email address (what it was for and which try, never what was typed; 0.5.30) are
  noted too. `GET /api/activity` takes any period kept, a kind and words to look for; `/api/activity.csv`
  downloads it (noted). With `AUDIT_LOG=on` (off by default) each entry is also a structured log line
  (`spruceAudit`), which a sink routes to the log bucket `spruce-audit`, kept `AUDIT_LOG_DAYS`. The hourly `spruce-sync-feeds` job runs a
  health check: no notification from Gmail for `QUIET_HOURS`, or watches about to end. It also downloads
  the phishing lists once a day, and a list whose download failed again 3 hours later
  (`state/feedHealth` keeps each list's last download); a list that newly fails, and once a day one that
  keeps failing, is an alert (`list-download`), on Today until it downloads again, and on Settings →
  About, whose Re-check (`POST /api/lists/recheck`) downloads it at once.
- **Mail that skipped the checks.** An email the user moves into the Inbox that the service never
  checked (it went to Spam first) is checked when its Inbox label shows in the history, and never moved.
  After a gap in a mailbox's history, its Inbox since the last notification is checked in batches of 25
  with the next notifications.
- **The weekly summary** (`src/digest.js`; off until an admin turns it on in Settings → Weekly summary) is put straight into
  each admin's Inbox with the Gmail API's `messages.insert`, which the `gmail.modify` scope already allows.
  Nothing is sent, nothing leaves Google, and no mailbox or new permission is needed. The hourly job sends
  it on Monday from 7 AM in `TIME_ZONE`, once a week whichever instance runs. The service never judges its
  own summary: it is marked as seen, and has the `X-SPRUCE-Summary` header with no `Received:` header,
  which mail from outside always has.
- **The retraining export** (`src/training.js`; off until an admin allows it in Settings → Retraining). The emails an
  admin marked are read from Gmail when an admin downloads them: one per campaign, the newest copy still
  in a mailbox. Each is judged again as on arrival, with `analyze(..., { keepAiFacts: true })`, to get
  what the model read. It is then written in the model's training format (`{ name, label, note, facts }`,
  as in TinyPhishLLM_Private_Training's `training/data/extra/`), with the people taken out:
  - the headers' names (`mime.readMessage`'s `people`);
  - titles, greetings and sign-offs;
  - the organization's domains;
  - the model's own redaction (`redactForAi`, `maskRecipient` from `vendor/spruce/ai.js`).

  Other possible names are marked ⟦like this⟧: common names (`src/names.js`) and words the model's
  vocabulary doesn't have, when they start a sentence; most capitalized words in the middle of one.
  Nothing is stored or counted. `tools/check-training-file.js` refuses a file with leftovers, and
  `docs/RETRAINING.md` covers the rest.
- **The policy, changed on the dashboard** (Settings → Policy, Settings → Allowlist).
  - **Which settings:** `MODE`, `AI_MOVE_THRESHOLD`, `AI_SUSPICIOUS_THRESHOLD`, `BRAKE_PER_HOUR`,
    `TIME_ZONE`, `ALLOW_DOMAINS`, `ALLOW_ADDRESSES` and `RETENTION_DAYS`, kept in Firestore as
    `state/policy-<key>`. Each document's expiry date (`expireAt`) is computed from the retention in
    force when it is written. The
    suspicious line is checked against the move threshold both ways (`policyValue`).
  - **How they apply:** in `loadConfig` these four are live values; everything else is frozen.
    `Service.refreshPolicy` reads them at least every 30 s (on each notification, each job, each
    dashboard request). Every check reads them when it runs, so a change applies everywhere within
    30 s.
  - **Settings.env:** a change records the settings.env value it replaced. If settings.env later has
    another value, that one is newer and applies.
  - **The installer:** `deploy/dashboard-policy.sh` (used by `install.sh`) takes the dashboard's value
    where settings.env is silent and asks which to keep where they differ. It writes the answer into
    settings.env, removes the dashboard's copy once the new build is deployed, and notes it in
    Activity.
  - **The server** checks the project ID against `GOOGLE_CLOUD_PROJECT`, and the agreement for enforce
    mode.
- **The dashboard reads little.** It keeps a copy of the records (`src/dashboard/cache.js`). After one full
  read, it asks only for records changed since (each record has `updatedAt`), at most every 15 s, however
  many dashboards are open.
- **Lookups that never block mail.** Every lookup has its own time limit and limits on requests at once,
  and answers are remembered (6 hours to a day; registry dates 30 days, shared). One that fails or is
  slow leaves the email "not checked". The verdict can only get stronger from a lookup, never weaker.
- **The user has the last word.** When a user takes a moved email back to the Inbox ("Not spam", or
  dragging it out of Spam), the history shows the Inbox label added back.
  - The record becomes "moved back by the user" and counts as a false alarm until an admin marks it
    otherwise. The service never moves that email again.
  - Only a label added after the service read the email counts. The label an email arrived with can show
    in the same history, and the two are told apart by their history IDs.
  - An admin's own move back is noted on the record first, so it isn't counted as the user's.
- **Records only for what matters.** Clean mail is counted per day, not recorded, which keeps Firestore
  small and private.
- **Re-checking delivered mail (0.5.35) without recording clean mail.** An email left in the Inbox keeps, on
  its `seen` marker (the write that marks it checked, so no extra write), up to 24 one-way hashes of its link
  sites and sender (`src/recheck.js`). A list's download reports what is new since its previous copy
  (`feeds.sync`); the hourly job hashes those entries and asks Firestore for the markers holding any of them
  (`array-contains-any`, 30 at a time, on Firestore's automatic single-field index), queues them
  (`state/recheckQueue`, at most 3,000), and checks them in full within its time (40 s; the rest the next
  hour), 12 at a time, through the same decision and brakes as on arrival. Suspicious records an hour and a
  day old are queued the same way. With Settings → Link clicks on, the Admin SDK Reports API's Gmail log
  events of each re-checked copy's recipient (opened, link clicked) are read as an admin with the Reports
  privilege, filtered by `event_info.mail_event_type`, and matched to the email by its Message-ID.

## Platform notifications and outside shares

A share or notification that a platform sends for a person (Google Classroom, Drive, Docs, Forms, Calendar;
DocuSign; Dropbox; Adobe Acrobat and Acrobat Sign; SharePoint; Box) carries the platform's address and passes the
platform's sender check, whoever the person is. `src/engine/notifications.js` recognizes one only when
Gmail's DMARC check passed for the platform's own domain, the sender is a notification mailbox, and (0.5.49) the
platform its name says it comes "via" belongs to the same company as the domain (`platformClaim`: "via Dropbox"
from google.com is no notification, and `platformClaimSigns` makes it red, as a platform named on a domain that
isn't any platform's while the brand check doesn't know it, such as Box), then
judges it by the person's own address: the Reply-To the platform set, or the "Name (address)" in its text
(none for Classroom: unknown). An outside share (such a notification for a person outside, or an outside
email linking a document, form or signature request) gets the colleague-name, sign-in and mass-share checks;
`pipeline.js` counts each outside account's reach per hour (`store.shareReach`) and alerts at 10.

## Throughput

The model doesn't read mail from inside the organization (your domains, DMARC passing) unless
`AI_SCANS_INSIDE` (Settings → Policy) is on, or `AI_MOVES_INSIDE` ("AI alone moves inside mail", which
needs it): the rules alone judge it (`src/engine/analyze.js`). The model reads English only: `src/engine/language.js` finds an email clearly in another language (its
writing system, or the commonest words of other languages), and then the model isn't run and the AI
gives no score, saying why (the rules run as always).

The model runs in ONNX Runtime (`src/engine/model.js`, from `models/phish-tiny/model.onnx`). Since 0.5.50 it
is an ELECTRA-small network (phish-tiny 0.18.0, 0.19.0 since 0.5.54, 0.20.0 since 0.5.55, 0.21.0 since 0.5.67, and 0.22.0 since 0.5.69; 12 layers; 14 MB): about 68 ms for a full-length pass on one
Cloud Run CPU, one thread, at the "basic" graph optimization level (the higher levels turn the 8-bit weights
into 8-bit arithmetic, which changes the answers); the BERT-tiny models before it took about 6 ms. An email's
explanation passes (its sentences) run as one batch, and only for an email the model leans toward phishing.
An ordinary email takes about 50 ms of processor time; one the model flags, with its explanation, about
420 ms; the rest is waiting for Gmail and Firestore. So each worker instance takes 32 requests at a time
(`--concurrency=32`) and checks at most 12 emails at once, 2 of them large (over 4 MB): roughly 15 emails a
second per instance before its processor is full (it was about 28 with the old model). A district of 10,000
mailboxes (about 100,000 emails a day, about 1 a second on average) still needs one instance outside
campaigns; during one, Cloud Run adds instances up to `WORKER_MAX_INSTANCES`.

Gmail API quota is per user and per project. Every call names its user (`quotaUser`), so a busy
mailbox can't use up everyone's quota.
