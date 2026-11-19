# S.P.R.U.C.E Mail Protection Service for Google Workspace

**Two repositories.** `spruce-google-service_testing` is where it's developed and tested.
`spruce-google-service_main` holds only the versions the maintainer has tried and approved, each copied there
unchanged. Which one you're reading: the repository's name on GitHub, or `git remote get-url origin`.
The version is in `package.json` and `CHANGELOG.md`.

S.P.R.U.C.E Mail Protection Service checks every new email in your Google Workspace domain with the same
checks and AI model as the S.P.R.U.C.E+ browser extension. It moves suspicious ones to Spam, or in
monitor mode only records them. An admin dashboard shows what was moved, why, which campaigns came in
and who was affected, and lets IT move an email back to the Inbox. Nothing is ever withheld: every email
reaches the user's mailbox, and the service only moves the suspicious ones to Spam (or not, in monitor
mode).

- **Runs in your own Google Cloud project** (Cloud Run, Pub/Sub, Firestore). Email is read through the
  Gmail API with domain-wide delegation and is not sent to any other service.
- **Its own checks, and the shared AI model.** `vendor/spruce/` holds the checks (`shared.js`,
  `decoders.js`) and the code that runs the phish-tiny model (`ai.js`). They began as the S.P.R.U.C.E+
  browser extension's; since 0.4.0 they are this project's own code, changed here. The model comes from
  **TinyPhishLLM**, the model's own public repository, which the extension uses too: each version pins
  one commit and every file's SHA-256 (`VENDOR.json`, by `tools/sync-model.js`), and every build of the
  image (install, update, Settings → Update) downloads the model from there and checks it
  (`tools/fetch-model.js`); the model's files are not in this repository. Since 0.5.0 the model runs in ONNX Runtime (the
  native engine, `src/engine/model.js`): about 25 times faster than the JavaScript that ran it, with
  the same answers.
- **Careful by default:**
  - **Monitor mode** (records, moves nothing) until you switch to enforce mode.
  - **The AI doesn't read mail from inside the organization** (your domains, DMARC passing) unless
    you turn it on (Settings → Policy, "AI on inside mail"; `AI_SCANS_INSIDE`). The rule checks read it
    as any email (its links, its headers and the rest), and can move it, for example when a staff
    account is compromised and sends dangerous links. Even when the AI reads it, its score alone doesn't
    move inside mail unless you turn on **"AI alone moves inside mail"** (Settings → Policy, with a ticked
    agreement; `AI_MOVES_INSIDE`), off by default.
  - **Mail dressed up as inside is outside mail:** a staff address that fails Gmail's DMARC check is read
    by the AI and gets a sign of its own ("claims to come from inside your organization"), and so does an
    outside sender whose name shows one of your addresses ("it@your-district.org" <x@elsewhere>).
  - **Allowlisted senders and domains** are never moved (Settings → Allowlist, or `ALLOW_DOMAINS` and
    `ALLOW_ADDRESSES`). Your own domains can't be allowlisted, so a staff account taken over can still be
    caught.
  - **Allowed link domains** (0.5.73, Settings → Allowlist, or `ALLOW_LINK_DOMAINS`) are link sites a phishing
    list flagged by mistake, such as a newsletter's click tracker: a list's listing of their whole domain no
    longer flags their links, in anyone's mail, and the email shows a note saying it wasn't counted. A listing
    of the exact page still does, and Cloudflare, Safe Browsing and where each link leads are checked as
    before. Sites where anyone can put up a page, link shorteners and your own domains can't be added.
  - **Both need DMARC to pass.** The allowlist and "inside the organization" go by the From address,
    which anyone can write. They count only when Gmail's own DMARC check passed for its domain. A
    forged allowlisted or staff address is judged like any mail from outside, and the record says so.
    When Gmail writes no DMARC result at all for one of your own domains (it happens on mail between two
    accounts of one Workspace), it is worked out from the SPF and DKIM results Gmail did verify, as DMARC
    defines it (0.6.3). Other senders keep what Gmail wrote.
  - **Brakes that still protect a whole district** (`src/pipeline.js`, `brakes`):
    - **Moving clear phishing is never paused.** "Strong evidence" means the rules flag it *and* something outside
      the email confirms it: a blocked or listed link, a listed or blocked sender, a brand-new look-alike
      domain, or DMARC failing. Every copy is moved, to every mailbox.
    - **On weaker evidence, moving pauses per campaign.** Once `CAMPAIGN_HOLD_AFTER` (25) copies of one
      campaign were moved without outside confirmation, the others are left in the Inbox, like any email
      not moved, and recorded, until an admin decides: **Confirm phishing** moves every copy to Spam,
      **False alarm** moves the moved ones back to the Inbox. Other mail keeps moving.
    - **A domain-wide brake as a last resort:** more than `BRAKE_PER_HOUR` moves in an hour (by default
      half the watched mailboxes, at least 100) stops moving everywhere. That is a misfire on many
      unrelated emails, not one campaign. Counted exactly. While it is on, emails are left in the Inbox;
      **Resume, and move those to Spam** moves them afterwards.
    - **Alerts by email** when a brake engages, moving a campaign pauses, a large campaign arrives, Gmail goes
      quiet, or a scheduled job fails (`ALERT_EMAIL`, Cloud Monitoring).
  - **Every move can be undone** from the dashboard, and by the user: an email the user moves back
    out of Spam stays in the Inbox. It is recorded as moved back by the user (a false alarm unless an
    admin marks it phishing), and an alert asks an admin to check when the checks had flagged it.

## How it decides

For each new Inbox message:

1. The raw message is read the way the extension reads an opened email:
   - the sender, and Gmail's own DMARC/SPF/DKIM results;
   - the links, unwrapped offline;
   - the text a person sees, plus how the email hides text: filler after a large blank gap, or a body
     that is only pictures;
   - its attachments and pictures (0.5.34): QR codes in pictures, PDFs and Office files, links in PDFs and
     Office files, web pages and SVG pictures sent as files (a sign-in form, a script that builds or
     redirects the page), double extensions, programs and disk images, archives or PDFs that need a password,
     documents with macros. The links found are checked like the email's own.
2. The checks add up their signs:
   - forged or spam headers;
   - a brand-name or look-alike sender, or one named after the recipient;
   - dangerous links (0.6.25: one weight however many: 5 for a blocked or listed site, a look-alike of a brand's
     domain, a name hidden before an "@" or code to run; 3 for a site registered in the last 90 days or on
     Spamhaus's lists; 2 for links flagged only because their text shows another, well-known site);
   - claims to be safe, and requests for passwords, codes, money or remote access;
   - a new sender from outside the organization;
   - a fake reply chain ("RE:" answering nothing this mailbox has, 0.5.33): 2 when its headers name no earlier email,
     1 (0.6.23) when they do but the mailbox doesn't have it (copied in partway, or the earlier mail deleted);
   - a QR code, a sign-in page or script sent as a file, a risky attachment (0.5.34).
   - "call this number" scams: a phone number to call about a purchase you didn't make (also "if this looks
     unfamiliar"), and (0.6.18) a bill or renewal for security software or a tech-support plan (McAfee, Norton,
     Geek Squad…) with an amount and a number to call, sent from a free mail account: flagged on its own;
   - a mass mailer's placeholder left unfilled in the subject ({{Offer_Code}}, 0.6.18).

   A score of 3 is amber, 5 is flagged.
3. The phish-tiny model scores the email (0–100%).
4. The policy acts:

| Situation | Action |
|---|---|
| The rules flag it (score 5+), from any sender | **Move to Spam** (label `SPRUCE/Moved`) |
| The AI scores **90%** or more (`AI_MOVE_THRESHOLD`), sender outside the organization (or a staff address without DMARC passing): the AI score alone, no rule, link check or other sign needs to agree | **Move to Spam** |
| **Spam, not phishing** (0.6.19): list or marketing mail (an unsubscribe header or link) that hides a block of unrelated text below the message, with nothing else suspicious; not from an established sender (0.6.27: Gmail verified it and its domain is a year old or more, as real newsletters pad their emails too) | **Move to Spam** as spam (trigger "spam"; the user can take it back out) |
| Same, in monitor mode, or while moving is paused (a campaign on weaker evidence, or the domain-wide brake) | Left in the Inbox, recorded as "would move" (a paused one can be moved later) |
| An admin dismissed the campaign as a false alarm | Recorded as suspicious, not moved |
| The user moved it into the Inbox themselves, and the service hadn't checked it | Checked and recorded, never moved (an alert if flagged) |
| Sender inside (your domains, DMARC passing), and the rules don't flag it | Nothing: the AI doesn't read it (with "AI on inside mail" on: a score of 90% or more is recorded as suspicious, not moved by the AI alone; with "AI alone moves inside mail" on: moved, as from outside) |
| A rules score of 3 or more, or an AI score of **65%** or more (`AI_SUSPICIOUS_THRESHOLD`), below what moves it | Recorded as suspicious, not moved |
| Allowlisted sender, DMARC passing | Nothing |

It also looks things up (`src/intel/`; `docs/PRIVACY.md` says exactly what is sent where):

| Check | What is sent | What it adds |
|---|---|---|
| **Cloudflare Security DNS** | host names of link sites, the sender's domain and its organization's domain | a blocked link is dangerous; a blocked or nonexistent sender domain is a sign (a sender subdomain with no DNS records of its own, common for newsletters and no-reply addresses, is judged by its organization's domain, and is never "made up" when that domain exists or Gmail verified the sender: 0.5.62) |
| **Google Safe Browsing**: optional, off by default. An admin adds the API key (kept in Secret Manager) and turns it on in Settings → Safe Browsing | link addresses (no `#…`; one-time links without their query) | a listed link is dangerous |
| **Phishing lists** (OpenPhish, Phishing Army, HaGeZi Threat Intelligence Feeds, TweetFeed, Sefinek) | nothing: downloaded once a day (a list that misses its download: tried again every 3 hours, a red banner on Today, an alert to the admins, and Settings → About shows it with a Re-check button), matched in the service. A download with the same entries as the day before isn't written again, and still counts as downloaded (0.6.7) | listed links are dangerous; a listed sender address or domain is a sign. TweetFeed (domains researchers reported in the last 30 days) is a community report: a reported link is amber and a sign of 2, never dangerous on its own. Your own domains count only as exact listed links and addresses, never as a whole site or domain |
| **Site age** (registries, RDAP) | domain names, to their own registry | brand-new link sites and sender domains are signs (stronger with sign-in or payment wording) |
| **Brand ownership** (0.5.64; DNS over HTTPS and RDAP) | when a sender's name claims a brand its domain isn't known to be, or (0.6.17) a link goes to the sender's own company-named domain behind another site's text: the domain names | whose the domain is, from public records (its name servers, DMARC reports, a corporate registrar and registrant), as in the extension: "Xoom, a PayPal Service" from xoom.com (PayPal's name servers) is no sign; unproven, the sign stays. A government agency's name on GovDelivery (Granicus, the service agencies send bulletins through: "IRS Newswire" <irs@service.govdelivery.com>) is no sign unless its sender check failed (0.5.70). "Business via QuickBooks" (a brand only after "via") from the sender's own address, its DMARC passing, is no sign either, unless the domain carries the brand's name (0.5.74). A link whose text shows another site but which goes to the sender's own domain, its DMARC passing, Cloudflare finding nothing, and the domain named after one company (email-lakeviewhotels.example: Lakeviewhotels): when public records prove the domain is that company's, it is a note of no weight, not a dangerous link; a company's own click tracker, also behind a partner's text on a co-branded card (0.6.17). A brand's name from a domain the public records show is an established company's (a corporate registrar and long registration) but not the brand's (a bank sending mail about the card it issues in the brand's name): no sign when its DMARC passes, every link goes back to its own domain, none is flagged and the domain isn't new or listed (0.6.20). A brand's invoicing run by a payment company from its own domain (Walmart Business's Pay By Invoice from TreviPay): no sign when its DMARC passes, and the AI is told it is the brand's own sender (0.6.28). Any other such sender is learned: a reviewer's False alarm on an email whose only sign was a brand's name from another verified domain remembers that brand and domain (Settings → Allowlist → Brand senders your reviewers confirmed; 0.6.29) |
| **Spamhaus** (0.5.37): optional, off by default. An admin adds the district's free DQS key (Secret Manager) and turns it on in Settings → Spamhaus | the sender's domain and up to 5 link sites' names, by DNS, at most `SPAMHAUS_DAILY_MAX` (90,000) lookups a day | a link site on the Domain Blocklist for phishing, malware or botnet control is dangerous (the sender's domain: strong evidence); low reputation or an abused site: a sign; a domain first seen in the last 24 hours (ZRD): a sign |
| **abuse.ch** (0.5.37): optional, off by default. An admin adds the district's free Auth-Key (Secret Manager) and turns it on in Settings → abuse.ch | nothing: URLhaus and ThreatFox are downloaded once a day and matched in the service | links spreading malware, malware sites and control servers are dangerous, as the phishing lists' |
| **The look-alike watch** (0.5.36; `LOOKALIKE_WATCH`): a pass a day over look-alike names of your domains (a letter left out, swapped or replaced, other endings, `-k12`, `schools`…), Threats → Look-alikes | those names only, to Cloudflare's public resolver | a newly registered look-alike is an alert; mail from it, replies to it and links to it are strong signs (one there before the watch: a small sign; one marked as yours: none) |

**Reputation check before a newsletter's link is called dangerous.** A link whose text shows a well-known
site but goes somewhere else is dangerous, except when it goes through the click tracker of the mail
service that sent the email, and the lookups vouch for that service. The sending service needs no list:
it is the third party whose DKIM signature Gmail verified on the email (link.mail.beehiiv.com in an email
signed by mail.beehiiv.com for a podcast's own domain; never the sender's own domain). The lookups:
Cloudflare and the phishing lists checked its domain and found nothing (nor did Safe Browsing, when on),
and its registry date isn't recent (180 days or more). (The engine's own click-tracker recognition, such
as Mailchimp's, SendGrid's and, since 0.6.24, Adobe Campaign's, still applies.) Then it is a warning: the link is amber,
and the email gets 1 point, never enough to move it alone. Blocked, listed, recently registered, or not
checked (a lookup that didn't answer): dangerous, as before.

**Re-checking delivered mail** (0.5.35; Settings → Policy, on by default; `RECHECK`). Phishing sites are
often put on a list hours after their email arrived. Each email left in the Inbox keeps, with its "checked"
marker, short one-way hashes of its link sites and sender (never readable, never shown). When a phishing
list's daily download adds one, every email of the last 7 days (`RECHECK_DAYS`) that has it, in every
mailbox, is read again and checked in full, and the policy acts as on arrival: moved to Spam (enforce mode,
through the brakes) or recorded as "would move" (monitor mode). An email found suspicious on arrival is also
looked at again an hour and a day later (Safe Browsing or a list may know its site by then; 0.6.7: an hour later
is looked for up to 6 hours after it arrived, a day later up to 30 hours). Never moved by a
re-check: an email its reader already archived or deleted, or one an admin released or marked. Each is listed
on **Threats → Re-checked**, a red banner on Today and Messages says so, and the admins get an alert.

Since 0.5.51 two more things start a re-check:

- **A look-alike of your domain** that the look-alike watch finds, or that an admin marks a threat on Threats →
  Look-alikes: the delivered mail of the last 7 days sent from it, asking for replies to it or linking to it.
  (The hashes now include the sender's domain and Reply-To domains too, never a personal mailbox provider's.)
- **An update that changes how email is checked**: the mail delivered in the last 24 hours that is still in
  the Inbox (`RECHECK_AFTER_UPDATE_HOURS`), newest first, at most 5,000 emails (`RECHECK_AFTER_UPDATE_MAX`),
  over the next hourly runs. Only an update that changes the checks does this (a rule, a sign, the AI model,
  how the lists are matched, what the policy does with a score: `checksLevel` in `package.json` raised); one
  that changes only the dashboard, wording, documentation or installation re-checks nothing. Health →
  Activity says when it starts.

A lookup that fails leaves an email "not checked", never "safe". Short links are **not** looked up:
there is no outside unshortening service. A short link is judged by its own host and by what decodes
offline.

**The AI model reads English only** (it was trained on English mail). An email clearly in another
language (its writing system, or the commonest words of Spanish, French, Vietnamese, Haitian Creole and
others) gets no AI score: the dashboard says so, the rule checks run as for any email, and the
retraining export leaves it out. A bilingual email with a real English part is read.

**Delivery reports from mail providers** (0.6.22): a "Delivery Status Notification (Failure)" or "Undeliverable"
from a big mail provider's own mail system (its mailer-daemon or postmaster address at google.com, googlemail.com,
gmail.com, outlook.com, hotmail.com, live.com, yahoo.com, aol.com, icloud.com or me.com), with Gmail's sender check
passing and written as a delivery report (multipart/report), gets no AI score: the model read its failure wording
as a lure. The rule checks read it as usual, the returned copy included. Forged or from anyone else, it is scored.

**The colleague-name check:** the full names in your directory are read (by `DIRECTORY_ADMIN`, every 12
hours) and kept only as one-way hashes, in memory; an outside sender whose display name is one of them
("Jordan Exampleton" <jordan.exampleton.office@gmail.com>) gets a sign (3: amber; it moves mail only with
other signs, since staff sometimes write from a personal address), **when the email claims to be from inside**
(0.5.43): written from a personal email account, from an address imitating your domain or a brand-new domain,
with Gmail's sender check failing, with replies going elsewhere, with a title or your organization's name in
the sender's name ("Jordan Exampleton, Superintendent", also matched now), or asking what impersonators ask (a
favor, a phone number, gift cards, payment or payroll details, codes). A personal email account as the only reason
counts 2 (0.6.23: staff write from their own Gmail too); with any other reason, 3. People share names: a vendor's employee
with a colleague's name, writing a greeting from her company's own address, is shown but doesn't count. The same names are looked for in the
other address lines: **Reply-To** under a colleague's name going to an outside address (3: replies would
go to someone else), and a colleague **copied in** (Cc or To) at an outside address (1) or at an address
that imitates your domain (3: "I've copied our superintendent").

**Look-alikes written inside other domains** (0.6.32): a sender, reply address or link that writes the district's own
domain inside someone else's (district-k12-example.mail.other.example) counts 5; a hidden, empty decoy link beside a
visible one counts 5 (0.6.33: flagged on its own), unless it goes to the sender's own site and Gmail verified the sender (0.6.34: newsletters do that). A store's co-branded card mail from the bank that issues it (TD Bank, Synchrony, Citi…), linking to the bank's own site behind the store's address, isn't counted as dangerous links (0.6.33).

**The allow lists' 30-day check** (0.6.30): every domain on an allow list is looked up again every 30 days (its registration
and reputation). A change flags it for review (Settings → Allowlist, Today, and an email to every admin); registered
again, expired, gone, or now blocked or listed suspends it: not trusted until an admin answers "Still trusted" (which
can also release the emails it got meanwhile) or removes it.

**Spam or phishing, at a glance** (0.6.27): Review, Mail and an email's page label each email **Spam** (purple) or
**Phishing** (red), from what the service took it for, so a padded newsletter moved as spam isn't mistaken for phishing.

**Spam people took back** (0.6.26): when someone moves mail the service moved as spam (trigger `spam`) back out
of Spam, that sender's spam isn't moved for them again for 6 months: a sender is its organization's domain, or the
address itself at a personal mail provider, and only one Gmail verified (DMARC passing) counts, so a forged copy is
judged as usual. When 3 or more people took back the same sender's, it isn't moved as spam for anyone and is listed
in Settings → Allowlist → Spam people took back, where an admin can add it to the allowlist or keep moving it (each
person who took some back still keeps theirs). Phishing is never affected: mail moved as phishing and taken back
teaches nothing (it goes to the admins as a possible false alarm), and a remembered sender's mail is still checked
and moved if it is phishing. Kept as one-way hashes of the sender and the person, in the shared store's cache.

**Signs that need another sign** (0.6.19): text hidden far below the message after a blank space, a colleague's
name whose only reason to count is that the sender's domain resembles yours (a local group's domain with your
town's name in it), and a colleague copied in at an outside or resembling address count only together with
another warning sign. Alone, with only "it comes from outside" and "first email from this sender" beside them,
they are shown with no weight. A sender's name giving a brand's program and the sender's own organization
("Brand Future Coders - Sample Scholarship Fund" from samplescholarshipfund.example, DMARC passing) is a partner,
not an imitation (no weight; 5 again when the domain is new or listed). A link whose text shows a well-known
brand but which goes to another established company's own domain (a hotel chain's click tracker in a co-branded
offer) is not dangerous when public records prove that domain is the company's, it is old and clean, and the
sender passed DMARC; a page anyone can make (a form, a file share, cloud storage) never counts as one.

**Shares and notifications sent through a platform** (Google Classroom, Drive, Docs, Forms, Calendar;
DocuSign; Dropbox; Adobe Acrobat Sign; SharePoint): the sender's address, the sender check and your
routing rule's `[EXTERNAL]` tag are the platform's, for a colleague's share as much as for a stranger's.
Once Gmail's sender check proves the platform sent it, the email is judged by the **person's own address**:
the Reply-To the platform sets from their account (Drive shares, DocuSign, Adobe Acrobat Sign: since 0.6.21 its
adobesign@adobesign.com, and adobesign.com and echosign.com count as Adobe's own domains), or the "Name (address)" it
writes in the text (Classroom gives neither: the person is then unknown, and their name counts for nothing
either way). A colleague's own share or Classroom post gets no mark. For a share from outside:
- **an account under a colleague's name**: at another organization 5 (flagged: moved in enforce mode), at a
  personal provider such as gmail.com 3;
- **a colleague named in its subject or text** ("Dana Madeup asked me to share…", a signature in their
  name): 2. Not a greeting ("Hi Dana Madeup"), not the reader's own name, not a quotation of the colleague's
  own email;
- **asking to sign in, verify an account or confirm details** (payroll, direct deposit) to see it: 1;
- **the same outside account reaching 10 or more of your people within the hour**: 2, and an alert (Health
  → Activity, emailed), once per account and hour.

**Google Classroom from a personal account** (gmail.com, outlook.com, yahoo.com and the other free
providers): 5, flagged (moved in enforce mode), whatever the name. A school's classes come from its own
domain; a class run from a personal account is the known way to send scams through Classroom's own
address. The account is known when the email shows it: the "Name (address)" next to the person's name, or,
for a class invitation, a personal address anywhere in its text. A Classroom email that shows no account
can't be told apart, and is judged by its links and the AI. To keep your people out of personal accounts'
classes altogether: Admin console → Apps → Google Workspace → Classroom → Class settings, "Which classes
can users in your domain join" (not "any").

With "outside" (1) and a first share from that person (1.5), the compromised-district campaign (a real
account elsewhere sharing a document "from" your colleague and asking to sign in) reaches 5.5: moved. A
partner you know sharing a document that mentions a colleague stays at 3: suspicious, not moved. An
outside email that links a document, form or signature request itself (not a notification) gets the same
three checks. The colleague-name checks need the **Users → Read**
privilege and one more delegation scope (docs/INSTALL.md, "The colleague-name check"); without them it is
off, and Health → Service status says how to turn it on. `COLLEAGUE_NAMES=off` (a setting of both services, docs/DEPLOY.md)
turns it off.

## The dashboard

The dashboard keeps itself up to date: the page you're on is fetched again every 30 seconds while
the tab is visible (not while you're typing in it, or using it otherwise). The bar at the top says
when it last updated, and **Pause updates** stops it. Since 0.6.7:

- Pages that rarely change (Help, the Settings pages except Mailboxes, About, Update) are fetched again every
  5 minutes instead.
- After 15 minutes with no key, click, touch or scroll, nothing is fetched: the bar says "Updates paused while you
  are away", and updating starts again at your next key or click.
- Service status is checked at most once a minute, shared by every open dashboard.
- Large answers are sent compressed.

Anything you start that takes more than a second (an action, opening a page, the retraining download) shows a
loading bar across the top (0.6.5), and in the bottom corner what it is doing ("Saving your answer…", "Reading the
email from Gmail…"; 0.6.12), until it is done. Every email address shown has a copy button beside
it (0.5.72).

The dashboard (0.6.0) has a menu on the left: **Today**, **Review**, **Threats**, **Mail**, **Health** and
**Settings**, with **Help** at its foot, the signed-in admin, a **theme** switcher (System follows the computer's light
or dark setting; Light; Dark; 0.6.11, kept in that browser), and a card saying the mode (monitor or enforce) and
where to go from it. Above the menu: the logo, S.P.R.U.C.E and Google Workspace (the domains are on Health → DMARC &
reputation and Settings → Policy). The mode is also in the bar at the top, with the period (7, 30 or 90 days) and the live
updates. Threats, Mail, Health, Settings and Help each have their pages in a menu beside the page (Settings' in four
groups: Protection, Threat feeds, Organization, System). On a phone the menu is a drawer, and a tab bar at the
bottom has Today, Review, Threats, Health and More. **Help** (0.5.46) shows this version's own docs (how it works,
the dashboard, alerts, privacy, Google Workspace settings, install and troubleshooting, the settings reference,
costs, the architecture deep dive) and **About & credits**, with a Donate button (`DONATE_BUTTON=off` hides it).
The classic tabs (before 0.6.0) are kept in `ui-classic/` and can be put back: `docs/DASHBOARD-ROLLBACK.md`.

- **Today:** first **Needs attention**, one list of what needs an admin, each with its button: moving paused by
  the brake (resume, moving the held emails or not), campaigns paused for your decision, a phishing list that
  missed its download, phishing found after it was delivered, new look-alikes of your domain, and the emails
  waiting for review. Then emails checked, moved and moved back (by admins and by users); users affected;
  campaigns; moves per day by trigger; top reasons; largest campaigns; recent activity. The daily chart (0.5.45)
  shows every email checked behind the emails moved (or, in monitor mode, that would be moved), each colored by
  what triggered it: rules + AI, the AI score alone, the rules alone, an admin's confirmation; **Zoom in to the
  moved ones** fits the scale to them. In monitor mode the big number says how many would move by each trigger.
- **Review**, with the number of emails waiting for review beside it: every email nobody has reviewed, in one
  list, in two queues: **Would move** (moved or would move, oldest first) and **Suspicious** (not moved, newest
  first). The copies of one email (a campaign: the same email to many people) are one item, answered together.
  - Each row shows the AI score, the subject, the sender, how many copies and people, when it arrived and its
    heaviest sign, with quick **Phishing**, **False alarm** (**Not phishing** for a suspicious email) and
    **Ignore** buttons for the clear cases. Tick several to answer them all at once.
  - **Open one** to weigh the evidence: who sent it to whom (the first two, **…show more** for everyone), where
    the AI score and the rules score stand, the signs that **point to phishing** and those that **point to safe**
    (each weak, medium or strong), and what the AI weighed most. Under the evidence, a note says when the
    sender check (DMARC) neither passed nor failed (no result from Gmail, a "none" policy, another result such as
    temperror): it is not counted either way (0.6.4). Its answers, with their keys:
    - **P Phishing**; **F False alarm** (**Not phishing**): an email in Spam goes back to the Inbox too (0.6.1); **I Ignore, unclear** (0.5.60): for an email that is
      neither clearly phishing nor clearly safe, such as an outside request for access to a form, where only the
      reader can tell. It is left as it is (still in the Inbox, with its Suspicious label), counts as reviewed so it
      leaves the queue, is never used for retraining, and the later checks and the re-check after an update leave
      it alone. Marking it phishing or not phishing afterwards replaces it;
    - **N Skip for now**: the next item opens, and this one stays in the queue, undecided;
    - **R Re-scan:** the email is read again from the mailbox and judged with today's checks and AI model (after
      a model update, say). Its scores, AI opinion, model and signs become the re-scan's, beside what they were on
      arrival; what happened to it (moved, flagged) stays. A re-scan never moves anything. Activity notes who
      re-scanned what. Its limits (0.6.6): one email is re-scanned again only 30 seconds after its last re-scan
      (kept on its record, so every instance knows), and the same email is refused while its re-scan runs; each
      instance runs 2 at a time, with up to 8 more waiting, then says to try again in a moment. The button is
      greyed out while it runs. A mailbox owner's own sent copy is never judged (0.6.3), and Re-scan says so;
    - **More details** opens the email's own page (Mail → Messages); **Show the email** reads it from Gmail at that
      moment and shows it as text only (0.6.6): who sent it to whom (with Cc and Reply-To), the date and subject,
      all its text, the earlier messages quoted below it and any text hidden from the reader (folded away), every
      link with where it really goes (not clickable), the attachments (name, type, size) and how many pictures
      (not loaded). Then what the AI reads, sentence by sentence (addresses keep only their domain), with what
      weighed most between the sentence of real text before and after it. When the whole email reads as genuine
      (under 50%), nothing is marked. Every sentence is shown; the first 40 are also scored on their own, and those
      the model's input leaves out (it keeps 60 sentences of a longer text: the first 40 and the last 20) are
      marked "not read by the model". Nothing is kept, and Activity notes that you looked.
  - Marking suspicious emails shows what the move rules miss, and gives the retraining export its best examples.
  - **In enforce mode, Phishing moves an email still in the Inbox to Spam** (the button then reads **Phishing:
    move to Spam**), with the service's `SPRUCE/Moved` label; Activity notes who. In monitor mode nothing is
    moved. An email no longer in the Inbox (archived, deleted) is left where it is.
- **Threats:**
  - **Campaigns** (a timeline since 0.6.0): the newest 15 as bars from their first copy to their last across the
    period, colored by whether they were moved (or would be) or only suspicious; pick one to see its people,
    moved, would move, moved back, highest AI score, top reason, first and last seen, and **Open every copy**.
    Every campaign is in the table below; each opens the list of emails behind it, with **Confirm phishing: move
    every copy** (optionally searching every watched mailbox for copies the service didn't record), **False
    alarm: move every copy back**, and **Find other copies**.
  - **Re-checked** (0.5.35): emails already delivered and found later to be phishing or suspicious, one
    card per email (all its copies): why (which list added which site, or a second look), when it was first
    delivered and re-checked, and for each person who got it: when it arrived, whether they had opened it,
    whether they clicked a link in it (with **Settings → Link clicks** on; Gmail's logs), and what was done
    (moved to Spam and when; would move; it had already left the Inbox). **Mark as seen** on a card, or **Mark
    all as seen**, takes it off the page (a link shows the ones marked) and off the red banner on Today and
    Messages, until something new is found in it (0.6.17).
  - **Look-alikes** (0.5.36): the look-alike watch's progress and each domain found that imitates yours
    (when, registered, mail servers, website, how it counts in mail), with **It's ours**, **Harmless**, **A
    threat** and **Watch as found** (each with the project ID, noted in Activity). A new one is a red banner
    on Today and an alert.
- **Mail:**
  - **Messages:** search and filters (also by Message-ID), opening each email's decision. **Download
    CSV** gives the same list. An email found to be phishing after it was delivered has a red mark and
    "found later".
    - Tick several to **move back to the Inbox**, **mark false alarm** or **confirm phishing** them at once
      (in enforce mode, confirming also moves those still in the Inbox to Spam).
    - Each email shows the signs found with their weights, flagged links, the AI score with what weighed
      most, the sender check, and how strong the evidence was. Buttons: **Re-scan**, **Move back to Inbox**, **Mark
      false alarm** (**False alarm: move back to Inbox** for an email in Spam, 0.6.1; **Mark not phishing** for a
      suspicious email), **Confirm phishing** (**Confirm phishing: move to Spam** for one still in the Inbox, in
      enforce mode), **Confirm spam** (0.6.26: unwanted bulk mail, not phishing; moved the same way, and the
      retraining export says spam). Review has **Spam** too (key **S**).
    - Each email also shows its **Message-ID** and Gmail ID, each with a **Copy** button. The Message-ID
      is what Google Workspace's Email log search and the security investigation tool look an email
      up by. **Copy for Vault** copies it as Google Vault's search writes it: `rfc822msgid:<Message-ID>`.
  - **Check an email:** paste a reported email's original (Gmail: Show original), or an `.eml` file, to
    see what the service would decide and why. Nothing is stored, moved or counted.
  - **Users:** everyone who had mail moved, would have had it moved, or got suspicious mail; each opens
    the list of their emails.
- **Health:**
  - **Service status** (a status page since 0.6.0): one line on how it is, then whether the service works end to
    end, with what to do for each problem, and beside them the Readiness checks and the AI model in use, its
    reviews and false alarms:
    - Identity-Aware Proxy off on the worker, and who may call it;
    - both services on the same build, and the jobs reaching the worker;
    - notifications arriving and watches renewed;
    - the AI model in the dashboard and in the worker: its version, the native engine (ONNX Runtime),
      whether it loaded and how fast, and a self-check that scores two made-up emails each time an
      instance starts (the worker notes its own in Firestore, `state/engine-worker`);
    - the domains the worker counts as the organization's, compared with the dashboard's (0.6.2);
    - the phishing lists (each one that missed its download), alerts, errors, the brake.

    `deploy/doctor.sh` checks the rest from Cloud Shell.
  - **Model health:** recorded emails by AI score, and how often each kind of move was undone (and how
    often by users themselves). This is the number to tune the threshold with. **Rules and AI together**
    counts the emails from outside senders that score in between on both (a rules score of 3 to under 5, an
    AI score from the suspicious line to under the move threshold), so neither moves them, and what admins
    marked them: whether moving such emails would be worth trying. It only measures. It names the model in use,
    and, after an upgrade, which models scored the period's emails (each keeps the score it got on arrival).
  - **DMARC & reputation** (0.6.1): for each of your domains (`ORG_DOMAINS`), its DMARC record and SPF record exactly as published
    (with a Copy button), what they tell other mail servers to do with mail that pretends to come from you (policy,
    subdomains, the share it applies to, alignment, where reports go), a grade (strong, can be stronger, needs
    attention), and what would make them stronger. A subdomain with no record of its own shows its parent's. Read
    through Cloudflare's public resolver when the page is opened (only the domain names are sent), kept 10 minutes;
    **Check again** reads them now. Admins only. Changing them is done where the domains' DNS is managed.
    - **Reputation and blocklists:** whether Cloudflare Security DNS blocks the domain, whether Google Safe Browsing
      lists its home page (with Settings → Safe Browsing on), and whether the Spamhaus Domain Blocklist lists it (with
      Settings → Spamhaus on; 2 lookups a domain, counted against the day's limit). Each says clean, listed, off or
      not checked; a lookup that fails is never "clean".
    - **In the downloaded phishing lists:** every entry the lists the service downloads (Settings → About) have for
      the domain or any name under it: a link on a hacked school page, a listed site, a sender address, the first 5 of
      each shown. Mail is still judged as before (your own domains count only as exact listed links and addresses).
  - **Retraining examples** (its own page since 0.6.1; it was on Model health): marking emails doesn't train the AI
    model. **Download for retraining** (allowed in Settings → Retraining, off by default) gives the emails admins and
    moderators marked, read from Gmail at that moment with the people taken out, as training examples in the
    extension's format. Nothing is stored. `docs/RETRAINING.md` says how to check the file and train the model with it.
  - **Readiness:** whether monitor mode has shown enough to switch to enforce mode, as checks:
    - time in monitor mode, emails reviewed, false alarms;
    - staff mail failing DMARC, and the busiest hour against the brake;
    - notifications arriving, and the group re-read reaching the service.
  - **Activity:** alerts (problems the admins are emailed about), what admins did (opening the dashboard and
    downloads included), errors and the watching of mailboxes. Kept a year (`AUDIT_DAYS`), apart from the email
    records; any period, a kind, words to look for, and a CSV download for audits. Optional (off by default,
    Google charges a little): a copy in a Cloud Logging bucket (`AUDIT_LOG`), and an alert when Gmail's
    notifications pile up in Pub/Sub (`PUBSUB_BACKLOG_ALERT`).
- **Settings:**
  - **Policy:** **Change** the mode, the AI move threshold, the AI suspicious line, the brake (automatic,
    or a fixed number of moves an hour) or the time zone, and how the rest decides (read-only). The
    suspicious line is never above the move threshold.
    - At the top (0.6.0), **Monitor** and **Enforce** side by side (the one in force marked, Monitor as the safe
      default; choosing the other opens its form), and the AI's two lines on one scale, with a button for each.
      Each setting below says **On** or **Off**, and whether it is the default.
    - Each change needs the Google Cloud project ID; five wrong ones lock it for 10 minutes.
    - Switching to enforce mode also needs **I agree**, next to how many Readiness checks pass.
    - A change applies everywhere within 30 seconds and is noted in Activity (What admins did).
    - Each setting says where its value comes from: settings.env, or changed here, by whom and when.
  - **Allowlist:** the domains and addresses never moved (when Gmail's DMARC check passes for them), and the
    link domains a phishing list's listing of the whole domain doesn't flag (0.5.73), changed the same way, one
    per line. Your own domains can't be added; single addresses in them can.
  - **Mailboxes:** **who is checked**: the pilot (always the default: `PILOT_GROUP`, `PILOT_OU`,
    `PILOT_USERS`) or the whole domain (0.5.53: every active mailbox of `ORG_DOMAINS`, from the directory).
    Switching shows how many mailboxes each would watch, and needs a ticked box, the project ID and the
    signed-in admin's own address, either way; the directory is read again at once, and a large domain is
    watched (or, back to the pilot, the others stopped) over the next hours, each hourly run continuing. The
    whole domain needs the **Users → Read** privilege and the `admin.directory.user.readonly` scope
    (docs/INSTALL.md, "The whole domain"). Below, the watched mailboxes, 100 a page by address with a search,
    each with the last time Gmail notified the service about it, and **Read the directory again now**, which
    re-reads who is checked at once instead of waiting for the daily run, and says whether that reached the
    service.
  - **Weekly summary** (off by default): every Monday from 7 AM (`TIME_ZONE`), the week's numbers, what
    waits, and the largest campaigns go into each dashboard admin's Inbox. **Preview** and **Send one
    now** are next to it.
  - **Retraining** (off by default): allows **Download for retraining** on Health → Retraining examples.
  - Each service's page (Safe Browsing, Spamhaus, abuse.ch, Link clicks; Threats → Look-alikes) shows beside
    its title whether it is on: a green "Service is on", a red "Service is on, but not working", or a grey
    "Service is off" (0.5.40).
  - **Spamhaus** and **abuse.ch** (0.5.37; optional, off by default): what each adds, its key (tested, then
    kept in Secret Manager only; never shown again), on and off, and how its lookups or downloads go (Spamhaus:
    the day's lookups against its limit). Each change needs the project ID.
  - **Phishing training** (0.5.44; off until set): your training service's test emails (KnowBe4, Wizer…) let
    through unchecked, recognized by the vendor's header with a secret token or its sending addresses, or by all
    their links going to the vendor's own domains; with step-by-step instructions. A rule can be edited in place
    (**Edit**, 0.5.61): its secret value is kept unless a new one is typed or it is removed. Each change needs the
    project ID. When an email has a rule's header but doesn't match it (sent from an address the rule doesn't list,
    say), the rule's row says so and why, as does Check an email (0.6.32).
  - **Link clicks** (0.5.35; optional, off by default): for each email found to be phishing after it was
    delivered, Gmail's own logs (Admin SDK Reports API) tell when each person first opened it and whether
    they clicked a link in it; a click is an alert. It needs Gmail log events in your Workspace edition, the
    `admin.reports.audit.readonly` scope on the domain-wide delegation, and an admin with the Reports
    privilege (docs/INSTALL.md, "Link clicks"). **Test** says what Google answers; turning it on or off
    needs the project ID.
  - **Update:** the version installed, the newest approved one (from your release repository, `RELEASES_REPO`), what's new
    since yours (its changelog), and the whole changelog. **Last checked** says when GitHub was asked (the answer
    is kept 10 minutes); **Check again** asks it now, at most once a minute for everyone and 10 times an hour per
    admin (0.5.38). **Update to …** works like
    `bash deploy/update.sh`:
    - it needs **I agree**, the Google Cloud project ID and the email address you are signed in with
      (five wrong answers lock it for 10 minutes);
    - both services are rebuilt from that version and redeployed with their settings as they are, by a
      Cloud Build the dashboard can only start (it can't deploy anything itself). It takes about
      10 minutes, and the page follows it: requested, building, done or failed;
    - its start is noted in Activity (What admins did); how it ended is in Activity and on the page, and a
      failure, or a build that never finished, is an alert: the admins are emailed.

    A version that changes the installation itself (new permissions, jobs or settings) is installed
    from Cloud Shell, `bash deploy/update.sh`: the page says so instead of offering the button. So is
    the first version with this page (0.3.9), which sets it up.
  - **About:** the version, the AI model, what is kept, and the network checks.
- **Moderators** (0.6.1): the members of `MODERATOR_GROUP` (`spruce-moderators@` your first domain unless set in
  `deploy/settings.env`; `off` for none) review and categorize emails without being admins. They see **Today**,
  **Review**, **Threats → Campaigns** and **Re-checked**, **Mail** (Messages, an email's page, Check an email, Users)
  and **Help**. They can answer phishing, false alarm (which moves an email in Spam back to the Inbox), ignore or
  re-scan, one at a time or ticked together; read an email from Gmail to decide (**Show the email**); and confirm,
  dismiss or search for the copies of a whole campaign. They don't see **Health** or **Settings** (nor Look-alikes),
  and can't resume the brake, download the CSV, or move an email back without marking it a false alarm. The service
  refuses those to them whatever the page shows. Activity names who answered, and notes a moderator's
  sign-in "as a moderator". Someone in both groups is an admin.
- **The brake** (0.6.1): while it holds, a red banner across the top of every page, for admins and moderators,
  says moving is paused and to contact an administrator; an admin resumes it on Today.
- **The browser tab's title** counts what needs you: the brake, paused campaigns, users who took flagged
  mail back.

Each page keeps its own address (`#/review`, `#/health`…), so links to a page keep working.

The dashboard's numbers come from `src/dashboard/aggregate.js`. The clickable mockup
(`tools/build-mockup.js`) uses that same file with made-up data.

## Dependency updates

Dependabot proposes **security fixes** for the npm packages as pull requests on
`spruce-google-service_testing`. GitHub runs the tests and `npm audit` on each one (`.github/workflows/test.yml`).
A fix reaches the product like any change: merged in `spruce-google-service_testing`, installed, tried, then
approved for `spruce-google-service_main`.

- **Turn on** Settings → Code security → **Dependabot security updates** in `spruce-google-service_testing`.
- **Leave it off** in `spruce-google-service_main`. Nothing changes there except approved releases.
- **Routine version updates are off** (`.github/dependabot.yml`). The file is copied unchanged into
  `spruce-google-service_main` with each release, so they would open pull requests there too.

## Try it

**Before every commit and every push** the git hooks in `.githooks/` check the change for personal information (real
email addresses, phone, SSN and card numbers, street addresses, and your own private words in `.pii-terms`, which is
never committed), and people's names whose surname isn't one of the made-up ones in `tools/pii-names.txt`:
`tools/pii-check.js`. `npm install` turns them on; `npm run pii` checks the whole repository, as
`npm test` does. Data in this repository is always made up (`maple-schools.example`).

```bash
npm install
```

```bash
npm run demo
```

`npm run demo` and `npm test` first download the AI model from TinyPhishLLM, at the commit
`vendor/spruce/VENDOR.json` pins, into `vendor/spruce/models/` (once; `tools/fetch-model.js` checks every
file's SHA-256). Offline, with a TinyPhishLLM checkout at that commit:
`node tools/fetch-model.js --from ../TinyPhishLLM`.

Then open http://localhost:8080. The demo uses made-up data from an invented district
(`maple-schools.example`), and every record in it is produced by the real engine. Demo mode has no
sign-in and refuses to run on Cloud Run.

```bash
npm test
```

The tests include the deploy scripts against stand-ins for `gcloud` and `docker` (`test/install.test.js`).
The Firestore store's tests (`test/firestore.test.js`) run against Google's Firestore emulator when
`FIRESTORE_EMULATOR_HOST` is set, as in CI:

```bash
gcloud emulators firestore start --host-port=127.0.0.1:8786
```

```bash
FIRESTORE_EMULATOR_HOST=127.0.0.1:8786 npm test
```

```bash
node tools/build-mockup.js
```

The last command writes `build/mockup.html`, a single file to share the look and feel.

## Deploying

**To test in your own Workspace, limited to one security group:** `docs/INSTALL.md`. A script,
`deploy/install.sh`, sets everything up from Cloud Shell, and the others look after it:
- **Your repositories** (0.6.9): each installation names where it downloads from, `RELEASES_REPO` (the approved
  versions) and `MODEL_REPO` (the AI model's files), in `deploy/settings.env`; neither has a default. Both can be
  changed on the dashboard (Settings → Update → Repositories) without installing again: a change needs the project
  ID, a ticked box and your own address, and is emailed as an alert, because the release repository decides what
  code an update installs.
- **`deploy/update.sh`** upgrades to the newest approved version (from your release repository), with no
  zip to upload. Each version brings its own AI model; the upgrade says when the model changes. Most
  versions can also be installed from the dashboard (Settings → Update), which runs
  `deploy/cloud-update.sh` in Cloud Build. The page links each AI model to its TinyPhishLLM repository
  (and the pinned commit) and the approved versions to `spruce-google-service_main`.
- **`deploy/upgrade.sh`** installs a version you unzipped over the installed one.
- **`deploy/rollback.sh`** goes back to the previous build.
- **`deploy/stop.sh`** stops it (0.6.7): every mailbox stops counting as watched at once (their notifications,
  `PILOT_USERS` too, are ignored from then on); Gmail is told to stop notifying, 10 mailboxes at a time, within the
  request's time, and the hourly job finishes the rest (it never renews watches while stopped). Running
  `deploy/install.sh` again, or **Read the directory again now** (Settings → Mailboxes), starts it again.
- **`deploy/doctor.sh`** checks the installation end to end and says what to run for each problem.
- **`deploy/dashboard-policy.sh`** (used by `install.sh` and `upgrade.sh`) compares the policy
  changed on the dashboard with settings.env.
- **`deploy/clear-data.sh`** clears what the dashboard shows (emails recorded, counts, campaign
  decisions, Activity) and keeps the watched mailboxes and settings, after you type the project ID.

Changing a setting is quick: edit `deploy/settings.env` and run `install.sh` again. It reuses the image
built from the same files, so it only redeploys, in about a minute. The policy settings can also be changed
on the dashboard: the mode, the AI move threshold and suspicious line, the AI on inside mail and "AI alone moves
inside mail", the brake, the time zone, how long records are kept, the Suspicious label, re-checking delivered
mail (Settings → Policy), the allowlist and allowed link domains (Settings → Allowlist), Safe Browsing, Spamhaus
and abuse.ch (their Settings pages), and who is checked (Settings → Mailboxes). When the two differ,
`install.sh` asks which to keep, and writes the answer into settings.env.

See `docs/DEPLOY.md` (each piece, by hand) and `docs/PRIVACY.md` (what is read, kept and shown).
`docs/COSTS.md` is what it costs a month, by district size. `docs/SCALING.md` is what a district of
10,000 mailboxes and 100,000 emails a day asks of it, measured, and the plan beyond.
`docs/ARCHITECTURE.md` explains the pieces. `docs/ALERTS.md` says what each alert the admins can receive means
and what to do. `docs/WORKSPACE.md` lists Google Workspace settings that work alongside the service (an outbound
recipient limit for a staff account taken over, Gmail's own Safety settings, DMARC). `docs/RETRAINING.md` turns the emails admins and moderators marked into
training examples, and a better AI model.

## Layout

| Path | What |
|---|---|
| `src/engine/` | MIME and HTML reading, the checks and the model (`spruce.js` loads `vendor/spruce/`; `model.js` runs the model in ONNX Runtime); `network.js` applies the lookups; `notifications.js` judges the person behind a platform's notification, and outside shares |
| `src/intel/` | Cloudflare Security DNS, Google Safe Browsing, the phishing lists, registry dates, brand ownership (`ownership.js`), Spamhaus, abuse.ch; request limits |
| `src/policy.js` | What happens to an analyzed email |
| `src/pipeline.js` | Notifications → messages → decisions → actions → records; moving back, brake, watches, retention |
| `src/gmail/` | Keyless domain-wide delegation, Gmail and Directory API calls |
| `src/store/` | Firestore (production) and memory (demo, tests) |
| `src/auth/verify.js` | OIDC for Pub/Sub and Scheduler; Identity-Aware Proxy and ADMIN_EMAILS / ADMIN_GROUP (admins), MODERATOR_GROUP (moderators) for the dashboard |
| `src/scheduler.js` | Cloud Scheduler, for the dashboard's "Read the directory again now" (runs the daily re-read job) and Settings → Update (runs the spruce-update job) |
| `src/releases.js`, `src/update.js` | Settings → Update: the newest approved version and its changelog (read from GitHub), and the request |
| `src/training.js`, `src/names.js` | The retraining export: an email → a training example, with the people taken out |
| `src/digest.js` | The weekly summary email (put in admins' Inboxes; never judged by the service) |
| `src/cloudrun.js` | Cloud Run, read-only, for the Service status page |
| `src/dashboard/cache.js` | The dashboard's copy of the records: the last 32 days first, older ones when a page shows them, then only what changed |
| `src/dashboard/dmarc.js` | Health → DMARC & reputation: the domains' DMARC and SPF records, read and graded (not a judging file) |
| `src/dashboard/reputation.js` | Health → DMARC & reputation: the domains on Cloudflare Security, Safe Browsing and Spamhaus, and in the downloaded lists (not a judging file) |
| `src/server.js` | The HTTP service (`ROLE=worker` / `admin`) |
| `public/` | The dashboard (plain HTML, CSS and JavaScript; no build step) |
| `src/demo/seed.js` | Made-up demo data, judged by the real engine |
| `deploy/` | `install.sh`, `update.sh`, `upgrade.sh`, `rollback.sh`, `stop.sh`, `doctor.sh` and `clear-data.sh` (Cloud Shell), `dashboard-policy.sh` (theirs), `cloud-update.sh` (Settings → Update's Cloud Build), `settings.example.env` |
| `.githooks/` | `pre-commit`, `commit-msg`, `pre-push`: the personal-information check (`tools/pii-check.js`) on every commit and push; `npm install` turns them on (`core.hooksPath`) |
| `.github/` | Dependabot (`dependabot.yml`: security fixes as pull requests) and the tests on every pull request (`workflows/test.yml`) |
| `tools/` | `build-mockup.js`, `release.js` (the install zip); `sync-model.js` (pins a model of TinyPhishLLM), `fetch-model.js` (downloads it: the image build and `npm test` run it); `checks-level.js` (records a raised or cosmetic checks level); `pii-check.js`, `pii-allow.txt` and `pii-names.txt` (refuses personal information, people's names included, before every commit and push: CLAUDE.md, `npm run pii` for the whole repository); for retraining: `check-training-file.js`, `split-examples.js`, `score-examples.js` |
| `ui-classic/` | the classic dashboard (0.5.74, before the 0.6.0 redesign), kept to put back: not served (`docs/DASHBOARD-ROLLBACK.md`) |
| `vendor/spruce/` | The checks and the code that runs the model (this project's own since 0.4.0; they began as the extension's); `VENDOR.json` says from which commits, and pins the model (`modelSource`); `models/phish-tiny/` is where `fetch-model.js` puts the model (not committed) |
