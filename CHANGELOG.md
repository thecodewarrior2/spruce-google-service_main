# Changelog

## 0.6.30: every allow list is checked every 30 days; a domain that may have changed hands is suspended

- **The 30-day check** (`src/allowwatch.js`): every domain on an allow list (allowlisted senders and addresses, allowed
  link domains, brand senders your reviewers confirmed, senders whose spam people took back; personal mail providers'
  and your own domains skipped) is looked up when first seen and again every 30 days, from the hourly job (at most 20 a
  run): its registration from its registry (RDAP: registered, expires, registrar, name servers; `record` in
  `src/intel/rdap.js`) and its reputation (Cloudflare, the phishing lists, Spamhaus's DBL when on). Only domain names
  are sent.
- **A change flags it for review:** Settings → Allowlist (**Needs review**, at the top), Today's Needs attention,
  Activity (an alert, also emailed to ALERT_EMAIL), and **an email in every admin's Inbox** (ADMIN_EMAILS and the members
  of ADMIN_GROUP).
- **Suspended when it may have lapsed or changed hands:** registered again (a newer registration date), expired, gone
  from the registry, or now blocked by Cloudflare, on a phishing list or on Spamhaus. A suspended domain isn't trusted
  anywhere until an admin answers: its mail is judged like anyone's, its links' allowance is off, it is no confirmed
  brand sender and its spam is moved again. A new registrar, or all name servers new, only flags it (companies move
  their DNS). Something the registry didn't answer is never a change.
- **Finding and releasing what it held back:** each email from a suspended domain is tagged (`allowSuspended`); the
  review lists how many, with a link to them in Mail. **Still trusted** takes a new snapshot and ends the suspension (for
  a suspended domain, with the project ID, as for any allowlist change); **Still trusted, and release its emails** also
  answers them as false alarms, moving those in Spam back to the Inbox. Not trusted any more: remove it from its list.
  (`GET`/`POST /api/allow-watch`.) The demo has one flagged and one suspended.
- Tests: `test/allow-watch.test.js` (made-up domains and registrars).
- **Checks level 29:** delivered mail of the last hours is checked again after this update.


## 0.6.29: a reviewer's "False alarm" teaches the service a brand's real senders

- **Learned, not listed by hand:** a company sending for a brand from its own domain (a store's invoices from its payment
  company, a bank's mail about the card it issues in a store's name) gets "the sender's name says the brand, but the
  address isn't the brand's" (5). When a reviewer answers **False alarm** on such an email, and that sign was its only
  one (besides "from outside" and "the first email from this sender"), and Gmail's DMARC check passed for the sender's
  domain, the brand and the sender's domain are remembered for the organization (`learnBrandSender` in
  `src/pipeline.js`, state `brandSenders`, at most 500). From then on that domain's verified mail under that brand's
  name is a note of no weight, and the AI is told it is the brand's sender (`brandSenderConfirmed` in
  `vendor/spruce/shared.js`). A forged copy, another brand's name on the domain, or an email with any other sign:
  judged as before. Activity notes each one learned.
- **Settings → Allowlist → Brand senders your reviewers confirmed:** the list (brand, domain, who confirmed it, how
  many emails); an admin removes one there (`GET`/`POST /api/brand-senders`). The demo has one.
- The brand sign now carries its kind (`brand-name-other`) and brand; records keep the DMARC result's domain.
- Tests: `test/brand-senders.test.js` (a made-up payment company and school).
- **Checks level 28:** delivered mail of the last hours is checked again after this update.


## 0.6.28: Walmart Business's invoices from TreviPay aren't an imitation of Walmart

- **"Walmart Business: Pay By Invoice Support" from no-reply@trevipay.app was moved:** the sender's name says
  Walmart and the address isn't Walmart's (5), and the AI, told the same, scored a made-up payment receipt 99.9%.
  Walmart Business's Pay By Invoice is run by TreviPay, which sends its mail from its own domains. A short list of
  such invoicing services and the brands each is known to send for (`BRAND_BILLING_SERVICES` in
  `vendor/spruce/shared.js`; TreviPay for Walmart) makes it a note of no weight when Gmail's DMARC check passed for
  the service's domain, and tells the AI the sender is the brand's own (identity owner "yes"). The made-up receipt now
  scores 2.5 on the rules (clean) and 1% from the AI. Forged (DMARC failing): 5, "may be forged" (the receipt scores
  10.5, flagged). A domain that only resembles TreviPay's, or another brand's name on TreviPay's: judged as before.
- Tests: `test/brand-billing.test.js` (a made-up school, amount and payment ID).
- **Checks level 27:** delivered mail of the last hours is checked again after this update.


## 0.6.27: spam or phishing, plainly labelled; a newsletter from an established sender isn't moved as spam for padding its email

- **Spam or phishing, at a glance:** every item in Review, and every email in Mail and its page, carries a coloured
  label: **Spam** (purple: moved or to be moved as spam, or an admin answered "Spam") or **Phishing** (red: moved, to be
  moved or flagged on the rules or the AI). An opened item's first line says it too ("Would be moved: spam, not
  phishing"), and for spam its evidence column is **Points to spam** (purple), starting with the spam trick that made it
  spam, instead of "Points to phishing". The review list gets each item's `kind` from the server (`verdictKind` in `src/dashboard/aggregate.js`).
  The demo has a padded store newsletter moved as spam, to show it.
- **Padded list mail from an established sender is left alone:** list or marketing mail that hides a block of text below
  the message, with nothing else wrong, was moved to Spam as spam (0.6.19), but real newsletters (a recipe site's,
  a store's) pad their emails too. Now it isn't moved when the sender is established: Gmail verified it (DMARC passed)
  and its domain is a year old or more (the same domain-age lookup as the "new domain" sign; an unknown age doesn't
  count). The hidden-filler sign says why, with no weight. Spam from a new domain, or one whose age isn't known, is
  moved as before; with any other warning sign (a failing sender check too) it is judged as phishing, as before
  (`signsNeedingCompany` in `src/engine/analyze.js`; `networkChecks` returns the sender's domain age).
- **The checks level is raised (26):** after this update, recent delivered mail is checked again.


## 0.6.26: spam people took back is remembered; "Spam" as an admin's answer, and in the retraining export

- **Spam someone took back:** when a person moves mail the service moved as spam (trigger `spam`) back out of Spam,
  that sender's spam isn't moved for them again for 6 months. A sender is its organization's registrable domain, or
  the address itself at a personal mail provider (one person, not everyone at gmail.com); only a sender Gmail verified
  (DMARC passing) counts, so a forged copy is judged as usual. Kept as one-way hashes in the store's cache (its expiry
  is the 6 months) (`rememberSpamRescue`, `spamKept`, `applySpamMemory` in `src/pipeline.js`).
- **Taken back by 3 or more people:** not moved as spam for anyone, noted in Activity, and listed in **Settings →
  Allowlist → Spam people took back**: add it to the allowlist (as before, with the project ID), or **Keep moving
  it** (each person who took some back still keeps theirs) (`GET`/`POST /api/spam-rescued`, admins only).
- **Phishing is never affected:** mail moved as phishing and taken back teaches nothing (it goes to the admins as a
  possible false alarm, as before), and a remembered sender's mail is still checked, and moved if it is phishing.
- **"Spam" as an admin's answer:** Review has **Spam** (key **S**, and **All spam** for ticked items), an email's
  page **Confirm spam**: confirmed (not a false alarm), recorded as spam rather than phishing, moved to Spam in
  enforce mode like **Phishing**. Moderators may use it.
- **The retraining export's `class`:** `genuine`, `spam`, `phishing`, or `phishing or spam` (marked before 0.6.26),
  beside the `label` (0 genuine, 1 spam or phishing, as the training reads it today), for a model with a spam answer
  of its own. `tools/check-training-file.js` checks that the two agree.
- Tests: `test/spam-memory.test.js` (made-up people and mail), and `test/training.test.js`.

## 0.6.25: the links sign has one weight, set by what is known against the link

- **Before:** a link whose text shows a well-known site but goes somewhere else was "dangerous", and the links sign
  was 3 for one such link and 5 for two or more (or when every link was), enough to move the email alone, though
  newsletters and marketing mail link through other companies' domains all the time.
- **Now one weight, however many links are flagged, set by the worst of them** (`linkSignals` in
  `src/engine/analyze.js`):
  - **5:** a link's site is blocked or on a phishing list (Cloudflare, Safe Browsing, the lists, Spamhaus's DBL for
    phishing), or the link is evidence on its own: a look-alike of a brand's domain, a name hidden before an "@" in
    its address, or code to run (javascript:, data:);
  - **3:** a link's site has a low reputation: registered in the last 90 days, or on Spamhaus's lists (DBL or ZRD)
    (`src/engine/network.js` marks it);
  - **2:** links flagged only by their own text, with nothing known against their sites.
- Tests: `test/link-weight.test.js` (made-up mail).
- **Checks level 25:** delivered mail of the last hours is checked again after this update.

## 0.6.24: Adobe Campaign's click tracker

- **A cable company's marketing mail sent through Adobe Campaign** was moved: its links show the company's site
  but go to Adobe Campaign's click tracker (<client>-mid-prod1-…-t.adobe-campaign.com), and two such links made a
  "dangerous links" sign of 5 on its own. Adobe Campaign's tracking domains (adobe-campaign.com, and neolane.net, its
  earlier name) are now known email-service click trackers, like SendGrid's, Mailchimp's and Marketo's: a tracker's
  address says nothing about where the link ends, so its text not matching isn't a sign (`espTrackers` in
  `vendor/spruce/shared.js`). A look-alike of those domains is judged as before.
- (The links sign counts once per email: 3 for one dangerous link, 5 for two or more or for all of them.)
- Tests: `test/adobe-campaign.test.js` (made-up company and links).
- **Checks level 24:** delivered mail of the last hours is checked again after this update.

## 0.6.23: a colleague's name from a personal email account alone counts 2; a "RE:" the mailbox has no start of, 1

- **"The sender uses the name of someone in your organization… from a personal email account"** counted 3; with
  "from outside" (1) and "the first email from this sender" (1.5) that moved the email, though staff and people who
  share a colleague's name write from their own Gmail too. When the personal account is the only reason, it now counts
  2 (suspicious with those two, not moved). With any other reason (a request impersonators make, replies going
  elsewhere, a title or the organization's name in the sender's name, a failed sender check, a new or look-alike
  domain) it is 3, as before (`colleagueInContext` in `src/engine/analyze.js`).
- **"RE:" with no earlier email in this mailbox:** a reply whose headers name an earlier email that this mailbox's
  conversation doesn't hold counted 2. It was wrong too often: the reader was copied into a conversation partway, or
  the earlier emails were deleted or removed by a retention policy. (Sent mail is in the conversation: Gmail counts
  it.) It now counts 1. A "RE:" whose headers name no earlier email at all, which real mail programs never write,
  stays 2 (`src/engine/replychain.js`).
- Tests: `test/colleague-context.test.js` (made-up names), `test/replychain.test.js`.
- **Checks level 23:** delivered mail of the last hours is checked again after this update.

## 0.6.22: a mail provider's delivery report isn't scored by the AI

- **"Delivery Status Notification (Failure)" was suspicious:** a bounce from Google's own mail system
  (mailer-daemon@googlemail.com), its sender check passing, was scored by the AI (a made-up one: 99.7%): it reads
  "your message wasn't delivered" and a returned message as a lure. A delivery report from a big mail provider's own
  mail system now gets no AI score: from its mailer-daemon or postmaster address at google.com, googlemail.com,
  gmail.com, outlook.com, hotmail.com, live.com, yahoo.com, aol.com, icloud.com or me.com, Gmail's DMARC check passing
  for that domain, and written as a delivery report (Content-Type multipart/report; report-type=delivery-status)
  (`providerBounce` in `src/engine/analyze.js`). The rule checks read it as usual, the returned copy included. Forged,
  from a look-alike or a person's mailbox, or not a delivery report: scored as before. The dashboard says why there is
  no score.
- Tests: `test/provider-bounce.test.js` (made-up addresses).
- **Checks level 22:** delivered mail of the last hours is checked again after this update.

## 0.6.21: Adobe Acrobat Sign's signature requests

- **"Name via Adobe Acrobat Sign" was flagged and moved:** Adobe's entry in the brand table knew only adobe.com,
  so a signature request from adobesign.com got "the sender's name says Adobe, but the address isn't Adobe's" (5),
  and the AI model read "the domain is not Adobe's" and scored it near 100%. adobesign.com and echosign.com (Acrobat
  Sign's earlier name) are now Adobe's own domains (`vendor/spruce/shared.js`), and Acrobat Sign's sending mailbox
  (adobesign@…) is a platform notification (`src/engine/notifications.js`): with Gmail's DMARC check passing for
  Acrobat Sign's domain, the email is judged by the person who sent the document (the Reply-To Acrobat Sign sets),
  as DocuSign's are. A made-up request now comes out clean and the AI scores it under 1%; forged (DMARC failing) or
  from a look-alike domain, it is flagged as before.
- Tests: `test/adobe-sign.test.js` (made-up names and documents).
- **Checks level 21:** delivered mail of the last hours is checked again after this update.

## 0.6.20: a brand's name from the established company that runs its product

- **A card issuer's mail under the brand's name:** "Brand Credit" mail from the bank that issues the brand's card,
  from the bank's own long-held domain, was flagged. The ownership lookup ran and found an established company (a
  corporate registrar, registered decades ago: "likely"), but not the brand's, since the domain is the bank's; that
  "likely" counted 3, and with "from outside" and "first time" the email was flagged. Now it is a note of no weight
  when Gmail's DMARC check passed for the sender's domain, every link the reader sees goes back to the sender's own
  domain, no link is flagged, and the domain isn't new or on a list (`establishedSenderInContext` in
  `src/engine/analyze.js`). A link anywhere else, DMARC not passing, a new domain or nothing in the public records:
  judged as before.
- Tests: `test/established-sender.test.js` (made-up bank and emails).
- **Checks level 20:** delivered mail of the last hours is checked again after this update.

## 0.6.19: signs that need another sign; padded list mail is spam; a brand's partner; one brand's text on another's link

- **Hidden filler alone:** text hidden far below the message after a blank space (3) made ordinary newsletters
  suspicious together with "it comes from outside" (1). It now counts only with another warning sign; alone it is
  shown with no weight ("Alone it isn't counted: nothing else in the email is suspicious"). With another sign it
  counts 3 as before.
- **Spam, not phishing:** the same filler in list or marketing mail (a List-Unsubscribe or List-Id header,
  Precedence: bulk, or an unsubscribe link near the end), with nothing else suspicious, is moved to Spam as spam:
  trigger `spam` (`src/policy.js`), under the same switch as the rules (`MOVE_ON_RULES`), monitor mode, the campaign
  hold and the brake; never mail from inside the organization or an allowlisted sender. The user can take it back
  out of Spam. The dashboard counts it apart ("Spam (padded list mail)").
- **A colleague's name on a resembling domain:** when the only reason a colleague's name on an outside address
  counted was that the domain resembles the organization's (a local group's domain with the town's name in it), it
  now needs another warning sign too. So does a colleague copied in at an outside or resembling address.
- **A brand's program run by a partner:** a sender's name giving a brand's program and the sender's own
  organization ("Brand Future Coders - Sample Scholarship Fund" from samplescholarshipfund.example) was a 5 (moved).
  Now, when Gmail's DMARC check passed for the sender's domain, one part of the name is that domain's own name
  letter for letter, of at least two words and none of an account desk's (Account Center, Security Team), and the
  domain doesn't carry the brand's name, it is a note of no weight; 5 again when the domain is new or listed
  (`partnerProgramName` in `vendor/spruce/shared.js`, `partnerNameInContext` in `src/engine/analyze.js`).
- **One brand's text on another established company's link:** a link whose text shows a well-known brand but which
  goes to another company's own domain (a hotel chain's click tracker in a co-branded offer) was dangerous (two made
  the email moved). Now it is a note of no weight when the sender passed DMARC and the destination is proven by
  public records to be the company it is named after (`ofCompany`, as in 0.6.17), is clean at Cloudflare, is at
  least 180 days old, and is no platform where anyone can make a page (a form, a file share, cloud storage, a big
  platform of the protected list) (`src/engine/network.js`).
- Tests: `test/needs-company.test.js` (made-up emails), and updated `test/colleague-context.test.js`,
  `test/explain.test.js`, `test/activity.test.js`. The scams forwarded for 0.6.18 are judged exactly as before.
- **Checks level 19:** delivered mail of the last hours is checked again after this update.

## 0.6.18: the "renewal" callback scam from a free mail account, and unfilled placeholders

- **The renewal callback scam:** a "billing notice" for security software or a tech-support plan, with an amount
  and a phone number to call, sent from a Gmail account, was only suspicious: the AI scored it 66% and no rule
  agreed. A bill like that naming McAfee, Norton, LifeLock, Geek Squad, an antivirus or Defender, with an amount
  and a phone number, from a personal mail account, is now a sign of 5 (flagged on its own): those companies don't
  bill from free mail (`freeMailBillSigns` in `vendor/spruce/shared.js`). The callback wording also covers "if this
  record appears unfamiliar" and "if you don't recognize this charge". None of the 329 genuine emails in the
  district's retraining exports gets either sign.
- **Unfilled placeholders:** a subject with a mass mailer's merge field left unfilled ({{Offer_Code}}) is a sign
  of 2: bulk mail from a tool its sender didn't set up.
- Tests: `test/callback-free-mail.test.js` (made-up emails; fictional 555 numbers).
- **Checks level 18:** delivered mail of the last hours is checked again after this update.

## 0.6.17: a company's own click tracker is not a dangerous link; Re-checked listings can be marked seen one by one

- **A company's own link domain:** a hotel chain's marketing mail sends every link through its own email domain
  (email-lakeviewhotels.example, say), also the links whose text shows its main site or a partner's (a co-branded
  card's brand). Each was a "dangerous link" (text shows one site, link goes to another). Now, when the link goes to
  the sender's own domain, Gmail's DMARC check passed for that domain, Cloudflare finds nothing against it, and the
  domain is named after one company (its marketing words taken off: email-, -news, mail…), the service asks public
  records whether the domain is that company's: registered to it through a corporate registrar, its name servers or
  its DMARC reports (`src/intel/ownership.js`, `ofCompany`, the same proof and cache as brand ownership; at most 6
  seconds). Proven, the link is a note of no weight ("2 links show another site but go to the sender's own
  domain…"); unproven (a look-alike registered by anyone), DMARC not passing, a link anywhere else or Cloudflare
  blocking it: judged as before (`src/engine/network.js`, `src/engine/mailers.js` `companyWordOf`). A domain whose
  name is more than one word, or only marketing words, isn't looked up. Tests: `test/own-brand-links.test.js`,
  `test/ownership.test.js`.
- **Threats → Re-checked:** "Mark all as seen" cleared only the banners on Today and Messages; the listings stayed.
  Now it takes them off the page too, and each listing has its own **Mark as seen** (not for moderators). A link
  shows the ones marked; something new found in one brings it back (`src/dashboard/aggregate.js`,
  `POST /api/rechecked/seen` with or without a campaign, `public/app.js`). Tests: `test/rechecked-seen.test.js`.
- **Checks level 17:** delivered mail of the last hours is checked again after this update.

## 0.6.16: the personal-information check can't hang on a long line

- **The check could hang:** the pattern for a name in an address (firstname.lastname@) backtracked without end on a
  long run of letters with no @ (33 characters were enough), so a commit or push touching such a line could wait
  forever. Addresses are now found with bounded patterns, only in lines with an @, and their domain is checked apart
  (`tools/pii-check.js`). A test feeds it long runs of letters, dots, digits and @ (`test/pii-check.test.js`).
- Nothing in the service changes.

## 0.6.15: every person in the repository has a plainly made-up name, and names are checked before every commit and push

- **People's names:** the people in the tests, docs, comments, the changelog and the demo had realistic names, some
  with a personal mailbox and a birth year, the way a real account looks. Each has a plainly made-up surname now
  (Madeup, Samplefield, Exampleton, Testwood…), in every form it took (the full name, first.last, the surname alone);
  first names are kept. The demo's staff get made-up surnames too (`src/demo/seed.js`). `src/names.js`, the
  retraining export's list of common names (no one in particular), is unchanged.
- **The name check:** `tools/pii-check.js` also refuses a person's name before every commit and push: a common first
  name with a surname that isn't on `tools/pii-names.txt`, a common surname after any word, a quoted display name
  ("Firstname Lastname" <…>), and the same as an address (firstname.lastname@…). It can't know every name: reading
  the change is still part of the rule (CLAUDE.md).
- **`tools/pii-allow.txt`:** its review section is gone; the test addresses at personal mailbox providers (which the
  checks about personal mailboxes need) carry the made-up names.
- **Not changed here:** one made-up name in `test/fixtures/model-input-format.jsonl`, the AI model's input-format
  reference, which comes from TinyPhishLLM byte for byte (the tests refuse any other): it changes there. The old
  names are still in the history of earlier commits.
- **Checks level unchanged:** in the files that judge email only comments changed, and the sender name of the
  self-check's made-up genuine email (its score is the same, 0.06%).

## 0.6.14: update.sh and the tests leave nothing behind in /tmp

- **`deploy/update.sh` left a copy of the release it downloaded in `/tmp`** on every update: it hands over to
  `upgrade.sh` with `exec`, which replaces the script, so its clean-up on exit never ran. It now removes the download
  first. (In Cloud Shell, `/tmp` is cleared when the session restarts; any `/tmp/tmp.*/release` folders left by an
  earlier update can be deleted.)
- **A model-download test left an empty folder** in `/tmp` each run (a second one it made for one check): removed.
- The `update.sh` test now gives the script a temporary folder of its own and checks it is empty afterwards
  (`test/install.test.js`). A whole `npm test` run leaves nothing in `/tmp`.
- No install or checks change: `update.sh` is run from Cloud Shell as before.

## 0.6.13: personal information is checked before every commit and every push

- **The rule** (CLAUDE.md, "Personal information"): before every commit and every push, the change, its files and its
  commit messages, is checked for personal information, and read for anything taken from a reported email, a
  screenshot or an export. Never skipped, never turned off.
- **`tools/pii-check.js`** looks for email addresses outside the reserved example names (a personal mailbox
  provider's always), phone, Social Security and payment card numbers (Luhn), street addresses, and your own private
  words in `.pii-terms` (your district's name and domains: in `.gitignore`, so they are checked without ever being
  committed). `--staged`, `--message FILE`, `--range A..B`, `--pre-push`, `--all`.
- **Git hooks** in `.githooks/` run it on every commit (`pre-commit`, `commit-msg`) and push (`pre-push`); `npm install`
  turns them on (`core.hooksPath`; it does nothing where there is no git, as in the image build).
- **`npm test` scans every tracked file** (`test/pii-check.test.js`); `npm run pii` does it alone.
- **`tools/pii-allow.txt`** lists what looks like personal information but is no person's: service accounts, the
  brands and services the checks are about, placeholders, the documented test card number. Its REVIEW section
  holds ten realistic personal-mailbox addresses that were already in the tests (made up, but a real person could
  own one): to be replaced with obviously made-up names.
- Nothing in the service changes: no install or checks change.

## 0.6.12: the loading bar stops when it is done, says what it is doing, and moves away from Pause updates

- **It never stopped:** an action that drew the page again (most of them) took away the page's entry in the
  loading bar's list instead of its own, and its own stayed: "Working on it…" for good, from the first click on.
  Each start is now its own entry with a ticket, and each end takes away exactly its own (`busyStart`/`busyEnd`
  in `public/app.js`).
- **It says what it is doing:** every request to the service has its words ("Saving your answer…", "Moving it back
  to the Inbox…", "Reading the email from Gmail…", "Testing and saving the key…"); "Working on it…" is gone.
- **The words are in the bottom corner,** as plain text with a turning ring, no longer a green pill beside Pause
  updates that looked like a button. Clicks go through them. The bar across the top stays.
- Dashboard only: no install or checks change (Settings → Update installs it).

## 0.6.11: light, dark, or the system's setting; the menu's heading without the domains

- **Theme:** a switcher at the foot of the menu: **System** (the default: follows the computer's light or dark
  setting, and changes with it), **Light** or **Dark**. The choice is kept in that browser (`public/theme.js` applies
  it before the page is drawn, so a dark page never flashes light; the page's security policy allows no inline
  script). Charts are drawn again in the new colors.
- **The menu's heading** shows the logo, S.P.R.U.C.E and Google Workspace, no longer the watched domains (a long
  list of domains made it messy). They are on Health → DMARC & reputation and Settings → Policy.
- Dashboard only: no install or checks change (Settings → Update installs it).

## 0.6.10: Health → DMARC & reputation lines up side by side

- **Side by side, each domain's sections line up:** the cards in a row share their rows (the head, DMARC, SPF,
  reputation, when it was read; CSS subgrid), so every divider is at the same height, whatever each record holds.
  The domain names line up at the top. Stacked in one column, each card keeps its own height.
- **In a narrow card** (a medium screen, a phone), each blocklist service's words go under its name instead of a
  thin column beside it.
- Dashboard only: no install or checks change (Settings → Update installs it).

## 0.6.9: each installation names the two repositories it downloads from

- **`RELEASES_REPO` and `MODEL_REPO`** (`deploy/settings.env`, and on the dashboard: Settings → Update →
  Repositories): where this installation gets its approved versions (what Settings → Update offers, what
  `deploy/update.sh` and the update job install) and the AI model's files. **Neither has a default**: each
  installation names its own (someone running their own copy points both to their own repositories);
  `deploy/settings.example.env` gives the maintainer's only as examples. `install.sh` stops when either is empty or
  not a usable address; `upgrade.sh` asks for them when the old settings don't have them (`deploy/repos.sh`).
- **Addresses** (`src/repos.js`): a GitHub repository (`https://github.com/OWNER/REPO`, or `OWNER/REPO` as before), a
  GitLab one (`https://gitlab.com/GROUP/REPO`, or a GitLab server of its own), or, for the model on another host, an
  https address under which `COMMIT/FILE` downloads each file. https only, never with a name or password in it.
  Settings → Update lists versions from GitHub and GitLab; a release repository on another host is updated from
  Cloud Shell.
- **Changed on the dashboard without reinstalling:** a change applies at once, for every instance. Whoever controls
  the release repository decides what code an update installs, and that code reads and moves mail, so a change
  needs the project ID, a ticked box and the admin's own address (admins only, never moderators), is noted in
  Activity, and is an **alert** (`repos`, emailed). An update still installs only when an admin presses Update.
- **The update job** (made by `install.sh`, which the dashboard can't change) now reads the release repository from
  the update request (the dashboard's setting at the time), falling back to `settings.env`'s, and passes the model
  repository to the image build (`MODEL_REPO`, a build argument: `Dockerfile`, `tools/fetch-model.js`). The model's
  files are still pinned by each version (commit and SHA-256: `vendor/spruce/VENDOR.json`): the model repository only
  says where those same files download from. `tools/sync-model.js` pins a model from any public https repository.
- **Installation level 7:** install it once from Cloud Shell (Settings → Update can't): docs/INSTALL.md, "Upgrading to
  0.6.9". Tests: `test/repos.test.js`, `test/update.test.js`, `test/install.test.js`, `test/model-source.test.js`.

## 0.6.8: the repositories are spruce-google-service_testing and spruce-google-service_main

- **New repositories:** `google_service_testing` and `google_service_main` were deleted and made again as
  `spruce-google-service_testing` (private: where the service is developed) and `spruce-google-service_main` (public:
  the approved versions, which installations download without a password), with their history rewritten so that no
  district data is left in any version or commit message (examples are made up). Every commit has a new id.
- **Where the approved versions come from:** `RELEASES_REPO` and the download address of `deploy/update.sh`,
  `deploy/install.sh` and the update job default to `thecodewarrior2/spruce-google-service_main` (were
  `Google_service_main`); every page, doc and comment names the new repositories.
- **An installation before 0.6.8** still reads the old address, which no longer exists: Settings → Update says it
  can't reach the approved versions. Once this version is approved, upgrade once from Cloud Shell from a fresh copy
  (docs/INSTALL.md, "Upgrading to 0.6.8"); after that, Settings → Update works as before. Then delete the old
  folders (they hold the old history).
- **CLAUDE.md:** the rule against district data now names everything it covers (code, comments, tests, docs, the
  changelog, commit messages; names, domains, businesses, numbers, addresses) and asks for a search of each change
  before a push.

## 0.6.7: a code review: less load, faster emails, five bugs fixed, comments and docs brought up to date

A review of the whole service for speed and unneeded load, its comments and its documentation. Only one change
judges an email differently (the phishing-training bypass below); the rest is speed, and every other verdict is the
same.

**Bugs fixed**
- **The dashboard's copy of the records got stuck** after more than 5,000 records changed within a minute (a campaign
  to most of a district, a whole campaign released): every refresh read the same 5,000 again (about 20,000 reads a
  minute) and the newer ones never arrived, so Today, Review and the counts went stale until the instance restarted.
  The changes are now read page after page from exactly where the last page ended (`src/dashboard/cache.js`,
  `listRecordsChangedSince` with `after`). Test: `test/qol.test.js`.
- **`deploy/stop.sh` didn't stop a large district:** the mailboxes were stopped one at a time with no time limit
  (10,000 took about 50 minutes, past the request's 2), and the hourly job then continued an unfinished renewal,
  watching them again; `PILOT_USERS` mailboxes were judged even when switched off. Now every mailbox stops counting
  as watched at once (its notifications are ignored, `PILOT_USERS` too), the unfinished renewal is dropped, Gmail is
  told to stop 10 at a time within the request's time, and the hourly job finishes the rest without ever renewing
  while switched off; any renewal (install.sh, the daily job, "Read the directory again now") switches it on again
  (`stopAll`/`finishStopping` in `src/pipeline.js`). Test: `test/pipeline.test.js`.
- **A deleted SPRUCE label** made every move in that mailbox fail until the instance restarted; two emails at once could
  both try to make the label. The mailbox's label ids are now asked again after a refusal, one request at a time, and a
  label another instance just made is found (`src/gmail/client.js`).

- **A phishing-training rule could be used to slip phishing through:** an email counted as the vendor's training mail
  when its first 100 links all went to the vendor's domains (they are public), so 100 such links and then the
  phisher's own one let it through unchecked. An email with more than 100 links is never training mail by its
  links now (`matchTraining` in `src/simulations.js`). Test: `test/simulations.test.js`.
- **Activity's events, more than 5,000 between two looks,** would have left a gap in the dashboard's copy: read page
  after page now. Test: `test/qol.test.js`.
- **Example names from a district's retraining file** had been copied into the 0.5.68 comments, a test, this changelog
  and docs/RETRAINING.md as examples; all are replaced with made-up names and numbers.

**The dashboard (less load)**
- **Activity's events** are read once and then only the new ones (`EventCache`): Activity read up to 10,000 events at
  every 30-second refresh, Today 500 to show 10, Service status 500 to count the errors, the sign-in note 2,000.
- **Service status** is checked at most once a minute, shared by every open dashboard (each look called Cloud Run and
  Cloud Scheduler); the brake and the held campaigns are kept 15 s; a campaign's bar comes from the dashboard's copy of
  the records (it read every copy from Firestore at each refresh); the weekly summary's preview at most once a minute.
  Any change made on the dashboard clears them.
- **Live refresh:** every 5 minutes, not 30 s, on pages that change only when someone changes them (Help, Settings but
  Mailboxes, About, Update); paused after 15 minutes with no key, click, touch or scroll, and back at the next one.
- **Compressed answers:** text over 8 KB is sent gzip-compressed (Messages: 85 KB → 6 KB at each refresh).

**Each email (faster)**
- The lookups the checks need (who sent it before, shares, the thread, colleagues' names, look-alikes) are asked at
  once, not one after another; the sender's brand ownership is looked up beside the other lookups (it waited for them,
  up to 6 s more); the brake is read only when an email would be moved (it was read for every email).
- A picture, PDF or Office file seen before (the same logo in every newsletter, the same attachment in every copy of a
  campaign) gives its answer without being decoded again (a large picture took up to seconds, holding up the
  instance); one DNS lookup per site at a time, shared by the copies arriving together, and a site with no address
  records kept 10 minutes; the look-alike list and the phishing-training settings read once at a time per instance.

**Scheduled work**
- **Phishing lists:** a download with the same entries as the copy kept isn't written again (every instance reloaded
  every list after each daily download, up to 1.5 million entries each); it still counts as downloaded.
- **Suspicious mail looked at again** an hour later (looked for up to 6 h) and a day later (up to 30 h), each window
  read on its own: one read of 50 hours, at most 3,000 records, never reached the day-old ones in a busy district.

**Comments:** every source file's comments checked against the code (about 250 fixed or added: wrong numbers and
names, old menu names, comments above the wrong code, logic without an explanation); the code itself unchanged
(compared file by file, syntax tree before and after). A few messages that named old pages say the new ones
(install.sh, clear-data.sh, the lists' "not updated" note).
- **Checks level 16:** after this update, recent delivered mail is checked again (for the training-rule fix).

**Documentation:** README, PRIVACY (Show the email shows the real email to admins and moderators; attachments are read
in memory), DEPLOY, INSTALL, ARCHITECTURE, RETRAINING, ROADMAP, COSTS, SCALING, WORKSPACE and DASHBOARD-ROLLBACK
brought up to date with 0.5.59 to 0.6.7.

## 0.6.6: Re-scan can't be repeated on one email; "Show the email" shows the whole email

- **Re-scan limits** (each re-scan reads the email from Gmail and runs every check and the AI again): one email is
  re-scanned again only 30 seconds after its last re-scan, said with how long to wait (kept on its record, so every
  dashboard instance knows; before: 5 seconds, per instance); while one runs, the same email again is refused at once
  ("being re-scanned now"); re-scans run 2 at a time per instance, at most 8 more waiting, then "try again in a
  moment" (`rescan`/`rescanNow` in `src/pipeline.js`, `POST /api/rescan` in `src/server.js`). On the page, its
  button is greyed out while it runs, and R or a click again only says so. Tests: `test/server.test.js`.
- **"Show the email"** shows the email itself first, whatever the AI did with it (it skips mail from inside and other
  languages, and an email of only a picture or an attachment has no text for it): who sent it to whom, the date and
  subject, all its text, the earlier messages quoted below it and any text hidden from the reader (folded away),
  every link with where it really goes, the attachments (name, type, size) and how many pictures. Then what the AI
  reads, as before. Read from Gmail when opened, never stored; shown as text only (its HTML is never rendered, its
  pictures never loaded, its links not clickable). Test: `test/review-ai-names.test.js`.
- No checks change.

## 0.6.5: a loading bar for anything that takes more than a second

- **The dashboard** shows a bar across the top, with what is happening ("Re-scanning: reading the email from Gmail and
  checking it again…", "Loading the page…", "Reading the emails for the retraining file…"), whenever something the
  person started takes more than a second: an action (Re-scan, a review answer, saving a setting, a campaign's
  decision, anything sent to the service), opening a page, or the retraining download. It goes when that is done;
  the live refresh in the background never shows it; with reduced motion it pulses instead of sliding
  (`busyStart`/`busyEnd` in `public/app.js`, `.busy` in `public/app.css`). No checks change.

## 0.6.4: Review notes a sender check that neither passed nor failed

- **Review** shows, under the evidence, a note when an email's sender check (DMARC) neither passed nor failed: Gmail
  wrote no result, the sender's domain publishes no DMARC policy ("none"), another result (temperror…), or nothing
  recorded. It is said "not counted either way": a missing DMARC result adds no points (a failure does, and a pass
  is already under "Points to safe"). Before, it was only in the email's details (`reviewEvidence` in
  `public/app.js`). No checks change.

## 0.6.3: no DMARC result from Gmail is worked out from its SPF and DKIM results; your own sent copy isn't judged

- **False alarm:** mail between two staff accounts of the district's second domain was judged
  "outside" and read by the AI (98%, "would move"): "the address is the organization's, but DMARC didn't pass".
  Gmail's verification line on that copy had no DMARC result at all ("dkim=pass header.i=@…; spf=pass
  smtp.mailfrom=…", no "dmarc="), while another email between the same two accounts had "dmarc=pass": Gmail leaves it
  out on some mail between accounts of one Workspace.
- **What changes** (`deriveDmarc` in `src/engine/mime.js`): with no DMARC result written, it is worked out from the
  results Gmail did verify, as DMARC defines it (RFC 7489): it passes when DKIM or SPF passed for the From address's
  own domain (the same registrable domain). Then the address counts for "inside" and the allowlist as with Gmail's own
  pass. Only for the organization's own domains (ORG_DOMAINS): other senders keep what Gmail wrote, as before.
  Another domain's signature (a mailing service's) proves nothing; a result Gmail wrote is never changed
  ("dmarc=fail" stays a failure). The record notes it: Details → Sender check, "DMARC pass (worked out from DKIM:
  Gmail wrote no DMARC result)". Test: `test/ownership.test.js`.
- **A mailbox owner's own sent copy is never judged** (`ownSentCopy` in `src/pipeline.js`): a copy with Gmail's SENT
  label, or from the mailbox owner's own address with nothing showing it was ever delivered (no receiving server's
  verification, no Received line; mail from anyone else always has both). The first check skipped SENT already; now
  the re-checks skip it too, and Re-scan says so (mark it Not phishing to clear it from the review). Test:
  `test/ownership.test.js`.
- **Checks level 15** (14, then 15 for the own-domains limit; one re-check): after this update, recent delivered mail is checked again (only to raise a verdict: Re-scan
  the emails from inside judged "outside" meanwhile).

## 0.6.2: Status says which domains the worker counts as the organization's

- **Why:** mail from the district's second domain (DMARC passing for it, as Gmail wrote) was judged "outside" and read
  by the AI, while the dashboard showed both domains. The checks count it as inside (0.5.59; the email was checked
  again here with both domains: inside, not read by the AI), so the worker that judged it had other domains than the
  dashboard (ORG_DOMAINS not updated in it) or a build before 0.5.59, and nothing on the dashboard showed that.
- **Status → "org-domains":** each worker instance now notes, with its AI engine, the domains it counts as the
  organization's (`state/engine-worker`, `orgDomains`; `src/server.js` reportEngine), and Status compares them with the
  dashboard's: the same, a check mark; different, a problem naming the domains judged as outside and what to do
  (`bash deploy/install.sh`, then Re-scan the emails judged meanwhile); a worker before 0.6.2, unknown until it is
  updated. Test: `test/server.test.js`.
- No checks change.

## 0.6.1: moderators (spruce-moderators) review emails without being admins; Retraining examples on its own page

- **Moderators:** the members of a new group, `MODERATOR_GROUP` (`spruce-moderators@` the first of `ORG_DOMAINS`
  unless `deploy/settings.env` names another; `off` for none), may open the dashboard to review and categorize
  emails. They see **Today**, **Review**, **Threats → Campaigns** and **Re-checked**, **Mail** (Messages, an
  email's page, Check an email, Users) and **Help**; they answer phishing, false alarm or ignore, and re-scan, one
  at a time or ticked together; read an email from Gmail to decide (Show the email); and confirm, dismiss or
  search for the copies of a whole campaign. They don't see **Health** or **Settings** (nor Look-alikes), and
  can't resume the brake, download the CSV, or move an email back without marking it a false alarm.
  - The service refuses everything else to them (403), whatever the page shows: `MODERATOR_ROUTES` in
    `src/server.js`. Someone in both groups is an admin. A failed check of the moderator group lets nobody in as a
    moderator, and never keeps an admin out (`src/auth/verify.js`).
  - Every answer names who gave it; Activity notes a moderator's sign-in "as a moderator". The weekly summary
    still goes to the admins only.
  - `GET /api/session`: who is signed in, as what, and what the page's frame needs (it was `/api/settings`,
    which is for admins).
  - `DEMO_ROLE=moderator` shows the demo as a moderator sees it.
  - Test: `test/moderators.test.js`.
- **A false alarm goes back to the Inbox:** marking an email a false alarm (not phishing) moves it back to the Inbox
  when it is in Spam, in Review, on its page and ticked together (`mark` in `src/pipeline.js`); Activity notes the
  move. On its page the button then reads **False alarm: move back to Inbox**. In monitor mode nothing was moved,
  so nothing moves back.
- **The brake banner:** while the brake holds, a red banner across the top of every page, for admins and
  moderators, says moving is paused and to contact an administrator (an admin resumes it on Today).
- **Health → DMARC & reputation:** each of your domains' DMARC and SPF records as published in DNS, what they say (policy,
  subdomains, pct, alignment, report addresses), a grade, and what would make them stronger; a subdomain without a
  record shows its parent's. Read through Cloudflare's public resolver when an admin opens the page (only the domain
  names are sent; kept 10 minutes; Check again reads them now). `src/dashboard/dmarc.js`, `GET /api/dmarc` (admins
  only); made-up records in demo mode. Test: `test/dmarc.test.js`.
  - **Reputation:** whether Cloudflare Security DNS blocks each domain, Google Safe Browsing lists its home page and
    the Spamhaus DBL lists it (the last two when they are on), each clean, listed, off or not checked; and every
    entry the downloaded phishing lists have on the domain or under it (links, sites, sender addresses), read from
    the lists' stored copies. `src/dashboard/reputation.js`, `GET /api/reputation` (admins only), the service's own
    lookups (no judging file changed). Test: `test/reputation.test.js`.
- **Health → Retraining examples:** the export of marked emails for retraining the AI model has its own page
  (it was at the foot of Model health). Settings → Retraining still allows it or stops it.
- **Install level 6:** `deploy/install.sh` passes `MODERATOR_GROUP` to the dashboard and lets the group through
  Identity-Aware Proxy (a group that doesn't exist yet is said, and the admins still get in). Install this version
  from Cloud Shell: `bash deploy/update.sh`. Create the group in the Admin console first (it may stay empty):
  docs/INSTALL.md, step 1.
- **Checks level unchanged:** only wording changed in the files that judge email.

## 0.6.0: a redesigned dashboard: a menu on the left, Today, a review list with the evidence, a campaign timeline

- **Roll back:** the classic design's three files are kept, unchanged from 0.5.74, in the new **`ui-classic/`**
  folder (not served); copying them into `public/` puts back its look. `docs/DASHBOARD-ROLLBACK.md` says more, and
  how to undo the whole change.
- **The menu** is on the left: **Today**, **Review** (with how many emails wait), **Threats** (Campaigns,
  Re-checked, Look-alikes), **Mail** (Messages, Check an email, Users), **Health** (Service status, Readiness, Model
  health, Activity) and **Settings**, in four groups: Protection (Policy, Allowlist), Threat feeds (Safe Browsing,
  Spamhaus, abuse.ch), Organization (Mailboxes, Weekly summary, Link clicks, Phishing training), System (Retraining,
  Update, About). **Help** is at its foot. A card in the menu says the mode and where to go from it; the badge stays
  in the top bar, beside the period and the live updates. Every page keeps its address (`#/review`, `#/health`…).
  The menu paths in the alerts, Activity, the signs' wording and the docs follow ("Status → Activity" is
  "Health → Activity", "Email → Re-checked" is "Threats → Re-checked").
- **On a phone** the menu is a drawer (the menu button, or More), and a tab bar at the bottom has Today, Review,
  Threats and Health.
- **Today** (was Overview) opens with a greeting and **Needs attention**: one list, each with its button, instead of
  a banner each (the brake, paused campaigns, a phishing list behind, phishing found after delivery, new
  look-alikes, and the emails waiting for review). Then the numbers, the daily chart, top reasons, the largest
  campaigns and recent activity, as before.
- **Review** lists every item (the copies of one email) at once, with its AI score, sender, copies, date and
  heaviest sign, and quick Phishing, False alarm (Not phishing) and Ignore buttons. Tick several to answer them
  together. **Open one** to see who sent it to whom, where the AI and rules scores stand, the signs that point to
  phishing and those that point to safe (weak, medium or strong), what the AI weighed most, and the five answers:
  **P** phishing, **F** false alarm, **I** ignore (unclear), **N** skip for now (stays in the queue, undecided),
  **R** re-scan; with **More details** (the email's page) and **Show the email** (read from Gmail now, as the AI
  reads it; nothing is kept). The review queue's items now carry what the list shows of them (`reviewGroups`, moved
  to `src/dashboard/aggregate.js` so the clickable mockup has them too).
- **Threats → Campaigns** shows the newest 15 as a timeline across the period, one picked out with its numbers
  and **Open every copy**; every campaign is in the table below.
- **Health → Service status** is a status page: one line on how it is, each check with what to do, and beside them
  the Readiness checks and the AI model's reviews and false alarms.
- **Settings → Policy** shows **Monitor** and **Enforce** side by side (Monitor the safe default) and the AI's two
  lines on one scale; each setting says On or Off and whether it is the default. Changing one works as before
  (the project ID; I agree for enforce mode).
- New colors (spruce green), with a dark mode of their own; what points to phishing is orange and what points to
  safe blue, told apart by lightness too.
- **Checks level unchanged:** only wording changed in the files that judge email (the menu paths).

## 0.5.74: "Business via QuickBooks" is no false alarm

- **False alarm:** "Lakeside Ink LLC via QuickBooks" (made up here) was flagged (score 6: "isn't Intuit's address", 5).
  QuickBooks sends a business's invoices through the business's own mailbox and names it "Business via QuickBooks";
  Docusign, Dropbox and others name senders the same way. A brand named only after "via" is now a note with no weight
  when the address is the sender's own: Gmail's DMARC check passed for its domain, and the domain doesn't carry or
  imitate the brand's name (quickbooks-billing…, intuit-invoices…). From a personal mailbox (gmail.com…), which anyone
  can open, it is a caution. The name before "via" naming a brand itself ("Intuit via QuickBooks"), no DMARC pass, or
  no "via" at all: judged as before (`viaPlatformSign` in `vendor/spruce/shared.js`, as in the S.P.R.U.C.E+ extension
  5.94.41; `src/engine/analyze.js` gives it the domain DMARC passed for). No list of platforms. Test:
  `test/ownership.test.js`.
- **Checks level 13:** after this update, recent delivered mail is checked again.

## 0.5.73: allowed link domains, for a link site a phishing list flagged by mistake

- **False alarm:** a restaurant chain's newsletter was "would move" because HaGeZi Threat Intelligence Feeds lists its click
  tracker's domain: all 19 of its links were "dangerous" (score 6; the AI said 0%). Allowlisting the sender would skip
  every check of its mail. **Settings → Allowlist** now has **Link domains** (`allowLinkDomains`, a policy setting like
  the allowlists, or `ALLOW_LINK_DOMAINS` in the services' environment): an allowed link domain and its subdomains are
  matched against the phishing lists by exact address only, as the organization's own domains are
  (`src/engine/network.js`). A listing of its whole domain is a note of no weight on the email ("on HaGeZi…, but it is
  an allowed link domain: a listing of the whole domain isn't counted"); a listing of the exact page still flags the
  link; Cloudflare Security, Safe Browsing, Spamhaus and where each link leads are checked as before. It applies to
  every sender's mail, so it refuses sites where anyone can put up a page (github.io, netlify.app…, and any site on
  them), link shorteners, suffixes (co.uk), domains the lists never list whole (the big brands', personal mail,
  cloud storage) and your own domains (`linkDomainRefused` in `src/pipeline.js`). A change is noted in Status →
  Activity. Emails already checked keep their verdict: Re-scan one to check it again. Test: `test/link-allow.test.js`.
- **Checks level unchanged:** with no link domains allowed (the default) every email is judged as before.

## 0.5.72: a copy button by every email address; no repeated "Sent to" box in Review

- **Copy an address:** in an email's view (its "From … to …" line under the subject) and in Review's list of who received
  it and who sent it (also in its "…show more" popup), each email address has a small copy button: it copies the address
  alone, and a message says so (`addr()` in `public/app.js`).
- **Review:** the "Sent to:" box above an email is shown only when it says more than the line under the subject (several
  copies, recipients or senders); for one copy it repeated the recipient.

## 0.5.71: the dashboard shows the S.P.R.U.C.E logo

- **The dashboard's logo and browser-tab icon** are now the S.P.R.U.C.E shield (the magnifying glass over the spruce,
  as in the S.P.R.U.C.E+ extension's `branding/icon.svg`), in place of a generic shield with a tick: `public/icon.svg`,
  used by the header and as the page's icon (`public/index.html`). No checks change.

## 0.5.70: a government agency's bulletin through GovDelivery is no false alarm

- **False alarm:** "IRS Newswire" <irs@service.govdelivery.com> got "isn't a known IRS address, though govdelivery.com
  looks like IRS's (registered through GoDaddy Corporate Domains…)" (a caution). GovDelivery (Granicus) is the service
  government agencies send their bulletins and alerts through; only government organizations can use it, and DNS
  can't show it (its records name only Granicus), so the ownership lookup (0.5.64) could only guess. An agency's name
  (a brand whose own domains all end in .gov or .mil) on GovDelivery's address is now a note with no weight, and a
  strong sign (5, forged) when its sender check (DMARC) failed: GovDelivery's DMARC policy is "none", so forgeries are
  still delivered. A company's name there, or an agency's on another domain, counts as before (`govMailService` in
  `vendor/spruce/shared.js`, as in the S.P.R.U.C.E+ extension 5.94.40). Test: `test/ownership.test.js`.
- **Checks level 12:** after this update, recent delivered mail is checked again.

## 0.5.69: phish-tiny 0.22.0, far fewer false alarms on the district's own mail

- **The AI model is phish-tiny 0.22.0** (TinyPhishLLM `c37a8f0`, `vendor/spruce/VENDOR.json` `modelSource`; was 0.21.0),
  input format 3 as before (the sync checked all 95 reference cases). It was trained with a third de-identified
  retraining export of the district's mail (`docs/RETRAINING.md`; the export's files are in no repository).
- **What changes**, against 0.21.0 (held-out sets, never trained on): the district's held-out genuine emails called
  phishing at 50%: 10 of 45 → 2 (at the service's 90% line: 4 → 2); its held-out phishing still all caught; every
  regression case right.
- **Worse:** one reported scam from a compromised staff account (an "estate sale" note) is no longer caught by the AI
  (99% → 9%); the AI score alone never moves mail from inside the organization, so such mail is judged by the rules
  as before. Published phishing missed at 90%: 16 of 771 → 18 (within chance).
- **Checks level 11:** after this update, recent delivered mail is checked again.

## 0.5.68: the retraining export catches names in capitals, rosters, IDs and addresses

- **What a district's file showed the export missed** (`src/training.js`): students' names in a records request written
  "LAST, FIRST" in capitals, a class roster of "Last, First" lines, a first name and an initial ("Theo V.", made up) in a
  classroom tool's summary, customers' names in capitals in insurance and card emails (made-up examples
  in `test/training.test.js`), a 6-digit student number, a card's last four digits, a payment reference and an agent's licence number,
  and a street address in a shipping confirmation. Now:
  - **⟦marked⟧ for a person to decide:** names written as a roster (in capitals anywhere; "Last, First" on a line of
    its own), a first name and an initial, and a known first name or surname in capitals with the word after it;
    a mark inside a mark becomes one;
  - **[NAME]:** a greeting with a comma ("Hello, CASEY FAIRWEATHER", made up);
  - **taken out:** 5- and 6-digit numbers, a card's last digits, codes of letters and 4 or more digits (`number`), and
    street addresses (`street address`).
- Nothing about how mail is judged changes. Test: `test/training.test.js`. Docs: `docs/RETRAINING.md`.

## 0.5.67: phish-tiny 0.21.0, a long email's last sentences reach the model

- **The AI model is phish-tiny 0.21.0** (TinyPhishLLM `7e61482`, `vendor/spruce/VENDOR.json` `modelSource`): 0.20.0's
  weights, reading **input format 3**. The model's input kept only the first 60 sentences of an email's text, so in
  a longer email the end it reads (its last 62 word pieces) was the 60th sentence, not the real ending where a long
  scam often asks. Format 3 keeps a longer text's first 40 and last 20 sentences (`splitSentences(text, format)` and
  `AI_INPUT_FORMAT` in `vendor/spruce/ai.js`); shorter emails are read exactly as before (the sync checked all 95
  reference cases, one of them a 75-sentence text).
- **What changes:** on held-out emails padded with 70 newsletter sentences before their own text, phishing flagged at
  90%: 638 of 771 → 696; genuine flagged: 4 of 846 → 4. Every other score is 0.20.0's.
- **"…show more"** marks the sentences the model's input leaves out (now the middle of a long email, not its end).
- **Checks level 10:** after this update, recent delivered mail is checked again. Docs: `README.md`,
  `docs/ARCHITECTURE.md`.

## 0.5.66: "…show more" shows the whole email

- **Review and Messages → AI opinion → …show more** now lists the whole email, every sentence of its text, redacted
  as the model reads it (addresses keep only their domain; phone numbers and long numbers replaced), read from Gmail
  on demand as before (nothing stored; Activity notes the look). It stopped at 40 sentences ("…and N more"), and read
  only the 8,000 characters the model is given; it now reads all of the text the service reads of an email. The
  first 40 sentences are also scored on their own as before.
- **What the model doesn't read is marked:** the model's input format keeps only an email's first 60 sentences
  (`modelInputParts` in `vendor/spruce/ai.js`, as in training), so the sentences after the 60th are shown dimmed,
  marked "not read by the model". (A change to that limit can come only with a new model.)
- `model.js` `reading()` (recorded as cosmetic: nothing that judges mail changed). Test: `test/explain.test.js`.
  Docs: `README.md`.

## 0.5.65: a personal account's own address in its name is no claim to be Google

- **False alarm:** a parent writing from a Gmail account whose name shows its own address ("1Jo.Doe@gmail.com 27jodoe")
  got "The sender's name says … but … isn't Google's address" (5): the word "gmail" in the name read as a claim to be
  Google. A personal mail service's own address (or its domain) written in the sender's name is now taken out before
  the name is read for a brand (`nameWithoutOwnAddress` in `vendor/spruce/shared.js`, as in the S.P.R.U.C.E+
  extension 5.94.36). "Google Security" from a Gmail account still counts, as does another domain's address in the
  name, and a company domain in its own name ("Amazon.de" from amazon.de). Test: `test/ownership.test.js`.
- **Checks level 9:** after this update, recent delivered mail is checked again.

## 0.5.64: whose a sender's domain is, from public records

- **False alarm:** "The sender's name says "Xoom, a PayPal Service", but noreply@service.xoom.com isn't PayPal's
  address" (5). The brand table knows only each brand's main domains, and the service had no other way to tell.
  Now, when a sender's name claims a brand whose known domains don't include the sender's, whose the domain is
  comes from public records (`src/intel/ownership.js`), as in the S.P.R.U.C.E+ extension (its `brandOwnership`),
  never from a hand-kept list:
  - **owned** (no sign; the reason says how it was shown): the brand's DMARC record sends its reports to the
    domain; or the domain's sends them to the brand and the brand publishes the RFC 7489 authorization; or its
    name servers are under the brand's domain, or the same set as the brand's (not at providers every customer
    shares); or a corporate brand-protection registrar and a registrant naming the brand. xoom.com: its name
    servers are PayPal's (ns1-pchnet.paypal.com).
  - **likely** (a caution, never moved): a corporate registrar plus one more link (reports to the brand, a
    registrant naming it, a year or more of age).
  - **unknown:** the sign stays as before.
- What is sent: domain names only, to Cloudflare's public resolver and the domain's registry and registrar;
  each answer is kept in the shared store 30 days (an unknown one, a day); an email waits at most 6 seconds for
  it (`docs/PRIVACY.md`). Test: `test/ownership.test.js`. Docs: `README.md`, `docs/PRIVACY.md`.
- **Checks level 8:** after this update, recent delivered mail is checked again.

## 0.5.63: Look-alikes: a marked domain shows Change

- **Status → Look-alikes:** a domain an admin has marked (its own, harmless, a threat, or watched as found) shows a
  **Change** button instead of the choices and **Mark**, which read as if it still needed marking. **Change** brings
  them back, with **Cancel**; a domain nobody has marked yet keeps the choices and **Mark**. Dashboard only: nothing
  about how mail is judged changes.

## 0.5.62: a newsletter's subdomain with no DNS records is not "made up"

- **False alarm:** "The sender's domain masterpiece.… doesn't exist, so the address is made up" (3) for newsletters and
  no-reply addresses, which often send from a subdomain with no DNS records of its own while their organization's
  domain is real. The sender's organization's domain (its registrable domain) is now looked up too
  (`src/engine/network.js`), and a sender subdomain that doesn't exist is:
  - judged by its organization's domain: blocked by Cloudflare Security → strong (5); exists → a note, no weight;
  - never "made up" when Gmail verified the sender (DMARC passed);
  - "made up" (3) only when its organization's domain doesn't exist either (or a domain of its own doesn't exist).
  The S.P.R.U.C.E+ extension already judged such a sender by its organization's domain.
- The other reputation checks of the sender (phishing lists, Spamhaus, the registration age of its organization's
  domain) are unchanged. Test: `test/mailers.test.js`. Docs: `README.md`.
- **Checks level 7:** after this update, recent delivered mail is checked again.

## 0.5.61: edit a phishing-training rule

- **Settings → Phishing training → Header rules: Edit** beside each rule's Remove. The rule's name, header and
  sending addresses can be changed in place (the same rule, so its counts go on). Its secret value, kept only as a
  one-way hash, stays as it is unless a new one is typed or **Remove the secret value** is ticked; with a new header
  it has to be typed again (the hash is of the header and the value). A rule still needs a secret value or sending
  addresses (a header alone is public). Each change needs the project ID and is noted in Activity, never with the
  value. `POST /api/phish-training/rule/edit`, `Service.editTrainingRule`. Test: `test/simulations.test.js`.

## 0.5.60: Review's "Ignore, treat as suspicious"

- **A third decision in Email → Review** (key **I**; also on an email's own page): **Ignore, treat as suspicious**
  (in the moved queue: "Ignore, unclear: leave it where it is"), for an email that is neither clearly phishing nor
  clearly safe (an outside request for access to a form: only the reader knows whether they expect it). It is left as
  it is, with its Suspicious label; it counts as reviewed (`markedBy`), so it leaves both queues; it is never a
  training example (`unclear: true`, `falseAlarm` stays empty: the retraining export takes only phishing and false
  alarms); the later checks and the re-check after an update leave it alone. Marking it phishing or not phishing
  afterwards replaces it. Every copy of a campaign at once (`/api/bulk` action `unclear`); Activity notes it.
- `POST /api/unclear`, `Service.setAside` (`src/pipeline.js`). Test: `test/qol.test.js`. Docs: `README.md` (Review),
  `docs/RETRAINING.md`.

## 0.5.59: mail from the organization's second domain is no longer called outside

- **A false alarm on an organization with two domains:** the checks that take one domain (whether the sender is
  outside, `senderContextSigns`; a colleague's name on an outside address, `nameAddressSigns`) were given only the
  first of `ORG_DOMAINS`. A student or staff member on the second domain writing to someone on it was "from outside
  your organization (first domain)" and, sharing a name with someone in the directory, "the name of someone in your
  organization on an outside address"; when the second domain looks like the first, also "from an address imitating
  your organization's domain" (score 4, suspicious). They now take the organization's domain the address is in
  (`ownOf` in `src/engine/analyze.js`), and one of the organization's own domains never counts as imitating another.
  A look-alike of the domains still counts. Test: `test/colleague-context.test.js`.
- Such mail is treated as inside only when DMARC passes for it: a domain without a DMARC record gets "none" from Gmail
  (`docs/DEPLOY.md`, `ORG_DOMAINS`).
- **Checks level 6:** how such mail is judged changes, so after this update the service checks recent delivered mail
  again.

## 0.5.58: a very long email's last character is checked too

- 0.5.57's reader kept a long text's first 15,000 and last 5,000 characters with a newline between them, 20,001 in
  all; the checks in `vendor/spruce/` read at most 20,000, so they missed its last character. It now keeps the
  last 4,999 (`TAIL_TEXT` in `src/engine/html.js`), 20,000 in all, as the S.P.R.U.C.E+ extension does (5.94.34).
- **Checks level 5** (what a very long email's checks read changes by one character).

## 0.5.57: a very long email's ending is read

- **The email reader keeps a long text's start and its end.** An email's visible text longer than 20,000 characters
  kept only its first 20,000, so a very long email's ending (where a long scam often asks: "reply to my personal
  email") reached neither the checks nor the AI model; with 0.5.55's model, "the end" of such an email was
  characters 18,000–20,000. It now keeps the first 15,000 and the last 5,000 (`headTail` in `src/engine/html.js`,
  `HEAD_TEXT`, `TAIL_TEXT`), for HTML and plain-text emails (`src/engine/mime.js`), and one huge block of text is cut
  the same way (before, it was kept whole). Emails of 20,000 characters or less read as before. A new test checks it.
- **Checks level 4:** how a very long email is judged can change, so after this update the service checks recent
  delivered mail again (`node tools/checks-level.js --raised`).
- The retraining export (0.5.56) holds the same text. Docs: `docs/RETRAINING.md`, `docs/PRIVACY.md`.

## 0.5.56: the retraining export keeps the whole body

- **The retraining export** (Status → Model health → Download for retraining, `docs/RETRAINING.md`) now holds each
  email's whole body, not its first 1,200 characters, so a model that reads more of an email (phish-tiny 0.20.0
  reads a long email's start and its end) is trained on the part where a long scam asks, and a later model can be
  trained from the same file. The export reads it from the message (`facts.visibleText`, at most about 20,000
  characters: the service reads no more of any email, `src/engine/html.js` `MAX_TEXT`), not from what the model is
  given (at most 8,000). Should that limit rise, a body over 20,000 characters keeps its first 15,000 and last 5,000
  (`BODY_CHARS`, `BODY_HEAD`, `BODY_TAIL` in `src/training.js`). The same de-identification applies to
  all of it; a long body means more to review, and the guide says to read it to the last line.
- Nothing about how mail is judged changes (no checks level). Docs: `docs/RETRAINING.md`, `docs/PRIVACY.md`.

## 0.5.55: phish-tiny 0.20.0, reads a long email's start and its end

- **The AI model is phish-tiny 0.20.0** (TinyPhishLLM `9e71652`, `vendor/spruce/VENDOR.json` `modelSource`; was
  0.19.0). Same architecture (ELECTRA-small), size, vocabulary and input format (2), but it reads a long email's
  start and its end: an input longer than 256 word pieces keeps its first 192 and its last 62 (`model.json`
  `config.headTokens`), not its first 254, because a long scam often asks at its end (for example an "estate sale"
  list from a compromised staff account that ends "reply to my personal email").
- **The cut:** `WordPiece.encode(text, maxLen, head)` in `vendor/spruce/ai.js` keeps `[CLS]`, the first `head`
  pieces, the last `maxLen - 2 - head` and `[SEP]` when the model's `config.headTokens` is set (else the first
  `maxLen - 2`, as before); `src/engine/model.js` passes it. `aiFacts` (`src/engine/analyze.js`) gives the model a
  long body's first 6,000 and last 2,000 characters (was its first 8,000). A new test checks the cut.
- **What changes**, against 0.19.0 at the service's 90% line (held-out sets, never trained on): published phishing
  missed 75 of 771 variants → 16; synthetic phishing missed 68 of 1,500 → 16; a district's reported estate-sale
  phishing now caught; every regression case right.
- **Worse:** about six more genuine emails called phishing across the check sets at 90% (published genuine 3 of
  774 → 5), mostly short account and security notices. The AI score alone still never moves mail from inside the
  organization, and monitor mode is the default.
- **Checks level 3:** the model and its input changed, so after this update the service checks recent delivered
  mail again (`node tools/checks-level.js --raised`).

## 0.5.54: phish-tiny 0.19.0, far fewer false alarms on a district's own mail

- **The AI model is phish-tiny 0.19.0** (TinyPhishLLM `a5e17c7`, `vendor/spruce/VENDOR.json` `modelSource`; was
  0.18.0). Same architecture (ELECTRA-small), size, vocabulary and input format (2): `modelInputParts` and the
  engine are unchanged (the sync checked all 94 reference cases; `test/fixtures/model-reference.json` is 0.19.0's).
  It was trained with one district's own de-identified examples from a retraining export (`docs/RETRAINING.md`;
  the export's files are in no repository) and two new training losses.
- **What changes**, against 0.18.0 at the service's 90% line (held-out sets, never trained on): the district's
  held-out genuine emails called phishing 12 of 29 → 0 (the one phishing email among them still caught); published
  phishing missed 13 of 681 variants → 6; published genuine called phishing 4 of 705 → 3.
- **Worse:** two more of the 14 platform-share check cases (a document shared through DocuSign or Adobe by another
  organization's account) fall under 90%; they stay above 50%. The AI score alone still never moves mail from
  inside the organization.
- **Checks level 2:** the model changes how email is judged, so after this update the service checks again the
  mail delivered in the last `RECHECK_AFTER_UPDATE_HOURS` that is still in the Inbox. No change to the
  installation (`installLevel` 5). Docs: `docs/ARCHITECTURE.md`.
- Tests: the update re-check tests (`test/recheck.test.js`) take the level from `package.json` and raise it by one,
  instead of assuming level 1.

## 0.5.53: Settings → Mailboxes can switch from the pilot to the whole domain; the mailbox list in pages

- **Who is checked: the pilot (always the default) or the whole domain.** A new setting, `watchScope`
  (`WATCH_SCOPE` in settings.env, `pilot` unless it says `domain`; also on the dashboard), chooses whether the
  service watches the pilot (`PILOT_GROUP`, `PILOT_OU`, `PILOT_USERS`, as before) or every active mailbox of
  `ORG_DOMAINS` (`domainUsers` in `src/gmail/client.js`: the directory's users at those domains, not suspended or
  archived). The whole domain needs the Users → Read privilege and the `admin.directory.user.readonly` scope (the
  colleague-name check's); a failed read stops nothing and says what's missing.
- **Switching on the dashboard** (Settings → Mailboxes → Who is checked → Change who is checked): it reads the
  directory and shows how many mailboxes the pilot and the whole domain would watch (`GET /api/scope-preview`, at
  most every 10 minutes), what happens (every mailbox checked in the current mode, costs), and needs a ticked box,
  the Google Cloud project ID and the signed-in admin's own address, both ways (`POST /api/policy`, key
  `watchScope`). The whole domain isn't switched to when the directory's mailboxes can't be read. The directory is
  read again at once (the renew-watches job); noted in Status → Activity → What admins did.
- **A large domain catches up within hours.** The daily renewal covers about 5,000 mailboxes in its time; what it
  leaves (`state/watchLeft`: watches to start, or to stop after switching back) is continued by each hourly job
  with what is left of its time, so a domain of 10,000 is watched within hours, not days.
- **Settings → Mailboxes for 10,000 mailboxes:** the watched mailboxes 100 a page by address, with Next and
  Previous and a search by the start of an address (`GET /api/mailboxes`, `listWatchedPage` in both stores:
  Firestore orders by the address alone, its single-field index), instead of the first 500 at once; the counts
  (watched, being added or stopped, watches ending within a day) at the top. "Update group membership now" is
  "Read the directory again now".
- No change in how email is checked (checks level 1); no change to the installation (`installLevel` 5).
- Docs: `README.md`, `docs/INSTALL.md` ("The whole domain"), `docs/DEPLOY.md` (`WATCH_SCOPE`), `docs/SCALING.md`,
  `docs/ALERTS.md`. Tests: `pipeline.test.js` (the pilot by default; the whole domain watched from the directory,
  continued by the hourly job; a failed read stops nothing; back to the pilot stops the others; the counts; the
  pages), `policy.test.js` (the box, the project ID and the admin's own address, both ways), `firestore.test.js`
  (the pages against the emulator), `server.test.js`. Made-up mailboxes.

## 0.5.52: the dashboard says every reason delivered mail is re-checked

- **Settings → Policy, "Re-check delivered mail"**: its choices and explanation said only that a phishing list's new
  entry re-checks delivered mail. They now name every reason (0.5.51): a list's new site or sender, a look-alike of
  the district's domain found or marked a threat, an update that changes how email is checked (with
  `RECHECK_AFTER_UPDATE_HOURS`), and the second look at suspicious mail an hour and a day after it arrived; and that
  an update that only changes the dashboard, wording or documentation re-checks nothing.
- **Email → Re-checked**: its introduction and its "Re-checking" line say the same, and a new "After updates" line
  says what an update re-checks and how the last one went (its version, when, how many emails), from
  `state/updateRecheck` (`GET /api/rechecked`: `afterUpdateHours`, `afterUpdateMax`, `updateSweep`).
- No change in how email is checked: the checks level stays 1.

## 0.5.51: re-checks after a look-alike is found or marked a threat, and after an update that changes the checks

- **A look-alike of the district's domain re-checks delivered mail.** When the look-alike watch finds a new
  domain imitating the district's, or an admin marks one a threat on Status → Look-alikes (it was a weak sign
  or none), the mail of the last `RECHECK_DAYS` days sent from it, asking for replies to it or linking to it is
  checked again in full, as for a list's new entry. For that, an email's re-check hashes (`src/recheck.js`
  `indexOf`) now also hold its sender's domain and its Reply-To domains, with the domains above them (never a
  personal mailbox provider's such as gmail.com, nor the organization's own); so a phishing list's new domain
  also finds the mail sent from it. Mail delivered before 0.5.51 has only its link sites and sender address.
  The dashboard says, after marking, how many emails will be checked again.
- **An update that changes how email is checked re-checks recent mail; one that doesn't, nothing.**
  `package.json` has a `checksLevel` (1), raised by one in a version that changes a rule, a sign or its weight,
  the AI model or its input, how the lists are matched or what the policy does with a score. The hourly job
  remembers the level it last ran (`state/checksLevel`; the first run of 0.5.51 only records it); a higher one
  checks again the mail delivered in the last `RECHECK_AFTER_UPDATE_HOURS` (24) that is still in the Inbox,
  newest first, at most `RECHECK_AFTER_UPDATE_MAX` (5,000), about 1,500 queued an hour as the queue has room
  (`checksUpdate` in `src/pipeline.js`, `state/updateRecheck`). Mail that arrived after the new version started
  was judged by it already and isn't taken. Status → Activity says when it starts; the re-check alert, the
  record's "why" and Email → Re-checked say "version … changed how email is checked". A version that changes
  only the dashboard, wording, documentation or installation keeps the level and re-checks nothing; a version
  rolled back re-checks nothing either. Only with `RECHECK` on.
- **The level can't be forgotten:** `src/checks-level.js` lists the files that judge email (the engine, the
  checks, the lists' matching, the policy, the look-alike watch, the training-email rules) and the model's
  SHA-256; `test/checks-level.test.js` keeps their fingerprint in `test/fixtures/checks-fingerprint.json` and
  fails when they change until `node tools/checks-level.js` records either `--raised` (the level raised) or
  `--cosmetic "what changed"`. `CLAUDE.md` says when to raise it.
- This version doesn't change how email is judged: its level is the first one recorded, so it re-checks
  nothing when installed.
- Docs: `README.md`, `docs/ARCHITECTURE.md`, `docs/DEPLOY.md` (`RECHECK_AFTER_UPDATE_HOURS`,
  `RECHECK_AFTER_UPDATE_MAX`), `docs/PRIVACY.md` (the new hashes), `docs/ALERTS.md`; Settings → Policy's
  "Re-check delivered mail" says so.
- Tests: `checks-level.test.js`; `recheck.test.js` (the new hashes; an update with the level raised re-checks
  the last 24 hours once, the same level or a lower one nothing; off, or 0 hours: noted, nothing checked; copies
  of the same millisecond across runs and the maximum; an admin marking a look-alike a threat). Made-up people
  and districts.

## 0.5.50: phish-tiny 0.18.0, an ELECTRA-small model

- **The AI model is phish-tiny 0.18.0** (TinyPhishLLM `2f596de`, `vendor/spruce/VENDOR.json`; was 0.16.0), an
  ELECTRA-small network (12 layers, 13.5 million parameters, `model.onnx` 14 MB) instead of BERT-tiny. Same
  input format (2) and vocabulary, so `modelInputParts` is unchanged; `model.onnx` is the whole network, so the
  engine (`src/engine/model.js`, ONNX Runtime at the "basic" level) runs it as it is. The BERT-tiny model is kept
  in TinyPhishLLM as `phish-tiny-old` and is not used here.
- **What changes for a district:** on the training repository's held-out published emails, against the BERT-tiny
  0.17.0, it misses fewer phishing emails (8 instead of 14 of 681 variants at 50%; 14 instead of 18 at 95%) and
  calls far fewer genuine ones phishing (5 instead of 20 of 705 at 50%; 4 instead of 14 at 95%); every regression
  case is right, and it recognizes documents shared through Google Docs, OneDrive, DocuSign, Dropbox or Adobe by
  another organization's account naming the district's leaders (14 of 14 check cases). One training run; a
  district's own examples are not in it.
- **It costs more processor time:** about 68 ms per full-length pass instead of about 6 ms; an ordinary email
  about 50 ms, one the model flags (with its explanation) about 420 ms. One worker instance checks roughly 15
  emails a second instead of 28; a district of 100,000 emails a day still needs one instance outside campaigns
  (`docs/SCALING.md`, `docs/ARCHITECTURE.md`).
- The comments and notes that described the model (`src/engine/model.js`, `vendor/spruce/ai.js`,
  `vendor/spruce/VENDOR.json`, `docs/ARCHITECTURE.md`) now describe ELECTRA-small.
- Tests: `firestore.test.js` (run only against the Firestore emulator, on GitHub) expected Activity entries to
  expire with the records (35 days); since 0.5.29 they are kept for the audit period (`AUDIT_DAYS`, 365 days by
  default), so GitHub's Firestore check failed. It now expects the audit period.
- Tests: the references (`test/fixtures/model-reference.json`) are 0.18.0's. The re-check tests' email
  (`recheck.test.js`) is now an ordinary newsletter: the old payroll "statement" with a sign-in link is flagged
  by the new model on arrival, leaving nothing for the re-check to find. Made-up people and districts.

## 0.5.49: a platform notification's name and domain must belong to the same company

- **A share or notification is the platform's own only when the platform its name says it comes "via" belongs
  to the same company as its domain** (`platformClaim` in `src/engine/notifications.js`), besides Gmail's DMARC
  check passing for the platform's domain and a notification mailbox, as before. "Dana Madeup (via Dropbox)"
  sent from drive-shares-dm-noreply@google.com, its sender check passing, was taken for Google's notification
  and judged by Dana's address; it is now no notification, and red (`platformClaimSigns`, 5, kind
  `platform-mismatch`). A platform named on a domain that isn't any platform's is red too when the brand check
  doesn't already say so (Box: kind `platform-claim`; for Google, Microsoft, DocuSign, Dropbox and Adobe the
  brand check flags it). Adobe Acrobat's own sharing domain (adobe.com) and Box (box.com) are platforms now.
  The S.P.R.U.C.E+ extension does the same since 5.102.
- Tests: `notifications.test.js` (the mismatch is no notification and flagged; the matching name is Google's;
  DocuSign on its domain; Box on another domain; Google on another domain left to the brand check; a name in
  brackets that is no platform). Made-up people and districts.

## 0.5.48: phish-tiny 0.16.0, which reads what the sender checks found (input format 2)

- **The AI model is phish-tiny 0.16.0** (TinyPhishLLM `78706ea`, `vendor/spruce/VENDOR.json`; was 0.13.0), the
  first that reads **input format 2**: besides the email, the facts 0.5.47 started giving it (who the sender's
  name claims to be and whether the domain is theirs, other Reply-To domains, the attached files' kinds, failing
  SPF/DKIM) and a subject or text in capitals. `modelInputParts` in `vendor/spruce/ai.js` is TinyPhishLLM's
  `tools/model-input.js` at that commit (`modelInputParts(facts, format)`), and the engine builds the format
  the loaded model names (`model.json` `inputFormat`; 1 for a model that names none), so an older model would
  still get its own text.
- **What changes for a district:** against 0.14.0 on the training repository's held-out published emails,
  0.16.0 misses fewer phishing emails (13 instead of 19 of 681 variants at 50%; 19 instead of 23 at the 90%
  move line) and calls far fewer genuine ones phishing (20 instead of 33 at 50%; 10 instead of 17 at 90%);
  genuine look-alikes of spear phishing (a DocuSign envelope, a phone system's voicemail) are now right. It
  still trusts routine sign-in wording from a calm impostor more than it should; the rules' own sender signs
  weigh those whatever it says. The full scores: TinyPhishLLM's `CHANGELOG.md`. Not yet scored on a district's
  own held-out examples (`tools/score-examples.js`): do that before relying on it.
- Tests: the references (`test/fixtures/model-reference.json`, `model-input-format.jsonl`: 94 cases, 12 new for
  format 2) are 0.16.0's; the native engine matches its answers; `npm test` all green.

## 0.5.47: The AI model's facts carry what the sender checks found (for the model's input format 2)

- **What the model is given** (`analyze.js`, `aiFacts`) now also has what the rule checks already found, so a
  model trained on phish-tiny's input format 2 (0.16.0) judges an email's words in context: who the sender's
  name claims to be and whether the domain is theirs (`identity`: **`aiSenderIdentity`** in
  `vendor/spruce/shared.js`, the same checks as `nameAddressSigns`: a brand's own domain, another domain,
  "not known to be", a free mailbox; a look-alike domain; a colleague's name on an outside address; nothing for
  the organization's own staff), the Reply-To domains that aren't the sender's (**`aiReplyToDomains`**), the
  attached files' kinds (**`aiAttachmentFacts`**: their endings and types, never their names; pictures inside
  the email aren't attachments) and failing SPF/DKIM. **Nothing the current model reads changes**: phish-tiny
  0.13.0 reads input format 1, which leaves these out. `modelInputParts` in `vendor/spruce/ai.js` takes format
  2's lines together with the model that reads them (`tools/sync-model.js`).
- **The retraining export** keeps them, with nothing personal: the identity's brand and yes/no answers, Reply-To
  domains (your domain becomes [OUR-DOMAIN]), attachment endings and types (`docs/RETRAINING.md`). A district's
  examples exported from now on can train a format-2 model with these facts.
- Tests: `engine.test.js` (a "PayPal" sender on another domain with a free-mail Reply-To, failing SPF and DKIM and
  an attachment whose name hides its type: what the model is given, with no file name; the organization's own
  staff get no identity), `training.test.js` (the export keeps them without anything personal). Made-up mail.

## 0.5.46: A Help tab, an architecture deep dive, and About & credits with a Donate button

- **Help (a new tab)**, like the S.P.R.U.C.E+ extension's: How it works, The dashboard, Alerts, Your privacy,
  Google Workspace settings, Install & troubleshooting, Settings reference, Costs, Architecture deep dive, and
  About & credits. Each page is this version's own doc (README.md, docs/*.md), read from the image, so Help always
  matches what is installed. Links between the docs open the matching Help page; web links a new tab. The page
  renders the Markdown as text (never HTML): headings, lists (numbered too), tables, code, links.
- **The architecture deep dive** (docs/ARCHITECTURE.md) now walks through an email step by step, the checks
  (what each reads, its signs and weights, where the code is), what is stored where (every Firestore collection,
  how long), the hourly job in order, re-checking delivered mail, the look-alike watch, the optional services,
  and the security model, before the design choices.
- **About & credits:** the version and model, who made it, the open-source libraries and data sources with their
  licenses and terms, and a **Donate** button (the extension's), which `DONATE_BUTTON=off` hides.
- **The image now holds `docs/` and `README.md`** (Dockerfile, .dockerignore, .gcloudignore), for Help.
- Tests: `test/server.test.js`.

## 0.5.45: Monitor mode says what would move each email; the daily chart shows the emails checked behind

- **Would move, by trigger.** In monitor mode everything landed under one "Would move". Now the Overview's daily
  chart colors each email moved, or that would be moved, by what triggered it: **rules + AI**, **the AI score
  alone**, **the rules alone**, or **an admin's confirmation** (moved and would-move together; hover a day, or the
  table, to see them apart). The big number says, in monitor mode, how many would move by each ("38 would be moved:
  20 by rules + AI, 8 by the AI score alone, 10 by the rules alone"), and a line under the chart gives the shares
  for the period: how much the AI and rules together decide, and how much either alone.
- **Emails checked behind.** The chart draws every email checked per day behind the moved ones, in its own neutral
  color, on the same scale (one axis, never two). Moved emails are a small share of what is checked, so **Zoom in to
  the moved ones** fits the axis to them (the checked ones aren't drawn then; remembered in the browser). The table
  view lists checked, and moved and would-move per trigger, day by day.
- Tests: `test/activity.test.js`.

## 0.5.44: Phishing-training emails can be let through (Settings → Phishing training)

Training emails from KnowBe4, Wizer and similar services are let through unchecked when an admin sets rules for
them: not checked, not moved, not recorded (only counted, "training" in the day's counters), so a campaign
measures whether people spot phishing without help. The same design as the S.P.R.U.C.E+ extension's phishing
simulation policies, as the service's own code (`src/simulations.js`). Off until a rule or domains are added.

- **Header rules:** the vendor's header, plus its **secret token** (or your custom header's value; kept only as a
  one-way hash, never shown again) and/or its **sending addresses** (IPv4/IPv6, ranges), matched against the hop
  Gmail's own server (mx.google.com) wrote: lower Received lines can be forged. A header name alone is refused:
  it is public, so a real phishing email could copy it. Presets for KnowBe4 (PST header token, or X-PHISHTEST with
  addresses) and Wizer (X-TestPhish with addresses). Up to 20 rules.
- **Training link domains:** an email whose links ALL go to the vendor's domains (after unwrapping security
  gateways' rewrites offline) is a training email; one link anywhere else and it is checked as usual. Shared
  platforms, link shorteners, personal mail and well-known companies' domains are refused. Up to 500.
- **The page** has step-by-step instructions (KnowBe4, Wizer, other vendors, Gmail's own allow-listing, testing,
  telling staff), the count today and over 7 days, and when each rule last matched. Each change needs the project
  ID and is noted in Activity. Check an email says when a pasted email is a training email.
- Training emails are left out of the re-checks of delivered mail too.
- Tests: `test/simulations.test.js`.

## 0.5.43: A colleague's name on an outside address counts only when the email claims to be from inside

People share names. A vendor's employee whose name matches someone in your directory, writing a greeting from her
company's own address, was flagged "The sender uses the name of someone in your organization, but writes from an
outside address". Now that sign (3) counts only when something in the email claims to be from inside:

- written from a **personal email account** (Gmail, Outlook.com…);
- from an address **imitating your domain**, or a **brand-new or look-alike** domain (site age, Spamhaus ZRD, the
  look-alike watch);
- **Gmail's sender check (DMARC) failing**;
- **replies going to another address**;
- a **title or your organization's name in the sender's name** ("Misty Samplefield, Principal", "… - Maple Schools");
- asking for **what impersonators ask**: a favor, a phone number, gift cards, payment, payroll or bank details,
  codes or passwords.

The sign says which. Otherwise it is shown with no weight: "The sender has the same name as someone in your
organization, writing from <domain>'s own address. Nothing in the email claims to be from inside your
organization, so it doesn't count." Also new: a colleague's name **with a title or the organization's name
added** ("Misty Samplefield - Maple Schools", "Misty Samplefield (Superintendent)") is now matched to the directory; the
exact name was needed before. Tests: `test/colleague-context.test.js`.

## 0.5.42: Spamhaus: a refused lookup is asked again; the page explains the hour a new key takes

- **Refused lookups are asked again.** A new Spamhaus key takes up to about an hour to sync across Spamhaus's
  servers; meanwhile some know it and some answer REFUSED. A refused lookup is now asked again: 3 tries for an
  email's lookups, 6 for Test (with short pauses), so a server that knows the key answers. Each try counts toward
  the day's lookups. A key every server refuses is still said plainly, and alerted.
- **Settings → Spamhaus** has a warning beside Add the key: a new key can take up to an hour to sync, and Test may
  say "Spamhaus refused the lookup: its servers don't know this key yet" until then. That is expected: wait and
  try again. **Getting a key** is now step by step: the free account; where the Query Key is in Spamhaus's portal
  (Blocklists via DNS Query → Datasets and access → Access, Enabled); the hour's wait; saving it here with the
  project ID; the green badge; and pasting a key nowhere else (if it was, generate a new one).
- Tests: `test/optional-services.test.js`.

## 0.5.41: Settings → Spamhaus says when Spamhaus doesn't know the key

- Spamhaus's servers answer **REFUSED** for a key they don't know: one not active yet (a key made today can take
  a while), disabled, replaced or mistyped. Cloud Run's resolver passes that on (EREFUSED), and the page said
  "Spamhaus couldn't be asked… try again in a minute". Now Test says Spamhaus refused the key and what to check
  (that the Query Key is Enabled in Spamhaus's portal and was copied whole), and a saved key Spamhaus stops
  knowing is the `spamhaus-key` alert instead of lookups silently not happening.
- Other DNS failures say so: "Spamhaus couldn't be reached through the service's DNS resolver (…)".
- Tests: `test/optional-services.test.js`.

## 0.5.40: Each service page says at its title whether it is on

- Beside the title of Settings → Safe Browsing, Spamhaus, abuse.ch and Link clicks, and Status → Look-alikes, a
  badge: **Service is on** with a green check when it is on and working; **Service is on, but not working** in
  red when it is on but its key is missing or refused, or its lookups or downloads fail (abuse.ch: one of its
  lists missed its download); **Service is off** in grey. (The look-alike watch: **Watch is on** or off.)

## 0.5.39: Settings → Link clicks says why Google refused, and what to do

- **Test, and the `click-logs` alert,** now explain Google's refusal instead of showing its raw answer:
  "not authorized to read activity records" means the admin's role lacks the **Reports** privilege (with where
  to tick it: Admin console → Account → Admin roles → the role → Privileges → Admin console privileges →
  Reports; the directory admin's role is "SPRUCE group reader"); a token refused means the
  `admin.reports.audit.readonly` scope isn't on the domain-wide delegation entry.
- The page and docs/INSTALL.md say that the directory admin filled in by default needs that privilege first.
- Tests: `test/recheck.test.js`.

## 0.5.38: Settings → Update says when GitHub was asked, and Check again asks it now

The Update page keeps GitHub's answer (the newest approved version) 10 minutes, and didn't say so: a version
approved a minute ago could stay unseen for up to 10 minutes. Now:

- **Last checked:** when GitHub was asked for the answer shown, and that it is kept 10 minutes, then asked again
  by itself.
- **Check again:** asks GitHub now. Every dashboard instance then reads GitHub again at its next view (the time of
  the check is shared: `state/releasesCheckedAt`), and so does the hourly look for a manual install.
- **Limited, so it can't be hammered:** once a minute for the whole dashboard (every admin, every instance), and
  10 times an hour per admin. A press too soon is refused, saying when it can be pressed again (GitHub isn't
  asked); the button counts down meanwhile. The time is kept before GitHub is asked, so a failing GitHub isn't
  asked faster.
- Nothing new for install.sh: installs from Settings → Update on a 0.5.37 installation.
- Tests: `test/update.test.js`.

## 0.5.37: Spamhaus and abuse.ch, two optional services (off by default)

**Needs `bash deploy/upgrade.sh` from Cloud Shell** (installLevel 5: two new secrets); Settings → Update says
so instead of offering the button.

- **Settings → Spamhaus (new; off by default):** Spamhaus's free Data Query Service, with the district's own
  DQS key. For each email, the sender's domain and up to 5 link sites (full host names; never your own
  domains or the big brands') are looked up in the **Domain Blocklist** (DBL) and **Zero Reputation Domains**
  (ZRD) by DNS, `<name>.<key>.dbl.dq.spamhaus.net` and `…zrd…`:
  - a link site the DBL lists for phishing, malware or botnet control is dangerous; the sender's domain
    listed so is strong evidence (5);
  - low reputation (spam): a sign of 2; a legitimate site Spamhaus says is abused for phishing or malware: 3
    (Spamhaus's advice: codes from 100 only score, never block);
  - a sender domain first seen in the last 24 hours (ZRD): 3; a link site: 2.
  - **Fair use:** the free service is for non-commercial small organizations, at most 100,000 lookups a day.
    The service stops for the day at `SPAMHAUS_DAILY_MAX` (90,000 by default; each name costs 2 lookups),
    counted for every instance together, and asks each name at most once an hour. Spamhaus allows DQS through
    shared resolvers (Cloud Run uses Google's) but recommends a dedicated one; a lookup that fails is "not
    checked". The key is tested with Spamhaus's test entry (`dbltest.com`) before it is saved. Spamhaus
    refusing it is an alert (`spamhaus-key`). The district should confirm with Spamhaus that it qualifies.
- **Settings → abuse.ch (new; off by default):** with the district's free abuse.ch Auth-Key, three more lists,
  downloaded once a day and matched like the phishing lists (and looked for in delivered mail, 0.5.35):
  **URLhaus** (links spreading malware: its export of the last 30 days, `recent.csv`) and **ThreatFox** (malware
  domains and links of the last 7 days, through its API). abuse.ch puts the key in URLhaus's export address: that
  address is made only for the download and never logged or stored (an error says only the HTTP status). A
  refused key is a list that missed its download. Settings → About lists them ("Off" until turned on).
- **Their keys** are kept like the Safe Browsing key: tested first, then in Secret Manager only
  (`spruce-spamhaus-key`, `spruce-abusech-key`, made by install.sh, empty until an admin saves one), never in
  Firestore, the logs or the dashboard's answers; saving, removing, turning on and off need the project ID and
  are noted in Activity.
- **No AI training on their data:** abuse.ch's and Spamhaus's terms don't allow it, so the retraining export
  leaves out a link's finding from them.
- The lists' shared copies: a list may now carry its own minimum size (ThreatFox's weekly lists can be small).
- Tests: `test/optional-services.test.js`.

## 0.5.36: The look-alike watch

Payroll and vendor fraud often starts with a domain made to pass for the district's own. Now the service looks
for them (`src/lookalike.js`):

- **Which names:** from `ORG_DOMAINS`, a fixed list: the domain's name with a letter left out, doubled or
  swapped, or replaced by a look-alike (0/o, 1/l, rn/m, vv/w…), a hyphen taken out, under the usual endings
  (.com, .org, .net, .us, .info, .co and your own), the forms people expect of a district (`name-k12.org`,
  `namek12fl.com`, `nameschools.com`, `name-county.org`…), and the name with a role added (`name-payroll.com`,
  `namehr.org`). Nothing under k12.st.us (only the state registers there). About 300 to 450 names a domain.
- **How:** each hour the next 80 are asked of Cloudflare's public DNS resolver (`cloudflare-dns.com`): does
  the name exist (NS), does it have mail servers (MX, a null MX doesn't count) and a website (A). A pass a
  day. A found one's registry date (RDAP) says how new it is. Only the candidate names are sent, nothing
  about any email.
- **The first pass takes stock:** what exists already is listed ("there before the watch"), no alert. A name
  that appears afterwards, or one there before but registered in the last 30 days, is **new**: an alert
  (`lookalike`), a red banner on Overview, and a strong sign in mail.
- **In mail:** from a new look-alike (or one marked a threat): the sender's domain 5, the reply address 5, a
  link 4, and the sender or reply address is strong evidence (the brakes never hold it). From one there before
  the watch: 3, 3, 2.
- **Status → Look-alikes (new):** the watch's progress, each domain found (when, registered, mail servers,
  website, how it counts), and an admin's mark, with the project ID: **It's ours** (a defensive
  registration: no sign), **Harmless** (someone else's, unrelated: no sign), **A threat** (strong), **Watch
  as found**. Marks are noted in Activity. A domain that lapses is shown as gone; registered again, it is new.
- **`LOOKALIKE_WATCH`** (on by default) turns it off. Nothing new for install.sh.
- The demo lists four made-up look-alikes, one new.
- Tests: `test/lookalike.test.js`.

## 0.5.35: Delivered mail is checked again when a list learns of it; Email → Re-checked; optional link clicks

Phishing sites are often put on a list hours after their email arrived. Now delivered mail is checked again:

- **When a phishing list adds a site or sender** (its daily download: what is new since the previous copy),
  every email of the last 7 days (`RECHECK_DAYS`, 1 to 30) that has it, in every mailbox, is read again from
  Gmail and checked in full: the same rules, AI, lists and brakes as on arrival. The policy then acts as on
  arrival: moved to Spam (enforce mode), recorded as "would move" (monitor mode), held by a brake, or
  recorded as suspicious. To find them, each email left in the Inbox keeps with its "checked" marker
  (`seen`) up to 24 short one-way hashes of its link sites (each host and the domains above it; the exact
  address for a page on shared hosting), its sender's address and when it arrived (`src/recheck.js`). No
  extra write: they go with the marker's own. They can't be read back, are never shown, and only find
  candidates: the full check decides.
- **Suspicious mail gets a second look** an hour after it arrived and again a day after: a site too new for
  the lists or Safe Browsing often is on them by then.
- **Never moved by a re-check:** an email its reader already archived, deleted or put in Spam (recorded:
  "it had already left the Inbox"), one an admin released, marked or holds in a paused campaign, one its
  reader moved into the Inbox themselves.
- **Who opened it:** Gmail's unread mark when it was re-checked.
- **Email → Re-checked (new):** one card per email (every copy, re-checked or moved on arrival): why it was
  re-checked, first delivered and re-checked when, and for each person who got it: delivered, opened, link
  clicked, what was done (moved to Spam and when, would move, had left the Inbox). **Mark all as seen.**
- **Alerts:** a red banner on Overview and Messages until an admin marks them seen; in Messages, a red mark
  and "found later" on each such email; on the email's page, what was found and when. Emailed alerts
  `recheck` (phishing found after delivery, one per hourly run) and `recheck-click` (a link clicked), and
  `click-logs` (Gmail's logs couldn't be read), in docs/ALERTS.md.
- **Settings → Link clicks (new; optional, off by default):** with the scope
  `https://www.googleapis.com/auth/admin.reports.audit.readonly` added to the domain-wide delegation and an
  admin with the Reports privilege, the service reads Gmail's log events (Admin SDK Reports API) of each
  re-checked email's recipient: first opened (event type 7) and a link clicked (15, 16), matched to the email
  by its Message-ID wherever the event carries it. Looked at right after the re-check and every 3 hours, 4
  times (Google's logs can lag). **Test** reads the admin's own last day and says whether its events name
  their emails. Turning it on or off needs the project ID and is noted in Activity.
- **Settings → Policy → Re-check delivered mail** (on by default, `RECHECK`): turned off, no hashes are kept.
- The phishing lists' shared copy: an instance loading a newer copy no longer answers from the older one
  meanwhile (every check waits for the new copy).
- Nothing new for install.sh: re-checking runs in the hourly job, within its time (the rest at the next
  run); Link clicks needs only the Admin console steps above (docs/INSTALL.md, "Link clicks").
- The demo has a made-up re-checked campaign (one person clicked; one had archived it).
- Tests: `test/recheck.test.js`.

## 0.5.34: Attachments and QR codes are read

Before, the service saw only attachments' names and types. Now `src/engine/attachments.js` reads them, in
memory, while the email is checked (nothing is stored; the record keeps what was found):

- **QR codes** ("quishing": a QR code hides its link from the reader and from link checks) in pictures (PNG,
  JPEG; attached or inside the email), in PDFs (pictures on the first 5 pages, JPEG ones from scanners too)
  and in Word, Excel and PowerPoint files. Each code's link is checked like any link in the email (security
  services, phishing lists, site age…). A QR code from outside is also a small sign (1).
- **Links** in PDFs (link annotations and written-out addresses) and Office files (hyperlinks), checked the
  same way.
- **Web pages sent as files:** one asking for a password (5), one that builds itself from hidden data or
  sends the reader elsewhere ("HTML smuggling", a meta refresh: 4), any other from outside (1). Their forms'
  and links' sites are checked.
- **SVG pictures** with a script, a form or event handlers (4).
- **The file itself:** a double extension ("Invoice.pdf.html", 3); a program, script, shortcut or disk image
  (.exe, .js, .lnk, .iso, .hta…: 3); an archive needing a password (2) or holding a program or page (3); a PDF
  needing a password (2) or running a script (2); a document with macros (2).
- **Limits:** 12 files per email, 15 MB per file, 5 PDF pages and 12 pictures per page, 24-megapixel
  pictures, 400 entries and 40 MB unpacked for an Office file, 10 seconds per email, and at most two files
  decoded at a time per instance. What is over a limit is skipped (not checked), never "safe".
- **The dashboard:** an email's Details lists what was found in its attachments ("Found in them"); a flagged
  link says where it came from ("A QR code in Payroll.pdf (page 1): …").
- **Libraries** (open source, from npm, pinned in package-lock.json): jsQR (QR codes), pngjs and jpeg-js
  (pictures), pdf.js (`pdfjs-dist`, PDFs), fflate (Office files). The image grows by about 40 MB.
- **The demo** has a made-up campaign with a QR code attached.
- Tests: `test/attachments.test.js` (every file made up in the test: `qrcode` and `pdf-lib`, test-only).

## 0.5.33: Fake reply chains count; an optional Suspicious label; Workspace settings to pair with the service

- **Fake reply chains** (a new sign, 2 points): an email whose subject says it is a reply ("RE:", and "AW:",
  "SV:", "Antw:", "RIF:", "RES:"…, also after an "[EXTERNAL]" tag), from outside the organization or from a
  sender never seen before, that answers nothing this mailbox has. Either it names no earlier email at all
  (no In-Reply-To or References), or it names one but its Gmail conversation holds only this email. A common
  invoice and payroll trick. It counts toward the rules' score: with a new outside sender it is amber; with
  payment or "confirm today" wording it reaches the move rules. The conversation is looked up only for a
  "RE:" that names an earlier email (Gmail's thread: the number of emails in it, nothing else). Not for a
  platform's notification (a share is never a reply). `src/engine/replychain.js`.
- **The Suspicious label** (Settings → Policy, **off by default**): when turned on, an email that is suspicious
  but not moved gets the Gmail label `SPRUCE/Suspicious` (`SUSPICIOUS_LABEL_NAME`), so its reader sees it, in
  monitor mode too. Nothing is moved by it. Marking the email a false alarm takes the label off; turning the
  setting off labels no more (the ones labeled keep it). A policy setting: the project ID to change it, noted in
  Activity.
- **docs/WORKSPACE.md (new):** Google Workspace settings that work alongside the service. An outbound
  recipient limit with an admin quarantine and a bypass address list catches a staff account taken over and
  sending phishing to many outside people (internal mail is left alone: all-staff, school and grade lists
  reach hundreds or thousands); Gmail's own Safety settings; DMARC for your own domain.
- Not added, on purpose: a fixed list of payroll or bank-change phrases (too many false alarms with static
  words); the AI model judges those in context, and more training will let rules and AI together decide.
- Tests: `test/replychain.test.js`.

## 0.5.32: Clearer gap alerts, and docs/ALERTS.md explains every alert

- **"Changes were missed" is now "The service fell behind".** "Missed" read as "emails missed". Each gap
  alert, and the note in Activity, now says in turn what happened (Gmail's list of what changed in a mailbox
  ran out before the service read it), what it means for mail (it reached the Inbox before it was checked;
  what is still in the Inbox is checked now; what was deleted or moved out meanwhile isn't), why it can
  happen, and numbered steps for what to do.
- **docs/ALERTS.md (new):** every alert the admins can receive, grouped by what it is about, each with
  when, what it means for mail, and what to do. Linked from the README, docs/INSTALL.md (Troubleshooting)
  and the alert email itself (the alert policy's text, updated by the next `install.sh`).
- "Gmail refused the service" names the Admin console's path exactly as docs/INSTALL.md does.

## 0.5.31: Missed changes, again and again, are an alert

A mailbox's changes are "missed" when Gmail's history for it has run out (it keeps about a week) before the
service read it; the service then catches up on its Inbox by itself, and Activity notes it. One now and then is
normal (after an outage, say). Many are a sign of a bug, something to optimize, or a problem with the cloud
service, so they are now an alert (emailed, once a day):

- **Across the organization:** 10 or more within 24 hours (`GAPS_ALERT_DAY`). Gmail's notifications weren't
  processed for days: the worker down or failing, Pub/Sub backing up, or a bug.
- **One mailbox:** 3 or more within 7 days (`GAPS_ALERT_MAILBOX`), each mailbox on its own. Probably its
  watch, or a bug.

Both limits are settings (`deploy/settings.env`, 1 to 1,000; empty = the defaults). Catching up isn't counted;
gaps noted before 0.5.31 count by their text. Tests: `test/audit.test.js`, `test/brakes.test.js`.

## 0.5.30: Every wrong project ID or email address is noted in Activity

- Each wrong Google Cloud project ID (Settings → Policy, Allowlist, Safe Browsing, Update) or wrong email
  address (Settings → Update) is noted in Status → Activity → **What admins did**: who, what they were
  changing, and which try it was ("try 2 of 5 within 10 minutes"). Never what was typed: someone could paste
  something private into the box by mistake. Not emailed.
- The fifth within 10 minutes still locks changes from that account, and that is an alert (emailed, 0.5.29).
  A try while locked is noted once per lock, so repeated tries can't flood Activity.
- Tests: `test/audit.test.js`.

## 0.5.29: What was missed: more alerts, a longer and searchable Activity, and two optional extras

**New alerts** (emailed, at most once a day while it lasts):
- **Gmail refusing the service:** domain-wide delegation removed or its scopes changed, a token refused,
  401/403 (not a rate limit). Every email then goes unchecked while Gmail's notifications keep coming, so
  the "quiet" alert never fired. Caught both while reading an email and before (the Pub/Sub route).
- **An email left unchecked** after three tries.
- **25 errors in an hour** (the hourly health check).
- **An admin's account locked** after five wrong project IDs or email addresses: it may not have been them.

**Recorded** in Activity → What admins did (not emailed): downloading the email list as CSV (Email →
Messages), downloading Activity, and opening the dashboard (once a day per admin).

**Activity for audits:**
- Kept `AUDIT_DAYS` (365 by default, 30 to 1,825), no longer `RETENTION_DAYS` like the email records. It holds
  no email text. Entries written before 0.5.29 keep their old date.
- Status → Activity: its own period (up to all that is kept), words to look for (an admin, a mailbox, a word),
  and **Download CSV** (when in UTC, kind, alert, admin action, mailbox, text), which is noted.

**Optional, off by default, because Google Cloud charges for them** (set in `deploy/settings.env`, then
`upgrade.sh` or `install.sh`; the installer says what each costs):
- `PUBSUB_BACKLOG_ALERT=on`: an email when Gmail's notifications have waited in Pub/Sub over 30 minutes (a
  metric alert policy: about $0.40 a month at Google's published price). Turned off again, the policy is
  removed.
- `AUDIT_LOG=on` (`AUDIT_LOG_DAYS`, 365 by default): each Activity entry also as a log line (`spruceAudit`),
  routed to the log bucket `spruce-audit` kept that long, where a Firestore wipe can't reach it (logs kept
  past 30 days: $0.01 per GiB a month, a few cents a year here). Turned off, the sink is removed; the bucket
  keeps what it has until its retention ends.

**Costs, corrected:** Google now charges for alert policies ($0.35 a month each at its published price), so
the two `install.sh` has always made (an alert from the service, a failed scheduled job) cost about $0.70 a
month; `ALERT_EMAIL=off` makes none. docs/INSTALL.md (Costs), settings.example.env and the installer say so.

The installation level stays 4: nothing new is needed unless an option is turned on, and turning one on is
done with `install.sh` anyway. Tests: `test/audit.test.js`, `test/install.test.js`, `test/pipeline.test.js`.

## 0.5.28: Alerts are the problems the admins are emailed about; an admin's own changes are what admins did

- **What an alert is.** An alert is a problem the admins are emailed about (to `ALERT_EMAIL`), such as a
  list that missed its download or a service that stopped working. Status → Activity → **Alerts** lists those
  only, each marked "alert, emailed to the admins".
- **An admin's own change is not an alert.** A policy change (and the allowlist), an update started from
  Settings → Update, and a Safe Browsing key saved or removed are noted in Activity → **What admins did**,
  and no longer emailed. Older records of them move there too.
- **Problems that weren't emailed now are:**
  - **Cloudflare Security or Safe Browsing down:** every lookup failing for 30 minutes (`OUTAGE_MS`; our
    own request limits don't count);
  - **Google refusing the Safe Browsing key** (revoked, restricted, quota): at once;
  - **the AI model not working in the worker** (not loaded, or its self-check failing) when an instance
    starts;
  - **an update from the dashboard that failed** (the build records it in Activity but can't send email: the
    hourly job emails it), **or never finished** (45 minutes).

  A problem that lasts is emailed at most once a day (`alertDaily`).
- **Unchanged:** an automatic alert of an admin-related kind (a large campaign, a failed update) is an alert,
  not something an admin did.
- docs/ARCHITECTURE.md lists every alert.
- Tests: `test/activity.test.js`.

## 0.5.27: The dashboard's days are the organization's, not UTC's

- **The fix.** Every day the dashboard counts was a UTC day: the chart's columns, its tooltip ("Emails
  checked"), the daily counters the worker writes, the weekly summary's week. In New York, mail from 7 PM
  (8 PM in summer) to midnight counted on the next day, and from 7 PM "today" was already tomorrow. Days
  now follow the time zone in Settings → Policy (`TIME_ZONE`; UTC when not set): an email at 10:13 PM on
  Thursday 12 November counts on the 12th.
- `aggregate.js`: `dayIn` (a day in a time zone), `addDays` (calendar arithmetic, the same in any time zone
  and across clock changes), `setTimeZone` (the server sets it at each request); the worker's
  `Service.dayOf`; the server's daily counters read day by day with `addDays` (not 24-hour steps).
- **The day of the upgrade:** the counters already written stay on the UTC day they were counted on, so
  that day, and the next, can show a few hours too many or too few in "Emails checked" (the moved,
  would-move and suspicious columns come from each email's own time, so they are right at once). From the
  next day on, every count is the organization's.
- Settings → Policy says what the time zone is used for.
- Tests: `test/timezone.test.js`.

## 0.5.26: The image builds with Cloud Build again (tools/fetch-model.js was left out)

- **The fix.** When Docker can't upload the image from Cloud Shell, `install.sh` (and so `upgrade.sh` and
  `update.sh`) builds it with Cloud Build instead. Cloud Build gets what `.gcloudignore` lets through, which
  left out all of `tools/`, so since 0.5.8 that build stopped at `COPY tools/fetch-model.js` ("file not found
  in build context"). `.gcloudignore` now lets that one file through (`tools/*` with an exception: a file in
  an ignored folder can't be let back in), as `.dockerignore` already did. Checked with
  `gcloud meta list-files-for-upload`. Builds with Docker, and Settings → Update (which builds from the
  repository), weren't affected.
- **If an upgrade stopped there:** nothing was deployed (the build is step 6 of 9; the services run the
  version they ran before). Upgrade again with this version: unzip it, then `bash deploy/upgrade.sh` from its
  folder.
- Tests: `test/model-source.test.js` checks that every file the Dockerfile copies is uploaded to Cloud Build.

## 0.5.25: The right script for an existing installation

No change in how mail is judged. Where the dashboard told an existing installation to run `install.sh`, it
now says to upgrade: `bash deploy/update.sh` (an approved version), or `bash deploy/upgrade.sh` from an
unzipped copy. Both run `install.sh` themselves, after copying the settings and showing what changes;
`install.sh` alone is for a first install or for settings changed in the same folder. On Settings → Safe
Browsing (a key that can't be saved yet), and where a change needs the project ID and the dashboard
doesn't know it. The 0.5.23 entry and docs/INSTALL.md say the same.

## 0.5.24: Settings → Update says when a version needs a manual install, and keeps the button off until then

- **"Manual install required"** on Settings → Update, when the newest approved version changes the
  installation itself (a higher `installLevel`: new permissions, jobs or settings, as 0.5.23's Secret
  Manager for the Safe Browsing key). It says which version, which installation level it needs and which
  this one is at, that **no update is installed from the page until then, neither that version nor any
  later one** (a level is never lowered), and the steps: Cloud Shell, the folder you installed from,
  `bash deploy/update.sh` (with a Copy button). Since when it has waited, too.
- **The update form stays on the page, switched off** (its fields and the button disabled, "manual
  install required"); the server refuses the update as well ("Manual install required."), and the update
  build still checks it.
- **Detection:** the installation's level is now read where the build reads it, the `spruce-install-level`
  label `install.sh` puts on the services (Cloud Run; never below the running version's own, which is used
  when Cloud Run can't be read, as before). So a rolled-back build no longer blocks an update its
  installation allows. Shown as **Installation level** on the page.
- **In the background:** the hourly job (the worker) looks at the newest approved version too, so the
  admins are alerted (`update-manual`, emailed to `ALERT_EMAIL`) once per version that needs a manual
  install, without anyone opening the page. `state/manualInstall` keeps which version and since when; it is
  cleared once the manual install raised the installation's level, and the page installs updates again by
  itself.
- Demo mode: **Settings → Update** has a link to a made-up version that needs a manual install.
- Tests: `test/update.test.js`.

## 0.5.23: Google Safe Browsing from the dashboard: the API key and on/off on Settings → Safe Browsing

**Needs an upgrade from Cloud Shell** (`installLevel` 4): `bash deploy/update.sh` once it is approved, or
`bash deploy/upgrade.sh` from an unzipped copy. The upgrade runs `install.sh`, which sets up Secret Manager for
the key. Settings → Update doesn't offer this version.

- **Settings → Safe Browsing** (new page). Safe Browsing stays **optional and off by default**; the page says
  the service works fully without it, and what it adds: Google's own list of phishing, malware and
  unwanted-software pages (the one Chrome and Gmail use), single pages on otherwise good sites (a hacked
  school site, a free page builder), malware downloads, and a second opinion. And what it doesn't change:
  phishing through real Google Docs, Drive, Classroom or DocuSign links.
- **The API key**, pasted by an admin with the project ID:
  - tried with Google first (a lookup of Google's own test address, nothing from anyone's mail); a key
    that doesn't work is refused with what to fix (not a valid key, the Safe Browsing API not enabled, the
    key's API or application restrictions, quota);
  - kept in **Secret Manager only** (`spruce-safe-browsing-key`, `src/secrets.js`): never in Firestore,
    `settings.env`, the logs, or any answer of the dashboard. Firestore keeps only that a key is saved, who
    saved it and when (`state/safeBrowsingKey`). Saving a new key destroys the old versions; **Remove the
    key** destroys them all and turns Safe Browsing off;
  - every instance notices a new or removed key within 30 seconds (`src/intel/sbkey.js`).
- **On and off** (the `safeBrowsing` policy setting, with the project ID, like the others): within 30
  seconds everywhere, noted in Activity and emailed as an alert. It can't be turned on without a key that
  can be used. `install.sh` doesn't set it, so the dashboard's choice stays across installs.
- **The key goes in a header** (`x-goog-api-key`), no longer in the lookup's address, which can end up in
  logs.
- **Whether lookups work** is noted (`state/safeBrowsingHealth`, when it changes and hourly): Google
  refusing the key (revoked, restricted, quota) shows on Settings → Safe Browsing (a red alert) and in
  Status → Service status.
- **install.sh** enables the Secret Manager and Safe Browsing APIs, makes the empty secret, and lets
  `spruce-run` read it, add a version and destroy old ones, on that secret only; both services get
  `SAFE_BROWSING_SECRET`. Without it (an older install), `SAFE_BROWSING=true` with `SAFE_BROWSING_KEY` still
  works as before.
- Secret Manager stays within its free tier (one secret version; the key is read once per instance and
  again only when it changes).
- Tests: `test/safebrowsing.test.js`; `test/intel.test.js`.

## 0.5.22: A phishing list that misses its download is shown, alerted and re-checked

- **Each list's last download is kept** (`state/feedHealth`: when, the error, since when it fails and how
  often; `src/intel/feeds.js`). A list "missed its download" when its last download failed, or when its
  copy is over two days old (the daily download isn't happening). The previous copy is still used, as before.
- **Tried again every 3 hours:** the hourly job downloads a list that missed its download again (only that
  one) 3 hours after the failed attempt, instead of the next day.
- **Overview:** a red banner names the lists that missed their download, with a link to Settings → About.
- **Settings → About:** the lists now have their own card. A list that missed its download is highlighted,
  with a red alert icon, what went wrong, since when, how many tries, and which copy is in use. A new
  **Last download** column says when each list was last downloaded and whether it worked. **Re-check the
  lists now** downloads again every list that missed its download or isn't up to date; one downloaded
  within the day is left as it is (at most once a minute; noted in Activity).
- **The admins are alerted** (`list-download`: Recent activity, and emailed to `ALERT_EMAIL`, the admin
  group by default, like the other alerts): when a list newly misses its download, and once a day while
  one keeps failing. A list that downloads again is noted in Activity.
- **Status → Service status** names the lists that missed their download.
- **An email's AMP version isn't an attachment.** Google's share and comment notifications carry
  `text/x-amp-html` beside the HTML version; the email's Details listed it under Attachments. (It never
  counted in the checks.) The share in the report that prompted it (a colleague's Drive share, "the sender
  uses the name of someone in your organization", rules score 4 on 0.5.14) has been judged by the
  sharer's own Reply-To address since 0.5.16; a test with Google's text, AMP and HTML versions now covers it.
- Tests: `test/lists.test.js`; `test/notifications.test.js`.

## 0.5.21: Two more phishing lists, updated once a day: HaGeZi and TweetFeed

- **HaGeZi Threat Intelligence Feeds** (medium version: about 366,000 phishing, malware and scam domains
  gathered from many feeds; GPL-3.0). Downloaded once a day with the others, kept as the others are; a
  link or sender domain on it counts as on the other lists (a listed link is dangerous). The full version
  (1.4 million domains) is too large to keep in each instance's memory.
- **TweetFeed** (domains security researchers reported on X in the last 30 days, about 2,500; CC0 1.0;
  its CSV on GitHub, the domain rows read by `feeds.js`). Its authors warn that community reports aren't always right, so it is a
  report, not a list (`confidence: 'report'`): a reported link is amber and a sign of 2 (`reported-link`),
  a reported sender domain a sign of 2 (`sender-domain-reported`), never "dangerous" on its own. A domain
  on both a list and TweetFeed counts as listed.
- **OpenPhish** moved its community feed to GitHub; its old address redirected there. The new address
  is used directly.
- Every list is cleaned as before: never a protected brand's domain, a cloud-storage host or a whole
  personal-mail domain (checked on the real lists: no whole hosting platform either).
- Not added: **URLhaus** (abuse.ch). Since October 2026 its downloads need an abuse.ch key (free for
  non-commercial use); keyless downloads answer "410 Gone".
- Tests: `test/intel.test.js` (made-up list contents).


## 0.5.20: The extension's own code removed from the engine

No change in how mail is judged (every test, and the AI model's reference answers, the same).

- `vendor/spruce/` began as a copy of the browser extension's files and still carried what only the
  extension uses: its settings and their backups, storage, webmail page layouts (`WEBMAIL_SITES`), sender
  pictures and their colors, conflicts with other extensions, phishing-simulation rules, outgoing-mail
  checks, attachment readers, country flags, its own network calls, and the code that edits its own pages.
  Everything the service can't reach is removed: 153 top-level declarations, about 1,900 lines
  (`shared.js` 3,092 → about 1,330 lines; `decoders.js` 665 → 607). Found with a parser from what
  `src/engine/spruce.js` takes, not by hand.
- The extension's release switches for its 5.90 company matching (`COMPANY_MATCHING`) are folded in:
  always on here, as they were.
- `src/engine/spruce.js` runs the engine with the language's own objects only (no stand-in "chrome" or
  "fetch"), and Gmail's receiving server (`mx.google.com`) is a constant instead of a look-up in the
  webmail layouts.


## 0.5.19: The sending mail service known from the email's signature, not a list

- 0.5.18's hand-kept list of marketing mail services is gone. The service that sent a newsletter is
  known from the email itself: the third party whose DKIM signature Gmail verified (the receiver's own
  Authentication-Results, `dkim=pass header.i=@mail.beehiiv.com`; `mime.receiverAuth` now keeps those
  domains, `dkimDomains`), never the sender's own domain. A link whose text shows a well-known site but
  goes through that service's domain gets the same reputation check as in 0.5.18 (Cloudflare and the
  phishing lists clean, Safe Browsing too when on, registered 180 days ago or more): a warning, 1 point.
  It covers every such service, including ones nobody listed; a link to one in an email it didn't send,
  or a scammer's own domain signing its own email, stays dangerous.
- The URI blocklists (SURBL, URIBL, Spam Eating Monkey) were looked at for the reputation: they refuse or
  fail queries from shared resolvers such as Google's, where the service runs (URIBL answers "refused" to
  its own test entry through Google's DNS), and they only say a domain is bad, not which service sent an
  email.
- Tests: `test/mailers.test.js`, `test/engine.test.js` (made-up mail).


## 0.5.18: A reputation check before a newsletter's link is called dangerous

- **A newsletter sent through beehiiv was moved to Spam**: its "Listen on open.spotify.com" link goes
  through beehiiv's click tracker (link.mail.beehiiv.com/v2/c/…), so "link text shows a well-known
  brand but goes elsewhere" made it dangerous (5, with "from outside" 6: moved).
- **Now such a link gets a reputation check first** (`src/engine/network.js`): when it goes through a
  known marketing mail service's click tracker (`src/engine/mailers.js`: beehiiv, Substack, MailerLite,
  HubSpot, Mailjet, Campaign Monitor, GetResponse, EmailOctopus, Customer.io, Emma, Benchmark, Zoho
  Campaigns; the engine's built-in trackers such as Mailchimp and SendGrid were never counted as
  mismatched), and Cloudflare and the phishing lists checked the service's domain and found nothing (nor
  Safe Browsing, when on), and its registry date is at least 180 days old (looked up first among the link
  domains), the link becomes a warning: amber, saying which service and what the lookups found, and 1
  point for the email (`mailer-link`). The email isn't moved for it alone; other signs still add up.
- Blocked, on a phishing list, registered recently, not checked (a lookup that didn't answer, or no
  lookups), or not a known mail service: dangerous, as before.
- Tests: `test/mailers.test.js` (made-up mail and lookups).


## 0.5.17: Google Classroom from personal accounts is flagged

- **A Google Classroom email (invitation, post, notification) from a personal account** (gmail.com,
  outlook.com, yahoo.com… `isPersonalMailDomain`): 5, flagged (moved in enforce mode), whatever the name.
  A school's classes come from its own domain; classes run from personal accounts are the known way to send
  scams through Classroom's own, genuine address (2025: 115,000 invitations to 13,500 organizations).
- The account is the one the email shows: the Reply-To, the "Name (address)" next to the person's name,
  or, for a **class invitation** (its subject, or the X-Notifications type), a personal address anywhere in
  its text. Classroom doesn't always show it (a post from a colleague doesn't): such an email stays
  unknown, judged by its links and the AI, as before.
- Not flagged: another school's class (a Workspace domain), an address quoted in a post's text that isn't
  the poster's, a colleague's own Classroom posts.
- Tests: `test/notifications.test.js` (made-up mail only).


## 0.5.16: Shares and notifications judged by the person behind them; compromised-district campaigns

- **Fixed: a colleague's own Classroom post, Drive share or DocuSign envelope was "suspicious".** A
  platform sends these from its own address: "Jordan Placeholder (Classroom)" <no-reply@classroom.google.com>,
  "Dana Madeup (via Google Docs)" <drive-shares-dm-noreply@google.com>. The colleague-name check (0.5.10)
  took that for a colleague's name on an outside address (3) and added "from outside" (1): 4, suspicious;
  with "first email from" Google's address, 5.5 and moved. Every Classroom notification from a teacher or
  student in the directory went to Review.
- **Platform notifications are judged by the person's own address** (`src/engine/notifications.js`):
  Google (Classroom, Drive, Docs, Sheets, Slides, Forms, Calendar), DocuSign, Dropbox, Adobe Acrobat Sign,
  SharePoint. Only when Gmail's sender check (DMARC) passed for the platform's own domain and the sender
  is one of its notification mailboxes; a forged one is judged like any email. The person's address: the
  Reply-To the platform sets from their account, or the "Name (address)" it writes in the text; neither
  (Classroom): unknown, and nothing comes of the name. "Outside" and "first email" go by that address. The
  routing rule's `[EXTERNAL]` tag, `header.i` and `dara=` can't tell: they are the platform's (or the
  recipient's) for every share.
- **Outside shares** (a notification for a person outside, or an outside email linking a document, form,
  folder or signature request):
  - an account under a colleague's name: at another organization 5 (flagged), at a personal provider 3;
  - a colleague named in the subject or text ("… asked me to share", a signature): 2; not a greeting, the
    reader's own name (the directory's primary addresses, read with the names, say whose), the sender's
    own name, or a quotation of the colleague's own email ("Dana Madeup <dana@your-district> wrote:");
  - asking to sign in, verify an account or confirm details to see it: 1;
  - the same outside account reaching 10 of your people within the hour: 2, and an alert once per account
    and hour (`store.shareReach`: in `moveCounts`, as hashes, deleted after 2 days; no new install step).
  A notification's note, which Gmail can set apart as a quotation, is read by the text checks too.
- "Name via Docusign" (Dropbox, Adobe Sign…) matches the directory's name, as "(via Google Docs)" did.
- Tests: `test/notifications.test.js` (made-up mail only: a Classroom post and shares from inside, an
  account under a colleague's name, the compromised-district share, a partner's share, the exclusions, a
  forged notification, the mass share).
- `installLevel` is unchanged: no new permission or install step (the directory read adds each user's
  primary address to the same request).


## 0.5.15: Links on Settings → Update; Copy for Vault

- **Settings → Update links to the repositories.** Each AI model ("phish-tiny 0.13.0, from
  thecodewarrior2/TinyPhishLLM") opens the model's repository, and its commit opens that commit; "From"
  opens `google_service_main`, where the approved versions come from. In a new tab; only GitHub addresses
  of the expected shape are made links.
- **Copy for Vault** beside an email's Message-ID copies it as Google Vault's search writes it:
  `rfc822msgid:<Message-ID>` (no angle brackets), ready to paste into a Vault search.
- Dashboard only: nothing in how mail is judged changes.


## 0.5.14: The directory's names in Reply-To, Cc and To

- The colleague-name check (the directory's names, as one-way hashes) looked only at the sender's name.
  It now looks at the other address lines too (each person on a line on their own, as 0.5.13 reads them):
  - **Reply-To** under the name of someone in your organization going to an outside address: replies
    would go to someone else. 3 (amber); the sign says when the domain imitates yours.
  - **A colleague copied in** (Cc or To) at an outside address: 1, since staff are sometimes copied at a
    personal address. At an address that imitates your organization's domain (its name under another
    ending, a hyphen more or less, one letter away, look-alike characters, or something added:
    `maple-schools-k12.example`), the "I've copied our superintendent" trick: 3.
  - Never for your own domains' addresses, nor for the sender's own address (the From check covers it).
  The names are hashed the same way as the directory's; nothing more is read or kept
  (`colleagueLineSigns`, `ownDomainLookalike` in `vendor/spruce/shared.js`; `addressLinePeople` in
  `src/engine/analyze.js`).
- Tests: `test/explain.test.js` (made-up mail only).
- `installLevel` is unchanged: no new permission (the same directory names).


## 0.5.13: The To line with several people (the calendar invitation false alarm)

- **The cause of the reported false alarm.** A Google Calendar invitation was marked suspicious (the AI
  at 0%) because of the To-line check: 2 points, and with "from outside" (1), 3. Its To line lists two
  people, the guest bare and the organizer with a name (`guest@district.org, Organizer Name
  <organizer@vendor.example>`). The check read the line whole, so it took "guest@district.org,
  Organizer Name" for the organizer's name, a name showing another address: the disguised-To trick. The
  line is now read person by person (split at the commas outside quotes and `<…>`), and each is judged
  alone; the trick on any one of them is still found. 0.5.12's change to the check (quotes, +tags) didn't
  cover this: with it, the invitation still got its 2 points. The same invitation now scores 1 (from
  outside): not suspicious.
- Tests: `test/explain.test.js` (a made-up invitation with the same To line).


## 0.5.12: Suspicious says why; "…show more" in context; "AI alone moves inside mail" on the dashboard; a To-line false alarm

- **A suspicious email says what made it suspicious.** "Because suspicious, below the move rules" named
  no cause, so an email with an AI score of 0% looked like an AI mistake. The reason now names it: "the
  rule checks scored it 3 (suspicious from 3, moved from 5)", "the AI scored it 72% (suspicious from 65%,
  moved from 90%)", both, or "a link check found a suspicious link". Records from before 0.5.12 are shown
  the same way (from their own scores, with today's thresholds; the record itself is left as it was).
- **"…show more" no longer reads as if the AI flagged a genuine email.** Each part of an email is also
  scored on its own, out of context, and a part alone can read more like phishing than the whole email
  ("click here to accept" is in invitations too). When the whole email scores under 50%, nothing is marked
  as what weighed most and no part is shown in red; a note says the whole email's score is the AI's
  opinion. Fixed too: the marked sentences took the page header's layout (the class `top`), lost their
  numbers and looked like separate boxes.
- **"…show more" gives context.** Each sentence that weighed most (up to 3) is shown between the sentence
  before it and the one after it, and those are always real text: blank lines, invisible padding
  (mailing lists fill their preview text with zero-width characters), lone punctuation, dashes, bullets
  and a stray letter or number are skipped, and left out of the sentence-by-sentence list too (it says
  how many). The model still reads the email exactly as before; only what is shown changed
  (`src/engine/model.js` `reading()`: `filler`, `weighed` with `before` and `after`).
- **Settings → Policy → "AI alone moves inside mail"** (`AI_MOVES_INSIDE`): off by default. On, an email
  from inside the organization that the AI scores at the move threshold (90%) or more is moved on the AI
  score alone, as outside mail is (in monitor mode: recorded as "would move"). Turning it on needs the
  project ID and a ticked agreement (it moves colleagues' mail on the AI alone); it is noted in Activity
  and emailed as an alert. It needs the AI to read inside mail, so it turns that on too. The dashboard
  says which way it is set wherever it matters: the AI opinion's "Where it stands", How it decides, the
  AI move threshold and "AI on inside mail" rows, and an email's reason ("…, but the sender is inside the
  organization and "AI alone moves inside mail" is off" or "AI 95% ≥ 90% (the sender is inside the
  organization; "AI alone moves inside mail" is on)").
- **The "To" line check misfired on ordinary To lines.** It counted any name holding an address other
  than the real one, character for character, so Outlook's `'ann@x.org' <ann@x.org>`, a name with the
  address in it ("Ann (ann@x.org)"), a +tag, or "mailto:" counted as a disguised To line (2 points: with
  a new outside sender, enough for "suspicious"). Now the address in the name is read as written and
  compared as a mailbox. Another address of the same domain, or the same name in another domain (an
  alias, a group, a domain change), is a weak sign (1); another address in another domain is still a sign
  (2), and says both domains. (The extension has the same check; this is the service's own copy.)
- Tests: `test/explain.test.js` (made-up mail only).
- `installLevel` is unchanged: nothing new to install (the setting is on the dashboard).


## 0.5.11: The AI doesn't read mail from inside by default; signs for mail dressed up as inside

- **AI on inside mail: off by default.** Mail from inside the organization (from your domains, with
  Gmail's DMARC check passing) is no longer read by the AI model. The rule checks still read it as any
  email (its links, through the link checks and lookups; its headers; the rest) and can still move it, as
  for a staff account taken over that sends dangerous links. An email's page says why there is no AI
  score ("Not scored: the sender is inside your organization"). **Settings → Policy → "AI on inside
  mail"** turns it on (or `AI_SCANS_INSIDE=on`), noted in Activity; then the AI reads inside mail too and
  its score can make one suspicious, but its score alone still never moves it (`AI_MOVES_INSIDE` aside,
  which turns the reading on too).
- **Mail dressed up as inside is outside mail**, read by the AI as before, now with signs of its own:
  - its From address is in your domains, but Gmail's DMARC check **failed** for it: "It claims to come
    from inside your organization …, but Gmail's sender check (DMARC) failed" (2, on top of the DMARC
    failure's own sign: together they flag it). Without any DMARC result (a domain that publishes none)
    there is no such sign;
  - an outside sender whose name shows one of your addresses ("it-support@your-district.org"
    <notices@elsewhere.example>): 3 (amber).
- Tests: `test/inside-mail.test.js`; `test/pipeline.test.js` (staff mail with DMARC passing is no longer
  scored by the AI by default; with `AI_SCANS_INSIDE` on, it is, and still isn't moved by it).
- `installLevel` is unchanged: nothing new to install (the setting is on the dashboard).


## 0.5.10: Review decides a campaign at once; Next works; more of the AI's reasoning; colleague names; English only

- **Review: the copies of one email are one item.** A campaign (the same email to many people) used to be
  one review per recipient, every copy looking the same, so **Next, undecided** seemed to do nothing. Now
  its copies are decided together: the item says who received it (the first two, **…show more** for
  everyone in a popup) and, when the copies came from several addresses, who sent it; **False alarm
  (all 12)** and **Phishing (all 12)** mark every copy at once (in enforce mode, Phishing moves the ones
  still in the Inbox to Spam), with a link to every copy in Messages. `GET /api/review` gives `groups`
  (keys, recipients, senders) besides the flat `keys`.
- **Fixed: Next, undecided after "Look again".** "Look again" put `restart=1` in the address, and every
  later redraw (Next) loaded the queue again from its first email: the page flashed and stayed. The queue
  is loaded once and the address cleared. A popup open on the page now holds the F, P and N keys and the
  live refresh.
- **The AI opinion says more.** Where its score stands against the lines in force (moves an outside
  email from 90%, suspicious from 65%; an inside sender's score alone never moves it), what weighed most,
  what the model reads. **…show more** opens what the model reads of that email, sentence by sentence,
  each scored on its own (what weighed most marked), with the line about the sender and links: read from
  Gmail on demand (`POST /api/message/context`), as the model sees it (addresses reduced to their domain,
  phone numbers and long numbers replaced), nothing stored, and Activity notes who looked.
- **The colleague-name check.** The directory's full names (read by `DIRECTORY_ADMIN` every 12 hours,
  kept only as one-way hashes, in memory) against outside senders' display names: "Jordan Exampleton"
  <jordan.exampleton.office@gmail.com> gets a sign (3: amber; staff sometimes write from a personal
  address, so it moves mail only with other signs). It is the extension's own check, which the service
  had no names for. Optional: it needs the **Users → Read** privilege and the
  `admin.directory.user.readonly` scope (docs/INSTALL.md); without them it is off and **Status** says how
  to turn it on. `COLLEAGUE_NAMES=off` turns it off.
- **English only, said.** The model was trained on English mail, so on an email clearly in another
  language its score means little. `src/engine/language.js` (no library) tells: the writing system
  (Chinese, Japanese, Korean, Cyrillic, Arabic, Hebrew, Greek, Thai, Hindi and others), or for the Latin
  alphabet the commonest words of Spanish, Portuguese, French, German, Italian, Dutch, Vietnamese,
  Polish, Turkish, Indonesian, Tagalog, Haitian Creole and Somali. Then the model isn't run: the AI
  opinion says **"Not scored: the AI model reads English only"** and names the language; the rule
  checks run as for any email; the retraining export leaves it out (and counts it). A bilingual email
  with a real English part, and a very short one, are read as before.
- **Overview:** hovering a day of "Emails moved per day" also gives the emails checked that day, and how
  many were moved back.
- Demo mode: a made-up colleague-name campaign and one in Spanish. Tests: `test/review-ai-names.test.js`
  (languages, the colleague-name check and its hashes, review groups, the bulk decision, "…show more").
- `installLevel` is unchanged: the colleague-name check's permission is optional.


## 0.5.9: The name is now S.P.R.U.C.E Mail Protection Service

Nothing in how emails are judged changes: only the name.

- **S.P.R.U.C.E Mail Protection Service** everywhere the service names itself: the dashboard's header and
  browser tab, the weekly summary's subject, the sender name on the notices it puts in mailboxes ("From:"),
  the install, update, upgrade and check scripts, and the documentation.
- **In Google Cloud,** new installations name the service accounts, the budget, the alert channel and the
  alert policies "SPRUCE Mail Protection Service …". `deploy/install.sh` finds an existing budget or alert
  policy under its old name too and renames it, so none is made twice; `deploy/doctor.sh` counts the alert
  policies under either name. Service accounts and the alert channel keep the name they were made with.
- Unchanged, so installations keep working: the services' and jobs' identifiers (`spruce-worker`,
  `spruce-admin`, `spruce-…`), the image (`mail-protection`), the install zip's name, the GitHub
  repositories, and Gmail's labels.
- `installLevel` is unchanged: nothing new to install.


## 0.5.8: The AI model comes from TinyPhishLLM, downloaded when the service is built

Nothing in how emails are judged changes: the model is still phish-tiny 0.13.0, byte for byte. It now
comes from **TinyPhishLLM**, the model's own public repository, which the S.P.R.U.C.E+ extension uses
too: one model, trained in one place. Its training (scripts, examples, check sets) is in a separate
private repository, TinyPhishLLM_Private_Training; TinyPhishLLM holds only the model and made-up
references.

- **The model's files are no longer in this repository.** `vendor/spruce/VENDOR.json` (`modelSource`)
  pins one TinyPhishLLM commit and each file's SHA-256, and **`tools/fetch-model.js`** downloads the files
  at that commit and stops if any differs. The Dockerfile runs it, so every build of the image takes the
  model from TinyPhishLLM: `deploy/install.sh`, `deploy/update.sh`, `deploy/upgrade.sh` (from a zip too)
  and **Settings → Update** (Cloud Build). `npm test` and `npm run demo` run it first;
  `--from <TinyPhishLLM folder>` works offline. Nothing is downloaded while the service runs, and the
  request carries no token and nothing about the installation.
- **Settings → Update** shows the AI model of the version installed and of the newest approved one, and
  where each comes from (TinyPhishLLM and the commit). `update.sh` and `upgrade.sh` say it too; the
  update's line in Activity names the model and its commit.
- **`tools/sync-model.js <TinyPhishLLM folder>`** pins a model: after TinyPhishLLM's own check
  (`tools/check.js`), a check that the commit is on TinyPhishLLM's main branch on GitHub, and a check that
  `vendor/spruce/ai.js` builds the model's input exactly as it was trained, it records the commit and
  hashes and copies the two references the tests use (`test/fixtures/model-reference.json`,
  `test/fixtures/model-input-format.jsonl`). Pinned to TinyPhishLLM `68f8dd6`. `model.bin` is no longer
  part of the service (only ONNX Runtime's `model.onnx` runs here).
- **The input-format reference is made up:** 72 made-up emails built to use every rule of the format,
  and 10 edge cases (TinyPhishLLM publishes nothing from its check sets). The service builds all 82 texts
  exactly.
- **Tests** (`test/model-source.test.js`): the pin is complete; the downloaded files match it; no model
  file is committed and the image build downloads them; `fetch-model.js` downloads, checks, keeps the
  right files without downloading them again, and never writes a file whose SHA-256 differs; the input
  format matches. `test/update.test.js`: the model's source on Settings → Update and in the update's
  Activity line.
- **`tools/export-onnx.py` moved** to the model's training repository, where `model.onnx` is made with the
  rest of the model.
- **Retraining** (`docs/RETRAINING.md`): steps 6 and 7 train in TinyPhishLLM_Private_Training, publish
  to TinyPhishLLM and pin it here. Also `README.md`, `CLAUDE.md` (never commit the model's files),
  `docs/INSTALL.md`, `docs/PRIVACY.md` (what the build downloads), `docs/ARCHITECTURE.md`, `docs/SCALING.md`.
- `installLevel` is unchanged: nothing new to install. The build needs to reach
  `raw.githubusercontent.com`, as updates already reach `github.com`.


## 0.5.7: Model health measures "rules and AI together"

Nothing in how emails are judged changes: this only counts.

- **Status → Model health → Rules and AI together (measured only).** It counts the emails from outside
  senders that score in between on both:
  - a rules score of 3 to under 5;
  - and an AI score from the suspicious line (65%) to under the move threshold (90%).

  Neither score alone moves them, so they are recorded as suspicious. The card shows how many there were in
  the period, how many admins marked as phishing and as false alarms, and how many aren't reviewed. It also
  says, once ten or more are marked, whether mostly phishing (moving such emails could be worth trying, in
  monitor mode first) or many genuine (it would make false alarms). The lines follow Settings → Policy.
- **Why measure first:** in the district's own examples, no email scored between 65% and 89% (0 of 71
  genuine, 0 of 26 phishing). The rules and the AI aren't independent either: the AI reads many of the
  rules' findings, so a total would count them twice.
- **Inside senders are left out,** since the AI never moves them. Each record now notes whether its sender
  counted as inside (your domains, DMARC passing). For records from before 0.5.7, any address in your
  domains counts as inside, which can only leave emails out of the count.
- **Install:** Settings → Update, once approved (`installLevel` 3, as 0.5.6).
- **Tests:** 124, with three more checks in existing tests: the zone and its marks, inside senders left out,
  and the zone following the settings.

## 0.5.6: Microsoft 365 links are no longer "look-alike domains"

- **Links to Microsoft 365 no longer get a false look-alike finding.** That covers
  `bookings.cloud.microsoft`, `forms.cloud.microsoft`, `teams.cloud.microsoft`, `outlook.cloud.microsoft`
  and every other name under `.microsoft`, which read as "one letter away from icloud.com". The finding
  marked the link dangerous (5 points), and the AI model reads it too. A made-up vendor reply with a
  Bookings link was flagged with a rules score of 6 and AI 100%, enough to move it to Spam in enforce
  mode. Now it is clean: rules score 1, AI 1%.
- **A brand's own top-level domain is never a look-alike.** Only the brand registers names under it. The
  list holds the 19 closed brand top-level domains whose operator IANA's root zone database names as the
  brand, checked November 2026:
  - Microsoft: `.microsoft`, `.azure`, `.bing`, `.office`, `.windows`, `.xbox`, `.skype`, `.hotmail`;
  - Google: `.google`, `.goog`, `.gmail`, `.youtube`, `.android`, `.chrome`;
  - `.apple`, `.amazon`, `.aws`, `.dell`, `.ibm`.

  Open top-level domains stay off the list, even ones a brand runs: `.live`, `.cloud`, `.play`, `.new`.
- **The ordinary word "cloud"** (`cloud.com`, say) isn't counted as a one-letter typo of iCloud. Real
  look-alikes are still found: look-alike characters (`icl0ud.com`), one letter off (`lcloud.com`,
  `iclouds.com`), the name with sign-in words (`icloud-login.com`), and the name in front of another domain
  (`icloud.com.verify-id.com`).
- **Re-scan** (Review) gives emails flagged this way their new scores.
- **Install:** Settings → Update, once approved (`installLevel` 3, as 0.5.5).
- **Tests:** 124 (from 123): the brand top-level domains and the word "cloud" aren't look-alikes, and nine
  real look-alikes still are.

## 0.5.5: Clearer wording on what moves an email

Nothing in how emails are judged changes. The words do, where they could be read as "the AI also needs
the rules".

- **Settings → Policy, the AI move threshold:**
  - an email from outside the organization that the AI scores at or above it is moved on the AI score
    alone, whatever the rules find;
  - from inside (your domains, DMARC passing), the AI score alone never moves it, and it is recorded as
    suspicious.

  It used to say "an email the AI scores this high or higher is moved (rules aside)".
- **Settings → Policy → How it decides,** row by row:
  - **Moved, sender outside:** either one is enough, the AI score at the threshold or the rules flagging
    it (a rules score of 5). The AI needs no rule, link check or other sign to agree.
  - **Moved, sender inside:** only by the rules; the AI score alone never moves it.
  - **Inside or outside:** your domains and DMARC passing make a sender inside; anything else is outside,
    a forged staff address too. DMARC decides only that (and whether an allowlisted sender counts), and an
    outside sender doesn't have to pass or fail it. A failed DMARC check is also one of the rules' signs (2
    or 3 points), never required.
  - **The rules:** what the rule checks add up, with 3 amber and 5 flagged; the AI score is separate.
- **README:** the same in its table of what happens to an email.
- **Install:** Settings → Update, once approved (`installLevel` 3, as 0.5.4).
- **Tests:** 123, as in 0.5.4.

## 0.5.4: A re-scan updates the email's scores and model

- **After a re-scan, the email's page shows the re-scan's results.** In 0.5.3 the AI opinion still named
  the model of the email's arrival scan (phish-tiny 0.11.0, say) and its score, with the re-scan only in
  the box under "What happened". Now these all become the re-scan's:
  - the AI score, the model and what weighed most;
  - the rules score and the signs found;
  - the flagged links and the lookups.
- **The arrival values stay beside them.** They are kept once, from the first re-scan on, and shown in the
  re-scan box and under the AI opinion ("On arrival: 99%, phish-tiny 0.11.0").
- **What happened doesn't change:** moved, would move or flagged, and why. Nothing is moved by a re-scan.
  An email stays in its review queue until you decide.
- **The sender counts as new on a re-scan if it was new on arrival.** In 0.5.3 a re-scan treated every
  sender as known, which lowered the rules score twice:
  - "first email from this sender" no longer counted;
  - neither did a brand-new link site, which counts only with a new or unverified sender.

  Now the same checks give the same rules score as on arrival (all 140 demo emails do). A re-scan differs
  from arrival only where the model or the checks changed.
- **Model health counts a re-scanned email under the model that re-scanned it.**
- **Demo mode uses its made-up district's domain** (`maple-schools.example`) when `ORG_DOMAINS` isn't set,
  as its emails were judged with. Re-scan and Check an email there now see "your organization" the way the
  records do.
- **An email re-scanned with 0.5.3** takes its arrival values from the scores it still has, the next time
  it is re-scanned.
- **Install:** Settings → Update, once approved (`installLevel` 3, as 0.5.3).
- **Tests:** 123 (from 122): after a re-scan, the email's model and scores are the new ones and the
  arrival values are kept, also over a second re-scan and for a record re-scanned by 0.5.3; a sender new on
  arrival keeps its rules score.

## 0.5.3: Re-scan an email; Status shows the AI engine; Model health names the model in use

- **Re-scan** (Email → Review, and each email's page):
  - **What it does:** the email is read again from its mailbox and judged with today's checks and AI
    model, the way "Check an email" does. Use it after a model update, for emails still in the queues.
  - **What you see:** the result beside what happened on arrival, which stays: the model, the AI score,
    the rules score (each with its on-arrival value), and what would happen now.
  - **Nothing is moved:** you decide with the usual buttons. In the Review queue the key is **R**, next to
    F, P and N.
  - **Noted in Activity**, with who re-scanned what. At most once every 5 seconds per email. An email
    deleted from its mailbox can't be re-scanned, and says so.
  - **The rules score can be lower than on arrival:** a re-scan doesn't count "first email from this
    sender", since by then the sender isn't new.
- **Status → Service status shows the AI engine,** in the dashboard and in the worker:
  - the phish-tiny version;
  - the native engine (ONNX Runtime and its version, basic optimization, one thread);
  - whether the model loaded, and in how long;
  - a self-check run each time an instance starts, which scores a made-up phishing email (it must be 50%
    or more) and a made-up genuine one (under 50%).

  The worker notes its own when it starts (`state/engine-worker`, one write per instance), with its version
  and revision. The page says when the worker's model failed to load, or differs from the dashboard's, and
  which model scored the newest email.
- **Status → Model health** said "Model: phish-tiny 0.11.0" after upgrading to 0.5.2, which runs 0.13.0.
  The line named the model that had scored the newest recorded email, and no flagged email had arrived
  since the upgrade. Now it says the model in use. When other models scored some of the period's emails,
  it also says which, and how many: emails keep the score they got on arrival, so the chart above mixes
  both until the old ones age out.
- **Install:** from 0.5.2, Settings → Update can install it once it is approved (`installLevel` 3, as
  0.5.2); otherwise from Cloud Shell with the zip.
- **Tests:** 122 (from 119): re-scan (judged again, the on-arrival result kept, nothing moved, noted, at
  most every 5 s, a deleted email); the AI engine's status (loaded, self-check, a model that fails to
  load); Status's engine checks (the worker not reported yet, on another model, failed). Model health's
  model in use, and the models that scored a period, are checked in existing tests.

## 0.5.2: The AI model trained with more of the district's phishing (phish-tiny 0.13.0)

phish-tiny 0.13.0 adds 6 more of the district's phishing emails to 0.5.1's examples. On emails it never
trained on, it beats 0.11.0 on both sides: fewer false alarms on the district's mail, and about half the
missed phishing. Use it instead of 0.5.1, which was not published. Everything in 0.5.0 is included;
install it the same way.

- **What it learned from:** 0.5.1's examples, plus 6 phishing and spam emails from a second batch of
  originals:
  - a "call this number" antivirus bill;
  - two retirement-outreach campaigns posing as the district's;
  - a fake wage-garnishment notice to payroll;
  - an estate-claim scam;
  - a motivational speaker's cold pitch to a principal.

  Each comes with two variants. That makes 48 genuine and 48 phishing training examples, the balance
  `docs/RETRAINING.md` asks for.
- **Made anonymous** like 0.5.1's examples, with one more kind of detail: a partial Social Security number
  of a named employee (in the fake garnishment notice) was replaced with a made-up one.
- **Left out of this batch:**
  - a SharePoint share notice, whose trick could only be in the shared file;
  - a Zoom webinar confirmation in Zoom's own template;
  - an ed-tech vendor's sales email from its real domain.

  Training on them would teach the model to distrust those services' genuine mail.
- **Measured with the service's own engine at the 90% line, on emails no model was trained on**
  (0.11.0 → 0.13.0):
  - the district's genuine mail called phishing: 15 → 7 of 23;
  - the district's phishing caught: 2 → 3 of 6;
  - published phishing missed: 20 → 11 of 603 (15 → 8 at the 50% line);
  - published genuine emails called phishing: 17 → 13 of 624;
  - genuine look-alikes called phishing: 3 → 3 of 24, and the hand-written emails all right, as before.

  0.12.0 (0.5.1) made fewer false alarms (5 of 23) but missed more phishing (21 of 603). The fake e-sign
  document it scored 3% scores 98% now.
- **`vendor/spruce/models/phish-tiny/MODEL_CARD.md`** has the details.
- **Install:** from Cloud Shell with the zip, as 0.5.0 (`installLevel` 3).
- **Tests:** 119, as in 0.5.0.

## 0.5.1: The AI model trained with the district's own mail (phish-tiny 0.12.0)

phish-tiny 0.12.0 is trained with 78 examples from a district's own mail, made anonymous first, and makes
far fewer false alarms on mail like the district's, while catching published phishing about as well as
0.11.0. Everything in 0.5.0 is included; install it the same way.

- **What it learned from:**
  - 48 genuine emails the district's admins marked as false alarms: staff notes, vendor threads, service
    notices.
  - 10 phishing and spam emails from the district: retirement and pension outreach posing as the
    district's, "AI data licensing" broker scams, a pay-on-results PR pitch, a fake invoice. Each comes
    with two variants that use other made-up names and domains.
  - A third of each kind was kept aside and never trained on: 23 genuine, 3 phishing.
- **How they were made anonymous** (`docs/RETRAINING.md`):
  - every person, the district, its schools and town, other districts, account and tracking identifiers,
    and bank details replaced with made-up ones or removed;
  - a list of students' names left out entirely, and a fake invoice whose trick was only in its
    attachment (which the model never sees);
  - every line read. The examples are in no repository.
- **Measured with the service's own engine, at the 90% line, on emails no model was trained on**
  (0.11.0 → 0.12.0):
  - the district's genuine mail called phishing: 15 → 5 of 23;
  - published genuine emails called phishing: 17 → 9 of 624;
  - published phishing missed: 20 → 21 of 603 (15 → 15 at the 50% line);
  - the district's held-out phishing caught: 1 → 1 of 3 (kinds it wasn't trained on);
  - hand-written emails: all right, as before.
- **The phishing it trained on** scores 100% where 0.11.0 gave it 0–6%, except the fake invoice (8%):
  invoices that look like real vendors' are still for the rule checks. This is a training score, not a
  test, but these campaigns come back in new copies.
- **`vendor/spruce/models/phish-tiny/MODEL_CARD.md`** has the details, including a run on the same data
  without the district's examples.
- **The engine's test** now holds ONNX Runtime to `tools/export-onnx.py`'s own computation of the new model
  (numpy, from `model.bin`), over the same 400 made-up inputs.
- **Install:** from Cloud Shell with the zip, as 0.5.0 (`installLevel` 3).
- **Tests:** 119, as in 0.5.0.

## 0.5.0: The native engine, records kept 35 days, the dashboard on when it's large

The AI model now runs in ONNX Runtime instead of JavaScript, each worker checks 32 emails at a time, how
long records are kept is a dashboard setting (35 days by default), and the dashboard reads less when it
starts. Measured on made-up mail: `docs/SCALING.md`.

- **The native engine.** The phish-tiny model runs in ONNX Runtime (`onnxruntime-node` 1.31.1, MIT)
  from `models/phish-tiny/model.onnx`, which `tools/export-onnx.py` makes from `model.bin`. A full-length
  pass takes about 6 ms instead of 146 ms, and an email's explanation passes (its sentences) run as one
  batch. All of an email now takes about 10 ms of processor time on average (97 ms in 0.4.1, 217 ms in
  0.3.12).
  - **The same answers:** on 400 made-up inputs the largest difference in the margin is 8.8e-6, and no
    email changes side of the 50%, 65% or 90% line. The test holds the engine to the JavaScript engine's
    answers, which stay in `test/fixtures/model-reference.json` with their token ids.
  - **It runs at the "basic" level of graph optimization.** The higher levels turn the 8-bit weights
    into 8-bit arithmetic, which changed answers by up to 0.36 in the margin. One thread and no spinning,
    so the instance's one vCPU is shared fairly.
  - **The JavaScript engine is removed** (`vendor/spruce/ai.js` keeps the tokenizer and the model's
    input text, as in training).
  - **A new model** gets new reference answers from `tools/export-onnx.py --reference`, which computes
    them from `model.bin` in numpy, without ONNX (it agrees with the JavaScript engine to 1.2e-6):
    `docs/RETRAINING.md`, step 7.
  - **The image** keeps ONNX Runtime for Linux x64 only: 47 MB of the package's 294 MB. Its installer's
    download is turned off (`.npmrc`).
- **32 at a time.** Each worker instance takes 32 requests at once (8 before) and checks at most 12
  emails at once, and only 2 of them over 4 MB, so large attachments can't fill its 1 GiB. Measured: 28
  emails a second per instance (4.8 in 0.4.1), half of them checked within 0.31 s.
- **Records kept 35 days by default** (60 before), and **changeable in Settings → Policy** (14 to 365
  days, with the project ID; noted in Activity and emailed as an alert), or with `RETENTION_DAYS` in
  `deploy/settings.env`. `install.sh` reconciles the two like the other policy settings.
  - **Each record goes on its own date**, that many days after its email arrived, oldest first. It is
    never a clear-out every 35 days.
  - **Shorter:** records older than the new value are deleted over the next hours, by the hourly
    cleanup.
  - **Longer:** applies to records saved from then on. Those already saved keep their date.
  - **After this upgrade,** records between 35 and 60 days old are deleted within hours, unless
    `RETENTION_DAYS` or the dashboard says otherwise.
- **The period buttons follow the setting:** with 35 days, Last 90 days becomes Last 35 days.
- **The dashboard reads the last 32 days when it starts**, not the whole retention period. Last 90 days
  (or the longest period kept) reads the older ones then; they are forgotten after an hour without such
  a page.
- **Always on from 10,000 watched mailboxes.** `install.sh` and Settings → Update keep one dashboard
  instance running (`--min-instances=1`, about $13 a month) when the last watch renewal counted 10,000
  or more watched mailboxes, so its pages open at once. Below that, it starts when opened, at no cost.
  When the count isn't known yet (a first install), the setting is left as it is.
- **Costs, counted again**, and **`docs/COSTS.md`**: what it costs a month by district size, where the
  money goes, the free allowances and what the estimates assume. Cloud Run bills an instance for all
  the time it has a request open, waiting included. The earlier estimates counted only processor time
  and were too low. At 10,000 mailboxes the worker costs about $21 a month with 0.5.0 (about $26 with
  0.4.1, which was estimated at $14). In all, about $50–65 a month at that size, $13 of it the
  always-on dashboard.
- **Install:** from Cloud Shell (`installLevel` 3: `install.sh` sets the dashboard's minimum instances
  and the new setting). Settings → Update can't install it.
- **Tests:** 119 (from 113). They cover:
  - the native engine against the reference answers, one at a time and in a batch, and the tokenizer
    against the stored ids;
  - at most 12 emails at once, 2 of them large;
  - retention from settings.env and the dashboard, the Activity texts, the cleanup after shortening,
    and Firestore's expiry dates following the setting;
  - the dashboard's copy (32 days first, older on demand, forgotten after an hour, trimmed when
    retention shrinks);
  - the installer (`RETENTION_DAYS` 14 to 365, reconciled with the dashboard; the dashboard always on
    from 10,000 mailboxes, at install and in Settings → Update).

## 0.4.1: Lower monthly costs

For school systems on small budgets: the same protection for less. Costs by district size, with the
prices checked on Google's pricing page: `docs/SCALING.md` ("What it costs") and `docs/INSTALL.md`
("Costs").

- **The dashboard no longer reads every mailbox.** Status, Readiness and every Settings page read each
  watched mailbox's document, and open pages refresh every 30 seconds: at 10,000 mailboxes, a Status page
  left open all day read about 29 million documents (about $17 a day in `us-east1`). Now they use a count
  of the watched mailboxes, the latest notification (one read) and a count of watches ending, kept a
  minute: about 17,000 reads a day. Only Settings → Mailboxes lists mailboxes, the first 500.
- **The hourly health check counts too** (it read every mailbox's document every hour).
- **A notification that brings nothing new writes nothing** (someone read or archived an email: two
  thirds of notifications). The mailbox's position waits up to 30 minutes; the next notification reads
  its history from there, for 2 Gmail quota units.
- **Three scheduled jobs, the free ones.** The cleanup of old documents runs with the hourly job (last,
  within 30 seconds), and `install.sh` removes the daily `spruce-purge` job: Cloud Scheduler gives 3 jobs
  per billing account for free, then $0.10 a job a month.
- **The example region is `us-central1`** (`deploy/settings.example.env`, `docs/INSTALL.md`). Firestore
  in `us-east1` costs twice as much as in any other US region ($0.06 per 100,000 reads and $0.18 per
  100,000 writes, against $0.03 and $0.09). The region can't be changed once installed.
- **Stopped mailboxes clear their watch's end**, so "watches ending within a day" counts only watched
  ones (those stopped before are cleared at the next renewal).
- **Install:** from Cloud Shell, as 0.4.0 (`installLevel` 2). From 0.4.0, Settings → Update would work
  too: the old cleanup job then keeps running until the next `install.sh`, harmlessly.
- **Tests:** 113 (from 109): a notification with nothing new writes nothing for 30 minutes, then writes;
  the mailboxes in numbers (memory and the Firestore emulator), stopped ones not "ending"; the Mailboxes
  list only on request; the hourly cleanup; three jobs, the old one removed.
- **Docs:** `docs/SCALING.md`, `docs/INSTALL.md`, `docs/DEPLOY.md`, `docs/ARCHITECTURE.md`.

## 0.4.0: Ready for a district (10,000 mailboxes, 100,000 emails a day); its own engine

Measured with the service's own code on a made-up district's mail; the numbers, and the plan for what
is left, are in `docs/SCALING.md`.

- **This project's own engine.** The checks and the AI model in `vendor/spruce/` began as the
  S.P.R.U.C.E+ browser extension's; they are now changed here, with tests. `tools/sync-engine.js` is
  gone. The dashboard says "The rule checks" (it said "The extension's checks").
- **The watches stay renewed at 10,000 mailboxes.** The daily renewal went through mailboxes one at a
  time and was cut off after 120 seconds: about 700 renewed a day, the others no longer checked after 7
  days. Now 10 at a time within 95 seconds, the oldest (and new members) first, the rest at the next run:
  about 5,800 a run, each mailbox every two days or so. Activity says how many are left for the next run.
- **The AI model twice as fast, with the same answers.** One pass at 256 tokens: 146 ms (it was 289);
  checked on 3,230 passes, identical to the bit. Each instance remembers a pass's answer by a hash of its
  input (in memory): a campaign's identical copies cost one pass. Per email: 97 ms of processor time (it
  was 217); one worker instance checks 4.8 emails a second (it was 2.8).
- **Far fewer Firestore operations, and no hot documents in a campaign burst:**
  - per notification without new mail: 2 reads and 1 write (it was 3 and 2), the "last notification"
    time written with the sync position;
  - per email: a message's claim and a new sender created without a transaction; when the service was
    installed, and senders' first-seen times, remembered per instance; the day's counters added up and
    written every 5 seconds (and when the instance stops), in 30 shards; domain ages remembered 6 hours;
  - a campaign's move counter stops once its alert is sent: a campaign to 10,000 mailboxes writes its
    campaign document 59 times (it was 5,000), and its sender's 10 (it was 10,000 transactions).
- **The dashboard counts every record.** It read at most 50,000 records and built pages from 20,000, so
  at a district's size the 30-day numbers were too low. Now every record of the period, kept slim (169 MB
  for 180,000 records; it was about 300 MB for 50,000), pages in 30–350 ms, past days' counters read once.
  A campaign's page and "Confirm phishing: move every copy" read that campaign's records only.
- **Old documents delete themselves.** What expires carries `expireAt`, and Firestore's TTL policies
  delete it (typically within a day). The daily cleanup job only takes older documents, within 90 seconds.
- **Scaling settings:** the worker up to `WORKER_MAX_INSTANCES` instances (new, 30 by default; it was
  10), gen2 with startup CPU boost; the dashboard 1 GiB (it was 512 MiB); Pub/Sub retries after 10 s.
- **Tokens:** calls for the same mailbox's access token at once share one request.
- **Install this version from Cloud Shell** (`bash deploy/update.sh`): it sets up the TTL policies and the
  new service settings (`installLevel` 2), so Settings → Update says so instead of offering the button.
  `upgrade.sh` adds `WORKER_MAX_INSTANCES=` (empty: 30).
- **Tests:** 109 (from 103): the renewal at scale (10 at a time, the oldest first, the rest next time),
  the counters added up, the same model answer remembered, shared token requests, the installer's TTL and
  scaling settings, and in the Firestore emulator: `expireAt` written and left out of reads, claims and
  senders created by one of 12 racing callers, the cleanup's time limit.
- **Docs:** `docs/SCALING.md` (new), `CLAUDE.md` (the engine is this project's own), `README.md`,
  `docs/DEPLOY.md`, `docs/ARCHITECTURE.md`, `docs/RETRAINING.md`, `docs/ROADMAP.md`.

## 0.3.12: Settings → Update loads while an update is under way

- **Fixed: "Couldn't load this page. internal error." on Settings → Update** as soon as **Update to …**
  was pressed, and from then on. The page's answer had a field named `status` (the update's progress),
  which the dashboard's server took as the HTTP status code. In 0.3.9 to 0.3.11 the page loaded only
  until the first update was asked for. The update itself was asked for, and the job run.
  - The progress is now `progress`, and the server takes a route's status as the HTTP status code only
    when it is one (a number from 100 to 599).
- **A second build for the same update changes nothing.** Pressing the button and also running the
  `spruce-update` job by hand started two builds for one request. A build that finds another one
  "building" (in the last 45 minutes) now leaves it to that one, and says so in its log.
- **Old progress isn't shown as current.** An update's progress about a version already installed or
  passed (installed from Cloud Shell since, say) no longer shows as "under way" or "didn't finish", and
  doesn't hold the button back.
- **Install this version from Cloud Shell** (`bash deploy/update.sh`, or `upgrade.sh` with the zip): the
  Update page of 0.3.9 to 0.3.11 can't load once an update was asked for. Nothing in the installation
  changes (`installLevel` stays 1), so later versions can come from the dashboard.
- **Tests:** 103: the page through the dashboard's server with an update requested, building, done or
  failed (it failed with HTTP 500 before); old progress left out; a second build standing aside, one
  stopped long ago not blocking, and the dashboard's "requested" as the usual start.
- **Docs:** `docs/DEPLOY.md`.

## 0.3.11: Review suspicious emails that weren't moved

- **Email → Review has two queues**, chosen at the top, each with how many are left:
  - **Moved or would move** (as before, oldest first);
  - **Suspicious, not moved** (new, newest first): emails the checks found suspicious (a rules score of 3
    or more, or an AI score from the suspicious line) but not enough to move, still in the Inbox, that
    nobody has reviewed. **F** not phishing, **P** phishing, **N** next.
- **In enforce mode, P moves an email still in the Inbox to Spam**, with the service's `SPRUCE/Moved`
  label. The button then reads **Phishing: move to Spam**, and only a button that says so moves
  anything (if another admin switches the mode meanwhile, it only marks). Activity notes who moved
  what; the email's page says "moved when … confirmed it as phishing"; **Move back to Inbox** undoes it.
  - **In monitor mode nothing is moved**, by the service or by an admin's decision, as before.
  - An email no longer in the Inbox (archived, deleted, moved by the user) is marked, and left where it is.
  - The service's own rules still never move a suspicious email: only an admin's decision does.
- **The same on an email's own page and for several at once:** **Confirm phishing: move to Spam** for an
  email still in the Inbox in enforce mode, and **Confirm phishing** on Messages moves those still in the
  Inbox (Activity says how many). **Mark not phishing** replaces "Mark false alarm" for a suspicious email.
- **Why it matters:** phishing among the suspicious emails is what the move rules miss, and marking them
  gives the retraining export its best examples (docs/RETRAINING.md). The export already takes every
  email an admin marked.
- **Fixed:** an email's Details showed "undefined" as the trigger of a copy found by an admin's search
  for a campaign. The note about pausing a campaign is no longer shown for emails the service didn't move.
- **Demo:** two made-up campaigns that are suspicious but not moved (a benefits survey, a webinar), so
  the new queue has emails to try. (The demo's earlier suspicious example now scores 100% with the AI
  model of 0.3.3, and is moved.)
- **Tests:** 103 (from 101): moving on P in enforce mode only, an email no longer in the Inbox, not
  phishing, monitor mode, an admin's earlier decision kept, several at once; and the queue through the
  dashboard (only suspicious emails still in the Inbox, newest first, both counts, out of the queue once
  marked).
- **Docs:** `README.md`, `docs/INSTALL.md`, `docs/RETRAINING.md`, `docs/ARCHITECTURE.md`.

## 0.3.10: Long links and addresses stay inside their cards

- **On an email's page** (Email → Review, and an email opened from Messages), text with no place to
  break now wraps inside its card instead of running out of it and making the page scroll sideways:
  - the AI's quotes ("What weighed most"), which are often a tracking link;
  - **Flagged links**, and the links named in **Signs found**;
  - the subject, the sender and recipient line, and **What happened**.
- **The same elsewhere:** alerts, Overview's recent alerts, Status → Activity, and the Status and
  Readiness checks, which can name a subject, an address or a link.
- **Signs found:** the score badge stays one line tall at the top of a sign that wraps over several
  lines.
- Nothing else changes: the AI's quotes and the links are shown in full, as before.
- **Tests:** 101 (from 100): the dashboard's styles let long words break wherever email text is shown.

## 0.3.9: Updating from the dashboard (Settings → Update)

- **Settings → Update**, its own page in the Settings menu:
  - the version installed, the newest approved one (from `google_service_main`), and the AI model it
    brings;
  - **what's new since your version**, and the whole changelog, read from the release repository;
  - **Update to …**, which works like `bash deploy/update.sh`. It needs **I agree**, the Google Cloud
    project ID and the email address you are signed in with. Five wrong answers lock it (and policy
    changes) for 10 minutes;
  - how the update goes: requested, building, done or failed (with the reason), and who started it.
- **The dashboard can't deploy anything itself.** It records the request (the version and its exact
  commit) and runs the new `spruce-update` job. That job starts a Cloud Build, fixed by `install.sh`,
  as the new `spruce-updater` service account. The build takes `deploy/cloud-update.sh` from
  `google_service_main` and checks again before building:
  - the request is from the last 30 minutes;
  - the commit is on `google_service_main`'s main branch, and has that version;
  - it is newer than the version running;
  - its `installLevel` isn't higher than the one installed.

  Then it builds that commit, deploys both services with it (their settings as they are), and notes in
  Activity how it ended (a failure as an alert). It takes about 10 minutes; mail keeps being checked.
  If the build can't read the request at all (permissions, say), it fails visibly in Cloud Build's
  history instead of doing nothing quietly.
- **No button when there's nothing to install:** the newest approved version is the one installed, or
  older than it (a version not yet approved, installed from a zip), and the page says which.
- **`installLevel`** (new in `package.json`, now 1) goes up with each version that changes the
  installation itself (roles, jobs, settings). Those versions aren't offered on the dashboard: the page
  says to run `bash deploy/update.sh` in Cloud Shell. Both services are labelled with the level
  installed (`spruce-install-level`).
- **`install.sh`** sets it up: the `spruce-updater` account (Cloud Build Editor, Logs Writer, Cloud
  Datastore User; Service Account User on itself and `spruce-run`; Artifact Registry Writer on the
  `spruce` repository; Cloud Run Developer on the two services), the `spruce-update` job (it runs by
  itself once a year, and then does nothing), and `UPDATE_JOB` and `RELEASES_REPO` on the dashboard.
  **Install 0.3.9 from Cloud Shell** (`update.sh` or `upgrade.sh`); later versions can come from the
  dashboard.
- **Privacy:** the dashboard reads the release repository from GitHub anonymously (no token, nothing
  about your installation), when the page is opened, kept 10 minutes.
- **Fixed:** the README still named the Messages button "Release to Inbox".
- **Tests:** 100 (from 93): reading the releases and the changelog; the button's checks and lock; the
  reasons no button is offered; the demo routes; the job, build and roles install.sh sets up;
  `cloud-update.sh` with a real git repository (nothing asked, Firestore refusing, the approved commit
  built and deployed,
  a commit not on main, too old, not newer, a higher installLevel, a deploy that fails); and its state
  and Activity line in the Firestore emulator.
- **Docs:** `README.md`, `docs/INSTALL.md`, `docs/DEPLOY.md`, `docs/ARCHITECTURE.md`, `docs/PRIVACY.md`,
  `CLAUDE.md` (raise `installLevel` when install.sh changes).

## 0.3.8: The AI suspicious line, a setting

- **Settings → Policy → AI suspicious line** (`AI_SUSPICIOUS_THRESHOLD`, 65% by default): the AI score
  from which an email that isn't moved is recorded as suspicious for review.
  - Lower records more emails for Email → Review, higher fewer. Nothing more or less is moved.
  - Below the line, and with a rules score under 3, an email isn't recorded at all.
- **Changed like the rest of the policy:** the project ID, noted in Activity, emailed as an alert,
  everywhere within 30 seconds.
- **It is never above the move threshold, and the threshold is never below it,** checked both ways:
  - on the dashboard: "To go higher, raise the move threshold first" / "To go lower, lower the
    suspicious line first";
  - in settings.env: the service doesn't start with them the wrong way round.
  - The move threshold is no longer held at 65% or more: its floor is the suspicious line.
- **The installer** carries it like the others: `install.sh` compares it with settings.env and asks when
  they differ. `upgrade.sh` adds `AI_SUSPICIOUS_THRESHOLD=` (empty: 65%).
- **Tests:** 93 (from 92): the line as a setting in the decision, both checks, the alert, the config
  check, and the installer taking it.
- **Docs:** `README.md`, `docs/INSTALL.md`, `docs/DEPLOY.md`, `docs/ARCHITECTURE.md`.

## 0.3.7: The allowlist and Settings in pages; the AI lines at 65% and 90%; clearer words

- **The AI's two lines:**
  - **Suspicious from 65%** (it was 50%). Below 65%, and with a rules score under 3, an email isn't
    recorded.
  - **Moved from 90% by default** (`AI_MOVE_THRESHOLD`, it was 85%). An install whose settings.env
    leaves it empty moves from 90% after upgrading; one that sets a value keeps it.
  - The threshold can't go below 65% (settings.env, or Settings → Policy).
  - The AI meter on an email's page turns red at the threshold in force, not at a fixed 85%.
- **Allowlist on Settings** (Settings → Allowlist): the domains and addresses never moved (when Gmail's
  DMARC check passes for them).
  - Changed like the policy: the project ID, noted in Activity, emailed as an alert naming what was
    added and removed, in force everywhere within 30 seconds.
  - **Your own domains (and their subdomains) can't be allowlisted**, or a staff account taken over would
    never be moved. Single addresses in them can.
  - One per line, or separated by commas; lower case, no repeats; at most 500 of each.
  - `install.sh` compares the lists with `ALLOW_DOMAINS` and `ALLOW_ADDRESSES` as sets (order and case
    aside), and asks when they differ, as for the policy.
- **Settings in pages,** with a menu on the left like Email and Status:
  - **Policy:** the four settings, and how the rest decides;
  - **Allowlist**;
  - **Mailboxes:** the watched mailboxes, and Update group membership now;
  - **Weekly summary**;
  - **Retraining**;
  - **About:** the version, the model, what is kept, and the network checks.
- **Words that don't suggest mail is withheld.** Every email reaches the user's mailbox; the service
  only moves some to Spam.
  - "Release" is now **move back to the Inbox**: **Move back to Inbox**, **False alarm: move every copy
    back**, "Moved back" in lists and filters.
  - "Held" is now **paused**, or **left in the Inbox**:
    - "Moving is paused for this campaign, waiting for your decision";
    - the brake's "Resume, and move those to Spam" and "Resume, and leave them in the Inbox";
    - Settings' "Campaign pause".
  - The same words in the alerts, Activity, the weekly summary, decision reasons, `clear-data.sh` and
    the docs. `--even-if-paused` replaces `--even-if-held` (which still works). The setting
    `CAMPAIGN_HOLD_AFTER` keeps its name.
  - The Gmail label on mail an admin moves back is now **`SPRUCE/Moved back`** (`RELEASED_LABEL`; it was
    `SPRUCE/Released`, which emails moved back before stay labelled with).
- **Review:** the "Open it with its other buttons" link is gone.
- **Tests:** 92 (from 90): the 65% and 90% lines, the allowlist (checks, the own-domain refusal, in
  force at once, the alert's text, the installer comparing lists, `&` in an address kept), and the
  clickable mockup building with scripts that parse (its allowlist stand-in had broken it).
- **Docs:** `README.md`, `docs/INSTALL.md`, `docs/DEPLOY.md`, `docs/PRIVACY.md`, `docs/ARCHITECTURE.md`,
  `docs/RETRAINING.md`, `docs/ROADMAP.md`.

## 0.3.6: The policy, changed on the dashboard

- **Settings → Policy:** a **Change** button for each of:
  - **the mode** (monitor or enforce);
  - **the AI move threshold** (51–100%);
  - **the brake** (automatic, or a fixed number of moves an hour, 10–100,000);
  - **the time zone** (a list of time zone names).

  Each row says where its value comes from: settings.env, or changed here, by whom and when.
- **The project ID is required for every change.** The dashboard checks it against
  `GOOGLE_CLOUD_PROJECT` (install.sh sets it), case and spaces aside. Five wrong ones lock changes for
  10 minutes.
- **Enforce mode also needs "I agree".** The form warns what enforce mode does and shows how many
  Readiness checks pass. Back to monitor needs only the project ID.
- **A change applies everywhere within 30 seconds.** It is kept in Firestore (`state/policy-<key>`), and
  both services read it on each notification, each job and each dashboard request.
- **Every change is noted in Activity and emailed as an alert**, except the time zone, which is only
  noted.
- **The header's mode badge** follows a switch made by any admin.
- **install.sh, upgrade.sh and update.sh** compare the dashboard with settings.env
  (`deploy/dashboard-policy.sh`, new):
  - settings.env doesn't set a setting the dashboard changed: the dashboard's is used;
  - settings.env sets it and the dashboard didn't change it: settings.env's is used;
  - the two differ: you're asked which to keep. The default is the dashboard's, since it is in force.
    Without a terminal to ask in, the dashboard's is kept; `SPRUCE_SETTINGS=file` uses settings.env's.
  - The choice is written into settings.env. Once the new build is deployed, the dashboard's copy is
    removed (until then it stays in force), and Activity notes what was chosen.
  - `upgrade.sh` says beforehand what will be taken or asked about, and `Mode now: …` when the
    dashboard switched it.
  - The nightly jobs follow the time zone chosen.
- **The services agree with settings.env changed later:** when settings.env has another value than the
  one a dashboard change replaced, settings.env's is newer and applies.
- **Tests:** 90 (from 85).
  - `test/policy.test.js` (new): values checked; a change at once here and after the refresh
    elsewhere; enforce really moves; alerts and notes; settings.env changed later wins; the project
    ID, the lock and the agreement through the dashboard's route.
  - `test/install.test.js`: the reconciliation (taken, kept, settings.env's chosen, a removal refused,
    the same on both sides), the env each service is deployed with, the jobs' time zone, the order (the
    removal after both deploys).
  - `test/firestore.test.js`: the helper against the Firestore emulator, reading what the service
    stores, removing it and noting it.
- **Docs:** `README.md`, `docs/INSTALL.md` (changing a setting, moving mail for real), `docs/DEPLOY.md`,
  `docs/ARCHITECTURE.md`.

## 0.3.5: The dashboard in four tabs

- **Four tabs instead of ten:** **Overview**, **Email**, **Status**, **Settings**.
- **Email** has a menu on the left: **Review**, **Campaigns**, **Messages**, **Users**, in that order.
  - The Email tab opens on Review.
  - The number of emails waiting for review is on the Email tab, and next to Review in the menu.
  - An email's page and **Check an email** belong to Messages.
- **Status** has the same kind of menu: **Service status** (the end-to-end checks that were the Status
  tab), **Model health**, **Readiness**, **Activity**.
- **On a phone** the menu is a row of buttons above the page, which scrolls sideways when it doesn't
  fit.
- **Every page keeps its address** (`#/review`, `#/health`, `#/activity`…), so links to a page keep
  working: bookmarks, and the Overview's links to held campaigns.
- **Where to go, in the texts:** the alert emails, the Status checks, the weekly summary, the
  Settings cards, `deploy/clear-data.sh` and the docs now say "Email → Campaigns", "Status → Model
  health" and so on.
- **Docs:** `README.md` (the dashboard, by tab), `docs/INSTALL.md`, `docs/RETRAINING.md`,
  `docs/PRIVACY.md`.

## 0.3.4: Clearing the dashboard's data

- **`deploy/clear-data.sh`** (Cloud Shell, from the install folder) clears what the dashboard shows, to
  start counting again (after a trial, before going live).
  - **Deleted** (Firestore): `records`, `stats`, `campaigns`, `moveCounts`, and `events` (Activity)
    unless `--keep-activity`.
  - **Kept:** the watched mailboxes (`users`), the emails already checked (`seen`), the Settings switches
    and the brake's state (`state`), sender history, the phishing lists. Nothing in Gmail changes.
  - **Before:** it shows all this and asks you to type the project ID (`--yes` for scripts; without a
    terminal it stops unless given `--yes`).
  - **When something is held, it stops:** the brake is on, a campaign waits for a decision, or Firestore
    didn't answer the check. The held emails stay in the Inbox and are no longer tracked once cleared.
    `--even-if-held` clears anyway.
  - **After:** Activity gets one entry saying who cleared it, and the dashboard restarts (each instance
    keeps a copy of the records, and a deletion doesn't reach it otherwise).
  - **`--reset-clock`** also restarts the monitor-mode clock (Readiness, and the senders' learning
    period).
  - Every collection is named: `gcloud firestore bulk-delete` without `--collection-ids` would delete
    every collection, and a test checks that no deploy script calls it that way.
- **Tests:** 85 (from 83).
  - `test/install.test.js`, with stand-ins for `gcloud` and `curl`: what is deleted and kept, the
    options, the order (the Activity entry after the deletion), refusing when something is held or
    can't be checked.
  - `test/firestore.test.js`, against the Firestore emulator with the real `curl`: the brake and held
    campaigns read as the service stores them, the Activity entry as the dashboard reads it, the clock
    reset, and a refused token stopping it before anything is deleted.
- **Docs:** `docs/INSTALL.md` ("Clearing the dashboard's data"), `README.md`, `docs/PRIVACY.md`.

## 0.3.3: The AI model phish-tiny 0.11.0

- **phish-tiny 0.11.0** replaces 0.4.0, copied unchanged from the S.P.R.U.C.E+ extension (5.94.13,
  `llm_testing` 9292388) with `tools/sync-engine.js`. Only the model changed: the extension's checks
  (`shared.js`, `decoders.js`, `ai.js`) are the same files as before.
- **Trained on twice as much** (17,024 emails, 3 runs averaged). The extra emails are published phishing
  and scams, including spear phishing and business email compromise, and published genuine emails that
  look like scams.
- **Scored on emails neither model was trained on**, at the service's move threshold (0.85):

  | | 0.4.0 | 0.11.0 |
  |---|---|---|
  | Published genuine emails called phishing | 276 of 624 (44%) | 17 of 624 (2.7%) |
  | Published phishing missed | 48 of 603 (8%) | 20 of 603 (3.3%) |
  | Hand-written genuine look-alikes called phishing | 9 of 24 | 3 of 24 |
  | Hand-written emails (both kinds) wrong | 0 of 33 | 0 of 33 |

  0.4.0 had never seen published genuine emails; 0.11.0 was trained on two thirds of them, and the third
  above is the one held out. The model card is `vendor/spruce/models/phish-tiny/MODEL_CARD.md`.
- **What it means here:** fewer emails moved on the AI score alone, and more phishing reaching it. The
  rules, the brakes and `AI_MOVE_THRESHOLD` are unchanged, and by default (`AI_MOVES_INSIDE`) the AI
  score alone still never moves mail from inside the organization.
- **Upgrading shows it:** `upgrade.sh` prints `AI model (phish-tiny): 0.4.0 -> 0.11.0`. In monitor mode,
  watch Model health and Readiness for a week: the undo rate of "AI score" moves should fall.
- **Tests:** the `update.sh` test now takes the installed model from `vendor/spruce/VENDOR.json` instead
  of assuming 0.4.0.

## 0.3.2: The retraining export, and how to retrain the AI model

Marking an email doesn't train the AI model: phish-tiny is a fixed file that comes with each version.
This version makes the marks usable for training.

- **Download for retraining** (Model health; **off until an admin allows it** in Settings → Retraining
  export; Activity notes who allowed it and every download):
  - The emails an admin confirmed as phishing, and with a tick the false alarms, from the chosen period.
  - One per campaign: the newest copy still in a mailbox. A campaign marked both ways is left out.
  - At most 100, newest first.
  - Each is read from Gmail at the moment of the download and judged again as on arrival, for what the
    model read. Nothing is stored or counted: the file is the only copy.
  - The file is JSON Lines in the extension's own training format (`tools/ai/data/extra/*.jsonl`:
    `name`, `label`, `note`, `facts`).
- **The people are taken out** (`src/training.js`), on top of the model's own redaction:
  - the recipient becomes "your name", as the model sees them;
  - the other people in To, Cc and Reply-To, and names after Mr./Ms./Dr., greetings and sign-offs,
    become [NAME];
  - the sender of genuine or inside mail becomes [SENDER];
  - your domains become [OUR-DOMAIN];
  - the text is cut to what the model reads.

  Other words that may be names are marked ⟦like this⟧ for a person to decide: common names
  (`src/names.js`), unusual words, and capitalized words in the middle of a sentence.
- **`docs/RETRAINING.md`:** how to read the file and train the model with it. In order: review every
  example, replace the placeholders with made-up names (by hand, or with claude.ai if your district
  allows it), keep a third aside, train in the extension, compare, release.
- **Tools** (Node only, no install):
  - `tools/check-training-file.js` refuses leftovers (marks, addresses, phone and long numbers, a `text`
    field), and with `--final`, placeholders;
  - `tools/split-examples.js` keeps every third email of each kind aside, with its variants;
  - `tools/score-examples.js` scores a file with the model the service runs, at its move threshold.
- **Engine:** `analyze()` can return what the model read (`keepAiFacts`, for the export only), and
  `readMessage()` the headers' names (`people`). Neither is stored.
- **Tests:** 83 (from 77). `test/training.test.js` covers:
  - the removal, and that everyday words in the demo's emails aren't marked;
  - the check, the split and the scorer;
  - the export: off by default, phishing only unless asked, one per campaign, a deleted copy replaced,
    nothing stored;
  - the dashboard's routes.
- **Docs:** `docs/RETRAINING.md` (new), `README.md`, `docs/PRIVACY.md`, `docs/ARCHITECTURE.md`,
  `docs/ROADMAP.md`.

## 0.3.1: Quality of life: review, bulk actions, Status, Check an email, the weekly summary

- **Review** (a new tab): the moved or "would move" emails nobody has reviewed, one at a time, oldest
  first. **F** marks a false alarm, **P** phishing, **N** goes to the next. The tab says how many are left;
  that's the Readiness check that asks for 80% reviewed.
- **Several at once** on Messages: tick emails (or all on the page), then **Release to Inbox**, **Mark
  false alarm** or **Confirm phishing**. Live updates wait while some are ticked.
- **The browser tab's title counts what needs you:** the brake, campaigns held for a decision, users who
  took a flagged email back.
- **Check an email** (Messages): paste a reported email's original (Gmail: Show original), or choose an
  `.eml` file. You see what the service would decide and why, judged as on arrival with the same lookups.
  Nothing is stored, moved or counted; Activity notes who checked one.
- **Message-ID on every email**, with a **Copy** button, for Google Workspace's Email log search and the
  security investigation tool. Messages can be searched by it, and the CSV has it. The Gmail ID of each
  copy is shown and copyable too. Emails recorded before 0.3.1 have no Message-ID.
- **Status** (a new tab) checks the service end to end, from the dashboard, and says what to do for each
  problem:
  - Identity-Aware Proxy off on the worker, and who may call it;
  - both services on the same build;
  - the re-read and hourly jobs reaching the worker;
  - Gmail's notifications arriving, and watches renewed;
  - the phishing lists, alerts, errors in the last day, and the brake.

  It needs the Cloud Run Viewer role (install.sh).
- **`deploy/doctor.sh`** checks the rest from Cloud Shell and says what to run for each problem:
  - billing;
  - Identity-Aware Proxy on both services;
  - the subscription's endpoint, sign-in and audience;
  - Gmail's permission to publish;
  - the jobs;
  - the alert policies;
  - errors in the worker's log.

  It is read-only.
- **A settings change doesn't rebuild.** The image is named after its files. `install.sh` with the same
  files reuses it and only redeploys, in about a minute. `FORCE_BUILD=1` builds anyway.
- **`TIME_ZONE`** (for example `America/New_York`): the scheduled jobs run in it (`--time-zone`), the
  installer shows times in it, and the weekly summary goes out Monday from 7 AM there. Empty means UTC,
  as before.
- **`deploy/update.sh`: upgrades without a zip.** It downloads the newest approved version from
  `google_service_main` (public), unpacks it next to your folder, and runs its `upgrade.sh`.
  - The upgrade shows the AI model's version change. Each service is now labelled with its version and
    model's (`spruce-version`, `spruce-model`).
  - The AI model comes with each version, so a new one arrives only with an approved version.
- **Weekly summary email** (Settings; **off by default**, the only setting changed from the dashboard;
  Activity says who turned it on or off):
  - every Monday from 7 AM, put straight into each dashboard admin's Inbox: `ADMIN_EMAILS`, and the
    members of `ADMIN_GROUP` in your domains;
  - the week's numbers, what waits for you, the largest campaigns, and (in monitor mode) the Readiness
    checks;
  - **Preview** and **Send one now** are next to the switch;
  - it uses the Gmail API's `messages.insert`, which the existing `gmail.modify` scope allows: nothing is
    sent and no new permission is needed;
  - the service never judges its own summary.
- **The dashboard reads far less from Firestore.** Since 0.2.12 every open dashboard re-read up to 20,000
  records every 30 s. It now keeps a copy and asks only for records changed since (records carry
  `updatedAt`; changes are read from a minute before the newest one seen, so none is missed).
- **Fixed:** the summary's campaign lines counted the copies wrongly ("0 copies"), found by its test
  before release.
- **Tests:** 77 (from 67). `test/qol.test.js` covers the summary, bulk, review, pending, Status and the
  cache. More in `test/install.test.js` (build reuse, `TIME_ZONE`, labels, `doctor.sh`, `update.sh`),
  `test/firestore.test.js` (change tracking, held campaigns) and `test/server.test.js` (Check an email,
  Message-ID).
- **Docs:** `README.md`, `docs/INSTALL.md` (upgrading with `update.sh`, investigating an email in Google
  Workspace, changing a setting, Troubleshooting starts at Status and `doctor.sh`), `docs/DEPLOY.md`,
  `docs/ARCHITECTURE.md`, `docs/PRIVACY.md`.

## 0.3.0: Brakes that protect a whole district, alerts, campaign decisions

With 7,000 mailboxes, the brake (100 moves an hour, for everyone) would have stopped protecting people
early in a real phishing campaign. The brakes now tell a clear phishing campaign from a possible
misfire.

- **Strong evidence is never held.** The rules flag the email *and* something outside it confirms it:
  - a link Cloudflare blocks or a phishing list has;
  - a sender on a list or blocked;
  - a brand-new look-alike domain;
  - Gmail's DMARC check failing.

  Every copy is moved, to every mailbox. Each record says how strong its evidence was.
- **Weaker evidence is held per campaign.** Past `CAMPAIGN_HOLD_AFTER` (25) copies of one campaign moved
  without outside confirmation, the rest wait in the Inbox, recorded as "would move". Other mail keeps
  moving. An alert and a banner on Overview ask an admin to decide.
- **The domain-wide brake is a last resort.** `BRAKE_PER_HOUR` now defaults to half the watched
  mailboxes, at least 100 (3,500 for 7,000).
  - Its count is exact: a slot is reserved before each move. Before, it was counted after the move, so
    moves happening at the same moment could pass the limit.
  - Tripping it is one atomic step (one alert).
- **Held mail is recoverable.** **Resume and move held mail** moves what the domain-wide brake held, if
  still in the Inbox. **Resume without moving** leaves it.
- **Campaign decisions** (Messages, filtered to a campaign):
  - **Confirm phishing: move every copy** moves held and recorded copies and marks them all phishing,
    and later copies aren't held. It can also search every watched mailbox's Inbox of the last 7 days
    for copies the service didn't record (same sender domain and subject), reading only From and
    Subject.
  - **False alarm: release every copy** releases the moved ones; later copies aren't moved.
  - **Find other copies** runs that search again.
  - In monitor mode nothing is moved.
- **Alerts by email** (`ALERT_EMAIL`, default the `ADMIN_GROUP`; `off` for none). The service logs each
  alert, and Cloud Monitoring emails it through two log-based alert policies that `install.sh` makes
  (expected free). The alerts:
  - the domain-wide brake engaged;
  - a campaign held;
  - a large campaign (`CAMPAIGN_ALERT_AFTER`, 50 moves);
  - no notification from Gmail for `QUIET_HOURS` (12), or watches about to end, from an hourly health
    check;
  - a user taking a flagged email into their Inbox;
  - the group re-read failing;
  - any failed scheduled job (as with Identity-Aware Proxy on the worker).
- **Mail that skipped the checks:**
  - **An email the user moves into the Inbox that was never checked** (it went to Spam first, within 7
    days of arrival) is checked and recorded, never moved, with an alert when the checks flag it.
  - **After a gap in a mailbox's history,** its Inbox since the last notification (at most a week) is
    checked, 25 at a time with each later notification. Before, it was skipped.
- **Dashboard:**
  - **Readiness**: whether monitor mode has shown enough for enforce mode, as checks;
  - **Activity**: alerts, admin actions, errors, watching, by kind;
  - **Download CSV** on Messages (cells a spreadsheet would run as formulas are written as text);
  - the strength of the evidence on each email;
  - the brake and campaign hold in Settings.
- **Scale**, found by the new Firestore tests: counters that every move or checked email updated were
  single Firestore documents, which take about one write a second.
  - The brake's hourly count is split in up to 32 shards, whose limits add up to the limit exactly.
  - The campaign hold only reads once a campaign is held. Campaign move counts use an increment.
  - The daily stats are split in 10 shards, summed when read (older days' single documents count too).
- **`install.sh`:**
  - Cloud Monitoring API, the email channel and the alert policies;
  - `spruce-sync-feeds` runs hourly for the health check (still 3 jobs; the lists are downloaded once a
    day, and a failed download is tried again the next day);
  - `CAMPAIGN_HOLD_AFTER` and `ALERT_EMAIL` settings, which `upgrade.sh` adds empty.
- **Tests:** 67 (from 47).
  - `test/brakes.test.js`: the brakes, held mail, campaign decisions, the two gaps, health.
  - `test/install.test.js`: the deploy scripts against stand-ins for `gcloud` and `docker`, which were
    checked by hand before.
  - `test/firestore.test.js`: the Firestore store against Google's emulator, run in CI by a new job.
  - New dashboard routes in `test/server.test.js`.
- **Docs:** `README.md`, `docs/INSTALL.md` (settings, the brakes in enforce mode, Troubleshooting, Costs),
  `docs/DEPLOY.md` (settings), `docs/ARCHITECTURE.md`, `docs/PRIVACY.md` (what the new checks read, alert
  emails, the CSV), `docs/ROADMAP.md`.

## 0.2.14: The files that are in both repositories read right in both

Each release copies `google_service_testing` unchanged to `google_service_main`. So `CLAUDE.md`, `README.md`
and `.github/dependabot.yml` are in both, but they were written for the testing repository alone. The
service itself is the same as 0.2.13.

- **`CLAUDE.md`** says it is in both repositories, and how to tell which one you're in
  (`git remote get-url origin`).
  - The rules for each are in their own section. The release repository: nothing is developed or
    edited there. The testing repository: tests, safety defaults, made-up data, the vendored engine,
    version bumps.
  - The approval rule for `google_service_main` is unchanged. A release now only moves
    `google_service_main` forward (the two share their history since 0.2.13).
- **`README.md`** opens with the two repositories instead of "This is the testing repository".
- **Dependabot:** only security fixes now, switched on per repository (on in `google_service_testing`,
  off in `google_service_main`). Routine version updates are off: from the copy of the file in
  `google_service_main`, they opened pull requests there too.

## 0.2.13: "Update group membership now" in Settings

- **Settings → Mailboxes watched** has a button, **Update group membership now**. It re-reads the
  pilot group at once: people added are watched, people removed are no longer watched.
  - It asks Cloud Scheduler to run the daily `spruce-renew-watches` job now. The dashboard never calls
    the worker itself, which stays reachable only by Pub/Sub and Cloud Scheduler.
  - At most once a minute. Recent activity says who asked, then "Watching N mailboxes" once the job
    has run. The page updates by itself.
- **When the group was last read** shows next to the button, with whether that reached the service.
  When it didn't (as with Identity-Aware Proxy on the worker), it says so in red and points to
  Troubleshooting. Before, that showed only in Cloud Scheduler's log.
- **`install.sh`:** gives `spruce-run` the Cloud Scheduler Job Runner and Viewer roles, and tells the
  dashboard which job to run (`RENEW_JOB`). Without `RENEW_JOB`, as in a hand-made deployment that
  doesn't set it, the button isn't shown.
- **Docs:** `README.md`, `docs/INSTALL.md` (step 7, Troubleshooting), `docs/DEPLOY.md` (the two roles,
  `RENEW_JOB`), `docs/ARCHITECTURE.md`.
- **Checked:**
  - tests for the Cloud Scheduler client (run, last run, a refusal) and for the dashboard action (needs
    the dashboard header, once a minute, recorded, a refused run says why);
  - the installer against a stand-in `gcloud` (roles granted, `RENEW_JOB` in the dashboard's
    settings);
  - in demo mode with a browser: the button, its message, the second press refused, and Recent activity.

## 0.2.12: DMARC must pass to be trusted; the dashboard updates itself; Dependabot

- **The allowlist and "inside the organization" need DMARC to pass.** Both go by the From address,
  which anyone can write. Now they count only when Gmail's own DMARC check passed for that address's
  domain (`header.from` the same domain).
  - **A forged allowlisted address** is judged like any other mail. The record says "allowlisted
    sender, but DMARC didn't pass, so it was judged like any other".
  - **A forged staff address** is treated as mail from outside, so the AI score can move it. The record
    says "the address is the organization's, but DMARC didn't pass, so it isn't treated as inside".
  - Genuine staff mail is unchanged: the AI alone never moves it. Before switching to enforce, check
    in monitor mode that your own staff's mail isn't being recorded with that note. A domain with no
    DMARC record, or one whose mail fails it, would lose the "inside" exemption.
  - The AI model's input is unchanged (as the extension gives it), so AI scores stay the same.
- **The dashboard updates itself.** The page you're on is fetched again every 30 seconds while the tab
  is visible, keeping your scroll position.
  - It waits while you're using the page: typing in a field, focus on a control, a tooltip open, text
    selected, or an action under way.
  - The bar under the tabs says "Live · updated …". **Pause updates** stops it, remembered in that
    browser only. If an update fails, the page stays as it was and the bar says so.
- **Dependabot** (`.github/dependabot.yml`):
  - npm updates weekly (minor and patch together, majors one by one);
  - GitHub Actions monthly;
  - every pull request runs the tests and `npm audit --omit=dev` (`.github/workflows/test.yml`).

  Turn on **Dependabot security updates** in the repository's settings for security fixes as soon as
  they're published.
- **Docs:** `README.md` (both exemptions need DMARC, live updates, dependency updates), `docs/DEPLOY.md`
  (`ALLOW_DOMAINS`, `ALLOW_ADDRESSES`, `AI_MOVES_INSIDE`).
- **Checked:**
  - a new test: allowlisted and staff addresses with and without DMARC passing, and DMARC for another
    domain than From; it fails on 0.2.11;
  - live updates in demo mode, with a browser: a release elsewhere shows within the interval, the
    scroll position is kept, half-typed search text holds the update, and Pause and Resume work;
  - light, dark and phone width; the clickable mockup (no live updates there).

## 0.2.11: The installer keeps Identity-Aware Proxy off the worker, and checks the jobs get through

In a pilot, Identity-Aware Proxy got turned on for `spruce-worker` (it belongs on the dashboard,
`spruce-admin`, only). Pub/Sub and Cloud Scheduler can't sign in through it, so from then on every
Gmail notification and every group re-read was refused with 401 before reaching the service. That leaves
nothing in the worker's log. The dashboard showed one mailbox watched and one email checked, the state
before IAP went on.

- **Step 7/9:** if IAP is on for `spruce-worker`, `install.sh` says so and turns it off there (the
  dashboard keeps it). It also removes the IAP service agent's permission to call the worker, which only
  the dashboard needs.
- **Step 9/9:** after starting the group re-read, `install.sh` waits up to a minute for the job to reach
  the worker. If the job was refused, it stops with the reason from Cloud Scheduler's log ("UNAUTHENTICATED
  … 401") and where to look. Before, it reported success whatever happened.
- **Docs:** `docs/INSTALL.md` (Troubleshooting: "The jobs and notifications are refused", and the IAP
  steps now say "never on `spruce-worker`"), `docs/DEPLOY.md` (the same).
- **Checked** against a stand-in `gcloud`: IAP on (turned off, install goes on), job refused (stops with
  the 401), job not run yet (says so, goes on). The real `gcloud` accepts the commands' options.

## 0.2.10: No known vulnerabilities in the dependencies

The build printed "6 moderate severity vulnerabilities". `npm audit --omit=dev` now finds none.

- **Why `npm audit fix` alone didn't fix them:** they came from `glob` and `minimatch`, through `rimraf`,
  in the older Google libraries that `@google-cloud/firestore` 9.4.0 (the newest) still requires
  (`@google-cloud/firestore-api` 0.2 → `google-gax` 5 → `rimraf` 5). No release in those ranges uses
  fixed versions.
- **The fix:** `package.json` overrides `rimraf` to `^6.1.4`, which brings `glob` 14.0.4 and
  `minimatch` 11.0.5. 21 packages fewer are installed.
- **Why the override is safe:** nothing in the service loads `rimraf`, `glob` or `minimatch`. They are
  listed by those libraries but never used. The flaws they had needed an attacker's file patterns,
  which the service never passes them.
- **Still printed:** a deprecation notice for `node-domexception`, from Google's libraries. It is not a
  vulnerability, and there is no newer version to move to yet.
- **Checked:** a clean `npm ci --omit=dev` (as in the Dockerfile) on Node 22, the Firestore client
  loading, and the 44 tests.

## 0.2.9: The dashboard says which mailboxes it watches, and why

A pilot showed "Mailboxes watched: 1" and "Emails checked: 1", with nothing on the dashboard to say
why. Nothing about how mail is judged changes.

- **Recent activity: "Watching N mailboxes."** after each re-read of the pilot group (daily, after
  `install.sh`, or the `spruce-renew-watches` job). For each group it says how many entries the group
  lists, how many people are watched, and what was left out:
  - accounts that aren't active;
  - addresses outside `ORG_DOMAINS`, with their domains;
  - "all users in the organization" entries (not expanded);
  - groups inside it, whose members are listed too.

  It also says how many mailboxes couldn't be watched, and how many were stopped. Before, only errors
  were shown, so people left out for these reasons were never mentioned.
- **Settings → Mailboxes watched:** each watched mailbox, with the last time Gmail notified the service
  about it and when its watch renews. A mailbox that gets mail but shows "None yet" isn't being
  notified.
- **Worker log:** a line for each notification (`notification: 1 new in the Inbox, 1 checked`) and for
  each re-read (`renew-watches: Watching …`), without email addresses.
- **Demo:** the made-up mailboxes have notification times, and Recent activity has a "Watching" line.
- **Docs:** `docs/INSTALL.md` (what step 6 should show; mail sent to yourself isn't checked;
  Troubleshooting for fewer mailboxes than people, and for "None yet"), `README.md` (Settings).
- **Tests:** what the group re-read says (people left out and why, mailboxes that couldn't be watched or
  were stopped), what the Directory API listing counts, and the Settings list.

## 0.2.8: Fixes from a code review

None of these could move mail in monitor mode, the default. They matter before enforce mode.

- **Your own domains and the phishing lists:** a list that names your organization's whole domain or
  website (a hacked school site, say) no longer flags staff mail, or links to your own sites. Your
  domains count only as exact listed links and addresses, as in the extension, and as the Cloudflare
  check already did. Before, one such listing scored every internal email with a link to your site as
  dangerous; in enforce mode they would have been moved until the brake stopped it.
- **A failed check is tried again.** Before, a message was marked as seen before it was judged, and
  the mailbox's place moved on even when its check failed. So a phish whose move Gmail refused once
  stayed in the Inbox with no record.
  - Now a message is marked done only after it is judged and recorded.
  - Until every message in a notification is done, the mailbox's place stays, and the worker asks
    Pub/Sub to deliver the notification again (503). `install.sh` gives the subscription a retry delay
    of 30 s to 10 min.
  - After 3 failed tries the message is left where it is, with an alert, and the mailbox moves on.
  - A move whose record then failed: the next try sees the `SPRUCE/Moved` label and writes the record
    without moving the email again. Before, such an email sat in Spam with no record, and couldn't be
    released from the dashboard.
  - Gmail's "slow down" answers (403 `rateLimitExceeded`, `userRateLimitExceeded`) are tried again like
    429. A message deleted before it was read is skipped without an error.
- **Two notifications at once:** one instance at a time judges a message (a claim in Firestore; one
  left by an instance that stopped is taken over after 5 minutes). Before, both judged it, counted it
  twice, and the mailbox's place could go back. The place now only moves forward.
- **A user's rescue when history is read again:** told from the label an email arrived with by their
  history IDs (records keep the message's history ID when read). Before, a rescue in a stretch of
  history read a second time was ignored.
- **The brake:** after an admin resumes, the count starts again. Before, the moves that tripped it
  still counted, so the next move tripped it again, for up to an hour.
- **A backlog over 4,000 messages** in one mailbox is read in parts. Before, the rest was skipped with
  no alert.
- **Not changed:** the allowlist and the "inside the organization" exemption still trust the From
  address without DMARC. That is a policy decision, left for the maintainer.
- **Tests:** 44 (10 new), each failing on 0.2.7.
- **Docs:** `README.md` (lists, brake), `docs/ARCHITECTURE.md` ("Safe to repeat", the user's rescue),
  `docs/DEPLOY.md` (the subscription's retry delay), `docs/INSTALL.md` (Troubleshooting).

## 0.2.7: The install goes on when Docker can't upload

In Cloud Shell, `docker push` to Artifact Registry can fail with `dial tcp …:443: connect: connection
refused` (a Cloud Shell network problem). `install.sh` stopped there, at step 6/9.

- **Cloud Build instead:** when Docker built the image but can't upload it, `install.sh` says so and
  builds it with Cloud Build, inside Google Cloud. Without Docker, it uses Cloud Build as before.
- **`spruce-build`:** a new service account with the Cloud Build Service Account role, created in step
  3/9. Cloud Build runs as it, not as the project's default build account, whose roles differ between
  projects (in newer organizations it may have none, and builds then fail).
  - The uploaded source and the build logs go to buckets in this project's `REGION`. In `us-east1`,
    `us-central1` and `us-west1` they are within Cloud Storage's free 5 GB.
- **A failed Docker build stops the install.** Before, a failed `docker build` was missed and the
  install went on to deploy an image that didn't exist.
- **Settings files with spaces:** `stop.sh`, `rollback.sh` and `upgrade.sh` read `PROJECT = x` and
  values with trailing spaces the way `install.sh` does. Before, `stop.sh` refused such a file.
- **Docs:** `docs/INSTALL.md` (Troubleshooting for this error and for Cloud Build; the Costs table),
  `docs/DEPLOY.md` (the fourth service account).
- **Checked** against a stand-in `gcloud` and `docker`: push refused (Cloud Build used, deploy goes
  on), push works (no Cloud Build), no Docker, `docker build` failing (stops), Cloud Build failing
  (stops with what to do). The real `gcloud` accepts the new build flags.

## 0.2.6: The installer keeps the bill at zero

Google requires a billing account for Cloud Run, Cloud Scheduler, Cloud Build and Artifact Registry,
even when nothing is charged. A pilot should stay within the free tier; the installer now makes sure
someone hears about it if it doesn't.

- **Billing check first:** `install.sh` stops at once, with what to do, when no billing account is
  linked. Before, it failed later, partway through.
- **Budget alert** (`BUDGET_ALERT`, 1 by default, in the billing account's currency; `off` for none).
  - A budget for this project only, emailing the billing account's admins at 1%, 50% and 100% of the
    amount: in practice, at the first charge.
  - It's created once and updated on later runs.
  - It needs the Billing Account Administrator or Costs Manager role. Without it, the installer explains
    and carries on.
- **Image cleanup:** Artifact Registry keeps only the newest 3 builds, within the free 0.5 GB.
  `deploy/rollback.sh` can still go back 2 builds.
- **Docs:** `docs/INSTALL.md` has a "Costs" section with the free allowances against a 50-mailbox
  pilot; `DEPLOY.md` lists `BUDGET_ALERT`.
- **Upgrades** add `BUDGET_ALERT=` (the default, 1) to older settings files.
- **Checked** against a stand-in `gcloud`: a new budget, an existing one updated, billing missing
  (stops), `off`, a bad value (stops), and a valid cleanup policy.

## 0.2.5: Upgrade and rollback scripts

- **`deploy/upgrade.sh`:** run it from the new version's unzipped folder in Cloud Shell.
  - It finds the previous version's `deploy/settings.env` in your home folder (or takes the old folder
    as an argument) and copies it.
  - Settings new in this version are added empty, which means their defaults, never the example's
    values.
  - Before changing anything, it shows the installed version (read from the worker's image) and the
    new one, the `CHANGELOG.md` headings in between, and the delegation scopes this version uses. It
    asks before going on, and warns when going to an older version.
  - It then runs `install.sh` in upgrade mode, which doesn't stop at the delegation step.
- **`deploy/rollback.sh`:** sends all traffic on both services back to the previous ready Cloud Run
  revision, with the settings it had. Nothing is rebuilt. Run it again to go back further.
- **`install.sh`:**
  - moves traffic to the new build after each deploy (`update-traffic --to-latest`), so it also undoes
    a rollback;
  - in upgrade mode, keeps a service stopped by `deploy/stop.sh` stopped.
- **Docs:** `docs/INSTALL.md` has an "Upgrading to a new version" section.
- **Checked** against a stand-in `gcloud`:
  - an upgrade from a 0.2.3 folder (settings found and completed, no pause, traffic to the new build);
  - an upgrade of a stopped service (it stays stopped);
  - a rollback (it skips a revision that never became ready).

## 0.2.4: The dashboard's admins can be a group

- **`ADMIN_GROUP`:** the members of a group may use the dashboard, as well as (or instead of) the
  addresses in `ADMIN_EMAILS`. At least one of the two must be set.
  - Identity-Aware Proxy still lets them in first (granted to `group:…`). Then the service asks Google
    whether the signed-in address is in the group (`groups.hasMember`, which counts groups inside it).
    It asks as `DIRECTORY_ADMIN`, with the group-member read scope the pilot group already uses.
  - Answers are remembered for 5 minutes ("no" for 1 minute, so someone just added gets in soon).
  - Only accounts in `ORG_DOMAINS` can get in through the group.
  - If the check fails, nobody gets in through the group: the answer is 503 with the reason.
  - A group Google doesn't know is an error, not a silent "no".
- **`deploy/install.sh`:**
  - takes `ADMIN_GROUP` (the template now uses it, with `ADMIN_EMAILS` optional);
  - grants IAP to the group;
  - gives the dashboard `DIRECTORY_ADMIN`;
  - refuses to run when neither is set.
- **Docs:** `docs/INSTALL.md` creates a second security group for the dashboard; `DEPLOY.md`,
  `PRIVACY.md` and `README.md` updated.
- **Tests:**
  - listed addresses, group members, outside accounts, a failed check, and the remembered answers
    (added and removed members);
  - `hasMember`'s request, and an unknown address versus an unknown group;
  - the configuration needs `DIRECTORY_ADMIN` with a group.

## 0.2.3: Install for a test, limited to a security group

- **`PILOT_GROUP`: watch the members of a security group** (or several, separated by semicolons).
  - Groups inside it count (`includeDerivedMembership`).
  - Only active user accounts in `ORG_DOMAINS` are watched: suspended accounts, outside addresses and
    group entries are skipped.
  - Members are read daily by `renew-watches`, as `DIRECTORY_ADMIN`, with only the
    `admin.directory.group.member.readonly` scope. Removed members stop being watched.
  - `PILOT_OU` and `PILOT_USERS` still work, alone or together with a group.
- **A failed read of the pilot's members stops nothing.** Before, the error stopped the renewal
  silently; now the dashboard's Recent activity names what to check.
- **`deploy/install.sh`: one script, run from Cloud Shell, for the whole Google Cloud side.**
  - It covers APIs, Firestore, the three service accounts (no keys), Pub/Sub, a single built image for
    both services, the worker, the dashboard with Identity-Aware Proxy, the push subscription, the daily
    jobs, and the first run.
  - It pauses for the domain-wide delegation entry and prints the client ID and exact scopes.
  - Settings come from `deploy/settings.env`, read as data, never run as shell. Safe to run again: it
    updates what exists.
- **`deploy/stop.sh`** stops every watch and pauses the renewal; `install.sh` starts it again.
- **`docs/INSTALL.md`:** step by step for a test limited to a security group, with the Admin console
  steps (group, read-only directory admin, delegation), a test email, and troubleshooting.
- **The Settings page** shows the pilot group.
- **`tools/release.js`** builds the install zip.
- **Tests:**
  - group members are watched, removed members are stopped, and a failed read stops nothing and says so;
  - the members request covers nested groups, pages, the scope, and skips suspended and outside
    accounts.
- **Checked:**
  - the installer, against a stand-in `gcloud`;
  - the image, built and run in both roles: the worker refuses an unsigned push, the dashboard refuses
    anyone without Identity-Aware Proxy.

## 0.2.2: Emails a user moves back out of Spam are recorded

- **A user who takes a moved email back to the Inbox** ("Not spam", or dragging it out of Spam) is now
  seen. Before, the email stayed in the Inbox but the dashboard still showed it as in Spam.
  - The mailbox history is read for the Inbox label added back as well as for new messages
    (`historyTypes` messageAdded and labelAdded).
  - The record becomes "released", marked as by the user (`releasedByUser`), and counts as a false
    alarm unless an admin marks it phishing.
  - The service never moves that email again.
  - An alert says who moved it back. When the rules had flagged it (score 5+), it asks an admin to make
    sure it's safe, since the user may be about to click it.
- **An admin's own release** is noted on the record before Gmail is changed, so its Inbox label isn't
  counted as the user's. A message judged in the same batch as its Inbox label is not a rescue either.
- **Dashboard:**
  - The overview splits moved-back emails into by admins and by users, and has a "Moved back by users"
    figure.
  - Model health has a "By users" column per trigger.
  - Messages show "Moved back by user" and "Moved back to the Inbox by the user". When the checks had
    flagged it (score 5+) and no admin has reviewed it, the box is amber and asks for a look; the
    verdict line says it counts as a false alarm only because the user moved it back.
  - In monitor mode, the "Moved" figure also shows how many were moved back, by admins and by users.
- **Demo and mockup:** one staff member moved the fake storage notice back, with its alert.
- **Tests:** a user rescue is recorded once with its alert; an admin's release (even when its
  notification arrives mid-release) and a same-batch label are not rescues; the history request asks
  for both kinds as repeated parameters.

## 0.2.1: Cloudflare only for threat lookups (Google Safe Browsing off by default)

- **Google Safe Browsing is off unless `SAFE_BROWSING=true`,** at the maintainer's request, to be on the
  safe side about its quota and terms.
  - The code stays, and turning it on needs its API key (`SAFE_BROWSING_KEY`).
  - By default no link address leaves the district: threat lookups send only host names, to Cloudflare
    Security DNS.
  - The worker no longer needs a Safe Browsing key to start.
  - While off, links aren't sent for that lookup at all, so they don't count as "not checked".
- **Unchanged:** the phishing lists (downloaded, matched locally) and site age (domain names to their
  registries).
- **Demo mode and the mockup** now match a real deployment: no Safe Browsing findings. The fake
  storage notice is still moved, by its failed sender check, hidden filler and brand-new domain.
- **Tests:**
  - By default nothing is sent to Safe Browsing, even with a key set.
  - Cloudflare still flags links.
  - Turning Safe Browsing on without a key is refused.

## 0.2.0: network checks (Cloudflare, Safe Browsing, phishing lists, site age)

- **Cloudflare Security DNS** for link sites (where a link goes, and its own host) and the sender's
  domain (`src/intel/threats.js`):
  - Only host names are sent.
  - A 0.0.0.0 answer is a block. A name the filter says doesn't exist is asked again of Cloudflare's
    unfiltered resolver: if that one answers, it was a block; if not, the domain doesn't exist.
- **Google Safe Browsing** (Lookup API v4) for the links:
  - Up to 500 per request.
  - The `#…` part is never sent, and one-time links (the extension's `isSingleUseToken`) go without
    their query string.
  - Needs `SAFE_BROWSING_KEY` (from Secret Manager); the worker refuses to start without it unless
    `SAFE_BROWSING=false`.
- **The extension's phishing lists** (OpenPhish, Phishing Army, Sefinek scam senders;
  `src/intel/feeds.js`):
  - Downloaded once a day for the whole district by a new Cloud Scheduler task (`/tasks/sync-feeds`),
    and checked as the extension checks them.
  - Kept gzipped in Firestore (in chunks), shared by every instance, and matched locally.
- **Site age** from each domain's registry (RDAP, via IANA's list; `src/intel/rdap.js`):
  - Up to 3 unfamiliar link domains per email, plus the sender's domain.
  - Answers kept 30 days for everyone; 4 seconds at most per lookup.
- **What they change** (`src/engine/network.js`):
  - A link any check flags is dangerous, so the extension's dangerous-links weight counts it.
  - Sender's address on the scam-sender list: 5. Sender's domain blocked or listed: 5. Domain doesn't
    exist: 3.
  - Sender's domain under 30 days old: 2; a look-alike under 90 days old: 5.
  - Young link sites: the extension's `linkAgeSigns` (3 or 2).
  - A failed or slow lookup leaves things "not checked", never "safe".
  - Allowlisted senders and the organization's own sites are not looked up.
- **Not looked up:** short links (no unshorten.me or other outside unshortening service). A short link
  is judged by its own host and by what decodes offline.
- **Request limits** (`src/intel/http.js`, from the extension): a few requests at a time per service,
  and back-off after "too many requests" or repeated server errors. Answers are remembered so a
  campaign's copies cost one lookup.
- **Dashboard:**
  - Each email shows what was looked up.
  - Settings shows which checks are on, plus each phishing list's size and last update.
  - New top-reason groups: "Sender on a threat list", "Brand-new site or domain", "Made-up sender domain".
- **Demo mode** uses made-up answers for these checks (no network), so the demo shows what they add.
- **Tests:**
  - Cloudflare blocks, NXDOMAIN and failures.
  - What Safe Browsing is sent (no fragments or one-time tokens), batching, and no key.
  - List syncing once a day, sanitizing (never a protected brand's domain or a cloud-storage host),
    matching, and keeping the previous copy.
  - Registry dates, sharing, and slow registries.
  - Their effect on verdicts, including that a dead network never makes an email safer.
- **Checked once against the real services** from the development machine (not Safe Browsing: no key
  there):
  - Cloudflare blocked its own malware test domain.
  - The three lists downloaded in 1.6 s (144,400 phishing sites).
  - Three registry lookups took 0.7 s.

## 0.1.0: first testing version

- **Worker:**
  - takes Gmail notifications through Pub/Sub and reads new Inbox messages (raw) through domain-wide
    delegation, without a key file;
  - judges them with the S.P.R.U.C.E+ extension's checks and phish-tiny model (extension 5.94.6,
    model 0.4.0; `vendor/spruce/`);
  - moves to Spam when the rules flag a message, or when the AI scores 85% or more for an outside sender.
- **Safety:**
  - monitor mode by default;
  - the AI score alone never moves inside mail;
  - allowlists;
  - a brake (moves per hour) that pauses moving until an admin resumes;
  - releases recorded with who did them.
- **Dashboard** behind Identity-Aware Proxy for `ADMIN_EMAILS`:
  - overview, campaigns, users, messages with each decision;
  - Release, Mark false alarm, Confirm phishing;
  - model health and settings.
  - Plain HTML, CSS and JavaScript, light and dark, works on a phone.
- **Records** in Firestore with no email bodies, deleted after 60 days. Daily jobs renew watches and
  delete old records; a task stops every watch.
- **Two Cloud Run services from one image** (`ROLE=worker`, `ROLE=admin`).
- **Demo mode** with an invented district: every record is judged by the real engine; it refuses Cloud
  Run. `tools/build-mockup.js` makes a one-file clickable mockup of the dashboard.
- **Tests:** engine, HTML reading, policy, pipeline (fake Gmail), brake, release, watches, retention,
  authorization of every route, and the dashboard API on the demo data.
- **Known:** `npm audit` reports 6 moderate advisories in dependencies of the Firestore client library
  (`minimatch` and `rimraf` used for file-path matching, not reachable with email content);
  `npm audit fix` can't resolve them without breaking changes.
