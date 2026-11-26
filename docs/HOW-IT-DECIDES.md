# How every email is judged: phishing, spam or safe

Two independent readers look at each email: the **rule checks**, which score what they can prove, and the **AI model**,
which reads the email the way a person would. A fixed policy (`src/policy.js` `decide`, then `src/pipeline.js` `judge`)
turns their findings into one outcome, and the answers people give in Review teach it over time. This page is the
overview to show colleagues; `docs/ARCHITECTURE.md` has the details. Every example here is made up.

## The decision map

Each question is asked in order. The first "yes" decides the outcome; every "no" falls through to the next question.
Both kinds of checks run on every email before the first question about the outcome.

![Decision map: an email arrives; phishing-training mail is let through; the rule checks and the AI score it; then in order: a confirmed Trusted sender is left alone, a move rule moves it as phishing, a spam rule moves it as spam, a suspicious sign keeps it in the Inbox for Review, confirmed marketing goes to Review's Promotional list, and anything else is safe.](images/decision-map.svg)

Thresholds as shipped: rule points 3 = suspicious, 5 = move. The AI lines are set in Settings → Policy (suspicious from
65%, move from 90% by default). Mail from inside your organization is never moved on the AI score alone.

| Outcome | What happens | When |
|---|---|---|
| **Phishing** | Moved to the Spam folder (monitor mode: recorded as "would move") | Rule points 5 or more, or the AI's phishing score at the move line for an outside sender, or a Skip review sign you chose |
| **Spam** | Moved to the Spam folder as spam | A sender on Spam senders, padded list mail, or the AI's spam score at the move line from a sender Gmail couldn't confirm; never mail from inside |
| **Suspicious** | Stays in the Inbox, listed in Review; looked at again an hour and a day later | Rule points 3 or more, or the AI at the suspicious line (under the move line) |
| **Promotional** | Never moved; Review → Promotional, one answer per company | Marketing from a sender Gmail confirmed (Gmail's Promotions tab, or a signed one-click unsubscribe) |
| **Safe** | Left alone; nothing is recorded about an ordinary safe email | Nothing to act on, or a sender on Trusted senders that Gmail confirms (DMARC) and the 30-day check hasn't suspended |

## What the rule checks look at

Each check that finds something adds points, and the email's total decides as shown on the map. A few signs need
nothing else: a link on a phishing list or an imitated brand is enough to move an email on its own.

- **Your Google Workspace directory:** every 12 hours the service reads the staff names in your directory (Admin SDK)
  and turns them at once into one-way hashes; no list of names is kept. An outside address using a staff member's name
  ("the superintendent" writing from a free-mail account) counts 3 points on its own, enough to make it suspicious, and
  the AI is told the name claims to be a colleague. Your own name in your own mail never counts. The directory also says
  which mailboxes are watched (Settings → Mailboxes).
- **Sender:** Gmail's DMARC, SPF and DKIM results, forged or spam-flagged headers, a forged Message-ID, and a "RE:" that
  answers nothing in the mailbox (a fake reply chain).
- **Imitation:** a brand's name on an address that isn't the brand's (unless your reviewers confirmed that sender: Brand
  senders), and look-alikes of your own domain, which a daily watch finds as soon as they are registered.
- **Links:** phishing lists downloaded daily, Google Safe Browsing, Cloudflare's malware blocking, Spamhaus and abuse.ch
  when turned on, the site's age, hidden decoy links, and link text that names a different site.
- **Attachments:** the kinds of files, and the links inside them: QR codes in pictures and links in documents are read and
  checked like any other link.
- **History and shares:** the first email from an address to anyone in your organization counts a little. A Drive or
  DocuSign share is judged by the person who shared it, and one outside account sharing with many of your people within
  an hour raises an alert.

## What can still change the outcome

After the map gives its answer, a few safeguards can soften or hold it. None of them can make a forged sender look real:
each requires Gmail's DMARC check to pass, or applies only to moving.

- **Monitor mode** (the default while you evaluate): every "move" is recorded as "would move".
- **Remembered answers:** when an admin marks an email safe, identical copies to anyone are answered the same way for 90
  days; a dismissed campaign works the same.
- **Sender standing** (Settings → Policy): a sender that has mailed you the same way for a month, or one an admin marked
  safe, isn't flagged or moved on the AI score alone. Any rule sign, a new link site or a new Reply-To cancels it.
- **The brakes:** too many moves in an hour stops all moving until an admin resumes; a large campaign on weak evidence is
  paused after a few copies for an admin's decision.
- **Re-checks:** when a phishing list adds a site, a look-alike of your domain appears, or an update changes the checks,
  delivered mail still in the Inbox is checked again and moved if it should be.
- **Staff mail:** mail from your own domains, with DMARC passing, is moved only by the rules (a staff account taken over),
  unless you change that setting.
- **Readers' reports** (Settings → User reports): an email a reader reports with Gmail's own Report phishing is listed in
  Review → Reported for an answer, even from a trusted sender.
- **Spam learning** (Settings → Policy): for the days you choose, marketing the AI is all but sure is spam goes to Spam and
  its sender to Spam senders, until someone takes its mail back out.
- **Alerts:** the brakes, a held or large campaign, a mass share, a new look-alike of your domain and a suspended Trusted
  sender are emailed to the admins (`docs/ALERTS.md`).

## How the AI reads an email

The model is **phish-tiny**, a small language model trained only for this job (an ELECTRA-small network: 12 layers,
13.5 million weights, 14 MB). It runs inside the service on your own Google Cloud project, about 70 milliseconds per
email, and nothing about the email is sent anywhere else to score it.

![The AI pipeline: the email's facts and text are written as one passage with addresses and numbers hidden, cut to 256 word pieces, read by 12 layers in which every word piece weighs every other, and turned into a phishing answer and a spam answer, which become three shares (genuine, spam, phishing) adding up to 100%. The service compares the phishing share with the suspicious and move lines.](images/ai-pipeline.svg)

The AI gives a probability, never a verdict on its own: the decision map decides what happens, and the rule checks can
override it either way.

What the AI actually reads, for a made-up statement email:

```
subject: Your statement is ready. from: "Madeup Bank Alerts" at mail.madeupbank.example (outside your organization)
(shared mailbox). sender check: dmarc pass. links: "View statement" goes to secure.madeupbank.example. text: Hi your
name, your November statement for the account ending in number is now available. Sign in to view it online.
```

| Term | Meaning |
|---|---|
| from | The sender's display name and only the domain of the address |
| shared mailbox | The sender's address is a team or role address (alerts@, no-reply@), not one person's; it never describes who received it |
| sender check | Gmail's DMARC result: "pass" means the address really belongs to that domain |
| identity | When present: who the sender's name claims to be (a brand, or a colleague found in your directory) and whether the domain is really theirs |
| links | Each link's visible words and the site it really goes to, with what the link checks found |
| your name, number | The reader's name and every phone or account number are replaced before the AI reads anything |

To explain itself, the dashboard (Show the email → What the AI reads) also scores each sentence on its own and marks the
ones that weighed most. A single line can read like phishing out of context ("click here to accept"); the score for the
whole email is the one that counts.

### What the next model will also read

Since 0.6.85 the service also gathers, for every email it records, what it knows beyond the email's own words, so the next
model can be trained on them (the current one doesn't read them yet, so nothing it decides has changed):

| Fact | What it tells the AI |
|---|---|
| Gmail's category | Primary, Updates, Promotions, Social or Forums: Gmail's own reading of the sender's mail |
| Unsubscribe marker | A one-click unsubscribe the sender signed (bulk mail must have one), or a plain unsubscribe header |
| Mailing service | The service that sent it for the company (from its verified signature or its link tracking) |
| Sender history | A first email; or how long the sender has written to your organization and how often, an admin's earlier answer, and **what differs this time** (a new signing domain, mail service, Reply-To or link site, an attachment). A known sender writing unlike itself is how an account taken over looks, so history alone never makes an email look safe |
| Conversation | A real answer to the reader's own email, or a "RE:" that answers nothing in the mailbox |
| How many got it | Copies of the same email your people received that day, so far |
| Domain age | How long ago the sender's domain was registered |
| Words in documents and pictures | The text of attached PDFs and Office files, and the words in up to two pictures (read on the service itself; for the retraining export only, never stored) |

Links are already given to the AI as where they really go: Safe Links, Proofpoint, Google and Bing redirects and the other
wrappers the link checks know are decoded first. The page behind a link isn't fetched.

## How the AI learned

The model learns by example: it is shown emails whose answer is known, and its weights are nudged until its answers
match. A new version replaces the old one only if it does better on emails it never saw in training.

![Training: four sources of examples (made-up emails, published warnings paraphrased, research collections with people removed, and the district's own reviewed emails kept on one computer) train fifteen runs, which are averaged into one model; it must pass the release checks on held-out emails before a program uses it.](images/ai-training.svg)

Your district's examples come from the retraining export (Health → Retraining examples; `docs/RETRAINING.md`) and are
used only on the computer that trains the model. The published model carries what it learned, never the emails.

## What it can't do

- **English only:** an email clearly in another language gets no AI score; the rule checks still read it.
- **It doesn't open links or forms:** it sees where a link goes, not the page behind it. A rogue form on a trusted site is
  judged by its wording, the share's sender and the link checks.
- **It sees domains, not people:** it never reads full addresses or numbers.
- **It knows mail, not your history:** a real company's statement and a lure with the same words look alike to it. Sender
  standing and Review answers supply what it can't know.

*Describes S.P.R.U.C.E Mail Protection Service 0.6.85 with the phish-tiny 0.29.0 model.*
