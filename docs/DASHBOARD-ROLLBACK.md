# Rolling the dashboard back to the classic design

Version 0.6.0 redesigned the dashboard: a menu on the left (Today, Review, Threats, Mail, Health, Settings, Help),
a grouped review list, a campaign timeline and a Health page. The checks, the API and the stored data didn't change,
so the dashboard's files can be put back on their own.

The classic design (tabs: Overview, Email, Status, Settings, Help) is kept in the **`ui-classic/`** folder: its
`index.html`, `app.css` and `app.js` exactly as they were in 0.5.74, the last version with it. The folder isn't
served (the image copies only `public/`).

## Only the look (keep everything else from 0.6.0 and later)

```bash
cp ui-classic/index.html ui-classic/app.css ui-classic/app.js public/
```

The classic `app.js` works with the newer service: the review groups only gained fields it ignores. Its menu paths
("Email → Review", "Status → Activity") then differ from the ones the alerts and docs use ("Review",
"Health → Activity"). Bump the version, add a `CHANGELOG.md` entry and run `npm test` as for any change.

What it doesn't have:
- **Moderators** (0.6.1): the classic dashboard is for admins only. It reads the settings (`/api/settings`, which
  the service gives only to admins) as it starts, knows nothing of moderators, and shows everyone Status and
  Settings; the service refuses those to a moderator.
- **What was added since 0.6.1:** Health → DMARC & reputation, the Retraining examples page, the whole email in
  "Show the email" (0.6.6; the classic "…show more" shows only what the AI reads), the DMARC note under the
  evidence (0.6.4), the loading bar (0.6.5), and the slower refresh of rarely changing pages and the pause while
  you are away (0.6.7).

## The whole 0.6.0 change

```bash
git revert <the 0.6.0 commit>
```

That puts back the classic design, the old menu paths in the alerts and docs, and the review groups without their
summary. The same files are also in git history: 0.5.74 is commit `3d5b1b1235b0d25ee05044d02bdf843d135b959d`.
