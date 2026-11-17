# Rolling the dashboard back to the classic design

Version 0.6.0 redesigned the dashboard: a menu on the left (Today, Review, Threats, Mail, Health, Settings, Help),
a grouped review list, a campaign timeline and a Health page. The checks, the API and the stored data didn't change,
so the dashboard's files can be put back on their own.

The last version with the classic design (tabs: Overview, Email, Status, Settings, Help) is **0.5.74**, commit
`3d5b1b1235b0d25ee05044d02bdf843d135b959d` on `main` (local tag `ui-classic-0.5.74`).

## Only the look (keep everything else from 0.6.0 and later)

```bash
git checkout 3d5b1b1235b0d25ee05044d02bdf843d135b959d -- public/index.html public/app.css public/app.js
```

The classic `app.js` works with the newer service: the review groups only gained fields it ignores. Its menu paths ("Email → Review", "Status → Activity") then differ from the ones the alerts and docs use
("Review", "Health → Activity"). Bump the version, add a `CHANGELOG.md` entry and run `npm test` as for any change.

## The whole 0.6.0 change

```bash
git revert <the 0.6.0 commit>
```

That puts back the classic design, the old menu paths in the alerts and docs, and the review groups without their
summary.
