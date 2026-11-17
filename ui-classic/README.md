# The classic dashboard (before 0.6.0)

The dashboard's three files as they were in version 0.5.74, the last with the classic design (tabs: Overview,
Email, Status, Settings, Help). They are kept here, unchanged, so the old look can be put back without going
through git history. They are not served: the image copies only `public/`.

To use the classic design again, copy them over the new ones:

```bash
cp ui-classic/index.html ui-classic/app.css ui-classic/app.js public/
```

Then bump the version, add a `CHANGELOG.md` entry and run `npm test`, as for any change. More, and what else
changed in 0.6.0: `docs/DASHBOARD-ROLLBACK.md`.
