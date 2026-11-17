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

The classic dashboard is for admins only: it reads the settings (`/api/settings`, admins only) as it starts, and
the service refuses moderators (0.6.1) most of what it shows. The pages and views added since 0.6.1 aren't in it:
Health → DMARC & reputation, Retraining examples, the whole email in "Show the email" (0.6.6), the DMARC note
under the evidence (0.6.4) and the loading bar (0.6.5).
