# Ndu backend (starter)

A real, working API behind the Reporting and Dashboard modules — not a mockup.
Built with **zero external dependencies** (only Node's built-in modules), so
there's nothing to `npm install` — it runs the moment you have Node.js.

## What's actually working right now

- `POST /api/reports` — submit a new problem report
- `GET /api/reports` — list reports (filter with `?category=Healthcare` or `?status=unverified`)
- `PATCH /api/reports/:id` — update a report's status (unverified → verified → resolved)
- `GET /api/stats` — counts by category and status, for the dashboard
- `GET /api/categories` — the 8 fixed categories
- Two working pages: `/report.html` (submit a real report) and `/dashboard.html` (see live counts)

Data is stored in `data/reports.json` — a plain file, not a real database.
That's fine for testing and demos, but **must** be replaced before this
handles real public data (see "Next steps" below).

## Run it

```
npm install    (does nothing — no dependencies — but harmless to run)
npm start
```

or directly:

```
node server.js
```

Then open `http://localhost:3000` in a browser on the same device.

## Running this in Termux (on your phone)

Same as any other project you've set up already:

```
cd ~
mkdir -p ndu-backend
# copy these files into ~/ndu-backend (same unzip process as the website)
cd ~/ndu-backend
pkg install nodejs -y     # if not already installed
node server.js
```

Then open a browser **on the same phone** and go to `http://localhost:3000`.
(This only works on the same device for now — see "Next steps" for making
it reachable from elsewhere.)

## Testing the API directly (optional)

```
curl http://localhost:3000/api/categories

curl -X POST http://localhost:3000/api/reports \
  -H "Content-Type: application/json" \
  -d '{"category":"Healthcare","location":"Lagos","description":"Clinic out of malaria drugs"}'

curl http://localhost:3000/api/stats
```

## Security layers already in place

- **Admin key required for moderation.** Changing a report's status
  (`PATCH /api/reports/:id`) requires an `X-Admin-Key` header matching an
  `ADMIN_KEY` environment variable. If `ADMIN_KEY` isn't set, this endpoint
  is locked entirely rather than left open.
- **Rate limiting.** Each IP can submit at most 5 reports per 15 minutes.
- **Input sanitization.** Location and description are stripped of HTML
  tags and capped in length before being stored.
- **Security headers** (`X-Frame-Options`, `X-Content-Type-Options`,
  a basic `Content-Security-Policy`, `Strict-Transport-Security`) are sent
  on every response.

### Setting your admin key

**Locally / in Termux:**
```
ADMIN_KEY=choose-a-long-random-value node server.js
```

**On Render** (so moderation works on the live site too):
1. Go to your service in the Render dashboard
2. Tap the **Environment** tab (or "Environment Variables" in setup)
3. Add a variable: Key = `ADMIN_KEY`, Value = a long random string you make up
4. Save — Render will redeploy automatically

Once set, you (or a moderator) can verify/resolve a report like this:
```
curl -X PATCH https://ndu-backend.onrender.com/api/reports/REPORT_ID \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: your-admin-key-here" \
  -d '{"status":"verified"}'
```

There's no admin webpage for this yet — it's done via direct API calls
for now. A proper login-protected moderator dashboard is a good next
build once this is worth the time investment.

## Next steps (this is a starting point, not production)

In priority order:

1. **Real database.** Swap the JSON file for Postgres or SQLite before any
   real citizen data touches this. A JSON file will corrupt or lose data
   under concurrent writes — fine for one person testing, not fine for
   real users.
2. **Hosting.** Right now this only runs on whatever machine starts it.
   To make it reachable by anyone, deploy it to a real host — Render,
   Railway, or a small VPS all work well for a Node app like this and
   have free tiers to start.
3. **Duplicate detection & verification.** The trust & safety plan calls
   for this — right now anyone can submit anything with no checks.
4. **Authentication.** There's currently no login system — anyone can hit
   the API. Fine for a demo, not fine once real moderators need
   restricted access to change report status.
5. **Connect the real website to this API.** `report.html` and
   `dashboard.html` here are plain test pages — the actual Ndu website
   (the one already live on GitHub Pages) should eventually call these
   same API endpoints instead of being a static page.
