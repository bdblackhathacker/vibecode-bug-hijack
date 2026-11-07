# site_audit.py — real-world website bug finder

A non-destructive Python audit for a live website. It connects from your own
machine, loads the site in a real Chromium browser, and produces a report with
evidence and fixes.

Built for and first run against **https://siscdacc.web.app/**.

## What it checks

| Area | Checks |
|---|---|
| HTTP / TLS | status, redirects, HTTP→HTTPS, certificate expiry, HSTS, compression, cache policy |
| Security headers | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORS, cookie flags |
| Static HTML/JS | duplicate IDs, missing labels/alt text, mixed content, SRI, inline handlers, password fields, secrets, client-side auth, Firebase config |
| Real browser | console errors, uncaught exceptions, failed requests, HTTP 4xx/5xx resources, blank page, `undefined`/`NaN` text, DOM/performance metrics |
| Accessibility | axe-core 4.10 WCAG scan with selectors and remediation links |
| Responsive | horizontal overflow at 390 / 768 / 1440 px, touch targets below 24×24 px |
| Links / PWA | broken links and assets, Content-Type mismatches, manifest, icons, fragments |
| Firebase (opt-in) | unauthenticated Firestore read probe using **masked fields only**; reports authorization status and field names, never values |

It does **not** submit forms, change data, brute-force credentials, or run
exploit payloads.

## Install

Python 3.10+ recommended.

```bash
cd /path/to/bugg
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium
```

On a minimal Linux server you may also need:

```bash
python -m playwright install --with-deps chromium
```

## Run it against the site

```bash
python site_audit.py https://siscdacc.web.app/
```

Open the report:

```bash
xdg-open audit-report/report.html      # Linux
open audit-report/report.html          # macOS
start audit-report\report.html         # Windows
```

Watch the browser run locally (useful for debugging):

```bash
python site_audit.py https://siscdacc.web.app/ --headed
```

Useful options:

```text
--firebase-probe       read-only Firestore rules check (see warning below)
--no-browser           HTTP/static checks only, faster in CI
--fail-on high         exit 1 if high/critical findings exist (default)
--fail-on none         always exit 0
--max-links 150        check more links/assets
--no-external          only check same-origin URLs
--timeout 30           per-request timeout
--wait 5000            wait longer for a slow SPA to settle
--out my-report        output directory
```

## Testing pages behind a login

The audit is read-only, but many bugs are only visible after login. Export an
authenticated browser session once:

```bash
python site_audit.py https://siscdacc.web.app/ --save-auth auth.json
```

A Chromium window opens. Log in normally, wait for the dashboard, then press
Enter in the terminal. The session (cookies + localStorage) is saved to
`auth.json` and is **not** included in the report.

Then audit with that session:

```bash
python site_audit.py https://siscdacc.web.app/ \
  --storage-state auth.json \
  --firebase-probe
```

`auth.json` contains live session credentials. Keep it private and delete it
when finished. You can also pass a single cookie:

```bash
python site_audit.py https://siscdacc.web.app/ --cookie "session=abc123"
```

## Firebase / Firestore probe warning

`--firebase-probe` is opt-in because it talks to the production Firestore REST
API. For each known path it performs **one GET request** with
`mask.fieldPaths=updatedAt`. That means Firestore returns only the
`updatedAt` field name/status, not student marks, PINs, names, or other data.
The report records:

- HTTP status
- whether the path is readable without authentication
- field names only

It never prints or stores field values.

Use it only on a site you own or are explicitly authorized to test. If a path
is publicly readable, fix the Firestore Security Rules before doing anything
else.

## Reports

Each run writes to `audit-report/`:

- `report.html` — readable report with severity filters and screenshots
- `report.json` — machine-readable results for CI/dashboards
- `report.csv` — spreadsheet-friendly findings
- `screenshot-desktop.png`, `screenshot-mobile.png` — visual evidence

The console prints a score, severity counts, and the top findings. Exit code is
`1` when a finding at or above `--fail-on` exists, `2` on an audit error, and
`0` otherwise. This makes it usable in CI:

```bash
python site_audit.py https://siscdacc.web.app/ \
  --no-browser --fail-on high --out audit-report
```

## Notes and limitations

- The score is a prioritization aid, not a certification. A site with public
  student data and a hard-coded default password correctly scores very low.
- Static checks are heuristics; browser axe results and manual confirmation are
  more reliable for accessibility.
- Headless Chromium cannot test every browser/device combination, CAPTCHAs,
  third-party payment flows, or destructive business actions.
- The tool intentionally avoids form submissions and data mutation. Test those
  flows manually in a staging environment with test accounts.
- `--insecure` disables certificate validation for staging only. Never use it
  against production.
