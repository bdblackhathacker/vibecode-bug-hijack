# Remediation plan — siscdacc.web.app

**Audit date:** 2026-11-07  
**Target:** https://siscdacc.web.app/  
**Source of truth:** `audit-report/report.html` / `report.json`  
**Result:** 2 critical, 8 high, 6 medium, 7 low, 8 info — score 0/100, grade F

The score is deliberately harsh because two critical data-exposure findings dominate it.
Fix the critical items first; the grade will jump quickly once those are closed.

> This plan is for the site owner. Do not publish screenshots, exports, or logs that
> contain real student, parent, or staff data. The audit itself only inspected
> authorization status and field names, never field values.

---

## Priority order

| # | Priority | Work | Effort | Blocks release? |
|---|---|---|---|---|
| 1 | **P0** | Lock down Firestore: `parentMarks`, `studentPins`, `parentComm`, `teacherDirectory` | 1–5 days | **Yes** |
| 2 | **P0** | Remove client-side password auth; rotate the exposed default password | 1–3 days | **Yes** |
| 3 | **P1** | Stop storing/exporting passwords; purge existing `localStorage` copies | 2–4 hours | **Yes** |
| 4 | **P1** | Add security headers and a phased CSP | 2–4 hours | Yes |
| 5 | **P1** | Enable Firebase App Check and restrict the web API key | 1–2 hours | No |
| 6 | **P2** | Fix accessibility violations (tablist, contrast, landmarks, labels) | 1–2 days | No |
| 7 | **P2** | Cut the 1.9 MB uncacheable HTML by extracting inline JS/CSS | 2–4 days | No |
| 8 | **P3** | Low/info hardening: SRI, robots/security.txt, Referrer-Policy, COOP | 2–3 hours | No |

---

## P0 — Firestore is readable without authentication

### Evidence

Unauthenticated `GET` requests returned **HTTP 200** for:

- `schools/main/public/parentMarks` — critical (student marks / parent portal)
- `schools/main/public/studentPins` — critical (student PIN registry)
- `schools/main/public/parentComm` — high (parent communications)
- `schools/main/public/teacherDirectory` — high (staff directory)

Protected paths returned **403**, which shows rules are active elsewhere:

- `schools/main/app/state`
- `schools/main/app/marks`
- `appUsers`

Only the `updatedAt` field was requested via `mask.fieldPaths`; values were not read,
stored, or printed. The risk is the **authorization result**, not the probe content.

### Why this is critical

A client-side PIN screen is not an access-control boundary. Anyone can call the
Firestore REST API directly with the public web API key. If `studentPins` is the
source of PINs used to enter the parent portal, exposing it defeats the portal’s
login entirely. `parentMarks` and `parentComm` expose children’s academic and
communication data.

### Recommended fix — move sensitive data behind real auth

1. **Introduce Firebase Authentication** for parents, teachers, and accountants.
   - Parents: email/password or email link, one account per guardian.
   - Staff: Google Workspace / email-password with MFA where possible.
2. **Set custom claims server-side** with the Admin SDK:
   `role` (`parent`, `teacher`, `accountant`, `admin`) and `schoolId`.
   For parents, store the guardian→student mapping in a custom claim
   (`studentIds`) or in an `access/{uid}` document that rules can `get()`.
3. **Restructure data per student** instead of one shared document:
   `schools/{schoolId}/students/{studentId}` with `marks`, `comm`, and profile
   subcollections. Avoid a single `public/parentMarks` document containing everyone.
4. **Store PINs as hashes**, never plaintext. Prefer removing PINs entirely and using
   Firebase Auth. If a PIN flow is required, verify it in a Cloud Function with
   rate limiting, lockout, generic error messages, and audit logging.
5. **Deploy rules only after the client is migrated.** Locking the paths first will
   break the live portal.

### Draft rules (starting point — test in the emulator)

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    // Default deny. Any matching allow below grants access.
    match /{document=**} {
      allow read, write: if false;
    }

    // Intentionally public content only (not marks, PINs, comms, staff data).
    match /schools/{schoolId}/public/{docId} {
      allow read: if docId in ['noticeBoard', 'calendar', 'siteConfig'];
    }

    // Per-student data: owner, their guardians, teachers, admins.
    match /schools/{schoolId}/students/{studentId} {
      allow read: if request.auth != null
                  && request.auth.token.schoolId == schoolId
                  && (
                       request.auth.uid == studentId
                       || studentId in request.auth.token.studentIds
                       || request.auth.token.role in ['teacher', 'admin']
                     );
      allow write: if request.auth != null
                   && request.auth.token.schoolId == schoolId
                   && request.auth.token.role == 'admin';
    }

    // Staff-only data.
    match /schools/{schoolId}/staff/{docId} {
      allow read: if request.auth != null
                  && request.auth.token.schoolId == schoolId
                  && request.auth.token.role in ['teacher', 'accountant', 'admin'];
    }

    // App state: authenticated staff only.
    match /schools/{schoolId}/app/{docId} {
      allow read, write: if request.auth != null
                          && request.auth.token.schoolId == schoolId
                          && request.auth.token.role in ['accountant', 'admin'];
    }
  }
}
```

Notes:

- Firestore rules are **additive**: the default-deny block does not override a
  specific allow. Keep the specific matches narrow.
- `request.auth.token.studentIds` requires setting the claim server-side when a
  guardian account is created or linked.
- `get()`/`exists()` in rules cost reads. Prefer custom claims for hot paths.
- Also review **Storage** and **Realtime Database** rules; this audit did not test them.

### Emergency stopgap

If the app cannot be migrated this week, the only safe stopgap is to disable public
reads on the four paths **and accept that the parent/teacher portal will stop working**
until the replacement flow ships. Do not leave the data public while “working on it.”
A Cloud Function proxy with App Check and rate limiting is an alternative, but it still
requires client changes.

### Verify

```bash
# Expect 401/403 after the fix. Do not add fields or print values.
curl -s -o /dev/null -w '%{http_code}\n' \
  'https://firestore.googleapis.com/v1/projects/siscdacc/databases/(default)/documents/schools/main/public/studentPins?mask.fieldPaths=updatedAt'
```

Then rerun the audit with `--firebase-probe`; the two critical findings should disappear.

---

## P0 — Client-side password authentication

### Findings

| Code | Issue |
|---|---|
| `CLIENT_SIDE_PASSWORD_CHECK` | Accountant login compares the password in browser JS: `document.getElementById('loginPassword').value !== getPassword()` |
| `CLIENT_DEFAULT_PASSWORD` | Hard-coded fallback password in source (redacted in the report; length 10) |
| `STORAGE_SENSITIVE_LOCALSTORAGE` | Password written to `localStorage`: `localStorage.setItem(PASSWORD_KEY, p)` |
| `PASSWORD_IN_BACKUP` | Backup export includes `password: localStorage.getItem(PASSWORD_KEY)` |

Anyone can read the JS, call the panel functions from DevTools, or read
`localStorage`. This is a UX lock, not authentication.

### Fix

1. **Rotate the default password immediately.** It is public in the deployed source.
   Changing it does not fix the root cause, but it closes the known credential.
2. **Replace the local comparison with Firebase Auth.**
   - Create an accountant account (or use a staff account with an `accountant` claim).
   - On login, call `signInWithEmailAndPassword(auth, email, password)`.
   - Gate the panel on `onAuthStateChanged` and the ID token claim
     (`role === 'accountant' || role === 'admin'`), not a boolean in memory.
   - Enforce the same role in Firestore rules and any callable functions.
3. **Delete the fallback constant** and any `getPassword()` helper.
4. **Remove password persistence.**
   - Delete `localStorage.setItem(PASSWORD_KEY, ...)` and every read of it.
   - On startup, run `localStorage.removeItem(PASSWORD_KEY)` once to clean devices
     that already have the old value.
   - Do not replace it with a plaintext PIN or “remember me” password. Use Firebase
     Auth’s built-in persistence (`browserLocalPersistence` / `indexedDBLocalPersistence`)
     and sign out on shared devices.
5. **Fix the backup exporter.**
   - Remove `password` (and any PIN/token) from the exported object.
   - Bump the backup schema version and add `exportedAt` / `appVersion`.
   - Treat previously downloaded backups as compromised; rotate credentials.
6. **Harden the login form.**
   - `autocomplete="current-password"`, `type="password"`, no password in URLs or logs.
   - Add rate limiting/lockout in the backend for any PIN or password verification.
   - Use generic “invalid credentials” errors.

### Search the source for

`PASSWORD_KEY`, `getPassword`, `loginPassword`, `doFirebaseLogin`,
`localStorage.setItem`, `backup`, `export`, `JSON.stringify`.

---

## P1 — Security headers and CSP

Current state: HSTS is present and TLS is valid, but the response has **no CSP**,
`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`,
`Permissions-Policy`, or COOP.

### Firebase Hosting `firebase.json`

```json
{
  "hosting": {
    "public": "dist",
    "headers": [
      {
        "source": "**",
        "headers": [
          { "key": "X-Content-Type-Options", "value": "nosniff" },
          { "key": "X-Frame-Options", "value": "DENY" },
          { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
          { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=(), payment=()" },
          { "key": "Cross-Origin-Opener-Policy", "value": "same-origin-allow-popups" }
        ]
      },
      {
        "source": "/assets/**",
        "headers": [
          { "key": "Cache-Control", "value": "public, max-age=31536000, immutable" }
        ]
      }
    ]
  }
}
```

- Use `Cross-Origin-Opener-Policy: same-origin` if you do **not** use Firebase
  `signInWithPopup`; `same-origin-allow-popups` keeps Google sign-in popups working.
- Deploy, then verify with `curl -sI`.

### CSP, phased

The page has ~1.6 MB of inline JS and 379 inline handlers, so a strict CSP cannot be
enabled in one step. Do not add `'unsafe-inline'` and call it done.

**Phase 1 (today): enforce the directives that cannot break the app**

```text
Content-Security-Policy: frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'
```

This blocks framing/clickjacking and plugin/base-tag abuse immediately.

**Phase 2 (report-only, 1–2 weeks): observe what the app actually loads**

```text
Content-Security-Policy-Report-Only: default-src 'self';
  script-src 'self' 'unsafe-inline' https://www.gstatic.com https://apis.google.com https://www.google.com https://www.recaptcha.net;
  connect-src 'self' https://*.googleapis.com https://*.firebaseio.com wss://*.firebaseio.com;
  img-src 'self' data: https:;
  style-src 'self' 'unsafe-inline';
  frame-src https://siscdacc.firebaseapp.com https://accounts.google.com https://www.google.com;
  frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'
```

Collect violations (add `report-uri`/`report-to` if desired), then remove domains you
do not need. If you add a nonce or hash, remove `'unsafe-inline'` from that directive —
browsers ignore `'unsafe-inline'` when a nonce/hash is present.

**Phase 3 (enforce): extract inline JS/CSS and remove inline handlers**

- Move `<script>` blocks into hashed `/assets/app.<hash>.js`.
- Move `<style>` into `/assets/app.<hash>.css`.
- Replace `onclick="..."` with `addEventListener` in the external bundle.
- Then set `script-src 'self' https://www.gstatic.com ...` without `'unsafe-inline'`.
- Self-hosting the Firebase SDK is even better: fewer third-party origins and SRI works.

Start with report-only; do not deploy a strict `script-src` blind.

---

## P1 — Firebase platform hardening

### App Check (`FIREBASE_APPCHECK_MISSING`)

1. Firebase Console → App Check → register the web app with reCAPTCHA Enterprise.
2. Initialize App Check in the app **before** other Firebase SDK calls.
3. Monitor for 1–2 weeks, then enforce for Firestore and Auth.
4. App Check reduces scripted abuse but is **not** a substitute for Security Rules.

### Restrict the web API key (`SECRET_GOOGLE_API_KEY`, informational)

The Firebase web API key is not a secret, but it should be restricted:

- Google Cloud Console → APIs & Services → Credentials → the browser key.
- Application restrictions: HTTP referrers for `https://siscdacc.web.app/*`
  (and localhost only during development).
- API restrictions: only the APIs the app uses (Identity Toolkit, Firestore,
  Firebase Installations, etc.).

### SRI / third-party scripts (`SRI_MISSING`)

The three Firebase compat scripts from `www.gstatic.com` have no `integrity`.
Options:

- Self-host the pinned SDK files and add `integrity` + `crossorigin`, or
- If keeping the CDN, add `integrity="sha384-..."` and `crossorigin="anonymous"`.

Generate a hash with:

```bash
curl -sS https://www.gstatic.com/firebasejs/10.12.5/firebase-app-compat.js \
  | openssl dgst -sha384 -binary | openssl base64 -A
```

Re-check the hash whenever the version changes; pin exact versions, never `latest`.

---

## P2 — Accessibility

### 1. `.portal-switch` tablist (`AXE_ARIA_REQUIRED_CHILDREN`, high)

The element has `role="tablist"`, but its children are plain buttons with
`tabindex` and no `role="tab"`. Pick one:

- **Keep the tab pattern:** add `role="tab"`, `aria-selected="true|false"`,
  `aria-controls="panel-id"`, and `id` to each button. Give panels
  `role="tabpanel"` and `aria-labelledby`. Implement arrow-key navigation and
  roving `tabindex` (selected `0`, others `-1`).
- **Or remove `role="tablist"`** if this is only a visual segmented control and
  the buttons switch sections without a tab interaction model.

### 2. Login button contrast (`AXE_COLOR_CONTRAST`, medium)

White text on `#10b981` measures **2.53:1**; WCAG AA needs 4.5:1 for normal text.
Change the background to a darker green such as `#047857` (emerald-700) or
`#065f46` (emerald-800), or use dark text. Re-run axe to confirm.

### 3. Landmarks (`AXE_REGION`, low; 12 nodes)

- Wrap page content in `<header>`, `<nav>`, `<main>`, `<footer>`.
- The login modal should be `role="dialog"`, `aria-modal="true"`,
  `aria-labelledby="<title-id>"`, with a focus trap and focus returned to the
  trigger on close.
- Do not put the whole app inside one generic `<div>`.

### 4. Labels (`FORM_LABELS_STATIC`, info; 227 controls)

Many controls are in hidden tab panels, but visible ones still need names.
Use `<label for="...">`, `aria-label`, or `aria-labelledby`. A placeholder is
not a label. Prioritize the login modal and the primary data-entry forms.

### 5. Password autocomplete (`PASSWORD_AUTOCOMPLETE`, low)

```html
<input id="loginPassword" type="password" autocomplete="current-password" ...>
```

Use `new-password` on registration/change-password fields.

### Manual checks after fixes

- Tab through the entire login and one data-entry flow; focus must always be visible.
- Open the modal, press Escape, confirm focus returns to the trigger.
- Test at 200% zoom and at 390 px width.
- Re-run the audit; axe findings should drop to zero (or only documented exceptions).

---

## P2 — Performance: the 1.9 MB page

### Findings

- HTML: **1,912,534 bytes**
- Inline JS: **1,600,207 bytes** (84% of the document)
- Inline CSS: **142,249 bytes**
- `Cache-Control: no-cache, no-store, must-revalidate`
- External scripts: 3 (Firebase compat SDKs)
- No external stylesheets

Every navigation re-downloads ~1.9 MB, and the browser cannot cache any of the
inline code. On a slow school connection this is a real usability problem.

### Fix, in order of impact

1. **Extract inline JS/CSS into static files.**
   - Build with Vite/esbuild (or a small script): `app.<hash>.js`, `app.<hash>.css`.
   - Serve under `/assets/` with `Cache-Control: public, max-age=31536000, immutable`.
   - Keep the HTML shell small (< ~100–200 KB) and use `no-cache` (not `no-store`)
     so the browser can revalidate with the existing ETag and get a 304.
2. **Minify and bundle.** Remove dead code, duplicate helpers, and unused panels.
   Consider code-splitting by role (parent / teacher / accountant) and lazy-loading
   Firebase SDKs or admin-only modules.
3. **Remove inline event handlers** (379 of them) as part of the extraction; this
   also unblocks CSP.
4. **Enable Brotli** at Firebase Hosting (usually automatic for static assets) and
   confirm with `Content-Encoding: br`.
5. **Measure again** with Lighthouse and the audit’s performance metrics:
   target HTML < 300 KB, total JS < 500 KB gzipped, LCP < 2.5 s on a throttled
   “Slow 4G” profile.

Caching nuance: `no-store` forbids storing the response at all, so the ETag cannot
save a repeat download. `no-cache` allows storage but requires revalidation, which
returns a cheap 304 when unchanged. Use `no-cache` for the HTML shell and immutable
caching for hashed assets.

---

## P3 — Low/info quick wins

- [ ] `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer`).
- [ ] `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`.
- [ ] `Cross-Origin-Opener-Policy` after testing popups.
- [ ] `robots.txt`: for a private portal, `User-agent: *` + `Disallow: /` and an
      `X-Robots-Tag: noindex` header. Do not index student data.
- [ ] `/.well-known/security.txt` with a monitored security contact.
- [ ] Add `autocomplete="current-password"` (see accessibility).
- [ ] Remove inline handlers when extracting JS (see performance/CSP).
- [ ] Keep HSTS and TLS as-is; certificate has ~80 days left at audit time.

---

## Verification checklist

Run after each batch of fixes:

```bash
# 1. Headers
curl -sI https://siscdacc.web.app/ | grep -iE \
  'content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|cross-origin-opener-policy|cache-control'

# 2. Sensitive Firestore paths (expect 401/403)
for p in parentMarks studentPins parentComm teacherDirectory; do
  printf '%s -> ' "$p"
  curl -s -o /dev/null -w '%{http_code}\n' \
    "https://firestore.googleapis.com/v1/projects/siscdacc/databases/(default)/documents/schools/main/public/$p?mask.fieldPaths=updatedAt"
done

# 3. Full audit
.venv/bin/python site_audit.py https://siscdacc.web.app/ \
  --firebase-probe --fail-on high --out audit-report

# 4. Browser-only accessibility/performance pass
.venv/bin/python site_audit.py https://siscdacc.web.app/ --headed --fail-on none
```

**Definition of done for P0/P1:**

- [ ] All four sensitive Firestore paths return 403 without auth.
- [ ] No password/PIN comparison exists in client JS.
- [ ] No password/PIN is written to `localStorage`, `sessionStorage`, or exports.
- [ ] Default password rotated; old backups treated as compromised.
- [ ] Accountant panel requires a valid Firebase Auth session with the right claim.
- [ ] CSP enforced for `frame-ancestors`, `object-src`, `base-uri`, `form-action`;
      full CSP report-only and trending toward enforcement.
- [ ] `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
      `Permissions-Policy`, COOP present.
- [ ] App Check enforced for Firestore/Auth; API key restricted by referrer/API.
- [ ] Audit rerun shows 0 critical and 0 high (or every remaining high is explicitly
      accepted and documented).

---

## Suggested sequence

**Day 1 (hours):**
Rotate the default password; remove password storage and backup export; clean
`localStorage`; add the four low-risk security headers; fix the login contrast and
tablist roles.

**Days 2–5:**
Design and implement Firebase Auth + custom claims; restructure sensitive documents;
add per-student access rules; test in the Firestore emulator; migrate the client reads.

**Week 2:**
Deploy rules after the client is ready; verify 403s; enable App Check in monitor mode;
start CSP report-only; extract inline JS/CSS.

**Week 3:**
Enforce App Check; enforce CSP `script-src`; finish labels/landmarks; rerun the full
audit and Lighthouse; document accepted risks.

---

## Scope and limitations

- The audit was non-destructive: no logins, form submissions, data changes, brute
  force, or exploit payloads.
- It tested the public page and known Firestore paths. It did **not** test Storage
  rules, Realtime Database rules, Cloud Functions, payment flows, or authenticated
  pages.
- To audit authenticated pages, use:
  `.venv/bin/python site_audit.py https://siscdacc.web.app/ --save-auth auth.json`
  then rerun with `--storage-state auth.json`.
- `auth.json` contains live session material. Keep it private and delete it when done.
- Re-run the audit after fixes; save the old report for comparison.
