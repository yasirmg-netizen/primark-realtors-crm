# Primark Realtors CRM — your own, private real estate CRM

This is not a subscription product. It is a small piece of software — one that
I (Claude) wrote for you — that you host yourself, with no credit card
required anywhere in the setup. Nobody else's company can see your leads,
your calls, or your team's activity.

## What's in this folder

- `server.js`, `db.js`, `auth.js` — the backend (stores data, checks logins)
- `public/index.html` — the app itself, what your team sees in the browser
- `render.yaml` — deployment configuration for Render (the app host)

## The two free, card-free services this uses

- **Render** — runs the app itself. Free, no card, but the app "falls asleep"
  after 15 minutes with nobody using it, and takes 30-60 seconds to wake up
  on the next visit. For a small internal sales tool, this is a fair trade.
- **Turso** — holds your database (every lead, every comment). Free, no card,
  and — unlike some other free databases — it does not expire or get wiped.

Between the two: Render never sees inside your database, and Turso never sees
your application code. Your data is queried only by code I wrote, running
under logins only your team has.

## What's new in this version

- **Duplicate lead detection.** Adding a lead now checks the phone number against every existing lead in the system (not just your own) and warns you before you create a duplicate. CSV imports flag likely duplicates in the preview too.
- **"My Day" view.** A new tab showing just today's (and overdue) follow-ups and today's site visits - no need to scan the full leads list every morning.
- **Auto-routing.** New leads that arrive via webhook (Instagram, Facebook, or the generic integration) are automatically assigned to whichever active rep currently has the fewest open leads, instead of sitting unassigned.
- **WhatsApp message templates.** Four starter templates (follow-up, site visit reminder, thanks-for-visiting, documents pending) - pick one from the lead drawer and it opens WhatsApp with the message already written, client's name and property filled in automatically.
- **Backup reminder.** The super admin's dashboard shows a gentle nag if it's been 7+ days since the last full export, linking straight to the download. No new service involved - just a visible reminder.
- **Add to Home Screen tip.** Shown once on mobile, dismissible, encouraging one-tap access from the phone's home screen.
- **Phone/email validation.** Obviously malformed entries are caught both in the browser (instant feedback) and on the server (so it can't be bypassed).

- **Bulk export locked to super admin.** Only a super admin sees or can use the "Download all leads" button (Reports tab), and the server itself refuses the request from anyone else - not just a hidden button.
- **Audit trail on every lead.** Any change to a lead's status, assignment, deal value, or other field is logged automatically with who changed it and when, shown right in that lead's activity log alongside comments.
- **Blocking access.** This already existed: from the Team tab, an admin can "Block access" for a rep, and a super admin can block anyone. A blocked login stops working immediately.
- **Marketing platform integrations.** Two ways to feed leads in automatically - see below.

### Connecting marketing platforms

**Option A - generic webhook (fastest to set up today).**
Works with Zapier, Make/Integromat, Typeform, most landing page builders, or
anything that can send a JSON web request. Steps:
1. Make up a long random password-like string and set it as `WEBHOOK_SECRET` in Render's environment variables.
2. In your other tool (e.g. a Zapier "Webhook" action), point it at:
   `https://your-app-url.onrender.com/api/webhooks/inbound?token=YOUR_SECRET&source=Instagram`
   (change `source` to `Facebook`, `Google Ads`, `Website`, etc. as needed)
3. Have it send a JSON body with `name`, `phone`, and `email`.

This is genuinely the easiest path for Google Ads specifically - Google Ads'
own API requires a lengthy developer approval process (often weeks) for
direct access. Zapier and Make already have a ready-made "Google Ads Lead
Form" trigger, so routing through one of those into this webhook gets you
automated Google Ads leads today without waiting on Google.

**Option B - native Instagram/Facebook connection (no middleman).**
This talks to Meta directly, but requires you personally to do some setup on
Facebook's side (only you can do this, since it needs your Page/Business
account):
1. Go to developers.facebook.com and create an App, add the "Webhooks" and
   "Lead Ads" products.
2. Under Webhooks, subscribe to the `leadgen` field for your Page, and set
   the callback URL to `https://your-app-url.onrender.com/api/webhooks/meta`
3. Set a verify token of your choosing on Facebook's side, and also set it
   as `META_WEBHOOK_VERIFY_TOKEN` in Render.
4. Get your App Secret (from the App's Basic Settings) and set it as
   `META_APP_SECRET` in Render.
5. Generate a long-lived Page Access Token for your Page and set it as
   `META_PAGE_ACCESS_TOKEN` in Render.

**Come back to me for this step** - Facebook's app review and permissions
can be fiddly, and I can walk you through whatever screen you're stuck on.
Once it's connected, new Instagram/Facebook lead-form submissions land in
your CRM automatically, unassigned, ready for an admin to assign to a rep.

## Setup, one step at a time


We'll go through this together, one step per message. Don't worry about
doing everything below in one sitting — come back to me at any point and
say "what's next" or paste any error you see.

### Step 1: Create a free Turso account and database
1. Go to turso.tech and sign up (no card needed)
2. Follow their dashboard prompts to create your first database — call it `primark-realtors`
3. From the database's page, find and copy two values: the **Database URL** (starts with `libsql://`) and an **Auth Token**
4. Send those two values to me (or keep them somewhere safe) — we'll need them in Step 3

### Step 2: Create a free Render account
1. Go to render.com and sign up (no card needed)
2. Connect it to a GitHub account if you have one, or choose "deploy without Git" if offered

### Step 3: Deploy the app
1. Upload this whole folder as a new "Web Service" on Render (their dashboard will guide you — Node.js is auto-detected, no configuration files to edit)
2. Add these Environment Variables in Render's dashboard (never in the code itself):
   - `JWT_SECRET` — any long random sentence, made up by you
   - `SUPER_ADMIN_USERNAME` — e.g. `admin`
   - `SUPER_ADMIN_PASSWORD` — a strong password
   - `TURSO_DATABASE_URL` — from Step 1
   - `TURSO_AUTH_TOKEN` — from Step 1
3. Click Deploy

### Step 4: Log in
Render gives you a URL like `https://primark-realtors-crm.onrender.com`. Open it in
Chrome (desktop or mobile) and log in with the super admin ID and password
you set in Step 3.

**At every step, if anything looks different from what's described, or you
hit an error, stop and tell me exactly what you see (a screenshot or the
exact error text) — I'll walk you through it before we move to the next step.**

## Day-to-day use

- The super admin logs in first, goes to the **Team** tab, and creates one
  account per team member (rep, admin, or another super admin).
- Reps only ever see leads assigned to them. Admins and super admins see everyone's.
- There's no self-service "forgot password" yet — an admin resets it for
  someone from the Team tab.

## Backing up your data

Turso lets you export your database at any time from their dashboard, or via
their command-line tool. Ask me for the exact steps whenever you'd like to
set up a regular backup — it takes a few minutes to configure once.

## When something breaks

Come back to me (Claude) with:
1. What you were trying to do
2. What happened instead (screenshot or exact error text helps a lot)
3. Which step you were on (Turso setup, Render setup, or using the app itself)

I wrote every file in this project, so I can read them again in a future
conversation and fix, extend, or explain any part of it — just share this
folder (or the specific file) with me again if I don't already have it in
the conversation.

## Adding features later

Some natural next steps, whenever you want them:
- Lead auto-routing (new leads assigned round-robin instead of manually)
- WhatsApp/SMS reminder templates for follow-ups
- A "my day" view for reps: today's follow-ups and site visits in one list
- Exportable PDF reports for management meetings
- Self-service password reset via email
- Upgrading Render to a paid "always-on" tier later if the 30-60 second wake-up ever becomes annoying (this is optional, not required)

None of these need a different architecture — they're additions to the same codebase.
