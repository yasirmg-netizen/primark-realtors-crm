const express = require("express");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");
const db = require("./db");
const { hashPassword, checkPassword, signToken, requireAuth, requireRole } = require("./auth");

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb", verify: (req, res, buf) => { req.rawBody = buf; } }));
app.use(express.static(path.join(__dirname, "public")));

function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}
function nowISO() {
  return new Date().toISOString();
}
// Loose but useful validation - catches obviously malformed entries (typos,
// stray characters, missing @ sign) without being so strict it rejects real
// numbers with spaces/dashes or valid uncommon email formats.
function normalizePhone(phone) {
  return String(phone || "").replace(/[^\d+]/g, "");
}
function isValidPhone(phone) {
  if (!phone) return true; // phone is optional
  const digits = normalizePhone(phone).replace(/^\+?91/, "");
  return /^\d{10}$/.test(digits);
}
function isValidEmail(email) {
  if (!email) return true; // email is optional
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email).trim());
}
// Wraps an async route handler so thrown errors become clean JSON responses
// instead of crashing the server.
function ah(fn) {
  return (req, res) => fn(req, res).catch((err) => {
    console.error(err);
    res.status(500).json({ error: err.message || "Something went wrong on the server." });
  });
}

// ---------- AUTH ----------

app.post("/api/login", ah(async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Enter a user ID and password." });
  const user = await db.get("SELECT * FROM users WHERE username = ?", [username]);
  if (!user || !user.active || !checkPassword(password, user.password_hash)) {
    return res.status(401).json({ error: "That user ID or password isn't right." });
  }
  const token = signToken(user);
  res.json({ token, user: { id: user.id, username: user.username, name: user.name, role: user.role } });
}));

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.post("/api/me/password", requireAuth, ah(async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: "New password needs at least 6 characters." });
  const user = await db.get("SELECT * FROM users WHERE id = ?", [req.user.id]);
  if (!checkPassword(currentPassword || "", user.password_hash)) return res.status(401).json({ error: "Current password is wrong." });
  await db.run("UPDATE users SET password_hash = ? WHERE id = ?", [hashPassword(newPassword), req.user.id]);
  res.json({ ok: true });
}));

// ---------- USERS (admin / super_admin only) ----------

app.get("/api/users", requireAuth, requireRole("admin", "super_admin"), ah(async (req, res) => {
  let rows = await db.all("SELECT id, username, name, role, active, created_at FROM users ORDER BY created_at");
  if (req.user.role === "admin") rows = rows.filter((u) => u.role === "rep");
  res.json({ users: rows });
}));

app.post("/api/users", requireAuth, requireRole("admin", "super_admin"), ah(async (req, res) => {
  const { username, password, name, role } = req.body || {};
  if (!username || !password || !name || !role) return res.status(400).json({ error: "All fields are required." });
  if (req.user.role === "admin" && role !== "rep") return res.status(403).json({ error: "Admins can only create team member accounts." });
  if (!["rep", "admin", "super_admin"].includes(role)) return res.status(400).json({ error: "Invalid role." });
  const existing = await db.get("SELECT id FROM users WHERE username = ?", [username]);
  if (existing) return res.status(400).json({ error: "That user ID is already taken." });
  const result = await db.run(
    "INSERT INTO users (username, password_hash, name, role, active, created_at) VALUES (?, ?, ?, ?, 1, ?)",
    [username, hashPassword(password), name, role, nowISO()]
  );
  res.json({ id: Number(result.lastInsertRowid) });
}));

app.patch("/api/users/:id", requireAuth, requireRole("admin", "super_admin"), ah(async (req, res) => {
  const target = await db.get("SELECT * FROM users WHERE id = ?", [req.params.id]);
  if (!target) return res.status(404).json({ error: "User not found." });
  if (req.user.role === "admin" && target.role !== "rep") return res.status(403).json({ error: "Admins can only manage team member accounts." });
  const { active, newPassword, name, role, username } = req.body || {};
  if (typeof active === "number" || typeof active === "boolean") await db.run("UPDATE users SET active = ? WHERE id = ?", [active ? 1 : 0, target.id]);
  if (newPassword) await db.run("UPDATE users SET password_hash = ? WHERE id = ?", [hashPassword(newPassword), target.id]);
  if (name) await db.run("UPDATE users SET name = ? WHERE id = ?", [name, target.id]);
  if (username && username !== target.username) {
    const clash = await db.get("SELECT id FROM users WHERE username = ? AND id != ?", [username, target.id]);
    if (clash) return res.status(400).json({ error: "That user ID is already taken." });
    await db.run("UPDATE users SET username = ? WHERE id = ?", [username, target.id]);
  }
  if (role && req.user.role === "super_admin" && ["rep", "admin", "super_admin"].includes(role)) await db.run("UPDATE users SET role = ? WHERE id = ?", [role, target.id]);
  res.json({ ok: true });
}));

// ---------- LEADS ----------

// Checks whether a phone number already exists anywhere in the system.
// Deliberately not scoped to the current user's own leads - the whole point
// is catching a lead someone else is already working, so a rep needs to see
// that a match exists even though they can't see that other lead's full detail.
app.get("/api/leads/check-duplicate", requireAuth, ah(async (req, res) => {
  const phone = normalizePhone(req.query.phone).replace(/^\+?91/, "");
  if (!phone || phone.length < 10) return res.json({ duplicate: false });
  const rows = await db.all("SELECT leads.name, leads.status, leads.created_at, leads.assigned_to, users.name as assigned_to_name FROM leads LEFT JOIN users ON users.id = leads.assigned_to WHERE leads.phone LIKE ?", [`%${phone}%`]);
  if (rows.length === 0) return res.json({ duplicate: false });
  const l = rows[0];
  res.json({ duplicate: true, name: l.name, status: l.status, createdAt: l.created_at, assignedToName: l.assigned_to_name || "Unassigned" });
}));

app.get("/api/leads", requireAuth, ah(async (req, res) => {
  let rows;
  if (req.user.role === "rep") {
    rows = await db.all("SELECT * FROM leads WHERE assigned_to = ? ORDER BY created_at DESC", [req.user.id]);
  } else {
    rows = await db.all("SELECT * FROM leads ORDER BY created_at DESC");
  }
  const users = await db.all("SELECT id, name FROM users");
  const userMap = {}; users.forEach((u) => { userMap[u.id] = u.name; });
  const leadIds = rows.map((r) => r.id);
  const comments = leadIds.length
    ? await db.all(`SELECT * FROM comments WHERE lead_id IN (${leadIds.map(() => "?").join(",")}) ORDER BY created_at`, leadIds)
    : [];
  const audit = leadIds.length
    ? await db.all(`SELECT * FROM audit_log WHERE lead_id IN (${leadIds.map(() => "?").join(",")}) ORDER BY created_at`, leadIds)
    : [];
  const byLead = {};
  comments.forEach((c) => { (byLead[c.lead_id] = byLead[c.lead_id] || []).push(c); });
  const auditByLead = {};
  audit.forEach((a) => { (auditByLead[a.lead_id] = auditByLead[a.lead_id] || []).push(a); });
  rows.forEach((r) => { r.comments = byLead[r.id] || []; r.audit = auditByLead[r.id] || []; r.assigned_to_name = userMap[r.assigned_to] || "Unassigned"; });
  res.json({ leads: rows });
}));

const LEAD_COLUMNS = [
  "id", "name", "phone", "email", "source", "campaign", "status", "disqualify_reason", "assigned_to", "deal_value",
  "follow_up_date", "property_interest", "configuration", "budget_min", "budget_max", "preferred_location",
  "lead_type", "channel_partner", "site_visit_date", "site_visit_status", "kyc_submitted",
  "booking_form_signed", "token_amount_received", "created_at", "updated_at",
];

// Keeps a canonical, autocomplete-able list of campaign names - fed both by
// manual entry and automatically by incoming webhook leads, so the list
// builds itself over time instead of needing to be maintained by hand.
async function upsertCampaign(name) {
  const trimmed = (name || "").trim();
  if (!trimmed) return;
  await db.run("INSERT INTO campaigns (name, created_at) VALUES (?, ?) ON CONFLICT(name) DO NOTHING", [trimmed, nowISO()]);
}

app.get("/api/campaigns", requireAuth, ah(async (req, res) => {
  const rows = await db.all("SELECT name FROM campaigns ORDER BY name");
  res.json({ campaigns: rows.map((r) => r.name) });
}));

// Saved views are personal - each user only ever sees their own, regardless
// of role, since a filter combination one rep finds useful may not make
// sense for another.
app.get("/api/saved-views", requireAuth, ah(async (req, res) => {
  const rows = await db.all("SELECT id, name, filters_json FROM saved_views WHERE user_id = ? ORDER BY created_at", [req.user.id]);
  res.json({ views: rows.map((r) => ({ id: r.id, name: r.name, filters: JSON.parse(r.filters_json) })) });
}));

app.post("/api/saved-views", requireAuth, ah(async (req, res) => {
  const { name, filters } = req.body || {};
  if (!name || !filters) return res.status(400).json({ error: "A name and the current filters are both required." });
  const info = await db.run(
    "INSERT INTO saved_views (user_id, name, filters_json, created_at) VALUES (?, ?, ?, ?)",
    [req.user.id, name.trim(), JSON.stringify(filters), nowISO()]
  );
  res.json({ id: Number(info.lastInsertRowid) });
}));

app.delete("/api/saved-views/:id", requireAuth, ah(async (req, res) => {
  await db.run("DELETE FROM saved_views WHERE id = ? AND user_id = ?", [req.params.id, req.user.id]);
  res.json({ ok: true });
}));

app.post("/api/leads", requireAuth, ah(async (req, res) => {
  const body = req.body || {};
  if (!isValidPhone(body.phone)) return res.status(400).json({ error: "That phone number doesn't look right - use a 10-digit number." });
  if (!isValidEmail(body.email)) return res.status(400).json({ error: "That email address doesn't look right." });
  const id = uid();
  const assignedTo = req.user.role === "rep" ? req.user.id : (body.assigned_to || req.user.id);
  const values = {
    id, name: body.name || "Unnamed lead", phone: body.phone || "", email: body.email || "",
    source: body.source || "Other", campaign: body.campaign || "", status: body.status || "New", disqualify_reason: body.disqualify_reason || null,
    assigned_to: assignedTo, deal_value: Number(body.deal_value) || 0, follow_up_date: body.follow_up_date || null,
    property_interest: body.property_interest || "", configuration: body.configuration || "",
    budget_min: Number(body.budget_min) || null, budget_max: Number(body.budget_max) || null,
    preferred_location: body.preferred_location || "", lead_type: body.lead_type || "Buyer",
    channel_partner: body.channel_partner || "", site_visit_date: body.site_visit_date || null,
    site_visit_status: body.site_visit_status || "Not scheduled", kyc_submitted: body.kyc_submitted ? 1 : 0,
    booking_form_signed: body.booking_form_signed ? 1 : 0, token_amount_received: body.token_amount_received ? 1 : 0,
    created_at: nowISO(), updated_at: nowISO(),
  };
  const args = LEAD_COLUMNS.map((c) => values[c]);
  await db.run(
    `INSERT INTO leads (${LEAD_COLUMNS.join(",")}) VALUES (${LEAD_COLUMNS.map(() => "?").join(",")})`,
    args
  );
  if (body.campaign) await upsertCampaign(body.campaign);
  if (body.note) {
    await db.run("INSERT INTO comments (lead_id, author_name, text, created_at) VALUES (?, ?, ?, ?)", [id, req.user.name, body.note, nowISO()]);
  }
  res.json({ id });
}));

async function getLeadOr404(id, res) {
  const lead = await db.get("SELECT * FROM leads WHERE id = ?", [id]);
  if (!lead) { res.status(404).json({ error: "Lead not found." }); return null; }
  return lead;
}

const PATCHABLE_FIELDS = LEAD_COLUMNS.filter((c) => c !== "id" && c !== "created_at" && c !== "updated_at");

const FIELD_LABELS = {
  name: "Name", phone: "Phone", email: "Email", source: "Source", campaign: "Campaign", status: "Status",
  disqualify_reason: "Disqualify reason", assigned_to: "Assigned to", deal_value: "Deal value",
  follow_up_date: "Follow-up date", property_interest: "Property/project", configuration: "Configuration",
  budget_min: "Budget min", budget_max: "Budget max", preferred_location: "Preferred location",
  lead_type: "Lead type", channel_partner: "Channel partner", site_visit_date: "Site visit date",
  site_visit_status: "Site visit status", kyc_submitted: "KYC submitted", booking_form_signed: "Booking form signed",
  token_amount_received: "Token amount received",
};

app.patch("/api/leads/:id", requireAuth, ah(async (req, res) => {
  const lead = await getLeadOr404(req.params.id, res);
  if (!lead) return;
  if (req.user.role === "rep" && lead.assigned_to !== req.user.id) return res.status(403).json({ error: "This lead isn't assigned to you." });
  const body = req.body || {};
  if (Object.prototype.hasOwnProperty.call(body, "campaign") && body.campaign) await upsertCampaign(body.campaign);
  if (Object.prototype.hasOwnProperty.call(body, "phone") && !isValidPhone(body.phone)) return res.status(400).json({ error: "That phone number doesn't look right - use a 10-digit number." });
  if (Object.prototype.hasOwnProperty.call(body, "email") && !isValidEmail(body.email)) return res.status(400).json({ error: "That email address doesn't look right." });
  const sets = [];
  const args = [];
  const changes = []; // { field, oldValue, newValue } for the audit trail
  let userMap = null;
  async function resolveUserName(id) {
    if (id === null || typeof id === "undefined") return "Unassigned";
    if (!userMap) {
      const users = await db.all("SELECT id, name FROM users");
      userMap = {}; users.forEach((u) => { userMap[u.id] = u.name; });
    }
    return userMap[id] || ("User #" + id);
  }
  for (const f of PATCHABLE_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(body, f)) continue;
    if (f === "assigned_to" && req.user.role === "rep") continue; // reps can't reassign
    const oldVal = lead[f];
    const newVal = body[f];
    if (String(oldVal ?? "") !== String(newVal ?? "")) {
      let oldDisplay = oldVal, newDisplay = newVal;
      if (f === "assigned_to") { oldDisplay = await resolveUserName(oldVal); newDisplay = await resolveUserName(newVal); }
      changes.push({ field: f, oldValue: oldDisplay, newValue: newDisplay });
    }
    sets.push(`${f} = ?`);
    args.push(newVal);
  }
  if (sets.length === 0) return res.json({ ok: true });
  // Automatically capture the moment a lead is first acted on - the first
  // time its status moves away from "New" - as a response-time metric.
  // This is server-controlled only; it's never something a client can set
  // directly, and it's only ever written once per lead.
  if (Object.prototype.hasOwnProperty.call(body, "status") && lead.status === "New" && body.status !== "New" && !lead.first_contacted_at) {
    sets.push("first_contacted_at = ?");
    args.push(nowISO());
  }
  sets.push("updated_at = ?");
  args.push(nowISO());
  args.push(lead.id);
  await db.run(`UPDATE leads SET ${sets.join(", ")} WHERE id = ?`, args);
  for (const c of changes) {
    await db.run(
      "INSERT INTO audit_log (lead_id, user_name, field, old_value, new_value, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      [lead.id, req.user.name, FIELD_LABELS[c.field] || c.field, c.oldValue === null || typeof c.oldValue === "undefined" ? "" : String(c.oldValue), c.newValue === null || typeof c.newValue === "undefined" ? "" : String(c.newValue), nowISO()]
    );
  }
  res.json({ ok: true });
}));

app.post("/api/leads/:id/comments", requireAuth, ah(async (req, res) => {
  const lead = await getLeadOr404(req.params.id, res);
  if (!lead) return;
  if (req.user.role === "rep" && lead.assigned_to !== req.user.id) return res.status(403).json({ error: "This lead isn't assigned to you." });
  const text = ((req.body && req.body.text) || "").trim();
  if (!text) return res.status(400).json({ error: "Comment can't be empty." });
  await db.run("INSERT INTO comments (lead_id, author_name, text, created_at) VALUES (?, ?, ?, ?)", [lead.id, req.user.name, text, nowISO()]);
  res.json({ ok: true });
}));

// Deleting a lead is permanent and irreversible - restricted to super admins
// only, and always leaves a record in deleted_leads_log (who deleted what,
// when) even though the lead itself, and its comments/audit history, are
// genuinely removed. This is a deliberately different tier of action from
// everything else in the app, which prefers Disqualified/Lost over erasing.
app.delete("/api/leads/:id", requireAuth, requireRole("super_admin"), ah(async (req, res) => {
  const lead = await db.get("SELECT * FROM leads WHERE id = ?", [req.params.id]);
  if (!lead) return res.status(404).json({ error: "Lead not found." });
  await db.run(
    "INSERT INTO deleted_leads_log (lead_name, lead_phone, lead_source, deleted_by_name, deleted_at) VALUES (?, ?, ?, ?, ?)",
    [lead.name, lead.phone, lead.source, req.user.name, nowISO()]
  );
  await db.run("DELETE FROM comments WHERE lead_id = ?", [lead.id]);
  await db.run("DELETE FROM audit_log WHERE lead_id = ?", [lead.id]);
  await db.run("DELETE FROM leads WHERE id = ?", [lead.id]);
  res.json({ ok: true });
}));

// Bulk version of the same thing - same permissions, same permanent log,
// just applied to a whole selection at once. Each lead is logged individually
// so the deletion log stays just as informative as single deletes.
app.post("/api/leads/bulk-delete", requireAuth, requireRole("super_admin"), ah(async (req, res) => {
  const ids = (req.body && req.body.ids) || [];
  if (!Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: "No leads selected." });
  let deletedCount = 0;
  for (const id of ids) {
    const lead = await db.get("SELECT * FROM leads WHERE id = ?", [id]);
    if (!lead) continue;
    await db.run(
      "INSERT INTO deleted_leads_log (lead_name, lead_phone, lead_source, deleted_by_name, deleted_at) VALUES (?, ?, ?, ?, ?)",
      [lead.name, lead.phone, lead.source, req.user.name, nowISO()]
    );
    await db.run("DELETE FROM comments WHERE lead_id = ?", [lead.id]);
    await db.run("DELETE FROM audit_log WHERE lead_id = ?", [lead.id]);
    await db.run("DELETE FROM leads WHERE id = ?", [lead.id]);
    deletedCount++;
  }
  res.json({ deleted: deletedCount });
}));

app.get("/api/deleted-leads-log", requireAuth, requireRole("super_admin"), ah(async (req, res) => {
  const rows = await db.all("SELECT * FROM deleted_leads_log ORDER BY deleted_at DESC LIMIT 100");
  res.json({ log: rows });
}));

app.post("/api/leads/import", requireAuth, ah(async (req, res) => {
  const rows = (req.body && req.body.rows) || [];
  // Users (for matching "Assigned To" by name) - only admins/super admins can
  // set this; a rep's imports always land on themselves regardless of what
  // the CSV says.
  const users = await db.all("SELECT id, name, username FROM users WHERE active = 1");
  function resolveAssignee(raw) {
    if (req.user.role === "rep" || !raw) return req.user.id;
    const match = users.find((u) => u.name.toLowerCase() === String(raw).trim().toLowerCase() || u.username.toLowerCase() === String(raw).trim().toLowerCase());
    return match ? match.id : req.user.id;
  }
  const statements = rows.map((r) => ({
    sql: `INSERT INTO leads (id,name,phone,email,source,campaign,status,assigned_to,deal_value,
          follow_up_date,property_interest,configuration,budget_min,budget_max,preferred_location,
          lead_type,channel_partner,site_visit_status,created_at,updated_at)
          VALUES (?,?,?,?,?,?,'New',?,?,?,?,?,?,?,?,?,?,'Not scheduled',?,?)`,
    args: [
      uid(), r.name || "Unnamed lead", r.phone || "", r.email || "", r.source || "Other", r.campaign || "",
      resolveAssignee(r.assigned_to),
      Number(r.deal_value) || 0, r.follow_up_date || null, r.property_interest || "", r.configuration || "",
      Number(r.budget_min) || null, Number(r.budget_max) || null, r.preferred_location || "",
      r.lead_type || "Buyer", r.channel_partner || "",
      nowISO(), nowISO(),
    ],
  }));
  if (statements.length) await db.client.batch(statements, "write");
  const campaignNames = [...new Set(rows.map((r) => (r.campaign || "").trim()).filter(Boolean))];
  for (const name of campaignNames) await upsertCampaign(name);
  res.json({ imported: statements.length });
}));

// Only super admins can bulk-export the entire lead database to a file.
// This is enforced here on the server, not just by hiding a button -
// so it holds even if someone edits the page in their browser.
function csvEscape(v) {
  const s = v === null || typeof v === "undefined" ? "" : String(v);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
app.get("/api/leads/export", requireAuth, requireRole("super_admin"), ah(async (req, res) => {
  const rows = await db.all("SELECT * FROM leads ORDER BY created_at DESC");
  const users = await db.all("SELECT id, name FROM users");
  const userMap = {}; users.forEach((u) => { userMap[u.id] = u.name; });
  const headers = ["Name", "Phone", "Email", "Source", "Campaign", "Status", "Disqualify reason", "Assigned to", "Deal value",
    "Follow-up date", "Property/project", "Configuration", "Budget min", "Budget max", "Preferred location",
    "Lead type", "Channel partner", "Site visit date", "Site visit status", "KYC submitted",
    "Booking form signed", "Token received", "Created", "Last updated"];
  const lines = [headers.map(csvEscape).join(",")];
  rows.forEach((l) => {
    lines.push([
      l.name, l.phone, l.email, l.source, l.campaign, l.status, l.disqualify_reason, userMap[l.assigned_to] || "Unassigned",
      l.deal_value, l.follow_up_date, l.property_interest, l.configuration, l.budget_min, l.budget_max,
      l.preferred_location, l.lead_type, l.channel_partner, l.site_visit_date, l.site_visit_status,
      l.kyc_submitted ? "Yes" : "No", l.booking_form_signed ? "Yes" : "No", l.token_amount_received ? "Yes" : "No",
      l.created_at, l.updated_at,
    ].map(csvEscape).join(","));
  });
  await db.run("INSERT INTO settings (key, value) VALUES ('last_backup_at', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", [nowISO()]);
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", `attachment; filename="primark-realtors-all-leads-${new Date().toISOString().slice(0, 10)}.csv"`);
  res.send(lines.join("\n"));
}));

// Lets the dashboard show "Last backup: N days ago" as a gentle nag - no
// automatic scheduling involved, just visibility so it's never forgotten.
app.get("/api/settings/last-backup", requireAuth, requireRole("super_admin"), ah(async (req, res) => {
  const row = await db.get("SELECT value FROM settings WHERE key = 'last_backup_at'");
  res.json({ lastBackupAt: row ? row.value : null });
}));


// ---------- MARKETING PLATFORM INTEGRATIONS ----------
// These endpoints are public (no login) because ad platforms can't log in -
// they're protected by secret tokens/signatures instead. Nothing here is
// reachable without knowing the secret you configure as an environment
// variable, which only you set.

// Picks the active rep currently carrying the fewest open (non-closed) leads.
// This self-balances the team automatically - no rotation counter to maintain,
// and a rep who's just closed a batch of deals naturally gets the next ones.
// Auto-assignment logic, in priority order:
// 1. If this lead's campaign has a configured rule, always goes to that rep
//    (regardless of their current workload) - e.g. "Diwali Offer" always
//    goes to the rep who knows that property best.
// 2. Otherwise, true round-robin across active reps - each new lead goes to
//    whoever is next in rotation, tracked via a settings row so it survives
//    restarts. Super admins (and admins) are never in this pool at all,
//    since only role='rep' is queried below.
async function pickAutoRouteRep(campaign) {
  if (campaign) {
    const rule = await db.get(
      `SELECT assignment_rules.assigned_to as assigned_to FROM assignment_rules
       JOIN users ON users.id = assignment_rules.assigned_to
       WHERE LOWER(assignment_rules.campaign) = LOWER(?) AND users.active = 1`,
      [campaign]
    );
    if (rule) return rule.assigned_to;
  }
  const reps = await db.all("SELECT id, name FROM users WHERE role = 'rep' AND active = 1 ORDER BY id");
  if (reps.length === 0) return null;
  const lastRow = await db.get("SELECT value FROM settings WHERE key = 'round_robin_last_rep_id'");
  const lastId = lastRow ? Number(lastRow.value) : null;
  let nextIndex = 0;
  if (lastId !== null) {
    const lastIndex = reps.findIndex((r) => r.id === lastId);
    nextIndex = lastIndex === -1 ? 0 : (lastIndex + 1) % reps.length;
  }
  const chosen = reps[nextIndex];
  await db.run(
    "INSERT INTO settings (key, value) VALUES ('round_robin_last_rep_id', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    [String(chosen.id)]
  );
  return chosen.id;
}

app.get("/api/assignment-rules", requireAuth, requireRole("admin", "super_admin"), ah(async (req, res) => {
  const rows = await db.all(
    `SELECT assignment_rules.id, assignment_rules.campaign, assignment_rules.assigned_to, users.name as assigned_to_name
     FROM assignment_rules JOIN users ON users.id = assignment_rules.assigned_to ORDER BY assignment_rules.campaign`
  );
  res.json({ rules: rows });
}));

app.post("/api/assignment-rules", requireAuth, requireRole("admin", "super_admin"), ah(async (req, res) => {
  const { campaign, assigned_to } = req.body || {};
  if (!campaign || !assigned_to) return res.status(400).json({ error: "Campaign and assigned rep are both required." });
  await db.run(
    `INSERT INTO assignment_rules (campaign, assigned_to, created_at) VALUES (?, ?, ?)
     ON CONFLICT(campaign) DO UPDATE SET assigned_to = excluded.assigned_to`,
    [campaign.trim(), Number(assigned_to), nowISO()]
  );
  res.json({ ok: true });
}));

app.delete("/api/assignment-rules/:id", requireAuth, requireRole("admin", "super_admin"), ah(async (req, res) => {
  await db.run("DELETE FROM assignment_rules WHERE id = ?", [req.params.id]);
  res.json({ ok: true });
}));

async function createLeadFromWebhook({ name, phone, email, source, campaign, note }) {
  const id = uid();
  const now = nowISO();
  const assignedTo = await pickAutoRouteRep(campaign);
  await db.run(
    `INSERT INTO leads (id,name,phone,email,source,campaign,status,assigned_to,deal_value,created_at,updated_at,site_visit_status,lead_type)
     VALUES (?,?,?,?,?,?,'New',?,0,?,?,'Not scheduled','Buyer')`,
    [id, name || "Unnamed lead", phone || "", email || "", source || "Other", campaign || "", assignedTo, now, now]
  );
  if (campaign) await upsertCampaign(campaign);
  if (note) await db.run("INSERT INTO comments (lead_id, author_name, text, created_at) VALUES (?, ?, ?, ?)", [id, "System", note, now]);
  if (assignedTo) await db.run("INSERT INTO audit_log (lead_id, user_name, field, old_value, new_value, created_at) VALUES (?, 'System', 'Assigned to', '', (SELECT name FROM users WHERE id = ?), ?)", [id, assignedTo, now]);
  return id;
}

// Generic inbound webhook - works with Zapier, Make/Integromat, Typeform,
// landing page builders, or any tool that can send a JSON POST request.
// Configure WEBHOOK_SECRET as an environment variable, then give that
// platform this URL: https://your-app-url/api/webhooks/inbound?token=YOUR_SECRET&source=Instagram
// To track which campaign a lead came from, map the platform's campaign name
// field into "campaign" in the JSON body (or a &campaign= query param).
app.post("/api/webhooks/inbound", ah(async (req, res) => {
  if (!process.env.WEBHOOK_SECRET || req.query.token !== process.env.WEBHOOK_SECRET) {
    return res.status(401).json({ error: "Invalid or missing webhook token." });
  }
  const body = req.body || {};
  const source = req.query.source || body.source || "Other";
  const campaign = req.query.campaign || body.campaign || body.campaign_name || "";
  const id = await createLeadFromWebhook({
    name: body.name || body.full_name || body.client_name,
    phone: body.phone || body.phone_number || body.contact_number,
    email: body.email || body.email_id,
    source, campaign,
    note: "Received automatically via webhook integration.",
  });
  res.json({ ok: true, id });
}));

// Native Meta (Instagram/Facebook) Lead Ads integration.
// Requires you to create a Facebook Developer App with Lead Ads access,
// linked to your Page - see README for the setup steps only you can do
// (this needs your own Facebook Business/Page ownership).
app.get("/api/webhooks/meta", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];
  if (mode === "subscribe" && token === process.env.META_WEBHOOK_VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  res.sendStatus(403);
});

app.post("/api/webhooks/meta", ah(async (req, res) => {
  // Verify this request genuinely came from Meta using the shared app secret.
  const signature = req.headers["x-hub-signature-256"];
  if (!process.env.META_APP_SECRET || !signature || !req.rawBody) return res.sendStatus(403);
  const expected = "sha256=" + crypto.createHmac("sha256", process.env.META_APP_SECRET).update(req.rawBody).digest("hex");
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return res.sendStatus(403);

  res.sendStatus(200); // acknowledge immediately - Meta requires a fast response
  try {
    const entries = (req.body && req.body.entry) || [];
    for (const entry of entries) {
      for (const change of entry.changes || []) {
        if (change.field !== "leadgen") continue;
        const leadgenId = change.value.leadgen_id;
        const pageId = change.value.page_id;
        // Meta's webhook only notifies us a lead exists - we fetch the actual
        // field values (name, phone, email) with a separate Graph API call.
        // Explicitly request campaign_name (and the finer-grained adset/ad
        // names as a fallback) - Meta only returns these if asked for by name.
        const url = `https://graph.facebook.com/v19.0/${leadgenId}?fields=field_data,campaign_name,adset_name,ad_name,platform&access_token=${process.env.META_PAGE_ACCESS_TOKEN}`;
        const r = await fetch(url);
        const data = await r.json();
        const fields = {};
        (data.field_data || []).forEach((f) => { fields[f.name] = (f.values || [])[0]; });
        const campaign = data.campaign_name || data.adset_name || data.ad_name || "";
        await createLeadFromWebhook({
          name: fields.full_name || fields.name,
          phone: fields.phone_number,
          email: fields.email,
          source: change.value.platform === "ig" ? "Instagram" : "Facebook",
          campaign,
          note: `Received automatically from Meta Lead Ads (page ${pageId})${campaign ? ` - campaign: ${campaign}` : ""}.`,
        });
      }
    }
  } catch (err) {
    console.error("Meta webhook processing error:", err);
  }
}));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;
db.init()
  .then(() => app.listen(PORT, () => console.log(`Primark Realtors CRM running on port ${PORT}`)))
  .catch((err) => { console.error("Failed to start:", err); process.exit(1); });
