const { createClient } = require("@libsql/client");
const bcrypt = require("bcryptjs");

if (!process.env.TURSO_DATABASE_URL || !process.env.TURSO_AUTH_TOKEN) {
  console.error("FATAL: TURSO_DATABASE_URL and TURSO_AUTH_TOKEN must both be set.");
  process.exit(1);
}

const client = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

async function run(sql, args = []) {
  return client.execute({ sql, args });
}
async function get(sql, args = []) {
  const res = await client.execute({ sql, args });
  return res.rows[0] || null;
}
async function all(sql, args = []) {
  const res = await client.execute({ sql, args });
  return res.rows;
}

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('rep','admin','super_admin')),
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS leads (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT,
    email TEXT,
    source TEXT,
    campaign TEXT,
    status TEXT NOT NULL DEFAULT 'New',
    disqualify_reason TEXT,
    assigned_to INTEGER REFERENCES users(id),
    deal_value REAL DEFAULT 0,
    follow_up_date TEXT,
    property_interest TEXT,
    configuration TEXT,
    budget_min REAL,
    budget_max REAL,
    preferred_location TEXT,
    lead_type TEXT DEFAULT 'Buyer',
    channel_partner TEXT,
    site_visit_date TEXT,
    site_visit_status TEXT DEFAULT 'Not scheduled',
    kyc_submitted INTEGER DEFAULT 0,
    booking_form_signed INTEGER DEFAULT 0,
    token_amount_received INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lead_id TEXT NOT NULL REFERENCES leads(id),
    author_name TEXT,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lead_id TEXT NOT NULL REFERENCES leads(id),
    user_name TEXT NOT NULL,
    field TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    created_at TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  )`,
  `CREATE TABLE IF NOT EXISTS campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL
  )`,
];

// Adds a column if an already-existing database doesn't have it yet.
// CREATE TABLE IF NOT EXISTS only helps on a brand-new database - once
// you're live, new fields need this instead so nobody's real data is at risk.
async function ensureColumn(table, column, definition) {
  const cols = await all(`PRAGMA table_info(${table})`);
  if (!cols.some((c) => c.name === column)) {
    await run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
    console.log(`Migration: added column "${column}" to "${table}".`);
  }
}

async function init() {
  for (const stmt of SCHEMA) {
    await run(stmt);
  }
  // Forward-compatible migrations - safe to run every startup, does nothing
  // once a column already exists.
  await ensureColumn("leads", "campaign", "TEXT");

  const countRow = await get("SELECT COUNT(*) as c FROM users");
  if (countRow.c === 0) {
    const username = process.env.SUPER_ADMIN_USERNAME || "admin";
    const password = process.env.SUPER_ADMIN_PASSWORD || "changeme123";
    const hash = bcrypt.hashSync(password, 10);
    await run(
      "INSERT INTO users (username, password_hash, name, role, active, created_at) VALUES (?, ?, ?, 'super_admin', 1, ?)",
      [username, hash, "Super Admin", new Date().toISOString()]
    );
    console.log(`First-run: created super admin "${username}". Log in and change the password immediately if you used the default.`);
  }
}

module.exports = { client, run, get, all, init };
