// Andy's Shoe Supply — store backend
// Endpoints: health, likes, reviews (purchase-gated, Maria's rule), Stripe checkout + webhook, USPS rates + labels, inventory,
// customer emails via Resend (welcome, purchase confirmation + review invite, admin promos).
// Secrets come ONLY from environment variables (see .env.example). Never hardcode keys.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite'); // built-in, no native build needed

const app = express();
const PORT = process.env.PORT || 8080;
const STORE_ORIGIN = process.env.STORE_ORIGIN || '*'; // set to the store's public URL in prod
const SHIP_FROM_ZIP = process.env.SHIP_FROM_ZIP || '79045'; // Hereford, TX

app.use(cors({ origin: STORE_ORIGIN === '*' ? true : STORE_ORIGIN }));
// Stripe webhook needs the raw body: mount it BEFORE express.json()
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), onStripeWebhook);
app.use(express.json({ limit: '256kb' }));

// ---------- Admin protection (private orders panel) ----------
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) return res.status(503).json({ error: 'admin not configured' });
  const t = req.get('x-admin-token') || req.query.token || '';
  const a = Buffer.from(t), b = Buffer.from(ADMIN_TOKEN);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b))
    return res.status(401).json({ error: 'unauthorized' });
  next();
}

// ---------- Catalog (price truth lives here, validated server-side) ----------
const CATALOG_PATH = process.env.CATALOG_PATH || path.join(__dirname, 'products_full.json');
let CATALOG = [];
try {
  const raw = JSON.parse(fs.readFileSync(CATALOG_PATH, 'utf8'));
  CATALOG = Array.isArray(raw) ? raw : raw.products || [];
  console.log(`Catalog loaded: ${CATALOG.length} products from ${CATALOG_PATH}`);
} catch (e) {
  console.warn('Catalog not found, starting empty:', e.message);
}
const byId = new Map(CATALOG.map(p => [String(p.id || p.itemId), p]));
const priceOf = (p) => Number(p.price ?? p.currentPrice ?? 0);
const DISCOUNT = 0.15; // 15% off eBay price on direct store
// Catalog price truth: p.price is the eBay price as a TEXT string ("$21.19");
// p.price_direct is the numeric 15%-off direct-store price this shop charges
// (the Payment Link builder uses it too). The legacy priceOf() turns "$21.19"
// into NaN, so anything money-facing must go through storePriceOf().
const storePriceOf = (p) => {
  const d = Number(p?.price_direct);
  if (Number.isFinite(d) && d > 0) return d;
  const e = Number(String(p?.price ?? '').replace(/[^0-9.]/g, ''));
  return Number.isFinite(e) && e > 0 ? e * (1 - DISCOUNT) : 0;
};

// ---------- Database ----------
const DB_PATH = process.env.DB_PATH || './store.db';
// Render's free plan wipes the local disk on every restart/redeploy.
// Restore the latest snapshot from Cloudflare R2 first (no-op if R2 isn't configured).
try {
  require('child_process').execFileSync(process.execPath, [path.join(__dirname, 'r2restore.js')], { stdio: 'inherit', timeout: 45000 });
} catch (e) { console.warn('DB restore step failed, continuing with local DB'); }
const db = new DatabaseSync(DB_PATH);
db.exec(`
  CREATE TABLE IF NOT EXISTS likes (product_id TEXT PRIMARY KEY, count INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE IF NOT EXISTS like_votes (product_id TEXT, voter TEXT, PRIMARY KEY (product_id, voter));
  CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT, product_id TEXT NOT NULL,
    name TEXT NOT NULL, rating INTEGER NOT NULL, text TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')), approved INTEGER NOT NULL DEFAULT 1
  );
  CREATE TABLE IF NOT EXISTS inventory (product_id TEXT PRIMARY KEY, qty INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT, stripe_session TEXT UNIQUE,
    email TEXT, items TEXT NOT NULL, amount_total INTEGER NOT NULL,
    ship_to TEXT, tracking_number TEXT, label_url TEXT,
    notified INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL, name TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
  );
`);
// Migration: users.unsubscribed (promo opt-out flag). Safe to run on every boot.
try {
  const userCols = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
  if (!userCols.includes('unsubscribed')) {
    db.exec('ALTER TABLE users ADD COLUMN unsubscribed INTEGER NOT NULL DEFAULT 0');
    console.log('migration: users.unsubscribed column added');
  }
} catch (e) { console.warn('migration users.unsubscribed skipped:', e.message); }
// Migration: users.favorite_brand + users.favorite_size (2026-10-10) —
// optional preferences from the Create Account form, used to personalize
// the "new arrivals" digest emails. Safe to run on every boot.
try {
  const userCols = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
  if (!userCols.includes('favorite_brand')) {
    db.exec('ALTER TABLE users ADD COLUMN favorite_brand TEXT NOT NULL DEFAULT \'\'');
    console.log('migration: users.favorite_brand column added');
  }
  if (!userCols.includes('favorite_size')) {
    db.exec('ALTER TABLE users ADD COLUMN favorite_size TEXT NOT NULL DEFAULT \'\'');
    console.log('migration: users.favorite_size column added');
  }
} catch (e) { console.warn('migration users.preferences skipped:', e.message); }
// Migration: email verification (2026-10-10, Maria) — new accounts must
// confirm their email before the account becomes active. Existing users
// are grandfathered as verified. Safe to run on every boot.
try {
  const uCols3 = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
  if (!uCols3.includes('email_verified')) {
    db.exec('ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0');
    db.exec('UPDATE users SET email_verified = 1');
    console.log('migration: users.email_verified column added (existing users grandfathered)');
  }
  if (!uCols3.includes('verify_token')) {
    db.exec('ALTER TABLE users ADD COLUMN verify_token TEXT');
    console.log('migration: users.verify_token column added');
  }
  if (!uCols3.includes('verify_expires')) {
    db.exec('ALTER TABLE users ADD COLUMN verify_expires TEXT');
    console.log('migration: users.verify_expires column added');
  }
} catch (e) { console.warn('migration users.email_verified skipped:', e.message); }
// Migration: users.terms_accepted_at + users.terms_version (2026-10-08) —
// when the customer accepted the Terms & Conditions at signup, and which
// version. Safe to run on every boot.
// when the customer accepted the Terms & Conditions at signup, and which
// version. Safe to run on every boot.
try {
  const uCols2 = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
  if (!uCols2.includes('terms_accepted_at')) {
    db.exec('ALTER TABLE users ADD COLUMN terms_accepted_at TEXT');
    console.log('migration: users.terms_accepted_at column added');
  }
  if (!uCols2.includes('terms_version')) {
    db.exec('ALTER TABLE users ADD COLUMN terms_version TEXT');
    console.log('migration: users.terms_version column added');
  }
} catch (e) { console.warn('migration users terms columns skipped:', e.message); }
// Reviews only after a purchase (Maria's rule, 2026-10-08): one unguessable
// review_tokens row per paid order. used_store gates the one-time store-wide
// review; per-product reuse is bounded by one review row per (token, product).
db.exec(`
  CREATE TABLE IF NOT EXISTS review_tokens (
    token TEXT PRIMARY KEY,
    order_id INTEGER,
    email TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    used_store INTEGER NOT NULL DEFAULT 0
  );
`);
// Migration: orders.fulfillment + orders.ship_charged_cents (dynamic checkout
// with calculated shipping, 2026-10-08). Safe to run on every boot.
try {
  const orderCols = db.prepare('PRAGMA table_info(orders)').all().map(c => c.name);
  if (!orderCols.includes('fulfillment')) {
    db.exec("ALTER TABLE orders ADD COLUMN fulfillment TEXT NOT NULL DEFAULT 'shipping'");
    console.log('migration: orders.fulfillment column added');
  }
  if (!orderCols.includes('ship_charged_cents')) {
    db.exec('ALTER TABLE orders ADD COLUMN ship_charged_cents INTEGER NOT NULL DEFAULT 0');
    console.log('migration: orders.ship_charged_cents column added');
  }
} catch (e) { console.warn('migration orders columns skipped:', e.message); }
// Migration: orders.shipped_notified + orders.delivered_notified (2026-10-15) —
// one-shot guards for the customer "on its way" and "delivered" emails, so a
// label re-buy or a repeated delivery check never emails the customer twice.
// Safe to run on every boot.
try {
  const oCols2 = db.prepare('PRAGMA table_info(orders)').all().map(c => c.name);
  if (!oCols2.includes('shipped_notified')) {
    db.exec('ALTER TABLE orders ADD COLUMN shipped_notified INTEGER NOT NULL DEFAULT 0');
    console.log('migration: orders.shipped_notified column added');
  }
  if (!oCols2.includes('delivered_notified')) {
    db.exec('ALTER TABLE orders ADD COLUMN delivered_notified INTEGER NOT NULL DEFAULT 0');
    console.log('migration: orders.delivered_notified column added');
  }
} catch (e) { console.warn('migration orders notify columns skipped:', e.message); }
// Migration: like_votes.house (2026-10-15) — flags votes cast by the house
// (nocount-marked devices / house accounts) so they never move the public
// like counter. Pre-existing votes keep house=0: their voter ids are
// anonymous device ids never linked to an email, so house votes cast before
// this deploy cannot be identified retroactively.
try {
  const lvCols = db.prepare('PRAGMA table_info(like_votes)').all().map(c => c.name);
  if (!lvCols.includes('house')) {
    db.exec('ALTER TABLE like_votes ADD COLUMN house INTEGER NOT NULL DEFAULT 0');
    console.log('migration: like_votes.house column added');
  }
} catch (e) { console.warn('migration like_votes.house skipped:', e.message); }
// Server-side carts (2026-10-15): mirrored from the storefront so the owner
// can see live carts in /admin. One row per device (or account), only while
// the cart is non-empty.
db.exec(`CREATE TABLE IF NOT EXISTS carts (
  cart_key TEXT PRIMARY KEY,
  email TEXT,
  items TEXT NOT NULL DEFAULT '[]',
  item_count INTEGER NOT NULL DEFAULT 0,
  subtotal_cents INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);`);
try {
  const reviewCols = db.prepare('PRAGMA table_info(reviews)').all().map(c => c.name);
  if (!reviewCols.includes('verified')) {
    db.exec('ALTER TABLE reviews ADD COLUMN verified INTEGER NOT NULL DEFAULT 0');
    console.log('migration: reviews.verified column added');
  }
  if (!reviewCols.includes('review_token')) {
    db.exec('ALTER TABLE reviews ADD COLUMN review_token TEXT');
    console.log('migration: reviews.review_token column added');
  }
} catch (e) { console.warn('migration reviews columns skipped:', e.message); }
// Seed inventory from catalog quantities (only for ids not already tracked)
{
  const ins = db.prepare('INSERT OR IGNORE INTO inventory (product_id, qty) VALUES (?, ?)');
  for (const p of CATALOG) {
    const id = String(p.id || p.itemId);
    const q = Number(p.quantity ?? p.qty ?? 1);
    ins.run(id, Number.isFinite(q) ? q : 1);
  }
}
// ---------- Store settings (Maria edits her store from /admin) ----------
// JSON blobs persisted in SQLite so they survive restarts (the DB file is
// snapshotted to R2 like everything else). Keys: 'featured' (her Top
// sellers / New arrivals / Top picks choices) and 'overrides' (per-product
// price_direct / hidden set from the admin panel).
db.exec('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)');
db.exec('CREATE TABLE IF NOT EXISTS visits (day TEXT NOT NULL, visitor TEXT NOT NULL, PRIMARY KEY (day, visitor))');
db.exec('CREATE TABLE IF NOT EXISTS product_views (product_id TEXT NOT NULL, day TEXT NOT NULL, views INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (product_id, day))'); // Maria 2026-10-11: per-product views for admin 'Más vistos'
db.exec(`CREATE TABLE IF NOT EXISTS feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rating INTEGER,
  improve TEXT,
  product TEXT,
  name TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
)`); // Maria 2026-10-16: customer feedback from the printed thank-you card QR (andysshoesupply.com/feedback)
function getSetting(key, fallback) {
  try {
    const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
    if (!row || row.value == null) return fallback;
    return JSON.parse(row.value);
  } catch (e) { return fallback; }
}
function setSetting(key, obj) {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .run(key, JSON.stringify(obj ?? null));
}
const FEATURED_DEFAULTS = { top_sellers: [], new_arrivals: [], top_picks: [] };
const cleanIdList = (v) => Array.isArray(v)
  ? [...new Set(v.filter(x => typeof x === 'string' || typeof x === 'number').map(x => String(x)).filter(Boolean))]
  : [];
function getFeatured() {
  const f = getSetting('featured', null);
  const out = { top_sellers: [], new_arrivals: [], top_picks: [] };
  if (f && typeof f === 'object') {
    out.top_sellers = cleanIdList(f.top_sellers);
    out.new_arrivals = cleanIdList(f.new_arrivals);
    out.top_picks = cleanIdList(f.top_picks);
  }
  return out;
}
function getOverrides() {
  const o = getSetting('overrides', null);
  return o && typeof o === 'object' && !Array.isArray(o) ? o : {};
}

const invQty = (id) => db.prepare('SELECT qty FROM inventory WHERE product_id = ?').get(String(id))?.qty ?? 0;

// ---------- Durable SQLite snapshots (Cloudflare R2) ----------
// Likes, reviews, orders, users and sessions live in the local SQLite file, which
// Render's free plan erases on restart. When R2_* env vars are set, a consistent
// snapshot (VACUUM INTO) is uploaded every 60s and on shutdown, and restored on boot.
const R2 = {
  endpoint: process.env.R2_ENDPOINT || '',
  bucket: process.env.R2_BUCKET || '',
  key: process.env.R2_KEY || 'store.db',
  accessKeyId: process.env.R2_ACCESS_KEY_ID || '',
  secretAccessKey: process.env.R2_SECRET_ACCESS_KEY || '',
};
const r2Enabled = () => !!(R2.endpoint && R2.bucket && R2.accessKeyId && R2.secretAccessKey);
let _s3 = null;
function r2client() {
  if (!r2Enabled()) return null;
  if (!_s3) {
    const { S3Client } = require('@aws-sdk/client-s3');
    _s3 = new S3Client({ region: 'auto', endpoint: R2.endpoint,
      credentials: { accessKeyId: R2.accessKeyId, secretAccessKey: R2.secretAccessKey } });
  }
  return _s3;
}
let r2BackupRunning = false;
async function r2Backup() {
  if (!r2Enabled() || r2BackupRunning) return;
  r2BackupRunning = true;
  try {
    const tmp = DB_PATH + '.snap.' + process.pid;
    db.exec(`VACUUM INTO '${tmp.replace(/'/g, "''")}'`);
    const { PutObjectCommand } = require('@aws-sdk/client-s3');
    await r2client().send(new PutObjectCommand({ Bucket: R2.bucket, Key: R2.key, Body: fs.createReadStream(tmp) }));
    fs.unlinkSync(tmp);
    console.log('r2: snapshot backup ok');
  } catch (e) {
    console.warn('r2: backup failed -', e.message || e);
  } finally {
    r2BackupRunning = false;
  }
}
if (r2Enabled()) {
  console.log('r2: durable snapshots enabled');
  setInterval(() => { r2Backup().catch(() => {}); }, 60000).unref();
  const r2Shutdown = async () => { try { await r2Backup(); } finally { process.exit(0); } };
  process.on('SIGTERM', r2Shutdown);
  process.on('SIGINT', r2Shutdown);
}

// ---------- Helpers ----------
// Voter identity: prefer the stable per-device id the store frontend sends
// (X-Voter header / voter param, stored in the visitor's localStorage), because
// phone IPs change constantly and IP-only voters made hearts "unlike" themselves.
const voterOf = (req, productId) => {
  const v = String((req.body && req.body.voter) || req.query.voter || req.get('x-voter') || '').trim();
  if (/^[A-Za-z0-9-]{8,64}$/.test(v)) return 'v:' + v;
  return 'ip:' + crypto.createHash('sha256').update((req.ip || '') + '|' + productId + '|' + (process.env.VOTE_SALT || 'andys')).digest('hex');
};

// ---------- House identities (2026-10-15) ----------
// The owner's own emails and devices are NOT customers: their likes, carts
// and accounts must never inflate any customer count or list in the panel.
// Devices are recognized by the same andy_nocount mark the visit counter
// uses (the storefront sends header x-nocount: 1 when the mark is set);
// accounts by the emails below (all four belong to the house).
const HOUSE_EMAILS = new Set([
  'maria6234montez@gmail.com',
  'roinelpadin@gmail.com',
  'roinelpf99@gmail.com',
  'roinelypf99@gmail.com',
]);
// Normalize before comparing: lowercase, trimmed, and with any "+tag"
// stripped from the local part — Gmail delivers roinelpadin+anything@
// to the same roinelpadin@ inbox, so every +variant is the same house
// account (2026-10-16: a promo blast landed 4 times in Roinel's mailbox
// because his test accounts were not recognized as house).
const normalizeEmail = (email) => {
  const e = String(email || '').trim().toLowerCase();
  const at = e.lastIndexOf('@');
  if (at < 1) return e;
  const local = e.slice(0, at).split('+')[0];
  return local + e.slice(at);
};
const isHouseEmail = (email) => HOUSE_EMAILS.has(normalizeEmail(email));
const isHouseRequest = (req) => {
  if (String(req.get('x-nocount') || '') === '1') return true;
  const u = accountUser(req);
  return !!(u && isHouseEmail(u.email));
};

// ---------- Email (Resend) ----------
// Customer emails via the Resend HTTP API (native fetch, no new dependencies).
// If RESEND_API_KEY is not set, sendEmail is a safe no-op: it only logs
// "[email] skipped (no RESEND_API_KEY)" and the request flow continues.
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const EMAIL_FROM = process.env.EMAIL_FROM || "Andy's Shoe Supply <hola@andysshoesupply.com>";
// Version of the Terms & Conditions customers accept at signup (2026-10-08).
const TERMS_VERSION = '2026-10-08';
// Signs the one-click unsubscribe links (HMAC-SHA256). Falls back to ADMIN_TOKEN.
const EMAIL_SIGNING_SECRET = process.env.EMAIL_SECRET || ADMIN_TOKEN || '';
const escHtml = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const textToHtml = (s) => escHtml(s).replace(/\n/g, '<br>');

// Store logo shown at the top of every outgoing email. The image is a
// dark wordmark banner hosted on the store domain (assets/logo-email.png
// in the store source + deploy folder) so it blends with the dark
// header band the standalone templates already use.
const EMAIL_LOGO_URL = 'https://andysshoesupply.com/assets/logo-email.png';
const EMAIL_LOGO_IMG = (width) => '<img src="' + EMAIL_LOGO_URL + '" alt="Andy\'s Shoe Supply" width="' + width + '" style="display:inline-block;width:' + width + 'px;max-width:90%;height:auto;border:0">';
const EMAIL_LOGO_HEADER = '<div style="text-align:center;margin:0 0 20px">' + EMAIL_LOGO_IMG(240) + '</div>';

function emailShell(innerHtml) {
  return '<div style="font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.55;color:#1a1a1a">'
    + EMAIL_LOGO_HEADER
    + innerHtml
    + '<hr style="border:none;border-top:1px solid #ddd;margin:24px 0">'
    + '<p style="font-size:13px;color:#666">Thanks for shopping small!<br>'
    + 'Andy\'s Shoe Supply · Hereford, TX · <a href="https://andysshoesupply.com">andysshoesupply.com</a></p>'
    + '</div>';
}

// Never throws: callers fire-and-forget. Returns { ok, id } / { skipped: true } / { ok: false, error }.
async function sendEmail({ to, subject, html, text, headers }) {
  const recipient = String(to || '').trim();
  if (!RESEND_API_KEY) {
    console.log(`[email] skipped (no RESEND_API_KEY): "${subject}" -> ${recipient || '(no recipient)'}`);
    return { skipped: true };
  }
  if (!recipient || !subject) return { ok: false, error: 'missing to/subject' };
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: EMAIL_FROM, to: recipient, subject, html, text, headers }),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) {
      console.error(`[email] Resend ${r.status} for "${subject}" -> ${recipient}:`, JSON.stringify(j).slice(0, 200));
      return { ok: false, error: `resend http ${r.status}` };
    }
    console.log(`[email] sent "${subject}" -> ${recipient} (id ${j.id || '?'})`);
    return { ok: true, id: j.id };
  } catch (e) {
    console.error(`[email] send failed "${subject}" -> ${recipient}:`, e.message);
    return { ok: false, error: e.message };
  }
}

// ---------- Owner review copy (Maria, 2026-10-17) ----------
// Maria wants to SEE every promotional email exactly as customers get it,
// so she can review it and ask for improvements. ONE copy goes at send time,
// clearly labeled in the subject, to the inbox Maria actually monitors:
// Roinel's Gmail (destination changed 2026-10-17 at Maria's instruction —
// her personal Gmail is nearly full and she checks Roinel's). This is NOT
// part of the blast: house addresses stay excluded from every recipient
// list (2026-10-16 rule); this is a separate single send to the owner only.
const OWNER_REVIEW_EMAIL = 'roinelpadin@gmail.com';
async function sendOwnerPromoCopy({ subject, html, text }) {
  try {
    const r = await sendEmail({
      to: OWNER_REVIEW_EMAIL,
      subject: `👀 TU COPIA — ${subject}`,
      html,
      text: `— Copia de revisión: así les llegó este correo a los clientes —\n\n${text || ''}`,
    });
    if (r && r.ok) console.log(`[email] owner review copy sent: "${subject}"`);
    return r;
  } catch (e) {
    console.error('[email] owner review copy failed:', e.message);
    return { ok: false, error: e.message };
  }
}

async function sendWelcomeEmail(email, name) {
  const first = String(name || '').trim().split(/\s+/)[0];
  const text = `Hi${first ? ' ' + first : ''}!

Welcome to Andy's Shoe Supply — thanks for creating your account!

Every pair in our direct store is 15% OFF the eBay price, every day — Nike, Jordan, Hoka, adidas and more, with new pairs landing all the time.

Start shopping: https://andysshoesupply.com

Thanks for shopping small!
Andy's Shoe Supply · Hereford, TX

By creating an account you agree to our Terms & Conditions: https://andysshoesupply.com/terms`;
  const html = ''
    + '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>'
    + '<body style="margin:0;padding:0;background:#f4f1ea;font-family:Arial,Helvetica,sans-serif">'
    + '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f1ea"><tr><td align="center" style="padding:24px 12px">'
    + '<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:14px;overflow:hidden">'
    + '<tr><td style="background:#111111;padding:34px 28px;text-align:center">'
    + EMAIL_LOGO_IMG(320)
    + '</td></tr>'
    + '<tr><td style="padding:34px 30px 6px;color:#1a1a1a">'
    + `<p style="font-size:22px;font-weight:700;margin:0 0 12px">Hi${first ? ' ' + escHtml(first) : ''}, welcome aboard!</p>`
    + '<p style="font-size:16px;line-height:1.6;margin:0 0 18px">Thanks for creating your account at <strong>Andy\'s Shoe Supply</strong>. You now get our direct-store prices on every pair we carry — Nike, Jordan, Hoka, adidas and more, with new pairs landing all the time.</p>'
    + '</td></tr>'
    + '<tr><td style="padding:4px 30px"><div style="background:#fff7e0;border:2px dashed #f5c518;border-radius:12px;padding:20px;text-align:center">'
    + '<div style="font-size:34px;font-weight:800;color:#111111">15% OFF</div>'
    + '<div style="font-size:15px;color:#444444;margin-top:6px">Every pair in our direct store, every day — no code needed.</div>'
    + '</div></td></tr>'
    + '<tr><td style="padding:26px 30px 8px;text-align:center">'
    + '<a href="https://andysshoesupply.com" style="display:inline-block;background:#111111;color:#ffffff;font-size:18px;font-weight:700;text-decoration:none;padding:16px 44px;border-radius:999px">Start shopping</a>'
    + '</td></tr>'
    + '<tr><td style="padding:18px 30px 30px;color:#666666;font-size:13px;line-height:1.6;text-align:center">'
    + '<p style="margin:0 0 10px">Thanks for shopping small!<br>Andy\'s Shoe Supply · Hereford, TX · <a href="https://andysshoesupply.com" style="color:#666666">andysshoesupply.com</a></p>'
    + '<p style="margin:0;font-size:12px;color:#888888">By creating an account you agree to our <a href="https://andysshoesupply.com/terms" style="color:#888888;text-decoration:underline">Terms &amp; Conditions</a>: andysshoesupply.com/terms</p>'
    + '</td></tr>'
    + '</table>'
    + '</td></tr></table>'
    + '</body></html>';
  return sendEmail({ to: email, subject: "Welcome to Andy's Shoe Supply", html, text });
}

// Verification email for new accounts (Maria, 2026-10-10): the user must
// click the link to confirm their email before the account becomes active.
async function sendVerificationEmail(email, name, token) {
  const link = `https://andys-store-backend.onrender.com/api/account/verify?token=${encodeURIComponent(token)}`;
  const first = String(name || '').trim().split(/\s+/)[0];
  const text = `Hi${first ? ' ' + first : ''}!

One last step: confirm your email to finish creating your Andy's Shoe Supply account.

Confirm my email: ${link}

This link expires in 48 hours. If you didn't create this account, just ignore this email.

Andy's Shoe Supply · Hereford, TX`;
  const html = ''
    + '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>'
    + '<body style="margin:0;padding:0;background:#f4f1ea;font-family:Arial,Helvetica,sans-serif">'
    + '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f1ea"><tr><td align="center" style="padding:24px 12px">'
    + '<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:14px;overflow:hidden">'
    + '<tr><td style="background:#111111;padding:34px 28px;text-align:center">'
    + EMAIL_LOGO_IMG(320)
    + '</td></tr>'
    + '<tr><td style="padding:34px 30px 8px;color:#1a1a1a;text-align:center">'
    + `<p style="font-size:24px;font-weight:800;margin:0 0 12px">One last step, ${first ? escHtml(first) : 'friend'}! ✉️</p>`
    + '<p style="font-size:16px;line-height:1.65;margin:0 0 22px">Tap the button below to <strong>confirm your email</strong> and finish creating your account. Then you can shop every pair at <strong>15% OFF the eBay price</strong>.</p>'
    + `<a href="${link}" style="display:inline-block;background:#d22;color:#ffffff;font-size:18px;font-weight:700;text-decoration:none;padding:16px 44px;border-radius:999px">Confirm my email</a>`
    + '<p style="font-size:13px;color:#888888;margin:18px 0 0">This link expires in 48 hours.<br>If you didn\'t create this account, just ignore this email.</p>'
    + '</td></tr>'
    + '<tr><td style="padding:18px 30px 30px;color:#666666;font-size:13px;line-height:1.6;text-align:center">'
    + '<p style="margin:0">Andy\'s Shoe Supply · Hereford, TX · <a href="https://andysshoesupply.com" style="color:#666666">andysshoesupply.com</a></p>'
    + '</td></tr>'
    + '</table>'
    + '</td></tr></table>'
    + '</body></html>';
  return sendEmail({ to: email, subject: "Confirm your email — Andy's Shoe Supply", html, text });
}

// Human title for an order line item. Payment Link variants carry the id
// "398339652878__size_6" (see make_variant_links.py) — show "Title — Size 6".
function orderItemTitle(it) {
  const raw = String(it.id || '');
  const m = raw.match(/^(.+?)__size_(.+)$/);
  const p = byId.get(m ? m[1] : raw);
  const title = (p && (p.title || p.name)) || raw;
  // Size comes either embedded in the id ("...__size_6", Payment Link flow) or
  // as its own field on the order item (dynamic checkout flow).
  const size = m ? m[2] : (it.size != null && String(it.size) !== '' ? String(it.size) : null);
  return size ? `${title} — Size ${size}` : String(title);
}

// ---------- Review-after-purchase tokens ----------
// One unguessable token per new paid order, created in the webhook and carried
// in the confirmation email (?rt=<token>). The review endpoints refuse to post
// without one — Maria's rule: reviews only after buying.
function createReviewToken(orderId, email) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO review_tokens (token, order_id, email) VALUES (?, ?, ?)')
    .run(token, orderId ?? null, String(email || ''));
  return token;
}
function getReviewToken(token) {
  const t = String(token || '').trim();
  if (!/^[0-9a-f]{64}$/.test(t)) return null;
  return db.prepare('SELECT * FROM review_tokens WHERE token = ?').get(t) || null;
}
// Did this order include the product? Order items may carry Payment Link
// variant ids ("398339652878__size_6") — match on the base product id.
function orderIncludesProduct(orderId, productId) {
  const row = db.prepare('SELECT items FROM orders WHERE id = ?').get(orderId);
  if (!row) return false;
  let items; try { items = JSON.parse(row.items || '[]'); } catch { return false; }
  const base = (raw) => String(raw).split('__size_')[0];
  return items.some(it => base(it.id) === String(productId));
}

async function sendPurchaseConfirmation(session, items, reviewToken, orderId) {
  const to = session.customer_email || session.customer_details?.email || '';
  if (!to) {
    console.log('[email] purchase confirmation skipped: no customer email on session', session.id);
    return { skipped: true };
  }
  const lines = items.map(it => {
    const qty = Math.max(1, Number(it.qty) | 0);
    return { label: orderItemTitle(it), qty };
  });
  const totalCents = Number(session.amount_total) || 0;
  const totalLine = totalCents > 0 ? `Total charged: $${(totalCents / 100).toFixed(2)}` : '';
  const orderLine = orderId ? `Order #${orderId}` : '';
  // Review links carry this order's token — only buyers can review (Maria's
  // rule), and the token proves this purchase at the API.
  const storeUrl = reviewToken
    ? `https://andysshoesupply.com/?rt=${reviewToken}#reviews`
    : 'https://andysshoesupply.com/#reviews';
  const itemLinks = [];
  if (reviewToken) {
    const seen = new Set();
    for (const it of items) {
      const baseId = String(it.id || '').split('__size_')[0];
      if (!baseId || seen.has(baseId)) continue;
      seen.add(baseId);
      itemLinks.push({ label: orderItemTitle(it), url: `https://andysshoesupply.com/?rt=${reviewToken}` });
    }
  }
  const text = `Thanks for your order!
${orderLine ? '\n' + orderLine + '\n' : ''}
Your payment went through and we're getting everything ready. Here's your order:

${lines.map(l => `• ${l.label}${l.qty > 1 ? ` × ${l.qty}` : ''}`).join('\n')}
${totalLine ? '\n' + totalLine + '\n' : ''}
We'll send your tracking number as soon as your shipping label is ready. You can also see your orders anytime under My Account on our site.

How was your experience? Review our store:
${storeUrl}
${itemLinks.length ? `\nReview your items too — your review gets a Verified Purchase badge:\n${itemLinks.map(l => `• ${l.label}: ${l.url}`).join('\n')}\n` : ''}
— Andy's Shoe Supply`;
  const html = emailShell(
    '<p>Thanks for your order!</p>'
    + (orderLine ? `<p><strong>${escHtml(orderLine)}</strong></p>` : '')
    + '<p>Your payment went through and we\'re getting everything ready. Here\'s your order:</p>'
    + '<ul>' + lines.map(l => `<li>${escHtml(l.label)}${l.qty > 1 ? ` × ${l.qty}` : ''}</li>`).join('') + '</ul>'
    + (totalLine ? `<p><strong>${escHtml(totalLine)}</strong></p>` : '')
    + '<p>We\'ll send your tracking number as soon as your shipping label is ready. You can also see your orders anytime under My Account on our site.</p>'
    + `<p><strong>How was your experience?</strong> <a href="${storeUrl}">Review our store</a></p>`
    + (itemLinks.length
      ? '<p>Review your items too — your review gets a <strong>Verified Purchase</strong> badge:</p><ul>'
        + itemLinks.map(l => `<li><a href="${l.url}">${escHtml(l.label)}</a></li>`).join('') + '</ul>'
      : '')
  );
  return sendEmail({ to, subject: "Your Andy's Shoe Supply order is confirmed", html, text });
}

// Order alert for the store owners (Maria asked for an email on every sale,
// 2026-10-09; later same day: also to the business account email). Fire-and-
// forget: never blocks or fails the Stripe webhook.
const ORDER_NOTIFY_EMAILS = (process.env.ORDER_NOTIFY_EMAILS || 'maria6234montez@gmail.com,roinelpadin@gmail.com')
  .split(',').map(s => s.trim()).filter(Boolean);
function sendOrderNotification(session, items, orderId) {
  const total = ((Number(session.amount_total) || 0) / 100).toFixed(2);
  const buyer = session.customer_email || session.customer_details?.email || '';
  const shipName = session.customer_details?.name || '';
  const lines = (items || []).map(it => `• ${orderItemTitle(it)}${Number(it.qty) > 1 ? ` × ${it.qty}` : ''}`);
  const text = `¡Nueva venta en tu tienda!\n\nOrden #${orderId || ''}\nCliente: ${shipName} <${buyer}>\n\n${lines.join('\n')}\n\nTotal cobrado: $${total}\n\nVela en tu panel: https://andysshoesupply.com/admin\n— Andy's Shoe Supply`;
  const html = emailShell(
    '<p><strong>¡Nueva venta en tu tienda!</strong></p>'
    + `<p>Orden #${orderId || ''} — Cliente: ${escHtml(shipName)} &lt;${escHtml(buyer)}&gt;</p>`
    + '<ul>' + lines.map(l => `<li>${escHtml(l.replace(/^• /, ''))}</li>`).join('') + '</ul>'
    + `<p><strong>Total cobrado: $${total}</strong></p>`
    + '<p><a href="https://andysshoesupply.com/admin">Verla en tu panel</a></p>'
  );
  return Promise.all(ORDER_NOTIFY_EMAILS.map(to =>
    sendEmail({ to, subject: `Nueva venta en tu tienda — $${total}`, html, text })));
}

// ---------- Shipped + delivered customer emails (2026-10-15) ----------
// "On its way" fires once per order, right after its shipping label is bought
// (notifyOrderShipped, called by both label buyers). "Delivered + review
// invite" fires once when the carrier tracking reports DELIVERED
// (refreshOrderDelivery). There are no Shippo webhooks registered today, so
// delivery is detected by a light tracking check: when the customer consults
// the order (thank-you screen / My Account) and from the cron sweep
// POST /api/cron/delivery-check. Both emails use the standard shell + logo.
function trackingUrlFor(carrier, tn) {
  const c = String(carrier || '').toLowerCase(), n = encodeURIComponent(String(tn || ''));
  if (!n) return '';
  if (c.includes('ups')) return 'https://www.ups.com/track?tracknum=' + n;
  if (c.includes('fedex')) return 'https://www.fedex.com/fedextrack/?trknbr=' + n;
  return 'https://tools.usps.com/go/TrackConfirmAction?tLabels=' + n; // USPS: our labels
}
function orderItemsOf(order) {
  try { const v = JSON.parse(order.items || '[]'); return Array.isArray(v) ? v : []; }
  catch { return []; }
}
function orderLinesOf(order) {
  return orderItemsOf(order).map(it => ({
    label: orderItemTitle(it),
    qty: Math.max(1, Number(it.qty) || 1),
  }));
}

async function sendShippedEmail(order, carrier) {
  const to = String(order.email || '').trim();
  if (!to) return { skipped: true };
  const lines = orderLinesOf(order);
  const tn = String(order.tracking_number || '');
  const trackUrl = trackingUrlFor(carrier, tn);
  const text = `Good news — your order is on its way!

Order #${order.id}

${lines.map(l => `• ${l.label}${l.qty > 1 ? ` × ${l.qty}` : ''}`).join('\n')}

Tracking number: ${tn}
${trackUrl ? `Track your package: ${trackUrl}\n` : ''}
Thanks for shopping with us!
— Andy's Shoe Supply`;
  const html = emailShell(
    '<p><strong>Good news — your order is on its way!</strong></p>'
    + `<p>Order #${order.id}</p>`
    + '<ul>' + lines.map(l => `<li>${escHtml(l.label)}${l.qty > 1 ? ` × ${l.qty}` : ''}</li>`).join('') + '</ul>'
    + `<p>Tracking number: <strong>${escHtml(tn)}</strong></p>`
    + (trackUrl ? `<p><a href="${trackUrl}">Track your package</a></p>` : '')
    + '<p>Thanks for shopping with us!</p>'
  );
  return sendEmail({ to, subject: `Your Andy's Shoe Supply order #${order.id} is on its way`, html, text });
}

// Fire-and-forget from the label buyers. Guarded by orders.shipped_notified
// so the customer is emailed exactly once per order.
async function notifyOrderShipped(orderId, carrier) {
  try {
    const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(Number(orderId));
    if (!order || !order.email || !order.tracking_number || order.shipped_notified) return;
    const r = await sendShippedEmail(order, carrier);
    if (r && r.ok) db.prepare('UPDATE orders SET shipped_notified = 1 WHERE id = ?').run(order.id);
  } catch (e) { console.error('shipped email failed:', e.message); }
}

async function sendDeliveredEmail(order) {
  const to = String(order.email || '').trim();
  if (!to) return { skipped: true };
  const lines = orderLinesOf(order);
  // Review links carry THIS order's purchase token (same gate as the
  // confirmation email): only the buyer can review, with a Verified badge.
  const tokenRow = db.prepare('SELECT token FROM review_tokens WHERE order_id = ? ORDER BY created_at ASC LIMIT 1').get(order.id);
  const reviewToken = tokenRow ? tokenRow.token : null;
  const storeUrl = reviewToken
    ? `https://andysshoesupply.com/?rt=${reviewToken}#reviews`
    : 'https://andysshoesupply.com/#reviews';
  const itemLinks = [];
  if (reviewToken) {
    const seen = new Set();
    for (const it of orderItemsOf(order)) {
      const baseId = String(it.id || '').split('__size_')[0];
      if (!baseId || seen.has(baseId)) continue;
      seen.add(baseId);
      itemLinks.push({ label: orderItemTitle(it), url: `https://andysshoesupply.com/?rt=${reviewToken}` });
    }
  }
  const text = `Your order was delivered!

Order #${order.id}

${lines.map(l => `• ${l.label}${l.qty > 1 ? ` × ${l.qty}` : ''}`).join('\n')}

Thank you for shopping with Andy's Shoe Supply — we hope you love your pair!

Enjoying them? A quick review helps our small family store a lot:
Review our store: ${storeUrl}
${itemLinks.length ? `\nReview your items too:\n${itemLinks.map(l => `• ${l.label}: ${l.url}`).join('\n')}\n` : ''}
— Andy's Shoe Supply`;
  const html = emailShell(
    '<p><strong>Your order was delivered!</strong></p>'
    + `<p>Order #${order.id}</p>`
    + '<ul>' + lines.map(l => `<li>${escHtml(l.label)}${l.qty > 1 ? ` × ${l.qty}` : ''}</li>`).join('') + '</ul>'
    + '<p>Thank you for shopping with Andy\'s Shoe Supply — we hope you love your pair!</p>'
    + `<p><strong>Enjoying them?</strong> A quick review helps our small family store a lot: <a href="${storeUrl}">Review our store</a></p>`
    + (itemLinks.length
      ? '<p>Review your items too:</p><ul>'
        + itemLinks.map(l => `<li><a href="${l.url}">${escHtml(l.label)}</a></li>`).join('') + '</ul>'
      : '')
  );
  return sendEmail({ to, subject: `Delivered: your Andy's Shoe Supply order #${order.id}`, html, text });
}

// Carrier tracking status lookups (best-effort; null = unknown / no tracker).
async function shippoTrackingStatus(tn) {
  const r = await fetch(`${SHIPPO_API}/tracks/usps/${encodeURIComponent(tn)}`, {
    headers: shippoHeaders(), signal: AbortSignal.timeout(5000),
  });
  if (!r.ok) return null;
  const j = await r.json().catch(() => ({}));
  return j && j.tracking_status ? String(j.tracking_status.status || '') : null;
}
async function easypostTrackingStatus(tn) {
  const r = await fetch(`${EASYPOST_API}/trackers?tracking_code=${encodeURIComponent(tn)}`, {
    headers: epHeaders(), signal: AbortSignal.timeout(5000),
  });
  if (!r.ok) return null;
  const j = await r.json().catch(() => ({}));
  const t = (j.trackers || [])[0];
  return t ? String(t.status || '') : null;
}

// If the carrier already delivered this order: flip status to 'delivered'
// and send the thank-you + review email (once, guarded by delivered_notified).
// Never throws — safe to call from request handlers and the cron sweep.
async function refreshOrderDelivery(order) {
  try {
    if (!order || !order.tracking_number || order.delivered_notified || order.status === 'delivered') return false;
    let st = null;
    if (process.env.EASYPOST_API_KEY) st = await easypostTrackingStatus(order.tracking_number);
    else if (process.env.SHIPPO_TOKEN) st = await shippoTrackingStatus(order.tracking_number);
    if (!st || st.toUpperCase() !== 'DELIVERED') return false;
    db.prepare("UPDATE orders SET status = 'delivered', delivered_notified = 1 WHERE id = ?").run(order.id);
    order.status = 'delivered'; order.delivered_notified = 1;
    sendDeliveredEmail(order).catch(e => console.error('delivered email failed:', e.message));
    console.log(`Order ${order.id} marked delivered (tracking ${order.tracking_number})`);
    return true;
  } catch (e) {
    console.warn('delivery check failed for order', order && order.id, ':', e.message);
    return false;
  }
}

// SMS sale alerts (Maria approved 2026-10-09 20:08 CDT: texts to her numbers
// on every sale). Uses Twilio when its env vars are set; safe no-op until
// then. Fire-and-forget: never blocks or fails the Stripe webhook.
const TWILIO_SID = process.env.TWILIO_ACCOUNT_SID || '';
const TWILIO_TOKEN = process.env.TWILIO_AUTH_TOKEN || '';
const TWILIO_FROM = process.env.TWILIO_FROM_NUMBER || '';
const ORDER_SMS_TO = (process.env.ORDER_SMS_TO || '+17025806374,+18063448673')
  .split(',').map(s => s.trim()).filter(Boolean);
async function sendOrderSms(session, items, orderId) {
  if (!TWILIO_SID || !TWILIO_TOKEN || !TWILIO_FROM) {
    console.log('[sms] skipped (Twilio not configured)');
    return { skipped: true };
  }
  const total = ((Number(session.amount_total) || 0) / 100).toFixed(2);
  const first = items && items[0] ? orderItemTitle(items[0]) : 'tu tienda';
  const more = items && items.length > 1 ? ` y ${items.length - 1} más` : '';
  const body = `¡Nueva venta en Andy's Shoe Supply! ${first}${more}. Total: $${total}. Orden #${orderId || ''} — mírala en andysshoesupply.com/admin`;
  const auth = Buffer.from(`${TWILIO_SID}:${TWILIO_TOKEN}`).toString('base64');
  for (const to of ORDER_SMS_TO) {
    try {
      const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${TWILIO_SID}/Messages.json`, {
        method: 'POST',
        headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ To: to, From: TWILIO_FROM, Body: body }).toString(),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) console.error(`[sms] Twilio ${r.status} -> ${to}:`, (j.message || JSON.stringify(j)).slice(0, 180));
      else console.log(`[sms] sent -> ${to} (${j.sid || ''})`);
    } catch (e) {
      console.error(`[sms] failed -> ${to}:`, e.message);
    }
  }
  return { ok: true };
}

// One-click unsubscribe links: base64url(JSON {u: userId, e: email}) + "." + HMAC-SHA256(payload).
function unsubToken(userId, email) {
  const payload = Buffer.from(JSON.stringify({ u: userId, e: String(email || '').toLowerCase() }), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', EMAIL_SIGNING_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}
function parseUnsubToken(t) {
  const parts = String(t || '').split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  const expected = crypto.createHmac('sha256', EMAIL_SIGNING_SECRET).update(parts[0]).digest();
  let got;
  try { got = Buffer.from(parts[1], 'base64url'); } catch { return null; }
  if (got.length !== expected.length || !crypto.timingSafeEqual(got, expected)) return null;
  try {
    const o = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    return (o && o.u && o.e) ? o : null;
  } catch { return null; }
}
function unsubscribeUrl(req, userId, email) {
  const base = String(process.env.API_PUBLIC_URL || process.env.RENDER_EXTERNAL_URL
    || (req ? `${req.protocol}://${req.get('host')}` : '')).replace(/\/+$/, '');
  return `${base}/api/unsubscribe?t=${unsubToken(userId, email)}`;
}

app.get('/api/unsubscribe', (req, res) => {
  const page = (msg) => '<!doctype html><html><head><meta charset="utf-8">'
    + '<title>Unsubscribe — Andy\'s Shoe Supply</title></head>'
    + '<body style="font-family:Arial,Helvetica,sans-serif;padding:32px;color:#1a1a1a">'
    + '<h1 style="font-size:20px">Andy\'s Shoe Supply</h1><p>' + msg + '</p>'
    + '<p><a href="https://andysshoesupply.com">Back to the store</a></p></body></html>';
  const data = parseUnsubToken(req.query.t);
  if (!data) return res.status(400).type('html').send(page('That unsubscribe link is invalid or expired.'));
  const user = db.prepare('SELECT id, email FROM users WHERE id = ?').get(data.u);
  if (!user || user.email.toLowerCase() !== data.e)
    return res.status(400).type('html').send(page('That unsubscribe link is invalid or expired.'));
  db.prepare('UPDATE users SET unsubscribed = 1 WHERE id = ?').run(user.id);
  res.type('html').send(page('You have been unsubscribed. You will no longer receive promotional emails from us. (Order emails still arrive when you buy something.)'));
});

// Admin promo blast: POST { subject, text } → one email per registered,
// non-unsubscribed user, each with its own signed unsubscribe link.
app.post('/api/admin/send-promo', requireAdmin, async (req, res) => {
  try {
    const subject = String(req.body.subject || '').trim().slice(0, 150);
    const text = String(req.body.text || '').trim().slice(0, 8000);
    if (!subject || !text) return res.status(400).json({ error: 'subject and text are required' });
    if (!RESEND_API_KEY) return res.status(503).json({ error: 'email not configured (set RESEND_API_KEY)' });
    const users = db.prepare('SELECT id, email, name FROM users WHERE unsubscribed = 0 ORDER BY id').all()
      .filter(u => !isHouseEmail(u.email));
    let sent = 0, failed = 0;
    for (const u of users) {
      const unsub = unsubscribeUrl(req, u.id, u.email);
      const r = await sendEmail({
        to: u.email,
        subject,
        html: emailShell(
          `<div>${textToHtml(text)}</div>`
          + `<p style="font-size:12px;color:#888;margin-top:20px">You're receiving this because you have an account at Andy's Shoe Supply. <a href="${unsub}">Unsubscribe</a></p>`
        ),
        text: `${text}\n\n—\nDon't want these emails? Unsubscribe here: ${unsub}`,
        headers: { 'List-Unsubscribe': `<${unsub}>` },
      });
      if (r.ok) sent++; else failed++;
      // Gentle pacing to stay under Resend's per-second rate limits.
      if (users.length > 1) await new Promise(done => setTimeout(done, 350));
    }
    console.log(`[email] promo "${subject}": ${sent} sent, ${failed} failed, ${users.length} recipients`);
    if (sent > 0) {
      await sendOwnerPromoCopy({
        subject,
        html: emailShell(
          `<div>${textToHtml(text)}</div>`
          + `<p style="font-size:12px;color:#888;margin-top:20px">Review copy for the owner — not sent to customers.</p>`
        ),
        text,
      });
    }
    res.json({ ok: true, recipients: users.length, sent, failed, ownerCopy: sent > 0 });
  } catch (e) {
    console.error('send-promo error:', e.message);
    res.status(500).json({ error: 'promo send failed', detail: e.message });
  }
});

// ---------- October giveaway promo to subscribers (Maria, 2026-10-14) ----------
// One-off blast about the October Community Giveaway. POST
// /api/cron/send-giveaway-promo (header x-cron-secret) — the subject and
// body are FIXED here (approved copy, not taken from the request), and the
// send is guarded by a setting so it can only go out once.
const GIVEAWAY_PROMO_SUBJECT = "🎁 You're invited: win up to $400 cash or $500 in shoes — free to enter";
const GIVEAWAY_PROMO_TEXT = `Hi! This is Andy's Shoe Supply — thanks for being part of our store. 💛

We're running our October Community Giveaway, and as one of our customers/subscribers, we want YOU in it:

💰 Win $50 to $400 in CASH
👟 or brand-new shoes worth $80 to $500 (your size, shipped free anywhere in the US)

Entering is 100% FREE and takes less than a minute:
1. Follow us on Facebook: Andy's Shoe Supply
2. Follow our eBay store: andysshoesupply
3. Comment DONE on the giveaway post on Facebook

Want extra chances? Follow us on TikTok (+1 entry) and invite friends with your personal referral code (+1 per friend, up to 4). Get your code by texting the word CODE to (806) 344-8673.

⏰ Entries close Sunday, October 25 — the winner is drawn LIVE on Facebook that day at 8:00 PM Central.

Full rules: https://andysshoesupply.com/reglas-sorteo/

Good luck — and thank you for supporting our small Hereford, Texas store!
— Andy's Shoe Supply`;

app.post('/api/cron/send-giveaway-promo', async (req, res) => {
  try {
    const secret = process.env.CRON_SECRET;
    if (!secret) return res.status(503).json({ ok: false, error: 'CRON_SECRET not configured' });
    const a = Buffer.from(req.get('x-cron-secret') || ''), b = Buffer.from(secret);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b))
      return res.status(401).json({ ok: false, error: 'unauthorized' });
    if (!RESEND_API_KEY) return res.status(503).json({ ok: false, error: 'email not configured (set RESEND_API_KEY)' });

    const already = getSetting('giveaway_promo_sent_at', null);
    if (already)
      return res.json({ ok: true, alreadySent: true, sentAt: already, recipients: 0, sent: 0, failed: 0 });

    const users = db.prepare('SELECT id, email, name FROM users WHERE unsubscribed = 0 ORDER BY id').all()
      .filter(u => !isHouseEmail(u.email));
    let sent = 0, failed = 0;
    for (const u of users) {
      const unsub = unsubscribeUrl(req, u.id, u.email);
      const r = await sendEmail({
        to: u.email,
        subject: GIVEAWAY_PROMO_SUBJECT,
        html: emailShell(
          `<div>${textToHtml(GIVEAWAY_PROMO_TEXT)}</div>`
          + `<p style="font-size:12px;color:#888;margin-top:20px">You're receiving this because you have an account at Andy's Shoe Supply. <a href="${unsub}">Unsubscribe</a></p>`
        ),
        text: `${GIVEAWAY_PROMO_TEXT}\n\n—\nDon't want these emails? Unsubscribe here: ${unsub}`,
        headers: { 'List-Unsubscribe': `<${unsub}>` },
      });
      if (r.ok) sent++; else failed++;
      // Gentle pacing to stay under Resend's per-second rate limits.
      if (users.length > 1) await new Promise(done => setTimeout(done, 350));
    }
    console.log(`[email] giveaway promo "${GIVEAWAY_PROMO_SUBJECT}": ${sent} sent, ${failed} failed, ${users.length} recipients`);
    if (sent > 0) {
      setSetting('giveaway_promo_sent_at', new Date().toISOString());
      await sendOwnerPromoCopy({
        subject: GIVEAWAY_PROMO_SUBJECT,
        html: emailShell(
          `<div>${textToHtml(GIVEAWAY_PROMO_TEXT)}</div>`
          + `<p style="font-size:12px;color:#888;margin-top:20px">Review copy for the owner — not sent to customers.</p>`
        ),
        text: GIVEAWAY_PROMO_TEXT,
      });
    }
    res.json({ ok: true, recipients: users.length, sent, failed, ownerCopy: sent > 0 });
  } catch (e) {
    console.error('giveaway promo error:', e.message);
    res.status(500).json({ ok: false, error: 'giveaway promo failed', detail: e.message });
  }
});

// ---------- New-arrivals digest emails (Maria, 2026-10-10) ----------
// A cron job calls POST /api/cron/new-arrivals (header x-cron-secret).
// The email goes out ONLY when 20+ un-mailed new arrivals pile up, and
// never more than once per 3 days (Maria: no daily emails — people
// unsubscribe when you fill their inbox). Each user gets a personalized
// 3-pick: their favorite brand/size first, everyone else the 3 freshest.
const NEWARRIVALS_THRESHOLD = 20;
const NEWARRIVALS_MIN_DAYS = 3;

function getMailedNewArrivals() {
  try { const v = getSetting('newarrivals_mailed', null); return Array.isArray(v) ? v : []; }
  catch (e) { return []; }
}

function newArrivalCandidates() {
  const mailed = new Set(getMailedNewArrivals().map(String));
  return CATALOG
    .filter(p => p && p.added && !mailed.has(String(p.id)))
    .sort((a, b) => String(b.added).localeCompare(String(a.added)));
}

function pick3NewArrivals(user, candidates) {
  const fb = String(user.favorite_brand || '').trim().toLowerCase();
  const fs = String(user.favorite_size || '').trim().replace(/\s+/g, '').toLowerCase();
  const picks = [], seen = new Set();
  const take = (p) => { const id = String(p.id); if (!seen.has(id)) { picks.push(p); seen.add(id); } };
  const brandHit = (p) => {
    const b = String(p.brand || '').trim().toLowerCase();
    return fb && b && (b.includes(fb) || fb.includes(b));
  };
  const sizeHit = (p) => {
    const s = String(p.size || '').trim().replace(/\s+/g, '').toLowerCase();
    return fs && s && (s.includes(fs) || fs.includes(s));
  };
  if (fb || fs) {
    for (const p of candidates) { // exact brand+size matches first
      if (brandHit(p) && (fs ? sizeHit(p) : true)) { take(p); if (picks.length >= 3) break; }
    }
    if (fb) { // then any of their brand
      for (const p of candidates) { if (brandHit(p)) { take(p); if (picks.length >= 3) break; } }
    }
  }
  for (const p of candidates) { take(p); if (picks.length >= 3) break; } // fill with freshest
  return picks.slice(0, 3);
}

function newArrivalImg(p) {
  // Store-only products use relative asset paths (assets/catalog/...) which
  // do NOT load inside an email — turn them into full domain URLs.
  const raw = String(p.image || '').trim();
  return /^https?:\/\//i.test(raw) ? raw : ('https://andysshoesupply.com/' + raw.replace(/^\/+/, ''));
}

function newArrivalCard(p) {
  const link = 'https://andysshoesupply.com/#item-' + encodeURIComponent(p.id);
  const img = escHtml(newArrivalImg(p));
  const title = escHtml(p.title || p.name || 'New arrival');
  const price = '$' + Number(p.price_direct || p.price || 0).toFixed(2);
  const sizeLine = p.size ? `<div style="font-size:14px;color:#555555;margin-top:4px">Size ${escHtml(p.size)}</div>` : '';
  return '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 18px;background:#ffffff;border:1px solid #eeeeee;border-radius:14px;overflow:hidden">'
    + '<tr><td align="center" style="padding:0;background:#ffffff">'
    + `<a href="${link}" style="text-decoration:none;color:#111111"><img src="${img}" alt="${title}" width="560" style="width:100%;max-width:560px;height:auto;display:block;border:0"></a>`
    + '</td></tr>'
    + '<tr><td style="padding:16px 20px 20px;background:#ffffff">'
    + `<a href="${link}" style="text-decoration:none;color:#111111"><div style="font-size:17px;font-weight:700;color:#111111">${title}</div></a>`
    + `<div style="font-size:22px;font-weight:800;color:#111111;margin-top:8px">${price} <span style="font-size:12px;font-weight:700;color:#ffffff;background:#d22;padding:3px 9px;border-radius:6px;vertical-align:middle">15% OFF</span></div>`
    + sizeLine
    + `<div style="margin-top:12px"><a href="${link}" style="display:inline-block;background:#111111;color:#ffffff;font-size:15px;font-weight:700;text-decoration:none;padding:12px 30px;border-radius:999px">See this pair</a></div>`
    + '</td></tr></table>';
}

app.post('/api/cron/new-arrivals', async (req, res) => {
  try {
    const secret = process.env.CRON_SECRET;
    if (!secret) return res.status(503).json({ ok: false, error: 'CRON_SECRET not configured' });
    const a = Buffer.from(req.get('x-cron-secret') || ''), b = Buffer.from(secret);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b))
      return res.status(401).json({ ok: false, error: 'unauthorized' });

    const dry = req.query.dry === '1';
    const testTo = String(req.query.to || '').trim().toLowerCase();
    const candidates = newArrivalCandidates();
    const pending = candidates.length;

    // Preview to a single address (Maria's), without marking anything as
    // mailed. Works even before the threshold is reached.
    if (dry && testTo) {
      if (!RESEND_API_KEY) return res.status(503).json({ ok: false, error: 'email not configured (set RESEND_API_KEY)' });
      const cards = candidates.slice(0, 3).map(newArrivalCard).join('');
      await sendEmail({
        to: testTo,
        subject: `[Preview] ${pending} new pairs at Andy's Shoe Supply`,
        html: emailShell(`<p style="font-size:14px;font-weight:700;letter-spacing:2px;color:#d22;margin:0 0 4px">👀 PREVIEW — NOT MAILED TO ANYONE</p>`
          + `<p style="font-size:30px;font-weight:800;margin:0 0 10px;color:#111111">NEW ARRIVALS JUST LANDED 👟</p>`
          + `<p style="font-size:16px;line-height:1.65;color:#333333;margin:0 0 12px">${pending} brand-new pairs just hit our direct store — and remember, everything at Andy's Shoe Supply is always <strong>15% OFF the eBay price</strong>. No codes, no games, every day.</p>`
          + `<p style="font-size:15px;line-height:1.6;color:#555555;margin:0 0 20px">This is exactly how the email your subscribers would get looks. Here are 3 of the ${pending} fresh pairs:</p>`
          + cards
          + `<p style="font-size:15px;line-height:1.6;color:#333333;margin:4px 0 18px">And that's just a taste — there are <strong>${pending} fresh pairs</strong> waiting. They go fast, so don't sleep on your size.</p>`
          + `<p style="text-align:center;margin:6px 0 18px"><a href="https://andysshoesupply.com/#new-arrivals-rail" style="display:inline-block;background:#d22;color:#fff;font-size:17px;font-weight:700;text-decoration:none;padding:15px 40px;border-radius:999px">Shop all new arrivals</a></p>`
          + `<p style="font-size:13px;color:#888888;text-align:center;margin:0">100% authentic · Fast US shipping · Free pickup in Hereford, TX</p>`),
        text: `PREVIEW (not mailed). NEW ARRIVALS JUST LANDED: ${pending} brand-new pairs at Andy's Shoe Supply, always 15% OFF the eBay price. See: https://andysshoesupply.com/#new-arrivals-rail`,
      });
      return res.json({ ok: true, sent: 0, reason: 'preview', pending, previewTo: testTo });
    }

    if (pending < NEWARRIVALS_THRESHOLD)
      return res.json({ ok: true, sent: 0, reason: 'not_ready', pending, threshold: NEWARRIVALS_THRESHOLD });

    const lastSent = getSetting('newarrivals_last_sent', null);
    if (lastSent && (Date.now() - new Date(lastSent).getTime()) < NEWARRIVALS_MIN_DAYS * 24 * 3600 * 1000)
      return res.json({ ok: true, sent: 0, reason: 'cooldown', pending });

    if (dry)
      return res.json({ ok: true, sent: 0, reason: 'dry_run_ready', pending, threshold: NEWARRIVALS_THRESHOLD,
        featured: candidates.slice(0, 3).map(p => ({ id: p.id, title: p.title, price_direct: p.price_direct, brand: p.brand, size: p.size })),
        recipientCount: db.prepare('SELECT email FROM users WHERE unsubscribed = 0').all().filter(r => !isHouseEmail(r.email)).length });

    if (!RESEND_API_KEY) return res.status(503).json({ ok: false, error: 'email not configured (set RESEND_API_KEY)' });

    const users = db.prepare('SELECT id, email, name, favorite_brand, favorite_size FROM users WHERE unsubscribed = 0 AND email_verified = 1 ORDER BY id')
      .all()
      .filter(u => !isHouseEmail(u.email));
    const subject = `Fresh arrivals: ${pending} new pairs at Andy's Shoe Supply`;
    const featured = candidates.slice(0, 3);
    let sent = 0, failed = 0;
    let sampleHtml = null, sampleText = null, sampleUnsub = ''; // first successful send, for the owner's review copy
    for (const u of users) {
      const picks = pick3NewArrivals(u, candidates);
      const first = String(u.name || '').trim().split(/\s+/)[0];
      const unsub = unsubscribeUrl(req, u.id, u.email);
      const personal = (u.favorite_brand || u.favorite_size)
        ? `Picked for you — ${escHtml([u.favorite_brand, u.favorite_size && ('size ' + u.favorite_size)].filter(Boolean).join(' · '))}.`
        : `Here are 3 of the ${pending} freshest pairs.`;
      const mailHtml = emailShell(
          `<p style="font-size:14px;font-weight:700;letter-spacing:2px;color:#d22;margin:0 0 4px">FRESH IN STORE</p>`
          + `<p style="font-size:30px;font-weight:800;margin:0 0 10px;color:#111111">NEW ARRIVALS JUST LANDED 👟</p>`
          + `<p style="font-size:17px;font-weight:700;color:#333333;margin:0 0 10px">Hi${first ? ' ' + escHtml(first) : ''}! 👋</p>`
          + `<p style="font-size:16px;line-height:1.65;color:#333333;margin:0 0 12px"><strong>${pending} brand-new pairs</strong> just hit our direct store — and remember, everything at Andy's Shoe Supply is always <strong>15% OFF the eBay price</strong>. No codes, no games, every day.</p>`
          + `<p style="font-size:15px;line-height:1.6;color:#555555;margin:0 0 20px">${personal} Here are 3 of the freshest pairs:</p>`
          + picks.map(newArrivalCard).join('')
          + `<p style="font-size:15px;line-height:1.6;color:#333333;margin:4px 0 18px">And that's just a taste — there are <strong>${pending} fresh pairs</strong> waiting for you. They go fast, so don't sleep on your size.</p>`
          + `<p style="text-align:center;margin:6px 0 18px"><a href="https://andysshoesupply.com/#new-arrivals-rail" style="display:inline-block;background:#d22;color:#fff;font-size:17px;font-weight:700;text-decoration:none;padding:15px 40px;border-radius:999px">Shop all ${pending} new arrivals</a></p>`
          + `<p style="font-size:13px;color:#888888;text-align:center;margin:0 0 10px">100% authentic · Fast US shipping · Free pickup in Hereford, TX</p>`
          + `<p style="font-size:12px;color:#888;margin-top:10px">You're receiving this because you have an account at Andy's Shoe Supply. <a href="${unsub}">Unsubscribe</a></p>`
        );
      const mailText = `Hi${first ? ' ' + first : ''}! ${pending} new pairs just landed at Andy's Shoe Supply (always 15% OFF the eBay price). See them: https://andysshoesupply.com/#new-arrivals-rail\n\n—\nDon't want these emails? Unsubscribe here: ${unsub}`;
      const r = await sendEmail({
        to: u.email,
        subject,
        html: mailHtml,
        text: mailText,
        headers: { 'List-Unsubscribe': `<${unsub}>` },
      });
      if (r.ok) { sent++; if (!sampleHtml) { sampleHtml = mailHtml; sampleText = mailText; sampleUnsub = unsub; } } else failed++;
      if (users.length > 1) await new Promise(done => setTimeout(done, 350));
    }
    console.log(`[email] new-arrivals digest: ${sent} sent, ${failed} failed, ${users.length} recipients, ${pending} pairs`);
    if (sent > 0) {
      setSetting('newarrivals_mailed', getMailedNewArrivals().concat(candidates.map(p => String(p.id))));
      setSetting('newarrivals_last_sent', new Date().toISOString());
    }
    if (sent > 0 && sampleHtml) {
      // Owner copy only: neutralize the sampled customer's personal
      // unsubscribe link so a tap can never unsubscribe a real customer.
      const safeHtml = sampleUnsub ? sampleHtml.split(sampleUnsub).join('#') : sampleHtml;
      const safeText = sampleUnsub ? sampleText.split(sampleUnsub).join('(unsubscribe link disabled in your review copy)') : sampleText;
      await sendOwnerPromoCopy({ subject, html: safeHtml, text: safeText });
    }
    res.json({ ok: true, sent, failed, recipients: users.length, pending, mailed: sent > 0, ownerCopy: sent > 0 && !!sampleHtml });
  } catch (e) {
    console.error('new-arrivals digest error:', e.message);
    res.status(500).json({ ok: false, error: 'digest failed', detail: e.message });
  }
});

// ---------- Preferences nudge (Maria, 2026-10-10) ----------
// One-off: invite subscribers who haven't set favorite brand/size to add
// them in My Account, so the new-arrivals digest can personalize their
// 3 picks. POST /api/cron/preferences-nudge (header x-cron-secret).
// ?to=address sends a single preview without touching anyone else.
app.post('/api/cron/preferences-nudge', async (req, res) => {
  try {
    const secret = process.env.CRON_SECRET;
    if (!secret) return res.status(503).json({ ok: false, error: 'CRON_SECRET not configured' });
    const a = Buffer.from(req.get('x-cron-secret') || ''), b = Buffer.from(secret);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b))
      return res.status(401).json({ ok: false, error: 'unauthorized' });
    if (!RESEND_API_KEY) return res.status(503).json({ ok: false, error: 'email not configured (set RESEND_API_KEY)' });

    const previewTo = String(req.query.to || '').trim().toLowerCase();
    const accountLink = 'https://andysshoesupply.com/#preferences';
    const bodyHtml = (first, unsub) =>
      `<p style="font-size:14px;font-weight:700;letter-spacing:2px;color:#d22;margin:0 0 4px">MAKE IT YOURS</p>`
      + `<p style="font-size:28px;font-weight:800;margin:0 0 10px;color:#111111">Get picks made for YOU 👟</p>`
      + `<p style="font-size:17px;font-weight:700;color:#333333;margin:0 0 10px">Hi${first ? ' ' + escHtml(first) : ''}! 👋</p>`
      + `<p style="font-size:16px;line-height:1.65;color:#333333;margin:0 0 12px">Quick favor that takes 20 seconds: add your <strong>favorite brand</strong> and your <strong>shoe size</strong> to your account. That way, when new pairs land, the email we send you shows the ones <strong>you'll actually love</strong> — your brand, your size, first.</p>`
      + `<p style="font-size:15px;line-height:1.6;color:#555555;margin:0 0 20px">Go to <strong>My Account → My preferences</strong>, pick your brand and size, hit save. Done. ✅</p>`
      + `<p style="text-align:center;margin:6px 0 18px"><a href="${accountLink}" style="display:inline-block;background:#d22;color:#fff;font-size:17px;font-weight:700;text-decoration:none;padding:15px 40px;border-radius:999px">Update my preferences</a></p>`
      + `<p style="font-size:13px;color:#888888;text-align:center;margin:0 0 10px">100% authentic · Always 15% OFF the eBay price · Free pickup in Hereford, TX</p>`
      + (unsub ? `<p style="font-size:12px;color:#888;margin-top:10px">You're receiving this because you have an account at Andy's Shoe Supply. <a href="${unsub}">Unsubscribe</a></p>` : '');

    if (previewTo) {
      await sendEmail({
        to: previewTo,
        subject: `[Preview] Get picks made for you — Andy's Shoe Supply`,
        html: emailShell(`<p style="font-size:14px;font-weight:700;letter-spacing:2px;color:#d22;margin:0 0 4px">👀 PREVIEW — NOT MAILED TO ANYONE</p>` + bodyHtml('', '')),
        text: `PREVIEW (not mailed). Add your favorite brand and size in My Account so our new-arrivals emails show your pairs first: ${accountLink}`,
      });
      return res.json({ ok: true, sent: 0, reason: 'preview', previewTo });
    }

    const users = db.prepare("SELECT id, email, name FROM users WHERE unsubscribed = 0 AND email_verified = 1 AND (favorite_brand IS NULL OR favorite_brand = '' OR favorite_size IS NULL OR favorite_size = '') ORDER BY id")
      .all()
      .filter(u => !isHouseEmail(u.email));
    let sent = 0, failed = 0;
    let sampleHtml = null, sampleText = null, sampleUnsub = ''; // first successful send, for the owner's review copy
    for (const u of users) {
      const first = String(u.name || '').trim().split(/\s+/)[0];
      const unsub = unsubscribeUrl(req, u.id, u.email);
      const mailHtml = emailShell(bodyHtml(first, unsub));
      const mailText = `Hi${first ? ' ' + first : ''}! Add your favorite brand and shoe size in My Account (My preferences) so our new-arrivals emails show the pairs you'll actually love — your brand, your size, first: ${accountLink}\n\n—\nDon't want these emails? Unsubscribe here: ${unsub}`;
      const r = await sendEmail({
        to: u.email,
        subject: `Get shoe picks made for you 👟 — Andy's Shoe Supply`,
        html: mailHtml,
        text: mailText,
        headers: { 'List-Unsubscribe': `<${unsub}>` },
      });
      if (r.ok) { sent++; if (!sampleHtml) { sampleHtml = mailHtml; sampleText = mailText; sampleUnsub = unsub; } } else failed++;
      if (users.length > 1) await new Promise(done => setTimeout(done, 350));
    }
    console.log(`[email] preferences nudge: ${sent} sent, ${failed} failed, ${users.length} recipients`);
    if (sent > 0 && sampleHtml) {
      // Owner copy only: neutralize the sampled customer's personal
      // unsubscribe link so a tap can never unsubscribe a real customer.
      const safeHtml = sampleUnsub ? sampleHtml.split(sampleUnsub).join('#') : sampleHtml;
      const safeText = sampleUnsub ? sampleText.split(sampleUnsub).join('(unsubscribe link disabled in your review copy)') : sampleText;
      await sendOwnerPromoCopy({ subject: `Get shoe picks made for you 👟 — Andy's Shoe Supply`, html: safeHtml, text: safeText });
    }
    res.json({ ok: true, sent, failed, recipients: users.length, ownerCopy: sent > 0 && !!sampleHtml });
  } catch (e) {
    console.error('preferences nudge error:', e.message);
    res.status(500).json({ ok: false, error: 'nudge failed', detail: e.message });
  }
});

// ---------- Favorites: products the current visitor liked ----------
app.get('/api/likes/mine', (req, res) => {
  const v = String(req.query.voter || req.get('x-voter') || '').trim();
  if (!/^[A-Za-z0-9-]{8,64}$/.test(v)) return res.json({ voter: null, favorites: [] });
  const voter = 'v:' + v;
  const rows = db.prepare('SELECT product_id FROM like_votes WHERE voter = ? ORDER BY rowid DESC').all(voter);
  res.json({ voter, favorites: rows.map(r => r.product_id) });
});

// ---------- Likes (public, shared across all visitors) ----------
app.get('/api/likes/:productId', (req, res) => {
  const id = String(req.params.productId);
  const row = db.prepare('SELECT count FROM likes WHERE product_id = ?').get(id);
  res.json({ productId: id, likes: row ? row.count : 0, liked: !!db.prepare('SELECT 1 FROM like_votes WHERE product_id=? AND voter=?').get(id, voterOf(req, id)) });
});

app.post('/api/likes/:productId/toggle', (req, res) => {
  const id = String(req.params.productId);
  const voter = voterOf(req, id);
  // House votes (owner's marked devices / house accounts) are still recorded
  // — her own favorites keep working — but they NEVER move the public
  // counter shown in the store or the panel (Maria, 2026-10-15).
  const house = isHouseRequest(req) ? 1 : 0;
  let liked;
  const voted = db.prepare('SELECT house FROM like_votes WHERE product_id=? AND voter=?').get(id, voter);
  if (voted) {
    db.prepare('DELETE FROM like_votes WHERE product_id=? AND voter=?').run(id, voter);
    if (!voted.house) {
      db.prepare('INSERT INTO likes (product_id, count) VALUES (?, 0) ON CONFLICT(product_id) DO UPDATE SET count = MAX(0, count - 1)').run(id);
    }
    liked = false;
  } else {
    db.prepare('INSERT INTO like_votes (product_id, voter, house) VALUES (?, ?, ?)').run(id, voter, house);
    if (!house) {
      db.prepare('INSERT INTO likes (product_id, count) VALUES (?, 1) ON CONFLICT(product_id) DO UPDATE SET count = count + 1').run(id);
    }
    liked = true;
  }
  const row = db.prepare('SELECT count FROM likes WHERE product_id = ?').get(id);
  res.json({ productId: id, likes: row ? row.count : 0, liked });
});

// ---------- Reviews (public) ----------
app.get('/api/reviews/:productId', (req, res) => {
  const id = String(req.params.productId);
  const rows = db.prepare(`SELECT name, rating, text, created_at, verified FROM reviews WHERE product_id=? AND approved=1 ORDER BY id DESC LIMIT 100`).all(id)
    .map(r => ({ name: r.name, rating: r.rating, text: r.text, created_at: r.created_at, verified: !!r.verified, productId: id }));
  const avg = db.prepare(`SELECT AVG(rating) AS a, COUNT(*) AS n FROM reviews WHERE product_id=? AND approved=1`).get(id);
  res.json({ productId: id, average: avg.a ? Math.round(avg.a * 10) / 10 : null, count: avg.n, reviews: rows });
});

app.post('/api/reviews/:productId', (req, res) => {
  const id = String(req.params.productId);
  const name = String(req.body.name || '').trim().slice(0, 40);
  const text = String(req.body.text || '').trim().slice(0, 500);
  const rating = Number(req.body.rating);
  if (!byId.has(id)) return res.status(404).json({ error: 'Unknown product' });
  if (!name || !text || !(rating >= 1 && rating <= 5)) return res.status(400).json({ error: 'Name, rating 1-5 and review text are required' });
  // Purchase gate (Maria's rule): only a buyer can review, proven by the
  // review_token emailed with their order; one review per product per purchase.
  const tokenRow = getReviewToken(req.body.review_token);
  if (!tokenRow || !tokenRow.order_id || !orderIncludesProduct(tokenRow.order_id, id)
      || db.prepare('SELECT 1 FROM reviews WHERE product_id=? AND review_token=?').get(id, tokenRow.token))
    return res.status(403).json({ error: 'Reviews are only available after a purchase' });
  db.prepare(`INSERT INTO reviews (product_id, name, rating, text, verified, review_token) VALUES (?, ?, ?, ?, 1, ?)`)
    .run(id, name, rating, text, tokenRow.token);
  res.json({ ok: true, verified: true });
});

// ---------- Store reviews (public, about the shop in general) ----------
app.get('/api/store-reviews', (req, res) => {
  const rows = db.prepare(`SELECT name, rating, text, created_at, verified, product_id FROM reviews WHERE product_id='STORE' AND approved=1 ORDER BY id DESC LIMIT 100`).all()
    .map(r => ({ name: r.name, rating: r.rating, text: r.text, created_at: r.created_at, verified: !!r.verified, productId: r.product_id }));
  const avg = db.prepare(`SELECT AVG(rating) AS a, COUNT(*) AS n FROM reviews WHERE product_id='STORE' AND approved=1`).get();
  res.json({ average: avg.a ? Math.round(avg.a * 10) / 10 : null, count: avg.n, reviews: rows });
});

app.post('/api/store-reviews', (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 40);
  const text = String(req.body.text || '').trim().slice(0, 500);
  const rating = Number(req.body.rating);
  if (!name || !text || !(rating >= 1 && rating <= 5)) return res.status(400).json({ error: 'Name, rating 1-5 and review text are required' });
  // Purchase gate (Maria's rule): one store review per purchase, proven by
  // the review_token emailed with the order; consumed on first use.
  const tokenRow = getReviewToken(req.body.review_token);
  if (!tokenRow || !tokenRow.order_id || tokenRow.used_store)
    return res.status(403).json({ error: 'Reviews are only available after a purchase' });
  db.prepare(`INSERT INTO reviews (product_id, name, rating, text, verified, review_token) VALUES ('STORE', ?, ?, ?, 1, ?)`)
    .run(name, rating, text, tokenRow.token);
  db.prepare('UPDATE review_tokens SET used_store = 1 WHERE token = ?').run(tokenRow.token);
  res.json({ ok: true, verified: true });
});

// ---------- Shipping price charged to the customer ----------
// Maria's FINAL rule 2026-10-08 (evening, reverses the calculated-with-cap
// rule from earlier that day): FLAT $11.95 for every shipped order; local
// Hereford pickup stays free. Customers pay inside Stripe's hosted checkout.
// computeShipping() below short-circuits to this flat amount; the weight/zone
// estimate and provider quote chain stay in the file for label-cost checks.
const SHIPPING_FLAT_CENTS = 1195;
const SHIPPING_CAP_CENTS = 1295;
const DEPT_WEIGHT_LB = { Men: 3.0, Unisex: 2.8, Women: 2.5, Kids: 1.8, Baby: 1.0, Toys: 1.5, Electronics: 2.0 };
const DEPT_PARCEL_IN = {
  Men: { l: 13, w: 8, h: 5 }, Unisex: { l: 13, w: 8, h: 5 }, Women: { l: 12, w: 7, h: 4.5 },
  Kids: { l: 10, w: 6, h: 4 }, Baby: { l: 7, w: 5, h: 3 }, Toys: { l: 10, w: 8, h: 6 }, Electronics: { l: 9, w: 7, h: 4 },
};
const ZONE_NEAR = new Set(['TX', 'OK', 'NM', 'KS', 'CO']); // +$0.00
const ZONE_CENTRAL = new Set(['AR', 'LA', 'MO', 'NE', 'SD', 'ND', 'MN', 'IA', 'WI', 'MI', 'IL', 'IN', 'OH', 'KY', 'TN', 'MS', 'AL']); // +$1.50
const ZONE_EAST = new Set(['FL', 'GA', 'SC', 'NC', 'VA', 'WV', 'PA', 'NY', 'NJ', 'CT', 'MA', 'VT', 'NH', 'ME', 'MD', 'DE', 'DC']); // +$3.00
const ZONE_WEST = new Set(['CA', 'OR', 'WA', 'NV', 'AZ', 'UT', 'ID', 'MT', 'WY']); // +$3.00 (AK/HI: +$6.00)
const US_STATE_CODES = {
  ALABAMA: 'AL', ALASKA: 'AK', ARIZONA: 'AZ', ARKANSAS: 'AR', CALIFORNIA: 'CA', COLORADO: 'CO', CONNECTICUT: 'CT',
  DELAWARE: 'DE', 'DISTRICT OF COLUMBIA': 'DC', FLORIDA: 'FL', GEORGIA: 'GA', HAWAII: 'HI', IDAHO: 'ID',
  ILLINOIS: 'IL', INDIANA: 'IN', IOWA: 'IA', KANSAS: 'KS', KENTUCKY: 'KY', LOUISIANA: 'LA', MAINE: 'ME',
  MARYLAND: 'MD', MASSACHUSETTS: 'MA', MICHIGAN: 'MI', MINNESOTA: 'MN', MISSISSIPPI: 'MS', MISSOURI: 'MO',
  MONTANA: 'MT', NEBRASKA: 'NE', NEVADA: 'NV', 'NEW HAMPSHIRE': 'NH', 'NEW JERSEY': 'NJ', 'NEW MEXICO': 'NM',
  'NEW YORK': 'NY', 'NORTH CAROLINA': 'NC', 'NORTH DAKOTA': 'ND', OHIO: 'OH', OKLAHOMA: 'OK', OREGON: 'OR',
  PENNSYLVANIA: 'PA', 'RHODE ISLAND': 'RI', 'SOUTH CAROLINA': 'SC', 'SOUTH DAKOTA': 'SD', TENNESSEE: 'TN',
  TEXAS: 'TX', UTAH: 'UT', VERMONT: 'VT', VIRGINIA: 'VA', WASHINGTON: 'WA', 'WEST VIRGINIA': 'WV',
  WISCONSIN: 'WI', WYOMING: 'WY',
};
function normalizeState(s) {
  const t = String(s || '').trim().toUpperCase();
  if (/^[A-Z]{2}$/.test(t)) return t;
  return US_STATE_CODES[t] || '';
}
const deptOf = (p) => {
  const d = String(p?.department || '').trim();
  return Object.prototype.hasOwnProperty.call(DEPT_WEIGHT_LB, d) ? d : '';
};
const itemWeightLb = (p) => {
  const w = Number(p?.weight_lbs);
  if (Number.isFinite(w) && w > 0) return w;
  return DEPT_WEIGHT_LB[deptOf(p)] ?? 2.5;
};
const itemParcelIn = (p) => {
  const pc = p?.parcel_in || {};
  if (Number(pc.l) > 0 && Number(pc.w) > 0 && Number(pc.h) > 0) return { l: Number(pc.l), w: Number(pc.w), h: Number(pc.h) };
  return DEPT_PARCEL_IN[deptOf(p)] || { l: 13, w: 8, h: 5 };
};
// ---------- Server-side carts (admin visibility, 2026-10-15) ----------
// The storefront mirrors every cart change here: keyed by a per-device id
// for guests, attached to the account email when the customer is logged in.
// Prices are recomputed from the catalog (storePriceOf) — numbers sent by
// the client are never trusted. An empty cart deletes its row, so the panel
// only ever lists live, non-empty carts. The local checkout flow is
// unaffected: this is a mirror for visibility, not a checkout dependency.
app.post('/api/cart/sync', (req, res) => {
  try {
    const cartKey = String((req.body && req.body.cartKey) || '').trim();
    if (!/^[A-Za-z0-9-]{8,64}$/.test(cartKey)) return res.status(400).json({ ok: false, error: 'bad cart key' });
    const rawItems = Array.isArray(req.body && req.body.items) ? req.body.items : [];
    if (!rawItems.length) {
      db.prepare('DELETE FROM carts WHERE cart_key = ?').run(cartKey);
      return res.json({ ok: true, cleared: true });
    }
    const lines = resolveCartLines(rawItems.slice(0, 50));
    const items = lines.map(l => ({ id: l.id, size: l.size, qty: l.qty }));
    const itemCount = lines.reduce((a, l) => a + l.qty, 0);
    const subtotal = lines.reduce((a, l) => a + Math.round(storePriceOf(l.p) * 100) * l.qty, 0);
    const acct = accountUser(req);
    db.prepare(`INSERT INTO carts (cart_key, email, items, item_count, subtotal_cents, updated_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(cart_key) DO UPDATE SET email = COALESCE(excluded.email, carts.email),
        items = excluded.items, item_count = excluded.item_count,
        subtotal_cents = excluded.subtotal_cents, updated_at = datetime('now')`)
      .run(cartKey, acct ? acct.email : null, JSON.stringify(items), itemCount, subtotal);
    res.json({ ok: true, itemCount, subtotal_cents: subtotal });
  } catch (e) {
    res.status(e.status || 500).json({ ok: false, error: e.message || 'cart sync failed' });
  }
});

// Admin: every non-empty cart, latest activity first — customer email when
// known, items with size and quantity, subtotal at direct prices. House
// carts (owner testing with her own accounts) are filtered out: they are
// not customers.
app.get('/api/admin/carts', requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT cart_key, email, items, item_count, subtotal_cents, updated_at, created_at
    FROM carts WHERE item_count > 0 ORDER BY updated_at DESC LIMIT 100`).all();
  res.json(rows
    .filter(r => !isHouseEmail(r.email))
    .map(r => {
      let items = []; try { items = JSON.parse(r.items || '[]'); } catch {}
      return {
        email: r.email || null,
        items: items.map(it => ({ title: orderItemTitle(it), qty: Math.max(1, Number(it.qty) || 1) })),
        item_count: r.item_count,
        subtotal_cents: r.subtotal_cents,
        updated_at: r.updated_at,
        created_at: r.created_at,
      };
    }));
});

// ---------- Customer feedback (printed thank-you card QR, 2026-10-16) ----------
// The public form at https://andysshoesupply.com/feedback POSTs here — no
// account needed. A star rating (1-5) and/or the "how can we improve?" text;
// at least one of the two is required. Stored only for the admin panel:
// nothing is published automatically.
// Basic abuse brake: max 5 submissions per IP per 10 minutes (in-memory).
const feedbackHits = new Map();
function feedbackRateOk(ip) {
  const now = Date.now(), win = 10 * 60 * 1000, max = 5;
  const arr = (feedbackHits.get(ip) || []).filter(t => now - t < win);
  if (arr.length >= max) { feedbackHits.set(ip, arr); return false; }
  arr.push(now); feedbackHits.set(ip, arr);
  return true;
}
app.post('/api/feedback', (req, res) => {
  try {
    if (!feedbackRateOk(req.ip || 'unknown'))
      return res.status(429).json({ ok: false, error: 'Too many submissions — please try again in a few minutes.' });
    const b = req.body || {};
    const rawRating = (b.rating === undefined || b.rating === null || b.rating === '') ? null : Number(b.rating);
    if (rawRating !== null && (!Number.isInteger(rawRating) || rawRating < 1 || rawRating > 5))
      return res.status(400).json({ ok: false, error: 'Rating must be between 1 and 5 stars.' });
    const improve = typeof b.improve === 'string' ? b.improve.trim().slice(0, 2000) : '';
    const product = typeof b.product === 'string' ? b.product.trim().slice(0, 200) : '';
    const name = typeof b.name === 'string' ? b.name.trim().slice(0, 100) : '';
    if (rawRating === null && !improve)
      return res.status(400).json({ ok: false, error: 'Please tap a star rating or tell us how we can improve.' });
    const info = db.prepare('INSERT INTO feedback (rating, improve, product, name) VALUES (?, ?, ?, ?)')
      .run(rawRating, improve || null, product || null, name || null);
    res.json({ ok: true, id: Number(info.lastInsertRowid) });
  } catch (e) {
    res.status(e.status || 500).json({ ok: false, error: e.message || 'feedback failed' });
  }
});

// Admin: most recent customer feedback first.
app.get('/api/admin/feedback', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT id, rating, improve, product, name, created_at FROM feedback ORDER BY id DESC LIMIT 200').all();
  res.json(rows);
});

// Validate + group raw cart entries [{id, size?, qty?}] against the catalog.
// Accepts the legacy "id__size_6" id form as well (size split out of the id).
function resolveCartLines(rawItems) {
  const map = new Map();
  for (const raw of rawItems || []) {
    let id = String(raw?.id || '');
    let size = raw?.size != null && String(raw.size) !== '' ? String(raw.size) : null;
    const m = id.match(/^(.+?)__size_(.+)$/);
    if (m) { id = m[1]; size = size ?? m[2]; }
    const p = byId.get(id);
    if (!p) { const e = new Error(`Unknown product ${id}`); e.status = 400; throw e; }
    const qty = Math.max(1, Math.min(99, Number(raw?.qty) || 1));
    const key = id + '|' + (size || '');
    if (map.has(key)) map.get(key).qty += qty;
    else map.set(key, { id, size, qty, p });
  }
  return [...map.values()];
}
// One parcel for the whole cart: combined weight, box of the heaviest item
// (same single-parcel assumption the label buyers already use).
function cartWeightParcel(lines) {
  let totalLb = 0, heaviest = null, heaviestW = -1;
  for (const l of lines) {
    const w = itemWeightLb(l.p);
    totalLb += w * l.qty;
    if (w > heaviestW) { heaviestW = w; heaviest = l.p; }
  }
  const pc = heaviest ? itemParcelIn(heaviest) : { l: 13, w: 8, h: 5 };
  return { totalLb, parcel: { weightLb: totalLb, boxL: pc.l, boxW: pc.w, boxH: pc.h } };
}
function estimateShippingDollars(totalLb, state) {
  const w = Math.max(0.1, Number(totalLb) || 0);
  let base;
  if (w <= 1) base = 6.95; else if (w <= 2) base = 7.95; else if (w <= 3) base = 9.25;
  else if (w <= 4) base = 10.75; else base = 10.75 + (Math.ceil(w) - 4) * 1.25;
  let adder = 3.00; // unknown state: mid-zone default
  if (ZONE_NEAR.has(state)) adder = 0;
  else if (ZONE_CENTRAL.has(state)) adder = 1.50;
  else if (ZONE_EAST.has(state) || ZONE_WEST.has(state)) adder = 3.00;
  else if (state === 'AK' || state === 'HI') adder = 6.00;
  return base + adder;
}
// Real carrier rate when a provider is configured. Throws on any provider
// failure; computeShipping catches and falls back to the estimate.
async function providerQuote(lines, dest) {
  const { parcel } = cartWeightParcel(lines);
  const zip = String(dest.zip || '');
  if (process.env.EASYPOST_API_KEY) {
    const shipment = await epCreateShipment({
      name: 'Customer', street1: 'Address at checkout', city: '', state: dest.state,
      zip, country: 'US',
    }, parcel);
    const pick = epPickRate(shipment.rates);
    if (pick && Number(pick.rate) > 0) return { dollars: Number(pick.rate), source: 'easypost' };
    throw new Error('EasyPost returned no usable rate');
  }
  if (process.env.SHIPPO_TOKEN) {
    const r = await fetch(`${SHIPPO_API}/shipments/`, {
      method: 'POST', headers: shippoHeaders(),
      body: JSON.stringify({
        address_from: SHIP_FROM,
        address_to: { name: 'Customer', street1: 'Address at checkout', city: '', state: dest.state, zip, country: 'US' },
        parcels: [{
          length: String(parcel.boxL), width: String(parcel.boxW), height: String(parcel.boxH),
          distance_unit: 'in', weight: String(parcel.weightLb), mass_unit: 'lb',
        }],
        async: false,
      }),
    });
    const sh = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error('Shippo quote failed: ' + JSON.stringify(sh).slice(0, 200));
    const rates = sh.rates || [];
    const pick = rates.find(x => /ground advantage/i.test(x.servicelevel?.name || '') && /usps/i.test(x.provider || ''))
      || rates.filter(x => /usps/i.test(x.provider || '')).sort((a, b) => Number(a.amount) - Number(b.amount))[0]
      || rates.slice().sort((a, b) => Number(a.amount) - Number(b.amount))[0];
    if (pick && Number(pick.amount) > 0) return { dollars: Number(pick.amount), source: 'shippo' };
    throw new Error('Shippo returned no rates');
  }
  return null;
}
async function computeShipping(lines, dest) {
  // Flat $11.95 shipping (Maria's final call, 2026-10-08). The calculated
  // estimate below is kept for internal cost checks, not for charging.
  return { amount_cents: SHIPPING_FLAT_CENTS, source: 'flat', capped: false };
  const state = normalizeState(dest?.state);
  const { totalLb } = cartWeightParcel(lines);
  let dollars = null, source = 'estimate';
  try {
    const pq = await providerQuote(lines, { state, zip: dest?.zip });
    if (pq && Number.isFinite(pq.dollars) && pq.dollars > 0) { dollars = pq.dollars; source = pq.source; }
  } catch (e) {
    console.warn('shipping quote: provider failed, using estimate:', e.message);
  }
  if (dollars == null) dollars = estimateShippingDollars(totalLb, state);
  const rounded = Math.ceil(dollars * 20 - 1e-6) / 20; // round UP to the next $0.05
  const capped = rounded > SHIPPING_CAP_CENTS / 100;
  return { amount_cents: Math.min(Math.round(rounded * 100), SHIPPING_CAP_CENTS), source, capped };
}

// ---------- Stripe checkout ----------
function stripe() {
  if (!process.env.STRIPE_SECRET_KEY) throw new Error('STRIPE_SECRET_KEY not configured');
  return require('stripe')(process.env.STRIPE_SECRET_KEY);
}

// POST { items: [{id, size?}], buyer: {name, email}, fulfillment: 'shipping'|'pickup',
//        shipTo: {line1, city, state, zip} }  (shipTo required only for shipping)
// Dynamic Stripe Checkout with CALCULATED shipping capped at $12.95 (the
// amount is always recomputed server-side from the catalog weights + the
// destination, never trusted from the client). Without STRIPE_SECRET_KEY —
// or if Stripe rejects the session — single-item carts fall back to the
// per-product Payment Link, so selling never breaks.
app.post('/api/checkout', async (req, res) => {
  try {
    const rawItems = Array.isArray(req.body.items) ? req.body.items : [];
    const buyer = req.body.buyer || {};
    const fulfillment = req.body.fulfillment === 'pickup' ? 'pickup' : 'shipping';
    const shipTo = req.body.shipTo || {};
    if (!rawItems.length) return res.status(400).json({ ok: false, error: 'Empty cart' });
    let lines;
    try { lines = resolveCartLines(rawItems); }
    catch (e) { return res.status(e.status || 400).json({ ok: false, error: e.message }); }
    // Maria's admin overrides win over the catalog: hidden products cannot
    // be bought at all, and a price_direct override replaces the computed
    // store price as the unit amount (in cents) for the Stripe session.
    const overrides = getOverrides();
    for (const l of lines) {
      const ov = overrides[l.id];
      if (ov && ov.hidden === true) return res.status(400).json({ ok: false, error: 'Sold out' });
      l.unitCents = ov && Number(ov.price_direct) > 0
        ? Math.round(Number(ov.price_direct) * 100)
        : Math.round(storePriceOf(l.p) * 100);
    }
    // Maria 2026-10-14: customers who created an account get an EXTRA 3% OFF
    // the item price (on top of the 15% OFF direct price). The discount is
    // decided HERE from the account session token — never from anything the
    // browser claims — and shipping stays the flat $11.95 either way.
    const acctUser = accountUser(req);
    let accountDiscountCents = 0;
    if (acctUser) {
      for (const l of lines) {
        const d = Math.round(l.unitCents * 0.03);
        if (d > 0) { l.unitCents -= d; accountDiscountCents += d * l.qty; }
      }
    }
    // Inventory: per-size variant quantities from the catalog first, then the
    // tracked total stock for the product.
    const wantedById = new Map();
    for (const l of lines) {
      if (Array.isArray(l.p.variants) && l.p.variants.length) {
        const v = l.size != null ? l.p.variants.find(vv => String(vv.size) === l.size) : null;
        if (!v || Number(v.qty || 0) < l.qty) return res.status(400).json({ ok: false, error: 'Sold out' });
        l.variant = v;
      }
      wantedById.set(l.id, (wantedById.get(l.id) || 0) + l.qty);
    }
    for (const [id, q] of wantedById) {
      if (invQty(id) < q) return res.status(400).json({ ok: false, error: 'Sold out' });
    }
    // Maria 2026-10-11: Stripe Checkout collects the buyer's shipping address
    // on its own page, so the storefront no longer asks for it up front.
    // shipTo is accepted when provided but never required.
    // Fallback to the per-product Payment Link (single-item carts only).
    const fallback = () => {
      if (lines.length !== 1 || lines[0].qty !== 1)
        return res.status(503).json({ ok: false, error: 'Checkout unavailable' });
      const l = lines[0];
      const url = (l.variant && l.variant.payment_url) || l.p.payment_url || null;
      if (!url) return res.status(503).json({ ok: false, error: 'Checkout unavailable' });
      return res.json({ ok: false, fallback: true, url });
    };
    if (!process.env.STRIPE_SECRET_KEY) return fallback();
    const lineItems = lines.map(l => ({
      price_data: {
        currency: 'usd',
        unit_amount: l.unitCents,
        product_data: { name: (String(l.p.title || l.id).slice(0, 120) + (l.size ? ` — Size ${l.size}` : '')) },
      },
      quantity: l.qty,
    }));
    if (lineItems.some(li => !(li.price_data.unit_amount > 0)))
      return res.status(400).json({ ok: false, error: 'Price unavailable' });
    const params = {
      mode: 'payment',
      line_items: lineItems,
      success_url: 'https://andysshoesupply.com/?paid=1&cs={CHECKOUT_SESSION_ID}',
      cancel_url: 'https://andysshoesupply.com/',
      customer_email: String(buyer.email || '').trim() || undefined,
      // Maria 2026-10-11: let Stripe calculate sales tax automatically.
      // No-op until Stripe Tax is activated and TX registration added in dashboard.
      automatic_tax: { enabled: true },
      metadata: {
        source: 'direct-store',
        items: JSON.stringify(lines.map(l => ({
          id: l.id,
          ...(l.size ? { size: l.size } : {}),
          ...(l.qty > 1 ? { qty: l.qty } : {}),
        }))),
        fulfillment,
        ...(acctUser ? { account_email: acctUser.email, account_discount_cents: String(accountDiscountCents) } : {}),
        buyer_email: String(buyer.email || '').slice(0, 120),
        buyer_name: String(buyer.name || '').slice(0, 80),
      },
    };
    if (fulfillment === 'shipping') {
      const q = await computeShipping(lines, {}); // flat $11.95, no address needed
      params.shipping_address_collection = { allowed_countries: ['US'] };
      params.shipping_options = [{
        shipping_rate_data: {
          type: 'fixed_amount',
          fixed_amount: { amount: q.amount_cents, currency: 'usd' },
          display_name: 'USPS Ground Advantage — flat rate',
        },
      }];
    }
    let session;
    try {
      session = await stripe().checkout.sessions.create(params, { idempotencyKey: crypto.randomUUID() });
    } catch (e) {
      console.error('stripe session create failed, falling back to payment link:', e.message);
      return fallback();
    }
    res.json({ ok: true, url: session.url });
  } catch (e) {
    console.error('checkout error:', e.message);
    res.status(500).json({ ok: false, error: 'Checkout failed', detail: e.message });
  }
});

async function onStripeWebhook(req, res) {
  const sig = req.headers['stripe-signature'];
  try {
    // Note: constructEvent is pure crypto verification — it needs only the
    // webhook secret, NOT the Stripe API secret key.
    const event = require('stripe').webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    if (event.type === 'checkout.session.completed') {
      const s = event.data.object;
      // Two flows: legacy cart checkout (metadata.items JSON) and per-product
      // Payment Links (payment link metadata.product_id copied onto the session).
      let items = [];
      try { items = JSON.parse(s.metadata.items || '[]'); } catch { items = []; }
      if (!items.length && s.metadata.product_id) {
        items = [{ id: String(s.metadata.product_id), qty: 1 }];
      }
      if (!items.length) {
        console.warn('webhook: session with no recognizable items', s.id);
        res.json({ received: true, ignored: true });
        return;
      }
      // Inventory decrement. Item ids may embed the size ("...__size_6" from
      // Payment Links) — decrement the base product either way.
      const fulfillment = s.metadata.fulfillment === 'pickup' ? 'pickup' : 'shipping';
      for (const it of items) {
        const baseId = String(it.id).split('__size_')[0];
        const q = Number(it.qty) > 0 ? Number(it.qty) : 1;
        db.prepare('UPDATE inventory SET qty = MAX(0, qty - ?) WHERE product_id = ?').run(q, baseId);
      }
      // Shipping address: Payment Links collect it via shipping_address_collection.
      const sh = s.shipping_details || {};
      const shipTo = {
        name: sh.name || s.metadata.ship_name || '',
        phone: s.customer_details?.phone || '',
        line1: sh.address?.line1 || '',
        line2: sh.address?.line2 || '',
        city: sh.address?.city || '',
        state: sh.address?.state || '',
        zip: sh.address?.postal_code || '',
        country: sh.address?.country || 'US',
      };
      const shipCharged = Number(s.total_details?.amount_shipping) || 0;
      const info = db.prepare(`INSERT OR IGNORE INTO orders
        (stripe_session, email, items, amount_total, ship_to, status, fulfillment, ship_charged_cents)
        VALUES (?, ?, ?, ?, ?, 'paid', ?, ?)`)
        .run(s.id, s.customer_email || s.customer_details?.email || '',
             JSON.stringify(items), s.amount_total || 0, JSON.stringify(shipTo),
             fulfillment, shipCharged);
      console.log('Order paid:', s.id, items.length, 'items');
      // Buy the shipping label right away (async, never blocks the webhook reply).
      if (info.changes > 0) {
        const orderId = db.prepare('SELECT id FROM orders WHERE stripe_session = ?').get(s.id)?.id;
        // Pickup orders never need a label; shipping orders keep the auto-buy.
        if (orderId && fulfillment !== 'pickup') buyLabelForOrder(orderId).catch(e => console.error('auto-label failed:', e.message));
        // Purchase confirmation + review invite, once per order: the
        // INSERT OR IGNORE above dedups webhook retries (changes = 0 on replays).
        // One review token per new order; the email carries it (?rt=<token>).
        const reviewToken = orderId
          ? createReviewToken(orderId, s.customer_email || s.customer_details?.email || '')
          : null;
        sendPurchaseConfirmation(s, items, reviewToken, orderId).catch(e => console.error('purchase email failed:', e.message));
        sendOrderNotification(s, items, orderId).catch(e => console.error('order notify email failed:', e.message));
        sendOrderSms(s, items, orderId).catch(e => console.error('order sms failed:', e.message));
      }
    }
    res.json({ received: true });
  } catch (e) {
    console.error('webhook error:', e.message);
    res.status(400).json({ error: e.message });
  }
}

// ---------- USPS (developer.usps.com API, OAuth client credentials) ----------
let uspsToken = null, uspsTokenExp = 0;
async function uspsAccessToken() {
  if (Date.now() < uspsTokenExp - 60000 && uspsToken) return uspsToken;
  const id = process.env.USPS_CLIENT_ID, secret = process.env.USPS_CLIENT_SECRET;
  if (!id || !secret) throw new Error('USPS_CLIENT_ID / USPS_CLIENT_SECRET not configured');
  const r = await fetch('https://api.usps.com/oauth2/v3/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: id, client_secret: secret, grant_type: 'client_credentials' }),
  });
  if (!r.ok) throw new Error('USPS auth failed: ' + (await r.text()).slice(0, 200));
  const j = await r.json();
  uspsToken = j.access_token; uspsTokenExp = Date.now() + (j.expires_in || 3600) * 1000;
  return uspsToken;
}

// POST { toZip, weightOz, lengthIn, widthIn, heightIn }
app.post('/api/usps/rates', requireAdmin, async (req, res) => {
  try {
    const token = await uspsAccessToken();
    const { toZip, weightOz = 16, lengthIn = 12, widthIn = 9, heightIn = 6 } = req.body;
    if (!toZip) return res.status(400).json({ error: 'toZip required' });
    const r = await fetch('https://api.usps.com/prices/v3/base-rates/search', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        originZIPCode: SHIP_FROM_ZIP, destinationZIPCode: String(toZip),
        weight: Number(weightOz) / 16, length: Number(lengthIn), width: Number(widthIn), height: Number(heightIn),
        mailClass: 'ALL', processingCategory: 'MACHINABLE', rateIndicator: 'SP', destinationEntryFacilityType: 'NONE',
      }),
    });
    const j = await r.json();
    if (!r.ok) return res.status(502).json({ error: 'USPS rates failed', detail: JSON.stringify(j).slice(0, 300) });
    const wanted = /GROUND ADVANTAGE|PRIORITY/i;
    const rates = (j.rates || j.rateOptions || []).filter(x => wanted.test(x.mailClass || x.description || ''))
      .map(x => ({ service: x.mailClass || x.description, price: Number(x.totalBasePrice ?? x.price ?? 0) }));
    res.json({ rates });
  } catch (e) {
    res.status(500).json({ error: 'USPS rates error', detail: e.message });
  }
});

// POST { orderId } — buy label for a paid order (uses stored ship-to from metadata)
app.post('/api/usps/label', requireAdmin, async (req, res) => {
  try {
    const token = await uspsAccessToken();
    const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(Number(req.body.orderId));
    if (!order || order.status !== 'paid') return res.status(404).json({ error: 'Paid order not found' });
    // NOTE: full ship-to parsing from metadata happens at deploy time with Maria's real flow.
    res.json({ ok: false, note: 'Label purchase wiring continues at deploy with live USPS credentials.' });
  } catch (e) {
    res.status(500).json({ error: 'USPS label error', detail: e.message });
  }
});

// ---------- Shippo: automatic label purchase (commercial USPS rates via API) ----------
const SHIPPO_API = 'https://api.shippo.com';
function shippoHeaders() {
  if (!process.env.SHIPPO_TOKEN) throw new Error('SHIPPO_TOKEN not configured');
  return { 'Authorization': `ShippoToken ${process.env.SHIPPO_TOKEN}`, 'Content-Type': 'application/json' };
}
const SHIP_FROM = {
  name: process.env.SHIP_FROM_NAME || 'Andys Shoe Supply',
  street1: process.env.SHIP_FROM_STREET || '223 N Greenwood St',
  city: process.env.SHIP_FROM_CITY || 'Hereford',
  state: process.env.SHIP_FROM_STATE || 'TX',
  zip: process.env.SHIP_FROM_ZIP || '79045',
  country: 'US',
  phone: process.env.SHIP_FROM_PHONE || '7025806374',
  email: process.env.SHIP_FROM_EMAIL || 'roinelpadin@gmail.com',
};

// Parcel for an order's items: box + weight of the heaviest product; fallback 13x8x5 in, 2.5 lb
function parcelForItems(items) {
  let weightLb = 2.5, boxL = 13, boxW = 8, boxH = 5;
  for (const it of items || []) {
    const p = byId.get(String(it.id));
    const w = Number(p?.weight_lbs);
    if (Number.isFinite(w) && w > 0 && w >= weightLb) {
      weightLb = w;
      const pc = p?.parcel_in || {};
      if (Number(pc.l) > 0) boxL = Number(pc.l);
      if (Number(pc.w) > 0) boxW = Number(pc.w);
      if (Number(pc.h) > 0) boxH = Number(pc.h);
    }
  }
  return { weightLb, boxL, boxW, boxH };
}

async function buyLabelShippo(orderId) {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(Number(orderId));
  if (!order || order.status !== 'paid') throw new Error('Paid order not found');
  if (order.label_url) return { label_url: order.label_url, tracking_number: order.tracking_number }; // already done
  const items = JSON.parse(order.items || '[]');
  const shipTo = JSON.parse(order.ship_to || '{}');
  if (!shipTo.zip || !shipTo.line1) throw new Error('Order is missing the shipping address');
  const { weightLb, boxL, boxW, boxH } = parcelForItems(items);
  const shipmentRes = await fetch(`${SHIPPO_API}/shipments/`, {
    method: 'POST', headers: shippoHeaders(),
    body: JSON.stringify({
      address_from: SHIP_FROM,
      address_to: {
        name: shipTo.name || 'Customer', street1: shipTo.line1, street2: shipTo.line2 || '',
        city: shipTo.city, state: shipTo.state, zip: shipTo.zip, country: shipTo.country || 'US',
        phone: shipTo.phone || '', email: order.email || '',
      },
      parcels: [{
        length: String(boxL), width: String(boxW), height: String(boxH),
        distance_unit: 'in', weight: String(weightLb), mass_unit: 'lb',
      }],
      async: false,
    }),
  });
  const shipment = await shipmentRes.json();
  if (!shipmentRes.ok) throw new Error('Shippo shipment failed: ' + JSON.stringify(shipment).slice(0, 300));
  const rates = shipment.rates || [];
  // Prefer USPS Ground Advantage, else cheapest USPS, else cheapest overall
  const pick = rates.find(r => /ground advantage/i.test(r.servicelevel?.name || '') && /usps/i.test(r.provider || ''))
    || rates.filter(r => /usps/i.test(r.provider || '')).sort((a, b) => Number(a.amount) - Number(b.amount))[0]
    || rates.sort((a, b) => Number(a.amount) - Number(b.amount))[0];
  if (!pick) throw new Error('Shippo returned no rates');
  const txRes = await fetch(`${SHIPPO_API}/transactions/`, {
    method: 'POST', headers: shippoHeaders(),
    body: JSON.stringify({ rate: pick.object_id, label_file_type: 'PDF', async: false }),
  });
  const tx = await txRes.json();
  if (!txRes.ok || tx.status !== 'SUCCESS') throw new Error('Shippo label failed: ' + JSON.stringify(tx).slice(0, 300));
  db.prepare('UPDATE orders SET tracking_number = ?, label_url = ? WHERE id = ?')
    .run(tx.tracking_number || '', tx.label_url || '', orderId);
  console.log(`Label bought for order ${orderId}: ${tx.tracking_number} $${tx.rate}`);
  notifyOrderShipped(orderId, pick.provider); // customer "on its way" email, once
  return { label_url: tx.label_url, tracking_number: tx.tracking_number };
}

// ---------- EasyPost: rates + label purchase (no manual approval gate; key active at signup) ----------
const EASYPOST_API = 'https://api.easypost.com/v2';
function epHeaders() {
  if (!process.env.EASYPOST_API_KEY) throw new Error('EASYPOST_API_KEY not configured');
  return {
    'Authorization': 'Basic ' + Buffer.from(process.env.EASYPOST_API_KEY + ':').toString('base64'),
    'Content-Type': 'application/json',
  };
}
function epPickRate(rates) {
  const usps = rates.filter(r => /usps/i.test(r.carrier || ''));
  return rates.find(r => /usps/i.test(r.carrier || '') && /ground advantage/i.test(r.service || ''))
    || usps.sort((a, b) => Number(a.rate) - Number(b.rate))[0]
    || rates.slice().sort((a, b) => Number(a.rate) - Number(b.rate))[0]
    || null;
}
async function epCreateShipment(toAddr, parcel) {
  const r = await fetch(`${EASYPOST_API}/shipments`, {
    method: 'POST', headers: epHeaders(),
    body: JSON.stringify({
      shipment: {
        from_address: {
          name: SHIP_FROM.name, street1: SHIP_FROM.street1, city: SHIP_FROM.city,
          state: SHIP_FROM.state, zip: SHIP_FROM.zip, country: SHIP_FROM.country,
          phone: SHIP_FROM.phone, email: SHIP_FROM.email,
        },
        to_address: toAddr,
        parcel: {
          length: parcel.boxL, width: parcel.boxW, height: parcel.boxH,
          weight: Math.max(1, Math.round(parcel.weightLb * 16)), // EasyPost weighs in ounces
        },
        options: { label_format: 'PDF', label_size: '4x6', currency: 'USD' },
      },
    }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error('EasyPost shipment failed: ' + JSON.stringify(j.error || j).slice(0, 300));
  if (!Array.isArray(j.rates) || !j.rates.length) {
    const msgs = (j.messages || []).filter(m => m.type === 'rate_error')
      .map(m => `${m.carrier}: ${m.message}`).join('; ');
    throw new Error('EasyPost returned no rates' + (msgs ? ': ' + msgs.slice(0, 250) : ''));
  }
  return j;
}

async function buyLabelEasyPost(orderId) {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(Number(orderId));
  if (!order || order.status !== 'paid') throw new Error('Paid order not found');
  if (order.label_url) return { label_url: order.label_url, tracking_number: order.tracking_number }; // already done
  const items = JSON.parse(order.items || '[]');
  const shipTo = JSON.parse(order.ship_to || '{}');
  if (!shipTo.zip || !shipTo.line1) throw new Error('Order is missing the shipping address');
  const parcel = parcelForItems(items);
  const shipment = await epCreateShipment({
    name: shipTo.name || 'Customer', street1: shipTo.line1, street2: shipTo.line2 || '',
    city: shipTo.city, state: shipTo.state, zip: shipTo.zip, country: shipTo.country || 'US',
    phone: shipTo.phone || '', email: order.email || '',
  }, parcel);
  const pick = epPickRate(shipment.rates);
  if (!pick) throw new Error('EasyPost returned no rates');
  const buyRes = await fetch(`${EASYPOST_API}/shipments/${shipment.id}/buy`, {
    method: 'POST', headers: epHeaders(),
    body: JSON.stringify({ rate: { id: pick.id } }),
  });
  const bought = await buyRes.json().catch(() => ({}));
  if (!buyRes.ok || !bought.postage_label?.label_url) {
    throw new Error('EasyPost label failed: ' + JSON.stringify(bought.error || bought).slice(0, 300));
  }
  db.prepare('UPDATE orders SET tracking_number = ?, label_url = ? WHERE id = ?')
    .run(bought.tracking_code || '', bought.postage_label.label_url, orderId);
  const sr = bought.selected_rate || pick;
  console.log(`Label bought (EasyPost) for order ${orderId}: ${bought.tracking_code} ${sr.carrier} ${sr.service} $${sr.rate}`);
  notifyOrderShipped(orderId, sr.carrier); // customer "on its way" email, once
  return { label_url: bought.postage_label.label_url, tracking_number: bought.tracking_code || '', carrier: sr.carrier, service: sr.service, rate: Number(sr.rate) };
}

// Label dispatcher: EasyPost when its key is set, Shippo as fallback
async function buyLabelForOrder(orderId) {
  if (process.env.EASYPOST_API_KEY) return buyLabelEasyPost(orderId);
  if (process.env.SHIPPO_TOKEN) return buyLabelShippo(orderId);
  throw new Error('No shipping provider configured (set EASYPOST_API_KEY or SHIPPO_TOKEN)');
}

// Public shipping quote: POST { items: [{id, size?}], state, zip } ->
// { ok, amount_cents, amount, source, capped } where amount is the calculated
// shipping CHARGED to the customer (real provider rate when configured, else
// the weight/zone estimate), never above the $12.95 cap. The legacy body
// { to: {...}, items } is still answered by legacyShippingQuote below.
app.post('/api/shipping/quote', async (req, res) => {
  if (req.body && req.body.to) return legacyShippingQuote(req, res);
  try {
    const rawItems = Array.isArray(req.body.items) ? req.body.items : [];
    const state = normalizeState(req.body.state);
    const zip = String(req.body.zip || '').trim();
    if (!rawItems.length) return res.status(400).json({ ok: false, error: 'Empty items' });
    if (!state || !/^\d{5}/.test(zip)) return res.status(400).json({ ok: false, error: 'Destination state and ZIP are required' });
    let lines;
    try { lines = resolveCartLines(rawItems); }
    catch (e) { return res.status(e.status || 400).json({ ok: false, error: e.message }); }
    const q = await computeShipping(lines, { state, zip });
    res.json({ ok: true, amount_cents: q.amount_cents, amount: (q.amount_cents / 100).toFixed(2), source: q.source, capped: q.capped });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'Shipping quote error', detail: e.message });
  }
});

// Legacy quote shape: POST { to: {name?, street1, city, state, zip}, items: [{id, qty}] }
async function legacyShippingQuote(req, res) {
  try {
    if (!process.env.EASYPOST_API_KEY && !process.env.SHIPPO_TOKEN) {
      return res.status(503).json({ error: 'Shipping provider not configured yet' });
    }
    const to = req.body.to || {};
    const items = Array.isArray(req.body.items) ? req.body.items : [];
    for (const f of ['street1', 'city', 'state', 'zip']) {
      if (!String(to[f] || '').trim()) return res.status(400).json({ error: `Missing address field: ${f}` });
    }
    if (!items.length) return res.status(400).json({ error: 'Empty items' });
    for (const it of items) if (!byId.get(String(it.id))) return res.status(400).json({ error: `Unknown product ${it.id}` });
    if (!process.env.EASYPOST_API_KEY) return res.status(503).json({ error: 'Quote provider not configured yet' });
    const parcel = parcelForItems(items);
    const shipment = await epCreateShipment({
      name: to.name || 'Customer', street1: to.street1, street2: to.street2 || '',
      city: to.city, state: to.state, zip: String(to.zip), country: to.country || 'US', phone: to.phone || '',
    }, parcel);
    const rates = shipment.rates
      .map(r => ({ carrier: r.carrier, service: r.service, rate: Number(r.rate), currency: r.currency || 'USD', rate_id: r.id }))
      .sort((a, b) => a.rate - b.rate);
    res.json({ rates, parcel: { weight_oz: Math.max(1, Math.round(parcel.weightLb * 16)), length_in: parcel.boxL, width_in: parcel.boxW, height_in: parcel.boxH } });
  } catch (e) {
    res.status(500).json({ error: 'Shipping quote error', detail: e.message });
  }
}

// Manual trigger (admin): POST { orderId }
app.post('/api/labels/buy', requireAdmin, async (req, res) => {
  try {
    res.json(await buyLabelForOrder(req.body.orderId));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- Orders feed (for the notification job) ----------
app.get('/api/orders/pending-labels', requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT id, stripe_session, email, items, amount_total, ship_to,
    tracking_number, label_url, created_at FROM orders
    WHERE status = 'paid' AND label_url IS NOT NULL AND notified = 0 ORDER BY id`).all();
  res.json(rows.map(r => ({ ...r, items: JSON.parse(r.items || '[]'), ship_to: JSON.parse(r.ship_to || '{}') })));
});

app.post('/api/orders/:id/notified', requireAdmin, (req, res) => {
  db.prepare('UPDATE orders SET notified = 1 WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

// Public order summary for the post-payment thank-you screen. The Stripe
// Checkout session id is the capability (unguessable, names exactly one
// order); only a shopper-facing summary is returned — never the address.
// found:false + pending:true while the webhook is still landing.
app.get('/api/orders/by-session/:sessionId', async (req, res) => {
  const sid = String(req.params.sessionId || '');
  if (!/^cs_[A-Za-z0-9_]+$/.test(sid)) return res.status(400).json({ found: false });
  const order = db.prepare('SELECT * FROM orders WHERE stripe_session = ?').get(sid);
  if (!order) return res.json({ found: false, pending: true });
  await refreshOrderDelivery(order); // light tracking check on consult
  res.json({
    found: true,
    order: {
      id: order.id,
      items: orderLinesOf(order),
      amount_total: order.amount_total,
      fulfillment: order.fulfillment || 'shipping',
      status: order.status,
      tracking_number: order.tracking_number || '',
      created_at: order.created_at,
    },
  });
});

// Cron sweep for delivered orders (header x-cron-secret, same guard as the
// other cron endpoints): checks tracking on shipped orders not yet marked
// delivered; each delivery flips the status + sends the thank-you/review
// email exactly once (orders.delivered_notified).
app.post('/api/cron/delivery-check', async (req, res) => {
  try {
    const secret = process.env.CRON_SECRET;
    if (!secret) return res.status(503).json({ ok: false, error: 'CRON_SECRET not configured' });
    const a = Buffer.from(req.get('x-cron-secret') || ''), b = Buffer.from(secret);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b))
      return res.status(401).json({ ok: false, error: 'unauthorized' });
    const rows = db.prepare(`SELECT * FROM orders WHERE tracking_number IS NOT NULL AND tracking_number <> ''
      AND delivered_notified = 0 AND status <> 'delivered' ORDER BY id DESC LIMIT 50`).all();
    let delivered = 0;
    for (const o of rows) { if (await refreshOrderDelivery(o)) delivered++; }
    res.json({ ok: true, checked: rows.length, delivered });
  } catch (e) {
    console.error('delivery-check error:', e.message);
    res.status(500).json({ ok: false, error: 'delivery check failed', detail: e.message });
  }
});

app.get('/api/orders/recent', requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT id, email, items, amount_total, ship_to, tracking_number,
    label_url, notified, status, fulfillment, shipped_notified, delivered_notified, created_at FROM orders ORDER BY id DESC LIMIT 50`).all();
  res.json(rows);
});
// ---------- Inventory (for the private admin panel to sync) ----------
app.get('/api/inventory', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT product_id AS id, qty FROM inventory').all());
});

// ---------- Visit counter (Maria asked 2026-10-10: her own visitor stats) ----------
// The storefront POSTs one beacon per page load; we count distinct visitors
// per Chicago day (hash of IP+UA, raw IPs are never stored; obvious bots out).
app.post('/api/visit', (req, res) => {
  try {
    const ua = String(req.get('user-agent') || '');
    if (!/bot|crawler|spider|headless|lighthouse/i.test(ua)) {
      const ip = String(req.get('x-forwarded-for') || req.ip || '').split(',')[0].trim();
      const visitor = crypto.createHash('sha256').update(ip + '|' + ua).digest('hex').slice(0, 24);
      const day = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Chicago' }).format(new Date());
      db.prepare('INSERT OR IGNORE INTO visits (day, visitor) VALUES (?, ?)').run(day, visitor);
    }
  } catch (e) { console.error('visit log failed:', e.message); }
  res.status(204).end();
});
// Maria 2026-10-11: product view tracking for the admin "Más vistos" list.
// Fire-and-forget from the storefront when a product is viewed.
app.post('/api/views', (req, res) => {
  try {
    const id = String((req.body && req.body.id) || '').slice(0, 64);
    if (!id) return res.json({ ok: false });
    const day = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Chicago' }).format(new Date());
    db.prepare(`INSERT INTO product_views (product_id, day, views) VALUES (?, ?, 1)
      ON CONFLICT(product_id, day) DO UPDATE SET views = views + 1`).run(id, day);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false }); }
});
app.get('/api/admin/product-likes', requireAdmin, (req, res) => {
  const byId = {};
  try { for (const p of CATALOG) byId[String(p.id || p.itemId)] = p; } catch (e) {}
  const rows = db.prepare(`SELECT product_id, count AS likes FROM likes
    ORDER BY count DESC LIMIT 60`).all()
    .filter(r => byId[String(r.product_id)] && Number(r.likes) > 0).slice(0, 20);
  res.json(rows.map(r => {
    const p = byId[String(r.product_id)] || {};
    return { id: r.product_id, likes: r.likes, title: p.title || p.name || r.product_id,
             price: p.price_direct || null, image: p.image || null };
  }));
});
app.get('/api/admin/product-views', requireAdmin, (req, res) => {
  const byId = {};
  try { for (const p of CATALOG) byId[String(p.id || p.itemId)] = p; } catch (e) {}
  // Only real catalog products (ignores stray/test ids).
  const rows = db.prepare(`SELECT product_id, SUM(views) AS views FROM product_views
    GROUP BY product_id ORDER BY views DESC LIMIT 60`).all()
    .filter(r => byId[String(r.product_id)]).slice(0, 20);
  res.json(rows.map(r => {
    const p = byId[String(r.product_id)] || {};
    return { id: r.product_id, views: r.views, title: p.title || p.name || r.product_id,
             price: p.price_direct || null, image: p.image || null };
  }));
});
app.get('/api/admin/visits', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT day, COUNT(*) AS visitors FROM visits GROUP BY day ORDER BY day DESC LIMIT 30').all();
  const today = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Chicago' }).format(new Date());
  const sum = (list) => list.reduce((a, r) => a + r.visitors, 0);
  res.json({
    today: (rows.find(r => r.day === today) || { visitors: 0 }).visitors,
    last7: sum(rows.slice(0, 7)),
    last30: sum(rows),
    total: sum(db.prepare('SELECT COUNT(*) AS visitors FROM visits GROUP BY day').all().map(v => ({ visitors: v.visitors }))),
    byDay: rows.slice(0, 14),
  });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  // House accounts (the owner's own emails) are not customers: excluded from
  // both the count and the list the panel shows (Maria, 2026-10-15).
  const rows = db.prepare(`SELECT id, email, name, created_at FROM users ORDER BY id DESC`).all()
    .filter(u => !isHouseEmail(u.email));
  const withOrders = db.prepare(`SELECT lower(email) AS e, COUNT(*) AS n FROM orders GROUP BY lower(email)`).all();
  const orderCount = Object.fromEntries(withOrders.map(r => [r.e, r.n]));
  res.json({ count: rows.length, users: rows.map(u => ({ ...u, orders: orderCount[u.email.toLowerCase()] || 0 })) });
});
app.get('/api/products/lite', (req, res) => {
  res.json(CATALOG.map(p => ({ id: String(p.id || p.itemId), title: p.title || p.name || '', price: storePriceOf(p) })));
});
// ---------- Store config Maria edits from /admin (featured picks + overrides) ----------
// Public read so the storefront can render her Top sellers / New arrivals /
// Top picks and apply her per-product price/hide overrides without a rebuild.
app.get('/api/store-config', (req, res) => {
  res.json({ featured: getFeatured(), overrides: getOverrides() });
});
app.get('/api/admin/featured', requireAdmin, (req, res) => {
  res.json(getFeatured());
});
app.put('/api/admin/featured', requireAdmin, (req, res) => {
  try {
    const body = req.body || {};
    setSetting('featured', {
      top_sellers: cleanIdList(body.top_sellers),
      new_arrivals: cleanIdList(body.new_arrivals),
      top_picks: cleanIdList(body.top_picks),
    });
    res.json({ ok: true });
  } catch (e) {
    console.error('featured save error:', e.message);
    res.status(500).json({ ok: false, error: 'Could not save featured picks' });
  }
});
app.get('/api/admin/overrides', requireAdmin, (req, res) => {
  res.json(getOverrides());
});
app.put('/api/admin/overrides', requireAdmin, (req, res) => {
  try {
    const body = req.body || {};
    const id = String(body.id || '');
    if (!byId.has(id)) return res.status(400).json({ ok: false, error: 'Unknown product' });
    const overrides = getOverrides();
    const entry = overrides[id] && typeof overrides[id] === 'object' ? { ...overrides[id] } : {};
    // price_direct: a number > 0 sets the store price; null / "" / 0 clears it.
    if (Object.prototype.hasOwnProperty.call(body, 'price_direct')) {
      const n = Number(body.price_direct);
      if (Number.isFinite(n) && n > 0) entry.price_direct = n;
      else delete entry.price_direct;
    }
    // hidden: only booleans count — true hides the product, false un-hides it.
    if (typeof body.hidden === 'boolean') {
      if (body.hidden) entry.hidden = true;
      else delete entry.hidden;
    }
    if (Object.keys(entry).length) overrides[id] = entry;
    else delete overrides[id];
    setSetting('overrides', overrides);
    res.json({ ok: true, overrides });
  } catch (e) {
    console.error('overrides save error:', e.message);
    res.status(500).json({ ok: false, error: 'Could not save override' });
  }
});
// ---------- Customer accounts ----------
const newSessionToken = () => crypto.randomBytes(32).toString('hex');
function accountUser(req) {
  const h = req.get('authorization') || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const row = db.prepare("SELECT s.user_id, s.expires_at, u.id, u.email, u.name, u.created_at, u.favorite_brand, u.favorite_size FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?").get(m[1]);
  if (!row) return null;
  if (new Date(row.expires_at) < new Date()) { db.prepare('DELETE FROM sessions WHERE token = ?').run(m[1]); return null; }
  return { id: row.id, email: row.email, name: row.name, created_at: row.created_at,
           favorite_brand: row.favorite_brand || '', favorite_size: row.favorite_size || '',
           favoriteBrand: row.favorite_brand || '', favoriteSize: row.favorite_size || '' };
}
function requireAccount(req, res, next) {
  const u = accountUser(req);
  if (!u) return res.status(401).json({ error: 'login required' });
  req.account = u; next();
}
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
app.post('/api/account/register', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const name = String(req.body.name || '').trim().slice(0, 80);
    const favoriteBrand = String(req.body.favoriteBrand || '').trim().slice(0, 60);
    const favoriteSize = String(req.body.favoriteSize || '').trim().slice(0, 20);
    if (req.body.agree !== true && req.body.acceptedTerms !== true)
      return res.status(400).json({ ok: false, error: 'You must agree to the Terms & Conditions' });
    if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'invalid email' });
    if (password.length < 8) return res.status(400).json({ error: 'password too short (min 8)' });
    if (db.prepare('SELECT id FROM users WHERE email = ?').get(email))
      return res.status(409).json({ error: 'email already registered' });
    const hash = await bcrypt.hash(password, 10);
    const vtoken = crypto.randomBytes(32).toString('hex');
    const vexp = new Date(Date.now() + 48*3600*1000).toISOString();
    const r = db.prepare('INSERT INTO users (email, password_hash, name, terms_accepted_at, terms_version, favorite_brand, favorite_size, email_verified, verify_token, verify_expires) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)')
      .run(email, hash, name, new Date().toISOString(), TERMS_VERSION, favoriteBrand, favoriteSize, vtoken, vexp);
    // No session yet — the account activates when the user confirms their
    // email (Maria, 2026-10-10). The welcome email goes out after verification.
    sendVerificationEmail(email, name, vtoken).catch(e => console.error('verification email failed:', e.message));
    res.json({ ok: true, verifySent: true, email });
  } catch (e) { res.status(500).json({ error: 'registration failed' }); }
});
app.post('/api/account/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const u = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!u || !(await bcrypt.compare(password, u.password_hash)))
      return res.status(401).json({ error: 'invalid credentials' });
    if (!u.email_verified)
      return res.status(403).json({ error: 'email_not_verified', message: 'Please confirm your email first — we sent you a confirmation link.' });
    // "Keep me signed in" (remember me): checked (default) keeps the 30-day
    // persistent session; unchecked gives a short 12-hour server session and
    // a browser-session cookie (no Max-Age, dies with the browser). The
    // storefront mirrors this by keeping the token in localStorage only when
    // remember is on, and in sessionStorage when it is off.
    const remember = req.body.remember !== false;
    const token = newSessionToken();
    const ttlMs = remember ? 30*24*3600*1000 : 12*3600*1000;
    const exp = new Date(Date.now() + ttlMs).toISOString();
    db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, u.id, exp);
    res.set('Set-Cookie', 'ass_session=' + encodeURIComponent(token) + '; Path=/; HttpOnly; Secure; SameSite=Lax' + (remember ? '; Max-Age=' + String(30*24*3600) : ''));
    res.json({ token, remember, expiresAt: exp, user: { email: u.email, name: u.name, favoriteBrand: u.favorite_brand || '', favoriteSize: u.favorite_size || '' } });
  } catch (e) { res.status(500).json({ error: 'login failed' }); }
});
// Email confirmation link: verifies the account, sends the welcome email,
// then lands the customer on the store with a success banner.
app.get('/api/account/verify', (req, res) => {
  try {
    const token = String(req.query.token || '').trim();
    const u = token ? db.prepare('SELECT id, email, name, verify_expires FROM users WHERE verify_token = ?').get(token) : null;
    if (!u) return res.redirect('https://andysshoesupply.com/#verify-failed');
    if (u.verify_expires && new Date(u.verify_expires) < new Date())
      return res.redirect('https://andysshoesupply.com/#verify-expired');
    db.prepare('UPDATE users SET email_verified = 1, verify_token = NULL, verify_expires = NULL WHERE id = ?').run(u.id);
    sendWelcomeEmail(u.email, u.name).catch(e => console.error('welcome email failed:', e.message));
    // The email travels in the URL fragment (#...) so the store can show it;
    // fragments are never sent to any server.
    return res.redirect('https://andysshoesupply.com/#verified=' + encodeURIComponent(u.email));
  } catch (e) { return res.redirect('https://andysshoesupply.com/#verify-failed'); }
});
// Resend the confirmation email (always answers ok to avoid email enumeration).
app.post('/api/account/resend-verification', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const u = email ? db.prepare('SELECT id, email, name, email_verified FROM users WHERE email = ?').get(email) : null;
    if (u && !u.email_verified) {
      const vtoken = crypto.randomBytes(32).toString('hex');
      const vexp = new Date(Date.now() + 48*3600*1000).toISOString();
      db.prepare('UPDATE users SET verify_token = ?, verify_expires = ? WHERE id = ?').run(vtoken, vexp, u.id);
      await sendVerificationEmail(u.email, u.name, vtoken).catch(e => console.error('verify resend failed:', e.message));
    }
    res.json({ ok: true });
  } catch (e) { res.json({ ok: true }); }
});
app.post('/api/account/logout', (req, res) => {  const h = req.get('authorization') || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (m) db.prepare('DELETE FROM sessions WHERE token = ?').run(m[1]);
  res.json({ ok: true });
});
app.get('/api/account/me', requireAccount, (req, res) => {
  const orders = db.prepare(`SELECT id, items, amount_total, tracking_number, label_url, status, fulfillment, shipped_notified, delivered_notified, created_at
    FROM orders WHERE lower(email) = lower(?) ORDER BY id DESC LIMIT 20`).all(req.account.email);
  // Light delivery check (fire-and-forget): a shipped order the carrier
  // already delivered flips to 'delivered' + thank-you/review email, and the
  // customer sees the fresh status on their next visit.
  orders.filter(o => o.tracking_number && !o.delivered_notified).slice(0, 5)
    .forEach(o => { refreshOrderDelivery(o); });
  res.json({ user: req.account, orders: orders.map(o => ({ ...o, items: JSON.parse(o.items || '[]') })) });
});

// Update optional shopping preferences (favorite brand/size) — used for
// personalized "new arrivals" digest emails. Both optional, never required.
app.put('/api/account/preferences', requireAccount, (req, res) => {
  try {
    const favoriteBrand = String(req.body.favoriteBrand || '').trim().slice(0, 60);
    const favoriteSize = String(req.body.favoriteSize || '').trim().slice(0, 20);
    db.prepare('UPDATE users SET favorite_brand = ?, favorite_size = ? WHERE id = ?')
      .run(favoriteBrand, favoriteSize, req.account.id);
    res.json({ ok: true, favoriteBrand, favoriteSize });
  } catch (e) { res.status(500).json({ error: 'preferences update failed' }); }
});

// Self-service account deletion (Maria, 2026-10-16): a signed-in customer can
// permanently delete their own account from My Account. The current password
// is required so an unlocked phone can't erase an account. Sessions and the
// customer's mirrored cart rows go with it; favorites are device-based (not
// tied to accounts), and past orders stay untouched in `orders` — that table
// is the store's sales record, keyed by email with no user foreign key.
// House accounts can never be deleted through this route.
app.delete('/api/account', requireAccount, async (req, res) => {
  try {
    if (isHouseEmail(req.account.email))
      return res.status(403).json({ ok: false, error: 'house_account', message: 'This account cannot be deleted.' });
    const password = String((req.body && req.body.password) || '');
    const u = db.prepare('SELECT id, password_hash FROM users WHERE id = ?').get(req.account.id);
    if (!u) return res.status(404).json({ ok: false, error: 'account not found' });
    if (!(await bcrypt.compare(password, u.password_hash)))
      return res.status(403).json({ ok: false, error: 'wrong_password', message: 'Incorrect password — your account was not deleted.' });
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(u.id);
    db.prepare('DELETE FROM carts WHERE lower(email) = lower(?)').run(req.account.email);
    db.prepare('DELETE FROM users WHERE id = ?').run(u.id);
    res.set('Set-Cookie', 'ass_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: 'account deletion failed' }); }
});

app.get('/api/health', (req, res) => res.json({
  ok: true,
  catalog: CATALOG.length,
  stripe: !!process.env.STRIPE_WEBHOOK_SECRET, // checkout uses Payment Links + webhook; no secret key needed
  checkout: !!process.env.STRIPE_SECRET_KEY, // dynamic checkout (calculated shipping) needs the secret key
  usps: !!(process.env.USPS_CLIENT_ID && process.env.USPS_CLIENT_SECRET),
  shipping: process.env.EASYPOST_API_KEY ? 'easypost' : (process.env.SHIPPO_TOKEN ? 'shippo' : 'none'),
  email: !!RESEND_API_KEY, // Resend wired for welcome / order / promo emails
  r2: r2Enabled(),
}));

app.listen(PORT, () => console.log(`Andy's store backend on :${PORT}`));
