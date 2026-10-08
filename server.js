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

// ---------- Email (Resend) ----------
// Customer emails via the Resend HTTP API (native fetch, no new dependencies).
// If RESEND_API_KEY is not set, sendEmail is a safe no-op: it only logs
// "[email] skipped (no RESEND_API_KEY)" and the request flow continues.
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const EMAIL_FROM = process.env.EMAIL_FROM || "Andy's Shoe Supply <hola@andysshoesupply.com>";
// Signs the one-click unsubscribe links (HMAC-SHA256). Falls back to ADMIN_TOKEN.
const EMAIL_SIGNING_SECRET = process.env.EMAIL_SECRET || ADMIN_TOKEN || '';
const escHtml = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const textToHtml = (s) => escHtml(s).replace(/\n/g, '<br>');

function emailShell(innerHtml) {
  return '<div style="font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.55;color:#1a1a1a">'
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

async function sendWelcomeEmail(email, name) {
  const first = String(name || '').trim().split(/\s+/)[0];
  const text = `Hi${first ? ' ' + first : ''}!

Welcome to Andy's Shoe Supply — thanks for creating your account.

Every pair in our direct store is 15% OFF the eBay price, every day, and new pairs land all the time. Come take a look:
https://andysshoesupply.com

— Andy's Shoe Supply`;
  const html = emailShell(
    `<p>Hi${first ? ' ' + escHtml(first) : ''}!</p>`
    + '<p>Welcome to Andy\'s Shoe Supply — thanks for creating your account.</p>'
    + '<p>Every pair in our direct store is <strong>15% OFF</strong> the eBay price, every day, and new pairs land all the time. Come take a look:</p>'
    + '<p><a href="https://andysshoesupply.com">Shop Andy\'s Shoe Supply</a></p>'
  );
  return sendEmail({ to: email, subject: "Welcome to Andy's Shoe Supply", html, text });
}

// Human title for an order line item. Payment Link variants carry the id
// "398339652878__size_6" (see make_variant_links.py) — show "Title — Size 6".
function orderItemTitle(it) {
  const raw = String(it.id || '');
  const m = raw.match(/^(.+?)__size_(.+)$/);
  const p = byId.get(m ? m[1] : raw);
  const title = (p && (p.title || p.name)) || raw;
  return m ? `${title} — Size ${m[2]}` : String(title);
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

async function sendPurchaseConfirmation(session, items, reviewToken) {
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
    const users = db.prepare('SELECT id, email, name FROM users WHERE unsubscribed = 0 ORDER BY id').all();
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
    res.json({ ok: true, recipients: users.length, sent, failed });
  } catch (e) {
    console.error('send-promo error:', e.message);
    res.status(500).json({ error: 'promo send failed', detail: e.message });
  }
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
  let liked;
  const voted = db.prepare('SELECT 1 FROM like_votes WHERE product_id=? AND voter=?').get(id, voter);
  if (voted) {
    db.prepare('DELETE FROM like_votes WHERE product_id=? AND voter=?').run(id, voter);
    db.prepare('INSERT INTO likes (product_id, count) VALUES (?, 0) ON CONFLICT(product_id) DO UPDATE SET count = MAX(0, count - 1)').run(id);
    liked = false;
  } else {
    db.prepare('INSERT INTO like_votes (product_id, voter) VALUES (?, ?)').run(id, voter);
    db.prepare('INSERT INTO likes (product_id, count) VALUES (?, 1) ON CONFLICT(product_id) DO UPDATE SET count = count + 1').run(id);
    liked = true;
  }
  const count = db.prepare('SELECT count FROM likes WHERE product_id = ?').get(id).count;
  res.json({ productId: id, likes: count, liked });
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

// ---------- Stripe checkout ----------
function stripe() {
  if (!process.env.STRIPE_SECRET_KEY) throw new Error('STRIPE_SECRET_KEY not configured');
  return require('stripe')(process.env.STRIPE_SECRET_KEY);
}

// POST { items: [{id, qty}], shipping: {name, phone, address, city, state, zip, method}, coupon?: string }
app.post('/api/checkout', async (req, res) => {
  try {
    const items = Array.isArray(req.body.items) ? req.body.items : [];
    const ship = req.body.ship || {};
    if (!items.length) return res.status(400).json({ error: 'Empty cart' });
    for (const f of ['name', 'address', 'city', 'state', 'zip']) {
      if (!String(ship[f] || '').trim()) return res.status(400).json({ error: `Missing shipping field: ${f}` });
    }
    // Validate items + stock against server catalog (never trust client prices)
    const lineItems = [];
    let subtotal = 0;
    for (const it of items) {
      const id = String(it.id);
      const qty = Math.max(1, Math.min(99, Number(it.qty) | 0));
      const p = byId.get(id);
      if (!p) return res.status(400).json({ error: `Unknown product ${id}` });
      const stock = invQty(id);
      if (qty > stock) return res.status(400).json({ error: `Only ${stock} available for "${p.title || id}"` });
      const unit = Math.round(priceOf(p) * (1 - DISCOUNT) * 100); // 15% off, in cents
      subtotal += unit * qty;
      lineItems.push({
        price_data: { currency: 'usd', unit_amount: unit, product_data: { name: String(p.title || id).slice(0, 120) } },
        quantity: qty,
      });
    }
    // Service fee 2.9% + $0.30 passed to the customer (configurable)
    const feeRate = Number(process.env.STRIPE_FEE_RATE || '0.029');
    const feeFixed = Number(process.env.STRIPE_FEE_FIXED_CENTS || '30');
    const fee = Math.round(subtotal * feeRate) + feeFixed;
    lineItems.push({
      price_data: { currency: 'usd', unit_amount: fee, product_data: { name: 'Service fee (card processing)' } },
      quantity: 1,
    });
    // Shipping: flat provisional options until USPS live rates are wired ("Calculated" in store UI)
    const method = /priority/i.test(ship.method || '') ? 'priority' : 'ground';
    const shipCents = method === 'priority'
      ? Number(process.env.SHIP_PRIORITY_CENTS || '0')
      : Number(process.env.SHIP_GROUND_CENTS || '0');
    if (shipCents > 0) {
      lineItems.push({
        price_data: { currency: 'usd', unit_amount: shipCents, product_data: { name: method === 'priority' ? 'USPS Priority Mail' : 'USPS Ground Advantage' } },
        quantity: 1,
      });
    }
    // Sales tax: Texas rate when shipping to TX (permit in mail; rate configurable)
    const taxEnabled = /^(1|true|yes)$/i.test(process.env.TAX_ENABLED || 'true');
    const taxRate = Number(process.env.TAX_TX_RATE || '0.0825');
    const shipState = String(ship.state || '').trim().toLowerCase();
    const taxable = taxEnabled && (shipState === 'tx' || shipState === 'texas');
    if (taxable) {
      const taxBase = subtotal + shipCents;
      const taxCents = Math.round(taxBase * taxRate);
      if (taxCents > 0) {
        lineItems.push({
          price_data: { currency: 'usd', unit_amount: taxCents, product_data: { name: `Sales tax (TX ${(taxRate * 100).toFixed(2)}%)` } },
          quantity: 1,
        });
      }
    }
    const session = await stripe().checkout.sessions.create({
      mode: 'payment',
      line_items: lineItems,
      success_url: `${process.env.STORE_URL}/?order=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.STORE_URL}/?order=cancelled`,
      customer_email: ship.email || undefined,
      metadata: {
        items: JSON.stringify(items.map(i => ({ id: String(i.id), qty: Number(i.qty) | 0 }))),
        ship_name: String(ship.name || '').slice(0, 80),
        ship_phone: String(ship.phone || '').slice(0, 20),
        ship_address: [ship.address, ship.city, ship.state, ship.zip].join(', '),
        ship_method: method,
        coupon: String(req.body.coupon || ''),
      },
    });
    res.json({ url: session.url });
  } catch (e) {
    console.error('checkout error:', e.message);
    res.status(500).json({ error: 'Checkout failed', detail: e.message });
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
      for (const it of items) {
        db.prepare('UPDATE inventory SET qty = MAX(0, qty - ?) WHERE product_id = ?').run(Number(it.qty) | 0, String(it.id));
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
      const info = db.prepare(`INSERT OR IGNORE INTO orders
        (stripe_session, email, items, amount_total, ship_to, status)
        VALUES (?, ?, ?, ?, ?, 'paid')`)
        .run(s.id, s.customer_email || s.customer_details?.email || '',
             JSON.stringify(items), s.amount_total || 0, JSON.stringify(shipTo));
      console.log('Order paid:', s.id, items.length, 'items');
      // Buy the shipping label right away (async, never blocks the webhook reply).
      if (info.changes > 0) {
        const orderId = db.prepare('SELECT id FROM orders WHERE stripe_session = ?').get(s.id)?.id;
        if (orderId) buyLabelForOrder(orderId).catch(e => console.error('auto-label failed:', e.message));
        // Purchase confirmation + review invite, once per order: the
        // INSERT OR IGNORE above dedups webhook retries (changes = 0 on replays).
        // One review token per new order; the email carries it (?rt=<token>).
        const reviewToken = orderId
          ? createReviewToken(orderId, s.customer_email || s.customer_details?.email || '')
          : null;
        sendPurchaseConfirmation(s, items, reviewToken).catch(e => console.error('purchase email failed:', e.message));
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
  return { label_url: bought.postage_label.label_url, tracking_number: bought.tracking_code || '', carrier: sr.carrier, service: sr.service, rate: Number(sr.rate) };
}

// Label dispatcher: EasyPost when its key is set, Shippo as fallback
async function buyLabelForOrder(orderId) {
  if (process.env.EASYPOST_API_KEY) return buyLabelEasyPost(orderId);
  if (process.env.SHIPPO_TOKEN) return buyLabelShippo(orderId);
  throw new Error('No shipping provider configured (set EASYPOST_API_KEY or SHIPPO_TOKEN)');
}

// Public shipping quote for the checkout: POST { to: {name?, street1, city, state, zip}, items: [{id, qty}] }
app.post('/api/shipping/quote', async (req, res) => {
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
});

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

app.get('/api/orders/recent', requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT id, email, items, amount_total, ship_to, tracking_number,
    label_url, notified, status, created_at FROM orders ORDER BY id DESC LIMIT 50`).all();
  res.json(rows);
});
// ---------- Inventory (for the private admin panel to sync) ----------
app.get('/api/inventory', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT product_id AS id, qty FROM inventory').all());
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT id, email, name, created_at FROM users ORDER BY id DESC`).all();
  const withOrders = db.prepare(`SELECT lower(email) AS e, COUNT(*) AS n FROM orders GROUP BY lower(email)`).all();
  const orderCount = Object.fromEntries(withOrders.map(r => [r.e, r.n]));
  res.json({ count: rows.length, users: rows.map(u => ({ ...u, orders: orderCount[u.email.toLowerCase()] || 0 })) });
});
app.get('/api/products/lite', (req, res) => {
  res.json(CATALOG.map(p => ({ id: String(p.id || p.itemId), title: p.title || p.name || '', price: priceOf(p) })));
});
// ---------- Customer accounts ----------
const newSessionToken = () => crypto.randomBytes(32).toString('hex');
function accountUser(req) {
  const h = req.get('authorization') || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const row = db.prepare("SELECT s.user_id, s.expires_at, u.id, u.email, u.name, u.created_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?").get(m[1]);
  if (!row) return null;
  if (new Date(row.expires_at) < new Date()) { db.prepare('DELETE FROM sessions WHERE token = ?').run(m[1]); return null; }
  return { id: row.id, email: row.email, name: row.name, created_at: row.created_at };
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
    if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'invalid email' });
    if (password.length < 8) return res.status(400).json({ error: 'password too short (min 8)' });
    if (db.prepare('SELECT id FROM users WHERE email = ?').get(email))
      return res.status(409).json({ error: 'email already registered' });
    const hash = await bcrypt.hash(password, 10);
    const r = db.prepare('INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)').run(email, hash, name);
    const token = newSessionToken();
    const exp = new Date(Date.now() + 30*24*3600*1000).toISOString();
    db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, r.lastInsertRowid, exp);
    // Welcome email (fire-and-forget; safe no-op until RESEND_API_KEY is set).
    sendWelcomeEmail(email, name).catch(e => console.error('welcome email failed:', e.message));
    res.json({ token, user: { email, name } });
  } catch (e) { res.status(500).json({ error: 'registration failed' }); }
});
app.post('/api/account/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const u = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!u || !(await bcrypt.compare(password, u.password_hash)))
      return res.status(401).json({ error: 'invalid credentials' });
    const token = newSessionToken();
    const exp = new Date(Date.now() + 30*24*3600*1000).toISOString();
    db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, u.id, exp);
    res.json({ token, user: { email: u.email, name: u.name } });
  } catch (e) { res.status(500).json({ error: 'login failed' }); }
});
app.post('/api/account/logout', (req, res) => {
  const h = req.get('authorization') || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (m) db.prepare('DELETE FROM sessions WHERE token = ?').run(m[1]);
  res.json({ ok: true });
});
app.get('/api/account/me', requireAccount, (req, res) => {
  const orders = db.prepare(`SELECT id, items, amount_total, tracking_number, label_url, status, created_at
    FROM orders WHERE lower(email) = lower(?) ORDER BY id DESC LIMIT 20`).all(req.account.email);
  res.json({ user: req.account, orders: orders.map(o => ({ ...o, items: JSON.parse(o.items || '[]') })) });
});

app.get('/api/health', (req, res) => res.json({
  ok: true,
  catalog: CATALOG.length,
  stripe: !!process.env.STRIPE_WEBHOOK_SECRET, // checkout uses Payment Links + webhook; no secret key needed
  usps: !!(process.env.USPS_CLIENT_ID && process.env.USPS_CLIENT_SECRET),
  shipping: process.env.EASYPOST_API_KEY ? 'easypost' : (process.env.SHIPPO_TOKEN ? 'shippo' : 'none'),
  email: !!RESEND_API_KEY, // Resend wired for welcome / order / promo emails
  r2: r2Enabled(),
}));

app.listen(PORT, () => console.log(`Andy's store backend on :${PORT}`));
