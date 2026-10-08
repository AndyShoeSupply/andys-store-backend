// Andy's Shoe Supply — store backend
// Endpoints: health, likes, reviews, Stripe checkout + webhook, USPS rates + labels, inventory.
// Secrets come ONLY from environment variables (see .env.example). Never hardcode keys.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
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
const db = new DatabaseSync(process.env.DB_PATH || './store.db');
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

// ---------- Helpers ----------
const voterOf = (req, productId) =>
  crypto.createHash('sha256').update((req.ip || '') + '|' + productId + '|' + (process.env.VOTE_SALT || 'andys')).digest('hex');

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
  const rows = db.prepare(`SELECT name, rating, text, created_at FROM reviews WHERE product_id=? AND approved=1 ORDER BY id DESC LIMIT 100`).all(id);
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
  // light spam guard: one review per voter per product
  const voter = voterOf(req, 'rev' + id);
  if (db.prepare(`SELECT 1 FROM reviews WHERE product_id=? AND name=?`).get(id, name))
    return res.status(409).json({ error: 'You already reviewed this product' });
  db.prepare(`INSERT INTO reviews (product_id, name, rating, text) VALUES (?, ?, ?, ?)`).run(id, name, rating, text);
  res.json({ ok: true });
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

async function buyLabelForOrder(orderId) {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(Number(orderId));
  if (!order || order.status !== 'paid') throw new Error('Paid order not found');
  if (order.label_url) return { label_url: order.label_url, tracking_number: order.tracking_number }; // already done
  const items = JSON.parse(order.items || '[]');
  const shipTo = JSON.parse(order.ship_to || '{}');
  if (!shipTo.zip || !shipTo.line1) throw new Error('Order is missing the shipping address');

  // Parcel: shoebox 13x8x5 in; weight from the heaviest item (fallback 2.5 lb)
  let weightLb = 2.5;
  for (const it of items) {
    const p = byId.get(String(it.id));
    const w = Number(p?.weight_lbs);
    if (Number.isFinite(w) && w > 0) weightLb = Math.max(weightLb, w);
  }
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
        length: '13', width: '8', height: '5',
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

app.get('/api/health', (req, res) => res.json({
  ok: true,
  catalog: CATALOG.length,
  stripe: !!process.env.STRIPE_SECRET_KEY,
  usps: !!(process.env.USPS_CLIENT_ID && process.env.USPS_CLIENT_SECRET),
}));

app.listen(PORT, () => console.log(`Andy's store backend on :${PORT}`));
