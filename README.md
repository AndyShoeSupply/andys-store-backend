# Andy's Shoe Supply — store backend

API server (Node 20+ + Express + SQLite, no native builds) that powers
[andysshoesupply.com](https://andysshoesupply.com): catalog validation,
customer accounts, Stripe checkout via Payment Links + webhook, automatic
shipping labels (EasyPost, Shippo fallback), public reviews/likes, and
customer emails via Resend.

Prices and stock are validated **server-side** from `products_full.json`.
Direct-store pricing rule: **15% off** the eBay price; the card-processing
service fee (2.9% + $0.30) is passed to the customer.

## Endpoints

| Feature | Endpoint |
|---|---|
| Health / readiness | `GET /api/health` — reports `catalog`, `stripe`, `usps`, `shipping` (`easypost`/`shippo`/`none`), `email` (true when `RESEND_API_KEY` is set), `r2` |
| Likes (public) | `GET /api/likes/:productId`, `POST /api/likes/:productId/toggle` |
| Product reviews | `GET /api/reviews/:productId`, `POST /api/reviews/:productId` |
| Store reviews | `GET /api/store-reviews`, `POST /api/store-reviews` |
| Accounts | `POST /api/account/register`, `POST /api/account/login`, `POST /api/account/logout`, `GET /api/account/me` |
| Checkout | `POST /api/checkout` → Stripe Checkout Session URL |
| Stripe webhook | `POST /api/webhooks/stripe` → stores order, decrements inventory, buys label, sends confirmation email |
| Orders (admin) | `GET /api/orders/recent`, `GET /api/orders/pending-labels`, `POST /api/orders/:id/notified` |
| Labels (admin) | `POST /api/labels/buy` `{ orderId }` |
| Shipping quote | `POST /api/shipping/quote` |
| Inventory (admin) | `GET /api/inventory` |
| Users (admin) | `GET /api/admin/users` |
| Send promo (admin) | `POST /api/admin/send-promo` `{ subject, text }` |
| Promo opt-out | `GET /api/unsubscribe?t=<token>` (link inside every promo email) |

Admin endpoints require the `x-admin-token` header with the `ADMIN_TOKEN` value.

## Customer emails (Resend)

All emails are in English, sent from `Andy's Shoe Supply <hola@andysshoesupply.com>`
(`EMAIL_FROM` to override). If `RESEND_API_KEY` is **not** set the server still
boots normally and every send is a no-op that only logs
`[email] skipped (no RESEND_API_KEY)` — nothing breaks.

1. **Welcome** — sent once when a customer registers (`POST /api/account/register`).
2. **Order confirmation** — sent from the Stripe webhook
   (`checkout.session.completed`) with the item list, the total charged and a
   "Review our store" link to `https://andysshoesupply.com/#reviews`. It fires
   only when the order row is actually inserted (`INSERT OR IGNORE` on the
   unique `stripe_session`), so Stripe webhook retries never duplicate it.
3. **Promotions** — `POST /api/admin/send-promo` with `{ "subject": "...", "text": "..." }`
   sends one individual email to every registered user who has not
   unsubscribed. Each email carries its own signed unsubscribe link and a
   `List-Unsubscribe` header.

Unsubscribe tokens are `base64url(JSON{userId,email}) + "." + HMAC-SHA256(payload)`,
signed with `EMAIL_SECRET` (falls back to `ADMIN_TOKEN` when unset).
`GET /api/unsubscribe?t=...` validates the signature, sets
`users.unsubscribed = 1` and shows a simple confirmation page. Invalid tokens
get HTTP 400.

**Schema migration:** the `users.unsubscribed` column is added automatically at
boot (`ALTER TABLE ... ADD COLUMN`, guarded by a `PRAGMA table_info` check), so
existing databases upgrade themselves on the next deploy — nothing to run by hand.

## Environment variables

See `.env.example` for the full list. The email feature adds:

| Variable | Purpose |
|---|---|
| `RESEND_API_KEY` | Resend API key. Unset = emails disabled (safe no-op, server still runs). |
| `EMAIL_FROM` | Optional sender. Default `Andy's Shoe Supply <hola@andysshoesupply.com>` (the domain must be verified in Resend). |
| `EMAIL_SECRET` | HMAC secret that signs unsubscribe links. Falls back to `ADMIN_TOKEN` when empty. |
| `API_PUBLIC_URL` | Public base URL of this backend, used to build unsubscribe links. On Render it falls back to the automatic `RENDER_EXTERNAL_URL`. |

## Run locally

```bash
cp .env.example .env   # fill in what you have; everything degrades gracefully
npm start              # node server.js, default port 8080
curl localhost:8080/api/health
```

## Deploy

Hosted on Render (service `andys-store-backend`). Render does **not**
auto-deploy: after pushing to GitHub, use Dashboard → Manual Deploy →
"Deploy latest commit", then verify `GET /api/health`.

The SQLite database is snapshotted to Cloudflare R2 every 60s and restored on
boot (`r2restore.js`), so accounts, orders, likes and reviews survive the
free-plan restarts.
