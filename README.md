# Andy's Shoe Supply — store backend

API server (Node 20+ + Express + SQLite, no native builds) that powers
[andysshoesupply.com](https://andysshoesupply.com): catalog validation,
customer accounts, Stripe checkout via Payment Links + webhook, automatic
shipping labels (EasyPost, Shippo fallback), verified-purchase reviews, public likes, and
customer emails via Resend.

Prices and stock are validated **server-side** from `products_full.json`.
Direct-store pricing rule: **15% off** the eBay price; the card-processing
service fee (2.9% + $0.30) is passed to the customer.

## Endpoints

| Feature | Endpoint |
|---|---|
| Health / readiness | `GET /api/health` — reports `catalog`, `stripe`, `usps`, `shipping` (`easypost`/`shippo`/`none`), `email` (true when `RESEND_API_KEY` is set), `r2` |
| Likes (public) | `GET /api/likes/:productId`, `POST /api/likes/:productId/toggle` |
| Product reviews | `GET /api/reviews/:productId`, `POST /api/reviews/:productId` (POST requires a purchase `review_token`) |
| Store reviews | `GET /api/store-reviews`, `POST /api/store-reviews` (POST requires a purchase `review_token`) |
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
   "Review our store" link plus per-item review links, all carrying the
   order's review token (`?rt=<token>` — see "Verified reviews" below). It
   fires only when the order row is actually inserted (`INSERT OR IGNORE` on
   the unique `stripe_session`), so Stripe webhook retries never duplicate it.
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

## Verified reviews (only after a purchase)

Maria's rule: nobody can review the store or a product unless they bought it.
How it works:

1. When the Stripe webhook stores a **new** order, it also creates one row in
   `review_tokens`: a random 64-hex-char token (`crypto.randomBytes(32)`)
   linked to that `order_id` and the buyer email. Webhook retries don't create
   duplicates (same `INSERT OR IGNORE` gate as the confirmation email).
2. The confirmation email carries the token in every review link:
   - Store review: `https://andysshoesupply.com/?rt=<token>#reviews`
   - Each purchased item: `https://andysshoesupply.com/?rt=<token>` (the page
     passes the token when posting that product's review).
3. The POST endpoints enforce it:
   - `POST /api/store-reviews` requires `review_token` in the JSON body. The
     token must exist, belong to an order and not have been used for a store
     review yet (`used_store`); a successful post sets `used_store = 1`.
   - `POST /api/reviews/:productId` requires a `review_token` whose order
     actually includes that product (Payment Link variant ids like
     `398339652878__size_6` count as their base product) and that has not
     already reviewed that product — one review per product per purchase.
   - Any missing, unknown or already-consumed token gets
     `403 {"error":"Reviews are only available after a purchase"}`.
4. Reviews posted with a token are stored with `verified = 1` (and the token,
   for audit). Both review GETs return `verified` (boolean) and `productId`
   on every review object, so the page can show a "Verified Purchase" badge.
   Pre-existing public reviews keep `verified = 0`.

**Schema:** `review_tokens` is created with `CREATE TABLE IF NOT EXISTS`, and
the `reviews.verified` / `reviews.review_token` columns are added at boot with
the same guarded `ALTER TABLE` pattern as `users.unsubscribed` — existing
databases upgrade themselves on deploy.

**Frontend contract:** read `rt` from the page URL (`?rt=<token>`) and send it
as `review_token` in the POST JSON body. On `403` with
`{"error":"Reviews are only available after a purchase"}`, show that message
and hide/disable the review form for visitors without a purchase link.

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
