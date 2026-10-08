# Andy's Shoe Supply — store backend

API server (Node + Express + SQLite) that powers the public store:

| Feature | Endpoint |
|---|---|
| Health / readiness | `GET /api/health` (also reports whether Stripe/USPS keys are set) |
| Likes (public, shared) | `GET /api/likes/:id`, `POST /api/likes/:id/toggle` |
| Reviews (public) | `GET /api/reviews/:id`, `POST /api/reviews/:id` |
| Checkout | `POST /api/checkout` → Stripe Checkout Session URL |
| Stripe webhook | `POST /api/webhooks/stripe` → marks orders paid, decrements inventory |
| USPS live rates | `POST /api/usps/rates` `{ toZip, weightOz, ... }` |
| USPS labels | `POST /api/usps/label` `{ orderId }` |
| Inventory | `GET /api/inventory` (for the private admin panel to sync) |

Prices and stock are validated **server-side** from `products_full.json` — the
browser never decides the price. Direct-store pricing rule baked in: **15% off**
the eBay price + card-processing service fee (2.9% + $0.30, configurable) passed
to the customer.

## Deploy (when Maria hands over the keys)

1. Pick a host (Fly.io or Render — both take this Dockerfile, free to start).
2. `cp .env.example .env` and fill in:
   - `STRIPE_SECRET_KEY` — stripe.com → Developers → API keys (Maria's account)
   - `STRIPE_WEBHOOK_SECRET` — Stripe dashboard → Developers → Webhooks →
     add endpoint `https://<tu-servidor>/api/webhooks/stripe`, event
     `checkout.session.completed`
   - `USPS_CLIENT_ID` / `USPS_CLIENT_SECRET` — developer.usps.com (Maria's app)
   - `STORE_URL` / `STORE_ORIGIN` — the store's public URL
3. Deploy, then point the storefront checkout at this server:
   `POST <server>/api/checkout` instead of the provisional SMS flow.
4. Verify: `GET <server>/api/health` → `stripe: true, usps: true`.

## Notes

- Inventory seeds from the catalog's real eBay quantities on first boot and
  decrements only on **paid** Stripe webhook events — no double-selling.
- Likes are one-per-visitor (hashed voter id), reviews are one-per-name per
  product with a light spam guard.
- The private admin panel (`andy-s-admin-panel`) can read `/api/inventory` to
  stay in sync with direct-store sales.
