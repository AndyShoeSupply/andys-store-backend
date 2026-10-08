// r2restore.js — standalone boot step (run BEFORE server.js opens SQLite).
// Downloads the latest store.db snapshot from Cloudflare R2 so likes, reviews,
// orders, users and sessions survive Render free-plan restarts/redeploys.
// Reads R2_ENDPOINT, R2_BUCKET, R2_KEY (default "store.db"),
// R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY and DB_PATH (default "./store.db").
// Exits 0 on success OR when R2 is not configured / nothing to restore.
// Exits 1 only on unexpected errors (server still boots with a fresh DB).
require('dotenv').config();
const fs = require('fs');
const path = require('path');

const ENDPOINT = process.env.R2_ENDPOINT || '';
const BUCKET = process.env.R2_BUCKET || '';
const KEY = process.env.R2_KEY || 'store.db';
const ACCESS = process.env.R2_ACCESS_KEY_ID || '';
const SECRET = process.env.R2_SECRET_ACCESS_KEY || '';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'store.db');

if (!ENDPOINT || !BUCKET || !ACCESS || !SECRET) {
  console.log('r2restore: R2 not configured, skipping');
  process.exit(0);
}

(async () => {
  try {
    const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');
    const s3 = new S3Client({
      region: 'auto',
      endpoint: ENDPOINT,
      credentials: { accessKeyId: ACCESS, secretAccessKey: SECRET },
    });
    const out = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: KEY }));
    const bytes = Buffer.from(await out.Body.transformToByteArray());
    if (bytes.length < 100) throw new Error('snapshot too small, refusing');
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    fs.writeFileSync(DB_PATH, bytes);
    console.log(`r2restore: restored ${bytes.length} bytes -> ${DB_PATH}`);
    process.exit(0);
  } catch (e) {
    if (e && (e.name === 'NoSuchKey' || e.$metadata?.httpStatusCode === 404)) {
      console.log('r2restore: no snapshot yet, starting fresh');
      process.exit(0);
    }
    console.warn('r2restore: skipped -', e.message || e);
    process.exit(0);
  }
})();
