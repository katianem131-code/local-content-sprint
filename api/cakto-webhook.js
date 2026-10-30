const crypto = require('crypto');

module.exports.config = { api: { bodyParser: false } };

function readBody(req) {
  return new Promise((resolve, reject) => {
    if (req.body && typeof req.body === 'object') return resolve(JSON.stringify(req.body));
    if (typeof req.body === 'string') return resolve(req.body);
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => resolve(raw));
    req.on('error', reject);
  });
}

function first(...values) {
  return values.find((value) => value !== undefined && value !== null && String(value).trim() !== '');
}

function getSignature(req) {
  return first(
    req.headers['x-cakto-signature'],
    req.headers['x-cakto-webhook-signature'],
    req.headers['x-webhook-signature'],
    req.headers['x-signature'],
    req.headers['x-cakto-signature-256']
  );
}

function validSignature(rawBody, signature, secret, payloadSecret) {
  if (!secret) return true;
  // Cakto's documented payload includes the webhook key as `secret`.
  if (payloadSecret && payloadSecret === secret) return true;
  if (!signature) return false;
  const supplied = String(signature).replace(/^sha256=/i, '').trim();
  const digestHex = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  const digestBase64 = crypto.createHmac('sha256', secret).update(rawBody).digest('base64');
  return [digestHex, digestBase64].some((expected) => {
    const a = Buffer.from(supplied);
    const b = Buffer.from(expected);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  });
}

function extract(payload) {
  const data = payload.data || payload;
  const customer = data.customer || data.buyer || data.client || {};
  const product = data.product || data.offer || {};
  return {
    event: String(first(payload.event, payload.type, data.event, data.status, '')).toLowerCase(),
    email: String(first(customer.email, data.email, data.customer_email, data.buyer_email, '')).trim().toLowerCase(),
    productName: String(first(product.name, product.title, data.product_name, data.offer_name, typeof data.product === 'string' ? data.product : '', '')).toLowerCase(),
    productId: String(first(product.id, data.product_id, data.offer_id, '')).trim(),
    orderId: String(first(data.id, data.order_id, data.transaction_id, data.order?.id, '')).trim(),
  };
}

function productKey(info) {
  const acceleratorId = process.env.CAKTO_ACCELERATOR_PRODUCT_ID;
  const mainId = process.env.CAKTO_MAIN_PRODUCT_ID;
  if (acceleratorId && info.productId === acceleratorId) return 'accelerator';
  if (mainId && info.productId === mainId) return 'main';
  if (info.productName.includes('accelerator')) return 'accelerator';
  if (info.productName.includes('local content sprint')) return 'main';
  return null;
}

async function supabase(path, options = {}) {
  const url = `${process.env.SUPABASE_URL.replace(/\/$/, '')}/rest/v1/${path}`;
  const headers = {
    apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
    'Content-Type': 'application/json',
    ...options.headers,
  };
  const response = await fetch(url, { ...options, headers });
  const text = await response.text();
  if (!response.ok) throw new Error(`Supabase ${response.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}

async function findUserId(email) {
  for (let page = 1; page <= 10; page += 1) {
    const url = `${process.env.SUPABASE_URL.replace(/\/$/, '')}/auth/v1/admin/users?page=${page}&per_page=1000`;
    const response = await fetch(url, {
      headers: {
        apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
      },
    });
    if (!response.ok) throw new Error(`Supabase Auth ${response.status}: ${await response.text()}`);
    const body = await response.json();
    const users = body.users || body;
    const match = users.find((user) => String(user.email || '').toLowerCase() === email);
    if (match) return match.id;
    if (!Array.isArray(users) || users.length < 1000) break;
  }
  return null;
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'Method not allowed' });
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    return res.status(500).json({ ok: false, error: 'Supabase server configuration is missing' });
  }

  try {
    const rawBody = await readBody(req);
    const payload = JSON.parse(rawBody || '{}');
    if (!validSignature(rawBody, getSignature(req), process.env.CAKTO_WEBHOOK_SECRET, payload.secret)) {
      return res.status(401).json({ ok: false, error: 'Invalid webhook signature' });
    }
    const info = extract(payload);
    const key = productKey(info);
    if (!info.email || !key) return res.status(200).json({ ok: true, ignored: true });

    const userId = await findUserId(info.email);
    if (!userId) return res.status(200).json({ ok: true, pending: true });

    const revoked = ['refund', 'refunded', 'chargeback', 'purchase_refunded', 'purchase_chargeback'].some((value) => info.event.includes(value));
    await supabase('entitlements?on_conflict=user_id,product_key', {
      method: 'POST',
      headers: { Prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify({
        user_id: userId,
        product_key: key,
        status: revoked ? 'revoked' : 'active',
        source: 'cakto',
        external_order_id: info.orderId || null,
      }),
    });
    return res.status(200).json({ ok: true, processed: true });
  } catch (error) {
    console.error('Cakto webhook error:', error);
    return res.status(500).json({ ok: false, error: 'Webhook processing failed' });
  }
};

