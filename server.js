'use strict';

/**
 * addadollar.com - Backend V4
 * ---------------------------------------------------------------
 * - Express + a local JSON database (atomic writes)
 * - Two sizes:
 *     Standard: 350x350 px, $1, 500 characters max
 *     Large:    500x500 px, $3, 900 characters max
 *   The price is ALWAYS derived server-side from the size. Never trust the client.
 * - Layer validation pipeline (zero tolerance, HTTP 400):
 *     1. length cap for the chosen size
 *     2. reject <script, inline event handlers, javascript:, vbscript:, data:,
 *        expression(, @import, url(, http://, https://, //
 *     3. strict DOMPurify allowlist. If DOMPurify has to strip or change
 *        anything, the whole submission is rejected (we never publish "what's left").
 *        <input> is only OK as type="checkbox" or type="radio".
 *     4. OpenAI Moderation API
 * - Payments (PAYMENT_MODE):
 *     "stripe"    -> Stripe Checkout Session. The validated layer is parked in the
 *                    database as a pending order. It is published ONLY when a Stripe
 *                    webhook (signature verified) confirms the payment.
 *     "simulated" -> local dev only: a fake "pay" button.
 * - HTTPS: in production every HTTP request gets a 301 to the canonical https URL,
 *   plus HSTS. Run behind a reverse proxy (Caddy/nginx) and set TRUST_PROXY=1.
 * - Secrets (Stripe keys, OpenAI key) are read from the environment only.
 *   They never reach the browser and are never logged.
 */

require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const DOMPurify = require('isomorphic-dompurify');

// ---------------------------------------------------------------
// Config
// ---------------------------------------------------------------
const PORT = parseInt(process.env.PORT, 10) || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const PAYMENT_MODE = process.env.PAYMENT_MODE || 'simulated';
const CHARITY_SHARE = Math.min(1, Math.max(0, parseFloat(process.env.CHARITY_SHARE) || 0.5));
const RATE_LIMIT_PER_MIN = parseInt(process.env.RATE_LIMIT_PER_MIN, 10) || 12;
const DATA_FILE = path.resolve(__dirname, process.env.DATA_FILE || './data/db.json');
const SEED_VERSION = 4;                     // bump this to replace the starter blocks
const PENDING_TTL_MS = 24 * 60 * 60 * 1000; // unpaid orders are forgotten after 24 hours
const STRIPE_SESSION_TTL_S = 30 * 60;       // Stripe Checkout link lives 30 minutes
const MAX_PENDING = 2000;                   // hard cap on parked orders (abuse guard)
const MAX_EVENT_IDS = 2000;                 // how many Stripe event ids we remember

// Public base URL, used for redirects and Stripe return URLs.
const BASE_URL = (process.env.BASE_URL || ('http://localhost:' + PORT)).replace(/\/+$/, '');
let BASE;
try {
  BASE = new URL(BASE_URL);
} catch (e) {
  console.error('[config] BASE_URL is not a valid URL: ' + BASE_URL);
  process.exit(1);
}
const CANONICAL_HOSTNAME = BASE.hostname;

// Force HTTPS in production unless explicitly turned off.
const FORCE_HTTPS = process.env.FORCE_HTTPS
  ? process.env.FORCE_HTTPS === 'true'
  : IS_PROD;

// How many reverse proxies sit in front of this app (0 = none).
// "true" is treated as 1. We never trust an unlimited chain: that would let
// anyone spoof X-Forwarded-For and dodge the rate limiter.
const TRUST_PROXY_HOPS = process.env.TRUST_PROXY === 'true'
  ? 1
  : Math.max(0, parseInt(process.env.TRUST_PROXY, 10) || 0);

// The two sizes (key = size in pixels). The client only ever picks the size.
const PLANS = {
  350: { size: 350, price: 1, maxChars: 500, label: 'Standard' },
  500: { size: 500, price: 3, maxChars: 900, label: 'Large' }
};

function getPlan(size) {
  return PLANS[Number(size)] || null;
}

// ---------------------------------------------------------------
// Stripe setup (only when PAYMENT_MODE=stripe)
// ---------------------------------------------------------------
let stripe = null;
let STRIPE_WEBHOOK_SECRET = '';

function initStripe() {
  const key = process.env.STRIPE_SECRET_KEY || '';
  const whsec = process.env.STRIPE_WEBHOOK_SECRET || '';

  const problems = [];
  if (!/^(sk|rk)_(live|test)_/.test(key)) problems.push('STRIPE_SECRET_KEY (should start with sk_ or rk_)');
  if (!/^whsec_/.test(whsec)) problems.push('STRIPE_WEBHOOK_SECRET (should start with whsec_)');
  if (IS_PROD && BASE.protocol !== 'https:') problems.push('BASE_URL (must be https:// in production)');
  if (problems.length) {
    console.error('[stripe] PAYMENT_MODE=stripe but these settings are missing or invalid: ' + problems.join(', '));
    process.exit(1);
  }

  const Stripe = require('stripe');
  const options = { maxNetworkRetries: 2, timeout: 20000, appInfo: { name: 'addadollar.com', version: '4.0.0' } };

  // Test hook ONLY: point the SDK at a local fake Stripe API. Never set this in production.
  if (process.env.STRIPE_API_HOST) {
    options.host = process.env.STRIPE_API_HOST;
    options.port = process.env.STRIPE_API_PORT || '12111';
    options.protocol = process.env.STRIPE_API_PROTOCOL || 'http';
    console.warn('[stripe] Using a custom Stripe API host (' + options.host + '). Test setups only!');
  }

  stripe = new Stripe(key, options);
  STRIPE_WEBHOOK_SECRET = whsec;
  console.log('[stripe] Ready in ' + (key.includes('_live_') ? 'LIVE' : 'TEST') + ' mode.');
}

if (PAYMENT_MODE === 'stripe') {
  initStripe();
} else if (PAYMENT_MODE !== 'simulated') {
  console.error('[config] Unknown PAYMENT_MODE "' + PAYMENT_MODE + '". Use "stripe" or "simulated".');
  process.exit(1);
} else if (IS_PROD) {
  console.error('[config] PAYMENT_MODE=simulated is not allowed with NODE_ENV=production.');
  process.exit(1);
}

// ---------------------------------------------------------------
// Security: allowlist and filters
// ---------------------------------------------------------------

// The only tags a layer may use.
const ALLOWED_TAGS = [
  'div', 'span', 'p', 'h1', 'h2', 'h3', 'b', 'i', 'strong', 'em',
  'br', 'hr', 'center', 'ul', 'ol', 'li', 'label', 'input', 'style',
  'svg', 'path', 'circle', 'rect', 'polygon', 'line'
];

// The only attributes a layer may use.
// No on*, no href/src/xlink:href, no data-*. "for", "id", "name", "type", "checked"
// and "value" exist so labels and checkbox/radio inputs can work with zero JavaScript.
const ALLOWED_ATTR = [
  'style', 'class', 'id', 'for', 'name', 'type', 'checked', 'value',
  'viewBox', 'd', 'cx', 'cy', 'r', 'rx', 'ry', 'x', 'y',
  'x1', 'y1', 'x2', 'y2', 'width', 'height', 'points', 'fill', 'stroke',
  'stroke-width', 'stroke-linecap', 'stroke-linejoin', 'opacity', 'transform',
  'preserveAspectRatio'
];

// Explicitly forbidden on top of the allowlist (belt and suspenders).
const FORBID_TAGS = [
  'script', 'iframe', 'object', 'embed', 'link', 'meta', 'form', 'img',
  'video', 'audio', 'base', 'button', 'textarea', 'select', 'option',
  'a', 'animate', 'animatetransform', 'animatemotion', 'set',
  'use', 'image', 'foreignobject', 'source', 'track', 'portal', 'frame', 'frameset'
];
const FORBID_ATTR = [
  'href', 'xlink:href', 'src', 'srcset', 'srcdoc', 'action', 'formaction',
  'background', 'poster', 'ping'
];

// DOMPurify's own bookkeeping elements (added by FORCE_BODY). Not user content.
const INTERNAL_NODES = new Set(['remove', 'body', 'html', 'head']);

// Collects problems the allowlist alone can't express (e.g. <input type="text">).
let hookViolations = [];

DOMPurify.addHook('uponSanitizeElement', (node, data) => {
  if (data.tagName === 'input') {
    const type = String(node.getAttribute('type') || '').trim().toLowerCase();
    if (type !== 'checkbox' && type !== 'radio') {
      hookViolations.push('<input type="' + (type || 'text') + '">');
    }
  }
});

// Belt and suspenders: drop any on* attribute that somehow survived.
DOMPurify.addHook('afterSanitizeAttributes', (node) => {
  if (!node.attributes) return;
  for (const attr of Array.from(node.attributes)) {
    if (/^on/i.test(attr.name)) node.removeAttribute(attr.name);
  }
});

// Page-structure tags have no business inside a layer.
const PAGE_TAG_RE = /<\s*\/?\s*(html|head|body)\b/i;

// Obvious XSS in the RAW code: reject on sight.
const SCRIPT_RE = /<\s*script/i;
const EVENT_ATTR_RE = /(?:^|[^\w])on\w+\s*=/i; // onclick=, onerror=, onload=, ...

/**
 * Anything that could load an external resource or run code.
 * Backslashes are banned outright, since CSS escapes like \75rl( would sneak past the filters.
 */
const FORBIDDEN_PATTERNS = [
  { re: /javascript\s*:/i, msg: "javascript: URLs aren't allowed" },
  { re: /vbscript\s*:/i, msg: "vbscript: URLs aren't allowed" },
  { re: /data\s*:/i, msg: "data: URIs aren't allowed" },
  { re: /expression\s*\(/i, msg: "expression() isn't allowed" },
  { re: /@import/i, msg: "@import isn't allowed" },
  { re: /url\s*\(/i, msg: "url() isn't allowed (no external resources)" },
  { re: /https?:/i, msg: "external links (http:// or https://) aren't allowed" },
  { re: /\/\//, msg: 'double slashes ("//") aren\'t allowed because they can hide protocol-relative URLs' },
  { re: /image-set\s*\(/i, msg: "image-set() isn't allowed" },
  { re: /@font-face/i, msg: "@font-face isn't allowed" },
  { re: /-moz-binding|behavior\s*:/i, msg: "behavior bindings aren't allowed" },
  { re: /\\/, msg: "backslashes aren't allowed (CSS escapes can be used to sneak past filters)" }
];

function findForbidden(code) {
  for (const { re, msg } of FORBIDDEN_PATTERNS) {
    if (re.test(code)) return msg;
  }
  return null;
}

/**
 * Sanitizes the HTML and also reports everything DOMPurify had to strip
 * (tags or attributes), so we can REJECT instead of publishing the remainder.
 */
function sanitizeHtml(html) {
  hookViolations = [];
  const clean = DOMPurify.sanitize(html, {
    ALLOWED_TAGS,
    ALLOWED_ATTR,
    FORBID_TAGS,
    FORBID_ATTR,
    ALLOW_DATA_ATTR: false,
    ALLOW_ARIA_ATTR: false,
    ALLOW_UNKNOWN_PROTOCOLS: false,
    FORCE_BODY: true // keeps a leading <style> instead of hoisting it out
  }).trim();

  const removed = [];
  for (const item of DOMPurify.removed || []) {
    if (item.element) {
      const name = String(item.element.nodeName || '').toLowerCase();
      if (INTERNAL_NODES.has(name)) continue;
      removed.push(name.startsWith('#') ? 'disallowed content' : '<' + name + '>');
    } else if (item.attribute) {
      removed.push(item.attribute.name);
    }
  }
  const violations = hookViolations.slice();
  hookViolations = [];
  return { clean, removed: Array.from(new Set(removed)), violations: Array.from(new Set(violations)) };
}

function extractText(html) {
  return DOMPurify.sanitize(html, { ALLOWED_TAGS: [], KEEP_CONTENT: true })
    .replace(/\s+/g, ' ')
    .trim();
}

function fail(error, status) {
  return { ok: false, error, status: status || 400 };
}

const ALLOWED_TAGS_HELP =
  'Allowed tags: div, span, p, h1-h3, b, i, strong, em, br, hr, center, ul, ol, li, label, ' +
  'input (checkbox or radio only), style, svg, path, circle, rect, polygon, line.';

/**
 * Synchronous checks (everything except moderation).
 * Returns { ok: true, clean } or { ok: false, error, status: 400 }.
 */
function checkCode(html, plan) {
  if (typeof html !== 'string') return fail("That code doesn't look right.");
  if (html.trim().length === 0) return fail('Your layer is empty. Write some HTML/CSS first.');
  if (html.length > plan.maxChars) {
    return fail(
      'Your code is ' + html.length + ' characters, but the ' + plan.label + ' size (' +
      plan.size + '×' + plan.size + ') allows ' + plan.maxChars + '.'
    );
  }

  // Obvious attacks: reject the whole thing, no "repairs".
  if (SCRIPT_RE.test(html)) {
    return fail('Rejected: <script> tags aren\'t allowed.');
  }
  if (EVENT_ATTR_RE.test(html)) {
    return fail('Rejected: inline event handlers (onclick=, onerror=, onload=, ...) aren\'t allowed.');
  }
  if (PAGE_TAG_RE.test(html)) {
    return fail('Rejected: <html>, <head> and <body> tags aren\'t allowed. Just write the contents of your block.');
  }
  const badRaw = findForbidden(html);
  if (badRaw) return fail('Rejected: ' + badRaw + '.');

  // Strict allowlist: if DOMPurify had to strip anything, we reject.
  const { clean, removed, violations } = sanitizeHtml(html);
  if (violations.length > 0) {
    return fail('Rejected: <input> is only allowed with type="checkbox" or type="radio" (found ' + violations[0] + ').');
  }
  if (removed.length > 0) {
    return fail(
      'Rejected: disallowed elements or attributes (' + removed.slice(0, 6).join(', ') + '). ' +
      ALLOWED_TAGS_HELP
    );
  }
  if (!clean) return fail('Rejected: nothing valid is left after the security check.');
  if (clean.length > 2000) return fail('Your code is too large after the security check.');

  // Re-check the sanitized output (it catches HTML entities like &#117;rl( decoded in attributes).
  const badClean = findForbidden(clean);
  if (badClean) return fail('Rejected: ' + badClean + '.');
  if (EVENT_ATTR_RE.test(clean) || SCRIPT_RE.test(clean)) {
    return fail('Rejected: dangerous content detected.');
  }

  return { ok: true, clean };
}

// ---------------------------------------------------------------
// Security: OpenAI Moderation
// ---------------------------------------------------------------
let warnedNoKey = false;

async function moderate(rawCode, text) {
  const key = process.env.OPENAI_API_KEY;
  if (!key) {
    if (IS_PROD) {
      console.error('[moderation] OPENAI_API_KEY is missing and NODE_ENV=production. Refusing submissions.');
      return fail("Moderation isn't configured on this server, so submissions are paused.", 503);
    }
    if (!warnedNoKey) {
      console.warn(
        '[moderation] OPENAI_API_KEY is missing: skipping OpenAI moderation ' +
        '(all other security checks are still on). Local dev only!'
      );
      warnedNoKey = true;
    }
    return { ok: true, skipped: true };
  }

  try {
    const inputs = [rawCode];
    if (text && text !== rawCode) inputs.push(text);

    const resp = await fetch('https://api.openai.com/v1/moderations', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + key
      },
      body: JSON.stringify({ model: 'omni-moderation-latest', input: inputs }),
      signal: AbortSignal.timeout(8000)
    });

    if (!resp.ok) {
      console.error('[moderation] OpenAI API error:', resp.status);
      // Fail closed: if we can't check it, we don't publish it.
      return fail('The moderation service is temporarily unavailable. Please try again in a moment.', 503);
    }

    const data = await resp.json();
    const flagged = Array.isArray(data.results) && data.results.some((r) => r.flagged === true);
    if (flagged) return fail('Content blocked by our moderation filter.', 400);
    return { ok: true };
  } catch (err) {
    console.error('[moderation] Request failed:', err.message);
    return fail('The moderation service is temporarily unavailable. Please try again in a moment.', 503);
  }
}

// ---------------------------------------------------------------
// Full layer validation pipeline
// ---------------------------------------------------------------
async function validateLayer({ html, x, y, size }) {
  const plan = getPlan(size);
  if (!plan) return fail('Unknown size. Pick 350 or 500 pixels.');

  const nx = Number(x);
  const ny = Number(y);
  if (!Number.isFinite(nx) || !Number.isFinite(ny)) {
    return fail('Invalid position.');
  }
  const px = Math.min(100, Math.max(0, Math.round(nx * 10) / 10));
  const py = Math.min(100, Math.max(0, Math.round(ny * 10) / 10));

  const check = checkCode(html, plan);
  if (!check.ok) return check;

  const mod = await moderate(html, extractText(html));
  if (!mod.ok) return mod;

  return { ok: true, html: check.clean, x: px, y: py, plan };
}

// ---------------------------------------------------------------
// Local JSON database (atomic writes)
//
//   layers   : published blocks (never edited or deleted by the app)
//   pending  : validated blocks waiting for payment, keyed by orderId
//   payments : money ledger, one row per confirmed payment (charity / dev split)
//   events   : Stripe event ids already handled (anti-duplicate)
//   flagged  : payments that need a human look (unknown order, amount mismatch)
// ---------------------------------------------------------------

// Starter blocks. Two of them are clickable with zero JavaScript (label + input),
// and three use CSS animation.
const SEED_LAYERS = [
  {
    // Checkbox toggle: click the label, the box below changes
    html:
      '<input type="checkbox" id="t"><label for="t">Click me!</label><div class="b">Hello, canvas!</div>' +
      '<style>input{display:none}label{display:inline-block;margin:20px;padding:8px 14px;border:2px solid #000;background:#eee;font:bold 14px Verdana;cursor:pointer}.b{margin:0 20px;padding:14px;border:2px solid #000;background:#fff;font:14px Verdana;transition:.3s}input:checked~.b{background:#ff0;transform:rotate(-4deg)}</style>',
    x: 12, y: 16
  },
  {
    // Pure CSS animation: three bouncing squares
    html:
      '<div class="w"><span></span><span></span><span></span></div>' +
      '<style>.w{margin:120px 50px;display:flex;gap:10px}.w span{width:30px;height:30px;background:#0055FF;animation:b 1s ease-in-out infinite}.w span:nth-child(2){animation-delay:.2s}.w span:nth-child(3){animation-delay:.4s}@keyframes b{50%{transform:translateY(-50px);background:#f50}}</style>',
    x: 82, y: 22
  },
  {
    // Radio buttons: pick a color, plus a CSS animation
    html:
      '<input type="radio" name="c" id="r" checked><label for="r">Red</label><input type="radio" name="c" id="u"><label for="u">Blue</label><i></i>' +
      '<style>input{display:none}label{display:inline-block;margin:10px 4px 0;padding:6px 10px;border:1px solid #000;font:12px Verdana;cursor:pointer}i{display:block;margin:14px;width:120px;height:120px;background:#c00;animation:p 2s infinite}#u:checked~i{background:#05f}@keyframes p{50%{border-radius:50%}}</style>',
    x: 14, y: 82
  },
  {
    // Lists, hr and center, with a gentle fade
    html:
      '<center><h2>House Rules</h2><hr><ul><li>Keep it fun</li><li>No scripts</li><li>Be nice</li></ul></center>' +
      '<style>h2{font:bold 22px Verdana;margin:20px 0 6px}ul{display:inline-block;text-align:left;font:13px Verdana;animation:f 3s infinite}@keyframes f{50%{opacity:.35}}</style>',
    x: 86, y: 80
  }
];

function buildSeedLayer(seed, id) {
  const check = checkCode(seed.html, PLANS[350]);
  if (!check.ok) {
    throw new Error('Starter block #' + id + ' fails the security checks: ' + check.error);
  }
  return {
    id, html: check.clean, x: seed.x, y: seed.y,
    size: 350, price: 1, createdAt: new Date().toISOString(), seed: true
  };
}

function loadDb() {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });

  let data;
  let dirty = false;
  if (fs.existsSync(DATA_FILE)) {
    data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } else {
    data = { nextId: 1, layers: [], seedVersion: 0 };
    dirty = true;
  }

  // Fields added in V4. Older databases get them automatically.
  if (!data.pending || typeof data.pending !== 'object') { data.pending = {}; dirty = true; }
  if (!Array.isArray(data.payments)) { data.payments = []; dirty = true; }
  if (!Array.isArray(data.events)) { data.events = []; dirty = true; }
  if (!Array.isArray(data.flagged)) { data.flagged = []; dirty = true; }

  // Migration from V1: old layers have no size or price.
  // They become Standard (350 px, $1), which is what they paid.
  let migrated = 0;
  for (const layer of data.layers) {
    if (!PLANS[layer.size]) { layer.size = 350; migrated++; }
    if (typeof layer.price !== 'number') layer.price = PLANS[layer.size].price;
  }
  if (migrated > 0) {
    dirty = true;
    console.log('[db] Migrated ' + migrated + ' older layer(s) to the Standard size.');
  }

  // Starter blocks: replace outdated ones, never touch paid layers.
  if (data.seedVersion !== SEED_VERSION) {
    data.layers = data.layers.filter((l) => !l.seed);
    for (const seed of SEED_LAYERS) {
      data.layers.push(buildSeedLayer(seed, data.nextId++));
    }
    data.seedVersion = SEED_VERSION;
    dirty = true;
    console.log('[db] Starter blocks installed (' + SEED_LAYERS.length + ').');
  }

  if (dirty) saveDb(data);
  return data;
}

function saveDb(data) {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, DATA_FILE); // atomic replace
}

const db = loadDb();

// orderId -> layer, so a webhook retry can never publish the same order twice.
const layerByOrder = new Map();
for (const l of db.layers) {
  if (l.orderId) layerByOrder.set(l.orderId, l);
}

/**
 * Public stats. Only the charity total is shown.
 * It's built from the money ledger, and only counts payments made in the current mode,
 * so test payments never inflate the live counter.
 */
function getStats() {
  let charityCents = 0;
  for (const p of db.payments) {
    if (p.mode === PAYMENT_MODE) charityCents += p.charityCents;
  }
  return { charityCents, charityDollars: (charityCents / 100).toFixed(2) };
}

// ---------------------------------------------------------------
// Orders and the payment layer
// ---------------------------------------------------------------
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function purgeExpiredOrders() {
  const now = Date.now();
  let removed = 0;
  for (const [id, o] of Object.entries(db.pending)) {
    if (now - o.createdAt > PENDING_TTL_MS) { delete db.pending[id]; removed++; }
  }
  if (removed > 0) saveDb(db);
}

/**
 * Turns a PAID order into a published layer and records the money split.
 * THIS IS THE ONLY FUNCTION THAT PUBLISHES A LAYER.
 * It is idempotent: calling it twice for the same order publishes once.
 *
 * payment = { id, mode, amountCents, currency, paymentIntent }
 * Returns { layer, duplicate } or null if the order is unknown.
 */
function finalizeOrder(orderId, payment) {
  const already = layerByOrder.get(orderId);
  if (already) return { layer: already, duplicate: true };

  const order = db.pending[orderId];
  if (!order) return null;

  const amountCents = payment.amountCents;
  const charityCents = Math.round(amountCents * CHARITY_SHARE);

  const layer = {
    id: db.nextId++,
    html: order.html,
    x: order.x,
    y: order.y,
    size: order.size,
    price: order.price,
    orderId,
    createdAt: new Date().toISOString()
  };
  db.layers.push(layer);
  db.payments.push({
    id: payment.id,
    orderId,
    layerId: layer.id,
    mode: payment.mode,
    currency: payment.currency,
    amountCents,
    charityCents,
    devCents: amountCents - charityCents,
    paymentIntent: payment.paymentIntent || null,
    createdAt: layer.createdAt
  });
  delete db.pending[orderId];
  saveDb(db);
  layerByOrder.set(orderId, layer);
  return { layer, duplicate: false };
}

function flagPayment(reason, details) {
  db.flagged.push(Object.assign({ reason, at: new Date().toISOString() }, details));
  saveDb(db);
  console.error('[payments] NEEDS REVIEW: ' + reason, JSON.stringify(details));
}

const paymentProvider = {
  /**
   * Creates the payment for a parked order.
   * simulated: nothing to create, the browser calls the fake "pay" route.
   * stripe:    creates a Checkout Session and returns the hosted payment page URL.
   */
  async createCheckout(orderId, order) {
    if (PAYMENT_MODE === 'simulated') {
      return { mode: 'simulated', orderId, size: order.size, price: order.price };
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      client_reference_id: orderId,
      line_items: [{
        quantity: 1,
        price_data: {
          currency: 'usd',
          unit_amount: order.price * 100, // price comes from PLANS, never from the client
          product_data: {
            name: 'addadollar.com block (' + order.size + 'x' + order.size + ' px)',
            description: 'One-time payment. 50% goes to charity.'
          }
        }
      }],
      // Only the order id travels through Stripe. The code stays on our server.
      metadata: { orderId, size: String(order.size) },
      payment_intent_data: { metadata: { orderId }, description: 'addadollar.com block ' + orderId },
      success_url: BASE_URL + '/success?order=' + orderId,
      cancel_url: BASE_URL + '/cancel?order=' + orderId,
      expires_at: Math.floor(Date.now() / 1000) + STRIPE_SESSION_TTL_S
    }, { idempotencyKey: 'order_' + orderId });

    order.sessionId = session.id;
    saveDb(db);
    return { mode: 'stripe', orderId, url: session.url };
  }
};

// ---------------------------------------------------------------
// Stripe webhook handlers
// ---------------------------------------------------------------

// Anti-duplicate, layer 1: remember every event id we fully handled.
function eventSeen(id) { return db.events.includes(id); }
function rememberEvent(id) {
  db.events.push(id);
  if (db.events.length > MAX_EVENT_IDS) db.events.splice(0, db.events.length - MAX_EVENT_IDS);
  saveDb(db);
}

function handlePaidSession(session) {
  if (session.payment_status !== 'paid') return; // e.g. async method still processing

  const orderId = (session.client_reference_id || (session.metadata && session.metadata.orderId) || '').toString();
  if (!UUID_RE.test(orderId)) {
    flagPayment('paid session without a valid order id', { sessionId: session.id, amount: session.amount_total });
    return;
  }

  // Anti-duplicate, layer 2: an order that's already published is never published again.
  if (layerByOrder.has(orderId)) return;

  const order = db.pending[orderId];
  if (!order) {
    flagPayment('paid session for an unknown or expired order', { sessionId: session.id, orderId, amount: session.amount_total });
    return;
  }

  // Never trust a webhook blindly: the amount must match what this order should cost.
  const expectedCents = order.price * 100;
  if (session.amount_total !== expectedCents || String(session.currency).toLowerCase() !== 'usd') {
    flagPayment('amount or currency mismatch', {
      sessionId: session.id, orderId, expectedCents, gotCents: session.amount_total, currency: session.currency
    });
    return;
  }

  // Anti-duplicate, layer 3: a Checkout Session can only ever back one payment row.
  if (db.payments.some((p) => p.id === session.id)) return;

  const result = finalizeOrder(orderId, {
    id: session.id,
    mode: 'stripe',
    amountCents: session.amount_total,
    currency: 'usd',
    paymentIntent: typeof session.payment_intent === 'string' ? session.payment_intent : null
  });
  if (result && !result.duplicate) {
    console.log('[payments] Published layer #' + result.layer.id + ' (order ' + orderId + ')');
  }
}

function handleExpiredSession(session) {
  const orderId = (session.client_reference_id || '').toString();
  if (UUID_RE.test(orderId) && db.pending[orderId] && !layerByOrder.has(orderId)) {
    delete db.pending[orderId];
    saveDb(db);
  }
}

// ---------------------------------------------------------------
// Express app
// ---------------------------------------------------------------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', TRUST_PROXY_HOPS);

// Health check for uptime monitors and the deploy script. Must work over plain HTTP.
app.get('/healthz', (req, res) => res.type('text/plain').send('ok'));

// HTTPS enforcement: any plain-HTTP request (or non-canonical host such as www)
// gets a permanent 301 to the canonical https URL. HSTS tells browsers to skip
// HTTP from then on. We deliberately do NOT use includeSubDomains or preload:
// your mail (Zimbra) subdomains must keep working however they're set up.
app.use((req, res, next) => {
  if (!FORCE_HTTPS) return next();
  if (!req.secure || req.hostname !== CANONICAL_HOSTNAME) {
    return res.redirect(301, BASE_URL + req.originalUrl);
  }
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  next();
});

/**
 * Content-Security-Policy for the main app.
 * Note: layers are rendered in srcdoc iframes, and a srcdoc document INHERITS this policy.
 * That's why style-src needs 'unsafe-inline' (layers are inline <style>). It's safe here:
 * scripts stay locked to 'self', and every layer is sandboxed with no allow-scripts,
 * carries its own default-src 'none' meta CSP, and is pre-filtered on the server.
 * Stripe payment happens on Stripe's own page (a plain redirect), so no Stripe
 * domain needs to be allowed here.
 */
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "frame-src 'self' about:",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'self'"
].concat(FORCE_HTTPS ? ['upgrade-insecure-requests'] : []).join('; ');

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  next();
});

/**
 * Stripe webhook.
 * IMPORTANT: this route is declared BEFORE express.json(). Stripe signs the exact
 * raw bytes, so the body must reach constructEvent() untouched.
 */
app.post('/api/stripe/webhook', express.raw({ type: 'application/json', limit: '100kb' }), (req, res) => {
  if (!stripe) return res.status(404).json({ error: 'Not available.' });

  let event;
  try {
    // Throws unless the Stripe-Signature header matches the body and our webhook secret.
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.warn('[webhook] Rejected: bad signature or malformed body.');
    return res.status(400).send('Invalid signature');
  }

  try {
    if (eventSeen(event.id)) {
      return res.json({ received: true, duplicate: true });
    }

    switch (event.type) {
      case 'checkout.session.completed':
      case 'checkout.session.async_payment_succeeded':
        handlePaidSession(event.data.object);
        break;
      case 'checkout.session.expired':
        handleExpiredSession(event.data.object);
        break;
      default:
        break; // ignore everything else
    }

    rememberEvent(event.id);
    res.json({ received: true });
  } catch (err) {
    // 500 makes Stripe retry later, which is what we want if the database write failed.
    console.error('[webhook] Handler error:', err.message);
    res.status(500).json({ error: 'Handler error.' });
  }
});

app.use(express.json({ limit: '50kb' }));

app.use(express.static(path.join(__dirname, 'public'), { maxAge: '5m' }));

// The contact page is the normal canvas plus a contact card (the client script handles it).
app.get(['/contact', '/contact/'], (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Stripe sends the customer here after paying. The page waits for the webhook to publish the block.
app.get('/success', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'success.html'));
});

// Stripe sends the customer here if they back out of the payment page.
// Nothing to undo: the parked order simply expires. We bring them back to their editor.
app.get('/cancel', (req, res) => {
  res.redirect(302, '/?canceled=1');
});

// Bad JSON / oversized body: clear errors
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid request.' });
  }
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request too large.' });
  }
  next(err);
});

// Simple in-memory per-IP rate limiter
function rateLimit(max, windowMs) {
  const hits = new Map();
  // Drop stale entries so the map can't grow forever
  setInterval(() => {
    const now = Date.now();
    for (const [ip, times] of hits) {
      if (!times.some((t) => now - t < windowMs)) hits.delete(ip);
    }
  }, 5 * 60 * 1000).unref();

  return (req, res, next) => {
    const now = Date.now();
    const recent = (hits.get(req.ip) || []).filter((t) => now - t < windowMs);
    if (recent.length >= max) {
      res.setHeader('Retry-After', Math.ceil(windowMs / 1000));
      return res.status(429).json({ error: 'Too many attempts. Please wait a minute and try again.' });
    }
    recent.push(now);
    hits.set(req.ip, recent);
    next();
  };
}

const submitLimiter = rateLimit(RATE_LIMIT_PER_MIN, 60 * 1000); // submission + moderation + Stripe session
const payLimiter = rateLimit(RATE_LIMIT_PER_MIN, 60 * 1000);
const readLimiter = rateLimit(240, 60 * 1000);

/**
 * Layers + charity total.
 * Incremental: pass ?since=<last id you have> and you only get newer layers.
 * Layers are never edited or deleted, so this is all a client needs to stay current.
 */
app.get('/api/layers', readLimiter, (req, res) => {
  const since = Math.max(0, parseInt(req.query.since, 10) || 0);
  const layers = db.layers
    .filter((l) => l.id > since)
    .map(({ id, html, x, y, size }) => ({ id, html, x, y, size }));
  res.json({
    layers,
    stats: getStats(),
    config: { plans: PLANS, paymentMode: PAYMENT_MODE }
  });
});

// Is this order live yet? The success page polls this while the webhook does its work.
app.get('/api/order/:orderId', readLimiter, (req, res) => {
  const orderId = String(req.params.orderId);
  if (!UUID_RE.test(orderId)) return res.status(400).json({ error: 'Invalid order.' });

  const layer = layerByOrder.get(orderId);
  if (layer) {
    return res.json({ status: 'published', layer: { id: layer.id, size: layer.size }, stats: getStats() });
  }
  if (db.pending[orderId]) return res.json({ status: 'pending' });
  res.json({ status: 'unknown' });
});

// Step 1: security checks + moderation, park the validated layer, create the payment
app.post('/api/checkout', submitLimiter, async (req, res) => {
  try {
    purgeExpiredOrders();
    if (Object.keys(db.pending).length >= MAX_PENDING) {
      return res.status(503).json({ error: "We're a bit overloaded right now. Please try again in a few minutes." });
    }

    const result = await validateLayer(req.body || {});
    if (!result.ok) return res.status(result.status || 400).json({ error: result.error });

    const orderId = crypto.randomUUID();
    const order = {
      html: result.html,
      x: result.x,
      y: result.y,
      size: result.plan.size,
      price: result.plan.price, // derived from the plan, never sent by the client
      status: 'pending',
      createdAt: Date.now()
    };
    db.pending[orderId] = order;
    saveDb(db);

    let checkout;
    try {
      checkout = await paymentProvider.createCheckout(orderId, order);
    } catch (err) {
      delete db.pending[orderId];
      saveDb(db);
      console.error('[checkout] Payment provider error:', err.message);
      return res.status(502).json({ error: "We couldn't start the payment. Please try again in a moment." });
    }
    res.json(checkout);
  } catch (err) {
    console.error('[checkout]', err.message);
    res.status(500).json({ error: 'Something went wrong on our end.' });
  }
});

// Step 2 (simulated payments only, never available with Stripe)
app.post('/api/checkout/:orderId/simulate', payLimiter, (req, res) => {
  if (PAYMENT_MODE !== 'simulated') {
    return res.status(404).json({ error: 'Not available.' });
  }
  const orderId = String(req.params.orderId);
  const order = UUID_RE.test(orderId) ? db.pending[orderId] : null;
  const result = order && finalizeOrder(orderId, {
    id: 'sim_' + crypto.randomUUID(),
    mode: 'simulated',
    amountCents: order.price * 100,
    currency: 'usd'
  });
  if (!result) {
    return res.status(404).json({ error: 'Order not found or expired. Please start over.' });
  }
  const l = result.layer;
  res.json({
    ok: true,
    layer: { id: l.id, html: l.html, x: l.x, y: l.y, size: l.size },
    stats: getStats()
  });
});

app.listen(PORT, () => {
  console.log('addadollar.com (V4) is running at ' + BASE_URL + ' (port ' + PORT + ')');
  console.log(
    'Payments: ' + PAYMENT_MODE + ' | Layers: ' + db.layers.length + ' | ' + (IS_PROD ? 'production' : 'dev') +
    ' mode | HTTPS redirect: ' + (FORCE_HTTPS ? 'on' : 'off') + ' | proxy hops: ' + TRUST_PROXY_HOPS
  );
});
