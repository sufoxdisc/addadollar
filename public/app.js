'use strict';

/**
 * addadollar.com - client V3
 * ---------------------------------------------------------------
 * Security
 *  - Every layer renders inside <iframe sandbox="" srcdoc="...">: the sandbox
 *    attribute is empty, so no scripts and no same-origin access.
 *  - Layer code never touches the page's DOM. It only goes through iframe.srcdoc
 *    (rendering) or textContent (the read-only code list).
 *  - The server is the source of truth for security, size and price.
 *    Everything checked here is just for convenience.
 *
 * Performance (anti-lag engine)
 *  - Each layer gets a cheap empty <div> box. The heavy part, the <iframe>, is only
 *    mounted while its box is near the viewport (IntersectionObserver + a generous margin).
 *  - A hard cap limits how many iframes are mounted at once. Past the cap, boxes that
 *    scrolled away are unmounted first.
 *  - Mounts are spread across animation frames so the page never freezes.
 *  - Updates are differential: the poll only asks for layers newer than the last id,
 *    and existing boxes and iframes are never rebuilt.
 *  - While the editor is open the wall's iframes are unmounted, and the editor's preview
 *    only mounts the few layers closest to your block.
 */

// Mirrors PLANS in server.js. The server always recomputes the price itself.
const PLANS = {
  350: { price: 1, max: 500, label: 'Standard' },
  500: { price: 3, max: 900, label: 'Large' }
};
const POLL_MS = 8000;
const WALL_MARGIN = '600px';     // how far outside the viewport we keep layers mounted
const MOUNTS_PER_FRAME = 3;      // never mount more than this many iframes in one frame
const PREVIEW_MOUNT_CAP = 10;    // live iframes in the editor preview (desktop)
const PREVIEW_MOUNT_CAP_MOBILE = 6;

const $ = (sel) => document.querySelector(sel);
const wall = $('#wall');
const stage = $('#stage');
const statsEl = $('#stats');
const ctaBtn = $('#ctaBtn');
const welcome = $('#welcome');
const editor = $('#editor');
const lockedList = $('#lockedLayers');
const codeEl = $('#code');
const counterEl = $('#counter');
const charCount = $('#charCount');
const charMax = $('#charMax');
const yourLayerLabel = $('#yourLayerLabel');
const posX = $('#posX');
const posY = $('#posY');
const posXOut = $('#posXOut');
const posYOut = $('#posYOut');
const applyBtn = $('#applyBtn');
const tryMode = $('#tryMode');
const previewPane = $('#previewPane');
const previewScaler = $('#previewScaler');
const previewStage = $('#previewStage');
const checkout = $('#checkout');
const checkoutError = $('#checkoutError');
const payBtn = $('#payBtn');
const toastEl = $('#toast');

// Max iframes alive at once. On desktop the whole canvas fits on one screen, so every
// layer is "visible" and this cap is what keeps the page smooth once the wall gets
// crowded. Raise it if your visitors have fast machines, lower it if they don't.
const MAX_MOUNTED_DESKTOP = 64;
const MAX_MOUNTED_MOBILE = 24;

const isMobile = () => window.matchMedia('(max-width: 767px)').matches;
const maxMounted = () => (isMobile() ? MAX_MOUNTED_MOBILE : MAX_MOUNTED_DESKTOP);

// /contact is the same canvas with a contact card on top.
const IS_CONTACT = /^\/contact\/?$/.test(location.pathname);
const contactCard = $('#contactCard');
const recapNote = $('#recapNote');
const RECAP_NOTE_LIVE = recapNote.textContent;
const DRAFT_KEY = 'addadollar_draft';

// How payments work on this server ("stripe" or "simulated"). The server tells us.
let paymentMode = 'stripe';

/* ------------------------------------------------------------------
 * Small helpers
 * ---------------------------------------------------------------- */

function normSize(s) { return Number(s) === 500 ? 500 : 350; }
function fmtMoney(n) { return '$' + Number(n).toFixed(2); }
function clamp(v, a, b) { return Math.min(b, Math.max(a, v)); }
function round1(v) { return Math.round(v * 10) / 10; }

let toastTimer = null;
function showToast(message) {
  toastEl.textContent = message;
  toastEl.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toastEl.classList.add('hidden'), 4500);
}

async function api(path, options) {
  const resp = await fetch(path, options);
  let data = {};
  try { data = await resp.json(); } catch (e) { /* empty body */ }
  if (!resp.ok) throw new Error(data.error || 'Network error (' + resp.status + ').');
  return data;
}

/* ------------------------------------------------------------------
 * Layer boxes and sandboxed iframes
 * ---------------------------------------------------------------- */

// The document that goes into the iframe. Its own CSP blocks all network access
// (defense in depth on top of the sandbox and the server-side filters).
function buildDoc(html) {
  return (
    '<!doctype html><html><head><meta charset="utf-8">' +
    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">' +
    '<style>html,body{margin:0;padding:0;overflow:hidden;background:transparent}</style>' +
    '</head><body>' + html + '</body></html>'
  );
}

// Lock the box to its exact size and place it at X% / Y%. The translate keeps the
// whole box on screen, even at 0% or 100%.
function placeBox(box, x, y, size) {
  box.style.width = size + 'px';
  box.style.height = size + 'px';
  box.style.left = x + '%';
  box.style.top = y + '%';
  box.style.transform = 'translate(-' + x + '%, -' + y + '%)';
}

function makeBox(x, y, size, extraClass) {
  const box = document.createElement('div');
  box.className = 'layer' + (extraClass ? ' ' + extraClass : '');
  placeBox(box, x, y, normSize(size));
  return box;
}

function makeFrame(html, size) {
  const s = normSize(size);
  const frame = document.createElement('iframe');
  frame.setAttribute('sandbox', ''); // strictly empty: no allow-scripts, no allow-same-origin
  frame.setAttribute('scrolling', 'no');
  frame.setAttribute('tabindex', '-1');
  frame.setAttribute('title', 'Community layer');
  frame.setAttribute('referrerpolicy', 'no-referrer');
  frame.style.width = s + 'px';
  frame.style.height = s + 'px';
  frame.srcdoc = buildDoc(html);
  return frame;
}

/* ------------------------------------------------------------------
 * The wall: viewport-aware rendering
 * ---------------------------------------------------------------- */

const records = new Map();        // layer id -> { id, html, x, y, size, box, frame, visible, seen }
const recordByBox = new Map();    // box element -> record
let lastId = 0;                   // highest layer id we have
let mountedCount = 0;
let seenTick = 0;
let wallPaused = false;           // true while the editor is open
let reconcileQueued = false;

const observer = new IntersectionObserver((entries) => {
  for (const entry of entries) {
    const rec = recordByBox.get(entry.target);
    if (!rec) continue;
    rec.visible = entry.isIntersecting;
    if (rec.visible) rec.seen = ++seenTick;
  }
  queueReconcile();
}, { root: wall, rootMargin: WALL_MARGIN });

function addLayers(list) {
  const fragment = document.createDocumentFragment();
  let added = 0;
  for (const l of list) {
    if (records.has(l.id)) continue; // differential: never rebuild what we already have
    const size = normSize(l.size);
    const box = makeBox(l.x, l.y, size);
    const rec = {
      id: l.id, html: l.html, x: l.x, y: l.y, size,
      box, frame: null, visible: false, seen: 0
    };
    records.set(l.id, rec);
    recordByBox.set(box, rec);
    fragment.appendChild(box);
    observer.observe(box);
    if (l.id > lastId) lastId = l.id;
    added++;
  }
  if (added > 0) {
    stage.appendChild(fragment);
    appendLocked(list);
  }
  return added;
}

function mountRec(rec) {
  if (rec.frame) return;
  rec.frame = makeFrame(rec.html, rec.size);
  rec.box.appendChild(rec.frame);
  mountedCount++;
}

function unmountRec(rec) {
  if (!rec.frame) return;
  rec.frame.remove();
  rec.frame = null;
  mountedCount--;
}

function queueReconcile() {
  if (reconcileQueued) return;
  reconcileQueued = true;
  requestAnimationFrame(reconcile);
}

// Decides which iframes should exist right now. Runs at most once per frame.
function reconcile() {
  reconcileQueued = false;

  // While the editor is open, free the whole wall (and every animation in it).
  if (wallPaused) {
    for (const rec of records.values()) unmountRec(rec);
    return;
  }

  const cap = maxMounted();

  // Visible layers that still need an iframe, newest first
  const wanted = [];
  for (const rec of records.values()) {
    if (rec.visible && !rec.frame) wanted.push(rec);
  }
  wanted.sort((a, b) => b.id - a.id);

  // Layers that are mounted but have scrolled away, least recently seen first
  let evictable = null;
  const getEvictable = () => {
    if (!evictable) {
      evictable = [];
      for (const rec of records.values()) {
        if (rec.frame && !rec.visible) evictable.push(rec);
      }
      evictable.sort((a, b) => a.seen - b.seen);
    }
    return evictable;
  };

  let budget = MOUNTS_PER_FRAME;
  let more = false;
  for (const rec of wanted) {
    if (budget <= 0) { more = true; break; }
    if (mountedCount >= cap) {
      const victim = getEvictable().shift();
      if (!victim) break; // everything mounted is on screen: leave it alone
      unmountRec(victim);
    }
    mountRec(rec);
    budget--;
  }

  // Unmount layers that scrolled far away if we're over the cap
  while (mountedCount > cap) {
    const victim = getEvictable().shift();
    if (!victim) break;
    unmountRec(victim);
  }

  if (more) queueReconcile(); // finish the rest on the next frame
}

/* ------------------------------------------------------------------
 * Talking to the server
 * ---------------------------------------------------------------- */

function renderStats(stats) {
  statsEl.textContent = 'Charity Donations: ' + fmtMoney(stats.charityDollars);
}

let polling = false;
async function refresh() {
  if (polling || document.hidden) return;
  polling = true;
  try {
    // Differential: only layers newer than the last one we have
    const data = await api('/api/layers?since=' + lastId);
    if (data.config && data.config.paymentMode) paymentMode = data.config.paymentMode;
    renderStats(data.stats);
    addLayers(data.layers);
  } catch (err) {
    // Keep the last good state on screen; try again on the next tick
  } finally {
    polling = false;
  }
}

function centerWallOnMobile() {
  // On phones the canvas is bigger than the screen, so start in the middle.
  if (stage.offsetWidth > wall.clientWidth) {
    wall.scrollLeft = (stage.offsetWidth - wall.clientWidth) / 2;
    wall.scrollTop = (stage.offsetHeight - wall.clientHeight) / 2;
  }
}

/* ------------------------------------------------------------------
 * Read-only code list (built incrementally)
 * ---------------------------------------------------------------- */

function appendLocked(list) {
  const fragment = document.createDocumentFragment();
  for (const l of list) {
    const block = document.createElement('div');
    block.className = 'locked';
    block.setAttribute('aria-readonly', 'true');
    block.title = 'Locked layer (read-only)';

    const head = document.createElement('span');
    head.className = 'c';
    const s = normSize(l.size);
    head.textContent = '/* Layer #' + l.id + ' - ' + s + 'x' + s + ' - Pos (' + l.x + '%, ' + l.y + '%) */';

    const pre = document.createElement('pre');
    pre.textContent = l.html; // textContent only, never HTML

    block.appendChild(head);
    block.appendChild(pre);
    fragment.appendChild(block);
  }
  lockedList.appendChild(fragment);
}

/* ------------------------------------------------------------------
 * Editor state, counter, prices
 * ---------------------------------------------------------------- */

const state = { size: 350, x: 50, y: 50 };
function plan() { return PLANS[state.size]; }

function updateCounter() {
  const n = codeEl.value.length;
  charCount.textContent = n;
  charMax.textContent = plan().max;
  counterEl.classList.toggle('over', n > plan().max);
}

function updateTexts() {
  const p = plan();
  yourLayerLabel.textContent = '/* Your Layer - Max ' + p.max + ' characters */';
  applyBtn.textContent = 'Apply & continue ($' + p.price + ')';
  updateCounter();
}

function updatePosLabels() {
  posXOut.textContent = state.x + '%';
  posYOut.textContent = state.y + '%';
}

/* ------------------------------------------------------------------
 * Live preview: the real canvas, to scale
 * ---------------------------------------------------------------- */

// pv.ctx: id -> { box, frame } for every published layer drawn in the preview
const pv = { W: 0, H: 0, k: 1, layer: null, frame: null, label: null, ctx: new Map() };
let previewTimer = null;
let contextTimer = null;

function buildPreview() {
  pv.W = stage.offsetWidth;
  pv.H = stage.offsetHeight;
  pv.ctx.clear();

  previewStage.textContent = '';
  previewStage.style.width = pv.W + 'px';
  previewStage.style.height = pv.H + 'px';

  // Every published layer becomes a cheap outline box. Only the ones nearest
  // to your block get a live iframe (see syncPreviewContext).
  const fragment = document.createDocumentFragment();
  for (const rec of records.values()) {
    const box = makeBox(rec.x, rec.y, rec.size, 'ghost');
    pv.ctx.set(rec.id, { box, frame: null, rec });
    fragment.appendChild(box);
  }
  previewStage.appendChild(fragment);

  // Your block (mounted right away; this is the one you're editing)
  pv.layer = makeBox(state.x, state.y, state.size, 'mine');
  pv.layer.appendChild(makeFrame(codeEl.value, state.size));
  previewStage.appendChild(pv.layer);

  // The dashed blue frame marks your exact box
  pv.frame = document.createElement('div');
  pv.frame.className = 'frame';
  pv.label = document.createElement('span');
  pv.frame.appendChild(pv.label);
  previewStage.appendChild(pv.frame);

  fitPreview();
  syncPreviewContext();
}

function fitPreview() {
  if (!pv.W || !pv.H) return;
  const availW = Math.max(40, previewPane.clientWidth - 24);
  const availH = Math.max(40, previewPane.clientHeight - 12);
  pv.k = Math.min(availW / pv.W, availH / pv.H, 1);

  previewScaler.style.width = Math.floor(pv.W * pv.k) + 'px';
  previewScaler.style.height = Math.floor(pv.H * pv.k) + 'px';
  previewStage.style.transform = 'scale(' + pv.k + ')';
  updatePreviewBox();
}

// Box center in canvas pixels (same math as CSS left:X% + translate(-X%))
function centerOf(x, y, size) {
  return {
    cx: (x / 100) * Math.max(0, pv.W - size) + size / 2,
    cy: (y / 100) * Math.max(0, pv.H - size) + size / 2
  };
}

// Mount live iframes only for the layers closest to your block; the rest stay outlines.
function syncPreviewContext() {
  if (!pv.layer) return;
  const cap = isMobile() ? PREVIEW_MOUNT_CAP_MOBILE : PREVIEW_MOUNT_CAP;
  const me = centerOf(state.x, state.y, state.size);

  const ranked = [];
  for (const entry of pv.ctx.values()) {
    const c = centerOf(entry.rec.x, entry.rec.y, entry.rec.size);
    ranked.push({ entry, d: Math.hypot(c.cx - me.cx, c.cy - me.cy) });
  }
  ranked.sort((a, b) => a.d - b.d);

  const keep = new Set(ranked.slice(0, cap).map((r) => r.entry));
  for (const entry of pv.ctx.values()) {
    const shouldMount = keep.has(entry);
    if (shouldMount && !entry.frame) {
      entry.frame = makeFrame(entry.rec.html, entry.rec.size);
      entry.box.appendChild(entry.frame);
      entry.box.classList.remove('ghost');
    } else if (!shouldMount && entry.frame) {
      entry.frame.remove();
      entry.frame = null;
      entry.box.classList.add('ghost');
    }
  }
}

function scheduleContextSync() {
  clearTimeout(contextTimer);
  contextTimer = setTimeout(syncPreviewContext, 200);
}

function updatePreviewBox() {
  if (!pv.layer || !pv.frame) return;
  const s = state.size;
  placeBox(pv.layer, state.x, state.y, s);
  const f = pv.layer.querySelector('iframe');
  if (f) { f.style.width = s + 'px'; f.style.height = s + 'px'; }

  placeBox(pv.frame, state.x, state.y, s);
  // Keep the border and label readable no matter how far the canvas is scaled down
  pv.frame.style.borderWidth = Math.max(2, 2 / pv.k) + 'px';
  pv.label.style.fontSize = Math.max(12, 12 / pv.k) + 'px';
  pv.label.textContent = s + '×' + s;
}

function updatePreviewCode(immediate) {
  if (!pv.layer) return;
  clearTimeout(previewTimer);
  const apply = () => {
    const f = pv.layer && pv.layer.querySelector('iframe');
    if (f) f.srcdoc = buildDoc(codeEl.value);
  };
  if (immediate) apply();
  else previewTimer = setTimeout(apply, 150); // don't reload the iframe on every keystroke
}

function setPosition(x, y) {
  state.x = round1(clamp(x, 0, 100));
  state.y = round1(clamp(y, 0, 100));
  posX.value = state.x;
  posY.value = state.y;
  updatePosLabels();
  updatePreviewBox();
  scheduleContextSync();
}

// Box position in canvas pixels
function boxLeftTop() {
  return {
    left: (state.x / 100) * Math.max(0, pv.W - state.size),
    top: (state.y / 100) * Math.max(0, pv.H - state.size)
  };
}

function setFromLeftTop(left, top) {
  const rangeX = pv.W - state.size;
  const rangeY = pv.H - state.size;
  setPosition(
    rangeX > 0 ? (left / rangeX) * 100 : 0,
    rangeY > 0 ? (top / rangeY) * 100 : 0
  );
}

// Drag the frame with a mouse or finger. Tapping anywhere else centers the box there.
previewScaler.addEventListener('pointerdown', (e) => {
  if (!pv.layer || tryMode.checked) return; // Click mode: let the block take the click
  e.preventDefault();

  const rect = previewScaler.getBoundingClientRect();
  const toCanvas = (ev) => ({
    px: (ev.clientX - rect.left) / pv.k,
    py: (ev.clientY - rect.top) / pv.k
  });

  const size = state.size;
  const cur = boxLeftTop();
  const start = toCanvas(e);
  let offX = start.px - cur.left;
  let offY = start.py - cur.top;
  if (offX < 0 || offY < 0 || offX > size || offY > size) {
    offX = size / 2;
    offY = size / 2;
  }
  setFromLeftTop(start.px - offX, start.py - offY);

  previewScaler.setPointerCapture(e.pointerId);

  const move = (ev) => {
    const p = toCanvas(ev);
    setFromLeftTop(p.px - offX, p.py - offY);
  };
  const up = () => {
    previewScaler.removeEventListener('pointermove', move);
    previewScaler.removeEventListener('pointerup', up);
    previewScaler.removeEventListener('pointercancel', up);
  };
  previewScaler.addEventListener('pointermove', move);
  previewScaler.addEventListener('pointerup', up);
  previewScaler.addEventListener('pointercancel', up);
});

tryMode.addEventListener('change', () => {
  previewScaler.classList.toggle('try', tryMode.checked);
});

/* ------------------------------------------------------------------
 * Opening and closing screens
 * ---------------------------------------------------------------- */

function openEditor() {
  editor.classList.remove('hidden');
  ctaBtn.classList.add('hidden');
  wallPaused = true;      // free the wall's iframes while you write
  queueReconcile();
  updateTexts();
  updatePosLabels();
  tryMode.checked = false;
  previewScaler.classList.remove('try');
  buildPreview();         // the editor must be visible first so we can measure the pane
  codeEl.focus({ preventScroll: true });
}

function closeEditor() {
  editor.classList.add('hidden');
  ctaBtn.classList.remove('hidden');
  clearTimeout(previewTimer);
  clearTimeout(contextTimer);
  previewStage.textContent = '';
  pv.ctx.clear();
  pv.layer = null;
  pv.frame = null;
  wallPaused = false;
  queueReconcile();       // bring back the iframes that are on screen
}

/* ------------------------------------------------------------------
 * Events: welcome screen, editor
 * ---------------------------------------------------------------- */

$('#exploreBtn').addEventListener('click', () => welcome.classList.add('hidden'));
$('#helpBtn').addEventListener('click', () => welcome.classList.remove('hidden'));

ctaBtn.addEventListener('click', openEditor);
$('#homeBtn').addEventListener('click', closeEditor);

codeEl.addEventListener('input', () => {
  updateCounter();
  updatePreviewCode(false);
});

posX.addEventListener('input', () => setPosition(parseFloat(posX.value), state.y));
posY.addEventListener('input', () => setPosition(state.x, parseFloat(posY.value)));

document.querySelectorAll('input[name="size"]').forEach((radio) => {
  radio.addEventListener('change', () => {
    state.size = normSize(radio.value);
    updateTexts();
    updatePreviewBox();
    scheduleContextSync();
  });
});

let resizeTimer = null;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    if (!editor.classList.contains('hidden')) fitPreview();
    queueReconcile(); // the mounted-iframe cap depends on screen size
  }, 120);
});

// Pause polling in background tabs; catch up as soon as the tab is back.
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) refresh();
});

/* ------------------------------------------------------------------
 * "Apply & continue" -> order summary
 * ---------------------------------------------------------------- */

applyBtn.addEventListener('click', () => {
  const code = codeEl.value;
  const p = plan();
  if (code.trim().length === 0) {
    showToast('Write some HTML/CSS first.');
    codeEl.focus();
    return;
  }
  if (code.length > p.max) {
    showToast('Your code is ' + code.length + ' characters, but this size allows ' + p.max + '.');
    codeEl.focus();
    return;
  }

  const half = p.price / 2;
  $('#recapPlan').textContent = p.label + ' · ' + state.size + ' × ' + state.size + ' px';
  $('#recapPrice').textContent = fmtMoney(p.price);
  $('#recapCharity').textContent = fmtMoney(half);
  $('#recapDev').textContent = fmtMoney(half);
  if (paymentMode === 'simulated') {
    payBtn.textContent = 'Continue and pay ' + fmtMoney(p.price) + ' (Test Mode)';
    recapNote.textContent = 'Your code goes through an automatic security check and content moderation before it goes live. This is test mode, so you will not be charged.';
  } else {
    payBtn.textContent = 'Continue to secure payment (' + fmtMoney(p.price) + ')';
    recapNote.textContent = RECAP_NOTE_LIVE;
  }

  checkoutError.classList.add('hidden');
  checkoutError.textContent = '';
  payBtn.disabled = false;
  checkout.classList.remove('hidden');
});

$('#backBtn').addEventListener('click', () => checkout.classList.add('hidden'));

/* ------------------------------------------------------------------
 * Server-side checks + simulated payment
 * ---------------------------------------------------------------- */

payBtn.addEventListener('click', async () => {
  payBtn.disabled = true;
  checkoutError.classList.add('hidden');

  try {
    // 1. The server runs every check (length, XSS, network, tags, moderation)
    //    and sets the price itself based on the size.
    const order = await api('/api/checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ html: codeEl.value, x: state.x, y: state.y, size: state.size })
    });

    // 2. Stripe: send the visitor to Stripe's secure payment page. The block is NOT
    //    published yet; it goes live when Stripe's webhook confirms the payment.
    //    Simulated (local dev only): call the fake "pay" route right away.
    let published = null;
    if (order.mode === 'stripe') {
      if (typeof order.url !== 'string' || !/^https:\/\/checkout\.stripe\.com\//.test(order.url)) {
        throw new Error('Unexpected response from the payment server. Please try again.');
      }
      saveDraft(); // so "Cancel" on Stripe's page brings the code back
      payBtn.textContent = 'Redirecting to secure payment…';
      window.location.href = order.url;
      return;
    } else if (order.mode === 'simulated') {
      const done = await api('/api/checkout/' + encodeURIComponent(order.orderId) + '/simulate', {
        method: 'POST'
      });
      renderStats(done.stats);
      published = done.layer;
    } else {
      throw new Error('Unexpected response from the payment server. Please try again.');
    }

    // 3. Success (simulated mode): close everything and put the new layer on the wall
    clearDraft();
    checkout.classList.add('hidden');
    codeEl.value = '';
    updateCounter();
    if (published) addLayers([published]);
    closeEditor();
    showToast('Your block is live on the canvas!');
  } catch (err) {
    checkoutError.textContent = err.message;
    checkoutError.classList.remove('hidden');
    payBtn.disabled = false;
  }
});

/* ------------------------------------------------------------------
 * Draft: keep the visitor's code safe while they're on Stripe's page
 * ---------------------------------------------------------------- */

function saveDraft() {
  try {
    localStorage.setItem(DRAFT_KEY, JSON.stringify({
      code: codeEl.value, x: state.x, y: state.y, size: state.size
    }));
  } catch (e) { /* storage blocked: the draft just won't be restored */ }
}

function loadDraft() {
  try {
    const d = JSON.parse(localStorage.getItem(DRAFT_KEY) || 'null');
    if (d && typeof d.code === 'string') return d;
  } catch (e) { /* ignore */ }
  return null;
}

function clearDraft() {
  try { localStorage.removeItem(DRAFT_KEY); } catch (e) { /* ignore */ }
}

// Back from Stripe's page via the browser's Back button: the page can come back frozen.
window.addEventListener('pageshow', (e) => {
  if (e.persisted) payBtn.disabled = false;
});

// Stripe's "cancel" link lands on /?canceled=1. Put the visitor back in their editor.
function handleCanceledReturn() {
  const params = new URLSearchParams(location.search);
  if (params.get('canceled') !== '1') return;
  history.replaceState(null, '', '/');
  welcome.classList.add('hidden');

  const d = loadDraft();
  if (!d) {
    showToast('Payment canceled. Nothing was charged.');
    return;
  }
  codeEl.value = d.code;
  state.size = normSize(d.size);
  const radio = document.querySelector('input[name="size"][value="' + state.size + '"]');
  if (radio) radio.checked = true;
  state.x = clamp(Number(d.x) || 50, 0, 100);
  state.y = clamp(Number(d.y) || 50, 0, 100);
  posX.value = state.x;
  posY.value = state.y;
  openEditor();
  showToast('Payment canceled. Your code is still here and nothing was charged.');
}

/* ------------------------------------------------------------------
 * Start up
 * ---------------------------------------------------------------- */

if (IS_CONTACT) {
  document.title = 'Contact · addadollar.com';
  welcome.classList.add('hidden');
  ctaBtn.classList.add('hidden');
  contactCard.classList.remove('hidden');
}

updateTexts();
refresh().then(() => {
  centerWallOnMobile();
  if (!IS_CONTACT) handleCanceledReturn();
});
setInterval(refresh, POLL_MS);
