'use strict';

/**
 * Success page. Stripe sends customers here right after they pay, but the block is only
 * published when Stripe's webhook reaches our server. That usually takes a moment, so
 * this page asks the server "is order X live yet?" every couple of seconds.
 */

const params = new URLSearchParams(location.search);
const orderId = params.get('order') || '';
const titleEl = document.getElementById('title');
const msgEl = document.getElementById('msg');
const detailEl = document.getElementById('detail');

const POLL_EVERY_MS = 2000;
const GIVE_UP_AFTER_MS = 90 * 1000;
const startedAt = Date.now();

// The payment went through, so the saved draft isn't needed anymore.
try { localStorage.removeItem('addadollar_draft'); } catch (e) { /* ignore */ }

function showLive() {
  titleEl.textContent = 'Your block is live!';
  msgEl.textContent = 'Thanks for adding to the canvas. Half of your payment goes to charity.';
  detailEl.classList.add('hidden');
}

function showSlow() {
  titleEl.textContent = 'Payment received';
  msgEl.textContent = "Stripe has your payment, but your block isn't on the canvas yet.";
  detailEl.textContent = "It will show up on its own within a minute or two. You can close this page. " +
    "If it's still missing after a while, email sufox@addadollar.com and mention order " + orderId + '.';
  detailEl.classList.remove('hidden');
}

async function check() {
  try {
    const resp = await fetch('/api/order/' + encodeURIComponent(orderId));
    const data = await resp.json();
    if (data.status === 'published') return showLive();
  } catch (e) { /* network hiccup: try again */ }

  if (Date.now() - startedAt > GIVE_UP_AFTER_MS) return showSlow();
  setTimeout(check, POLL_EVERY_MS);
}

if (!/^[0-9a-f-]{36}$/i.test(orderId)) {
  titleEl.textContent = 'Nothing to confirm';
  msgEl.textContent = "We couldn't find an order in this link.";
} else {
  check();
}
