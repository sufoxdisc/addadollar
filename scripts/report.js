'use strict';

/**
 * Money report: how much has been paid and how it splits between charity and development.
 * Usage:  npm run report            (reads DATA_FILE from .env)
 * It only reads the database, it never changes anything.
 */

require('dotenv').config();
const fs = require('fs');
const path = require('path');

const file = path.resolve(__dirname, '..', process.env.DATA_FILE || './data/db.json');
if (!fs.existsSync(file)) {
  console.error('No database found at ' + file);
  process.exit(1);
}

const db = JSON.parse(fs.readFileSync(file, 'utf8'));
const money = (cents) => '$' + (cents / 100).toFixed(2);

const byMode = {};
for (const p of db.payments || []) {
  const m = (byMode[p.mode] = byMode[p.mode] || { count: 0, gross: 0, charity: 0, dev: 0 });
  m.count++;
  m.gross += p.amountCents;
  m.charity += p.charityCents;
  m.dev += p.devCents;
}

console.log('addadollar.com money report');
console.log('---------------------------');
for (const [mode, m] of Object.entries(byMode)) {
  console.log(mode.toUpperCase() + ': ' + m.count + ' payment(s), gross ' + money(m.gross) +
    ' -> charity ' + money(m.charity) + ' | development ' + money(m.dev));
}
if (!Object.keys(byMode).length) console.log('No payments recorded yet.');
console.log('');
console.log('Note: "gross" is what customers paid. Stripe takes its processing fee out of your');
console.log('balance, so what you actually receive is lower. Check the Stripe Dashboard for net amounts.');

const pending = Object.keys(db.pending || {}).length;
if (pending) console.log('\nOrders waiting for payment right now: ' + pending);

if ((db.flagged || []).length) {
  console.log('\nNEEDS A HUMAN LOOK (' + db.flagged.length + '):');
  for (const f of db.flagged) console.log(' - ' + f.at + ' ' + f.reason + ' ' + JSON.stringify(f));
}
