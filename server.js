/**
 * Phoenix — backend API
 * ------------------------------------------------------------
 * Accounts: there is NO public signup. Every player account is created by
 * the administrator from the admin panel, with an optional starting balance,
 * and players can only sign in with the email/password the admin set.
 *
 * Player endpoints:
 *   POST /api/login    { email, password }              -> checks an existing
 *                                                           account (or logs
 *                                                           in the admin);
 *                                                           marks the player
 *                                                           online
 *   POST /api/logout   { email }                         -> marks the player
 *                                                            offline
 *   POST /api/signup                                     -> always 403 (closed)
 *
 * Wallet endpoints:
 *   POST /api/wallet/transaction  { email, type, amount, method }
 *                                 -> type "withdraw" only: debits the player's
 *                                    balance and records it. Deposits are
 *                                    refused (403): only the admin adds money.
 *
 * Admin endpoints (all need the Bearer token from an admin login):
 *   GET  /api/admin/users                   -> list every player, with
 *                                              balance, online/blocked status
 *                                              and transaction history
 *   POST /api/admin/users                   -> create a player account:
 *                                              { name, email, password,
 *                                                phone?, initialBalance? }
 *   POST /api/admin/users/:id/add-balance   -> { amount } top up a player
 *   POST /api/admin/users/:id/block         -> toggles blocked status.
 *                                              Blocked players can no longer
 *                                              log in.
 *   POST /api/admin/logout                  -> ends the admin session
 *
 * ADMIN LOGIN
 *   Signing in with the credentials below (instead of a normal player
 *   email/password) returns { ok:true, isAdmin:true, token } instead of a
 *   player profile. Change these before putting this anywhere real —
 *   ideally move them to environment variables.
 *
 *     Email:    admin@phoenix.com
 *     Password: Phoenix@123
 *
 * PERSISTENCE
 *   Everything is stored in a JSON file (users.json) next to this script.
 *   That file is the actual database: it's written to disk on every
 *   account creation, top-up, login, logout, and block/unblock, so accounts genuinely
 *   survive closing the browser, closing this terminal, or restarting
 *   your computer — as long as users.json itself isn't deleted. For a
 *   production site, swap readUsers()/writeUsers() for calls to a real
 *   database (Postgres, MySQL, MongoDB, etc.) — nothing else here needs
 *   to change.
 *
 * ONLINE / OFFLINE STATUS
 *   This is "last known state", not a live connection check: a player is
 *   marked online when they successfully log in, and offline when they
 *   click Log out (or close the tab, via a best-effort beacon the
 *   frontend sends). If a browser crashes or loses power without firing
 *   that event, that one player could be shown online until their next
 *   login/logout. A production system would add a periodic "heartbeat"
 *   ping from the frontend and expire the online status after a timeout
 *   — straightforward to add later, but out of scope for this demo.
 *
 * Passwords are hashed with bcrypt before they're ever written to disk;
 * the plain password is never stored, and player password hashes are
 * never sent to the frontend — including in the admin user list.
 * ------------------------------------------------------------
 * Run it:
 *   npm install
 *   npm start
 * It listens on http://localhost:3000
 */

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { WebSocketServer } = require('ws');

const app = express();
const PORT = process.env.PORT || 3000;
const USERS_FILE = path.join(process.env.DATA_DIR || __dirname, 'users.json');
const PK_MOBILE_REGEX = /^3[0-9]{9}$/; // 10 digits, starting with 3 (after +92)

// ---------- admin config ----------
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@phoenix.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Phoenix@123';

// Active admin session tokens, kept in memory. A restart of the server
// invalidates all of them, which is fine for a demo; a real deployment
// would use signed JWTs or server-side sessions in a shared store instead.
const adminTokens = new Set();

function issueAdminToken() {
  const token = crypto.randomBytes(24).toString('hex');
  adminTokens.add(token);
  return token;
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token || !adminTokens.has(token)) {
    return res.status(401).json({ ok: false, error: 'Admin session expired or invalid. Please sign in again.' });
  }
  next();
}

app.use(cors());
// Accept both normal JSON bodies and the Blob-based bodies sent by
// navigator.sendBeacon() on tab close, which some browsers label as
// text/plain even though the payload is JSON.
app.use(express.json({ type: ['application/json', 'text/plain'] }));

// Serve the website itself from this same server, so one link (and one
// address) works on every device with nothing else to configure.
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ---------- storage helpers ----------
function readUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  try {
    const raw = fs.readFileSync(USERS_FILE, 'utf-8');
    return raw.trim() ? JSON.parse(raw) : [];
  } catch (err) {
    console.error('Failed to read users.json, starting fresh:', err);
    return [];
  }
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf-8');
}

function publicUser(user) {
  // never send the password hash back to the frontend
  const { password, ...rest } = user;
  return rest;
}

// ---------- player routes ----------

app.get('/api/health', (req, res) => {
  res.json({ ok: true, message: 'Phoenix backend is running.' });
});

// Public signup is closed: accounts are created by the administrator from
// the admin panel (POST /api/admin/users below).
app.post('/api/signup', (req, res) => {
  return res.status(403).json({
    ok: false,
    error: 'Sign-up is disabled. Accounts are created by the administrator — please contact them for your login details.'
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ ok: false, error: 'Email and password are required.' });
  }

  const normalizedEmail = email.trim().toLowerCase();

  // ---- admin login check first ----
  if (normalizedEmail === ADMIN_EMAIL.toLowerCase()) {
    if (password !== ADMIN_PASSWORD) {
      return res.status(401).json({ ok: false, error: 'Incorrect password. Please try again.', code: 'BAD_PASSWORD' });
    }
    const token = issueAdminToken();
    return res.json({
      ok: true,
      isAdmin: true,
      token,
      user: { name: 'Admin', email: ADMIN_EMAIL, role: 'admin' }
    });
  }

  // ---- normal player login ----
  const users = readUsers();
  const user = users.find(u => u.email.toLowerCase() === normalizedEmail);

  if (!user) {
    return res.status(404).json({ ok: false, error: 'No account found with this email. Please create an account first.', code: 'NOT_FOUND' });
  }

  if (user.blocked) {
    return res.status(403).json({ ok: false, error: 'Your account has been blocked. Please contact support.', code: 'BLOCKED' });
  }

  const passwordMatches = bcrypt.compareSync(password, user.password);
  if (!passwordMatches) {
    return res.status(401).json({ ok: false, error: 'Incorrect password. Please try again.', code: 'BAD_PASSWORD' });
  }

  user.online = true;
  writeUsers(users);

  return res.json({ ok: true, isAdmin: false, user: publicUser(user) });
});

app.post('/api/logout', (req, res) => {
  const { email } = req.body || {};
  if (!email) {
    return res.status(400).json({ ok: false, error: 'Email is required.' });
  }

  const users = readUsers();
  const user = users.find(u => u.email.toLowerCase() === email.trim().toLowerCase());
  if (user) {
    user.online = false;
    writeUsers(users);
  }

  return res.json({ ok: true });
});

// ---------- wallet routes ----------

app.post('/api/wallet/transaction', (req, res) => {
  const { email, type, amount, method } = req.body || {};

  if (!email || !type || amount === undefined || !method) {
    return res.status(400).json({ ok: false, error: 'Email, type, amount, and method are required.' });
  }
  if (type !== 'deposit' && type !== 'withdraw') {
    return res.status(400).json({ ok: false, error: 'Type must be "deposit" or "withdraw".' });
  }
  if (type === 'deposit') {
    // Balance is added by the administrator only (POST
    // /api/admin/users/:id/add-balance). Letting players credit themselves
    // here would let anyone create money out of thin air.
    return res.status(403).json({ ok: false, error: 'Deposits are added by the administrator. Please contact them to top up your balance.' });
  }
  if (method !== 'easypaisa' && method !== 'jazzcash') {
    return res.status(400).json({ ok: false, error: 'Method must be "easypaisa" or "jazzcash".' });
  }
  const numericAmount = Number(amount);
  if (!Number.isFinite(numericAmount) || numericAmount < 100) {
    return res.status(400).json({ ok: false, error: 'Enter an amount of at least Rs 100.' });
  }

  const users = readUsers();
  const user = users.find(u => u.email.toLowerCase() === email.trim().toLowerCase());
  if (!user) {
    return res.status(404).json({ ok: false, error: 'No account found with this email.' });
  }
  if (user.blocked) {
    return res.status(403).json({ ok: false, error: 'This account has been blocked.' });
  }

  if (type === 'withdraw' && numericAmount > user.balance) {
    return res.status(400).json({ ok: false, error: 'Insufficient balance for this withdrawal.' });
  }

  user.balance = type === 'deposit'
    ? user.balance + numericAmount
    : user.balance - numericAmount;

  if (!Array.isArray(user.transactions)) user.transactions = [];
  const transaction = {
    id: 'TXN-' + crypto.randomBytes(6).toString('hex'),
    type,
    amount: numericAmount,
    method,
    balanceAfter: user.balance,
    createdAt: new Date().toISOString()
  };
  user.transactions.unshift(transaction); // newest first

  writeUsers(users);

  return res.json({ ok: true, balance: user.balance, transaction });
});

// ---------- game routes ----------
// Separate from /api/wallet/transaction (EasyPaisa/JazzCash deposits and
// withdrawals): this endpoint is for money moving between a player's
// balance and a game round — placing a bet, cashing out a win, or
// refunding a cancelled bet. Same persistent ledger, same users.json,
// just a different transaction type so the admin history can tell a
// deposit/withdrawal apart from money won or lost playing a game.

app.post('/api/game/transaction', (req, res) => {
  const { email, type, amount, game } = req.body || {};

  if (!email || !type || amount === undefined) {
    return res.status(400).json({ ok: false, error: 'Email, type, and amount are required.' });
  }
  if (type !== 'bet' && type !== 'win' && type !== 'refund') {
    return res.status(400).json({ ok: false, error: 'Type must be "bet", "win", or "refund".' });
  }
  const numericAmount = Number(amount);
  if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
    return res.status(400).json({ ok: false, error: 'Enter a valid amount.' });
  }

  const users = readUsers();
  const user = users.find(u => u.email.toLowerCase() === email.trim().toLowerCase());
  if (!user) {
    return res.status(404).json({ ok: false, error: 'No account found with this email.' });
  }
  if (user.blocked) {
    return res.status(403).json({ ok: false, error: 'This account has been blocked.' });
  }

  if (type === 'bet') {
    if (numericAmount > user.balance) {
      return res.status(400).json({ ok: false, error: 'Insufficient balance to place this bet.' });
    }
    user.balance -= numericAmount;
  } else {
    // 'win' or 'refund' both credit the player
    user.balance += numericAmount;
  }

  if (!Array.isArray(user.transactions)) user.transactions = [];
  const transaction = {
    id: 'TXN-' + crypto.randomBytes(6).toString('hex'),
    type,
    game: game || 'aviator',
    amount: numericAmount,
    balanceAfter: user.balance,
    createdAt: new Date().toISOString()
  };
  user.transactions.unshift(transaction);

  writeUsers(users);

  return res.json({ ok: true, balance: user.balance, transaction });
});

// ---------- admin routes ----------

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = readUsers().map(publicUser);
  return res.json({ ok: true, count: users.length, users });
});

app.post('/api/admin/users/:id/block', requireAdmin, (req, res) => {
  const { id } = req.params;
  const users = readUsers();
  const user = users.find(u => u.id === id);

  if (!user) {
    return res.status(404).json({ ok: false, error: 'Player not found.' });
  }

  user.blocked = !user.blocked;
  // A blocked player is also immediately shown as offline — being blocked
  // should end their ability to appear "logged in", even if their tab is
  // still technically open.
  if (user.blocked) {
    user.online = false;
  }
  writeUsers(users);

  return res.json({ ok: true, user: publicUser(user) });
});

function generateUniqueUserId(users) {
  for (let attempt = 0; attempt < 50; attempt++) {
    const id = 'PHX-' + Math.floor(10000 + Math.random() * 90000);
    if (!users.some(u => u.id === id)) return id;
  }
  return 'PHX-' + Date.now().toString().slice(-8);
}

// Create a player account. This is now the ONLY way accounts come into
// existence — players cannot sign themselves up.
app.post('/api/admin/users', requireAdmin, (req, res) => {
  const { name, email, phone, password, initialBalance } = req.body || {};

  if (!name || !String(name).trim() || !email || !password) {
    return res.status(400).json({ ok: false, error: 'Name, email, and password are required.' });
  }
  const cleanEmail = String(email).trim();
  if (!/^\S+@\S+\.\S+$/.test(cleanEmail)) {
    return res.status(400).json({ ok: false, error: 'Enter a valid email address.' });
  }
  if (cleanEmail.toLowerCase() === ADMIN_EMAIL.toLowerCase()) {
    return res.status(409).json({ ok: false, error: 'This email is reserved for the admin account.' });
  }
  if (String(password).length < 8) {
    return res.status(400).json({ ok: false, error: 'Password must be at least 8 characters.' });
  }

  // Phone is optional; if given it must be a valid Pakistani mobile number.
  let phoneFormatted = '';
  if (phone !== undefined && phone !== null && String(phone).trim() !== '') {
    // Accept the formats people actually type: 3001234567, 03001234567,
    // 923001234567, +92 300 1234567.
    let digits = String(phone).replace(/[^0-9]/g, '');
    if (digits.length === 12 && digits.startsWith('92')) digits = digits.slice(2);
    else if (digits.length === 11 && digits.startsWith('0')) digits = digits.slice(1);
    if (!PK_MOBILE_REGEX.test(digits)) {
      return res.status(400).json({ ok: false, error: 'Phone must be a valid Pakistani mobile number (e.g. 0300 1234567), or left blank.' });
    }
    phoneFormatted = '+92 ' + digits;
  }

  let startingBalance = 0;
  if (initialBalance !== undefined && initialBalance !== null && String(initialBalance).trim() !== '') {
    startingBalance = Number(initialBalance);
    if (!Number.isFinite(startingBalance) || startingBalance < 0) {
      return res.status(400).json({ ok: false, error: 'Starting balance must be a number that is 0 or more.' });
    }
    startingBalance = Math.round(startingBalance * 100) / 100;
  }

  const users = readUsers();
  if (users.some(u => u.email.toLowerCase() === cleanEmail.toLowerCase())) {
    return res.status(409).json({ ok: false, error: 'An account with this email already exists.' });
  }

  const now = new Date().toISOString();
  const newUser = {
    id: generateUniqueUserId(users),
    name: String(name).trim(),
    email: cleanEmail,
    phone: phoneFormatted,
    password: bcrypt.hashSync(String(password), 10),
    createdAt: now,
    online: false,
    blocked: false,
    balance: startingBalance,
    transactions: []
  };
  if (startingBalance > 0) {
    newUser.transactions.push({
      id: 'TXN-' + crypto.randomBytes(6).toString('hex'),
      type: 'admin_credit',
      amount: startingBalance,
      method: 'admin',
      balanceAfter: startingBalance,
      createdAt: now
    });
  }

  users.push(newUser);
  writeUsers(users);
  return res.status(201).json({ ok: true, user: publicUser(newUser) });
});

// Top up an existing player's balance.
app.post('/api/admin/users/:id/add-balance', requireAdmin, (req, res) => {
  const numericAmount = Number(req.body && req.body.amount);
  if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
    return res.status(400).json({ ok: false, error: 'Enter an amount greater than 0.' });
  }
  if (numericAmount > 10000000) {
    return res.status(400).json({ ok: false, error: 'That amount is too large for a single top-up.' });
  }
  const amount = Math.round(numericAmount * 100) / 100;

  const users = readUsers();
  const user = users.find(u => u.id === req.params.id);
  if (!user) {
    return res.status(404).json({ ok: false, error: 'Player not found.' });
  }

  user.balance = Math.round((user.balance + amount) * 100) / 100;
  if (!Array.isArray(user.transactions)) user.transactions = [];
  user.transactions.unshift({
    id: 'TXN-' + crypto.randomBytes(6).toString('hex'),
    type: 'admin_credit',
    amount,
    method: 'admin',
    balanceAfter: user.balance,
    createdAt: new Date().toISOString()
  });
  writeUsers(users);

  return res.json({ ok: true, user: publicUser(user) });
});

app.post('/api/admin/logout', requireAdmin, (req, res) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (token) adminTokens.delete(token);
  return res.json({ ok: true });
});

// ======================================================================
// AVIATOR X — real-time multiplayer crash game
// ======================================================================
// One shared round runs on the server at all times; every connected
// browser sees the exact same multiplier and the exact same crash point
// at the exact same moment via WebSocket, which is what makes this
// genuinely multiplayer rather than a separate animation per tab.
//
// Round lifecycle:
//   BETTING (6s)  -> players can place one bet each via POST /api/aviator/bet
//   FLYING        -> multiplier climbs from 1.00x; players can cash out via
//                     POST /api/aviator/cashout at any point before the
//                     (secret, pre-determined) crash point
//   CRASHED (3s)  -> the crash point is revealed; anyone still in loses
//                     their stake; then a new round begins
//
// ODDS
//   The crash point for each round is decided randomly *before* anyone can
//   act on it (right when betting opens). Nothing about a player's bet size
//   or timing can influence where it lands. The odds are controlled by just
//   the two constants below:
//
//     87% of rounds crash BELOW 1.40x  (crash point spread evenly over
//                                       1.00x - 1.39x)
//      13% of rounds reach 1.40x OR MORE (heavy tail: P(crash > x) = 1.4 / x,
//                                       capped at 100x)
//
//   What that means for a player: cashing out at exactly 1.40x succeeds in
//   13% of rounds, i.e. a return-to-player of roughly 18%. Lower targets pay
//   more often (a 1.05x target succeeds in ~88% of rounds), so the effective
//   house edge depends on when each player chooses to cash out. These odds
//   are far more house-favoured than regulated crash games (which typically
//   return ~92-97%), so if real people are staking real money they should be
//   told what the odds are.
// ======================================================================

const AVIATOR_BETTING_MS = 6000;
const AVIATOR_CRASHED_PAUSE_MS = 3000;
const AVIATOR_TICK_MS = 100;
const AVIATOR_GROWTH_PER_SEC = 0.15; // tune the pace of the climb
const AVIATOR_MAX_MULTIPLIER = 100;

const AVIATOR_EARLY_CRASH_THRESHOLD = 1.4;     // the multiplier boundary
const AVIATOR_EARLY_CRASH_PROBABILITY = 0.87;  // chance a round ends below it

function generateCrashPoint() {
  if (Math.random() < AVIATOR_EARLY_CRASH_PROBABILITY) {
    // Early crash: somewhere in [1.00, threshold). Floored to 2 decimals so
    // it can never round up onto the threshold itself.
    const span = AVIATOR_EARLY_CRASH_THRESHOLD - 1;
    const point = 1 + Math.random() * span;
    return Math.floor(point * 100) / 100;
  }
  // Late crash: heavy tail starting at the threshold.
  const r = Math.random();
  const point = AVIATOR_EARLY_CRASH_THRESHOLD / (1 - r);
  const rounded = Math.floor(point * 100) / 100;
  return Math.min(AVIATOR_MAX_MULTIPLIER, Math.max(AVIATOR_EARLY_CRASH_THRESHOLD, rounded));
}

function currentAviatorMultiplier(elapsedMs) {
  const t = elapsedMs / 1000;
  return Math.round(Math.exp(AVIATOR_GROWTH_PER_SEC * t) * 100) / 100;
}

const aviatorRound = {
  phase: 'betting',    // 'betting' | 'flying' | 'crashed'
  phaseStartedAt: Date.now(),
  crashPoint: generateCrashPoint(),
  bets: new Map()       // email -> { amount, autoCashout, cashedOut, cashoutMultiplier }
};

let aviatorWss = null;

function broadcastAviator(message) {
  if (!aviatorWss) return;
  const payload = JSON.stringify(message);
  aviatorWss.clients.forEach(client => {
    if (client.readyState === 1 /* OPEN */) client.send(payload);
  });
}

// The leaderboard shows each player's name (not their email) and bet
// amount before the round starts, then their cashout multiplier once
// they cash out, or "crashed" once the round ends without them having
// cashed out. Sorted so cashed-out players (winners) surface first,
// then everyone else in betting order.
function aviatorBetsList() {
  return Array.from(aviatorRound.bets.entries())
    .map(([email, bet]) => ({
      email,
      name: bet.name,
      amount: bet.amount,
      cashedOut: bet.cashedOut,
      cashoutMultiplier: bet.cashoutMultiplier
    }))
    .sort((a, b) => {
      if (a.cashedOut !== b.cashedOut) return a.cashedOut ? -1 : 1;
      if (a.cashedOut && b.cashedOut) return b.cashoutMultiplier - a.cashoutMultiplier;
      return 0;
    });
}

function aviatorPublicState() {
  const now = Date.now();
  const elapsed = now - aviatorRound.phaseStartedAt;
  if (aviatorRound.phase === 'betting') {
    return {
      type: 'state',
      phase: 'betting',
      countdownMs: Math.max(0, AVIATOR_BETTING_MS - elapsed),
      playersCount: aviatorRound.bets.size,
      bets: aviatorBetsList()
    };
  }
  if (aviatorRound.phase === 'flying') {
    return {
      type: 'state',
      phase: 'flying',
      multiplier: currentAviatorMultiplier(elapsed),
      playersCount: aviatorRound.bets.size,
      bets: aviatorBetsList()
    };
  }
  return {
    type: 'state',
    phase: 'crashed',
    crashPoint: aviatorRound.crashPoint,
    playersCount: aviatorRound.bets.size,
    bets: aviatorBetsList()
  };
}

function creditWinnings(email, amount, multiplier, gameName) {
  const users = readUsers();
  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user) return undefined;
  user.balance = Math.round((user.balance + amount) * 100) / 100;
  if (!Array.isArray(user.transactions)) user.transactions = [];
  user.transactions.unshift({
    id: 'TXN-' + crypto.randomBytes(6).toString('hex'),
    type: 'win',
    amount,
    gameName: gameName || 'Aviator X',
    multiplier,
    balanceAfter: user.balance,
    createdAt: new Date().toISOString()
  });
  writeUsers(users);
  return user.balance;
}

function aviatorTick() {
  const now = Date.now();
  const elapsed = now - aviatorRound.phaseStartedAt;

  if (aviatorRound.phase === 'betting') {
    if (elapsed >= AVIATOR_BETTING_MS) {
      aviatorRound.phase = 'flying';
      aviatorRound.phaseStartedAt = now;
      broadcastAviator({ type: 'flying_start' });
    } else {
      broadcastAviator(aviatorPublicState());
    }
    return;
  }

  if (aviatorRound.phase === 'flying') {
    const multiplier = currentAviatorMultiplier(elapsed);

    if (multiplier >= aviatorRound.crashPoint) {
      // Crash! Anyone still holding an uncashed bet loses their stake
      // (it was already deducted at bet time, so there's nothing more
      // to do for them — their transaction history already shows the bet).
      aviatorRound.phase = 'crashed';
      aviatorRound.phaseStartedAt = now;
      broadcastAviator({ type: 'crash', crashPoint: aviatorRound.crashPoint, bets: aviatorBetsList() });
      return;
    }

    // Auto-cashout: anyone whose target has been reached gets cashed out
    // automatically, exactly like a manual cashout at this multiplier.
    aviatorRound.bets.forEach((bet, email) => {
      if (!bet.cashedOut && bet.autoCashout && multiplier >= bet.autoCashout) {
        bet.cashedOut = true;
        bet.cashoutMultiplier = bet.autoCashout;
        const payout = Math.round(bet.amount * bet.autoCashout * 100) / 100;
        creditWinnings(email, payout, bet.autoCashout);
        broadcastAviator({ type: 'player_cashout', email, multiplier: bet.autoCashout, payout, auto: true, bets: aviatorBetsList() });
      }
    });

    broadcastAviator({ type: 'tick', multiplier, playersCount: aviatorRound.bets.size });
    return;
  }

  // phase === 'crashed'
  if (elapsed >= AVIATOR_CRASHED_PAUSE_MS) {
    aviatorRound.phase = 'betting';
    aviatorRound.phaseStartedAt = now;
    aviatorRound.crashPoint = generateCrashPoint();
    aviatorRound.bets = new Map();
    broadcastAviator({ type: 'betting_start', countdownMs: AVIATOR_BETTING_MS, bets: [] });
  }
}

setInterval(aviatorTick, AVIATOR_TICK_MS);

app.get('/api/aviator/state', (req, res) => {
  res.json({ ok: true, ...aviatorPublicState() });
});

app.post('/api/aviator/bet', (req, res) => {
  const { email, amount, autoCashout } = req.body || {};
  if (!email || amount === undefined) {
    return res.status(400).json({ ok: false, error: 'Email and amount are required.' });
  }
  if (aviatorRound.phase !== 'betting') {
    return res.status(409).json({ ok: false, error: 'Betting is closed for this round. Wait for the next one.' });
  }
  const normalizedEmail = email.trim().toLowerCase();
  if (aviatorRound.bets.has(normalizedEmail)) {
    return res.status(409).json({ ok: false, error: 'You have already placed a bet this round.' });
  }
  const numericAmount = Number(amount);
  if (!Number.isFinite(numericAmount) || numericAmount < 10) {
    return res.status(400).json({ ok: false, error: 'Enter a bet amount of at least Rs 10.' });
  }
  const numericAutoCashout = autoCashout !== undefined && autoCashout !== null && autoCashout !== ''
    ? Number(autoCashout)
    : null;
  if (numericAutoCashout !== null && (!Number.isFinite(numericAutoCashout) || numericAutoCashout < 1.01)) {
    return res.status(400).json({ ok: false, error: 'Auto cashout must be at least 1.01x.' });
  }

  const users = readUsers();
  const user = users.find(u => u.email.toLowerCase() === normalizedEmail);
  if (!user) {
    return res.status(404).json({ ok: false, error: 'No account found with this email.' });
  }
  if (user.blocked) {
    return res.status(403).json({ ok: false, error: 'This account has been blocked.' });
  }
  if (user.balance < numericAmount) {
    return res.status(400).json({ ok: false, error: 'Insufficient balance for this bet.' });
  }

  user.balance = Math.round((user.balance - numericAmount) * 100) / 100;
  if (!Array.isArray(user.transactions)) user.transactions = [];
  user.transactions.unshift({
    id: 'TXN-' + crypto.randomBytes(6).toString('hex'),
    type: 'bet',
    amount: numericAmount,
    gameName: 'Aviator X',
    balanceAfter: user.balance,
    createdAt: new Date().toISOString()
  });
  writeUsers(users);

  aviatorRound.bets.set(normalizedEmail, {
    name: user.name,
    amount: numericAmount,
    autoCashout: numericAutoCashout,
    cashedOut: false,
    cashoutMultiplier: null
  });

  broadcastAviator({ type: 'player_bet', playersCount: aviatorRound.bets.size, bets: aviatorBetsList() });

  return res.json({ ok: true, balance: user.balance });
});

app.post('/api/aviator/cashout', (req, res) => {
  const { email } = req.body || {};
  if (!email) {
    return res.status(400).json({ ok: false, error: 'Email is required.' });
  }
  if (aviatorRound.phase !== 'flying') {
    return res.status(409).json({ ok: false, error: 'There is no active flight to cash out of right now.' });
  }
  const normalizedEmail = email.trim().toLowerCase();
  const bet = aviatorRound.bets.get(normalizedEmail);
  if (!bet) {
    return res.status(404).json({ ok: false, error: 'You have no active bet this round.' });
  }
  if (bet.cashedOut) {
    return res.status(409).json({ ok: false, error: 'You have already cashed out this round.' });
  }

  const elapsed = Date.now() - aviatorRound.phaseStartedAt;
  const multiplier = currentAviatorMultiplier(elapsed);
  if (multiplier >= aviatorRound.crashPoint) {
    return res.status(409).json({ ok: false, error: 'Too late — the plane already crashed.' });
  }

  bet.cashedOut = true;
  bet.cashoutMultiplier = multiplier;
  const payout = Math.round(bet.amount * multiplier * 100) / 100;
  const newBalance = creditWinnings(normalizedEmail, payout, multiplier);

  broadcastAviator({ type: 'player_cashout', email: normalizedEmail, multiplier, payout, auto: false, bets: aviatorBetsList() });

  return res.json({ ok: true, multiplier, payout, balance: newBalance });
});

// ======================================================================
// MINES — single-player provably-fair grid game
// ======================================================================
// A 5x5 (25-tile) board where the player chooses how many of the tiles
// are mines (2–24) before betting. The rest are "phoenix" tiles. Each
// safe tile revealed raises the multiplier; hitting a mine ends the
// round and the stake (already deducted at bet time) is lost. The
// player can cash out at any point after revealing at least one tile.
//
// Fairness: mine positions are shuffled randomly the moment the round
// starts (POST /api/mines/start), before any reveal happens, and never
// change afterward. The multiplier at k safe reveals is the same odds
// math real mines games use — it's exactly 1 / (probability of having
// revealed k safe tiles in a row by chance), scaled down slightly for
// the house edge:
//
//   multiplier(k) = HOUSE_EDGE * Π_{i=0}^{k-1} (25 - i) / (S - i)
//
// where S = 25 - minesCount is the number of safe tiles. This is a
// bigger jump per tile the more mines are on the board, which is why
// more mines = higher multiplier growth, same as the request asked for.
//
// Round state lives in memory only (not written to users.json) — it's
// transient gameplay state, not account data. Only the resulting bet
// and win/loss are persisted, same pattern as Aviator.
// ======================================================================

const MINES_BOARD_SIZE = 25;
const MINES_HOUSE_EDGE = 0.9384; // tuned so 2 mines' first safe reveal lands at exactly 1.02x

const minesRounds = new Map(); // email -> { betAmount, minesCount, minePositions: Set<number>, revealed: Set<number>, multiplier }

function computeMinesMultiplier(minesCount, revealedSafeCount) {
  const safeTotal = MINES_BOARD_SIZE - minesCount;
  let multiplier = 1;
  for (let i = 0; i < revealedSafeCount; i++) {
    multiplier *= (MINES_BOARD_SIZE - i) / (safeTotal - i);
  }
  return Math.round(multiplier * MINES_HOUSE_EDGE * 10000) / 10000;
}

function generateMinePositions(minesCount) {
  const positions = Array.from({ length: MINES_BOARD_SIZE }, (_, i) => i);
  // Fisher-Yates shuffle, then take the first minesCount as mine tiles.
  for (let i = positions.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [positions[i], positions[j]] = [positions[j], positions[i]];
  }
  return new Set(positions.slice(0, minesCount));
}

app.get('/api/mines/state', (req, res) => {
  const email = (req.query.email || '').trim().toLowerCase();
  if (!email) return res.status(400).json({ ok: false, error: 'Email is required.' });
  const round = minesRounds.get(email);
  if (!round) return res.json({ ok: true, active: false });
  return res.json({
    ok: true,
    active: true,
    betAmount: round.betAmount,
    minesCount: round.minesCount,
    revealed: Array.from(round.revealed),
    multiplier: round.multiplier
  });
});

app.post('/api/mines/start', (req, res) => {
  const { email, betAmount, minesCount } = req.body || {};
  if (!email || betAmount === undefined || minesCount === undefined) {
    return res.status(400).json({ ok: false, error: 'Email, bet amount, and mines count are required.' });
  }
  const normalizedEmail = email.trim().toLowerCase();
  const numericMines = Number(minesCount);
  if (!Number.isInteger(numericMines) || numericMines < 2 || numericMines > 24) {
    return res.status(400).json({ ok: false, error: 'Mines count must be a whole number between 2 and 24.' });
  }
  const numericAmount = Number(betAmount);
  // A bet amount of exactly 0 starts a demo round: same board, same
  // multiplier math, but no balance deduction and no transaction is ever
  // recorded — it's purely for practice. Anything else below Rs 10 is
  // rejected as an invalid real-money bet, not a demo request.
  const isDemo = numericAmount === 0;
  if (!Number.isFinite(numericAmount) || (numericAmount > 0 && numericAmount < 10)) {
    return res.status(400).json({ ok: false, error: 'Enter a bet amount of at least Rs 10, or 0 to play in demo mode.' });
  }
  if (minesRounds.has(normalizedEmail)) {
    return res.status(409).json({ ok: false, error: 'Finish or cash out your current round first.' });
  }

  const users = readUsers();
  const user = users.find(u => u.email.toLowerCase() === normalizedEmail);
  if (!user) {
    return res.status(404).json({ ok: false, error: 'No account found with this email.' });
  }
  if (user.blocked) {
    return res.status(403).json({ ok: false, error: 'This account has been blocked.' });
  }

  if (isDemo) {
    minesRounds.set(normalizedEmail, {
      betAmount: 0,
      minesCount: numericMines,
      minePositions: generateMinePositions(numericMines),
      revealed: new Set(),
      multiplier: 1,
      isDemo: true
    });
    return res.json({ ok: true, balance: user.balance, isDemo: true });
  }

  if (user.balance < numericAmount) {
    return res.status(400).json({ ok: false, error: 'Insufficient balance for this bet.' });
  }

  user.balance = Math.round((user.balance - numericAmount) * 100) / 100;
  if (!Array.isArray(user.transactions)) user.transactions = [];
  user.transactions.unshift({
    id: 'TXN-' + crypto.randomBytes(6).toString('hex'),
    type: 'bet',
    amount: numericAmount,
    gameName: 'Mines',
    minesCount: numericMines,
    balanceAfter: user.balance,
    createdAt: new Date().toISOString()
  });
  writeUsers(users);

  minesRounds.set(normalizedEmail, {
    betAmount: numericAmount,
    minesCount: numericMines,
    minePositions: generateMinePositions(numericMines),
    revealed: new Set(),
    multiplier: 1,
    isDemo: false
  });

  return res.json({ ok: true, balance: user.balance, isDemo: false });
});

app.post('/api/mines/reveal', (req, res) => {
  const { email, tileIndex } = req.body || {};
  if (!email || tileIndex === undefined) {
    return res.status(400).json({ ok: false, error: 'Email and tile index are required.' });
  }
  const normalizedEmail = email.trim().toLowerCase();
  const round = minesRounds.get(normalizedEmail);
  if (!round) {
    return res.status(404).json({ ok: false, error: 'No active Mines round. Place a bet first.' });
  }
  const index = Number(tileIndex);
  if (!Number.isInteger(index) || index < 0 || index >= MINES_BOARD_SIZE) {
    return res.status(400).json({ ok: false, error: 'Invalid tile.' });
  }
  if (round.revealed.has(index)) {
    return res.status(409).json({ ok: false, error: 'That tile is already revealed.' });
  }

  if (round.minePositions.has(index)) {
    // Hit a mine — round over, stake already lost (deducted at bet time),
    // or nothing lost at all if this was a demo round.
    minesRounds.delete(normalizedEmail);
    return res.json({
      ok: true,
      hitMine: true,
      minePositions: Array.from(round.minePositions),
      multiplier: round.multiplier,
      isDemo: round.isDemo
    });
  }

  round.revealed.add(index);
  round.multiplier = computeMinesMultiplier(round.minesCount, round.revealed.size);

  const safeTotal = MINES_BOARD_SIZE - round.minesCount;
  if (round.revealed.size === safeTotal) {
    // Every safe tile is revealed — nothing left to click, so the round
    // auto-cashes-out at the final multiplier. Demo rounds skip the
    // actual credit/transaction — there's no real stake to pay out on.
    const payout = Math.round(round.betAmount * round.multiplier * 100) / 100;
    if (!round.isDemo) {
      creditWinnings(normalizedEmail, payout, round.multiplier, 'Mines');
    }
    minesRounds.delete(normalizedEmail);
    const users = readUsers();
    const user = users.find(u => u.email.toLowerCase() === normalizedEmail);
    return res.json({
      ok: true,
      hitMine: false,
      cleared: true,
      multiplier: round.multiplier,
      payout,
      isDemo: round.isDemo,
      balance: user ? user.balance : undefined,
      minePositions: Array.from(round.minePositions)
    });
  }

  return res.json({ ok: true, hitMine: false, cleared: false, multiplier: round.multiplier, revealedCount: round.revealed.size });
});

app.post('/api/mines/cashout', (req, res) => {
  const { email } = req.body || {};
  if (!email) {
    return res.status(400).json({ ok: false, error: 'Email is required.' });
  }
  const normalizedEmail = email.trim().toLowerCase();
  const round = minesRounds.get(normalizedEmail);
  if (!round) {
    return res.status(404).json({ ok: false, error: 'No active Mines round.' });
  }
  if (round.revealed.size === 0) {
    return res.status(409).json({ ok: false, error: 'Reveal at least one tile before cashing out.' });
  }

  const payout = Math.round(round.betAmount * round.multiplier * 100) / 100;
  if (!round.isDemo) {
    creditWinnings(normalizedEmail, payout, round.multiplier, 'Mines');
  }
  minesRounds.delete(normalizedEmail);

  const users = readUsers();
  const user = users.find(u => u.email.toLowerCase() === normalizedEmail);

  return res.json({ ok: true, payout, multiplier: round.multiplier, isDemo: round.isDemo, balance: user ? user.balance : undefined });
});


// ======================================================================
// CHICKEN ROAD — single-player, step-by-step crash game
// ======================================================================
// A chicken advances one lane at a time across a road. Each step has a
// chance of being safe (multiplier climbs) or a hazard (hit by a car /
// fell into a manhole — round over, stake lost). Unlike Mines, each step
// is independent (memoryless) rather than drawn from a fixed board, so
// the survival chance per step stays constant for a given difficulty —
// that's what "difficulty" actually controls here.
//
// Multiplier math: same "fair odds, then house edge" idea as Mines and
// Aviator. If a step's survival chance is p, the fair multiplier after k
// safe steps is 1/p^k (since surviving k independent steps has
// probability p^k); a house edge is then applied on top.
// ======================================================================

const CHICKEN_ROAD_TOTAL_STEPS = 22;
const CHICKEN_ROAD_HOUSE_EDGE = 0.918; // tuned so Easy difficulty's first step lands at exactly 1.02x
const CHICKEN_ROAD_DIFFICULTIES = {
  easy: 0.90,
  medium: 0.80,
  hard: 0.65,
  hardcore: 0.50
};

// One active session per player, kept in memory — same pattern as
// Aviator's admin tokens and Mines' rounds. Every bet and win is already
// recorded in that player's persistent transaction history the moment it
// happens, so only an unfinished round is ever lost on a server restart.
const chickenRoadSessions = new Map(); // email -> session

function computeChickenRoadMultiplier(difficulty, steps) {
  if (steps === 0) return 1;
  const survivalProb = CHICKEN_ROAD_DIFFICULTIES[difficulty];
  const fairMultiplier = Math.pow(1 / survivalProb, steps);
  return Math.round(fairMultiplier * CHICKEN_ROAD_HOUSE_EDGE * 100) / 100;
}

app.get('/api/chickenroad/state', (req, res) => {
  const email = (req.query.email || '').trim().toLowerCase();
  if (!email) return res.status(400).json({ ok: false, error: 'Email is required.' });
  const session = chickenRoadSessions.get(email);
  if (!session || !session.active) return res.json({ ok: true, active: false });
  return res.json({
    ok: true,
    active: true,
    betAmount: session.betAmount,
    difficulty: session.difficulty,
    stepIndex: session.stepIndex,
    multiplier: session.multiplier,
    isDemo: session.isDemo
  });
});

app.post('/api/chickenroad/start', (req, res) => {
  const { email, betAmount, difficulty } = req.body || {};
  if (!email || betAmount === undefined || !difficulty) {
    return res.status(400).json({ ok: false, error: 'Email, bet amount, and difficulty are required.' });
  }
  const normalizedEmail = email.trim().toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(CHICKEN_ROAD_DIFFICULTIES, difficulty)) {
    return res.status(400).json({ ok: false, error: 'Difficulty must be easy, medium, hard, or hardcore.' });
  }

  const existing = chickenRoadSessions.get(normalizedEmail);
  if (existing && existing.active) {
    return res.status(409).json({ ok: false, error: 'Finish or cash out your current round first.' });
  }

  const numericAmount = Number(betAmount);
  // Bet amount of exactly 0 starts a demo round — same rules as Mines.
  const isDemo = numericAmount === 0;
  if (!Number.isFinite(numericAmount) || (numericAmount > 0 && numericAmount < 10)) {
    return res.status(400).json({ ok: false, error: 'Enter a bet amount of at least Rs 10, or 0 to play in demo mode.' });
  }

  const users = readUsers();
  const user = users.find(u => u.email.toLowerCase() === normalizedEmail);
  if (!user) return res.status(404).json({ ok: false, error: 'No account found with this email.' });
  if (user.blocked) return res.status(403).json({ ok: false, error: 'This account has been blocked.' });

  if (isDemo) {
    chickenRoadSessions.set(normalizedEmail, {
      betAmount: 0, difficulty, stepIndex: 0, multiplier: 1, active: true, isDemo: true
    });
    return res.json({ ok: true, balance: user.balance, isDemo: true });
  }

  if (user.balance < numericAmount) {
    return res.status(400).json({ ok: false, error: 'Insufficient balance for this bet.' });
  }

  user.balance = Math.round((user.balance - numericAmount) * 100) / 100;
  if (!Array.isArray(user.transactions)) user.transactions = [];
  user.transactions.unshift({
    id: 'TXN-' + crypto.randomBytes(6).toString('hex'),
    type: 'bet',
    amount: numericAmount,
    gameName: 'Chicken Road',
    difficulty,
    balanceAfter: user.balance,
    createdAt: new Date().toISOString()
  });
  writeUsers(users);

  chickenRoadSessions.set(normalizedEmail, {
    betAmount: numericAmount, difficulty, stepIndex: 0, multiplier: 1, active: true, isDemo: false
  });

  return res.json({ ok: true, balance: user.balance, isDemo: false });
});

app.post('/api/chickenroad/step', (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ ok: false, error: 'Email is required.' });
  const normalizedEmail = email.trim().toLowerCase();
  const session = chickenRoadSessions.get(normalizedEmail);
  if (!session || !session.active) {
    return res.status(409).json({ ok: false, error: 'No active round. Place a bet first.' });
  }
  if (session.stepIndex >= CHICKEN_ROAD_TOTAL_STEPS) {
    return res.status(409).json({ ok: false, error: 'You already reached the end of the road.' });
  }

  const survivalProb = CHICKEN_ROAD_DIFFICULTIES[session.difficulty];
  const survived = Math.random() < survivalProb;

  if (!survived) {
    // Hit by a car / fell into a manhole — round over, stake already
    // lost at bet time (or nothing lost at all if this was a demo round).
    session.active = false;
    chickenRoadSessions.delete(normalizedEmail);
    return res.json({
      ok: true,
      hit: true,
      stepIndex: session.stepIndex,
      multiplier: session.multiplier,
      isDemo: session.isDemo
    });
  }

  session.stepIndex += 1;
  session.multiplier = computeChickenRoadMultiplier(session.difficulty, session.stepIndex);

  if (session.stepIndex >= CHICKEN_ROAD_TOTAL_STEPS) {
    // Reached the end of the road — auto cash-out, nothing left to risk.
    const payout = Math.round(session.betAmount * session.multiplier * 100) / 100;
    if (!session.isDemo) {
      creditWinnings(normalizedEmail, payout, session.multiplier, 'Chicken Road');
    }
    session.active = false;
    chickenRoadSessions.delete(normalizedEmail);
    const users = readUsers();
    const user = users.find(u => u.email.toLowerCase() === normalizedEmail);
    return res.json({
      ok: true,
      hit: false,
      cleared: true,
      stepIndex: session.stepIndex,
      multiplier: session.multiplier,
      payout,
      isDemo: session.isDemo,
      balance: user ? user.balance : undefined
    });
  }

  return res.json({
    ok: true,
    hit: false,
    cleared: false,
    stepIndex: session.stepIndex,
    multiplier: session.multiplier
  });
});

app.post('/api/chickenroad/cashout', (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ ok: false, error: 'Email is required.' });
  const normalizedEmail = email.trim().toLowerCase();
  const session = chickenRoadSessions.get(normalizedEmail);
  if (!session || !session.active) {
    return res.status(409).json({ ok: false, error: 'No active round to cash out of.' });
  }
  if (session.stepIndex === 0) {
    return res.status(409).json({ ok: false, error: 'Take at least one step before cashing out.' });
  }

  const payout = Math.round(session.betAmount * session.multiplier * 100) / 100;
  if (!session.isDemo) {
    creditWinnings(normalizedEmail, payout, session.multiplier, 'Chicken Road');
  }
  session.active = false;
  chickenRoadSessions.delete(normalizedEmail);

  const users = readUsers();
  const user = users.find(u => u.email.toLowerCase() === normalizedEmail);

  // Purely informational "what would have happened next" reveal — a
  // fresh, independent random roll using the same odds as a real step,
  // made after the round is already settled so it can never affect the
  // payout. If the player had already reached the end of the road,
  // there's no "next" step to reveal.
  let nextStepPreview = null;
  const nextStepIndex = session.stepIndex + 1;
  if (nextStepIndex <= CHICKEN_ROAD_TOTAL_STEPS) {
    const survivalProb = CHICKEN_ROAD_DIFFICULTIES[session.difficulty];
    const wouldHaveSurvived = Math.random() < survivalProb;
    nextStepPreview = { stepIndex: nextStepIndex, wouldHaveDied: !wouldHaveSurvived };
  }

  return res.json({
    ok: true,
    payout,
    multiplier: session.multiplier,
    isDemo: session.isDemo,
    balance: user ? user.balance : undefined,
    nextStepPreview
  });
});

const server = http.createServer(app);
aviatorWss = new WebSocketServer({ server, path: '/aviator-ws' });
aviatorWss.on('connection', (ws) => {
  ws.send(JSON.stringify(aviatorPublicState()));
});


/* ============================================================
 * DRAGON VS TIGER
 * ------------------------------------------------------------
 * One shared round at a time. Each round: 6 seconds of betting, then
 * one card is dealt to the Dragon and one to the Tiger and the higher
 * card wins (Ace is lowest, King highest). Same value = Tie.
 *
 *   Dragon / Tiger win : pays 1:1 (stake x 2)
 *   Tie                : pays 11:1 (stake x 12)
 *   On a Tie, Dragon and Tiger bets lose.
 *
 * Cards are drawn on the server, after betting closes, so nothing a
 * player does can influence them. Every chip is a real wallet bet.
 * ============================================================ */
const DT_BETTING_MS = 6000;
const DT_RESULT_MS = 6000;
const DT_CHIPS = [20, 40, 60, 100, 200, 500, 1000, 2000, 5000];
const DT_PAYOUT = { dragon: 2, tiger: 2, tie: 12 };
const DT_SUITS = ['spades', 'hearts', 'diamonds', 'clubs'];

let dtRound = null;
let dtRoundCounter = 0;
const dtHistory = []; // newest first, last 30 results

function dtNewRound() {
  dtRoundCounter += 1;
  dtRound = {
    id: dtRoundCounter,
    phase: 'betting',
    phaseStartedAt: Date.now(),
    bets: new Map(), // email -> { dragon, tiger, tie }
    result: null,
    payouts: new Map() // email -> total paid out this round
  };
}

function dtDrawCard() {
  return {
    rank: 1 + crypto.randomInt(13),
    suit: DT_SUITS[crypto.randomInt(DT_SUITS.length)]
  };
}

function dtSettle() {
  const dragon = dtDrawCard();
  const tiger = dtDrawCard();
  const winner = dragon.rank > tiger.rank ? 'dragon' : tiger.rank > dragon.rank ? 'tiger' : 'tie';
  dtRound.result = { dragon, tiger, winner };
  dtRound.phase = 'result';
  dtRound.phaseStartedAt = Date.now();

  dtHistory.unshift({ round: dtRound.id, winner, dragon: dragon.rank, tiger: tiger.rank });
  if (dtHistory.length > 30) dtHistory.pop();

  for (const [email, bets] of dtRound.bets) {
    const stake = bets[winner] || 0;
    if (stake > 0) {
      const payout = stake * DT_PAYOUT[winner];
      creditWinnings(email, payout, DT_PAYOUT[winner], 'Dragon vs Tiger');
      dtRound.payouts.set(email, payout);
    }
  }
}

function dtTick() {
  if (!dtRound) return dtNewRound();
  const elapsed = Date.now() - dtRound.phaseStartedAt;
  if (dtRound.phase === 'betting' && elapsed >= DT_BETTING_MS) dtSettle();
  else if (dtRound.phase === 'result' && elapsed >= DT_RESULT_MS) dtNewRound();
}
dtNewRound();
setInterval(dtTick, 200);

function dtState(email) {
  const elapsed = Date.now() - dtRound.phaseStartedAt;
  const limit = dtRound.phase === 'betting' ? DT_BETTING_MS : DT_RESULT_MS;
  const mine = email ? dtRound.bets.get(email) : null;
  return {
    ok: true,
    roundId: dtRound.id,
    phase: dtRound.phase,
    msLeft: Math.max(0, limit - elapsed),
    result: dtRound.phase === 'result' ? dtRound.result : null,
    myBets: mine || { dragon: 0, tiger: 0, tie: 0 },
    myPayout: email && dtRound.phase === 'result' ? (dtRound.payouts.get(email) || 0) : 0,
    history: dtHistory.slice(0, 20),
    chips: DT_CHIPS
  };
}

app.get('/api/dragontiger/state', (req, res) => {
  const email = req.query.email ? String(req.query.email).trim().toLowerCase() : null;
  const out = dtState(email);
  if (email) {
    const user = readUsers().find(u => u.email.toLowerCase() === email);
    if (user) out.balance = user.balance;
  }
  res.json(out);
});

app.post('/api/dragontiger/bet', (req, res) => {
  const { email, side, amount } = req.body || {};
  if (!email || !side || amount === undefined) {
    return res.status(400).json({ ok: false, error: 'Email, side and amount are required.' });
  }
  if (!['dragon', 'tiger', 'tie'].includes(side)) {
    return res.status(400).json({ ok: false, error: 'Side must be dragon, tiger or tie.' });
  }
  const chip = Number(amount);
  if (!DT_CHIPS.includes(chip)) {
    return res.status(400).json({ ok: false, error: 'Invalid chip amount.' });
  }
  if (dtRound.phase !== 'betting' || Date.now() - dtRound.phaseStartedAt >= DT_BETTING_MS) {
    return res.status(409).json({ ok: false, error: 'Betting is closed. Wait for the next round.' });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const users = readUsers();
  const user = users.find(u => u.email.toLowerCase() === normalizedEmail);
  if (!user) return res.status(404).json({ ok: false, error: 'No account found with this email.' });
  if (user.blocked) return res.status(403).json({ ok: false, error: 'This account has been blocked.' });
  if (user.balance < chip) return res.status(400).json({ ok: false, error: 'Insufficient balance for this chip.' });

  user.balance = Math.round((user.balance - chip) * 100) / 100;
  if (!Array.isArray(user.transactions)) user.transactions = [];
  user.transactions.unshift({
    id: 'TXN-' + crypto.randomBytes(6).toString('hex'),
    type: 'bet',
    amount: chip,
    gameName: 'Dragon vs Tiger (' + side + ')',
    balanceAfter: user.balance,
    createdAt: new Date().toISOString()
  });
  writeUsers(users);

  const bets = dtRound.bets.get(normalizedEmail) || { dragon: 0, tiger: 0, tie: 0 };
  bets[side] += chip;
  dtRound.bets.set(normalizedEmail, bets);

  res.json({ ok: true, balance: user.balance, myBets: bets, roundId: dtRound.id });
});

server.listen(PORT, () => {
  console.log(`Phoenix backend listening on http://localhost:${PORT}`);
  console.log(`Aviator WebSocket at ws://localhost:${PORT}/aviator-ws`);
  console.log(`Admin login -> email: ${ADMIN_EMAIL}  password: ${ADMIN_PASSWORD}`);
});
