const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const indexPath = path.join(__dirname, 'index.html');
const indexContent = fs.readFileSync(indexPath, 'utf8');

app.set('trust proxy', true);

// ---- one canonical address: https://findmyexpense.com ----
const CANONICAL_HOST = process.env.CANONICAL_HOST || 'findmyexpense.com';
const REDIRECT_HOSTS = new Set(['www.findmyexpense.com', 'expense-calculator.fly.dev']);
app.use((req, res, next) => {
  const host = String(req.headers.host || '').toLowerCase().split(':')[0];
  if (REDIRECT_HOSTS.has(host) && req.path !== '/health') {
    return res.redirect(301, 'https://' + CANONICAL_HOST + req.originalUrl);
  }
  next();
});

// Real visitor IP: Cloudflare puts it in CF-Connecting-IP (otherwise every visitor looks like a Cloudflare server)
function clientIp(req) { return String(req.headers['cf-connecting-ip'] || req.ip || 'unknown'); }

const jsonSmall = express.json(), jsonLarge = express.json({ limit: '8mb' });
app.use((req, res, next) => (req.path === '/api/receipts/scan' ? jsonLarge : jsonSmall)(req, res, next));

// PWA files: manifest, service worker, icons
app.get('/sw.js', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Service-Worker-Allowed', '/');
  res.sendFile(path.join(__dirname, 'public', 'sw.js'));
});
app.get('/manifest.webmanifest', (req, res) => {
  res.setHeader('Content-Type', 'application/manifest+json');
  res.sendFile(path.join(__dirname, 'public', 'manifest.webmanifest'));
});
app.use('/icons', express.static(path.join(__dirname, 'public', 'icons'), { maxAge: '7d' }));

// Root route
app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(indexContent);
});

// ---- PWA files ----
app.get('/manifest.webmanifest', (req, res) => {
  res.type('application/manifest+json').set('Cache-Control', 'no-cache').sendFile(path.join(__dirname, 'manifest.webmanifest'));
});
app.get('/sw.js', (req, res) => {
  res.type('application/javascript').set({ 'Cache-Control': 'no-cache', 'Service-Worker-Allowed': '/' }).sendFile(path.join(__dirname, 'sw.js'));
});
app.use('/icons', express.static(path.join(__dirname, 'icons'), { maxAge: '7d', fallthrough: false }));
app.get('/favicon.ico', (req, res) => res.sendFile(path.join(__dirname, 'icons', 'favicon-32.png')));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});


// ================= USERS (server-side) =================
// Stored as JSON in DATA_DIR. On Fly.io mount a volume at /data so accounts survive deploys.
const DATA_DIR = process.env.DATA_DIR || (fs.existsSync('/data') ? '/data' : path.join(__dirname, 'data'));
fs.mkdirSync(DATA_DIR, { recursive: true });
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PERSISTENT = DATA_DIR === '/data' || !!process.env.DATA_DIR;
let db = { users: [], secret: null };
try { db = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch { /* first run */ }
if (!db.secret) db.secret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
db.users = db.users || []; db.households = db.households || []; db.expenses = db.expenses || []; db.invites = db.invites || []; db.receipts = db.receipts || [];
function saveDb() {
  const tmp = USERS_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, USERS_FILE);
}
saveDb();
const SECRET = process.env.SESSION_SECRET || db.secret;

function findByPhone(phone) { return db.users.find(u => u.phone === phone); }
function findByEmail(email) { return db.users.find(u => u.email === String(email || '').trim().toLowerCase()); }
function publicUser(u) { return { id: u.id, name: u.name, email: u.email, phone: u.phone, hasPassword: !!u.passwordHash }; }

function hashPassword(pw, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(pw, salt, 64).toString('hex') };
}
function checkPassword(pw, u) {
  if (!u || !u.passwordHash) return false;
  const h = crypto.scryptSync(pw, u.salt, 64);
  const stored = Buffer.from(u.passwordHash, 'hex');
  return stored.length === h.length && crypto.timingSafeEqual(stored, h);
}

// Signed tokens: base64url(payload).signature
function sign(payload, ttlMs) {
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + ttlMs })).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}
function verifyToken(tok, type) {
  const [body, sig] = String(tok || '').split('.');
  if (!body || !sig) return null;
  const expect = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (sig.length !== expect.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (p.exp < Date.now() || p.t !== type) return null;
    return p;
  } catch { return null; }
}
const SESSION_TTL = 30 * 24 * 3600e3;
function newHousehold(u) {
  const h = { id: crypto.randomUUID(), name: (u.name || '').split(' ')[0] + '’s household', ownerId: u.id, createdAt: new Date().toISOString() };
  db.households.push(h); u.householdId = h.id;
  return h;
}
function ensureHousehold(u) {
  let h = u.householdId && db.households.find(x => x.id === u.householdId);
  if (!h) { h = newHousehold(u); saveDb(); }
  return h;
}
db.users.forEach(ensureHousehold);   // migrate accounts created before households existed
function sessionFor(u) { return { token: sign({ t: 'session', uid: u.id }, SESSION_TTL), user: publicUser(u) }; }
function authUser(req) {
  const p = verifyToken((req.headers.authorization || '').replace(/^Bearer\s+/i, ''), 'session');
  return p ? db.users.find(u => u.id === p.uid) : null;
}

// ================= PHONE OTP =================
// Provider: 2Factor.in when TWOFACTOR_API_KEY is set (flyctl secrets set TWOFACTOR_API_KEY=...).
// Without a key the app runs in TEST MODE: no SMS is sent and the code is shown on screen.
const TWOFACTOR_KEY = process.env.TWOFACTOR_API_KEY || '';
const TEST_MODE = !TWOFACTOR_KEY;
const OTP_TTL_MS = 10 * 60 * 1000;
const RESEND_COOLDOWN_MS = 30 * 1000;
const MAX_SENDS_PER_HOUR = 5;
const MAX_VERIFY_ATTEMPTS = 5;
const MAX_SENDS_PER_IP_HOUR = 20;

const otpStore = new Map();   // phone -> { code?, sessionId?, expiresAt, attempts, sends: [timestamps] }
const ipSends = new Map();    // ip -> [timestamps]

function normalizePhone(p) {
  const digits = String(p || '').replace(/\D/g, '').replace(/^(91|0)(?=[6-9]\d{9}$)/, '');
  return /^[6-9]\d{9}$/.test(digits) ? digits : null;
}
function recent(list, windowMs) { const now = Date.now(); return (list || []).filter(t => now - t < windowMs); }

setInterval(() => {               // housekeeping
  const now = Date.now();
  for (const [k, v] of otpStore) if (v.expiresAt < now && recent(v.sends, 3600e3).length === 0) otpStore.delete(k);
  for (const [k, v] of ipSends) { const r = recent(v, 3600e3); r.length ? ipSends.set(k, r) : ipSends.delete(k); }
}, 10 * 60 * 1000).unref();

app.get('/api/otp/status', (req, res) => res.json({ testMode: TEST_MODE, persistent: PERSISTENT, receipts: !!(process.env.GEMINI_API_KEY || process.env.ANTHROPIC_API_KEY), receiptProvider: process.env.GEMINI_API_KEY ? 'gemini' : process.env.ANTHROPIC_API_KEY ? 'claude' : null }));

app.post('/api/otp/send', async (req, res) => {
  const phone = normalizePhone(req.body && req.body.phone);
  if (!phone) return res.status(400).json({ error: 'Enter a valid 10-digit Indian mobile number.' });
  const purpose = req.body.purpose === 'login' ? 'login' : 'signup';
  if (purpose === 'signup' && findByPhone(phone)) return res.status(409).json({ error: 'This number is already registered. Please log in instead.', code: 'EXISTS' });
  if (purpose === 'login' && !findByPhone(phone)) return res.status(404).json({ error: 'No account found for this number. Please sign up first.', code: 'NOT_FOUND' });

  const ip = clientIp(req);
  const ipList = recent(ipSends.get(ip), 3600e3);
  if (ipList.length >= MAX_SENDS_PER_IP_HOUR) return res.status(429).json({ error: 'Too many OTP requests. Try again later.' });

  const entry = otpStore.get(phone) || { sends: [] };
  entry.sends = recent(entry.sends, 3600e3);
  const last = entry.sends[entry.sends.length - 1];
  if (last && Date.now() - last < RESEND_COOLDOWN_MS) {
    return res.status(429).json({ error: 'Please wait before requesting another OTP.', retryIn: Math.ceil((RESEND_COOLDOWN_MS - (Date.now() - last)) / 1000) });
  }
  if (entry.sends.length >= MAX_SENDS_PER_HOUR) return res.status(429).json({ error: 'Too many OTPs for this number. Try again in an hour.' });

  try {
    let devCode;
    if (TEST_MODE) {
      entry.code = String(crypto.randomInt(0, 1e6)).padStart(6, '0');
      entry.sessionId = null;
      devCode = entry.code;
      console.log(`🧪 TEST MODE OTP for ••${phone.slice(-4)}: ${entry.code}`);
    } else {
      const r = await fetch(`https://2factor.in/API/V1/${TWOFACTOR_KEY}/SMS/+91${phone}/AUTOGEN`);
      const d = await r.json().catch(() => ({}));
      if (d.Status !== 'Success') {
        console.error('2Factor send failed:', d);
        return res.status(502).json({ error: 'Could not send OTP right now. Please try again.' });
      }
      entry.sessionId = d.Details;
      entry.code = null;
    }
    entry.expiresAt = Date.now() + OTP_TTL_MS;
    entry.attempts = 0;
    entry.purpose = purpose;
    entry.sends.push(Date.now());
    otpStore.set(phone, entry);
    ipList.push(Date.now()); ipSends.set(ip, ipList);
    res.json({ sent: true, testMode: TEST_MODE, devCode, resendIn: RESEND_COOLDOWN_MS / 1000 });
  } catch (err) {
    console.error('OTP send error:', err);
    res.status(500).json({ error: 'Could not send OTP right now. Please try again.' });
  }
});

app.post('/api/otp/verify', async (req, res) => {
  const phone = normalizePhone(req.body && req.body.phone);
  const otp = String((req.body && req.body.otp) || '').replace(/\D/g, '');
  if (!phone || otp.length < 4) return res.status(400).json({ error: 'Enter the OTP you received.' });

  const entry = otpStore.get(phone);
  if (!entry || (!entry.code && !entry.sessionId)) return res.status(400).json({ error: 'Request an OTP first.' });
  if (Date.now() > entry.expiresAt) { entry.code = entry.sessionId = null; return res.status(400).json({ error: 'OTP expired. Request a new one.' }); }
  if (entry.attempts >= MAX_VERIFY_ATTEMPTS) { entry.code = entry.sessionId = null; return res.status(429).json({ error: 'Too many wrong attempts. Request a new OTP.' }); }
  entry.attempts++;

  try {
    let ok = false;
    if (entry.code) {
      ok = otp.length === entry.code.length && crypto.timingSafeEqual(Buffer.from(otp), Buffer.from(entry.code));
    } else {
      const r = await fetch(`https://2factor.in/API/V1/${TWOFACTOR_KEY}/SMS/VERIFY/${encodeURIComponent(entry.sessionId)}/${otp}`);
      const d = await r.json().catch(() => ({}));
      ok = d.Status === 'Success' && /matched/i.test(d.Details || '');
    }
    if (!ok) return res.status(400).json({ error: 'Incorrect OTP.', attemptsLeft: MAX_VERIFY_ATTEMPTS - entry.attempts });
    entry.code = entry.sessionId = null;   // one-time use
    if (entry.purpose === 'login') {
      const u = findByPhone(phone);
      if (!u) return res.status(404).json({ error: 'No account found for this number.' });
      return res.json({ verified: true, ...sessionFor(u) });
    }
    res.json({ verified: true, phone, signupToken: sign({ t: 'signup', phone }, 20 * 60e3) });
  } catch (err) {
    console.error('OTP verify error:', err);
    res.status(500).json({ error: 'Could not verify OTP right now. Please try again.' });
  }
});


// ================= ACCOUNTS =================
const loginFails = new Map(); // key -> [timestamps]
function tooManyFails(key) { return recent(loginFails.get(key), 15 * 60e3).length >= 8; }
function noteFail(key) { const l = recent(loginFails.get(key), 15 * 60e3); l.push(Date.now()); loginFails.set(key, l); }

app.post('/api/signup', (req, res) => {
  const b = req.body || {};
  const name = String(b.name || '').trim().slice(0, 80);
  const email = String(b.email || '').trim().toLowerCase();
  const password = String(b.password || '');
  const p = verifyToken(b.signupToken, 'signup');
  if (!p) return res.status(400).json({ error: 'Please verify your phone number again.' });
  if (name.length < 2) return res.status(400).json({ error: 'Enter your name.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password && password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (findByPhone(p.phone)) return res.status(409).json({ error: 'This number is already registered. Please log in.' });
  if (findByEmail(email)) return res.status(409).json({ error: 'This email is already registered. Please log in.' });
  const u = { id: crypto.randomUUID(), name, email, phone: p.phone, createdAt: new Date().toISOString() };
  if (password) { const h = hashPassword(password); u.salt = h.salt; u.passwordHash = h.hash; }
  db.users.push(u); newHousehold(u); saveDb();
  console.log(`👤 New account: ••${u.phone.slice(-4)}`);
  res.json(sessionFor(u));
});

app.post('/api/login/password', (req, res) => {
  const id = String((req.body && req.body.identifier) || '').trim();
  const password = String((req.body && req.body.password) || '');
  const key = id.toLowerCase(), ipKey = 'ip:' + clientIp(req);
  if (tooManyFails(key) || tooManyFails(ipKey)) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes, or log in with OTP.' });
  const phone = normalizePhone(id);
  const u = phone ? findByPhone(phone) : findByEmail(id);
  if (u && !u.passwordHash) return res.status(400).json({ error: 'This account has no password yet. Log in with OTP, then set one.', code: 'NO_PASSWORD' });
  if (!checkPassword(password, u)) { noteFail(key); noteFail(ipKey); return res.status(401).json({ error: 'Incorrect phone/email or password.' }); }
  loginFails.delete(key);
  res.json(sessionFor(u));
});

app.get('/api/me', (req, res) => {
  const u = authUser(req);
  if (!u) return res.status(401).json({ error: 'Not logged in' });
  res.json({ user: publicUser(u) });
});

app.patch('/api/me', (req, res) => {
  const u = authUser(req);
  if (!u) return res.status(401).json({ error: 'Not logged in' });
  const name = String((req.body && req.body.name) || '').trim().slice(0, 80);
  const email = String((req.body && req.body.email) || '').trim().toLowerCase();
  if (name.length < 2) return res.status(400).json({ error: 'Enter your name.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  const other = findByEmail(email);
  if (other && other.id !== u.id) return res.status(409).json({ error: 'This email is used by another account.' });
  u.name = name; u.email = email; saveDb();
  res.json({ user: publicUser(u) });
});

app.post('/api/me/password', (req, res) => {
  const u = authUser(req);
  if (!u) return res.status(401).json({ error: 'Not logged in' });
  const pw = String((req.body && req.body.password) || '');
  if (pw.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (u.passwordHash && !checkPassword(String(req.body.current || ''), u)) return res.status(401).json({ error: 'Current password is incorrect.' });
  const h = hashPassword(pw); u.salt = h.salt; u.passwordHash = h.hash; saveDb();
  res.json({ ok: true, user: publicUser(u) });
});


// ================= HOUSEHOLD + EXPENSES =================
const MAX_MEMBERS = 10;
const membersOf = hid => db.users.filter(x => x.householdId === hid);
const maskPhone = p => p ? '••••• ' + p.slice(-5) : '';
function requireUser(req, res) {
  const u = authUser(req);
  if (!u) { res.status(401).json({ error: 'Not logged in' }); return null; }
  ensureHousehold(u);
  return u;
}
function invitesFor(u) {
  return db.invites.filter(i => i.status === 'pending' && i.householdId !== u.householdId &&
    ((i.phone && i.phone === u.phone) || (i.email && i.email === u.email)));
}
function householdView(u) {
  const h = ensureHousehold(u);
  const isOwner = h.ownerId === u.id;
  return {
    household: { id: h.id, name: h.name, isOwner },
    members: membersOf(h.id).map(m => ({ id: m.id, name: m.name, email: m.email, phone: m.id === u.id ? m.phone : maskPhone(m.phone), role: m.id === h.ownerId ? 'owner' : 'member', you: m.id === u.id }))
      .sort((a, b) => (b.role === 'owner') - (a.role === 'owner') || a.name.localeCompare(b.name)),
    pending: db.invites.filter(i => i.householdId === h.id && i.status === 'pending').map(i => ({ id: i.id, to: i.phone ? '+91 ' + i.phone : i.email, createdAt: i.createdAt })),
    incoming: invitesFor(u).map(i => {
      const hh = db.households.find(x => x.id === i.householdId); const by = db.users.find(x => x.id === i.invitedBy);
      return { id: i.id, household: hh ? hh.name : 'a household', from: by ? by.name : 'Someone', members: hh ? membersOf(hh.id).length : 0 };
    }).filter(i => i.members > 0),
  };
}
function moveUser(u, targetHid) {
  db.expenses.forEach(e => { if (e.userId === u.id) e.householdId = targetHid; });
  u.householdId = targetHid;
}
// When someone leaves, the household keeps going; if the owner leaves, the longest-standing member takes over
function afterDeparture(hid, leavingId) {
  const h = db.households.find(x => x.id === hid); if (!h) return;
  const rest = membersOf(hid).filter(m => m.id !== leavingId);
  if (!rest.length) { db.households = db.households.filter(x => x.id !== hid); db.invites = db.invites.filter(i => i.householdId !== hid); return; }
  if (h.ownerId === leavingId) h.ownerId = rest.sort((a, b) => (a.joinedAt || a.createdAt).localeCompare(b.joinedAt || b.createdAt))[0].id;
}

app.get('/api/household', (req, res) => { const u = requireUser(req, res); if (u) res.json(householdView(u)); });

app.patch('/api/household', (req, res) => {
  const u = requireUser(req, res); if (!u) return;
  const h = ensureHousehold(u);
  if (h.ownerId !== u.id) return res.status(403).json({ error: 'Only the household owner can rename it.' });
  const name = String((req.body && req.body.name) || '').trim().slice(0, 50);
  if (name.length < 2) return res.status(400).json({ error: 'Enter a household name.' });
  h.name = name; saveDb(); res.json(householdView(u));
});

app.post('/api/household/invite', (req, res) => {
  const u = requireUser(req, res); if (!u) return;
  const h = ensureHousehold(u);
  if (h.ownerId !== u.id) return res.status(403).json({ error: 'Only the household owner can invite people.' });
  const raw = String((req.body && req.body.identifier) || '').trim();
  const phone = normalizePhone(raw);
  const email = !phone && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(raw) ? raw.toLowerCase() : null;
  if (!phone && !email) return res.status(400).json({ error: 'Enter a 10-digit mobile number or an email address.' });
  if ((phone && phone === u.phone) || (email && email === u.email)) return res.status(400).json({ error: 'That’s you.' });
  const existing = phone ? findByPhone(phone) : findByEmail(email);
  if (existing && existing.householdId === h.id) return res.status(409).json({ error: (existing.name || 'This person') + ' is already in your household.' });
  if (membersOf(h.id).length >= MAX_MEMBERS) return res.status(400).json({ error: 'A household can have up to ' + MAX_MEMBERS + ' people.' });
  if (db.invites.filter(i => i.householdId === h.id && i.status === 'pending').length >= 20) return res.status(400).json({ error: 'Too many pending invites. Cancel some first.' });
  const dup = db.invites.find(i => i.householdId === h.id && i.status === 'pending' && ((phone && i.phone === phone) || (email && i.email === email)));
  if (!dup) db.invites.push({ id: crypto.randomUUID(), householdId: h.id, phone, email, invitedBy: u.id, status: 'pending', createdAt: new Date().toISOString() });
  saveDb();
  res.json({ ...householdView(u), invitedHasAccount: !!existing });
});

app.delete('/api/household/invite/:id', (req, res) => {
  const u = requireUser(req, res); if (!u) return;
  const i = db.invites.find(x => x.id === req.params.id && x.householdId === u.householdId && x.status === 'pending');
  if (!i) return res.status(404).json({ error: 'Invite not found.' });
  if (ensureHousehold(u).ownerId !== u.id) return res.status(403).json({ error: 'Only the owner can cancel invites.' });
  i.status = 'cancelled'; saveDb(); res.json(householdView(u));
});

app.post('/api/invites/:id/:action', (req, res) => {
  const u = requireUser(req, res); if (!u) return;
  const i = invitesFor(u).find(x => x.id === req.params.id);
  if (!i) return res.status(404).json({ error: 'This invite is no longer available.' });
  if (req.params.action === 'decline') { i.status = 'declined'; saveDb(); return res.json(householdView(u)); }
  if (req.params.action !== 'accept') return res.status(400).json({ error: 'Unknown action' });
  const target = db.households.find(x => x.id === i.householdId);
  if (!target || !membersOf(target.id).length) { i.status = 'cancelled'; saveDb(); return res.status(410).json({ error: 'That household no longer exists.' }); }
  if (membersOf(target.id).length >= MAX_MEMBERS) return res.status(400).json({ error: 'That household is full.' });
  const old = u.householdId;
  moveUser(u, target.id); u.joinedAt = new Date().toISOString();
  afterDeparture(old, u.id);
  i.status = 'accepted';
  db.invites.forEach(x => { if (x !== i && x.status === 'pending' && ((x.phone && x.phone === u.phone) || (x.email && x.email === u.email))) x.status = 'superseded'; });
  saveDb(); res.json(householdView(u));
});

app.post('/api/household/leave', (req, res) => {
  const u = requireUser(req, res); if (!u) return;
  const old = u.householdId;
  if (membersOf(old).length <= 1) return res.status(400).json({ error: 'You’re the only person in this household.' });
  const h = { id: crypto.randomUUID(), name: (u.name || '').split(' ')[0] + '’s household', ownerId: u.id, createdAt: new Date().toISOString() };
  db.households.push(h);
  moveUser(u, h.id); afterDeparture(old, u.id);
  saveDb(); res.json(householdView(u));
});

app.delete('/api/household/members/:id', (req, res) => {
  const u = requireUser(req, res); if (!u) return;
  const h = ensureHousehold(u);
  if (h.ownerId !== u.id) return res.status(403).json({ error: 'Only the household owner can remove people.' });
  const m = membersOf(h.id).find(x => x.id === req.params.id);
  if (!m || m.id === u.id) return res.status(404).json({ error: 'Member not found.' });
  moveUser(m, newHousehold(m).id);
  saveDb(); res.json(householdView(u));
});


// ================= RECEIPT SCANNING =================
// Reads a receipt photo with an AI vision model and returns the fields for the Add expense form.
// Provider: Google Gemini (free tier) when GEMINI_API_KEY is set, otherwise Claude when ANTHROPIC_API_KEY is set.
// Photos are kept on the volume.
const RECEIPT_DIR = path.join(DATA_DIR, 'receipts');
fs.mkdirSync(RECEIPT_DIR, { recursive: true });
const RECEIPT_MODEL = process.env.RECEIPT_MODEL || 'claude-haiku-4-5-20251001';
const ANTHROPIC_URL = (process.env.ANTHROPIC_BASE_URL || 'https://api.anthropic.com') + '/v1/messages';
const GEMINI_BASE = process.env.GEMINI_BASE_URL || 'https://generativelanguage.googleapis.com';
// Each model has its own free daily quota, so the second is a backup when the first runs out
const GEMINI_PREFERRED = (process.env.GEMINI_MODELS || 'gemini-3.8-flash,gemini-3.5-flash-lite').split(',').map(x => x.trim()).filter(Boolean);
let geminiModels = null;          // resolved list, cached; refreshed if Google retires a model
let geminiListedAt = 0;
// Ask Google which Flash models this key can use, newest first (so a retired model never breaks scanning)
async function discoverGeminiModels() {
  try {
    const r = await fetch(GEMINI_BASE + '/v1beta/models?pageSize=200', { headers: { 'x-goog-api-key': process.env.GEMINI_API_KEY }, signal: AbortSignal.timeout(10000) });
    const d = await r.json().catch(() => ({}));
    const ver = n => (n.match(/gemini-(\d+(?:\.\d+)?)/) || [])[1] || '0';
    return (d.models || [])
      .filter(m => (m.supportedGenerationMethods || []).includes('generateContent'))
      .map(m => String(m.name || '').replace(/^models\//, ''))
      .filter(n => /^gemini-\d+(\.\d+)?-flash(-lite)?$/.test(n))
      .sort((a, b) => parseFloat(ver(b)) - parseFloat(ver(a)) || (a.includes('lite') - b.includes('lite')));
  } catch (e) { console.error('🧾 Gemini model list failed:', e.message); return []; }
}
let geminiFound = [];
async function geminiCandidates(refresh) {
  if (!geminiModels || refresh) {
    if (!geminiModels || Date.now() - geminiListedAt > 60e3) { geminiFound = await discoverGeminiModels(); geminiListedAt = Date.now(); }
    const preferred = GEMINI_PREFERRED.filter(m => !geminiFound.length || geminiFound.includes(m));
    geminiModels = [...new Set([...preferred, ...geminiFound.slice(0, 4)])];
    console.log('🧾 Gemini models:', geminiModels.join(', ') || '(none found)');
  }
  return geminiModels;
}
const CATEGORY_LIST = ['Food & Dining', 'Groceries', 'Travel', 'Transport', 'Shopping', 'Bills & Utilities', 'Entertainment', 'Health', 'Subscriptions', 'Loans & EMI', 'Transfers', 'Other'];
const scanLog = new Map(); // userId -> [timestamps]
const receiptPath = id => path.join(RECEIPT_DIR, id.replace(/[^a-f0-9-]/gi, '') + '.jpg');
function dropReceipt(id) { if (!id) return; db.receipts = db.receipts.filter(r => r.id !== id); fs.unlink(receiptPath(id), () => {}); }
function cleanupReceipts() {   // photos scanned but never saved with an expense
  const cutoff = Date.now() - 24 * 3600e3;
  db.receipts.filter(r => !r.expenseId && Date.parse(r.createdAt) < cutoff).forEach(r => dropReceipt(r.id));
}
setInterval(() => { cleanupReceipts(); saveDb(); }, 3600e3).unref();

const RECEIPT_PROMPT = `You read photos of receipts, bills, invoices and payment screenshots (often Indian: GST bills, restaurant bills, fuel slips, UPI/app payment confirmations).
Return ONLY a JSON object, no other text:
{"is_receipt": true|false, "amount": number|null, "currency": "INR"|"USD"|"EUR"|"GBP"|"AED"|"SGD"|"THB"|"JPY"|null, "date": "YYYY-MM-DD"|null, "merchant": string|null, "category": one of ${JSON.stringify(CATEGORY_LIST)}, "payment": "Credit Card"|"Direct Bank Transfer"|"UPI"|"Cash"|"Other"|null, "description": string|null}
Rules:
- amount = the final total actually paid (grand total / net payable / amount paid, including taxes, after discounts). Never a subtotal, item price, GST line, change returned or "you saved".
- currency: from the symbol or text; ₹ / Rs / INR -> "INR". If none is shown and it looks Indian, "INR".
- date: the transaction date. Indian receipts are usually DD/MM/YY. If no date is visible, null.
- merchant: the shop/restaurant/company name, cleaned up (e.g. "Starbucks", "Big Basket", "Indian Oil"). Max 40 characters.
- payment: only if the receipt says how it was paid. Any card (credit or debit) -> "Credit Card"; UPI/GPay/PhonePe/Paytm UPI -> "UPI"; NEFT/IMPS/net banking -> "Direct Bank Transfer"; cash -> "Cash". Otherwise null.
- description: 2–6 words saying what it was for, starting with the merchant, e.g. "Starbucks coffee", "Indian Oil petrol".
- If the image is not a receipt or bill, or the total is unreadable, set is_receipt false and the rest null.`;

class ScanError extends Error { constructor(msg, code) { super(msg); this.code = code; } }
function parseJsonText(text) {
  const t = String(text || '');
  try { return JSON.parse(t.slice(t.indexOf('{'), t.lastIndexOf('}') + 1)); } catch { return null; }
}
async function readWithGemini(buf, today, retried) {
  const models = await geminiCandidates(retried);
  if (!models.length) throw new ScanError('No Gemini Flash model is available for this API key', 404);
  let lastErr, sawRetired = false;
  for (const model of models) {
    const body = {
      systemInstruction: { parts: [{ text: RECEIPT_PROMPT }] },
      contents: [{ role: 'user', parts: [
        { inline_data: { mime_type: 'image/jpeg', data: buf.toString('base64') } },
        { text: 'Today is ' + today + '. Read this receipt.' },
      ] }],
      // generous output limit: newer models may "think" before answering, and that counts against it
      generationConfig: { temperature: 0, maxOutputTokens: 4096, responseMimeType: 'application/json' },
    };
    const r = await fetch(GEMINI_BASE + '/v1beta/models/' + encodeURIComponent(model) + ':generateContent', {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-goog-api-key': process.env.GEMINI_API_KEY },
      body: JSON.stringify(body), signal: AbortSignal.timeout(25000),
    }).catch(e => { throw new ScanError('Gemini ' + model + ' ' + (e.name === 'TimeoutError' ? 'timed out' : e.message), e.name === 'TimeoutError' ? 504 : 502); });
    const d = await r.json().catch(() => ({}));
    if (r.ok) {
      const cand = (d.candidates || [])[0] || {};
      const parts = ((cand.content || {}).parts || []).filter(p => !p.thought);
      console.log('🧾 Gemini ' + model + ' ok', cand.finishReason || '', (d.usageMetadata && d.usageMetadata.totalTokenCount) || '');
      const x = parseJsonText(parts.map(p => p.text || '').join(''));
      if (x) { geminiModels = [model, ...models.filter(m => m !== model)]; return x; }   // remember what works
      lastErr = new ScanError('Gemini ' + model + ' returned no readable answer (' + (cand.finishReason || 'empty') + ')', 502);
      continue;
    }
    lastErr = new ScanError((d.error && d.error.message) || ('Gemini ' + r.status), r.status);
    console.error('🧾 Gemini ' + model + ' failed:', r.status, d.error && d.error.status, String((d.error && d.error.message) || '').slice(0, 300));
    if (r.status === 404) sawRetired = true;
    if (![429, 404, 500, 503].includes(r.status)) break;   // only try the next model on quota / availability errors
  }
  if (sawRetired && !retried) return readWithGemini(buf, today, true);   // a model was retired: re-check the list once
  throw lastErr;
}
async function readWithClaude(buf, today) {
  const r = await fetch(ANTHROPIC_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({
      model: RECEIPT_MODEL, max_tokens: 400, system: RECEIPT_PROMPT,
      messages: [{ role: 'user', content: [
        { type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: buf.toString('base64') } },
        { type: 'text', text: 'Today is ' + today + '. Read this receipt.' },
      ] }],
    }),
    signal: AbortSignal.timeout(45000),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new ScanError((d.error && d.error.message) || ('Claude ' + r.status), r.status);
  return parseJsonText((d.content || []).filter(c => c.type === 'text').map(c => c.text).join(''));
}

app.post('/api/receipts/scan', async (req, res) => { try {
  const u = requireUser(req, res); if (!u) return;
  if (!process.env.GEMINI_API_KEY && !process.env.ANTHROPIC_API_KEY) return res.status(503).json({ error: 'Receipt scanning isn’t set up yet.' });
  const recent1h = recent(scanLog.get(u.id), 3600e3);
  if (recent1h.length >= 40) return res.status(429).json({ error: 'You’ve scanned a lot of receipts this hour. Try again a bit later.' });
  const b64 = String((req.body && req.body.image) || '').replace(/^data:image\/\w+;base64,/, '');
  const buf = Buffer.from(b64, 'base64');
  if (buf.length < 500 || buf.length > 6 * 1024 * 1024 || buf[0] !== 0xFF || buf[1] !== 0xD8) return res.status(400).json({ error: 'Please upload a JPEG photo of the receipt.' });
  recent1h.push(Date.now()); scanLog.set(u.id, recent1h);
  console.log('🧾 Scan started: ' + Math.round(buf.length / 1024) + ' KB via ' + (process.env.GEMINI_API_KEY ? 'Gemini' : 'Claude'));

  const id = crypto.randomUUID();
  fs.writeFileSync(receiptPath(id), buf);
  db.receipts.push({ id, userId: u.id, householdId: u.householdId, expenseId: null, bytes: buf.length, createdAt: new Date().toISOString() });
  cleanupReceipts(); saveDb();

  try {
    const today = new Date().toISOString().slice(0, 10);
    const x = process.env.GEMINI_API_KEY ? await readWithGemini(buf, today) : await readWithClaude(buf, today);
    if (!x || !x.is_receipt) return res.json({ receiptId: id, found: false });

    const amount = Number(x.amount);
    const now = Date.now(); const dt = /^\d{4}-\d{2}-\d{2}$/.test(String(x.date || '')) ? x.date : null;
    const okDate = dt && Date.parse(dt) <= now + 864e5 && Date.parse(dt) > now - 5 * 365 * 864e5 ? dt : null;
    const merchant = x.merchant ? String(x.merchant).trim().slice(0, 40) : '';
    res.json({ receiptId: id, found: true, fields: {
      amount: isFinite(amount) && amount > 0 ? Math.round(amount * 100) / 100 : null,
      currency: CURRENCIES.has(String(x.currency || '').toUpperCase()) ? String(x.currency).toUpperCase() : 'INR',
      date: okDate,
      category: CATEGORY_LIST.includes(x.category) ? x.category : 'Other',
      payment: METHODS.includes(x.payment) ? x.payment : null,
      note: String(x.description || merchant || '').trim().slice(0, 140),
    } });
  } catch (err) {
    console.error('Receipt scan failed:', err.code || '', err.message);
    // Reply 200 with the reason: proxies (Fly / Cloudflare) replace 5xx bodies with generic error pages
    const badKey = /api key|permission|unauthenticated|forbidden/i.test(err.message) || err.code === 401 || err.code === 403;
    const error = err.code === 429
      ? 'Today’s free scanning limit has been reached. The photo is attached; please fill in the details yourself, and scanning will be back tomorrow.'
      : badKey ? 'Receipt scanning isn’t set up correctly (the scanning service rejected its key). The photo is attached; please fill in the details yourself.'
      : 'Couldn’t read the receipt right now. The photo is attached; you can fill the details in yourself.';
    res.json({ receiptId: id, found: false, error });
  }
} catch (err) { console.error('🧾 Scan handler crashed:', err); if (!res.headersSent) res.status(500).json({ error: 'Scan failed on the server (' + err.message + ').' }); }
});

// Receipt photo: visible to everyone in the household of the expense it's attached to (or its uploader while unsaved)
app.get('/api/receipts/:id', (req, res) => {
  const u = requireUser(req, res); if (!u) return;
  const r = db.receipts.find(x => x.id === req.params.id);
  const e = r && r.expenseId && db.expenses.find(x => x.id === r.expenseId);
  const ok = r && (e ? e.householdId === u.householdId : r.userId === u.id);
  if (!ok || !fs.existsSync(receiptPath(r.id))) return res.status(404).json({ error: 'Receipt not found.' });
  res.set('Cache-Control', 'private, max-age=86400').type('image/jpeg').sendFile(receiptPath(r.id));
});

// Attach / detach a receipt when an expense is saved
function bindReceipt(u, e, receiptId) {
  if (receiptId === undefined) return null;
  if (!receiptId) { if (e.receiptId) { dropReceipt(e.receiptId); delete e.receiptId; } return null; }
  if (e.receiptId === receiptId) return null;
  const r = db.receipts.find(x => x.id === receiptId && x.userId === u.id && !x.expenseId);
  if (!r) return 'That receipt photo has expired. Please scan it again.';
  if (e.receiptId) dropReceipt(e.receiptId);
  r.expenseId = e.id; e.receiptId = r.id;
  return null;
}

// ---- expenses (shared by the whole household) ----
const CURRENCIES = new Set(['INR', 'USD', 'EUR', 'GBP', 'AED', 'SGD', 'THB', 'JPY']);
const METHODS = ['Credit Card', 'Direct Bank Transfer', 'UPI', 'Cash', 'Other'];
// Map anything typed before the dropdown existed (e.g. "HDFC card", "Kotak account") onto the fixed list
function toMethod(v) {
  const k = String(v || '').trim().toLowerCase();
  if (!k) return '';
  const exact = METHODS.find(m => m.toLowerCase() === k); if (exact) return exact;
  if (/\bupi\b|gpay|google ?pay|phonepe|bhim/.test(k)) return 'UPI';
  if (/\bcash\b/.test(k)) return 'Cash';
  if (/card|credit|debit|amex|visa|master|rupay|diners/.test(k)) return 'Credit Card';
  if (/account|a\/c|\bbank\b|net ?banking|transfer|nach|neft|imps|rtgs|ecs/.test(k)) return 'Direct Bank Transfer';
  return 'Other';
}
let migrated = 0;
db.expenses.forEach(e => { const m = toMethod(e.payment); if (m !== e.payment) { if (e.payment) e.paymentDetail = e.payment; e.payment = m; migrated++; } });
if (migrated) { saveDb(); console.log('💳 Converted ' + migrated + ' expense(s) to the payment-method list'); }
// Shared bills: amount = your share; billTotal / splitWays record the full bill
function splitFields(b, amount) {
  const n = Math.round(Number(b.splitWays));
  if (!isFinite(n) || n < 2) return { splitWays: 1, billTotal: null };
  const ways = Math.min(n, 50);
  let total = Number(b.billTotal);
  if (!isFinite(total) || total === 0) total = amount * ways;
  if (Math.sign(total) !== Math.sign(amount)) total = -total;
  return { splitWays: ways, billTotal: Math.round(total * 100) / 100 };
}
function cleanExpense(b) {
  const amount = Number(b.amount);
  if (!isFinite(amount) || amount === 0 || Math.abs(amount) > 1e9) return { error: 'Enter a valid amount.' };
  const currency = String(b.currency || 'INR').toUpperCase();
  if (!CURRENCIES.has(currency)) return { error: 'Unsupported currency.' };
  const date = String(b.date || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return { error: 'Pick a valid date.' };
  return { value: {
    amount: Math.round(amount * 100) / 100, currency, date,
    category: String(b.category || 'Other').slice(0, 40),
    payment: toMethod(b.payment),
    ...splitFields(b, amount),
    note: String(b.note || '').trim().slice(0, 140),
  } };
}
const expenseOut = e => ({ id: e.id, userId: e.userId, amount: e.amount, currency: e.currency, date: e.date, category: e.category, payment: e.payment, note: e.note, receiptId: e.receiptId || null, splitWays: e.splitWays || 1, billTotal: e.billTotal || null, createdAt: e.createdAt });

app.get('/api/expenses', (req, res) => {
  const u = requireUser(req, res); if (!u) return;
  res.json({ expenses: db.expenses.filter(e => e.householdId === u.householdId).map(expenseOut), ...householdView(u) });
});

app.post('/api/expenses', (req, res) => {
  const u = requireUser(req, res); if (!u) return;
  const c = cleanExpense(req.body || {}); if (c.error) return res.status(400).json({ error: c.error });
  const e = { id: crypto.randomUUID(), householdId: u.householdId, userId: u.id, ...c.value, createdAt: new Date().toISOString() };
  const err = bindReceipt(u, e, req.body.receiptId); if (err) return res.status(400).json({ error: err });
  db.expenses.push(e); saveDb(); res.json({ expense: expenseOut(e) });
});

// one-time upload of expenses that were saved in the browser before server storage existed
app.post('/api/expenses/import', (req, res) => {
  const u = requireUser(req, res); if (!u) return;
  const list = Array.isArray(req.body && req.body.expenses) ? req.body.expenses.slice(0, 5000) : [];
  const have = new Set(db.expenses.filter(e => e.userId === u.id && e.clientId).map(e => e.clientId));
  let added = 0;
  for (const raw of list) {
    const cid = String(raw.id || '').slice(0, 64);
    if (cid && have.has(cid)) continue;
    const c = cleanExpense(raw); if (c.error) continue;
    db.expenses.push({ id: crypto.randomUUID(), clientId: cid || undefined, householdId: u.householdId, userId: u.id, ...c.value, createdAt: new Date().toISOString() });
    if (cid) have.add(cid); added++;
  }
  if (added) saveDb();
  res.json({ added });
});

app.patch('/api/expenses/:id', (req, res) => {
  const u = requireUser(req, res); if (!u) return;
  const e = db.expenses.find(x => x.id === req.params.id && x.householdId === u.householdId);
  if (!e) return res.status(404).json({ error: 'Expense not found.' });
  if (e.userId !== u.id && ensureHousehold(u).ownerId !== u.id) return res.status(403).json({ error: 'Only the person who added it (or the household owner) can edit this.' });
  const c = cleanExpense(req.body || {}); if (c.error) return res.status(400).json({ error: c.error });
  const err = bindReceipt(u, e, req.body.receiptId); if (err) return res.status(400).json({ error: err });
  Object.assign(e, c.value, { updatedAt: new Date().toISOString() });
  saveDb(); res.json({ expense: expenseOut(e) });
});

app.delete('/api/expenses/:id', (req, res) => {
  const u = requireUser(req, res); if (!u) return;
  const e = db.expenses.find(x => x.id === req.params.id && x.householdId === u.householdId);
  if (!e) return res.status(404).json({ error: 'Expense not found.' });
  const h = ensureHousehold(u);
  if (e.userId !== u.id && h.ownerId !== u.id) return res.status(403).json({ error: 'Only the person who added it (or the household owner) can delete this.' });
  if (e.receiptId) dropReceipt(e.receiptId);
  db.expenses = db.expenses.filter(x => x !== e); saveDb(); res.json({ ok: true });
});

// Any error inside an /api route comes back as JSON (never an HTML error page)
app.use((err, req, res, next) => {
  console.error('API error on', req.method, req.path, err.type || '', err.message);
  if (res.headersSent) return next(err);
  const status = err.status || err.statusCode || 500;
  res.status(status).json({ error: status === 413 ? 'That photo is too large. Please try again.' : 'Server error (' + (err.type || err.message || status) + ').' });
});
process.on('unhandledRejection', e => console.error('Unhandled rejection:', e));

// Catch-all for SPA routing
app.get('*', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(indexContent);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Find My Expense is LIVE on http://localhost:${PORT}`);
  console.log(TEST_MODE ? '🧪 OTP TEST MODE (set TWOFACTOR_API_KEY to send real SMS)' : '📱 OTP via 2Factor.in');
  console.log(PERSISTENT ? `💾 Accounts stored in ${USERS_FILE}` : `⚠️  Accounts stored in ${USERS_FILE} — NOT persistent on Fly.io until a volume is mounted at /data`);
});
