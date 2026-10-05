const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const indexPath = path.join(__dirname, 'index.html');
const indexContent = fs.readFileSync(indexPath, 'utf8');

app.set('trust proxy', true);
app.use(express.json());

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

app.get('/api/otp/status', (req, res) => res.json({ testMode: TEST_MODE, persistent: PERSISTENT }));

app.post('/api/otp/send', async (req, res) => {
  const phone = normalizePhone(req.body && req.body.phone);
  if (!phone) return res.status(400).json({ error: 'Enter a valid 10-digit Indian mobile number.' });
  const purpose = req.body.purpose === 'login' ? 'login' : 'signup';
  if (purpose === 'signup' && findByPhone(phone)) return res.status(409).json({ error: 'This number is already registered. Please log in instead.', code: 'EXISTS' });
  if (purpose === 'login' && !findByPhone(phone)) return res.status(404).json({ error: 'No account found for this number. Please sign up first.', code: 'NOT_FOUND' });

  const ip = req.ip || 'unknown';
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
  db.users.push(u); saveDb();
  console.log(`👤 New account: ••${u.phone.slice(-4)}`);
  res.json(sessionFor(u));
});

app.post('/api/login/password', (req, res) => {
  const id = String((req.body && req.body.identifier) || '').trim();
  const password = String((req.body && req.body.password) || '');
  const key = id.toLowerCase(), ipKey = 'ip:' + (req.ip || '');
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
