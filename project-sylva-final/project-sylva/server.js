require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const PASSWORD = process.env.SITE_PASSWORD || 'change-this-before-deploying';
const SECRET = process.env.SESSION_SECRET || 'development-only-change-this-secret';
const COOKIE = 'sylva_access';

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});
app.use(express.json({ limit: '20kb' }));

const loginAttempts = new Map();
function loginRateLimit(req, res, next) {
  const key = req.ip;
  const now = Date.now();
  const recent = (loginAttempts.get(key) || []).filter(t => now - t < 10 * 60 * 1000);
  if (recent.length >= 12) return res.status(429).json({ error: 'Too many tries. Please wait a little before trying again.' });
  recent.push(now);
  loginAttempts.set(key, recent);
  next();
}

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function validToken(token) {
  if (!token || !token.includes('.')) return false;
  const [body, signature] = token.split('.');
  const expected = crypto.createHmac('sha256', SECRET).update(body).digest();
  let actual;
  try { actual = Buffer.from(signature, 'base64url'); } catch { return false; }
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return false;
  try {
    const data = JSON.parse(Buffer.from(body, 'base64url').toString());
    return data.exp > Date.now();
  } catch { return false; }
}
function isAuthed(req) { return validToken(req.headers.cookie?.split(';').map(x => x.trim()).find(x => x.startsWith(COOKIE + '='))?.slice(COOKIE.length + 1)); }
function requireAuth(req, res, next) {
  if (isAuthed(req)) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Please unlock the experience again.' });
  return res.redirect('/login');
}

app.get('/login', (req, res) => {
  if (isAuthed(req)) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.post('/api/login', loginRateLimit, (req, res) => {
  const attempt = String(req.body?.password || '');
  const a = Buffer.from(attempt);
  const b = Buffer.from(PASSWORD);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'Not quite, potato. Try again.' });
  const token = sign({ exp: Date.now() + 12 * 60 * 60 * 1000 });
  res.cookie(COOKIE, token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/' });
  res.json({ ok: true });
});
app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/' });
  res.json({ ok: true });
});
app.get('/api/session', (req, res) => res.json({ authenticated: isAuthed(req) }));
app.get('/health', (req, res) => res.status(200).send('ok'));

// Everything in the experience, including its photographs and videos, is served only after authentication.
app.use(requireAuth);
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', etag: true, maxAge: '1h' }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`Project Sylva listening on ${PORT}`));
