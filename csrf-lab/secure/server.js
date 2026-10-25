// =============================================================================
//  SECURE SERVER  —  csrf-lab/secure/server.js
// -----------------------------------------------------------------------------
//  The SAME app as vulnerable/server.js, but the CSRF hole is closed. Each
//  defense is tagged `// FIX:` and maps 1:1 to a `// VULN:` in the vulnerable
//  build and to a row in the README's mitigation table.
//
//  Primary defense: a hand-rolled SYNCHRONIZER TOKEN (a.k.a. anti-CSRF token).
//    - Server mints a random token, stores it in the session, and embeds it as
//      a hidden field in every state-changing form.
//    - On POST the submitted token must equal the session token, compared in
//      constant time. Missing/wrong -> 403.
//    - An attacker's cross-site page cannot read the victim's session token
//      (Same-Origin Policy), so it cannot forge a valid submission.
//
//  We use a hand-rolled token ON PURPOSE. The popular `csurf` middleware is
//  DEPRECATED and no longer maintained, so rolling the synchronizer pattern by
//  hand (it is ~15 lines) is both safer to depend on and more instructive.
//
//  Defense-in-depth added alongside the token:
//    - SameSite=Lax + HttpOnly + (Secure-ready) cookie attributes.
//    - Origin/Referer allow-list check on unsafe methods.
//
//  Runs on http://localhost:5000
// =============================================================================

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');

const app = express();
const PORT = 5000;
const SELF_ORIGIN = `http://localhost:${PORT}`;

const users = {
  alice: { username: 'alice', password: 'password123', email: 'alice@example.com' }
};

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({
  name: 'sid',
  secret: 'secure-lab-not-a-real-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    // FIX: HttpOnly keeps the session cookie out of reach of JavaScript (blunts
    //      XSS-assisted token theft — defense in depth).
    httpOnly: true,
    // FIX: In production set secure:true so the cookie is HTTPS-only. Left false
    //      here only because the lab runs on plain http://localhost.
    secure: false,
    // FIX: SameSite=Lax stops the cookie from being attached to cross-site POSTs
    //      (and to top-level cross-site requests that use unsafe methods). This
    //      alone defeats the classic auto-submitting <form> attack in modern
    //      browsers — but we still require the token below, because SameSite is
    //      a browser behaviour we cannot rely on universally (old browsers,
    //      certain navigations, misconfig), and the token is the real guarantee.
    sameSite: 'lax'
  }
}));

// --- Synchronizer token helpers ----------------------------------------------

// FIX: mint a cryptographically-random per-session token, created lazily.
function getCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  return req.session.csrfToken;
}

// FIX: constant-time comparison so we don't leak the token via timing.
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// FIX: verify token on every state-changing request. Accept it from a hidden
//      form field (_csrf) or, for the fetch()/AJAX case, an X-CSRF-Token header.
function verifyCsrf(req, res, next) {
  // FIX: belt-and-braces Origin/Referer allow-list. Cheap, and catches forged
  //      requests even before we look at the token.
  const origin = req.get('origin') || req.get('referer');
  if (origin && !origin.startsWith(SELF_ORIGIN)) {
    return res.status(403).send('CSRF check failed: cross-origin request rejected (bad Origin/Referer)');
  }

  const sent = req.body._csrf || req.get('x-csrf-token');
  const expected = req.session.csrfToken;
  if (!expected || !safeEqual(sent, expected)) {
    return res.status(403).send('CSRF check failed: invalid or missing CSRF token');
  }
  next();
}

// --- Auth guard --------------------------------------------------------------
function requireLogin(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect('/login');
}

// --- Routes ------------------------------------------------------------------

app.get('/', (req, res) => {
  res.redirect(req.session.user ? '/account' : '/login');
});

app.get('/login', (req, res) => {
  // Token embedded in the login form too, so even login is CSRF-safe.
  res.render('login', { error: null, csrfToken: getCsrfToken(req) });
});

app.post('/login', verifyCsrf, (req, res) => {
  const { username, password } = req.body;
  const user = users[username];
  if (!user || user.password !== password) {
    return res.status(401).render('login', { error: 'Invalid credentials', csrfToken: getCsrfToken(req) });
  }
  req.session.user = username;
  res.redirect('/account');
});

app.post('/logout', verifyCsrf, (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/account', requireLogin, (req, res) => {
  const user = users[req.session.user];
  // FIX: hand the current token to the template so it can be embedded.
  res.render('account', { user, csrfToken: getCsrfToken(req) });
});

// POST /account/change-email — now guarded by verifyCsrf.
app.post('/account/change-email', requireLogin, verifyCsrf, (req, res) => {
  const newEmail = req.body.email;
  if (!newEmail) return res.status(400).send('Email required');
  users[req.session.user].email = newEmail;

  if (req.is('application/json')) {
    return res.json({ ok: true, email: newEmail });
  }
  res.send(
    `<h2>Email updated to: ${newEmail}</h2>` +
    `<p><a href="/account">Back to account</a></p>`
  );
});

app.listen(PORT, () => {
  console.log(`[SECURE] app listening on http://localhost:${PORT}`);
  console.log(`         login: alice / password123`);
});
