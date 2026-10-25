// =============================================================================
//  VULNERABLE SERVER  —  csrf-lab/vulnerable/server.js
// -----------------------------------------------------------------------------
//  A deliberately insecure "bank" app. It authenticates users with a session
//  cookie and exposes a state-changing action (change-email) that is protected
//  by NOTHING except that cookie. Because the browser attaches the cookie to
//  EVERY request to this site — including requests triggered by a completely
//  different page — an attacker page can forge the request. That is CSRF.
//
//  Every deliberate weakness below is tagged `// VULN:` so it maps 1:1 to the
//  README's weaknesses table. The secure/ version fixes each one with `// FIX:`.
//
//  Runs on http://localhost:3000
// =============================================================================

const path = require('path');
const express = require('express');
const session = require('express-session');

const app = express();
const PORT = 3000;

// --- In-memory "database". No external DB to set up. -------------------------
const users = {
  alice: { username: 'alice', password: 'password123', email: 'alice@example.com' }
};

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Parse HTML form posts (application/x-www-form-urlencoded) — exactly what a
// cross-site <form> sends. We also accept JSON so the fetch() attack variant
// can be demonstrated.
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// --- Session / cookie configuration ------------------------------------------
app.use(session({
  name: 'sid',
  secret: 'vuln-lab-not-a-real-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: false,   // VULN: cookie is readable by JS (defense-in-depth lost). Not the CSRF hole itself, but bad hygiene.
    secure: false,     // VULN: sent over plain HTTP.
    // VULN: No CSRF-protective SameSite policy (no 'strict').
    //       NOTE: 'none' would be the "most vulnerable" setting, but browsers
    //       REJECT SameSite=None cookies unless they are also Secure (HTTPS).
    //       Since this lab runs on plain http://localhost, a 'none' cookie is
    //       silently dropped, which breaks login. We use 'lax' instead.
    //
    //       The attack still works because localhost:3000 and localhost:4000
    //       are the SAME SITE (browsers ignore the port for "site"), so Lax
    //       cookies are still sent on the forged request from :4000.
    //       Real-world cross-site CSRF is also possible via top-level form
    //       navigations (Lax allows cookies on top-level GET navigations).
    sameSite: 'lax'
  }
}));

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
  res.render('login', { error: null });
});

// POST /login — establish an authenticated session.
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users[username];
  if (!user || user.password !== password) {
    return res.status(401).render('login', { error: 'Invalid credentials' });
  }
  req.session.user = username;
  res.redirect('/account');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// GET /account — shows current state so the attack's effect is visible.
app.get('/account', requireLogin, (req, res) => {
  const user = users[req.session.user];
  res.render('account', { user });
});

// POST /account/change-email — the STATE-CHANGING action under attack.
app.post('/account/change-email', requireLogin, (req, res) => {
  // VULN: No CSRF token is expected or checked.
  // VULN: No Origin / Referer header is validated.
  // The server trusts the session cookie alone, so it cannot distinguish a
  // genuine submission of its own form from a forged cross-site request.
  const newEmail = req.body.email;
  if (!newEmail) return res.status(400).send('Email required');

  users[req.session.user].email = newEmail;

  // Reply differs slightly for form vs fetch so the demo is legible.
  if (req.is('application/json')) {
    return res.json({ ok: true, email: newEmail });
  }
  res.send(
    `<h2>Email updated to: ${newEmail}</h2>` +
    `<p><a href="/account">Back to account</a></p>`
  );
});

app.listen(PORT, () => {
  console.log(`[VULNERABLE] app listening on http://localhost:${PORT}`);
  console.log(`             login: alice / password123`);
});