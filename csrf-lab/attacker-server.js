// Tiny static host for the attacker page, so evil.html is served from a REAL
// different origin (http://localhost:4000) rather than a file:// URL. This makes
// the demo a genuine CROSS-SITE request, which is the whole point of CSRF.
//
//   node attacker-server.js   ->   http://localhost:4000/evil.html
//
// (You could equally use `npx serve attacker -l 4000` or Python's http.server;
//  this keeps the lab dependency-free beyond what package.json already lists.)

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 4000;
const file = path.join(__dirname, 'attacker', 'evil.html');

http.createServer((req, res) => {
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(500); return res.end('cannot read evil.html'); }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(buf);
  });
}).listen(PORT, () => {
  console.log(`[ATTACKER] evil.html served at http://localhost:${PORT}/evil.html`);
});
