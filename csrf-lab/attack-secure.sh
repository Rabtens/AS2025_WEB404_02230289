#!/bin/bash
BASE=http://localhost:5000
JAR=/tmp/secure-jar.txt
rm -f $JAR

get_token() {
  grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//; s/"$//'
}

echo "===== ATTACK vs SECURE ($BASE) ====="

# Victim logs in. The secure server may require a CSRF token on /login too,
# so fetch the login page first and send its token if there is one.
LOGIN_TOKEN=$(curl -s -c $JAR -b $JAR $BASE/login | get_token)
echo "--- [1] victim logs in (login token: ${LOGIN_TOKEN:+found}${LOGIN_TOKEN:-none}) ---"
curl -si -c $JAR -b $JAR -X POST $BASE/login \
  -H "Origin: $BASE" \
  -d "username=alice&password=password123&_csrf=$LOGIN_TOKEN" | grep -E "HTTP/|Location"
echo

echo "--- [2] BEFORE: current email ---"
curl -s -c $JAR -b $JAR $BASE/account | grep current-email
echo

echo "--- [3a] FORGED POST: session cookie present, NO csrf token (mimics evil.html form) ---"
curl -si -c $JAR -b $JAR -X POST $BASE/account/change-email \
  -H "Origin: http://localhost:4000" \
  -d "email=attacker@evil.com" | grep -E "HTTP/|CSRF"
echo

echo "--- [3b] FORGED POST: attacker GUESSES a wrong token ---"
curl -si -c $JAR -b $JAR -X POST $BASE/account/change-email \
  -H "Origin: http://localhost:4000" \
  -d "email=attacker@evil.com&_csrf=0000000000000000000000000000000000000000000000000000000000000000" \
  | grep -E "HTTP/|CSRF"
echo

echo "--- [3c] FORGED POST with NO Origin/Referer header, missing token -> token check rejects ---"
curl -si -c $JAR -b $JAR -X POST $BASE/account/change-email \
  -d "email=attacker@evil.com" | grep -E "HTTP/|CSRF"
echo

echo "--- [4] AFTER attack attempts: email UNCHANGED ---"
curl -s -c $JAR -b $JAR $BASE/account | grep current-email
echo

echo "--- [5] LEGIT change from the real form (valid same-origin token) still works ---"
TOKEN=$(curl -s -c $JAR -b $JAR $BASE/account | get_token)
echo "      (token fetched from the real form: ${TOKEN:0:12}...)"
curl -si -c $JAR -b $JAR -X POST $BASE/account/change-email \
  -H "Origin: $BASE" \
  -d "email=alice.new@example.com&_csrf=$TOKEN" | grep -E "HTTP/|Email updated"
