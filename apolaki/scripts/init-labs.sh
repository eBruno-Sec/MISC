#!/bin/sh
# Idempotent one-time initialization for the cross-validation labs. Safe to re-run.
# DVWA needs its CSRF user_token to create the DB; bWAPP + Mutillidae are simple GETs.
set -u
echo "[init-labs] initializing lab databases (idempotent)..."

wait_http() {   # url name tries
  i=0
  while [ "$i" -lt "${3:-30}" ]; do
    if curl -fsS -o /dev/null --max-time 3 "$1" 2>/dev/null; then return 0; fi
    i=$((i + 1)); sleep 2
  done
  echo "[init-labs] WARN: $2 not reachable at $1 (skipping)"; return 1
}

# bWAPP — creates the MySQL schema
if wait_http "http://localhost:42088/install.php" "bWAPP" 30; then
  curl -fsS -o /dev/null --max-time 20 "http://localhost:42088/install.php?install=yes" 2>/dev/null \
    && echo "[init-labs] bWAPP schema created (login bee/bug, security=low)"
fi

# Mutillidae — builds the MySQL schema
if wait_http "http://localhost:42089/" "Mutillidae" 30; then
  curl -fsS -o /dev/null --max-time 25 "http://localhost:42089/set-up-database.php" 2>/dev/null \
    && echo "[init-labs] Mutillidae schema built"
fi

# DVWA — create_db needs the CSRF user_token read from setup.php
if wait_http "http://localhost:42080/setup.php" "DVWA" 30; then
  jar=$(mktemp)
  token=$(curl -fsS -c "$jar" --max-time 10 "http://localhost:42080/setup.php" 2>/dev/null \
          | grep -oE "user_token'[^>]*value='[a-f0-9]+" | grep -oE "[a-f0-9]+$" | head -1)
  if [ -n "${token:-}" ]; then
    curl -fsS -o /dev/null -b "$jar" --max-time 25 \
      --data "create_db=Create+%2F+Reset+Database&user_token=${token}" \
      "http://localhost:42080/setup.php" 2>/dev/null \
      && echo "[init-labs] DVWA database created"
    # auto-set DVWA Security = Low (log in admin/password, then POST the security level)
    lt=$(curl -fsS -c "$jar" --max-time 10 "http://localhost:42080/login.php" 2>/dev/null \
         | grep -oE "user_token'[^>]*value='[a-f0-9]+" | grep -oE "[a-f0-9]+$" | head -1)
    if [ -n "${lt:-}" ]; then
      curl -fsS -o /dev/null -b "$jar" -c "$jar" --max-time 10 \
        --data "username=admin&password=password&Login=Login&user_token=${lt}" \
        "http://localhost:42080/login.php" 2>/dev/null
      st=$(curl -fsS -b "$jar" --max-time 10 "http://localhost:42080/security.php" 2>/dev/null \
           | grep -oE "user_token'[^>]*value='[a-f0-9]+" | grep -oE "[a-f0-9]+$" | head -1)
      if [ -n "${st:-}" ]; then
        curl -fsS -o /dev/null -b "$jar" --max-time 10 \
          --data "security=low&seclev_submit=Submit&user_token=${st}" \
          "http://localhost:42080/security.php" 2>/dev/null \
          && echo "[init-labs] DVWA security set to Low"
      fi
    fi
  else
    echo "[init-labs] WARN: could not read DVWA user_token — open http://localhost:42080/setup.php and click 'Create / Reset Database'"
  fi
  rm -f "$jar"
fi
echo "[init-labs] done."
