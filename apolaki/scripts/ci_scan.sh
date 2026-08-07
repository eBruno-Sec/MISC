#!/bin/sh
# Apolaki CI security gate (Strix-borrow #111) — run a SCOPED deterministic scan of a staging URL from CI,
# poll to completion, then decide pass/fail via ci_summary.py and write an evidence-first PR comment.
#
# The engine enforces scope + no-DoS + no-credential-brute; NEVER point this at production. Intended for a
# disposable/staging deploy. auto_approve:true because CI is non-interactive (no operator at the HITL gate).
#
# Usage: sh scripts/ci_scan.sh <target_url> [out_comment.md]
# Env:   APOLAKI_API (default http://localhost:8000), APOLAKI_FAIL_ON (default critical,high),
#        APOLAKI_MAX_POLL (default 600 iterations x 2s), APOLAKI_AUTH (set 1 to run an authenticated scan)
set -u
A="${APOLAKI_API:-http://localhost:8000}"
TARGET="${1:?usage: ci_scan.sh <target_url> [out_comment.md]}"
OUT="${2:-apolaki_pr_comment.md}"
FAIL_ON="${APOLAKI_FAIL_ON:-critical,high}"
MAXP="${APOLAKI_MAX_POLL:-600}"
AUTH="${APOLAKI_AUTH:-0}"
authflag=""; [ "$AUTH" = "1" ] && authflag=',"authenticated_scan":true'

echo "[ci] engage deterministic scan of $TARGET (fail-on=$FAIL_ON)"
sid=$(curl -s -X POST "$A/engage" -H 'Content-Type: application/json' \
  -d "{\"program_name\":\"ci\",\"in_scope\":[\"$TARGET\"],\"mode\":\"active\",\"strategy\":\"deterministic\",\"auto_approve\":true$authflag}" \
  | grep -oE '"session_id":"[a-f0-9]+"' | head -1 | cut -d'"' -f4)
[ -z "$sid" ] && { echo "[ci] engage failed"; exit 2; }
echo "[ci] session $sid; running…"
curl -s -X POST "$A/run/$sid" >/dev/null 2>&1
i=0; st=""
while [ "$i" -lt "$MAXP" ]; do
  st=$(curl -s "$A/status/$sid" | grep -oE '"status":"[a-z_]+"' | head -1 | cut -d'"' -f4)
  case "$st" in complete | stopped | failed) break ;; esac
  i=$((i + 1)); sleep 2
done
[ "$st" != "complete" ] && { echo "[ci] scan did not complete (status=${st:-timeout})"; exit 2; }

# Decide the gate + write the PR comment. ci_summary exits 1 on a confirmed gating finding (fails the check).
echo "[ci] scan complete; evaluating gate"
MSYS_NO_PATHCONV=1 ${COMPOSE:-docker compose} exec -T agent \
  python ci_summary.py "$A" "$sid" --out "/app/$OUT" --fail-on "$FAIL_ON"
rc=$?
MSYS_NO_PATHCONV=1 ${COMPOSE:-docker compose} exec -T agent cat "/app/$OUT" > "$OUT" 2>/dev/null
echo "[ci] gate exit=$rc; comment -> $OUT"
exit $rc
