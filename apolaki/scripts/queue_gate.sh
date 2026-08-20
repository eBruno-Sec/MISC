#!/usr/bin/env bash
# queue_gate.sh -- integrity checks on docs/QUEUE.md.
#
# WHY THIS EXISTS
# Closing a ticket and updating its header are two actions, and only one of them was ever enforced.
# Ten separate sweeps have found headers reading `ready` on tickets whose closing commit was already
# in history. Worse, the file grew a second copy of some tickets: Q-020 read **CLOSED** in one place
# and `proposed` in another, in the same file, at the same time. A reader has no way to tell which
# record is the live one, and neither did I.
#
# This gate checks FACTS about the file, not declarations inside it:
#
#   1. Every commit hash a ticket header cites exists in git history.
#      (Fabricated hashes are not hypothetical here -- a lane wrote invented hashes into a handoff
#      before measuring anything and caught itself minutes before being killed.)
#   2. No ticket ID carries two headers whose states CONTRADICT: one closed, one open.
#      Duplicate headers are allowed only when they agree, since a long file legitimately carries a
#      summary line and the full body.
#
# It deliberately does NOT check "a CLOSED header must cite a hash". That was measured first: some
# tickets are closed by a fix that landed inside another ticket's commit, and demanding a hash there
# would push people to paste an approximate one. A wrong hash is worse than no hash.
#
# Run:  bash scripts/queue_gate.sh              (from the repo, any cwd)
#       bash scripts/queue_gate.sh --self-test  (positive control: prove the checks can fail)
#
# Exit 0 clean, 1 violations found, 2 the gate itself could not run.

set -u

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(dirname "$here")"
QUEUE="${QUEUE_FILE:-$repo/docs/QUEUE.md}"

# ------------------------------------------------------------------------ positive control
# A gate that has never failed is indistinguishable from a gate that cannot fail. This project has
# shipped four of those. --self-test plants each violation into a COPY and requires the gate to
# catch it; it also requires the clean copy to pass, so "always fails" is not a way to pass either.
if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  rc=0

  # control A: the real file, unmodified, must PASS (or the planted-violation results mean nothing)
  QUEUE_FILE="$QUEUE" bash "${BASH_SOURCE[0]}" >"$tmp/a.out" 2>&1
  if [ $? -ne 0 ]; then
    echo "self-test FAIL: the unmodified queue does not pass, so no planted result is meaningful"
    sed 's/^/    /' "$tmp/a.out"
    rc=1
  else
    echo "self-test  control A (unmodified queue passes)                  ok"
  fi

  # control B: a fabricated hash must be CAUGHT
  printf '### Q-999 - planted - **CLOSED** `%s`\n' "deadbeefdead" >"$tmp/b.md"
  QUEUE_FILE="$tmp/b.md" bash "${BASH_SOURCE[0]}" >"$tmp/b.out" 2>&1
  if grep -q 'hash-not-in-history' "$tmp/b.out"; then
    echo "self-test  control B (fabricated hash is caught)                ok"
  else
    echo "self-test FAIL: a fabricated hash passed the gate"; sed 's/^/    /' "$tmp/b.out"; rc=1
  fi

  # control C: one ticket, two headers, opposite states, must be CAUGHT
  { printf '### Q-998 - planted - **CLOSED**\n'; printf '### Q-998 - planted again - `ready`\n'; } >"$tmp/c.md"
  QUEUE_FILE="$tmp/c.md" bash "${BASH_SOURCE[0]}" >"$tmp/c.out" 2>&1
  if grep -q 'contradictory-duplicate' "$tmp/c.out"; then
    echo "self-test  control C (closed-and-open duplicate is caught)      ok"
  else
    echo "self-test FAIL: a ticket that is both CLOSED and ready passed"; sed 's/^/    /' "$tmp/c.out"; rc=1
  fi

  # control D: two headers that AGREE must NOT be flagged -- otherwise check 2 is just a dup counter
  { printf '### Q-997 - planted - **CLOSED**\n'; printf '### Q-997 - planted body - **CLOSED**\n'; } >"$tmp/d.md"
  QUEUE_FILE="$tmp/d.md" bash "${BASH_SOURCE[0]}" >"$tmp/d.out" 2>&1
  if grep -q 'contradictory-duplicate' "$tmp/d.out"; then
    echo "self-test FAIL: agreeing duplicates were flagged; check 2 cannot tell states apart"
    sed 's/^/    /' "$tmp/d.out"; rc=1
  else
    echo "self-test  control D (agreeing duplicates are not flagged)      ok"
  fi

  # control E: the letter-suffixed family must NOT read as duplicates of its base id
  { printf '### Q-996 - planted - `ready`\n'; printf '### Q-996B - planted - **CLOSED**\n'; } >"$tmp/e.md"
  QUEUE_FILE="$tmp/e.md" bash "${BASH_SOURCE[0]}" >"$tmp/e.out" 2>&1
  if grep -q 'contradictory-duplicate' "$tmp/e.out"; then
    echo "self-test FAIL: Q-996B was treated as Q-996; the id regex is a prefix match"
    sed 's/^/    /' "$tmp/e.out"; rc=1
  else
    echo "self-test  control E (Q-NNNx is a distinct ticket)              ok"
  fi

  [ $rc -eq 0 ] && echo "self-test: OK" || echo "self-test: FAIL"
  exit $rc
fi

if [ ! -f "$QUEUE" ]; then
  echo "queue_gate: cannot read $QUEUE" >&2
  exit 2
fi
if ! git -C "$repo" rev-parse --git-dir >/dev/null 2>&1; then
  echo "queue_gate: $repo is not inside a git work tree; cannot verify hashes" >&2
  exit 2
fi
# A shallow clone has none of the older commits, so check 1 fails on EVERY cited hash for a reason
# that has nothing to do with the queue. MEASURED: `git clone --depth 1` of this repo produces 45 of
# 45 "hash-not-in-history" failures. Someone acting on that output would go and "fix" 45 hashes that
# were never wrong. Exit 2 (cannot run) rather than 1 (violations found) -- the distinction between
# a failed check and an unrunnable one is the entire subject of this queue.
if [ "$(git -C "$repo" rev-parse --is-shallow-repository 2>/dev/null)" = "true" ]; then
  echo "queue_gate: shallow clone -- hashes cannot be resolved. Use fetch-depth: 0 (CI) or a full clone." >&2
  exit 2
fi

# A ticket ID is Q-NNN with an OPTIONAL letter suffix. Q-021B is a DIFFERENT ticket from Q-021, and
# a prefix match reports five phantom duplicates for the Q-021 family. Measured, not assumed.
ID_RE='Q-[0-9]{3}[A-Z]?'
HDR_RE="^#{1,3} $ID_RE"

headers="$(grep -nE "$HDR_RE" "$QUEUE" || true)"
if [ -z "$headers" ]; then
  echo "queue_gate: no ticket headers matched in $QUEUE -- the parser is broken, not the file" >&2
  exit 2
fi

n_hdr=$(printf '%s\n' "$headers" | wc -l | tr -d ' ')
violations=0

# ---------------------------------------------------------------- check 1: cited hashes are real
n_hash=0
while IFS= read -r h; do
  [ -z "$h" ] && continue
  n_hash=$((n_hash + 1))
  if [ "$(git -C "$repo" cat-file -t "$h" 2>/dev/null)" != "commit" ]; then
    line="$(printf '%s\n' "$headers" | grep -m1 -F "\`$h\`" | cut -d: -f1)"
    echo "FAIL  hash-not-in-history  QUEUE.md:${line:-?}  cites \`$h\`, which is not a commit"
    violations=$((violations + 1))
  fi
done <<EOF
$(printf '%s\n' "$headers" | grep -oE '`[0-9a-f]{7,40}`' | tr -d '`' | sort -u)
EOF

# ------------------------------------------------- check 2: duplicate headers must not contradict
# "closed" is any header whose text carries CLOSED (in any casing/emphasis). "open" is any header
# carrying a `ready` / `proposed` / `in flight` state marker. A header can be neither; that is fine.
ids="$(printf '%s\n' "$headers" | sed -E "s/^[0-9]+:#{1,3} ($ID_RE).*/\1/" | sort -u)"
n_dup=0
for id in $ids; do
  same="$(printf '%s\n' "$headers" | grep -E "^[0-9]+:#{1,3} $id( |\$)" || true)"
  [ "$(printf '%s\n' "$same" | wc -l | tr -d ' ')" -lt 2 ] && continue
  n_dup=$((n_dup + 1))
  closed=$(printf '%s\n' "$same" | grep -ci 'CLOSED' || true)
  open=$(printf '%s\n'   "$same" | grep -ciE '`(ready|proposed|in flight)`' || true)
  if [ "$closed" -gt 0 ] && [ "$open" -gt 0 ]; then
    echo "FAIL  contradictory-duplicate  $id has $closed closed header(s) and $open open header(s):"
    printf '%s\n' "$same" | sed 's/^/        QUEUE.md:/' | cut -c1-140
    violations=$((violations + 1))
  fi
done

echo "queue_gate: $n_hdr headers, $n_hash distinct hashes cited, $n_dup ids with >1 header"
if [ "$violations" -gt 0 ]; then
  echo "queue_gate: FAIL ($violations violation(s))"
  exit 1
fi
echo "queue_gate: OK"
exit 0
