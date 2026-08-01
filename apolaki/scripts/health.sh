#!/bin/sh
# Readiness check — "up" is not "ready". Reports each service; exits non-zero only if a CORE
# service (agent or Juice Shop) is down. The profile labs are optional and never fail the check.
set -u
core_fail=0

check() {   # url name core?
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "$1" 2>/dev/null)
  [ -z "$code" ] && code=000
  if [ "$code" -ge 200 ] && [ "$code" -lt 500 ]; then
    printf "  OK    %-12s %s (%s)\n" "$2" "$1" "$code"
  else
    printf "  DOWN  %-12s %s (%s)\n" "$2" "$1" "$code"
    [ "${3:-}" = "core" ] && core_fail=$((core_fail + 1))
  fi
}

echo "[health] service readiness:"
check "http://localhost:8000/health"     "apolaki"    core
check "http://localhost:42000/"          "juice-shop" core
check "http://localhost:42080/login.php" "dvwa"       opt
check "http://localhost:42088/"          "bwapp"      opt
check "http://localhost:42089/"          "mutillidae" opt

echo "[health] containers restart-looping (should be none):"
loops=$(docker compose --profile labs --profile browser --profile proxy --profile dast ps 2>/dev/null | grep -i 'restarting')
if [ -n "$loops" ]; then echo "$loops" | sed 's/^/  /'; else echo "  none"; fi

if [ "$core_fail" -eq 0 ]; then
  echo "[health] core OK."
else
  echo "[health] core NOT ready ($core_fail down)."
fi
[ "$core_fail" -eq 0 ]
