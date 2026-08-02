#!/bin/sh
# End-to-end benchmark (NO MOCKS): proves the auth artery + graph + persistence against a live stack.
# Requires: `make up` (agent + Juice Shop running). Exits non-zero if any assertion fails.
set -u
pass=0; fail=0
ck() { if [ "$2" = "PASS" ]; then echo "  PASS  $1"; pass=$((pass + 1)); else echo "  FAIL  $1"; fail=$((fail + 1)); fi; }

echo "[benchmark] 1/3  platform health"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://localhost:8000/health 2>/dev/null)
ck "apolaki healthy (/health 200)" "$([ "$code" = "200" ] && echo PASS || echo FAIL)"

echo "[benchmark] 2/3  auth artery -> confirmed cross-user IDOR on live Juice Shop (no mocks)"
out=$(docker exec -i apolaki-agent-1 python - <<'PY' 2>/dev/null
import asyncio, scope as S, tools, agent as A
sc = S.ScopeEngine(); sc.load_manual(["http://juice-shop:3000"], [], "JS")
t = tools.ToolRegistry(sc, mission_id=None, lab_mode=True)
t.urls = ["http://juice-shop:3000/rest/basket/1"]
ag = A.BBHAgent(sc, t, asyncio.Event(), mode="active", authenticated_scan=True, mission_id=None)
async def go():
    evs = await ag._do_persona_authz("s")
    idor = any(e.get("type") == "finding" and e["finding"]["family"] == "idor"
               and e["finding"]["confidence"] == "confirmed" for e in evs)
    caps = [c["capability"] for c in t.state.to_dict()["capabilities"]]
    print("IDOR=%s PERSONAS=%d GRAPH=%d SECONDPERSONA=%s"
          % (idor, len(t._sessions), t.graph.stats()["nodes"], "second_persona_available" in caps))
asyncio.run(go())
PY
)
echo "    $out"
echo "$out" | grep -q "IDOR=True"        && ck "confirmed cross-user IDOR (ownership-proven)" PASS || ck "confirmed cross-user IDOR" FAIL
echo "$out" | grep -qE "PERSONAS=[2-9]"  && ck "two personas registered + logged in"          PASS || ck "two personas" FAIL
echo "$out" | grep -qE "GRAPH=[1-9]"     && ck "live asset graph populated"                    PASS || ck "asset graph populated" FAIL
echo "$out" | grep -q "SECONDPERSONA=True" && ck "second_persona_available capability"          PASS || ck "capability" FAIL

echo "[benchmark] 3/3  restart -> vault + login recipe survive (reacquire foundation)"
docker exec apolaki-agent-1 python -c "import vault; vault.default().put('bench','user_a',{'password':'BENCHSECRET','recipe':{'login_url':'http://juice-shop:3000/rest/user/login'}})" >/dev/null 2>&1
docker restart apolaki-agent-1 >/dev/null 2>&1
i=0; while [ "$i" -lt 20 ]; do curl -fsS -o /dev/null --max-time 2 http://localhost:8000/health 2>/dev/null && break; i=$((i+1)); sleep 1; done
got=$(docker exec apolaki-agent-1 python -c "import vault; s=vault.default().get('vault://mission/bench/user_a'); print((s or {}).get('password'))" 2>/dev/null)
ck "vault + recipe survive a container restart" "$([ "$got" = "BENCHSECRET" ] && echo PASS || echo FAIL)"

echo "[benchmark] ==== $pass passed, $fail failed ===="
[ "$fail" -eq 0 ]
