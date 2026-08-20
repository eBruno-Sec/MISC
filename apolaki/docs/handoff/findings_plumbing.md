# Q-053 · findings plumbing — the four gaps, re-measured before building

Lane: findings-plumbing (Builder). Baseline `8c7065c` — 3362 passed / 11 skipped / 12 xfailed / 0 failed.

**The ticket handed me four gaps and a warning that five tickets this week were wrong in scope. Three
of the four had commits against them. So the first result here is a re-measurement, not a build.**

---

## Measurement apparatus, and its positive control

Every number below is taken against the REAL findings corpus in the named volume, never a fixture:

    docker run --rm -v "apolaki_bbh_data:/data" ... python  # db.init('/data/bbh.db')

**Positive control (proves the apparatus was looking at the real DB, not an empty `/app/data`):**

    POSITIVE CONTROL: (1773, 154, 9691)      # findings, missions, exchanges

1773 findings and 154 missions match the ticket's stated control exactly. A bare `agent:/app` mount
returns `(0, 0, 0)` and every count below would have been a silent zero.

### Corpus baseline at HEAD `8c7065c`, before any edit of mine

    findings           : 1773
    objectives hit     : 11 / 33
    findings mapped    : 1026
    findings UNMAPPED  : 747

    families with NO objective at all (finding counts):
       weak_crypto                261
       weak_random                219
       weak_hash                  153
       trust_boundary              83
       security_misconfig          24
       open_redirect                6
       <no family key>              1

---

## STATE OF THE FOUR GAPS — measured, not read

| Gap | Ticket says | MEASURED at `8c7065c` | Verdict |
| --- | --- | --- | --- |
| GAP-1 `takeover` | detected, never reportable | producer **landed** (`fb6f457`); consumer half **never landed** | **HALF-LANDED — real work remains, in my files** |
| GAP-2 dalfox | no `family` at all | still no family; fix site is `tools.py` | **LIVE — handoff patch (file not mine)** |
| GAP-3 `sqli` auth bypass | mislabelled | **fixed** (`7ce79bb` + `44a6cbf`) | **DISPROVED as open** |
| GAP-4 transport families | one family, three properties | still one ternary; 24 real findings affected | **LIVE — both halves in my files** |

`docs/QUEUE.md:172` claims Q-053 closed "all four family gaps" against four commits. **That claim is
wrong on two of the four.** The four commits are GAP-3 (`7ce79bb`), GAP-1's producer (`fb6f457`),
GAP-4's *evidence* defect (`7fbd1bf` — a different defect the lane found while in the file, not the
family split the gap describes), and the AUTHN-02 consumer (`44a6cbf`). **No commit in the tree
references GAP-2 at all.**

---

## GAP-1 · the producer landed and the consumer never did

`fb6f457` added `ToolRegistry._takeover_finding` (`agent/tools.py:6455`), which stamps
`family = "takeover"`, and `check_takeover` is in `agent._AUTO_STORE_TOOLS`, so detection → family →
store is real and is already pinned by `tests/test_finding_provenance.py`.

**What nobody tested is `assess()`.** The existing tests stop at `map_findings`. MEASURED:

    POSITIVE CONTROL objectives loaded: 33
    takeover finding + engine ran  -> failed | reason: check_takeover yields recon CANDIDATES, not fin…
    CLEAN run, engine RAN          -> not_implemented | engine field: n/a
    engine never ran               -> not_implemented

Three separate defects in that output, all reader-facing:

1. **A FAILED objective still carries `not_implemented_reason`**, and the reason is now false in both
   of its clauses: `check_takeover` *does* yield findings, and they *do* carry a family. The row tells
   a reader "we found this" and "we have no engine for this, our detector returns no family" at once.
2. **`verified` is unreachable.** A clean `check_takeover` run reports `not_implemented` — the report
   declares the PRODUCT lacks a capability that exists, ran, and was clean. That is the flattering
   direction of a false statement, which is the one that does not get noticed.
3. **`not_implemented` no longer discriminates.** Rows 2 and 3 are identical, so "we have no engine"
   and "we did not run it" are indistinguishable — the exact distinction `report.coverage_rollup`
   gives its own bucket to, citing Q-012, one layer up.

`engine: NO_ENGINE` also renders as `n/a` in the objective table while `check_takeover` is a real
dispatchable tool carried in the auto-store set.

## GAP-4 · one ternary, three properties, and 24 real findings behind it

`agent/transport_posture.py:404` is still, unchanged:

    "family": "transport_posture" if kind in ("tls", "cert") else "security_misconfig",

`kind` takes five values — `tls`, `cert`, `cookie`, `header`, `methods` — so cookie, header and
methods share one label. MEASURED against the real corpus:

    security_misconfig by transport kind: {'cookie': 4, 'header': 20}

    Session cookie without a restrictive SameSite  4     <- cookie hardening
    No Content-Security-Policy                     4     <- header hygiene
    HSTS not enabled on an HTTPS origin            4
    MIME sniffing not disabled                     4
    No Referrer-Policy                             4
    No Permissions-Policy                          4

And the consequence, measured:

    security_misconfig   -> []      # NO objective keys on it
    transport_posture    -> []      # NO objective keys on it
    insecure_cookie      -> ['SESS-02']

**All 24 are invisible to the entire ASVS model**, including 4 genuine session-cookie hardening
findings against a real target. SESS-02 was deliberately narrowed by Q-048 to `insecure_cookie` and
explicitly REFUSED `security_misconfig`, because a missing Permissions-Policy would then fail "session
cookies carry Secure" (`asvs_model.py:127-131`). That refusal was correct and it left the 4 stranded.
