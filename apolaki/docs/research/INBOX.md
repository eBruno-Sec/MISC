# RESEARCH INBOX — raw, unfiltered

The Watcher appends here. The Analyst drains it into [../QUEUE.md](../QUEUE.md) and records
rejections there. Nothing in this file is a commitment; entries are hypotheses until distilled.

Every entry must carry: **problem solved · evidence and primary sources · Apolaki compatibility ·
expected benchmark or real-world benefit · false-positive risk · a concrete acceptance test.**
Tag each claim **MEASURED** (with the command and output) or **UNVERIFIED**. A disproved hypothesis
is a result — keep it, marked disproved.

---

## 2026-08-10 · Capability-gap sweep #1 — DRAINED into QUEUE Q-001…Q-008

**Measured inventory**: 88 engines (`run_*` in `agent/tools.py`), 85 finding families, technique
registry in `agent/techniques.py`, 109 hand-mapped WSTG tests in `agent/wstg_catalog.py`
(FULL/PARTIAL/EXCLUDED). Residual `none` set computed from the catalog and cross-checked against
live code rather than trusted from the table.

**Coverage verdicts**: ~90% of the PortSwigger Academy topic list. Zero-engine topics: HTTP request
smuggling, WebSockets, server-side prototype pollution, web messaging. OWASP API Top 10 2023: one
empty slot (API4 unrestricted resource consumption); API6 graph-reasoned only. OWASP Top 10 2021:
nothing structurally absent (A02 is the accepted crypto-visibility limit; A09 is not black-box
testable).

Six proposals distilled to **Q-001 … Q-006**; two defects to **Q-007 / Q-008**. Twelve expected gaps
checked and found **already covered** — recorded in QUEUE's `rejected` section so they are not
re-proposed.

---
