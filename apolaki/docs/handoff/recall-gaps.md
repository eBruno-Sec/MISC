# Builder lane - recall gaps (defect 1) and falsy credential-probe target (defect 2)

Lane: BUILDER. Written as I go. Every row is MEASURED (command + real output) or UNVERIFIED.
Source of the two defects: `docs/handoff/breaker-v16.md` sections 6.2 and 4.1, mission `bed9ffcd`,
target `http://mutillidae` (compose hostname, reachable only from inside the apolaki docker network).

Write set for this lane: this file, `agent/agent.py`, `agent/exposure_tool.py`,
`agent/tests/test_autoindex_discovery.py`, `agent/tests/test_credential_probe_target.py`.

STATUS: in progress.

## 0. Plan

1. Reproduce defect 1 (recall gap on `/passwords/accounts.txt`) and MEASURE which of the three
   candidate causes is the real one.
2. Reproduce defect 2 (falsy default at `agent/agent.py` ~1928).
3. Fix, mutation-test both fixes plus both over-correction mutants.

---

## 1. DEFECT 1 - REPRODUCED. Root cause MEASURED, and it is NOT what I would have guessed.

Every step of the harvest chain ALREADY WORKS. The engine has a browsable-directory harvester
(`tools.py::_run_dir_harvest` -> `exposure_tool.looks_like_listing` / `parse_listing` /
`is_harvestable` / `_SENSITIVE_SIG`). Fed the listing by hand, it does the right thing at every
stage. It was never fed the listing.

Command (read-only, inside the shared container):

```
MSYS_NO_PATHCONV=1 docker exec -i apolaki-agent-1 python - <<'PY'
import sys; sys.path.insert(0,'/app')
import httpx, exposure_tool as exp
c = httpx.Client(timeout=25, follow_redirects=True)
r = c.get("http://mutillidae/passwords/?C=N;O=D")
print("GET /passwords/?C=N;O=D ->", r.status_code, "len=%d" % len(r.text))
print("looks_like_listing:", exp.looks_like_listing(r.text))
print("parse_listing     :", exp.parse_listing(r.text))
for fp in exp.parse_listing(r.text):
    print("   is_harvestable(%r) = %s" % (fp, exp.is_harvestable(fp)))
f = c.get("http://mutillidae/passwords/accounts.txt")
print("GET accounts.txt ->", f.status_code, "len=%d" % len(f.text))
print("_SENSITIVE_SIG match:", bool(exp._SENSITIVE_SIG.search(f.text)))
print("DIR_CANDIDATES     :", exp.DIR_CANDIDATES)
print("'passwords' in it  :", "passwords" in exp.DIR_CANDIDATES)
print(".txt in _HARVEST_EXT:", ".txt" in exp._HARVEST_EXT)
PY
```

Real output:

```
GET /passwords/?C=N;O=D -> 200 len=946
looks_like_listing: True
parse_listing     : ['accounts.txt']
   is_harvestable('accounts.txt') = True
GET accounts.txt -> 200 len=929
_SENSITIVE_SIG match: True
DIR_CANDIDATES     : ['ftp', 'uploads', 'upload', 'files', 'file', 'backup', 'backups', 'download',
                      'downloads', 'data', 'public', 'static', 'encryptionkeys', 'attachments',
                      'documents', 'media']
'passwords' in it  : False
.txt in _HARVEST_EXT: True
```

### 1.1 The three candidate causes, adjudicated

| Candidate cause from the brief | Verdict | Deciding measurement |
|---|---|---|
| "content discovery only tries a fixed wordlist and never follows links found in an autoindex listing" | **CONFIRMED - this is the cause** | `_run_dir_harvest` iterates `exp.DIR_CANDIDATES[:20]` and nothing else. 16 hardcoded names; `passwords` is not one. The observed listing is never an input to the engine. |
| "the exposure engine only flags a fixed set of filenames" | TRUE of the *other* engine, NOT the cause here | `EXPOSURE_CHECKS` is 15 fixed paths (`.git/HEAD`, `.env`, ...). But `_run_dir_harvest` is already content-driven and does not use that list, so this is not what suppressed the file. |
| "a static-extension filter that skips `.txt`" | **DISPROVED** | `.txt in _HARVEST_EXT` -> `True`. `is_harvestable('accounts.txt')` -> `True`. `.txt` was never filtered. |

### 1.2 The mission HAD the listing. Measured from its own database.

```
MSYS_NO_PATHCONV=1 docker exec -i apolaki-agent-1 python - <<'PY'
import sqlite3
c=sqlite3.connect('file:/app/data/bbh.db?mode=ro', uri=True)
n=0
for row in c.execute("SELECT * FROM exchanges WHERE mission_id='bed9ffcd'"):
    if "/passwords" in str(row): n+=1
print("exchange rows mentioning /passwords:", n)
PY
```

```
exchange rows mentioning /passwords: 3
   HIT: ... '{"url": "http://mutillidae/passwords/?C", ...
   HIT: ... '{"url": "http://mutillidae/passwords/?C", ...
   HIT: ... '{"url": "http://mutillidae/passwords/?C=N;O=D", ...
```

So the fetch happened three times. Every downstream stage would have said yes. The engine's only
source of directories to harvest is a 16-word list written by hand, so a directory the crawler
actually walked is invisible to it. **A directory listing we already fetched is a list of real
files, and the harvester never sees it.**

### 1.3 A SECOND, independent defect found while measuring: the content oracle is unsound BOTH ways

`_SENSITIVE_SIG` is a substring regex (`password|passwd|secret|api[_-]?key|...`). Measured on four
real bodies across three labs:

```
  mutillidae/passwords/accounts.txt              SENSITIVE=True  match='password'
  mutillidae/robots.txt                          SENSITIVE=True  match='password'
  bwapp/robots.txt                               SENSITIVE=True  match='password'
  dvwa/robots.txt                                SENSITIVE=False match=''
```

- **False positive:** `robots.txt` on two of three labs matches, because it contains
  `Disallow: /passwords/`. A robots file is not a credential exposure. Had `passwords` merely been
  added to the wordlist, the engine would have shipped `robots.txt` as a HIGH "Exposed sensitive
  file" on two labs.
- **The true positive is luck.** The only reason `accounts.txt` matched is that ten of its rows
  contain a password whose literal value is the word `password`
  (`4,jeremy,password,d1373 1337 speak,Admin`). A credential dump using real passwords would not
  contain the substring `password` anywhere and would be silently skipped.

So "add `passwords` to the wordlist" is not only a benchmark-specific signature (forbidden), it
would also have been wrong. The file has to be judged on the STRUCTURE of its content.

(fix + mutation results below)
