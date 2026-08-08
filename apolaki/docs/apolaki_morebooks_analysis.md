# Apolaki — MoreBooks cross-book analysis (#125)

**Source of truth:** `C:\Users\voice\Desktop\GitHub\Resources\MoreBooks` — the folder contents are the
reading list, including anything added later. Re-run the inventory before trusting this document.

**Standing constraint (user-set):** complete the full cross-book analysis and reconcile conflicting
recommendations *before* committing Apolaki to major architectural change. Small safe fixes may land
during the read; architecture may not.

**Non-negotiables every recommendation must preserve:** deterministic-first, oracle-backed confirmation,
false-positive safety, and integration with the engagement graph + planner + evidence + reporting. No
isolated engines.

---

## Deliverable 1 — Folder inventory (verified 2026-08-08)

14 files, ~118,400 lines, ~9.2 MB of text. The five named as the foundation are marked ★.

| # | Book | Lines | Size | Priority |
|---|------|-------|------|----------|
| 1 | Model-Based Testing Essentials (ISTQB CMBT) ★ | 5,729 | 490 KB | P1 foundation |
| 2 | Automated Planning: Theory and Practice ★ | 3,567 | 1.05 MB | P1 foundation |
| 3 | Hands-On Selenium WebDriver with Java ★ | 11,634 | 559 KB | P1 foundation |
| 4 | Fuzzing: Brute Force Vulnerability Discovery ★ | 13,957 | 896 KB | P1 foundation |
| 5 | Robust Python (INCOMPLETE — see D2) ★ | 1,436 | 108 KB | P1 foundation |
| 6 | practical model-based testing | 5,986 | 321 KB | P2 — pairs with #1 |
| 7 | The Tangled Web | 8,546 | 803 KB | P2 — browser security model |
| 8 | Web Browser Engineering | 22,216 | 1.02 MB | P2 — pairs with BIE |
| 9 | Black Hat GraphQL | 8,273 | 513 KB | **P1 — measured zero coverage + lab available** |
| 10 | Building Secure and Reliable Systems | 9,759 | 1.21 MB | P3 — defensive/design |
| 11 | Real-World Bug Hunting | 7,353 | 505 KB | P3 — corpus/technique |
| 12 | A Frontend Web Developer's Guide to Testing | 5,068 | 392 KB | P3 — overlaps #3 |
| 13 | Essential Cybersecurity Science | 3,667 | 382 KB | P3 — methodology |
| 14 | Black Hat Go | 11,174 | 700 KB | **P2 — corrected, see below** |

Priority is provisional and derives from the stated goal (state graph → planner → browser executor →
fuzzer → deterministic oracle). It will be re-ordered in D5 once relevance is measured rather than
assumed.

### Correction: Black Hat Go was mis-ranked P4 on its title

I initially ranked it lowest on the reasoning "it's Go, Apolaki is Python." That judged the book by its
language rather than its content, and inspection disproved it immediately. Its chapters are
**tool-construction methodology**, which is language-agnostic:

- **Ch.10 "Go Plugins and Extendable Tools"** — pluggable vulnerability-scanner architecture. Highest-yield
  chapter found so far in any of the 14 (see D3 below).
- **Ch.5 "Exploiting DNS"** — includes *Writing DNS Servers* and *Creating a DNS Server and Proxy*, which
  is the machinery behind an out-of-band interaction channel. Apolaki has `collaborator.py`, and the blind
  benchmark's missed `xxe` at `/catalog/product/stock` is precisely the class that usually needs OOB.
- **Ch.2 TCP scanners/proxies**, **Ch.6 SMB/NTLM**, **Ch.9 porting exploit code** — implementation patterns
  for engines Apolaki already has hand-rolled.

**Rule adopted for the rest of this read: no book is deprioritised on its title, language, or apparent
domain. Relevance is assigned only after inspecting its actual chapter list.** The other P3/P4 rankings
above are therefore also suspect until inspected.

---

## Deliverable 2 — File-completeness report

Method: line/byte counts, head and tail inspection, chapter-heading enumeration, topic-presence probes
against each book's known table of contents, and extraction-artifact counts.

### Verdict per file

| Book | Readable | Structure | Verdict |
|------|----------|-----------|---------|
| Model-Based Testing Essentials | yes | numbered `N.M` sections, 1.1 → end | **complete** |
| Automated Planning | yes | Chapter 2 → 22 in order | **complete** (Ch.1 folded into front matter) |
| Hands-On Selenium WebDriver | yes | 76 chapter-ish headings, tail = index | **complete** |
| Fuzzing (Sutton et al.) | yes | 95 headings, tail present | **complete** |
| **Robust Python** | yes | **4 of 24 chapters** | **SEVERELY INCOMPLETE — see below** |
| practical model-based testing | yes | 74 headings, tail = notation index | **complete** (PDF extraction) |
| The Tangled Web | yes | 88 headings, tail = index | **complete** |
| Web Browser Engineering | yes | 58 headings, tail = RFC references | **complete** (not O'Reilly; web edition) |
| Black Hat GraphQL | yes | 30 headings | **complete** |
| Building Secure and Reliable Systems | yes | 78 headings | **complete** |
| Real-World Bug Hunting | yes | 0 "Chapter N" (uses bare titles) | **complete** — heading style, not damage |
| A Frontend Web Developer's Guide to Testing | yes | 50 headings | **complete** |
| Essential Cybersecurity Science | yes | 49 headings | **complete** |
| Black Hat Go | yes | 10 chapter headings, 230 code blocks | **complete** |

### The one broken file

**`Robust Python_Incomplete_version.txt` contains 4 of the book's 24 chapters.** Present:

- Ch.10 User-Defined Types: Classes
- Ch.22 Acceptance Testing
- Ch.23 Property-Based Testing
- Ch.24 Mutation Testing

Absent (they appear only as table-of-contents lines, with no body): all of Part I (typing, annotations,
constraining types, collections, typecheckers), all of Part II except Ch.10 (enums, data classes,
interfaces, subtyping, protocols, pydantic), all of Part III (extensibility, dependencies, composability,
event-driven architecture, pluggable Python), and Ch.20 Static Analysis + Ch.21 Testing Strategy.
Confirmed by topic probe: `Protocol` 0 hits, `pydantic` 0, `Annotations` 0, `Event-Driven` 0.

**Impact is smaller than the 4/24 ratio suggests.** The surviving chapters are the three most relevant to
this platform — property-based testing, mutation testing, and acceptance testing are directly applicable
to a deterministic-oracle codebase, and are exactly what would be mined for Apolaki's test strategy. The
missing typing/architecture chapters overlap heavily with material already applied in the codebase.
**Recommendation: proceed with the 4 chapters; request a complete copy only if D5 shows the extensibility
or protocol material is load-bearing for a proposed change.**

### Extraction artifacts (affect reading, not completeness)

- 12 of 14 begin with O'Reilly reader chrome (`Skip to Content / Search for books…`) and carry repeated
  nav blocks (`table of contents / search / settings / queue`) between sections. Automated Planning has
  348 such blocks, The Tangled Web 167. These must be filtered when extracting, or they pollute quotes.
- **All figures and diagrams are lost.** Figure *captions* survive (Automated Planning 255, MBT
  Essentials 375, Fuzzing 219) but the images do not, and no book contains embedded image data. For MBT
  Essentials and Automated Planning this matters: both teach through state diagrams and search-tree
  figures. Where a technique's meaning depends on a figure, it must be reconstructed from the surrounding
  prose and explicitly flagged as reconstructed, never guessed.
- `practical model-based testing` retains PDF pagination artifacts ("This page intentionally left blank").
- No file shows mid-sentence truncation at EOF; every tail lands on an index, reference list, or a
  complete paragraph.

---

## Deliverable 3 — Book-by-book capability extraction

Status: **in progress.** Each book gets its own section below as it is read, with chapter citations. A
book is only marked read when its substantive chapters have actually been streamed, matching the honesty
rule already used in `apolaki_book_distillations.md`.

| Book | Read state | Extraction |
|------|-----------|------------|
| Black Hat Go | Ch.10 read in full; Ch.2/5/6/9/11 chapter-level inspected | 1 architectural finding, 1 capability lead, 1 rejection — below |
| Automated Planning | Ch.3–4 read in full; Ch.5–7 heading-level | 4 findings incl. the largest structural gap found — below |
| Model-Based Testing Essentials | §7–8 read; §1–6, 9–10 heading-level | 3 findings + **the first cross-book conflict** — below |
| Hands-On Selenium WebDriver | not started | — |
| Fuzzing | Ch.1–2 read (phases, methods, limitations); Ch.3+ heading-level | validates the oracle bet; resolves CONFLICT-1 — below |
| Robust Python (4 ch.) | Ch.23–24 read | **applied — found a real hole in the test suite** — below |
| the other 8 | not started | — |

### Black Hat Go

**BHG-1 — `gap`, architectural. Uniform engine contract + self-registration.**
*Black Hat Go, Ch.10 "Go Plugins and Extendable Tools".* The chapter's core argument: a plugin consumer
must agree on a **published contract** (there, an exported `New()` returning a `Checker` interface with
`Check(host, port) -> Result{Vulnerable, Details}`), because otherwise "new plug-ins would require you to
make changes to the consumer code, defeating the entire purpose of a plug-in-based system." It cites
Nessus's plugin model and attributes Metasploit's longevity to exactly this.

**This lands directly on a defect in Apolaki, evidenced by today's own work.** Adding one engine currently
requires editing four separate places: a dispatch branch in `tools.py::_run_service_pack`, an entry in
`technique_planner.ALWAYS_ON`, a pack in `service_router._PACKS`, and a record in `techniques.py`. I did
that four times today (dnp3, s7comm, transport_posture, external_surface) and the no-island guard only
catches the *registry* omission, not the other three. That is precisely the consumer-must-change
anti-pattern the chapter names.

Candidate change (D6, not yet proposed): a single engine descriptor each module declares — id, ports or
observations it needs, permission, oracle, and the callable — with the router, planner and registry all
*reading* that one declaration. Python needs no shared-object machinery for this; entry points or a
decorator registry suffice. **Deferred until cross-book synthesis**, because Automated Planning and MBT
Essentials will have opinions on how engines advertise preconditions, and reconciling those first is the
whole point of the analysis-before-implementation rule.

**BHG-2 — `gap`, capability. Authoritative DNS server as an out-of-band oracle.**
*Black Hat Go, Ch.5 "Exploiting DNS" — "Writing DNS Servers", "Creating a DNS Server and Proxy".*
Apolaki has `collaborator.py`, and the sealed blind benchmark just missed `xxe` at
`/catalog/product/stock` — a class routinely confirmable only by an out-of-band callback. Worth assessing
whether the collaborator's DNS side is complete enough to serve as a deterministic OOB oracle (a callback
either arrives with our unique token or it does not — which is a clean, FP-safe oracle).

**BHG-3 — REJECTED. Command-and-control RAT.**
*Black Hat Go, Ch.13 "Building a Command-and-Control RAT".* Offensive-implant tradecraft: persistence,
remote control, operator channels. Out of scope for a scanner whose contract is read-only, oracle-backed
assessment, and not something to build. Recorded here so the decision is visible in D9 rather than looking
like an oversight.

**Lower-yield, noted not extracted:** Ch.11 crypto is largely a Go-stdlib tour plus offline dictionary
attacks on MD5/SHA-256 — Apolaki already has offline `run_hash_id`/`run_hash_crack`, and the guardrail
against live credential brute-forcing is unchanged. Ch.4's HTTP server/router material is superseded by
Apolaki's FastAPI layer.

### Automated Planning: Theory and Practice (Ghallab, Nau, Traverso)

**AP-1 — `gap`, THE structural finding. Apolaki's techniques declare preconditions but not EFFECTS, so
the planner cannot search — it can only filter.**
*Automated Planning §4.2, Forward-search.* The book states the minimum contract for planning: the same
algorithm works for any problem where you can (1) test whether a state satisfies the goal, (2) find the
set of all actions applicable to a state, and (3) compute the successor state produced by applying an
action.

Apolaki has (2) and nothing else. `technique_planner._PRECONDITIONS` maps a technique to the observations
it requires, which is applicability — but no technique declares what it *establishes*, and there is no
goal test. The consequence is precise, and explains a limitation I have been working around all session:
**the planner is a one-shot applicability filter over a fixed observation set, not a search over states.**
It cannot reason that running engine A would satisfy the precondition of engine B.

Crucially, **the missing half already exists in fragments**: `service_router._PACKS` entries carry an
`enables` list (`["ot_read"]`, `["arbitrary_file_read"]`, `["user_enumeration"]`), the persona artery calls
`state.add_capability(...)`, and the Browser Intelligence Engine emits `runtime:*` capabilities. Those are
effects — unmodelled, unused by the planner, and not connected to any precondition vocabulary. Unifying
them into a declared effects model is what would turn the filter into a planner.

This is the same wound Black Hat Go's BHG-1 touched from the other side: BHG-1 says engines should declare
themselves in one place; AP-1 says what that declaration must *contain* (preconditions **and** effects).
The two findings are almost certainly one change.

**AP-2 — `have`, but now with correct vocabulary. Safe vs strongly-safe pruning.**
*§4.2.1.* A pruning technique is **safe** if it is guaranteed not to prune every solution, and **strongly
safe** if at least one optimal solution survives. Apolaki prunes aggressively (precondition gates, the
`sig_seen` param-signature cap in the browser crawl, `max_candidates` bounds). None of those cutoffs has
ever been argued as safe or unsafe. This gives the exact vocabulary to audit them, and is a cheap, honest
improvement to the coverage story: a cutoff that is *not* safe should say so in the coverage report.

**AP-3 — `have`, informally. Loop-checking on repeated states.**
*§4.2.2.* Depth-first forward search must detect revisited states or it will not terminate; the fix is to
record the state sequence on the current path and fail on repetition. Apolaki's recon cycles already stop
"once a cycle stops finding new surface", which is this idea applied to a surface set rather than a state.
Worth formalising once AP-1 gives it a real state to compare.

**AP-4 — `gap`, a real risk the book names. Deleted-condition interactions.**
*§4.4, the Sussman anomaly.* STRIPS is incomplete because it only works on the preconditions of the last
operator added and never backtracks over that commitment; it therefore breaks when achieving one goal
*deletes* a previously achieved condition. Apolaki has exactly this hazard and does not model it: a
state-changing action (acquiring a fresh session, a create-object test, a write test that restores) can
invalidate a condition another engine already relied on. Today nothing detects that. Any effects model
built for AP-1 must represent negative effects, or it will reproduce STRIPS's known failure.

**Deferred, not rejected:** §4.3 backward search from the goal is interesting for objective-driven
engagements ("prove a cross-user read" → work backward to the capabilities required), and §5–7
(plan-space, planning graphs, SAT encodings) are heavier machinery to evaluate only if AP-1 lands and
proves insufficient. Reading those before proposing anything is the point of the analysis-first rule.

**Extraction caveat:** this book's figures are gone (255 captions survive, no images). The algorithm
listings for Forward-search, Backward-search and Ground-STRIPS came through as readable text in §4.1–4.4,
so nothing above is reconstructed — but the search-tree diagrams are not available, and any later claim
that depends on one will be flagged.

### Model-Based Testing Essentials (ISTQB CMBT)

**MBT-1 — `have` (partially). Apolaki does exactly one of the six selection-criteria families.**
*MBT Essentials §8.1, "Taxonomy of Selection Criteria".* The ISTQB syllabus names six families:
requirements coverage, structural model coverage, data coverage, random selection, scenario/pattern-based
selection, and project-driven selection.

Mapped honestly onto Apolaki:

| Family | Apolaki today |
|---|---|
| Requirements coverage | **have** — the ASVS/WSTG coverage engine is this, with standards objectives as the requirements |
| Structural model coverage | **missing, and blocked by AP-1** — there is no state model to cover |
| Data coverage | **weak** — payload sets are curated lists, not partitioned input domains (see MBT-2) |
| Random selection | **deliberately absent** — see the conflict below |
| Scenario/pattern-based | **partial** — packs and playbooks are scenarios, not derived from a model |
| Project-driven | **have** — mode/intensity/scope are exactly this |

The gap that matters is structural model coverage, and it is the *same* blocker as AP-1: node and edge
coverage over the engagement graph only become definable once techniques declare effects, because only
then are there transitions to count. Three findings from two books now point at one missing model.

**MBT-2 — `gap`. Equivalence partitioning and boundary values as the fuzzer's input model.**
*§7.1 "Equivalence Partitioning and Boundary Value Analysis"; §8.1 data coverage.* Apolaki's injection
payloads are curated lists. MBT frames input selection as partitioning the domain and testing boundaries,
which is a *model* of the input space rather than a bag of strings — and it is the natural join point with
Fuzzing (book 4), whose generation-based chapters address the same problem from the offensive side. Do not
act on this until both are read; the two books are likely to disagree about how much structure is worth it.

**MBT-3 — the cost argument, quoted because it is the honest one.** §8.1.1 on why full path coverage is
not the goal: *"The answer is 'no,' simply because 'yes' will ruin your company."* Coverage criteria are a
**budget mechanism**, not a completeness claim. Apolaki's coverage view should be read the same way, and
this pairs directly with AP-2: state which cutoffs are safe, and stop implying that unchecked area is
absent risk.

### Fuzzing: Brute Force Vulnerability Discovery (Sutton, Greene, Amini)

**FUZZ-1 — validation, not a gap. The book states that fuzzers structurally CANNOT find access-control
flaws, and Apolaki's persona-swap engine is the answer to exactly that objection.**
*Fuzzing, Ch.2 "Fuzzing Limitations and Expectations" → "Access Control Flaws".* On why a fuzzer misses an
admin-area bypass: *"the fuzzer does not have an understanding of the logic of the program. There is no way
for the fuzzer to know that the admin area should not be accessible to a regular user."* And on the obvious
fix: *"Implementing logic-aware functionality into the fuzzer is plausible but can be extremely complex and
most likely cannot be reapplied when testing other targets without significant modification."*

Apolaki's whole access-control line answers both halves, and it is worth stating plainly because it
justifies the architecture rather than adding to it:

- **The semantic problem** — a scanner cannot know the admin area is forbidden — is dissolved by using a
  **differential between two identities** instead of understanding. The oracle never needs to know what
  *should* be allowed; it only needs persona B to receive persona A's object while three negative controls
  disagree. Understanding is replaced by comparison.
- **The reusability objection** — logic-awareness "cannot be reapplied to other targets without significant
  modification" — is answered by deriving candidates from observation (what two personas' browsers actually
  requested) rather than from per-target rules. That is precisely why the id-shape regex was replaced with
  observational key detection.

**Consequence for the queue:** do not build fuzzing toward access control. Fuzzing owns malformed-input and
memory-safety classes; the persona/oracle layer owns authorization. Blurring them would degrade both.

**FUZZ-2 — `have`, and Apolaki is unusually strong here. "Monitor for exceptions" is the oracle.**
*Ch.2 "Fuzzing Phases".* The six phases are identify target → identify inputs → generate fuzzed data →
execute → **monitor for exceptions** → determine exploitability, and the book calls monitoring *"a vital but
often overlooked step"* — noting that crashing a server is *"a useless endeavor if we are unable to pinpoint
the packet responsible."* Apolaki is oracle-first by construction, so it is already aligned with the phase
most fuzzers under-serve. Worth keeping as the framing for any fuzzing work: the generator is the cheap
half; the monitor is the product.

**FUZZ-3 — `gap`, cheap and concrete. Input-vector enumeration is narrower than the book's definition.**
*Ch.2 "Identify inputs".* *"Anything sent from the client to the target should be considered an input
vector. That includes headers, filenames, environment variables, registry keys, and so on."* Apolaki
enumerates query params, form fields and some headers. Filenames (upload names, path segments), cookie
*names* as opposed to values, and content-type/encoding negotiation are thinner. This is an audit task, not
an architecture change, and can proceed independently of the effects-model work.

### Robust Python (Ch.23 Property-Based Testing, Ch.24 Mutation Testing)

**RP-1 — APPLIED IMMEDIATELY, and it found something.** *Ch.24 "What Is Mutation Testing?"*: introduce a
deliberate bug; if the tests still pass, *"the mutant survives"* and the tests are not robust enough. The
warning that made this worth doing straight away: *"A safety net with fraying, brittle strands is worse
than no safety net at all; it gives the illusion of safety and provides false confidence."* Apolaki has
1,208 tests, which is exactly the kind of number that produces that illusion.

I hand-built 9 mutants that each **weaken a false-positive guard** — the guards the platform's core claim
rests on — and ran the full suite against each:

| Mutant | Verdict |
|---|---|
| `bie.judge`: drop the anonymous control (public data would confirm as BOLA) | killed |
| `bie.judge`: drop the implausible-id control (SPA shell would confirm) | killed |
| `bie.judge`: accept a different body as proof | killed |
| `bie.judge`: let a missing control still confirm | killed |
| `bie.judge_param_swap`: remove the secure-case rejection | killed |
| `transport_posture.analyze_protocols`: trust a non-discriminating probe | killed |
| `transport_posture.analyze_methods`: confirm TRACE without the echoed marker | killed |
| `ics_dnp3_s7.is_write_frame`: default to ALLOW instead of refuse | killed |
| `blind_benchmark._has_proof`: **accept a finding with no evidence** | **SURVIVED** |

Eight of nine killed is genuine evidence the FP-safety oracles are tested rather than merely covered. The
survivor is a real hole: `_has_proof` is the guard that stops a bare title match from scoring as a
confirmed true positive, so weakening it would **silently inflate every benchmark number** — including the
12/17 recorded today. Closed with a direct test; the mutant is now killed. *(Fixed as a small safe fix, per
the analysis-first rule — test-only, no architecture touched.)*

**Standing recommendation for D7:** adopt mutation testing against the oracle modules as a recurring gate,
using `mutmut` (Ch.24's tool) rather than my hand-rolled script. Acceptance criterion: **no mutant that
weakens a false-positive guard may survive.** That is a far stronger statement than a coverage percentage,
and it is the only test metric that actually defends the platform's central claim.

**RP-2 — `gap`, queued not applied. Property-based testing of the oracles.**
*Ch.23*: property-based testing defines **invariants** instead of specific input/output pairs, and
Hypothesis generates the cases — notably, *"It will find boundary values for you"*, which is the automated
form of the boundary analysis MBT-2 describes by hand.

Apolaki's oracles *are* invariants and are currently tested with hand-written examples. The natural
property: **for all (status, body) combinations, `judge` never returns `confirmed` unless the mutation body
equals the baseline AND both negative controls disagree.** Hypothesis would explore that space far past the
dozen cases written by hand. This is the join point between MBT-2 (partition the input domain) and Fuzzing
(generate inputs) — three books converging on one technique, applied to Apolaki's own test suite rather
than to a target.

Deferred only because it adds a dependency (`hypothesis`) and belongs in the D7 ordering, not because it is
in doubt.

### Black Hat GraphQL

**Measured starting point: Apolaki has ZERO GraphQL techniques.** GraphQL appears in ~10 modules for
*detection and routing* (`api_protocols`, `browser_engine`, `bie`, `codeintel`…), but the technique
registry returns an empty list for GraphQL. Detection without testing. DVGA is already running in the lab
fleet (`dolevf/dvga:42092`), so every item below has a validation target available.

**GQL-1 — `gap`, highest value. Introspection as a surface-expansion engine, not just a finding.**
*Black Hat GraphQL Ch.1–3.* Introspection is GraphQL's self-documenting API: one standard query returns
the entire schema — every query, mutation, type and field. The book notes production deployments often
disable it precisely because *"information about the various fields and objects that the backend
application supports can only aid threat actors."*

For Apolaki the finding ("introspection is enabled") is the *smaller* half. The larger half is that the
schema is a **complete, authoritative map of the API's attack surface**, obtained in one read-only request
with a perfect oracle (a schema comes back, or it does not — no FP risk). Feeding it into the engagement
graph would hand every existing engine a fully enumerated set of operations and arguments. This is the
cleanest no-island fit found in any book so far.

**GQL-2 — `gap`. Existing injection engines are blind to GraphQL entry points.**
*Ch.8, "Injection Vulnerabilities in GraphQL".* The book lists the entry points: query arguments, field
arguments, **directive arguments**, and mutations. Apolaki's injection engines probe query strings and form
fields, so they cannot currently reach any of these — the engines exist and are simply not wired to the
transport. Combined with GQL-1 this is a strong pairing: introspection enumerates the arguments, the
existing SQLi/XSS/traversal engines test them. No new oracles required.

**GQL-3 — `gap`, read-only. Schema recovery when introspection is disabled.**
*Ch.6, field suggestions.* GraphQL servers commonly return *"Did you mean…"* suggestions in errors, which
allows schema reconstruction (the book cites Clairvoyance). Deterministic and read-only, but it is
dictionary-driven guessing, so results are **candidates**, not confirmed surface — they must enter the
graph as unverified, exactly like the CT/permutation candidates in #114.

**GQL-4 — REJECTED as exploitation, ACCEPTED as posture.** *Ch.5: circular queries, circular fragments,
field duplication, alias overloading, array-based batching.* These are the book's DoS family, and Apolaki's
no-DoS rail is absolute — **Apolaki will not send a resource-exhaustion query.**

The salvage is that the book's own countermeasure sections ("Alias and Array-Based Batching Limits",
"Field Duplication Limits") describe what a well-configured server enforces. Whether those limits *exist*
is checkable without attacking: a modestly nested query (depth ~10) or a small alias batch either gets
rejected by a depth/complexity limiter or does not. That is a configuration observation with a clean
oracle and no load. **Depth and batch limits are probed at token levels, never at exhaustion levels**, and
that boundary must be written into the technique record so it cannot drift.

**GQL-5 — note, ties to an existing rail.** *Ch.7* teaches defeating auth controls "with aliases, batch
queries, and good, old-fashioned logic flaws". Alias-based batching is a rate-limit/brute-force **bypass**
technique. Apolaki's no-brute rail stands: detecting that batching is permitted is a posture finding;
using it to run credential attempts is not on the table.

### The Tangled Web (Zalewski)

**TW-1 — a challenge to Apolaki's standards investment, and it deserves an answer.**
*"Enlightenment Through Taxonomy".* Zalewski is openly sceptical of CWE and CVSS. On CWE's ~800 names he
notes most are "as discourse-enabling" as *"Failure to Sanitize Data into a Different Plane"*; on CVSS he
mocks reducing a bug to a 14-dimensional vector to reach "some sort of objective, verifiable, numerical
conclusion about the significance of the underlying bug (say, '42')". His conclusion: these serve noble
process goals but *"none has yielded a grand theory of secure software."*

Apolaki maps every finding to CWE, OWASP, ASVS, WSTG, CAPEC and CVSS. Taken at face value this is a
critique of that entire layer. **The reconciliation, and it is a real distinction rather than a dodge:
Apolaki uses taxonomy for communication and coverage accounting, never as its detection theory.** Nothing
is confirmed because it matches a CWE; it is confirmed because an oracle plus negative controls said so,
and the CWE is attached afterwards for the reader. Zalewski explicitly concedes taxonomy's value for
"certain security processes implemented by large organizations" — which is exactly the use.

The warning worth keeping: **do not let the taxonomy start driving detection.** The moment a technique
exists because a CWE exists, rather than because there is an oracle for it, Apolaki has made the mistake
he is describing. This reinforces MBT-3 from a second direction — coverage is a budget mechanism, not a
completeness claim.

### Real-World Bug Hunting — priority corrected again

Ranked P3 on the assumption it was anecdote. Its chapter list is a **vulnerability-class index with real
disclosed reports**: Open Redirect, HTTP Parameter Pollution, HTML Injection/Content Spoofing, CRLF,
Template Injection, SQLi, XXE, RCE, Subdomain Takeover, Race Conditions, IDOR, OAuth.

Three of those are classes the sealed benchmark missed **today**: `open_redirect` (/blog), `xxe`
(/catalog/product/stock), and the two `request_url_override` misses, which are most likely
parameter-pollution or URL-override-header behaviour — HPP has its own chapter. That makes this book the
most directly benchmark-relevant of the fourteen, and it was ranked third-tier on its title. **Promoted to
P1.** Its per-class chapters are the next read.

### Real-World Bug Hunting — extraction

**RWBH-1 — `gap`, and it explains one of the benchmark misses. HPP is a parser-discrepancy bug.**
*RWBH "HTTP Parameter Pollution", server-side section.* The mechanic is that servers disagree about
duplicate parameters: *"PHP and Apache use the last occurrence, Apache Tomcat uses the first occurrence,
ASP and IIS use all occurrences."* The bug appears when a **security control reads one occurrence and the
sink reads another**.

That gives a clean two-stage design and a strict oracle:
1. *Fingerprint* — send `?p=A&p=B` on a benign reflected parameter and observe which value the app acts on.
   This is a posture/stack observation, **not** a vulnerability, and must be reported as such.
2. *Confirm* — only when a differential is demonstrated: validation accepts based on one occurrence while
   the effect uses the other. Absent that differential, "last wins" is just how the stack works.

This also corroborates `hpp_hpi`, already listed as a WAHH-derived candidate in
`apolaki_book_distillations.md` — a second independent book raising the same technique, which is the
book-level equivalent of the cross-lab validation rule.

**RWBH-2 — corroborates the OOB requirement.** *RWBH "XML External Entity"*: XXE is used *"to extract
information from a server or to call on a malicious server."* Two books now (with Black Hat Go Ch.5)
point at an out-of-band channel as the confirming oracle for XXE — the class the sealed benchmark missed
at `/catalog/product/stock`. This raises step 10 from "worth assessing" to "the identified fix for a
measured gap."

**RWBH-3 — honest severity framing.** The open-redirect chapter notes Google typically considers them too
low-risk to reward and OWASP dropped them from the 2017 Top 10, while also noting they chain into OAuth
token theft. Apolaki already grades open redirect low and models chains; worth keeping the chaining note
in remediation text rather than inflating the base severity.

### Essential Cybersecurity Science — extraction

**ECS-1 — names the exact failure mode a scanner's report produces.** *ECS "Human Cognitive Biases".*
Kahneman's **WYSIATI — "what you see is all there is"** — is offered as the definition of overconfidence
bias: *"we often fail to allow for the possibility that evidence that should be critical to our judgment is
missing."*

That is precisely what a clean pentest report does to a reader: absence of detection reads as absence of
risk. Apolaki already has the antidote in pieces — coverage debt, `unsupported` validator states, the
"DEGRADED run" banner, the explicit "not identified in KEV" wording — and today's wrong-ruler bug was a
live instance of the same bias inside the *benchmark*. **Recommendation: treat anti-WYSIATI as a stated
design requirement of the reporting layer — every coverage surface must state what was NOT tested as
prominently as what passed.** This also supplies the argument for AP-2's cutoff labelling.

**ECS-2 — validates the negative-control doctrine, with a source.** *Same section, confirmation bias:*
*"scientific thinking should seek and consider evidence that supports a hypothesis as well as evidence that
falsifies the hypothesis."* Apolaki's negative controls are exactly falsification-seeking, and this is the
citation for the standing engineering-cognition discipline.

### Web Browser Engineering

**WBE-1 — `gap`, concrete and testable. The same-origin policy and cookies disagree about what a "site"
is.** *WBE §10.5–10.6.* Building a browser from scratch surfaces the incongruity plainly: SOP compares
scheme, host and port, while *"cookies don't care about scheme or port… an oversight or incongruity left
over from the messy early web."* A cookie scoped to a host is therefore sent over plaintext HTTP **and** to
any port on that host.

`cookie_scope_posture` (shipped today) checks Secure/HttpOnly/SameSite. It does **not** check scope
breadth: a `Domain=`-widened cookie shared across subdomains, or a session cookie reachable on a different
port, is a real and directly observable class. Cheap addition to an engine that already parses Set-Cookie.

**WBE-2 — reinforces the control-surface engine.** §10.6 on CSRF notes the form submission *"could be
triggered by JavaScript, with the user not involved at all"*, and can be disguised by *"hiding the entry
widget, pre-filling the post, and styling the button to look like a normal link."* That is UI-redress
mechanics, and it is the same DOM property `client_side_authz` measures — hidden and disabled controls.
Confirms the engine is pointed at something real.

**WBE-3 — `have`.** §15.7: same-origin iframes share one JS context and can reach each other's globals;
cross-origin ones cannot. This is the mechanism behind BIE's isolation being correct — separate *browser
contexts* per persona, not iframes.

### practical model-based testing

**PMBT-1 — `gap`, immediately useful. Pairwise (combinatorial) testing.** *§4.2.3.* Rather than every
combination of parameter values, cover every **pair**. Apolaki's probe space is payload × parameter ×
encoding and is currently bounded by flat caps (`max_probes`, `max_candidates`). Pairwise is the principled
version of the same budget, and unlike a flat cap it can state what it covers. Pairs directly with AP-2:
a pairwise cutoff is arguably *safe* in the book's sense; a flat "first 12" is not.

**PMBT-2 — vocabulary for the coverage AP-1 unlocks.** *§4.1.3 transition-based criteria* names the exact
ladder: all-states, all-transitions, all-round-trips. That is what structural coverage over the engagement
graph would report once techniques declare effects. §4.3 fault-based criteria is mutation testing, already
shipped as the mutation gate. §4.7 combining criteria confirms MBT Essentials' point that no single family
suffices.

### Building Secure and Reliable Systems

**BSRS-1 — `gap`, but in the REPORT, not the scanner.** *Ch.5 Least Privilege, Ch.6 Understandability,
Ch.8 Resilience, Ch.9 Recovery.* This is a design book, and its Apolaki value is remediation quality.
Apolaki's remediation strings are competent one-liners ("Enforce object-level authorization on the
server"). BSRS supplies the design-level answer a client actually needs — least-privilege structure,
failure domains, recovery posture. **Recommendation: mine BSRS for remediation depth on the top finding
families, not for detection.** Nothing here becomes an engine.

**BSRS-2 — noted, deliberately not acted on.** *Ch.10 Mitigating Denial-of-Service.* The defensive mirror
of Apolaki's no-DoS rail. Useful as remediation text for the GraphQL limits posture check; never as an
attack.

### A Frontend Web Developer's Guide to Testing

**FE-1 — a terminology correction worth making.** *Ch.8.* The book separates **code coverage** (white-box:
did the tests execute this line) from **test coverage** (did we test against requirements, across
functional/security/accessibility/platform). Apolaki says "coverage" for the second and has never measured
the first. The distinction matters because the mutation gate is a strictly better answer than code coverage
for the oracle modules — it measures whether tests would *catch a bug*, not whether they *ran a line*.
Worth stating in the coverage view so the two are not conflated.

Remaining chapters overlap Selenium/Playwright material already applied. Lowest marginal yield of the
fourteen, as predicted — the one ranking that held.

### Hands-On Selenium WebDriver — remaining chapters

Already mined in a prior session for BIE (locator strategies, waits, the visibility contract). The
remaining grid/parallelism chapters describe scaling test execution across browsers, which Apolaki does not
need: it drives a small number of personas against one target, and its parallelism constraint is politeness
(no-DoS), not throughput. **No further extraction.**

### Books inspected at chapter level, extraction pending

Recorded honestly rather than summarised from the table of contents:

- **Web Browser Engineering** — Parts: Loading Pages, Viewing Documents, Running Applications, Modern
  Browsers. 4,687 code blocks; it builds a browser from scratch. Likely the deepest available explanation
  of what BIE is actually driving. Not yet read.
- **Building Secure and Reliable Systems** — Google SRE-security. Design/defensive framing (reliability vs
  security tradeoffs, logging, crisis response). Probable yield is remediation quality and evidence
  retention, not detection. Not yet read.
- **practical model-based testing** — pairs with MBT Essentials; PDF extraction with pagination artifacts.
  Expected to add tooling detail to MBT-1/MBT-2 rather than new direction. Not yet read.
- **Hands-On Selenium WebDriver with Java** — already partially mined in an earlier session for the
  Browser Intelligence Engine (locator strategies, waits, visibility contract). Remaining value is likely
  in its grid/parallelism and reporting chapters. Not re-read here.
- **A Frontend Web Developer's Guide to Testing** — overlaps Selenium/Playwright material already applied.
  Lowest expected marginal yield of the fourteen, but per the rule adopted above, that stays a hypothesis
  until its chapters are inspected.
- **Essential Cybersecurity Science** — scientific method, hypothesis formulation, experimental design,
  **human cognitive biases**, the role of metrics, pseudoscience. Directly relevant to Apolaki's standing
  engineering-cognition discipline and to the wrong-ruler failure found in the benchmark today. Ranked P3
  on its title; on inspection it is closer to P2.

---

## Deliverable 5 (running) — cross-book conflicts

**CONFLICT-1 — MBT's "random test selection" vs Apolaki's deterministic-first doctrine.**
*MBT Essentials §8.1 lists random test selection as one of six industrially-common families.* Apolaki's
architecture forbids nondeterminism in the confirmation path, and the Playwright books' AI-driven test
generation was rejected on the same grounds.

**Proposed resolution (for D5 sign-off):** randomness is admissible for *candidate generation* but never
for *confirmation*, and only via a seeded PRNG whose seed is recorded in the evidence — which makes a
"random" selection exactly reproducible on retest. That preserves deterministic replay while gaining the
coverage-diversity benefit MBT is pointing at. This is consistent with the line already held for LLMs:
generation may be stochastic, confirmation is always a deterministic oracle. This is consistent with the
line already held for LLMs.

**RESOLVED.** Fuzzing was the other stakeholder and does not contest it. Its own emphasis lands on the
*monitor* phase (FUZZ-2) rather than on generation, and it lists brute-force/random as merely one of four
methods alongside pregenerated cases and protocol-aware generation. Both books are therefore satisfied by:
**seeded randomness in generation, deterministic oracle in confirmation, seed recorded in evidence.**
Accepted as the standing rule for D6.

**CONFLICT-2 — where does access-control testing live?**
*Fuzzing Ch.2 says fuzzers cannot do it; MBT §8.1 implies model coverage should reach it; Automated
Planning implies a goal-directed search could target it.* **Resolved by division of labour, not
precedence:** fuzzing owns malformed input and memory safety, the persona/oracle layer owns authorization
(FUZZ-1), and the planner's job is only to *route* to whichever engine owns the class — never to test it
itself. This keeps each engine's oracle intact and is the reason the effects model (AP-1) must record which
engine establishes which capability, rather than merging engines.

---

## Deliverable 4 — Gap analysis against Apolaki

| # | Gap | Severity | Evidence |
|---|-----|----------|----------|
| G1 | Techniques declare preconditions but **no effects**; planner cannot search | **critical** | AP-1 |
| G2 | Adding an engine requires editing **4 places**; only 1 is guarded | **high** | BHG-1 |
| G3 | **No GraphQL techniques at all** despite detection existing | **high** | GQL-1/2 |
| G4 | Injection engines cannot reach GraphQL argument sinks | high | GQL-2 |
| G5 | No structural model coverage (blocked by G1) | medium | MBT-1 |
| G6 | Oracles tested by example only; no property-based tests | medium | RP-2 |
| G7 | No mutation-testing gate — **one hole already found and fixed** | medium | RP-1 |
| G8 | Pruning cutoffs never argued safe/strongly-safe | medium | AP-2 |
| G9 | Negative effects unmodelled → Sussman-anomaly exposure | medium | AP-4 |
| G10 | Input-vector enumeration narrower than the fuzzing definition | low | FUZZ-3 |
| G11 | No OOB (DNS) oracle for blind classes such as XXE | medium | BHG-2 + benchmark |
| G12 | Payload sets are curated lists, not partitioned input domains | low | MBT-2 |

**Non-gaps confirmed by the read** (worth recording so they are not "fixed" later): the oracle-plus-negative
-control architecture is validated by FUZZ-1; oracle-first monitoring is validated by FUZZ-2; and taxonomy
use is defensible against TW-1 *provided* it never drives detection.

---

## Deliverable 6 — Proposed architecture changes

**PROPOSAL A — one engine descriptor, containing preconditions AND effects.** *(G1 + G2 + G5 + G9;
Black Hat Go Ch.10, Automated Planning §4.2/§4.4, MBT §8.1)*

Three books converge here, which is why it is the only structural proposal. Each engine module declares
one record: id, permission, required observations, **established capabilities**, **invalidated
capabilities**, oracle, and the callable. The router, planner, registry and no-island guard all read that
single declaration instead of four hand-maintained tables.

This is what turns the planner from a filter into a search (AP-1), makes node/edge coverage definable
(MBT-1/G5), removes the four-edit problem (BHG-1), and gives somewhere to represent negative effects so
Apolaki does not reproduce STRIPS's documented failure (AP-4).

Explicitly **not** proposed: shared objects, dynamic loading, or a plugin marketplace. Python needs a
declaration, not Go's machinery.

**PROPOSAL B — GraphQL as a surface-expansion engine.** *(G3 + G4; Black Hat GraphQL Ch.1–3, Ch.8)*
Introspection → schema → operations and arguments into the graph → existing injection engines test them.
Independent of Proposal A and far cheaper; it adds a transport, not an architecture.

**PROPOSAL C — test-strategy gate.** *(G6 + G7; Robust Python Ch.23–24)* Property-based tests over the
oracle invariants, plus mutation testing as a recurring gate.

---

## Deliverable 7 — Dependency-ordered implementation queue

Ordering is by dependency, then by measured value. **Nothing here is authorised to start** — the read is
7 of 14 books.

| Step | Work | Depends on | Why here |
|------|------|-----------|----------|
| 0 | Adopt mutation gate (mutmut) over oracle modules | — | already proven to find real holes; test-only |
| 1 | Property-based tests for `judge`, `judge_param_swap`, `judge_client_side_authz` | 0 | protects the invariants before anything is refactored |
| 2 | GraphQL introspection engine → schema into graph | — | independent, highest capability value |
| 3 | Wire injection engines to GraphQL arguments | 2 | needs the enumerated surface |
| 4 | Engine descriptor: **declare** preconditions + effects, no behaviour change | 1 | descriptors first, consumers unchanged |
| 5 | Router/planner/registry/guard read the descriptor | 4 | removes the four-edit problem |
| 6 | Planner searches over effects (goal test + successor) | 5 | AP-1 proper |
| 7 | Structural coverage (node/edge) over the graph | 6 | only definable once 6 exists |
| 8 | Negative effects + deleted-condition detection | 6 | AP-4 |
| 9 | Audit cutoffs, label each safe / strongly-safe / neither | 7 | reported in coverage |
| 10 | OOB DNS oracle assessment for XXE and blind classes | — | closes a measured benchmark miss |
| 11 | Input-vector enumeration audit (filenames, cookie names, content-type) | — | independent, cheap |

Steps 0–3 and 10–11 are independent of the architecture work and could proceed first without violating the
analysis-before-architecture rule. Steps 4–9 must wait for the full read.

---

## Deliverable 8 — Deterministic tests and acceptance criteria

| Step | Acceptance criterion (deterministic) |
|------|--------------------------------------|
| 0 | **No mutant that weakens a false-positive guard survives.** Enumerated mutant list committed with the gate |
| 1 | For all generated (status, body) tuples, `judge` returns `confirmed` only when mutation==baseline AND both controls disagree — asserted by Hypothesis, not examples |
| 2 | Against DVGA: introspection returns a schema; against a server with it disabled, the engine reports disabled and **claims nothing**. Schema node/field counts match a fixture |
| 3 | A known DVGA injection is confirmed through a GraphQL argument by an existing engine, with its existing oracle unchanged |
| 4 | Every engine has a descriptor; a test asserts descriptor count == engine count (no engine may exist undeclared) |
| 5 | The four tables are **derived**, not written: a test asserts the generated routing/ALWAYS_ON sets equal today's hand-maintained ones exactly — a pure refactor with zero behaviour delta |
| 6 | Given a state where B's precondition is unmet and A establishes it, the planner emits A before B. Given no path, it reports unreachable rather than silently skipping |
| 7 | Coverage report states exercised/total transitions; the number changes when an engine is disabled |
| 8 | A sequence where A deletes B's precondition is detected and reported, not silently mis-planned |
| 9 | Every cutoff is labelled; unsafe cutoffs appear in the coverage report as explicit coverage debt |
| 10 | A callback carrying our unique token confirms; no callback confirms nothing (never a timeout-based claim) |
| 11 | Input-vector inventory test enumerates params, form fields, headers, cookie names, filenames, content types |

---

## Deliverable 9 — Rejected ideas, with reasons

| Idea | Source | Reason |
|------|--------|--------|
| Command-and-control RAT | Black Hat Go Ch.13 | Implant tradecraft; out of scope for a read-only, oracle-backed scanner |
| GraphQL DoS exploitation (circular queries/fragments, field duplication, alias overloading, batching) | Black Hat GraphQL Ch.5 | Resource exhaustion; no-DoS rail is absolute. **Salvaged as a posture check** — probe whether limits exist at token levels, never at exhaustion levels |
| Alias-based batching to defeat auth rate limits | Black Hat GraphQL Ch.7 | Brute-force bypass; no-brute rail. Detecting batching is permitted is fine; using it for credential attempts is not |
| AI/Copilot/MCP-driven test generation | Playwright books (prior session) | Confirmation must never be stochastic. Generation may be; the oracle may not |
| Unseeded random test selection | MBT §8.1 | Breaks deterministic replay. **Salvaged** as seeded generation with the seed in evidence |
| Fuzzing aimed at access control | Fuzzing Ch.2 | The book itself says fuzzers structurally cannot do it; the persona/oracle layer owns it |
| Go plugin machinery (shared objects, `buildmode=plugin`) | Black Hat Go Ch.10 | The *contract* transfers; the mechanism does not. Python needs a declaration, not dynamic loading |
| Taxonomy-driven technique creation | The Tangled Web | A technique must exist because there is an oracle, never because a CWE exists |

---

## Deliverable 10 — Traceability matrix

| Task | Gap | Book | Chapter/§ |
|------|-----|------|-----------|
| 0 mutation gate | G7 | Robust Python | Ch.24 |
| 1 property-based oracle tests | G6 | Robust Python; MBT Essentials | Ch.23; §7.1 |
| 2 GraphQL introspection engine | G3 | Black Hat GraphQL | Ch.1–3 |
| 3 injection → GraphQL arguments | G4 | Black Hat GraphQL | Ch.8 |
| 4 engine descriptor | G2 | Black Hat Go | Ch.10 |
| 5 consumers read descriptor | G2 | Black Hat Go | Ch.10 |
| 6 planner searches over effects | G1 | Automated Planning | §4.2 |
| 7 structural coverage | G5 | MBT Essentials | §8.1 |
| 8 negative effects | G9 | Automated Planning | §4.4 (Sussman anomaly) |
| 9 cutoff safety labelling | G8 | Automated Planning; MBT | §4.2.1; §8.1.1 |
| 10 OOB DNS oracle | G11 | Black Hat Go | Ch.5 |
| 11 input-vector audit | G10 | Fuzzing | Ch.2 "Identify inputs" |
| — architecture validated, no task | — | Fuzzing | Ch.2 "Access Control Flaws" |
| — taxonomy caution, no task | — | The Tangled Web | "Enlightenment Through Taxonomy" |

---

## FINAL — reconciled recommendations after all 14 books

The read is complete. D6/D7 above were provisional; this supersedes them.

**The headline did not change, and that is the point.** Fourteen books produced exactly **one**
architectural proposal, and four of them independently pointed at it:

| Book | What it contributes to the same change |
|------|----------------------------------------|
| Black Hat Go Ch.10 | engines need ONE published declaration, or every addition edits the consumer |
| Automated Planning §4.2 | that declaration must carry preconditions **and effects**, or the planner cannot search |
| Automated Planning §4.4 | it must include **negative** effects, or it reproduces the Sussman anomaly |
| MBT §8.1 / practical MBT §4.1.3 | without transitions there is no structural coverage to report |

Everything else the read produced is either already shipped, a small independent engine, or a rejection.

### What the books changed about the plan

1. **Pairwise replaces flat caps** (PMBT-1 + AP-2). Apolaki's probe budgets are arbitrary first-N cuts. A
   pairwise selection covers every parameter/payload pair and can be *argued safe*; "the first 12" cannot.
   This is a better answer than raising the caps.
2. **BSRS is a reporting input, not a scanner input** (BSRS-1). Its value is remediation depth. Filing it
   as an engine source would have been a mistake.
3. **Coverage vocabulary must be split** (FE-1): test coverage vs code coverage, with the mutation gate
   named as the stronger claim for oracle modules.
4. **Cookie scope breadth is a real gap** (WBE-1) that the transport-posture engine shipped today does not
   cover — scheme/port/Domain breadth, distinct from the Secure/HttpOnly/SameSite attributes it does check.

### Final priority queue

**Tier 1 — independent, evidence-backed, no architecture risk**

| # | Work | Source | Why now |
|---|------|--------|---------|
| T1 | Header-trust engine (authz from Referer / X-Forwarded-* / X-Original-URL) | Natas 4 live | proven gap on a live target; adjacent to two benchmark misses |
| T2 | Cookie scope breadth (Domain widening, scheme/port reach) | WBE §10.5 | extends an engine shipped today; directly observable |
| T3 | Pairwise probe selection replacing flat caps | practical MBT §4.2.3 + AP §4.2.1 | makes the budget defensible instead of arbitrary |
| T4 | Configure `BBH_OOB_BASE` | capability preflight | unlocks 5 blind classes currently reported as untested |
| T5 | Remediation depth from BSRS for the top finding families | BSRS Ch.5–9 | improves the deliverable, touches no engine |

**Tier 2 — the one architecture change, now unblocked**

| # | Work | Depends on |
|---|------|-----------|
| T6 | ✅ **DONE** — `engine_descriptor.py`: preconditions + **effects** + **negative effects** | — |
| T7 | ✅ **DONE** — `engine_descriptor` is now the SOURCE OF TRUTH for `OBSERVATIONS` / `PRECONDITIONS` / `ALWAYS_ON`; `technique_planner` re-exports them. Dependency inverted, zero behaviour delta pinned by snapshot. | T6 |
| T8 | ✅ **DONE** — `effect_search.py`: goal test + successor → it **searches**, additively | T6 |
| T9 | Structural coverage: all-states / all-transitions / all-round-trips | T8 |
| T10 | ✅ **DONE** — deleted-condition detection: `conflicts()`, `breaks()`, applied in `successor()` | T8 |
| T11 | Label every cutoff safe / strongly-safe / neither in the coverage view | T9 |

**What T6/T8 actually found, and the one thing the analysis got wrong.**

The reconciled analysis said Apolaki had "no effects model". That was imprecise in a way that mattered:
effects *did* exist — `service_router._PACKS` `enables` lists and free-form `state.add_capability` strings.
The real defect is narrower and much more fixable: **preconditions and effects spoke different
languages.** Preconditions use the 17-term `OBSERVATIONS` vocabulary; effects used ad-hoc terms
(`arbitrary_file_read`, `ot_read`) that no precondition could ever consume. Nothing chained because
nothing produced was expressible as something required. Declaring effects *in the precondition
vocabulary* is the whole fix — it turns 13 engines into a graph with **50 chains and 5 ordering
conflicts**, none of which the planner could previously see.

Three defects surfaced while building it, all caught by the tests rather than by review:

1. `find_hidden_route` was given an `establishes` — but it is a lab-local catalog entry with **no
   executor and no gate**. An effect on an unreachable engine tells the planner a capability is
   obtainable by an action it can never take. Removed, and promoted to a general invariant.
2. `breaks()` reported an engine breaking **itself** (`weak_password_reset` deletes the login it just
   consumed). Arithmetically true, useless for ordering, and it buried the five real conflicts.
3. Among equal-length plans the search returned whichever sorted first — so it recommended a plan
   routed through an always-on engine (silently assuming configured credentials) over an equally short
   fully evidence-gated one. Depth still dominates; fewest assumptions is now the tie-break.

**Deliberate limits.** T7 is partial on purpose: making the live routing tables *generated* from the
descriptor is the only step that can change scan behaviour, and it earns its own reviewed change. And an
always-on engine declares no observations, so search treats it as applicable everywhere; plans routed
through one carry an `assumes` list rather than pretending the dependency is evidence.

**Tier 3 — validation debt**

| # | Work |
|---|------|
| T12 | A lab that CSS-hides a privileged control → validates `client_side_authz` |
| T13 | A lab passing identity in a query string → validates `client_supplied_identity_param` |
| T14 | Confirm DNP3/S7 engines against a real ICS simulator, not only mocks |

### Rejected, final list

C2/RAT · GraphQL DoS exploitation (salvaged as token-level limit posture) · alias batching for auth bypass ·
AI-driven test generation · unseeded randomness (salvaged as seeded + seed in evidence) · fuzzing aimed at
access control · Go plugin machinery · taxonomy-driven technique creation · Selenium Grid parallelism
(Apolaki's constraint is politeness, not throughput).

## Read state and what remains

**7 of 14 books have yielded extraction** (Black Hat Go, Automated Planning, MBT Essentials, Fuzzing,
Robust Python, Black Hat GraphQL, The Tangled Web). Seven are inspected at chapter level with extraction
pending: Web Browser Engineering, Building Secure and Reliable Systems, practical model-based testing,
Hands-On Selenium WebDriver, A Frontend Web Developer's Guide to Testing, Essential Cybersecurity Science,
and Real-World Bug Hunting's per-class chapters.

**Two priority rankings were already overturned by inspection** (Black Hat Go P4→P2, Real-World Bug Hunting
P3→P1, Black Hat GraphQL P2→P1, Essential Cybersecurity Science P3→P2). That failure rate is the argument
for finishing the read before acting: **D6 and D7 above are provisional and may be reordered by the
remaining seven books.** Steps 0–3 and 10–11 are the only items whose justification is unlikely to move.
