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
| 9 | Black Hat GraphQL | 8,273 | 513 KB | P2 — capability gap |
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

## Deliverables 4–10

Not started. They depend on D3 and will be written only from material actually read:

4. Gap analysis against Apolaki's current architecture
5. Cross-book synthesis and conflict resolution
6. Proposed architecture changes
7. Dependency-ordered implementation queue
8. Deterministic tests and acceptance criteria
9. Rejected ideas, with reasons
10. Traceability matrix (task → book → chapter)

**Scale note, stated plainly:** this is ~118,000 lines of source. A genuine cover-to-cover read is a
multi-session effort, and claiming otherwise would be the exact failure this document is supposed to
prevent. Progress is tracked in the D3 table above; nothing enters D6/D7 without a chapter citation.
