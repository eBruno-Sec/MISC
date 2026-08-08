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
| 14 | Black Hat Go | 11,174 | 700 KB | P4 — language-specific |

Priority is provisional and derives from the stated goal (state graph → planner → browser executor →
fuzzer → deterministic oracle). It will be re-ordered in D5 once relevance is measured rather than
assumed.

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
| Model-Based Testing Essentials | not started | — |
| Automated Planning | not started | — |
| Hands-On Selenium WebDriver | not started | — |
| Fuzzing | not started | — |
| Robust Python (4 ch.) | not started | — |
| the other 9 | not started | — |

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
