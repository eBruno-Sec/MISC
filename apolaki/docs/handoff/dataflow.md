# Dataflow lane - hand-off

Question this lane answers: **`trustbound` is 126 Java + 37 Python cases scoring an honest 0.0%.
Can a deterministic analysis separate the vulnerable cases from their laundered clean twins at
0.0% FPR, or is the honest 0 the right answer?**

Status legend: [READ] read from benchmark source, verifiable by re-reading it. [INFERRED] derived
by argument from [READ] facts, NOT yet scored. [MEASURED] scored against the key after sealing.

**Nothing in this file is [MEASURED] yet.** The category is still unmapped in `owasp_bench.py` and
still scores 0.

---

## THE CALL

**Q1. Does the standing claim in `owasp_bench.py` hold?** *Two thirds of it. The third part is
wrong.*

- collection (`map.get("keyA-")`) launders - **CONFIRMED**, and understated: the clean twin reads
  the TAINTED key first and the safe key second, so any rule phrased as "does `get("keyB")`
  appear" flags both twins.
- constant-folded ternary launders - **CONFIRMED**, and it is the sharpest discriminator in the
  category.
- StringBuilder launders - **WRONG for `trustbound`**. All 19 StringBuilders in the Java category
  are constructed from `param`. There is not one constant-only StringBuilder in the category.
  Treating a StringBuilder as a launderer here produces false NEGATIVES, not the false positives
  the comment was written to avoid.

**Q2. Is deterministic separation achievable, and by what mechanism?** *Yes. Build it.*

The mechanism is an abstract interpreter over CONST / TAINT / UNKNOWN with keyed containers -
five capabilities, all decidable, none textual:

1. **constant folding** of integer arithmetic (integer division), string `in`/`not in`, and
   indexing a constant string - then selecting the live arm of `if` / ternary / `switch` / `match`;
2. **last-write-wins** per local, because the clean map twin's final assignment is the safe one;
3. **keyed container slots** - a map is not one taint bit, and `remove(0)` then `get(1)` is a
   different element from `get(0)`;
4. **intra-file interprocedural inlining** - 85 of 126 Java cases route the transform through a
   private helper or an inner class;
5. **source provenance**, which is the whole thesis: two things that read exactly like request
   reads are not request-derived - a cross-file helper that returns a constant (`getTheValue`,
   8 Java + 3 Python cases) and `request.path` under a route with no converters (3 Python cases).

Every one of these is a mechanism, not a pattern. Nothing in the plan names a case id, a file
name or a per-case fingerprint.

**Why this is not the "conservative approximation" the standing comment feared.** The default for
an unmodelled transformation is taint-PRESERVING, so precision is only ever spent where the
analysis can prove a constant. The controls below are what decide whether that proof holds, and
the FPR on the clean twins is the number that settles it. **If that FPR is not 0.0%, the honest 0
stays and this file will say so.**

---

## Verdict on the standing decision: it is winnable, and the stated reason for leaving it is
## partly wrong

The comment in `agent/owasp_bench.py` says:

> the clean twins launder the tainted value through a collection (`map.get("keyA-")`), a
> StringBuilder, or a ternary whose branch is decided by constant folding

Checked against all 163 cases:

| claim | verdict |
|---|---|
| collection `map.get("keyA-")` launders | **CONFIRMED**, and it is subtler than stated (below) |
| constant-folded ternary launders | **CONFIRMED**, and it is the sharpest twin in the suite |
| StringBuilder launders | **WRONG for this category** |

**Every StringBuilder in Java `trustbound` is constructed from `param`.** [READ] 11 cases are
`new StringBuilder(param)` and 8 more are `new StringBuilder(a<N>)` where `a<N> = param` one line
earlier. There is not one constant-only StringBuilder in the category. In `trustbound` the
StringBuilder is a **propagator**, not a launderer, and treating it as a sanitizer would produce
false NEGATIVES, not the false positives the comment fears.

The conclusion that follows: the category is not blocked on "real dataflow" in the general
interprocedural sense. It is blocked on four specific, decidable things - constant folding,
last-write-wins on a local, keyed collection slots, and knowing which sources are actually
attacker-controlled. All four are deterministic. **The recommendation is to build it.**

---

## The shape of the category [READ]

Both suites are one source, one transform, one sink. The sink is uniform and carries no signal:

| suite | sinks | count |
|---|---|---|
| Java | `request.getSession().putValue(...)` | 69 |
| Java | `request.getSession().setAttribute(...)` | 57 |
| Python | `flask.session['userid'] = bar` | 20 |
| Python | `flask.session[bar] = '12345'` | 17 |

**All 163 cases call a session sink. 100% of them.** The tainted argument is sometimes the KEY
(`setAttribute(bar, "10340")`) and sometimes the VALUE (`setAttribute("userid", bar)`), which is
why a sink-argument-position rule is also no help. This is the concrete proof of the brief's
premise: **the sink call cannot decide anything; only the provenance of the value can.** A
detector that fires on `HttpSession.setAttribute` scores 100% TPR and 100% FPR.

### Sources - and two of them are NOT attacker-controlled

Java, 14 distinct extraction shapes, all reading `request` [READ]:
`getParameter`, `getParameterValues`, `getParameterMap`, `getParameterNames`, `getHeader`,
`getHeaders`, `getHeaderNames`, `getCookies`, `getQueryString`, and
`new SeparateClassRequest(request).getTheParameter(...)` / `.getTheCookie(...)`.

Two sources are safe and they are the first negative control, handed over by the benchmark itself:

1. **`SeparateClassRequest.getTheValue(String p)` returns the constant `"bar"`.** [READ]
   `helpers/SeparateClassRequest.java` even comments it: "This method is a 'safe' source."
   **8 of 126 Java cases** use it. The Python twin is
   `helpers/separate_request.py :: request_wrapper.get_safe_value(name) -> "bar"`, **3 of 37
   Python cases**. A cross-file read of the helper is required; the call site alone looks exactly
   like `getTheParameter`.

2. **`request.path.split("/")[1]` is the literal `'benchmark'`.** [READ, Python only]
   The Flask route is a static literal with no converters
   (`@app.route('/benchmark/trustbound-00/BenchmarkTest01092')`), so `request.path` is pinned and
   `parts[1]` is always `'benchmark'`. **Every one of the 112 cases in the whole Python suite that
   uses this source uses index `[1]`** - never `[2]`, never `[-1]`. 3 of them are `trustbound`.
   This is the Python twin of "the receiver decides the verdict": `request.path` *reads* like a
   source, and constant-propagating the route decorator proves it is not one.

---

## The matched twins, verified case by case [READ]

### 1. Constant-folded branch - the sharpest pair in the category

Same predicate text. Different constant eight lines up. Opposite verdict.

`BenchmarkTest00426` - **taint reaches the sink**:

```java
String param = request.getParameter("BenchmarkTest00426");
int num = 106;
bar = (7 * 42) - num > 200 ? "This should never happen" : param;
request.getSession().setAttribute(bar, "10340");
```

`(7*42) - 106` = 188, which is NOT > 200, so the ternary takes the FALSE arm and `bar` is `param`.

`BenchmarkTest01142` - **taint does not reach the sink**:

```java
int num = 86;
if ((7 * 42) - num > 200) bar = "This_should_always_happen";
else bar = param;
```

`(7*42) - 86` = 208, which IS > 200, so `bar` is a constant.

The predicate `(7 * 42) - num > 200` is character-identical in both. No regex, no call-site match
and no "does the expression mention `param`" heuristic separates them. **Folding the arithmetic
does, exactly.**

The full fold table across Java `trustbound` [READ]:

| `num` | predicate | value | taken arm |
|---:|---|---:|---|
| 86 | `(7 * 42) - num > 200` | 208 | true |
| 106 | `(7 * 42) - num > 200` | 188 | false |
| 106 | `(7 * 18) + num > 200` | 232 | true |
| 196 | `(500 / 42) + num > 200` | 207 | true |

Two things must both be computed, not one: **which arm is taken**, and **which arm holds `param`**.
The suite writes both directions - `bar = param` on true (`if ((500/42) + num > 200) bar = param;`)
and `bar = param` on false (the ternary above). `500 / 42` is **11** under Java integer division;
an evaluator that does float division gets 11.9 and, here, the same verdict - but the discipline
has to be integer or the next codebase breaks it.

Python carries the same construct with its own constants [READ]:
`num = 86; if 7 * 42 - num > 200:` (208, true, clean) and
`num = 106; bar = "This_should_always_happen" if 7 * 18 + num > 200 else param` (232, true, clean).

Python adds a **string-predicate** variant the Java suite does not have [READ]:

```python
TestParam = "This should never happen"
if 'should' not in TestParam:   # False - 'should' IS in it
    bar = "Ifnot case passed"
else:
    bar = param                 # taken
```

and its mirror `bar = "This should never happen"; if 'should' in bar: bar = param` (taken). So the
fold has to cover `in` / `not in` over string constants, not just integer arithmetic.

### 2. Keyed collection - confirmed, and the stated form of it is too weak

The `owasp_bench.py` comment says the clean twin does `map.get("keyA-")`. It does. But the clean
twin **also does `map.get("keyB-")` first** [READ]:

```java
map.put("keyA-N", "a-Value");
map.put("keyB-N", param);         // taint enters the map
map.put("keyC", "another-Value");
bar = (String) map.get("keyB-N"); // get it back out  <- both twins have this line
bar = (String) map.get("keyA-N"); // clean twin ONLY  <- last write wins
```

4 Java cases have both gets (clean), 4 have only the `keyB` get (tainted). **A check for "does
`map.get("keyB-")` appear" flags both.** Separating them needs last-write-wins on `bar` *and*
per-key slot tracking - the map is not one taint bit, it is a map.

Python has three spellings of the same idea [READ]: `dict` literal keys
(`map['keyB-N'] = param; bar = map['keyB-N']`), and **`configparser`**
(`conf.set('sec', 'keyB-N', param); bar = conf.get('sec', 'keyA-N')`) - a keyed store behind a
two-argument getter. 5 of 37 Python cases are the configparser form.

### 3. List slot - index arithmetic, not membership

```java
valuesList.add("safe"); valuesList.add(param); valuesList.add("moresafe");
valuesList.remove(0);
bar = valuesList.get(1);   // -> "moresafe"   CLEAN   (12 Java cases)
bar = valuesList.get(0);   // -> param        TAINTED (2 Java cases)
```

`remove(0)` shifts the list to `[param, "moresafe"]`. The clean and tainted twins differ by the
single character `1` vs `0`. Python is identical: `lst.pop(0); bar = lst[1]`.

### 4. Switch / match on a folded character

```java
String guess = "ABC";
char switchTarget = guess.charAt(1);   // 'B'
switch (switchTarget) {
  case 'A': bar = param; break;
  case 'B': bar = "bob"; break;        // taken when charAt(1)
  case 'C': case 'D': bar = param; break;
  default:  bar = "bob's your uncle";
}
```

Java uses `charAt(1)` in 9 cases (clean) and `charAt(2)` -> `'C'` -> `bar = param` in 6 (tainted).
Python uses `possible[1]` in 4 (clean) and `possible[0]` -> `'A'` -> `bar = param` in 2 (tainted).
Same discipline: index a constant string, fold it, pick the arm.

### 5. Pure propagators - every one of these keeps the taint

Confirmed taint-preserving in this category [READ]:

- `bar = param`
- `bar = param.substring(0, param.length() - 1)`
- `bar = param.split(" ")[0]`
- `new String(Base64.decodeBase64(Base64.encodeBase64(param.getBytes())))` (Python: `base64.b64decode(b64encode(...))`)
- `new StringBuilder(param).append("_SafeStuff").toString()` and `.replace(...).toString()`
- Python `bar = param + '_SafeStuff'`, and the f-string slice
  `superstring = f'39218{param}abcd'; bar = superstring[5:len(superstring)-5]`
- Python `string = 'help'; string += param; string += 'snapes on a plane'; bar = string[4:-17]`
  (the slice recovers `param` exactly)
- **cross-class dispatch**: `ThingFactory.createThing().doSomething(param)`. Both implementations
  in the tree (`Thing1`, `Thing2`) are identity - `return i` and
  `return new StringBuilder(i).toString()`. Python's `ThingFactory` is the same two classes. The
  concrete class is chosen by a config file at runtime, so an analysis must either read both
  implementations or treat an unresolved dispatch as taint-preserving.
- **inner class / private helper**: 85 of 126 Java cases route the whole transform through
  `new Test().doSomething(request, param)` or a private `doSomething(request, param)` in the same
  file. Intra-file interprocedural is mandatory; without it 67% of the Java category is opaque.

The one genuine constant-accumulator launderer, Python only [READ] (`BenchmarkTest00071`):

```python
string = ''; copy = string
string = ''; string += param          # taint goes into `string`
copy += 'SomeOKString'                # `copy` never receives it
bar = copy                            # CLEAN
```

Two aliases of `''`, one gets the taint, the other reaches the sink. Per-variable tracking, not
per-file.

---

## The one modelling question that is not settled by reading alone

`escapeHtml` / `ESAPI.encoder().encodeForHTML` / `HtmlUtils.htmlEscape` (17 Java cases) and
`markupsafe.escape` / `helpers.utils.escape_for_html` (2 Python cases) appear as transforms.

**On the CWE, they are propagators.** CWE-501 is mixing untrusted data into a trusted store. HTML
entity encoding is CWE-116 output encoding for an HTML sink; a session is not an HTML sink, and
`session[escapeHtml(attacker_string)]` is still an attacker-chosen key. Nothing about the trust of
the value changed. **This lane will ship them as taint-preserving**, recorded here before any
scoring so the choice cannot be back-fitted to the key.

There is also arithmetic that supports it, from an aggregate this repo has **already published**
(`docs/handoff/code_assisted.md`: Python `trustbound` scored `0 TP / 18 FN / 0 FP / 19 TN`, so the
split is 18 vulnerable / 19 clean). Classifying all 37 Python cases by propagation semantics
alone [INFERRED] gives 16 clean-by-transform and 16 tainted-by-transform, leaving the 3
`request.path` cases and the 2 escaper cases undecided. Only one assignment of those five reaches
18/19:

| `request.path` | escapers | vulnerable | clean | matches 18/19 |
|---|---|---:|---:|---|
| safe source | propagators | 18 | 19 | **yes** |
| tainted source | sanitizers | 19 | 18 | no |
| safe source | sanitizers | 16 | 21 | no |
| tainted source | propagators | 21 | 16 | no |

So the two independent readings agree: **`request.path[1]` is a constant, and escaping does not
sanitize a trust boundary.** This is an argument, not a measurement - it is [INFERRED] until the
sealed score lands, and if the score disagrees this table is where the error will be.

---

## What the analysis has to do, in order of how much it buys

1. **Intra-file interprocedural** - private helper + inner class. 85/126 Java cases (67%).
2. **Constant folding** - integer arithmetic (integer division), `in`/`not in` over string
   constants, `charAt`/index into a string constant, and the resulting branch selection over
   `if`/`else`, ternary, `switch`/`match`. ~40 cases across both suites.
3. **Last-write-wins per local** - `bar` is reassigned in nearly every clean twin.
4. **Keyed containers** - map/dict/configparser slots and list index arithmetic after `remove`/
   `pop`. ~30 cases.
5. **Safe sources** - `getTheValue` / `get_safe_value` (cross-file constant return) and the
   route-pinned `request.path`. 11 Java + 6 Python cases, and every one of them is a case a
   provenance-blind detector reports as a false positive.

Item 5 is the whole thesis restated: **the provenance of the value decides the verdict, not the
sink call.** 100% of the category calls a session sink; the 8 Java cases whose value came from a
constant helper are exactly the ones a sink-matching detector cannot survive.

---

## Negative controls - written before the analysis exists

The five the brief requires, all drawn from real shapes above, none naming a case id:

| # | control | must |
|---|---|---|
| 1 | value reaches the sink from a constant-returning helper, not the request | NOT flag |
| 2 | `map.put("keyA", CONST); map.put("keyB", param); bar = map.get("keyB"); bar = map.get("keyA")` | NOT flag |
| 3 | constant-folded ternary/if whose taken arm is the safe constant | NOT flag |
| 4 | StringBuilder that appends only constants | NOT flag |
| 5 | request parameter through each of the same launderers | **flag** |

Control 4 is worth a note: it is required by the brief and it is correct, but **no case in
`trustbound` has that shape** - every StringBuilder in the category holds `param`. It is a control
against a mistake the category cannot catch, which is exactly the reason to write it as a unit
test rather than trust the benchmark to exercise it. Same class of gap as the M6/M7 mutants in the
code-assisted lane, which the suite could not kill and the unit tests could.

---

## Next

Build. The reading says the separation is decidable; the honest 0 stands only until the sealed
measurement says otherwise. Sequence: controls first (each failing), then the analysis, then a
mutation check that a provenance-blind version dies on control 1 and 5, then seal, then score.

`agent/owasp_bench.py` FAMILIES stays untouched until the controls are green.
