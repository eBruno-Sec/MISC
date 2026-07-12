# RedFlag — Dual-Mode Content Spec v2
## Platform Architecture · Quiz · Export Formats · Profiles · Blog
### 2026-07-12

---

## Overview

RedFlag's quiz runs in two modes from a **unified question bank**:

| Mode | Entry Label | Perspective |
|---|---|---|
| **Partner Audit** | "Audit My Partner" | User observes their partner's behavior; options describe how the partner acts |
| **Self Audit** | "Audit Myself" | User reflects on their own behavior; options describe how they personally act |

The same 8 questions and 4 options power both modes. Pronoun tokens in the copy are substituted at render time based on mode selection.

---

## Archetype Key Reference

| Key | Name | Tagline |
|---|---|---|
| `[A]` | The Avoidant | Fear of Closeness |
| `[C]` | The Consumer | Hungry for Validation |
| `[U]` | The Under-Functioner | Fear of Accountability |
| `[S]` | The Secure Attacher | The Healthy Baseline |

---

## Dual-Mode Token System

Use these tokens throughout question and option copy. The frontend substitutes them based on mode.

| Token | Partner Audit renders as | Self Audit renders as |
|---|---|---|
| `{THEY}` | they | you |
| `{THEIR}` | their | your |
| `{THEM}` | them | you |
| `{THEYRE}` | they're | you're |
| `{THEYVE}` | they've | you've |
| `{THEY_UC}` | They | You |
| `{SUBJECT}` | Your partner | You |
| `{RANK_PROMPT}` | Rank how they'd most likely respond. | Rank how you'd most likely respond. |

**Scenario flip:** Each question has two scenario variants — one per mode — that share the same 4 options but frame the setup differently. Both are provided below.

---

## Part 1: The 8 Quiz Questions

*Archetype key on each option is internal metadata only — never shown to users. Shuffle option order per render.*

---

### Q1 — The Boundary Test
*Needing space / saying no*

**Partner Audit scenario:**
> You tell your partner you need this weekend to yourself — you love them, you just need to recharge. Rank how their response would most likely go.

**Self Audit scenario:**
> Your partner tells you they need this weekend to themselves — they love you, they just need to recharge. Rank how your response would most likely go.

| Option | Copy | Key |
|---|---|---|
| A | `{THEY_UC}` say "Fine, no problem" — almost too easily. No temperature shift in either direction. You couldn't tell if `{THEY}` were hurt, relieved, or completely indifferent. The weekend was `{yours/theirs}`, technically. | `[A]` |
| B | `{THEY_UC}` don't argue — but `{THEIR}` energy shifts. Quieter, slightly withdrawn. By Saturday `{you've/they've}` spent half `{your/their}` alone time managing how `{they feel/your partner feels}` about `{your/their}` alone time. | `[C]` |
| C | `{THEY_UC}` agree — then text `{you/them}` three times that day anyway. Not urgently, just checking in, sharing something funny. `{THEY_UC}` forgot the terms of what `{you/they}` asked for. | `[U]` |
| D | "Of course — let me know when you're ready to reconnect." No fallout, no undercurrent. `{THEY_UC}` meant it. `{The weekend was yours. / You gave them the weekend.}` | `[S]` |

---

### Q2 — The Conflict Test
*Handling minor grievances or call-outs*

**Partner Audit scenario:**
> You bring up something small that bothered you — a comment they made, something minor they missed. Rank how they'd most likely respond.

**Self Audit scenario:**
> Your partner brings up something small that bothered them — a comment you made, something you missed. Rank how you'd most likely respond.

| Option | Copy | Key |
|---|---|---|
| A | `{THEY_UC}` acknowledge it briefly — "yeah, fair" — and want to move past it immediately. Technically resolved. But `{you don't / they don't}` feel heard. `{THEY_UC're}` slightly cooler for the rest of the day. | `[A]` |
| B | `{THEY_UC}` spiral. What started as `{your/their}` grievance becomes a conversation about whether `{they're/you're}` a bad partner. Somehow `{you end up/they end up}` reassuring `{them/you}` about the thing `{they/you}` did. | `[C]` |
| C | `{THEY_UC}` apologize immediately and enthusiastically. Then do the exact same thing two weeks later. | `[U]` |
| D | `{THEY_UC}` listen, acknowledge it without collapsing or deflecting, and the air actually clears. `{You feel / They feel}` heard. The rupture gets repaired. | `[S]` |

---

### Q3 — The Communication Test
*Texting habits and digital patterns when apart*

**Partner Audit scenario:**
> You've been apart for three days — different schedules, sporadic contact. When you reconnect, what's the vibe from their side?

**Self Audit scenario:**
> You've been apart for three days — different schedules, sporadic contact. What's your vibe when you reconnect?

| Option | Copy | Key |
|---|---|---|
| A | `{THEY_UC}` pick up like nothing happened — warm, present, no reference to the gap. The distance clearly didn't register the same way for `{them/you}`. | `[A]` |
| B | There's a coolness `{you have to / they have to}` thaw. Nothing explicit — `{they'd/you'd}` deny it if asked — but the limited contact left a mark. Some relational maintenance required before things feel even. | `[C]` |
| C | `{THEY_UC}` also went quiet. Nobody reached out first. There's a weird texture to the reconnection that neither of you is naming directly. | `[U]` |
| D | `{THEY_UC}` checked in when it felt natural — not constantly, not absent. The reconnection feels easy. No accumulation, no residue. | `[S]` |

---

### Q4 — The Intimacy Spike
*The reaction immediately following intense vulnerability or a great date*

**Partner Audit scenario:**
> You shared something heavy — a real fear, something from before them you've never told anyone. In the days immediately after, how do they show up?

**Self Audit scenario:**
> Your partner shared something heavy — a real fear, something they've never told anyone. How do you show up in the days after?

| Option | Copy | Key |
|---|---|---|
| A | `{THEY_UC}` were present in the moment — kind, the right words. But in the days after `{they're/you're}` slightly more distant, like the closeness raised the stakes in a way `{they're/you're}` quietly managing. | `[A]` |
| B | `{THEY_UC}` immediately matched `{your/their}` vulnerability with `{their/your}` own — something bigger. The focus shifted before `{you'd/they'd}` finished processing. Connection, technically. But also a takeover. | `[C]` |
| C | `{THEY_UC}` were exactly right in the moment. And then nothing. No follow-up, no "hey, how are you feeling about what you shared?" It just evaporated. | `[U]` |
| D | `{THEY_UC}` sat in it with `{you/them}`. Asked a real follow-up question. Checked in two days later without being prompted. The thing `{you/they}` shared didn't disappear. | `[S]` |

---

### Q5 — The Accountability Test
*The reaction when feelings are hurt or a mistake is made*

**Partner Audit scenario:**
> You told them something they said hurt you. Rank how they'd most likely respond.

**Self Audit scenario:**
> Your partner told you that something you said hurt them. Rank how you'd most likely respond.

| Option | Copy | Key |
|---|---|---|
| A | `{THEY_UC}` apologize briefly and cleanly, then want to move on. Any attempt to stay in the conversation reads as relitigating. The closure feels imposed more than earned. | `[A]` |
| B | `{Your/Their}` hurt becomes evidence of something `{they/you}` need to process about `{themselves/yourself}`. By the end, `{you're/they're}` comforting `{them/you}` about the thing `{they/you}` did. | `[C]` |
| C | `{THEY_UC}` find the angle where it was actually complicated — or `{you're/they're}` too sensitive — or `{they/you}` didn't mean it that way. The apology, if it comes, arrives with conditions. | `[U]` |
| D | `{THEY_UC}` hear it. Take responsibility without collapsing or making it about `{them/you}`. The air is genuinely different afterward. | `[S]` |

---

### Q6 — The Crisis Test
*The reaction when one partner has a devastating, stressful day*

**Partner Audit scenario:**
> Something genuinely terrible happened — work, family, health. You're not okay and you told them. How do they show up?

**Self Audit scenario:**
> Something genuinely terrible happened to your partner — work, family, health. They told you they're not okay. How do you show up?

| Option | Copy | Key |
|---|---|---|
| A | `{THEY_UC}` acknowledge it — maybe try to solve it — then give `{you/them}` space. More space than `{you/they}` wanted. `{THEY_UC}` meant well. It felt like being handled rather than held. | `[A]` |
| B | Initially present and attentive — but the conversation finds its way to `{their/your}` parallel stress, or advice `{you/they}` didn't ask for, or a comparison that quietly shrinks what `{you're/they're}` going through. | `[C]` |
| C | Warm in the moment. But no follow-up comes. If `{you/they}` need more, `{you'd/they'd}` have to ask explicitly. The burden of receiving support stays with `{you/them}`. | `[U]` |
| D | `{THEY_UC}` showed up — actually there, not just technically. Asked what `{you/they}` needed. Checked in unprompted the next day. | `[S]` |

---

### Q7 — The Integration Test
*Blending into social circles, friend groups, and public social media*

**Partner Audit scenario:**
> A few months in. Rank which best describes their approach to bringing you into their world — friends, family, social life.

**Self Audit scenario:**
> A few months in. Rank which best describes your approach to bringing them into your world — friends, family, social life.

| Option | Copy | Key |
|---|---|---|
| A | Slow. `{You've/They've}` met one of `{their/your}` friends, maybe, in a low-stakes way. The relationship still exists somewhat in a bubble `{they haven't/you haven't}` opened. | `[A]` |
| B | Fast and curated. `{You've/They've}` met everyone — but it felt like a rollout. Deliberate. `{You were/They were}` the subject of scene-setting before `{you/they}` arrived. | `[C]` |
| C | Lots of "we should all get together soon" that never becomes actual plans. `{Their/Your}` friends know `{you/they}` exist. `{You/They}` haven't actually met them. | `[U]` |
| D | It happened naturally. `{You've/They've}` met the people who matter. Introduced with warmth and easy context. No performance, no avoidance. | `[S]` |

---

### Q8 — The Pace Test
*Handling timelines, commitment talks, and future planning*

**Partner Audit scenario:**
> You had a real conversation about where things are going. Rank which best describes their approach.

**Self Audit scenario:**
> You had a real conversation about where things are going. Rank which best describes your approach.

| Option | Copy | Key |
|---|---|---|
| A | `{THEY_UC}` engaged warmly but kept everything slightly vague — abstract, philosophical, unresolved. `{They seemed/You seemed}` comfortable leaving it there. Nothing landed concrete. | `[A]` |
| B | Very enthusiastic — lots of future language from `{them/you}`, declarations. But push on specifics — logistics, real timelines, actual decisions — and the conversation goes fuzzy. | `[C]` |
| C | Deflection or defensiveness. "Why does it need a label?" Or `{they/you}` agreed to something `{they/you}` clearly hadn't thought through and would revisit when convenient. | `[U]` |
| D | Direct. `{They told you/You told them}` where `{they/you}` actually are, including where `{they're/you're}` uncertain. `{You/They}` left knowing where `{you/they}` stood. | `[S]` |

---

## Part 2: Scoring Logic & Export Formats

### Scoring Math

| Click Order | Points |
|---|---|
| 1st (Most like `{them/me}`) | 3 |
| 2nd | 2 |
| 3rd | 1 |
| 4th (Least like `{them/me}`) | 0 |

Max per archetype: **24 pts** (3 × 8 questions)
Percentage: `Math.round((raw / 24) * 100)`
Blend rule: If top two archetypes are within **4 pts** of each other, surface a blend reading.

---

### Export Format 1: JSON Schema

```json
{
  "_schema": "rf-report-v1",
  "_exportedAt": "2026-07-12T14:33:00.000Z",
  "mode": "partner-audit",
  "answers": [
    {
      "qid": 1,
      "pressurePoint": "The Boundary Test",
      "ranked": ["S", "A", "U", "C"]
    }
  ],
  "scores": {
    "A": { "raw": 14, "pct": 58, "label": "Prominent" },
    "C": { "raw": 9,  "pct": 38, "label": "Contributing" },
    "U": { "raw": 5,  "pct": 21, "label": "Minimal" },
    "S": { "raw": 20, "pct": 83, "label": "Dominant" }
  },
  "result": {
    "primary": "S",
    "secondary": null,
    "blend": false,
    "primaryLabel": "The Secure Attacher",
    "primaryTagline": "The Healthy Baseline",
    "dominantSubtype": "The Secure Partner"
  }
}
```

**Threshold labels:**

| pct | label |
|---|---|
| 70–100% | Dominant |
| 50–69% | Prominent |
| 30–49% | Contributing |
| 0–29% | Minimal |

---

### Export Format 2: Viral Share Text Template

Optimized for native mobile clipboard → WhatsApp, iMessage, SMS. Max 200 chars per line, emoji used sparingly.

**Partner Audit — Share Template:**

```
🚩 just ran my relationship through RedFlag

their type: {PRIMARY_ARCHETYPE_NAME}
"{PRIMARY_TAGLINE}"

sub-type flagged: {DOMINANT_SUBTYPE}

{ONE_LINE_SUMMARY}

take the free quiz 👇
redflag.io
```

**Self Audit — Share Template:**

```
🚩 just audited myself on RedFlag

my type: {PRIMARY_ARCHETYPE_NAME}
"{PRIMARY_TAGLINE}"

sub-type: {DOMINANT_SUBTYPE}

{ONE_LINE_SUMMARY}

take the free quiz 👇
redflag.io
```

**One-Line Summary copy by archetype** (use in `{ONE_LINE_SUMMARY}`):

| Archetype | Partner Audit one-liner | Self Audit one-liner |
|---|---|---|
| `[A]` Avoidant | "they show up just enough to keep you — and just little enough to keep the exit open" | "i'm there when it's easy and hard to find when it gets real" |
| `[C]` Consumer | "everything is fine until you need to be the main character for five minutes" | "i'm basically running a real-time validation scan at all times lol" |
| `[U]` Under-Functioner | "great in theory, somehow always unavailable for the actual part" | "i have a lot of potential that i keep meaning to work on" |
| `[S]` Secure | "honestly refreshing — consistent, direct, actually does the repair work" | "apparently i'm well-adjusted which feels suspicious but i'll take it" |

**Blend variant** (when blend = true):

```
🚩 RedFlag says i'm a {PRIMARY}/{SECONDARY} blend

primary: {PRIMARY_ARCHETYPE_NAME} ({PRIMARY_PCT}%)
secondary: {SECONDARY_ARCHETYPE_NAME} ({SECONDARY_PCT}%)

{BLEND_SUMMARY}

redflag.io
```

**Blend summaries:**

| Blend | Summary |
|---|---|
| A + C | "avoidant energy with a side of needing you to notice i'm pulling away" |
| A + U | "emotionally unavailable AND somehow still not taking accountability for it" |
| C + U | "wants the validation but not the work that comes after" |
| A + S | "mostly secure, some old wiring still runs the show under pressure" |
| C + S | "healthy baseline with a validation habit that kicks in under stress" |
| U + S | "generally solid, slight accountability gap in the hard moments" |

---

### Export Format 3: HTML / Markdown Print Layout

Used by `buildReportHTML()` and `buildReportMD()` in the codebase. See below for section map.

**Section structure:**

```
[HEADER]
  Platform wordmark + mode label
  "Relationship Diagnostic Report"
  Date

[SCORE SUMMARY]
  Primary: {ARCHETYPE_NAME} — {PRIMARY_PCT}%
  {blend line if applicable}
  Score breakdown table:
    Archetype | Raw | % | Label
    ----      | --- | - | -----
    [A]       | 14  | 58| Prominent
    ...

[PRIMARY PROFILE]
  Archetype name + tagline
  Core wound paragraph (2–3 sentences)
  Dominant sub-type callout:
    Name, description, hallmark

[PRESSURE POINT BREAKDOWN]
  Table: Question | Your choice | Archetype scored
  (surfaces the 3-pt answers only)

[ACTION ITEMS]
  Bulleted list (3–5 items, archetype-specific)

[FOOTER]
  Disclaimer
  redflag.io
```

**Markdown template skeleton:**

```markdown
# RedFlag · {MODE_LABEL} Report
**{DATE}**

---

## Result: {PRIMARY_ARCHETYPE_NAME}
> {PRIMARY_TAGLINE}

**Primary score:** {PRIMARY_PCT}%{BLEND_LINE}

| Archetype | Score | % | Reading |
|---|---|---|---|
| {A_NAME} | {A_RAW}/24 | {A_PCT}% | {A_LABEL} |
| {C_NAME} | {C_RAW}/24 | {C_PCT}% | {C_LABEL} |
| {U_NAME} | {U_RAW}/24 | {U_PCT}% | {U_LABEL} |
| {S_NAME} | {S_RAW}/24 | {S_PCT}% | {S_LABEL} |

---

## {PRIMARY_ARCHETYPE_NAME} — Profile
{CORE_WOUND_PARAGRAPH}

**Your primary sub-type: {DOMINANT_SUBTYPE}**
{SUBTYPE_DESCRIPTION}

---

## Your Answers

| Pressure Point | Top Pick | Pattern |
|---|---|---|
{ANSWERS_TABLE_ROWS}

---

## What To Do With This
{ACTION_BULLETS}

---
*RedFlag is an educational platform. This report is not clinical diagnosis.*
```

---

### Export Format 4: PDF Deep-Dive Blueprint

**Format:** 8.5" × 11" (US Letter), 4 pages. Portrait orientation. Print via `window.open()` popup.

---

#### Page 1 — Cover

```
┌─────────────────────────────────────────────────────┐
│  🚩 REDFLAG             [MODE: Partner Audit]  10pt  │  ← Header bar (crimson bg, white text)
├─────────────────────────────────────────────────────┤
│                                                      │
│  RELATIONSHIP DIAGNOSTIC REPORT          14pt label  │
│  ─────────────────────────────────────────          │
│                                                      │
│                                          64pt display│
│              83%                                     │  ← Primary score, accent color
│                                                      │
│  THE SECURE ATTACHER                     38pt display│
│  The Healthy Baseline                    16pt italic  │
│                                                      │
│  ─────────────────────────────────────────          │
│  Assessed: July 12, 2026               12pt muted    │
│  Mode: Partner Audit                   12pt muted    │
│                                                      │
├─────────────────────────────────────────────────────┤
│  redflag.io  ·  Private & Confidential   10pt footer │
└─────────────────────────────────────────────────────┘
```

**Typography:** Archetype name — 38pt Georgia bold. Score — 64pt Georgia bold, accent color. Labels — 10–12pt monospace uppercase.

---

#### Page 2 — Score Breakdown

```
┌─────────────────────────────────────────────────────┐
│  🚩 REDFLAG  ·  Score Breakdown          Header bar  │
├─────────────────────────────────────────────────────┤
│                                                      │
│  DIAGNOSTIC SCORES                 14pt section head │
│  ─────────────────────────────────────────          │
│                                                      │
│  The Secure Attacher                                 │
│  ████████████████████░░░   83%  20/24  DOMINANT      │  ← Green bar, full width
│                                                      │
│  The Avoidant                                        │
│  ██████████████░░░░░░░░░   58%  14/24  PROMINENT     │  ← Blue bar
│                                                      │
│  The Consumer                                        │
│  █████████░░░░░░░░░░░░░░   38%  9/24   CONTRIBUTING  │  ← Crimson bar
│                                                      │
│  The Under-Functioner                                │
│  █████░░░░░░░░░░░░░░░░░░   21%  5/24   MINIMAL       │  ← Amber bar
│                                                      │
│  ─────────────────────────────────────────          │
│  HOW TO READ THIS                  12pt label        │
│  70–100%  Dominant — core pattern                    │
│  50–69%   Prominent — present, may blend             │  ← Right column, 30% width
│  30–49%   Contributing — stress-triggered            │
│  0–29%    Minimal — situational only                 │
│                                                      │
│  ┌─ BLEND READING ─────────────────────────────┐   │
│  │ [Only shown when blend = true]               │   │  ← Amber border box
│  │ {BLEND_SUMMARY_SENTENCE}                     │   │
│  └─────────────────────────────────────────────┘   │
│                                                      │
├─────────────────────────────────────────────────────┤
│  redflag.io  ·  Page 2 of 4              10pt footer │
└─────────────────────────────────────────────────────┘
```

**Visual specs:** Score bars use `<div>` with `width: {pct}%; background: {archetype color}`. Bar height: 12px, border-radius: 6px, on a muted track.

---

#### Page 3 — Primary Archetype Deep Dive

```
┌─────────────────────────────────────────────────────┐
│  🚩 REDFLAG  ·  Primary Pattern          Header bar  │
├─────────────────────────────────────────────────────┤
│                                                      │
│  [A] / [C] / [U] / [S]              Archetype badge │
│  THE {ARCHETYPE_NAME}               24pt display     │
│  {TAGLINE}                          14pt italic muted│
│                                                      │
│  THE CORE WOUND                     12pt label       │
│  {CORE_WOUND_TEXT — 3–4 sentences, 13pt body}        │
│                                                      │
│  ─────────────────────────────────────────          │
│                                                      │
│  ┌─ PRIMARY SUB-TYPE IDENTIFIED ───────────────┐    │
│  │  {DOMINANT_SUBTYPE_NAME}       16pt bold     │    │  ← Accent-colored border
│  │  {SUBTYPE_DESCRIPTION — 2 paragraphs, 12pt}  │    │
│  │                                              │    │
│  │  HALLMARK                                    │    │
│  │  {HALLMARK_TEXT}               12pt italic   │    │
│  └─────────────────────────────────────────────┘    │
│                                                      │
│  OTHER PATTERNS PRESENT             12pt label       │
│  {Only shown if blend = true}                        │
│  {SECONDARY_ARCHETYPE brief paragraph, 12pt}         │
│                                                      │
├─────────────────────────────────────────────────────┤
│  redflag.io  ·  Page 3 of 4              10pt footer │
└─────────────────────────────────────────────────────┘
```

---

#### Page 4 — Action Framework

```
┌─────────────────────────────────────────────────────┐
│  🚩 REDFLAG  ·  What To Do With This    Header bar  │
├─────────────────────────────────────────────────────┤
│                                                      │
│  WHAT THIS LOOKS LIKE IN PRACTICE   14pt label       │
│  • {BEHAVIORAL_BULLET_1}                             │
│  • {BEHAVIORAL_BULLET_2}                             │  ← 3–5 bullets, 13pt
│  • {BEHAVIORAL_BULLET_3}                             │
│                                                      │
│  ─────────────────────────────────────────          │
│                                                      │
│  QUESTIONS WORTH ASKING             14pt label       │
│  {3–4 reflection prompts, archetype-specific}        │
│  Each prompt: 13pt italic                            │
│                                                      │
│  ─────────────────────────────────────────          │
│                                                      │
│  NEXT STEPS                         14pt label       │
│  {3 action items, direct and practical}              │
│                                                      │
│  ┌─ WHEN TO SEEK SUPPORT ──────────────────────┐    │
│  │  If the patterns in this report are causing  │    │  ← Amber border
│  │  real distress, consider speaking with a     │    │
│  │  licensed therapist. Couples counseling is   │    │
│  │  not recommended when coercive patterns      │    │
│  │  are present. Individual support first.      │    │
│  └─────────────────────────────────────────────┘    │
│                                                      │
│  ─────────────────────────────────────────          │
│                                                      │
│  RedFlag is an educational platform. Content is      │  ← 10pt muted
│  research-informed and does not constitute clinical  │
│  diagnosis or therapy.                               │
│                                                      │
│  redflag.io                                          │
├─────────────────────────────────────────────────────┤
│  redflag.io  ·  Page 4 of 4              10pt footer │
└─────────────────────────────────────────────────────┘
```

**Per-archetype action items (populate `NEXT STEPS` and `BEHAVIORAL_BULLETS`):**

**`[A]` Avoidant:**
- What this looks like: creates distance when things deepen; uses vagueness as self-protection; the exit is always half-open
- Reflection prompts: "When do you/they most reliably pull back?" / "What would it mean to fully arrive in this relationship?"
- Next steps: Name the pattern, not the motive. Track whether distance increases at key milestones. Consider whether this dynamic is manageable or structural.

**`[C]` Consumer:**
- What this looks like: cycles of intensity followed by withdrawal; conversations drift back to their own needs; external validation runs in the background
- Reflection prompts: "When does the warmth feel transactional?" / "What happens when you stop chasing the high?"
- Next steps: Log the cycle (flood / gap / re-flood). Test whether quiet consistency feels like love or boredom to you/them. Notice what triggers the validation scan.

**`[U]` Under-Functioner:**
- What this looks like: always a reason it's not quite ready; apologies without behavior change; the relationship requires over-functioning from the other person
- Reflection prompts: "Who's carrying the most weight in this relationship?" / "What would full accountability actually cost?"
- Next steps: Name the over/under-function split explicitly. Stop carrying what isn't yours. Watch whether behavior changes when the rescue stops.

**`[S]` Secure Attacher:**
- What this looks like: consistent, direct, repairs quickly; holds space without absorbing anxiety; the relationship has a foundation
- Reflection prompts: "Is the calm genuine security or conflict aversion?" / "Where does this pattern show cracks under real stress?"
- Next steps: This is the baseline to protect and build from. The question isn't what's wrong — it's whether both people can meet here.

---

## Part 3: Core Archetype Profiles

### `[A]` The Avoidant
**Fear of Closeness**

**The Core Wound**

The Avoidant doesn't lack the capacity for love. They fear what love costs.

At some early point — through a caregiver who was inconsistent, a parent who met closeness with criticism, or a formative heartbreak that arrived before they had the vocabulary to process it — intimacy and threat got wired together. The result is a nervous system that reads "getting close" as danger and responds with distance as self-protection.

This is not coldness. This is armor that became invisible over time.

In practice: The Avoidant often presents as independent, self-sufficient, low-drama. Present during the easy chapters and absent — emotionally, physically, or both — when depth is required. They don't leave because they don't care. They leave because caring, fully, feels unsurvivable.

**Sub-Types**

**The Ghost-in-Waiting**
Present enough to qualify as a partner. Absent enough to maintain the escape hatch. The Ghost doesn't end things dramatically — they slow-fade. One shorter text, one missed call, one "let's figure out this weekend" that never gets figured out. The breakup always feels sudden to the other person. It was anything but.
*Hallmark: Warmth in person, absence everywhere else. Never picks a fight — just quietly deprioritizes until the relationship starves.*

**The Contrarian / Debater**
Creates just enough friction to justify not fully arriving. Picks at flaws, manufactures distance through criticism. If they can maintain a list of reasons the other person isn't quite right, they never have to admit the real reason: the right person is terrifying. The relationship is perpetually "almost" — almost solid, almost right, almost the right time.
*Hallmark: The relationship has never quite arrived — even after a year, it feels provisional.*

**The "Right Person, Wrong Time" Martyr**
The noblest exit in the avoidant toolkit. Frames withdrawal as sacrifice — "I can't give you what you deserve right now." The timing is always wrong. The timing is always managed. "Wrong time" is a way to hold the door open just enough — enough to feel kind, not enough to require presence.
*Hallmark: Leaves with warmth. Returns when the next person gets close to them.*

---

### `[C]` The Consumer
**Hungry for Validation**

**The Core Wound**

The Consumer learned early that love was conditional — earned through performance, beauty, achievement, or being the most interesting person in the room. What they didn't receive was the quieter message that they were worth loving simply for existing.

The adult version: a relationship style built around the hunt for proof. Proof that they're chosen. That they're special to this particular person. That they haven't been replaced. This is not vanity. It is unmet hunger.

**Sub-Types**

**The Love-Bomber**
The first chapter is extraordinary — because it was architected to be. The rush of being seen, declared, and claimed is completely real. What's not yet visible is that this intensity was produced not from surplus but from strategy: attach quickly, then manage the attachment through calibrated withdrawal. The cycle: flood → withdrawal → flood → withdrawal.
*Hallmark: Said "I love you" before the 60-day mark. Future-planned in the first month. Then, without clear incident, became half as available.*

**The Main Character**
Not malicious — just constitutionally cast as the protagonist. The Main Character isn't trying to eclipse their partner. They're incapable of staying in the supporting role under emotional demand. Your crisis gets heard and then, mid-conversation, the focus shifts. Your good news is met with their related better news.
*Hallmark: Excellent in low-stakes moments. Functionally disappears when you actually need the spotlight.*

**The Collector / Rotator**
Keeps multiple connections alive at low heat. Doesn't cheat technically — maintains optionality. Each person in the rotation provides a different flavor of validation. No one is fully released. No one is fully claimed. The moment someone pushes for exclusivity, they become "the needy one."
*Hallmark: Always slightly unavailable. Their social world implies richer complexity than you have access to.*

---

### `[U]` The Under-Functioner
**Fear of Accountability**

**The Core Wound**

For the Under-Functioner, being fully responsible for a relationship — its upkeep, its conflicts, its repair — feels like being set up to fail. At some level, accountability = disappointment = losing love. So the system operates slightly below full capacity: not enough to be abandoned, not enough to be held accountable.

This is not laziness. It is a sophisticated (if unconscious) management of perceived risk. The Under-Functioner's partner almost always Over-Functions — carrying more emotional labor, more logistics, more repair work — because the Under-Functioner has calibrated the relationship to require it.

**Sub-Types**

**The Project (Fixer-Upper)**
The relationship always has a problem the partner is helping solve. The problem is never quite solved — when it comes close, a new one materializes. The Project unconsciously maintains a state of requiring rescue, because rescue is the love they recognize. A partner who shows up without being needed feels unsafe.
*Hallmark: There's always a reason the relationship isn't "quite there yet" — and it's always rooted in their current project (career, health, "figuring things out").*

**The Peter Pan (Forever Child)**
Permanently adolescent in relational terms. May be professionally accomplished or socially charming — but emotionally operating in an earlier developmental chapter. Accountability means adulthood. Adulthood means conditional love. The logic: if I never fully grow up, I can never be held to adult standards.
*Hallmark: Plans made loosely. Feelings rarely named directly. Accountability conversations derailed by charm, humor, or a convenient crisis.*

---

### `[S]` The Secure Attacher
**The Healthy Baseline**

**The Core Reading**

This is not the absence of history. It is the presence of repair.

The Secure Attacher has either early attachment figures who were consistently responsive — not perfect, but reliably present when it mattered — or a longer reckoning of their own, through therapy, reflection, or the hard education of difficult relationships, that brought them to functional security.

Security is not ease. It is not never being hurt, never being afraid, never needing reassurance. It is the capacity to hold those feelings without letting them run the relationship.

**Sub-Type**

**The Secure Partner**
Knows what they want. Says what they need. Can hold their partner's anxiety without absorbing it or dismissing it. Repairs quickly — not because conflict doesn't cost them, but because they've internalized that rupture and repair is the actual texture of a real relationship. They don't catastrophize distance. They don't perform closeness. The hallmark is not perfection — it is consistency.
*Caution reading: High secure scores can occasionally reflect emotional suppression or conflict-aversion rather than genuine security. Ask: is the calm because things feel safe — or because having needs has historically created problems?*

---

## Part 4: Blog Articles

### Article 1: The Chemistry Illusion
**"The Chemistry Illusion: Why the Love-Bomber Feels Like Your Soulmate (Until Day 90)"**

You know that feeling.

The one where you met someone and your brain immediately said: *this is different.* Not butterflies — something more seismic. The texts that go on until 2am. The plans that form like there's no reason to wait. The way they look at you like you're the most interesting person in any room they've been in, and somehow you believe them, because no one has ever looked at you quite like that before.

You weren't naive. You weren't moving too fast. What was happening felt real, because most of it was.

Here's what nobody tells you about love bombing: the warmth is genuine. The connection is genuine. The problem isn't that you fell for something fake — it's that you fell for something that was designed to run at that intensity for exactly as long as it needed to, and no longer.

**What Love Bombing Actually Is (And Isn't)**

Love bombing gets described in pop psychology as a manipulation tactic — which is technically accurate and completely inadequate.

Most Love-Bombers are not sitting in a dimly lit room calculating your attachment vulnerabilities. Most of them are people with a deep wound around validation — people who learned, at some early and formative point, that love is earned through performance rather than presence. The bombing is what happens when that wound meets a new person who seems like the answer.

They're not lying when they say you're extraordinary. They're flooding the space with the intensity they wish someone had given them. The manipulation — if we even want to call it that — is mostly unconscious. What's being managed isn't you. It's their own terror of intimacy, which arrives like clockwork right around the point where things could become real.

**Why Day 90**

The 90-day mark is not a rule. It's a range — could be six weeks, could be four months. What it represents is the moment the nervous system can no longer maintain peak output.

Early-stage love activates dopamine systems measurably similar to the early stages of stimulant use. The neurochemistry of new attachment is supposed to stabilize over time, settling into the quieter rewards of secure connection. For most people, this settling feels natural — the relationship deepens even as the fireworks soften. For the Love-Bomber, this is where it unravels.

The settling reads as loss. The absence of intensity feels like evidence that something is wrong. So it does one of two things: recalibrates by finding a new person, or pulls back and waits to see if you'll chase. Almost always, you chase. The intensity is still in your body. You remember it. You want it back.

**The Cycle in Practice**

*Phase 1 — The Flood (Weeks 1–8).* Constant contact. Deep, revelatory conversations. Future-planning that feels natural even at this speed. You feel seen in a way that is genuinely rare.

*Phase 2 — The Recalibration (Weeks 8–12).* It's subtle at first. A text that takes longer. Plans that are a little less certain. You notice but don't say anything, because maybe you're being too sensitive. You actually have that thought: *maybe I'm too sensitive.*

*Phase 3 — The Gap.* You're still technically together. But there's a distance between the relationship you had and the relationship you have, and you can feel the gap with your whole body, and you don't know how to talk about it without sounding like you're asking for too much.

*Phase 4 — The Re-flood.* You say something. Or pull back yourself. The original flood returns — briefly, convincingly enough — and you feel it again and think: *there it is. It's still real.* You weren't imagining it. But you're now in the cycle.

**What You Can Do With This**

First: you are not stupid for falling for it. The warmth was real. The recalibration phase is diagnostic — what happens when the intensity drops is information. A secure person will feel the natural settling and lean into it. A Love-Bomber will start to disappear.

Second: ask yourself the harder question. Not "are they love-bombing me?" — but "am I addicted to the high?" If quiet consistency has ever felt boring to you, that's worth sitting with.

Soulmate energy is real. It can also be manufactured. The two are indistinguishable until the factory closes.

---

### Article 2: Trapped in the Orbit
**"Trapped in the Orbit: How to Tell if You're Being 'Pocketed' by a Collector"**

You're not confused about what you two are.

You're confused about *why* you're confused, because everything on the surface looks fine. You see each other. The conversations are good. There's obvious chemistry. And yet. You're not quite in. You haven't met a single friend. You don't appear on their grid, not once in eight months. When plans are made, they're made on their schedule with ambient flexibility that means they can evaporate without much notice.

You're not in a relationship. You're in an orbit.

**The Rotator's Logic**

The Collector keeps multiple connections alive at low heat — never fully committing to any, never fully releasing them. The logic, operating mostly below conscious awareness: *If I fully commit to one person, I become vulnerable to that one person. If I keep several people at a consistent warmth, I have options. Options are protection.*

Every time someone in the rotation pushes for more definition, they become — in the Collector's nervous system — the threat. The person who wants to be chosen introduced the risk of loss. Suddenly they're "too intense," or "the timing isn't right." And someone else in the rotation becomes temporarily more appealing. This is not a strategy. It's a wound wearing a very effective disguise.

**Pocketing vs. Privacy**

Privacy looks like: they're naturally private, they've told you this, their whole life is relatively low-profile. Pocketing looks like: *you specifically* are not part of their visible world, while other things clearly are. Their friends know they're "seeing someone" but have no idea who.

The tell: how they handle an accidental collision. If a friend shows up unexpectedly while you're together, how are you introduced? With warmth and context? Or with a slight recalibration — a vague title, a reason to move on quickly?

**The Eight Signs You're in the Orbit**

1. Plans are confirmed last-minute, reliably. Not sometimes — consistently.
2. Their phone is a closed system. Perpetually faced down, notifications silenced, quick to sleep.
3. You've never seen them initiate social media acknowledgment. Not once.
4. Their friends know they're "seeing someone" but not who.
5. Emotional availability is highest right after you've pulled back.
6. The future is always hypothetical — pointed toward something, never resolving.
7. You have the same defining conversation on a loop. Ends warmly. Nothing changes.
8. You feel peripheral in a relationship that doesn't look peripheral.

**What You're Owed**

You are owed a conversation. Not a perfect one — but a real one with real answers. "Are we exclusive?" is a reasonable question. If the answer is a warm drift toward nothing, that is an answer.

The Collector will not usually get cold when asked. They'll get warm. They'll say something that sounds like an answer but resolves to nothing. They'll make you feel a little bit unreasonable for having asked.

Pay attention to that last part. That's the clearest signal of all.

---

### Article 3: The Caretaker Trap
**"The Caretaker Trap: When Loving a 'Project' Turns You Into Their Therapist"**

There was a moment — probably early — when it felt like strength.

You saw something in them that other people missed. The intelligence underneath the chaos. The sensitivity underneath the self-destruction. The person they could be if someone would just believe in them long enough, consistently enough, with the particular flavor of love that you specifically had to offer.

The thing about the Caretaker Trap is that it never starts as a trap. It starts as love.

**What a "Project" Actually Is**

The Project isn't performing incompetence. The struggles are real. What's instructive isn't the struggles themselves — it's the pattern around them. There's always a reason why now isn't quite the right time for full accountability. The job situation. The mental health chapter. The family thing. Each individual element is sympathetic. The constellation of them, sustained over time, is the structure.

Underneath: a person for whom being fully present in a relationship feels like a test they're not sure they can pass. Better to be almost-there than to try and fail. Better to keep someone close enough to serve as a steady tether, without crossing into the full accountability of a mutual relationship.

**The Line Between Partner and Therapist**

Here is the question worth sitting with: When was the last time you were having a bad week and *they* were the person who helped carry it?

The line is drawn around *directionality and reciprocity*. A relationship where one person's needs consistently organize the relationship's emotional bandwidth — that's not a partnership. That's a treatment relationship with rent.

**What Enabling Looks Like From the Inside**

Enabling feels, from the inside, exactly like love. It looks like: covering for them when they don't follow through. Softening the consequence when accountability would hurt. Renegotiating your own needs downward. Staying through behavior you said you wouldn't stay through — because leaving feels like abandonment, and they need you right now.

The cruel irony: enabling is not neutral. It is an active force that maintains the Project in their current state. You are not helping them heal. You are keeping the conditions stable enough that healing isn't required.

**The Hardest Part: You Have a Role in This**

The people most likely to fall into the Caretaker Trap learned, somewhere in their history, that love = labor. When they fell for someone with problems they could solve, some part of them recognized the configuration: *this is how love works. This is what I'm for.*

The Caretaker Trap is, at its deepest level, a story two people tell together — where one person's need and another person's wound find each other and agree, without a word, to confirm everything the other already believed about love.

**Getting Out**

Getting out doesn't necessarily mean leaving. It means leaving the role. What you're watching for: Can they hold their own weight when you stop carrying it? If yes: you may be watching someone beginning to move. That's worth staying to see. If no: the relationship required you to be smaller than you are. And no amount of love is going to change that.

---

## Developer Notes

### Mode Toggle State

```javascript
const MODES = { PARTNER: "partner-audit", SELF: "self-audit" };

const TOKEN_MAP = {
  PARTNER: {
    THEY: "they", THEIR: "their", THEM: "them",
    THEYRE: "they're", THEYVE: "they've",
    THEY_UC: "They", SUBJECT: "Your partner",
    RANK_PROMPT: "Rank how they'd most likely respond.",
  },
  SELF: {
    THEY: "you", THEIR: "your", THEM: "you",
    THEYRE: "you're", THEYVE: "you've",
    THEY_UC: "You", SUBJECT: "You",
    RANK_PROMPT: "Rank how you'd most likely respond.",
  },
};

function renderCopy(template, mode) {
  const tokens = TOKEN_MAP[mode];
  return template.replace(/\{(\w+)\}/g, (_, key) => tokens[key] ?? `{${key}}`);
}
```

### Score Computation

```javascript
const CLICK_POINTS = [3, 2, 1, 0];
const ARCHETYPE_KEYS = ["A", "C", "U", "S"];

function computeScores(answers) {
  const scores = Object.fromEntries(ARCHETYPE_KEYS.map(k => [k, 0]));
  for (const { ranked } of answers) {
    ranked.forEach((key, i) => { scores[key] += CLICK_POINTS[i]; });
  }
  return scores;
}

function computeResult(scores) {
  const sorted = Object.entries(scores).sort((a, b) => b[1] - a[1]);
  const [[pk, ps], [sk, ss]] = sorted;
  const blend = (ps - ss) <= 4;
  const pct = v => Math.round((v / 24) * 100);
  const LABELS = v => v >= 70 ? "Dominant" : v >= 50 ? "Prominent" : v >= 30 ? "Contributing" : "Minimal";
  return {
    primary: pk, secondary: blend ? sk : null, blend,
    scores: Object.fromEntries(
      Object.entries(scores).map(([k, v]) => {
        const p = pct(v);
        return [k, { raw: v, pct: p, label: LABELS(p) }];
      })
    ),
  };
}
```

### Archetype Constant

```javascript
const ARCHETYPES = {
  A: {
    name: "The Avoidant", tagline: "Fear of Closeness",
    color: "#3E7098",
    subtypes: ["The Ghost-in-Waiting", "The Contrarian / Debater", "The 'Right Person, Wrong Time' Martyr"],
  },
  C: {
    name: "The Consumer", tagline: "Hungry for Validation",
    color: "#B03020",
    subtypes: ["The Love-Bomber", "The Main Character", "The Collector / Rotator"],
  },
  U: {
    name: "The Under-Functioner", tagline: "Fear of Accountability",
    color: "#9A6B15",
    subtypes: ["The Project", "The Peter Pan"],
  },
  S: {
    name: "The Secure Attacher", tagline: "The Healthy Baseline",
    color: "#2E7D46",
    subtypes: ["The Secure Partner"],
  },
};
```

---

*RedFlag is an educational platform. Content is research-informed and does not constitute clinical diagnosis or therapy. If you're experiencing relationship distress, consider speaking with a licensed therapist.*
