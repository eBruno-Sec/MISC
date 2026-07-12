# RedFlag — Self-Assessment Content Spec
## Multi-Role Architecture Brief · Quiz v2 · 2026-07-12

---

## Overview

This document covers the complete content and architecture blueprint for **RedFlag's self-assessment mode**: a scenario-ranking quiz that diagnoses the user's own attachment archetype rather than their partner's red flags. Intended audience: developers, content team, and product leads.

---

## Scoring Architecture

### Click-Order Ranking System

Each question presents a real-world scenario with **4 unlabeled option cards**. The user clicks options in order of likelihood (how they would most plausibly respond). Each click-order maps to a point value:

| Click Order | Label | Points |
|---|---|---|
| 1st click | Most Likely | 3 |
| 2nd click | 2nd Likely | 2 |
| 3rd click | 3rd Likely | 1 |
| 4th click | Least Likely | 0 |

### Archetype Score Calculation

Each option maps to one of 4 archetypes. Final scores are summed across all 8 questions.

- **Maximum per archetype:** 24 points (3 pts × 8 questions)
- **Conversion:** `(raw score / 24) × 100` = percentage
- **Primary archetype:** Highest raw score
- **Blended results:** If two archetypes are within 4 points of each other, surface a blend reading

### Archetype Keys (Internal — Not Shown to Users)

| Key | Name |
|---|---|
| `A` | The Avoidant |
| `B` | The Consumer |
| `C` | The Under-Functioner |
| `D` | The Secure Attacher |

---

## Part 1: The 8 Quiz Questions

Each question: scenario text + 4 unlabeled option cards. Internal archetype key is listed for each option — do **not** surface to users.

---

### Q1 — The Boundary Test
*Pressure point: Needing space / saying no*

**Scenario:**
> Your partner asks to spend Saturday together, but you'd already mentally set that day aside as solo time to recharge. What's most likely your response?

| Option | Text | Archetype |
|---|---|---|
| A | You say you have plans — vague ones — and feel a wave of relief when they don't push back. You don't explain. | `A` Avoidant |
| B | You say yes immediately, then spend the week quietly hoping they'll read your mood and offer to reschedule on their own. | `B` Consumer |
| C | You go along with it, build quiet resentment through the day, and bring it up three weeks later during a fight about something else entirely. | `C` Under-Functioner |
| D | You tell them honestly that you'd planned some solo time, and suggest another day you're actually excited about. | `D` Secure |

---

### Q2 — The Conflict Test
*Pressure point: Handling minor grievances*

**Scenario:**
> Your partner made a comment in front of friends that stung. It wasn't malicious — but it landed wrong. What's your move?

| Option | Text | Archetype |
|---|---|---|
| A | You let it go in the moment. And the next one. And the one after that. Until one day the list is long enough that you exit quietly. | `A` Avoidant |
| B | You post something vague on your story and wait to see if they notice and ask what's wrong. | `B` Consumer |
| C | You mention it three weeks later in an unrelated argument — louder than you intended. | `C` Under-Functioner |
| D | You bring it up privately, same day or the next morning. "Hey, that comment earlier — can we talk about it for a sec?" | `D` Secure |

---

### Q3 — The Communication Test
*Pressure point: Texting habits / digital patterns when apart*

**Scenario:**
> You're both busy for three days — different cities, different schedules. How does the silence sit with you?

| Option | Text | Archetype |
|---|---|---|
| A | Honestly? Fine. You almost prefer it. The distance gives you room to breathe that you didn't realize you needed. | `A` Avoidant |
| B | You're checking their last-active, overthinking every gap, drafting texts you delete before you can send them. | `B` Consumer |
| C | You go quiet to "give them space" — but really you're hoping they'll reach out first. When they don't, you feel abandoned. But you don't say that. | `C` Under-Functioner |
| D | You send a quick check-in — low pressure, no hidden agenda — and trust the rhythm you've both built. | `D` Secure |

---

### Q4 — The Intimacy Spike
*Pressure point: Reaction immediately following intense vulnerability*

**Scenario:**
> Your partner just shared something heavy — a real fear, an old wound, something they've never told anyone. The room goes quiet. What happens inside you?

| Option | Text | Archetype |
|---|---|---|
| A | You feel the weight of it and quietly panic. This level of closeness feels like obligation. You change the subject. | `A` Avoidant |
| B | You immediately match it with your own story — a bigger one — because this feels like a moment you should show up with equal intensity. | `B` Consumer |
| C | You say all the right things in the moment, then go distant for two days with no explanation you can name. | `C` Under-Functioner |
| D | You stay present. You don't rush to fix it. You ask one gentle follow-up and let them actually feel heard. | `D` Secure |

---

### Q5 — The Accountability Test
*Pressure point: Reaction when they hurt the user's feelings*

**Scenario:**
> You tell your partner that something they said hurt you. Before they respond — what are you expecting? What outcome have you already braced for?

| Option | Text | Archetype |
|---|---|---|
| A | You've already packaged your hurt as "just venting" to lower the stakes. You're not really expecting them to take it in. | `A` Avoidant |
| B | You want a full, visible mea culpa — an apology that matches the size of the impact. Quickly. Anything less reads as not caring. | `B` Consumer |
| C | You expect them to turn it around — to find a reason why you misunderstood or overreacted. You're already drafting your counter. | `C` Under-Functioner |
| D | You expect a real conversation — not painless, but honest. You trust the outcome will be something you both can live with. | `D` Secure |

---

### Q6 — The Crisis Test
*Pressure point: Reaction when the user has a devastating day*

**Scenario:**
> Something genuinely terrible happened today — work, family, health. You're not okay. What do you actually do?

| Option | Text | Archetype |
|---|---|---|
| A | You handle it alone. Telling them feels like a burden, or too intimate, or risky in ways you can't quite articulate to yourself. | `A` Avoidant |
| B | You tell them immediately — partly for support, but also watching how they respond. Their reaction will tell you something important about the relationship. | `B` Consumer |
| C | You hint at it. "Rough day." You wait to see if they dig in. If they don't, you feel invisible — but you never said you needed them to. | `C` Under-Functioner |
| D | You reach out directly: "I need to talk. Not okay right now." You let them actually show up for you. | `D` Secure |

---

### Q7 — The Integration Test
*Pressure point: Blending into social circles, family, and social media*

**Scenario:**
> Three months in. Your friends ask when they're going to meet this person. What's your gut response?

| Option | Text | Archetype |
|---|---|---|
| A | You feel mildly seized. Meeting friends makes it Real. You're not sure you're ready for it to be Real. | `A` Avoidant |
| B | You've already been quietly staging for this moment. Outfit drafted, context pre-briefed, narrative curated. You want it to go perfectly. | `B` Consumer |
| C | You haven't mentioned it to them either. Social merging is complicated. You'd rather let it happen vaguely, whenever. | `C` Under-Functioner |
| D | You feel ready — it's a natural next step. You arrange a low-key hangout and let it unfold. | `D` Secure |

---

### Q8 — The Pace Test
*Pressure point: Handling timelines, commitment talks, and future planning*

**Scenario:**
> Six months in. They bring up the future casually but clearly — something about where this is going. How do you land?

| Option | Text | Archetype |
|---|---|---|
| A | You feel a flicker of something — pressure, maybe — and manage it by keeping the conversation abstract, philosophical, unresolved. | `A` Avoidant |
| B | Your excitement spikes — not because you've thought it through, but because them bringing it up first feels like confirmation that you're chosen. | `B` Consumer |
| C | You deflect or get slightly defensive. "We'll figure it out." Not because you don't like them — because accountability to a future is terrifying. | `C` Under-Functioner |
| D | You share where you actually are — even if that's "I'm not ready to define this yet." You say it directly, without dramatics. | `D` Secure |

---

## Part 2: Core Archetype Profiles

### Scoring Thresholds

| Score % | Reading |
|---|---|
| 70–100% | **Dominant** — this pattern is primary |
| 50–69% | **Prominent** — significant presence, likely with a secondary blend |
| 30–49% | **Contributing** — shows up under stress or in specific dynamics |
| 0–29% | **Minimal** — situational, not a core pattern |

---

### Profile 1: The Avoidant
**Fear of Closeness**

---

**The Core Wound**

The Avoidant doesn't lack the capacity for love. They fear what love costs.

At some early point — through a caregiver who was inconsistent, a parent who met closeness with criticism, or a formative heartbreak that arrived before they had the vocabulary to process it — intimacy and threat got wired together. The result is a nervous system that reads "getting close" as danger and responds with distance as self-protection.

This is not coldness. This is armor that became invisible over time.

In practice: The Avoidant often presents as independent, self-sufficient, low-drama. They're the partner who seems fine when you're together and unreachable when you're apart. The person who can be present during the easy chapters and absent — emotionally, physically, or both — when depth is required.

They don't leave because they don't care. They leave because caring, fully, feels unsurvivable.

---

**The Three Sub-Types**

**The Ghost-in-Waiting**

Present enough to qualify as a partner. Absent enough to maintain the escape hatch.

The Ghost doesn't end things dramatically. They slow-fade — one shorter text, one missed call, one "let's figure out this weekend" that never gets figured out. By the time their partner recognizes what's happening, the Ghost has been emotionally checked out for months. The breakup, when it comes, always feels sudden to the other person. It was anything but.

*Hallmark behavior:* Warmth in person, absence everywhere else. Never picks a fight — just quietly deprioritizes until the relationship starves.

---

**The Contrarian**

Creates friction to justify not arriving.

The Contrarian is a subtle archetype. On the surface they seem engaged — even challenging, which can read as chemistry. But the pattern: they find the flaw in every plan, pick at your enthusiasm, keep a mental ledger of reasons this might not work. The relationship is perpetually "almost" — almost solid, almost right, almost the right time.

It isn't really about the flaws they're citing. It's that a reason-not-to is always cheaper than the vulnerability of fully choosing someone.

*Hallmark behavior:* The relationship has never quite arrived — even after a year, it feels provisional.

---

**The "Right Person, Wrong Time" Martyr**

The noblest exit in the avoidant toolkit.

The Martyr doesn't frame their withdrawal as selfishness — they frame it as sacrifice. "I can't give you what you deserve right now." "The timing is just off." "If we'd met two years from now..." There's a real tenderness in how it's delivered, which is part of why it's so disorienting to receive.

The timing is never an accident. The timing is managed. "Wrong time" is a way to hold the door open just enough — enough to feel kind, not enough to require presence.

*Hallmark behavior:* Leaves with warmth. Returns when the next person gets close to them.

---

### Profile 2: The Consumer
**Hungry for Validation**

---

**The Core Wound**

The Consumer learned early that love was conditional — earned through performance, beauty, achievement, or being the most interesting person in the room. What they didn't receive was the quieter message that they were worth loving simply for existing.

The adult version of this wound is a relationship style built around the hunt for proof. Proof that they're chosen. That they're special to this particular person. That they haven't been replaced.

This is not vanity. It is unmet hunger.

The Consumer doesn't mean to make everything about them. It's that their nervous system is constantly running a threat-detection scan — *am I still valued?* — and the scan requires constant input to stay quiet.

---

**The Three Sub-Types**

**The Love-Bomber**

Weaponized intensity. Consciously or not.

The first chapter with a Love-Bomber is extraordinary — because it was architected to be. The rush of being seen, declared, and claimed is completely real. You're not imagining the electricity. What you're not yet seeing is that this level of intensity was produced not from surplus, but from strategy: attach the target quickly, then manage the attachment through calibrated withdrawal.

The cycle: flood → withdrawal → flood → withdrawal. The partner spends the relationship trying to get back to Day 14 when everything felt perfect. The Love-Bomber knows, in their body if not in their mind, exactly how long to wait before the next flood.

*Hallmark behavior:* Said "I love you" before the 60-day mark. Future-planned in the first month. Suddenly, without clear incident, became half as available.

---

**The Main Character**

Not malicious. Just constitutionally cast as the protagonist.

The Main Character isn't trying to eclipse their partner. They're just incapable of staying in the supporting role for long. Your crisis is briefly interesting to them — and then somehow, mid-conversation, the focus shifts. Your good news is met with their related better news. Your grief is heard and then pivoted to their grief which is, importantly, also happening.

This is not cruelty. It's an attentional architecture that collapses inward under emotional demand.

*Hallmark behavior:* Excellent in low-stakes moments. Disappears — subtly, functionally — when you actually need the spotlight.

---

**The Collector (The Rotator)**

Keeps multiple connections alive at low heat.

The Collector doesn't cheat in the technical sense. They maintain optionality. There are always two or three people in various states of warmth — someone they're "not really seeing anymore" but still texting, someone who's "just a friend" but in a way that requires management, someone from before who "just reached out." No one in the rotation is fully released. No one is fully claimed.

Each person provides a different flavor of validation. The moment someone in the rotation pushes for exclusivity, the balance of value shifts — suddenly they become the needy one, and someone else becomes more interesting.

*Hallmark behavior:* Always slightly unavailable. Their social media implies a richer, more complicated social world than you have access to.

---

### Profile 3: The Under-Functioner
**Fear of Accountability**

---

**The Core Wound**

For the Under-Functioner, being fully responsible for a relationship — its upkeep, its conflicts, its repair — feels like being set up to fail. At some level, accountability = disappointment = losing love. So the system has learned to operate in a register slightly below full capacity: not enough to be abandoned, not enough to be held accountable.

This is not laziness. This is a sophisticated (if unconscious) management of perceived risk.

The Under-Functioner's partner almost always Over-Functions. They carry more — more emotional labor, more logistics, more repair work — because the Under-Functioner has calibrated the relationship to require it. It feels like love to the over-functioner. It functions as control for the under-functioner.

---

**The Two Sub-Types**

**The Project (The Fixer-Upper)**

The relationship always has a problem the partner is helping them solve.

The Project isn't fraudulent. The struggles are real. What's instructive is the pattern: the problem is never quite solved. When it comes close, a new one materializes. The Project unconsciously maintains a state of requiring rescue — because rescue is the love they recognize. A partner who shows up consistently without being needed feels unsafe. Over-closeness without a task to complete is terrifying.

Their partner's identity gets organized around being the helper. When that identity is threatened — when the Project becomes functional — the dynamic often collapses.

*Hallmark behavior:* There's always a reason the relationship isn't "quite there yet" — and it's always rooted in their current project (career, family, mental health, "figuring things out").

---

**The Peter Pan (The Forever Child)**

Permanently adolescent in relational terms.

The Peter Pan may be professionally accomplished, socially charming, even intellectually sophisticated — but their emotional operating system is stuck in an earlier developmental chapter. Accountability in a relationship means adulthood. Adulthood means conditional love. Conditional love means the possibility of losing it.

The logic: if I never fully grow up, I can never be held to adult standards. I can always be forgiven because I'm still figuring it out.

*Hallmark behavior:* Plans made loosely. Feelings rarely named directly. Accountability conversations derailed by charm, humor, or a sudden crisis that makes it the wrong time.

---

### Profile 4: The Secure Attacher
**The Healthy Baseline**

---

**The Core Reading**

This is not the absence of history. It is the presence of repair.

The Secure Attacher has either: early attachment figures who were consistently responsive — not perfect, but reliably present when it mattered — or a longer reckoning of their own, through therapy or reflection or the hard education of difficult relationships, that brought them to a functional security.

Security is not ease. It is not never being hurt, never being afraid, never needing reassurance. It is the capacity to hold those feelings without letting them run the relationship.

---

**The Sub-Type**

**The Secure Partner**

Knows what they want. Says what they need. Can hold their partner's anxiety without absorbing it or dismissing it.

The Secure Partner repairs quickly — not because conflict doesn't cost them, but because they've internalized that rupture and repair is the actual texture of a real relationship. They don't catastrophize distance. They don't perform closeness. They show up, and they stay.

The hallmark is not perfection. It is consistency: they are roughly the same person in a crisis that they are on an easy Tuesday.

*Caution reading:* High secure scores can occasionally reflect emotional suppression or conflict-aversion rather than genuine security. The question to ask: is the calm because things feel safe — or because you've learned that having needs creates problems?

---

## Part 3: Blog Articles

---

### Article 1
# The Chemistry Illusion: Why the Love-Bomber Feels Like Your Soulmate (Until Day 90)

You know that feeling.

The one where you met someone and your brain immediately said: *this is different.* Not butterflies — something more seismic. The texts that go on until 2am. The plans that form like there's no reason to wait. The way they look at you like you're the most interesting person in any room they've been in, and somehow you believe them, because no one has ever looked at you quite like that before.

You weren't naive. You weren't moving too fast. What was happening felt real, because most of it was.

Here's what nobody tells you about love bombing: the warmth is genuine. The connection is genuine. The problem isn't that you fell for something fake — it's that you fell for something that was designed to run at that intensity for exactly as long as it needed to, and no longer.

---

**What Love Bombing Actually Is (And Isn't)**

Love bombing gets described in pop psychology as a manipulation tactic — which is technically accurate and also completely inadequate.

Most Love-Bombers are not sitting in a dimly lit room calculating your attachment vulnerabilities. Most of them are people with a deep wound around validation — people who learned, at some early and formative point, that love is earned through performance rather than presence. The bombing is what happens when that wound meets a new person who seems like the answer.

They're not lying when they say you're extraordinary. They're flooding the space with the intensity they wish someone had given them.

The manipulation — if we even want to call it that — is mostly unconscious. What's being managed isn't you. It's their own terror of intimacy, which arrives like clockwork right around the point where things could become real.

---

**Why Day 90**

The 90-day mark is not a rule. It's a range — could be six weeks, could be four months. What it represents is the moment the nervous system can no longer maintain peak output.

Early-stage love activates dopamine systems that are, measurably, similar to the early stages of stimulant use. The neurochemistry of new attachment is supposed to stabilize over time, settling into the quieter rewards of secure connection. For most people, this settling feels natural — the relationship deepens even as the fireworks soften.

For the Love-Bomber, this is where it unravels.

The settling reads as loss. The absence of intensity feels like evidence that something is wrong — either with them, with you, or with the relationship. Their nervous system, which was calibrated to win love through performance, has no operating manual for the quieter chapter. So it does one of two things: recalibrates by finding a new person, or pulls back and waits to see if you'll chase.

Almost always, you chase. The intensity is still in your body. You remember it. You want it back. You work harder, show up more, become a slightly more anxious version of yourself trying to return to Day 14.

Which is, functionally, exactly what was needed.

---

**The Cycle in Practice**

**Phase 1 — The Flood (Weeks 1–8)**
Constant contact. Deep, revelatory conversations about things neither of you usually share. Future-planning that feels natural even at this speed. You feel seen in a way that is genuinely rare. Because it is. Most people don't offer this kind of attention. Most people can't sustain it.

**Phase 2 — The Recalibration (Around Weeks 8–12)**
It's subtle at first. A text that takes longer to come back. Plans that are a little less certain. A conversation that doesn't quite go as deep. You notice but don't say anything, because maybe you're being too sensitive. You actually have that thought: *maybe I'm too sensitive.*

**Phase 3 — The Gap**
This is the phase with no agreed-upon name. You're still technically together. But there's now a distance between the relationship you had and the relationship you have, and you can feel the gap with your whole body, and you don't know how to talk about it without sounding like you're asking for too much.

**Phase 4 — The Re-flood**
You say something. Or pull back yourself. Or they sense the distance and the original flood returns — briefly, convincingly enough — and you feel it again and think: *there it is, it's still real, I wasn't imagining it.*

You weren't imagining it. But you're now in the cycle.

---

**What You Can Do With This**

First: you are not stupid for falling for it. You were responding to something real. The warmth was real. The connection was real. What wasn't real — what couldn't be sustained — was the pace.

Second: the recalibration phase is diagnostic. What happens when the intensity drops is information. A person with secure attachment will feel the natural settling and lean into it. A Love-Bomber will start to disappear. The difference becomes visible right around the moment things could become genuinely close.

Third: ask yourself the harder question. Not "are they love-bombing me?" — but "am I addicted to the high?" Sometimes the people most drawn to Love-Bombers are carrying their own wound — a part of them that believes love that doesn't feel overwhelming isn't real. If quiet consistency has ever felt boring, that's worth sitting with.

Soulmate energy is real. It can also be manufactured. The two are indistinguishable until the factory closes.

---

### Article 2
# Trapped in the Orbit: How to Tell if You're Being "Pocketed" by a Collector

You're not confused about what you two are.

You're confused about *why* you're confused, because everything on the surface looks fine. You see each other. The conversations are good. There's obvious chemistry. They seem happy when you're together.

And yet.

You're not quite in. You haven't met a single friend. You don't appear on their grid, not once in eight months. When plans are made, they're made on their schedule, in their time, with an ambient flexibility that means they can evaporate without much notice. When you've tried to name what this is, the conversation goes slippery — warm but unresolved, like trying to hold water.

You're not in a relationship. You're in an orbit.

---

**Meet the Collector**

The Collector is a sub-type of what we call the Consumer archetype — someone whose primary relational anxiety is about validation and being chosen. But where the Love-Bomber floods to attach, the Collector operates in a different register entirely: low heat, wide coverage, zero full commitment.

The Collector maintains multiple connections simultaneously, each at a carefully managed temperature. Not hot enough to require full accountability. Not cold enough to be released. A warm simmer of maybe, of "we'll see," of "things are complicated right now."

It looks like: an ex they still check in on "as friends." A new person they're "not really seeing but it's complicated." You. Possibly someone else. Each of you in a separate pocket, unaware of the others, each experiencing something that feels exclusive enough not to require confirmation.

---

**Pocketing vs. Privacy**

There's a word for when someone keeps you deliberately separate from their real life: pocketing. And it's distinct from privacy.

Privacy looks like: they're a naturally private person, they've told you this, their whole life is relatively low-profile, they don't document much of anything.

Pocketing looks like: *you specifically* are not part of their visible world, while other things clearly are. Their friends know they're "seeing someone" but have no idea who. You've been introduced to no one. Social media isn't the bar — the bar is whether you exist in any part of their life that other people can witness.

The tell: how they handle an accidental collision. If a friend shows up unexpectedly while you're together, how are you introduced? With warmth and context? Or with a slight recalibration — a shift in their body language, a vague title, a reason to move on quickly?

---

**The Rotator's Logic**

Here's the thing about the Collector that makes it so disorienting to experience from the inside: there is no malice. This person is not plotting to hurt you. They are genuinely afraid of fully claiming anyone.

The logic — operating mostly below conscious awareness — goes something like this:

*If I fully commit to one person, I become vulnerable to that one person. If I keep several people at a consistent warmth, I have options. Options are protection. Protection is survival.*

Every time someone in the rotation pushes for more definition, they become — in the Collector's nervous system — the threat. The person who wants to be chosen is the person who introduced the risk of loss. Suddenly they're "too intense," or "it's not really working," or "the timing isn't right." And someone else in the rotation, who hasn't yet asked for accountability, becomes temporarily more appealing.

This is not a strategy. It's a wound wearing a very effective disguise.

---

**The Eight Signs You're in the Orbit**

1. **Plans are confirmed last-minute, reliably.** Not sometimes. Consistently. The future is always held loosely.

2. **Their phone is a closed system.** Not guarded in a paranoid way — just perpetually faced down, notifications silenced, quick to sleep. With you it's fine. With whoever else it is, it's managed.

3. **You've never seen them initiate social media acknowledgment.** Not a tagged photo. Not a check-in. Nothing that places you in the same world publicly.

4. **Their friends know they're "seeing someone" but not who.** If you ever do meet a friend, you're introduced without context — "this is my friend" or just your name, flatly.

5. **The emotional availability is highest right after you've pulled back.** When you get warm, they cool slightly. When you get a little distant, they get warmer. The calibration is consistent enough to be a pattern.

6. **The future is always hypothetical.** They'll say things that point toward a future — casually, even affectionately — but nothing ever resolves into an actual plan or a named commitment.

7. **You have the same defining conversation on a loop.** It goes roughly the same way each time. Ends warmly. Nothing changes.

8. **You feel peripheral in a relationship that doesn't look peripheral.** The things are there — the chemistry, the time, the apparent connection. But you feel like you're standing on the outside of a window looking in, watching something that looks like it should be yours.

---

**What the Orbit Costs**

The Collector's orbit is expensive to inhabit, and the cost is invisible until you've spent it.

You spend it in the form of: shrinking your needs to fit their availability. Becoming a more anxious version of yourself in a relationship that looked easy from the outside. Learning to need less — which sounds like growth but is actually accommodation. Finding your self-worth starting to track their responsiveness. Good week with them: you feel good about yourself. Distant week: something must be wrong with you.

This is the true damage of being kept in orbit — not the rejection (which at least would be clear) but the ambiguity, which your brain fills with the most convenient available explanation: *this is probably your fault.*

---

**What You're Owed**

You are owed a conversation. Not a perfect one. Not a guarantee. But a real one, with real answers.

"Are we exclusive?" is a reasonable question. "Where is this going?" is a reasonable question. If the answer is a warm drift toward nothing, that is an answer — and it tells you what you need to know about whether this person can give you what you're actually looking for.

The Collector will not usually get cold when asked. They'll get warm. They'll say something that sounds like an answer but resolves to nothing. They'll make you feel a little bit unreasonable for having asked.

Pay attention to that last part. That's the clearest signal of all.

---

### Article 3
# The Caretaker Trap: When Loving a "Project" Turns You Into Their Therapist

There was a moment — probably early — when it felt like strength.

You saw something in them that other people missed. The intelligence underneath the chaos. The sensitivity underneath the self-destruction. The person they could be if someone would just believe in them long enough, consistently enough, with the particular flavor of love that you specifically had to offer.

You chose this, you remind yourself. Nobody forced you into this. You went in with your eyes open.

The thing about the Caretaker Trap is that it never starts as a trap. It starts as love.

---

**What a "Project" Actually Is**

In the relationship archetype framework, The Project — also called The Fixer-Upper — is a sub-type of what we call the Under-Functioner pattern: someone whose relational style keeps them in a perpetual state of almost-ready, almost-healed, almost-functional enough to fully show up.

The Project isn't performing incompetence. The struggles are real. What's instructive isn't the struggles themselves — it's the pattern around them.

There's always a reason why now isn't quite the right time for full accountability. The job situation. The mental health chapter. The family thing that's been complicated for years. The financial piece that's almost sorted. The therapy they're about to start (or just started, or paused because it was a lot, or stopped because the therapist wasn't the right fit).

Each individual element is sympathetic. The constellation of them, sustained over time, is the structure.

And underneath the structure: a person for whom being fully present in a relationship feels like a test they're not sure they can pass. Better to be almost-there than to try and fail. Better to have a reason for falling short than to fully arrive and be found insufficient.

Their solution, often unconsciously: keep someone close enough to serve as a steady tether, without crossing into the full accountability of a mutual relationship.

---

**How You Got Here**

The entry point into the Caretaker Trap almost always involves an attractive combination:

1. **They recognized you.** Really saw you. Often Fixer-Uppers are acutely perceptive — they've spent a lifetime reading rooms to survive. They can see what you need to be seen. That feels like intimacy, and it is — it just isn't stability.

2. **They needed something only you seemed to have.** Patience. Belief. A particular quality of attentiveness. You became necessary in a way that felt like connection.

3. **The potential was real.** You weren't manufacturing it. They do have the qualities you saw. The gap between who they are and who they're becoming is genuinely interesting. You're not wrong to find it compelling.

4. **The early moments of progress confirmed everything.** They got better. For a while. You saw what was possible. And then it slipped back, and you tried harder, and it got better again, and you got closer, and then it slipped back again — and now you're two years in and the cycle has a rhythm you've memorized.

---

**The Line Between Partner and Therapist**

Here is the question worth sitting with:

When was the last time you were having a bad week and they were the person who helped carry it?

Not a crisis. A regular week. The kind where things pile up in the ordinary way and you'd benefit from a partner who noticed and asked.

If you're struggling to remember, that's the data.

The line between being a supportive partner and functioning as someone's therapist isn't drawn around the size of the problems being shared. It's drawn around *directionality* and *reciprocity*. A relationship where one person's needs consistently organize the relationship's emotional bandwidth — that's not a partnership. That's a treatment relationship with rent.

Therapists, for good reason, have supervisors to process their clients. They have boundaries. They have clear role definitions. They don't take calls at midnight about the feeling that showed up after the session. They don't quietly absorb the fallout of their client's growth process.

You don't have any of those protections. You just have love — which has turned out to be load-bearing infrastructure in a building with a faulty foundation.

---

**What Enabling Looks Like From the Inside**

Enabling is one of the most misunderstood concepts in relationship psychology, because it feels, from the inside, exactly like love.

It looks like:
- Covering for them when they don't follow through
- Softening the consequence when accountability would hurt
- Renegotiating your own needs downward so that you're not "adding to their plate"
- Staying through behavior you said you wouldn't stay through — because leaving feels like abandonment, and they need you right now
- Explaining their behavior to yourself, to your friends, to the part of you that keeps noticing the pattern

The cruel irony of enabling: it is not neutral. It is not the absence of action. Enabling is an active force that maintains the Project in their current state. You are not helping them heal. You are keeping the conditions stable enough that healing isn't required.

This is painful to read. It is more painful to have done it for years.

---

**The Hardest Part: You Have a Role in This**

This is where the honesty has to go both directions.

The people most likely to fall into the Caretaker Trap are not naive. They are not weak. They are often extraordinarily capable, emotionally sophisticated, high-functioning people who have, somewhere in their history, learned that love = labor.

Maybe you were the one who stabilized your household as a kid. Maybe love was modeled to you as something you earn through sacrifice. Maybe the relationships that felt like home were the ones where you had a clear role.

When you fell for someone with problems you could solve, some part of you recognized the configuration. *This is how love works. This is what I'm for.*

The Caretaker Trap is, at its deepest level, a story two people tell together — a story where one person's need and another person's wound find each other in the dark and agree, without ever saying a word, to confirm everything the other already believed about love.

---

**Getting Out**

Getting out doesn't necessarily mean leaving. It means leaving the role.

Which, in many cases, will test the relationship structurally — because the relationship was built on the role. If you stop over-functioning, the system will demand you restart. The Project will find, consciously or not, ways to recreate the conditions that require your rescue.

What you're watching for: Can they hold their own weight when you stop carrying it? Not perfectly — nobody functions perfectly — but in the direction of growth, with accountability to you as a partner rather than as a resource?

If yes: you may be watching someone who was stuck, who is now beginning to move. That's worth staying to see.

If no: then the relationship required you to be smaller than you are. And no amount of love — not even the specific, particular quality of love that only you had to offer — is going to change that.

You can grieve the person they could be. You were right about the potential.

You can't keep living in the space between who they are and who they might become. That space will cost you everything it has to cost, and then ask for a little more.

---

*RedFlag is an educational platform. Content is research-informed but does not constitute clinical diagnosis or therapy. If you're experiencing relationship distress, consider speaking with a licensed therapist.*

---

## Developer Notes

### Recommended State Shape (Self-Assessment Mode)

```javascript
const SELF_STATE = {
  mode: "self-assessment",       // distinct from "partner-scan" mode
  answers: [
    { qid: 1, ranked: ["D","A","C","B"] }  // index = click order (0-indexed)
  ],
  scores: { A: 0, B: 0, C: 0, D: 0 },     // computed on completion
  primary: null,                             // highest scoring key
  secondary: null,                           // within 4pts of primary
  blend: false,                              // true if primary/secondary < 4pt gap
};
```

### Score Computation

```javascript
const CLICK_POINTS = [3, 2, 1, 0]; // index = click order

function computeScores(answers) {
  const scores = { A: 0, B: 0, C: 0, D: 0 };
  for (const { ranked } of answers) {
    ranked.forEach((archetypeKey, clickIndex) => {
      scores[archetypeKey] += CLICK_POINTS[clickIndex];
    });
  }
  return scores;
}

function computeResult(scores) {
  const sorted = Object.entries(scores).sort((a, b) => b[1] - a[1]);
  const [primaryKey, primaryScore] = sorted[0];
  const [secondaryKey, secondaryScore] = sorted[1];
  const blend = (primaryScore - secondaryScore) <= 4;
  const pct = (score) => Math.round((score / 24) * 100);
  return {
    primary: primaryKey,
    secondary: blend ? secondaryKey : null,
    blend,
    percentages: Object.fromEntries(Object.entries(scores).map(([k,v]) => [k, pct(v)])),
  };
}
```

### Archetype Key → Profile Mapping

```javascript
const ARCHETYPES = {
  A: {
    name: "The Avoidant",
    tagline: "Fear of Closeness",
    subtypes: ["The Ghost-in-Waiting", "The Contrarian", "The 'Right Person, Wrong Time' Martyr"],
  },
  B: {
    name: "The Consumer",
    tagline: "Hungry for Validation",
    subtypes: ["The Love-Bomber", "The Main Character", "The Collector"],
  },
  C: {
    name: "The Under-Functioner",
    tagline: "Fear of Accountability",
    subtypes: ["The Project", "The Peter Pan"],
  },
  D: {
    name: "The Secure Attacher",
    tagline: "The Healthy Baseline",
    subtypes: ["The Secure Partner"],
  },
};
```
