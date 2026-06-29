import { useState, createContext, useContext } from "react";

// ─── DARK MODE ────────────────────────────────────────────────────────────────
const DarkCtx = createContext({ dark: false, toggle: () => {} });
const LIGHT_VARS = {
  "--rf-bg":      "var(--color-background-tertiary)",
  "--rf-surface": "var(--color-background-primary)",
  "--rf-surface2":"var(--color-background-secondary)",
  "--rf-text":    "var(--color-text-primary)",
  "--rf-text2":   "var(--color-text-secondary)",
  "--rf-text3":   "var(--color-text-tertiary)",
  "--rf-border":  "var(--color-border-tertiary)",
  "--rf-border2": "var(--color-border-secondary)",
  "--rf-danger":  "var(--color-text-danger)",
};
const DARK_VARS = {
  "--rf-bg":      "#0F0F0F",
  "--rf-surface": "#1A1A1A",
  "--rf-surface2":"#242424",
  "--rf-text":    "#F0EDE8",
  "--rf-text2":   "#A09890",
  "--rf-text3":   "#6B6058",
  "--rf-border":  "rgba(255,255,255,0.08)",
  "--rf-border2": "rgba(255,255,255,0.15)",
  "--rf-danger":  "#E05A4E",
};
function DarkToggle() {
  const { dark, toggle } = useContext(DarkCtx);
  return (
    <button onClick={toggle} aria-label={dark ? "Light mode" : "Dark mode"}
      style={{ position:"fixed", top:14, right:14, zIndex:999, background:dark?"#2A2A2A":"var(--color-background-secondary)", border:`0.5px solid ${dark?"rgba(255,255,255,0.12)":"var(--color-border-tertiary)"}`, borderRadius:50, width:36, height:36, display:"flex", alignItems:"center", justifyContent:"center", cursor:"pointer", fontSize:16 }}>
      {dark ? "☀" : "☾"}
    </button>
  );
}

// ─── ARCHETYPES ───────────────────────────────────────────────────────────────
const ARC = {
  gaslight:    { street:"The Reality Bender",         clinical:"Systematic reality distortion",       one:"Makes you question your own memory and perception",                                              kids:false, max:12 },
  control:     { street:"The Puppet Master",          clinical:"Coercive control pattern",            one:"Controls who you see, where you go, and what you do",                                            kids:false, max:12 },
  emotional:   { street:"The Feelings Dismisser",     clinical:"Emotional invalidation",              one:"Makes your emotions feel like an inconvenience or attack",                                       kids:false, max:9  },
  lovebomb:    { street:"Hot and Cold",               clinical:"Love bombing / devaluation cycle",    one:"Sweeps you off your feet, then makes you chase that feeling forever",                            kids:false, max:9  },
  stone:       { street:"The Ice Wall",               clinical:"Emotional withdrawal",                one:"Shuts down completely instead of working through conflict",                                       kids:false, max:9  },
  passive:     { street:"The Silent Punisher",        clinical:"Passive-aggressive pattern",          one:'Says "fine" — then makes you pay for it anyway',                                                kids:false, max:9  },
  identity:    { street:"The Identity Controller",   clinical:"Identity-based coercion",             one:"Uses who you are against you to make you feel undeserving",                                      kids:false, max:9  },
  narcissistic:{ street:"The Center of the Universe",clinical:"Narcissistic traits pattern",         one:"Everything is about them — your needs are an afterthought",                                      kids:false, max:9  },
  financial:   { street:"The Money Controller",      clinical:"Economic control",                    one:"Uses money to trap, punish, or create dependency",                                               kids:false, max:9  },
  intimidation:{ street:"The Threatener",            clinical:"Physical intimidation",               one:"Never hits — but makes you feel like they could",                                                kids:false, max:9  },
  sexual:      { street:"The Pressurer",             clinical:"Sexual coercion",                     one:"Makes you feel like saying no to intimacy isn't really an option",                               kids:false, max:9  },
  isolation:   { street:"The Cutter",                clinical:"Social isolation tactics",            one:"Quietly dismantles your friendships and family ties",                                            kids:false, max:6  },
  blame:       { street:"Nothing Is Ever Their Fault",clinical:"Perpetual victim / DARVO",           one:"Every argument ends with you apologizing for something they did",                                kids:false, max:6  },
  somatic:     { street:"The Fragile One",            clinical:"Somatic manipulation",               one:"Uses real or exaggerated illness to shut down conflict and avoid accountability",                 kids:false, max:9  },
  jealousy:    { street:"The Suspicious One",         clinical:"Pathological jealousy",              one:"Constantly accuses you of cheating with no real basis",                                          kids:false, max:9  },
  religious:   { street:"The Holy Manipulator",       clinical:"Religious or cultural coercion",     one:"Uses God, scripture, or family honor to justify control",                                        kids:false, max:9  },
  humiliation: { street:"The Embarrasser",            clinical:"Public humiliation pattern",         one:"Degrades you in front of others or weaponizes your reputation",                                  kids:false, max:9  },
  rage:        { street:"The Volcano",                clinical:"Explosive anger pattern",            one:"Unpredictable outbursts followed by remorse — you never know which version you'll get",          kids:false, max:9  },
  gatekeeper:  { street:"The Gatekeeper",             clinical:"Parental alienation",                one:"Uses your children as weapons — turning them against you or withholding access",                 kids:true,  max:9  },
};

const COMBINED = {
  gaslight:    { passive:"Coercive Emotional Avoidance", control:"Reality-Based Coercive Control", emotional:"Comprehensive Reality Distortion", narcissistic:"Ego-Driven Reality Manipulation", blame:"The DARVO Loop" },
  control:     { passive:"Indirect Dominance Pattern", emotional:"Isolation and Suppression Pattern", financial:"Total Control Pattern", gatekeeper:"Parental Hostage Pattern" },
  lovebomb:    { gaslight:"Idealize-Devalue-Confuse Cycle", narcissistic:"The Charming Predator", control:"Romantic Coercion Pattern" },
  stone:       { passive:"Double Shutdown Pattern" },
  emotional:   { passive:"Chronic Invalidation Pattern", somatic:"Weaponized Fragility" },
  narcissistic:{ financial:"Entitled Exploitation Pattern", blame:"The Eternal Victim Who Causes Everything", humiliation:"The Status Predator" },
  financial:   { isolation:"Total Dependency Pattern" },
  intimidation:{ sexual:"Physical and Sexual Coercion Pattern", rage:"Escalating Violence Pattern" },
  blame:       { gaslight:"The DARVO Loop" },
  jealousy:    { control:"Obsessive Possession Pattern" },
  religious:   { control:"Sacred Cage Pattern" },
  rage:        { lovebomb:"The Cycle of Violence" },
  humiliation: { narcissistic:"Public Predator Pattern" },
  somatic:     { emotional:"Weaponized Fragility" },
};

const ARC_DESC = {
  gaslight:    "Making someone doubt their own memory, perception, or sanity through denial, contradiction, or minimization.",
  control:     "Limiting a partner's freedom through monitoring, guilt, jealousy, or punishment for independent behavior.",
  emotional:   "Treating a partner's emotions as burdens, weaknesses, or attacks rather than valid human experiences.",
  lovebomb:    "Cycles of intense affection followed by withdrawal — keeping a partner chasing the relationship's early feeling.",
  stone:       "Shutting down, going silent, or refusing to engage during conflict as a consistent pattern.",
  passive:     "Expressing frustration indirectly through behavior — silent treatment, forgetting, small digs.",
  identity:    "Using a partner's background, identity, or insecurities against them to diminish self-worth.",
  narcissistic:"Consistent self-centering — conversation hijacking, entitlement, inability to acknowledge mistakes.",
  financial:   "Using money to limit a partner's independence through controlling access or weaponizing financial decisions.",
  intimidation:"Using physical size, proximity, or property destruction to create fear without necessarily making contact.",
  sexual:      "Using intimacy as leverage or ignoring a partner's limits through persistence, guilt, or implied consequences.",
  isolation:   "Systematically reducing a partner's connections to friends and family, creating dependency.",
  blame:       "Perpetual victimhood and DARVO — the person who raises a concern ends up apologizing for raising it.",
  somatic:     "Using real or exaggerated physical illness to halt conflict, avoid accountability, and create guilt.",
  jealousy:    "Persistent unfounded accusations of cheating or infidelity that no reassurance can resolve.",
  religious:   "Using faith, scripture, or cultural tradition as tools of control rather than shared values.",
  humiliation: "Degrading a partner in public, sharing private information, or building status by tearing them down.",
  rage:        "Explosive disproportionate anger followed by remorse — a cycle that keeps a partner walking on eggshells.",
  gatekeeper:  "Using children as leverage — withholding access, undermining the parenting relationship, or threatening custody.",
};

const SCRIPTS = {
  gaslight:    ['"I know we see this differently, but my experience of what happened is real to me and I need that acknowledged."', '"When I bring something up and end up feeling like the problem, that\'s when I go quiet. I don\'t want to go quiet."'],
  control:     ['"I\'ve noticed that when I do things independently, there are often consequences. I need that to stop."', '"I should be able to see my friends without it creating a problem between us."'],
  intimidation:['"What happened made me feel physically afraid, and that is not acceptable."', '"I need to be able to have an argument without feeling threatened."'],
  rage:        ['"Your anger during conflict has started to feel unpredictable and frightening. I need that to change."', '"I shouldn\'t have to manage what I say based on fear of your reaction."'],
  sexual:      ['"I need to feel like I can say no without it becoming a problem. That has to be safe."', '"Intimacy can\'t be a bargaining chip. That\'s not what it\'s for."'],
};
const DEFAULT_SCRIPTS = ['"I need to talk about something that happened, and I need you to hear me out before responding."', '"When [behavior] happens, I feel [impact]. I\'m saying it because it matters to me."'];

// ─── PARTNER QUESTIONS ────────────────────────────────────────────────────────
const PARTNER_Q = [
  {id:"P1-Q1",  a:"gaslight",  sensitive:false, q:"When you bring up something your partner said or did that hurt you, what usually happens?",                                                                                 h:"Think about the typical time — not the best or worst.",         ans:[{t:"They listen and acknowledge what I felt",w:0},{t:"They get defensive but eventually hear me out",w:1},{t:"They say I'm overreacting or too sensitive",w:2},{t:"They deny it happened or say I'm making things up",w:3}]},
  {id:"P1-Q2",  a:"gaslight",  sensitive:false, q:"After an argument, how do you usually feel?",                                                                                                                               h:"Not the best fight — the typical one.",                          ans:[{t:"Resolved, even if it was hard",w:0},{t:"Tired but okay",w:1},{t:"Confused about what actually happened",w:2},{t:"Like somehow I became the problem",w:3}]},
  {id:"P1-Q3",  a:"gaslight",  sensitive:false, q:"Has your partner brought up past events to use against you during current arguments in ways that felt twisted?",                                                             h:"This feels like keeping score or rewriting history.",            ans:[{t:"No, they stay focused on the current issue",w:0},{t:"Occasionally, but not weaponized",w:1},{t:"Yes, it always derails the conversation",w:2},{t:"Yes — by the end I'm defending myself instead",w:3}]},
  {id:"P1-Q4",  a:"gaslight",  sensitive:false, q:"How confident do you feel in your own memory of events between you and your partner?",                                                                                      h:"About your gut trust in your own perception.",                   ans:[{t:"Fully confident — I trust what I remember",w:0},{t:"Mostly confident, occasional normal doubt",w:1},{t:"I often second-guess myself after talking to them",w:2},{t:"I genuinely can't tell what actually happened anymore",w:3}]},
  {id:"P1-Q5",  a:"control",   sensitive:false, q:"How does your partner respond when you spend time with friends or family without them?",                                                                                    h:"The consistent pattern, not a one-off.",                        ans:[{t:"Fine with it, maybe asks how it went",w:0},{t:"Prefers to be included but doesn't make it an issue",w:1},{t:"Gets quiet or moody when I get back",w:2},{t:"Checks in constantly or starts an argument afterward",w:3}]},
  {id:"P1-Q6",  a:"control",   sensitive:false, q:"Have you ever avoided doing something because you knew your partner would react badly?",                                                                                    h:"Includes canceling plans just to keep the peace.",              ans:[{t:"No, I don't change plans based on their mood",w:0},{t:"Occasionally, rare and minor",w:1},{t:"More often than I'd like to admit",w:2},{t:"Yes — I think twice about almost everything I do",w:3}]},
  {id:"P1-Q7",  a:"control",   sensitive:false, q:"Does your partner check your phone, monitor your location, or want to know where you are at all times?",                                                                    h:"Mutual transparency is normal. One-sided monitoring is different.",ans:[{t:"No, they respect my privacy",w:0},{t:"They occasionally ask, feels like curiosity not control",w:1},{t:"They check regularly and I feel I must explain myself",w:2},{t:"Yes, and not responding fast enough has consequences",w:3}]},
  {id:"P1-Q8",  a:"control",   sensitive:false, q:"How do decisions get made — where you go, how money is spent, who you see?",                                                                                                h:"Think about the pattern across small and big decisions.",        ans:[{t:"We discuss and decide together equally",w:0},{t:"One of us leads more but it doesn't feel unfair",w:1},{t:"My partner usually decides and I go along to avoid conflict",w:2},{t:"I feel like I need permission and pushback has consequences",w:3}]},
  {id:"P1-Q9",  a:"emotional", sensitive:false, q:"When you cry or show strong emotion, how does your partner typically react?",                                                                                                h:"Think about when you're genuinely upset, not just venting.",    ans:[{t:"They check in, ask what's wrong, offer comfort",w:0},{t:"Not great at it but they try",w:1},{t:"They go quiet, leave the room, or shut down",w:2},{t:"They say things like 'here we go again' or 'you're so dramatic'",w:3}]},
  {id:"P1-Q10", a:"emotional", sensitive:false, q:"When you share something bothering you, does your partner make you feel like your feelings are valid?",                                                                     h:"Valid means acknowledged, not agreed with.",                    ans:[{t:"Yes, even when they disagree they acknowledge how I feel",w:0},{t:"Sometimes — depends on their mood",w:1},{t:"Rarely — I usually end up feeling like the problem",w:2},{t:"Never — my feelings always become an inconvenience or attack on them",w:3}]},
  {id:"P1-Q11", a:"emotional", sensitive:false, q:"Do you feel safe being vulnerable with your partner — sharing fears, insecurities, or embarrassing things?",                                                                h:"Safe means without fear of it being used against you later.",   ans:[{t:"Yes, fully — they hold those things carefully",w:0},{t:"Mostly, with some things I hold back",w:1},{t:"I'm selective because some things have come back to hurt me",w:2},{t:"No — I've learned not to show weakness around them",w:3}]},
  {id:"P1-Q12", a:"lovebomb",  sensitive:false, q:"How does the relationship feel compared to when it first started?",                                                                                                         h:"About an extreme or confusing shift, not normal maturing.",     ans:[{t:"It naturally matured — still good, just more settled",w:0},{t:"A bit less intense but still secure and warm",w:1},{t:"Affection feels inconsistent — great periods followed by cold ones",w:2},{t:"I'm constantly trying to get back to how it felt at the beginning",w:3}]},
  {id:"P1-Q13", a:"lovebomb",  sensitive:false, q:"When things are bad between you, how does your partner typically try to repair it?",                                                                                        h:"The question is what the repair looks like.",                   ans:[{t:"They acknowledge what happened and we work through it",w:0},{t:"They apologize and things get better without fully resolving",w:1},{t:"They do something big — gifts, grand gestures — then back to normal",w:2},{t:"They flip to incredibly loving and I feel confused about the bad part",w:3}]},
  {id:"P1-Q14", a:"lovebomb",  sensitive:false, q:"How often do you feel like you're walking on eggshells?",                                                                                                                   h:"A persistent low-level alertness to their state, not occasional tension.",ans:[{t:"Rarely or never — I feel relaxed around them",w:0},{t:"Occasionally, around specific topics",w:1},{t:"Often — I'm frequently reading their mood first",w:2},{t:"Almost always — managing their state feels like a full-time job",w:3}]},
  {id:"P1-Q15", a:"stone",     sensitive:false, q:"When there is a disagreement, what does your partner typically do?",                                                                                                        h:"The most common pattern, not the best or worst fight.",         ans:[{t:"They stay in the conversation even when it's hard",w:0},{t:"They need a breather but come back to talk it out",w:1},{t:"They go silent and I have to wait it out, sometimes hours",w:2},{t:"They shut down completely — sometimes for days — and refuse to engage",w:3}]},
  {id:"P1-Q16", a:"stone",     sensitive:false, q:"After a conflict, who usually reaches out first to reconnect?",                                                                                                             h:"Not who apologizes — who breaks the silence.",                  ans:[{t:"Either of us, it's pretty natural",w:0},{t:"Usually me, but it feels mutual enough",w:1},{t:"Almost always me — if I don't reach out it stays cold",w:2},{t:"Always me, and even then they make me work for it",w:3}]},
  {id:"P1-Q17", a:"stone",     sensitive:false, q:"Do you feel heard during disagreements — like your point lands before the conversation ends?",                                                                               h:"Not whether you win — whether they took in what you said.",     ans:[{t:"Yes, even if we disagree I feel heard",w:0},{t:"Sometimes — depends on the topic",w:1},{t:"Rarely — conversation usually ends before I feel understood",w:2},{t:"Never — conversations blow up or shut down before anything lands",w:3}]},
  {id:"P1-Q18", a:"passive",   sensitive:false, q:"After your partner says 'fine' or 'whatever,' what usually happens next?",                                                                                                  h:"Surface agreement — then what comes after.",                    ans:[{t:"They actually mean it — the issue is dropped",w:0},{t:"They're a little off but shake it off quickly",w:1},{t:"They're cold or distant for a while",w:2},{t:"They act fine but make small digs or 'forget' things that matter to me",w:3}]},
  {id:"P1-Q19", a:"passive",   sensitive:false, q:"Does your partner express frustration directly, or do you have to figure out something is wrong?",                                                                          h:"Direct = they tell you. Indirect = you piece it together.",     ans:[{t:"Directly — they tell me when something is bothering them",w:0},{t:"Mostly directly, occasional hints",w:1},{t:"Mostly indirect — I'm usually figuring out what's wrong",w:2},{t:"Always indirect — if I ask I get 'nothing' while the behavior continues",w:3}]},
  {id:"P1-Q20", a:"passive",   sensitive:false, q:"Has your partner agreed to do something and then not done it — or done it badly — as a way of expressing displeasure without saying so?",                                   h:"Different from forgetting. This feels intentional.",            ans:[{t:"No, if they agree they follow through",w:0},{t:"Occasionally, but it doesn't feel pointed",w:1},{t:"Yes, and there's a correlation with prior conflict",w:2},{t:"Yes, consistently — it's how I know they're upset",w:3}]},
  {id:"P1-Q21", a:"identity",  sensitive:false, q:"Has your partner ever threatened to expose something private about you without your consent?",                                                                               h:"Including anything you haven't chosen to share.",               ans:[{t:"No, never",w:0},{t:"Comments that felt like a warning but nothing direct",w:1},{t:"Yes, during arguments they've implied they could",w:2},{t:"Yes, explicitly — as leverage or punishment",w:3}]},
  {id:"P1-Q22", a:"identity",  sensitive:false, q:"Does your partner use your background, identity, or insecurities against you during conflict?",                                                                             h:"'No one else would want you.' 'You're lucky I put up with you.'",ans:[{t:"No, they respect and affirm who I am",w:0},{t:"Occasionally a comment slips but they walk it back",w:1},{t:"Yes, it comes up in ways that feel like diminishment",w:2},{t:"Yes, consistently — to make me feel undeserving",w:3}]},
  {id:"P1-Q23", a:"identity",  sensitive:false, q:"Do you feel like you can be fully yourself around your partner — in how you dress, speak, act?",                                                                            h:"Without fear of criticism, mockery, or punishment.",            ans:[{t:"Yes, completely — they celebrate who I am",w:0},{t:"Mostly, with some things I hold back",w:1},{t:"No, I've toned myself down to avoid their reactions",w:2},{t:"No, I feel like I've lost a significant part of myself",w:3}]},
  {id:"P2-Q1",  a:"narcissistic",sensitive:false,q:"How does your partner respond when conversation shifts to you — your achievements, problems, needs?",                                                                      h:"Think about a time you shared good news or needed support.",    ans:[{t:"They engage genuinely — ask questions, celebrate, offer support",w:0},{t:"Okay at it but sometimes redirect to themselves",w:1},{t:"Usually find a way to make it about them within minutes",w:2},{t:"My moments consistently get hijacked",w:3}]},
  {id:"P2-Q2",  a:"narcissistic",sensitive:false,q:"Does your partner believe rules that apply to others — waiting, being on time, commitments — apply to them?",                                                             h:"Entitlement is often subtle. Look for a pattern of self-exemptions.",ans:[{t:"Yes, they hold themselves to the same standard as everyone else",w:0},{t:"They have moments but nothing that feels like a pattern",w:1},{t:"Regularly expect exceptions and get irritated when they don't get them",w:2},{t:"Genuinely believe they are above normal rules",w:3}]},
  {id:"P2-Q3",  a:"narcissistic",sensitive:false,q:"When your partner makes a mistake that affects you, how do they handle it?",                                                                                               h:"The consistent pattern.",                                       ans:[{t:"They own it and make a genuine effort to fix it",w:0},{t:"They acknowledge it but move on quickly without much repair",w:1},{t:"They minimize it or find a reason it wasn't really their fault",w:2},{t:"They never acknowledge mistakes — bringing it up turns into an attack on you",w:3}]},
  {id:"P2-Q4",  a:"financial",  sensitive:false, q:"Do you have independent access to money — your own account, income, ability to spend without reporting back?",                                                             h:"About financial autonomy, not who earns more.",                 ans:[{t:"Yes, fully — I manage my own finances freely",w:0},{t:"Mostly, with some shared oversight that feels fair",w:1},{t:"Limited — I feel I need to justify purchases",w:2},{t:"No — my partner controls the money",w:3}]},
  {id:"P2-Q5",  a:"financial",  sensitive:false, q:"Has your partner ever undermined your ability to work, earn money, or maintain financial independence?",                                                                    h:"Includes sabotaging job applications, causing scenes at work, or pressuring you to quit.",ans:[{t:"No, they support my financial independence",w:0},{t:"Expressed preferences but nothing controlling",w:1},{t:"Yes, made working harder through conflict, guilt, or interference",w:2},{t:"Yes, deliberately — it has affected my income or employment",w:3}]},
  {id:"P2-Q6",  a:"financial",  sensitive:false, q:"Has your partner put debt in your name, made financial decisions without your knowledge, or used money as a reward or punishment?",                                         h:"Think about credit cards, loans, or withholding money after conflict.",ans:[{t:"No, financial decisions are made together and transparently",w:0},{t:"There have been surprises but nothing intentional or harmful",w:1},{t:"Yes, and it created stress or financial consequences",w:2},{t:"Yes, repeatedly — money is used as control",w:3}]},
  {id:"P2-Q7",  a:"intimidation",sensitive:false,q:"Has your partner ever used their physical presence to make you feel unsafe — blocking a doorway, standing over you, getting close in a threatening way?",                  h:"This does not require physical contact.",                       ans:[{t:"No, never",w:0},{t:"Once or twice in a heated moment but felt unintentional",w:1},{t:"Yes, and it made me feel trapped or scared",w:2},{t:"Yes, regularly — I feel physically unsafe during arguments",w:3}]},
  {id:"P2-Q8",  a:"intimidation",sensitive:false,q:"Has your partner ever thrown, broken, or hit objects during an argument?",                                                                                                 h:"Destroying property during conflict is intimidation regardless of whether you were physically touched.",ans:[{t:"No, never",w:0},{t:"Once, in an extreme moment that felt out of character",w:1},{t:"Yes, more than once — it frightens me even if I'm not the target",w:2},{t:"Yes, regularly — it feels like a demonstration",w:3}]},
  {id:"P2-Q9",  a:"intimidation",sensitive:false,q:"Have you ever felt physically afraid of your partner — even briefly?",                                                                                                     h:"This includes a gut fear response, not just being startled.",   ans:[{t:"No, never",w:0},{t:"Once, in an isolated situation",w:1},{t:"Yes, occasionally — something in their behavior triggers fear",w:2},{t:"Yes, regularly — I manage my behavior to avoid physical escalation",w:3}]},
  {id:"P2-Q10", a:"sexual",     sensitive:true,  q:"When you are not in the mood for intimacy, how does your partner respond?",                                                                                                h:"This question is about the pattern when you say no or not now.",ans:[{t:"They accept it without issue",w:0},{t:"Occasionally disappointed but never make me feel bad",w:1},{t:"They sulk, guilt-trip, or make the rejection feel like a problem I created",w:2},{t:"They pressure, persist, or punish emotionally until I give in",w:3}]},
  {id:"P2-Q11", a:"sexual",     sensitive:false, q:"Has your partner ever used sex or intimacy as a bargaining chip — withholding it as punishment or using it as a reward?",                                                  h:"About intimacy being weaponized, not normal fluctuations in desire.",ans:[{t:"No, intimacy is never tied to compliance",w:0},{t:"Dry periods after conflict but it doesn't feel deliberate",w:1},{t:"Yes — intimacy increases when I comply and decreases when I don't",w:2},{t:"Yes, explicitly — it is used as leverage",w:3}]},
  {id:"P2-Q12", a:"sexual",     sensitive:false, q:"Have you ever felt pressured into sexual activity you did not want — through persistence, guilt, withdrawal, or implied consequences?",                                     h:"You do not have to have said no out loud for this to count.",   ans:[{t:"No, I always feel free to decline without consequence",w:0},{t:"Occasionally gone along when I didn't want to, but felt minor",w:1},{t:"Yes, I have complied to avoid conflict or emotional punishment",w:2},{t:"Yes, regularly — genuine refusal doesn't feel like a safe option",w:3}]},
  {id:"P2-Q13", a:"isolation",  sensitive:false, q:"Has your circle of friends or family contact gotten smaller since being with your partner?",                                                                                h:"About a pattern of disconnection that correlates with your partner's behavior.",ans:[{t:"No, my relationships outside this one are healthy",w:0},{t:"Some drift, but it feels like normal life change",w:1},{t:"Yes, connected to conflict, guilt, or pressure about those relationships",w:2},{t:"Yes, significantly — my partner is my primary or only source of support",w:3}]},
  {id:"P2-Q14", a:"isolation",  sensitive:false, q:"Has your partner ever created conflict or behaved in ways that damaged your relationships with people you were close to?",                                                   h:"Includes turning family against you, causing scenes, or making you choose.",ans:[{t:"No, they support my outside relationships",w:0},{t:"There have been tensions but nothing that felt strategic",w:1},{t:"Yes, and some relationships have been damaged or ended",w:2},{t:"Yes, deliberately — I believe they have worked to isolate me",w:3}]},
  {id:"P2-Q15", a:"blame",      sensitive:false, q:"When conflict happens, who ends up apologizing most of the time?",                                                                                                         h:"Regardless of who started it or who was actually at fault.",    ans:[{t:"It varies — whoever was actually wrong apologizes",w:0},{t:"Usually me, but that's sometimes fair",w:1},{t:"Almost always me — even when I know I wasn't wrong",w:2},{t:"Always me — I cannot recall my partner genuinely apologizing first",w:3}]},
  {id:"P2-Q16", a:"blame",      sensitive:false, q:"When you raise a concern about your partner's behavior, does the conversation stay on the original issue?",                                                                 h:"DARVO: the person who raised the concern ends up defending themselves.",ans:[{t:"It stays on the issue",w:0},{t:"Sometimes drifts but we usually come back",w:1},{t:"It almost always shifts — I end up explaining myself",w:2},{t:"Every time — by the end I am the one who wronged them",w:3}]},
  {id:"P2-Q17", a:"somatic",    sensitive:false, q:"When conflict arises, does your partner experience or report physical symptoms — chest pain, headaches, anxiety attacks — that cause the conversation to stop?",           h:"Real illness exists. This is about whether symptoms consistently appear at moments of accountability.",ans:[{t:"No, their health and conflict are not connected in a pattern",w:0},{t:"Occasionally they're unwell during stress but it doesn't feel like a pattern",w:1},{t:"Yes, and I notice the symptoms tend to appear when I raise concerns",w:2},{t:"Yes, consistently — any conflict immediately triggers a health event that ends the discussion",w:3}]},
  {id:"P2-Q18", a:"somatic",    sensitive:false, q:"Do you feel guilty or cruel for having needs or raising concerns because of your partner's health?",                                                                        h:"This is about whether their health status has become a reason your needs cannot be addressed.",ans:[{t:"No, their health never enters into whether I can raise something",w:0},{t:"Sometimes I hold back but it feels like consideration not manipulation",w:1},{t:"Often — I pre-filter what I bring up based on their current health state",w:2},{t:"Always — I feel like having needs at all is dangerous given their condition",w:3}]},
  {id:"P2-Q19", a:"somatic",    sensitive:false, q:"Has your partner ever recovered quickly from a health episode once a conflict was dropped or you apologized?",                                                              h:"Not about medical reality — about whether resolution of tension correlates with recovery.",ans:[{t:"No, their health runs independently of our relationship dynamics",w:0},{t:"Hard to say — I haven't noticed a clear pattern",w:1},{t:"Yes, I've noticed they tend to feel better once tension is resolved in their favor",w:2},{t:"Yes, consistently — recovery happens fast once I back down or give in",w:3}]},
  {id:"P2-Q20", a:"jealousy",   sensitive:false, q:"Does your partner accuse you of cheating or being interested in others — without real evidence?",                                                                          h:"Occasional insecurity is normal. Persistent unfounded accusations are different.",ans:[{t:"No, they trust me",w:0},{t:"They get insecure occasionally but it passes without becoming an accusation",w:1},{t:"Yes, they regularly imply or accuse without real basis",w:2},{t:"Yes, constantly — no amount of reassurance changes their suspicion",w:3}]},
  {id:"P2-Q21", a:"jealousy",   sensitive:false, q:"Does your partner react with anger, punishment, or interrogation when you interact with certain people?",                                                                   h:"Think about their reaction pattern, not just whether they get jealous.",ans:[{t:"No, they are comfortable with my interactions with others",w:0},{t:"They occasionally feel uncomfortable but handle it reasonably",w:1},{t:"Yes, certain interactions reliably trigger anger, interrogation, or punishment",w:2},{t:"Yes, almost any interaction with others gets monitored and questioned",w:3}]},
  {id:"P2-Q22", a:"jealousy",   sensitive:false, q:"Have you changed your behavior — who you talk to, what you post, how you dress — to avoid triggering your partner's jealousy?",                                            h:"This is about self-censorship driven by their reaction pattern.",ans:[{t:"No, I don't change my behavior based on jealousy concerns",w:0},{t:"Minor adjustments, but it feels like normal relationship consideration",w:1},{t:"Yes, I regularly filter my behavior to avoid triggering a jealous reaction",w:2},{t:"Yes, significantly — my social life and self-expression are shaped around their jealousy",w:3}]},
  {id:"P2-Q23", a:"religious",  sensitive:false, q:"Does your partner use religion, scripture, cultural tradition, or family honor to justify controlling your behavior or dismissing your concerns?",                          h:"Faith and culture are meaningful. This is about them being used as tools of control.",ans:[{t:"No, faith or culture is shared respectfully or not used at all",w:0},{t:"Occasionally referenced in ways that feel off but not a consistent pattern",w:1},{t:"Yes, religious or cultural framing is regularly used to justify their behavior or dismiss mine",w:2},{t:"Yes, consistently — I am told my concerns are sinful, shameful, or a violation of duty",w:3}]},
  {id:"P2-Q24", a:"religious",  sensitive:false, q:"Has your partner used your shared faith, community, or family expectations to prevent you from leaving, seeking help, or speaking to others?",                              h:"This includes threats of spiritual consequences, family shame, or community rejection.",ans:[{t:"No, faith or family is never used to restrict my options",w:0},{t:"There is pressure but it feels more like genuine concern than manipulation",w:1},{t:"Yes, I feel that leaving or seeking help would bring consequences tied to faith or family",w:2},{t:"Yes, explicitly — I have been told I would be shamed or punished spiritually for speaking out",w:3}]},
  {id:"P2-Q25", a:"religious",  sensitive:false, q:"Do you feel like your spiritual or cultural identity is used to keep you compliant rather than to genuinely practice shared values?",                                       h:"Shared faith should feel like connection. This is about it feeling like a leash.",ans:[{t:"No, our shared values feel like genuine connection",w:0},{t:"Occasionally it feels lopsided but not deliberately weaponized",w:1},{t:"Yes, I notice the standards apply to me more than to them",w:2},{t:"Yes, clearly — the rules apply to controlling me, not to how they behave",w:3}]},
  {id:"P2-Q26", a:"humiliation",sensitive:false, q:"Has your partner ever put you down, mocked you, or criticized you in front of other people?",                                                                              h:"This includes jokes at your expense, correcting you publicly, or sharing your failures with others.",ans:[{t:"No, they are respectful of me in public",w:0},{t:"Occasional teasing that crossed a line but they apologized",w:1},{t:"Yes, it happens regularly and I feel humiliated even if others laugh it off",w:2},{t:"Yes, consistently — I dread social situations because I never know what they'll say",w:3}]},
  {id:"P2-Q27", a:"humiliation",sensitive:false, q:"Has your partner shared private information about you — your struggles, your body, your past, your mistakes — with others without your consent?",                          h:"This includes telling family, friends, or posting things online.",ans:[{t:"No, what I share with them stays private",w:0},{t:"Once or twice in a way that felt careless but not malicious",w:1},{t:"Yes, private information has been shared and it has affected how others see me",w:2},{t:"Yes, deliberately — my private life is used as social currency or punishment",w:3}]},
  {id:"P2-Q28", a:"humiliation",sensitive:false, q:"Do you feel like your partner builds themselves up by tearing you down — especially in front of others?",                                                                   h:"This is about whether your diminishment is how they gain status or confidence.",ans:[{t:"No, they build me up or stay neutral in public",w:0},{t:"Occasionally they make themselves look good at my expense but it doesn't feel deliberate",w:1},{t:"Yes, I notice I am frequently the example of what not to do in their stories",w:2},{t:"Yes, clearly — making me look small is how they make themselves look big",w:3}]},
  {id:"P2-Q29", a:"rage",       sensitive:false, q:"How would you describe your partner's anger during conflict?",                                                                                                              h:"Not how they are on a normal day — how they get when they're genuinely angry.",ans:[{t:"Controlled — they get upset but stay regulated",w:0},{t:"Occasionally raises their voice but de-escalates fairly quickly",w:1},{t:"Unpredictable — I never know if a small conflict will turn into a big explosion",w:2},{t:"Explosive — their anger is disproportionate, frightening, and hard to predict",w:3}]},
  {id:"P2-Q30", a:"rage",       sensitive:false, q:"After an explosive outburst, how does your partner typically behave?",                                                                                                     h:"The cycle after the explosion matters as much as the explosion itself.",ans:[{t:"They reflect on it seriously and work to change the behavior",w:0},{t:"They apologize but the pattern repeats without real change",w:1},{t:"They act as if nothing happened or minimize what occurred",w:2},{t:"They become overly loving and remorseful — until the next explosion",w:3}]},
  {id:"P2-Q31", a:"rage",       sensitive:false, q:"Have you changed how you behave — topics you avoid, timing of conversations, tone you use — specifically to avoid triggering an explosive reaction?",                       h:"This is a deeper version of eggshell-walking, specifically around disproportionate anger.",ans:[{t:"No, I don't manage my behavior around fear of their anger",w:0},{t:"Minor adjustments that feel like normal communication consideration",w:1},{t:"Yes, I have a mental list of things that are too risky to bring up",w:2},{t:"Yes, significantly — I feel like I am constantly managing a situation that could detonate",w:3}]},
  {id:"P2-Q32", a:"gatekeeper", sensitive:false, q:"Has your partner withheld access to your children, used parenting time as leverage, or threatened to take the children away during conflict?",                             h:"This includes both formal custody situations and day-to-day access within the home.",ans:[{t:"No, parenting is handled separately from our conflict",w:0},{t:"There has been tension around parenting during conflict but nothing deliberate",w:1},{t:"Yes, access to or time with the children has been used as leverage",w:2},{t:"Yes, explicitly — the children are used as a direct tool of punishment or control",w:3}]},
  {id:"P2-Q33", a:"gatekeeper", sensitive:false, q:"Has your partner said or done things to undermine your relationship with your children — speaking negatively about you to them or positioning themselves as the good parent?",h:"This is about deliberate erosion of your relationship with your own children.",ans:[{t:"No, they support my relationship with our children",w:0},{t:"Occasional venting to the kids that felt inappropriate but isolated",w:1},{t:"Yes, I have noticed my children pulling away or repeating things that came from my partner",w:2},{t:"Yes, consistently — I feel like my relationship with my children is being deliberately damaged",w:3}]},
  {id:"P2-Q34", a:"gatekeeper", sensitive:false, q:"Do you feel like your partner uses your role as a parent to keep you in the relationship — implying you will lose the children or damage them if you leave?",              h:"This is a form of coercion specific to co-parents.",            ans:[{t:"No, parenting and relationship decisions are kept separate",w:0},{t:"There have been comments but they felt more like fear than threat",w:1},{t:"Yes, leaving feels impossible because of what they imply about the children",w:2},{t:"Yes, explicitly — I have been told or made to feel I will lose my children if I leave",w:3}]},
];

// ─── SELF QUESTIONS (Part 1 + Part 2 combined, filtered by archetype at runtime)
const SELF_Q = [
  {id:"SC-Q1",  a:"gaslight",  sensitive:false, q:"When your partner brings up something you said or did that hurt them, how do you usually respond?",                                                                         h:"Think about your typical reaction — not your best or worst moment.",ans:[{t:"I listen and try to understand what they felt",w:0},{t:"I get defensive but eventually hear them out",w:1},{t:"I tell them they're overreacting or being too sensitive",w:2},{t:"I deny it happened or say they're making things up",w:3}]},
  {id:"SC-Q2",  a:"gaslight",  sensitive:false, q:"After an argument, how does your partner usually seem to feel?",                                                                                                            h:"Not after your best fight — after a typical one.",              ans:[{t:"Resolved, even if it was hard",w:0},{t:"Tired but okay",w:1},{t:"Confused about what actually happened",w:2},{t:"Like they somehow became the problem even though they started it with a valid concern",w:3}]},
  {id:"SC-Q3",  a:"gaslight",  sensitive:false, q:"Do you ever bring up your partner's past mistakes during a current argument to strengthen your position?",                                                                   h:"This is different from normal conflict. This is using history as a weapon.",ans:[{t:"No, I stay focused on the current issue",w:0},{t:"Occasionally, but not in a way I'd call weaponized",w:1},{t:"Yes, and it usually derails the conversation",w:2},{t:"Yes, and by the end they're defending themselves instead of the thing they brought up",w:3}]},
  {id:"SC-Q4",  a:"gaslight",  sensitive:false, q:"Do you ever challenge your partner's memory of events in ways that make them doubt themselves?",                                                                             h:"This is about how your responses affect their confidence in their own perception.",ans:[{t:"No, I respect their recollection even when we remember things differently",w:0},{t:"Occasionally I push back but I don't think it undermines them",w:1},{t:"Yes, I often reframe events in ways that leave them second-guessing",w:2},{t:"Yes, consistently — my version of events tends to override theirs",w:3}]},
  {id:"SC-Q5",  a:"control",   sensitive:false, q:"How do you feel when your partner spends time with friends or family without you?",                                                                                         h:"Honest self-check — not the answer you think you should give.", ans:[{t:"Fine — I encourage it and ask how it went",w:0},{t:"I prefer to be included but I don't make it an issue",w:1},{t:"I get quiet or moody when they get back",w:2},{t:"I check in constantly while they're out or start an argument afterward",w:3}]},
  {id:"SC-Q6",  a:"control",   sensitive:false, q:"Has your partner ever avoided doing something because of how you might react?",                                                                                              h:"Think about whether your reactions shape their choices.",        ans:[{t:"No, I don't think my reactions limit their choices",w:0},{t:"Occasionally they adjust minor things but it feels mutual",w:1},{t:"Probably more often than I'd like to admit",w:2},{t:"Yes — they think twice about most things because of me",w:3}]},
  {id:"SC-Q7",  a:"control",   sensitive:false, q:"Do you check your partner's phone, monitor their location, ask who they're texting, or expect to know where they are at all times?",                                        h:"Mutual transparency is normal. One-sided monitoring is different.",ans:[{t:"No, I respect their privacy",w:0},{t:"I occasionally ask but it feels like curiosity not control",w:1},{t:"I check regularly and expect them to explain themselves",w:2},{t:"Yes, and there are consequences if they don't respond fast enough",w:3}]},
  {id:"SC-Q8",  a:"control",   sensitive:false, q:"How are decisions made in your relationship — where you go, how money is spent, who you see?",                                                                              h:"Think about who drives decisions and what happens when your partner pushes back.",ans:[{t:"We discuss and decide together pretty equally",w:0},{t:"I tend to lead more but it doesn't feel unfair",w:1},{t:"My partner usually goes along with my decisions to avoid conflict",w:2},{t:"I expect to make most decisions and pushback has consequences",w:3}]},
  {id:"SC-Q9",  a:"emotional", sensitive:false, q:"When your partner cries or shows strong emotion, how do you typically react?",                                                                                               h:"Think about when they're genuinely upset — not just frustrated.", ans:[{t:"I check in, ask what's wrong, and offer comfort",w:0},{t:"I'm not great at it but I try in my own way",w:1},{t:"I go quiet, leave the room, or shut down",w:2},{t:"I say things like 'here we go again' or make them feel dramatic",w:3}]},
  {id:"SC-Q10", a:"emotional", sensitive:false, q:"When your partner shares something that is bothering them, do you make them feel like their feelings are valid?",                                                            h:"Valid doesn't mean you agree — it means you acknowledge they feel what they feel.",ans:[{t:"Yes, even when I disagree I acknowledge how they feel",w:0},{t:"Sometimes — depends on my mood",w:1},{t:"Rarely — they usually end up feeling like the problem for bringing it up",w:2},{t:"Never — their feelings become an inconvenience or an attack on me",w:3}]},
  {id:"SC-Q11", a:"emotional", sensitive:false, q:"Does your partner feel safe being vulnerable with you — sharing fears, insecurities, or embarrassing things?",                                                              h:"Safe means without fear of it being used against them or being mocked.",ans:[{t:"Yes, fully — I hold those things carefully",w:0},{t:"Mostly, though I've slipped occasionally",w:1},{t:"Probably not — some things they shared have come back in arguments",w:2},{t:"No — I think they've learned not to show weakness around me",w:3}]},
  {id:"SC-Q12", a:"lovebomb",  sensitive:false, q:"How does your behavior toward your partner compare to how you were early in the relationship?",                                                                              h:"Early intensity is normal. This is about an extreme or confusing shift.",ans:[{t:"Naturally matured — still warm, just more settled",w:0},{t:"A bit less intense but still consistent and secure",w:1},{t:"My affection is inconsistent — warm periods followed by cold or withdrawn ones",w:2},{t:"Significantly different — I pursued intensely at the start and know things have shifted dramatically",w:3}]},
  {id:"SC-Q13", a:"lovebomb",  sensitive:false, q:"When things are bad between you, how do you typically try to repair it?",                                                                                                   h:"Repair is healthy. The question is what your repair looks like.", ans:[{t:"I acknowledge what happened and work through it",w:0},{t:"I apologize and move on without fully resolving the issue",w:1},{t:"I do something big — gifts, intense affection, grand gestures — then expect things to return to normal",w:2},{t:"I flip to being incredibly loving in a way that makes the bad part feel confusing or unreal",w:3}]},
  {id:"SC-Q14", a:"lovebomb",  sensitive:false, q:"Does your partner seem to walk on eggshells around you — carefully reading your mood before saying or doing things?",                                                       h:"This is about whether your state shapes their behavior.",        ans:[{t:"No, they seem relaxed around me most of the time",w:0},{t:"Occasionally around specific topics",w:1},{t:"Often — I notice them checking my mood before they speak or act",w:2},{t:"Almost always — managing my state takes up significant energy for them",w:3}]},
  {id:"SC-Q15", a:"stone",     sensitive:false, q:"When there is a disagreement, what do you typically do?",                                                                                                                   h:"Pick the option that matches your most common pattern.",         ans:[{t:"I stay in the conversation even when it is hard",w:0},{t:"I need a breather but come back to talk it out",w:1},{t:"I go silent and wait for things to blow over",w:2},{t:"I shut down completely — sometimes for days — and refuse to engage",w:3}]},
  {id:"SC-Q16", a:"stone",     sensitive:false, q:"After a conflict, who usually reaches out first to reconnect?",                                                                                                             h:"Not who apologizes first — who breaks the silence.",            ans:[{t:"Either of us — it's pretty natural",w:0},{t:"Usually them, but it feels mutual enough",w:1},{t:"Almost always them — if they don't reach out it stays cold",w:2},{t:"Always them — and even when they do I make them work for it",w:3}]},
  {id:"SC-Q17", a:"stone",     sensitive:false, q:"Does your partner feel heard during disagreements — like their point lands before the conversation ends?",                                                                   h:"Not whether they win — whether you actually take in what they say.",ans:[{t:"Yes, even when I disagree I make sure they feel heard",w:0},{t:"Sometimes — depends on the topic",w:1},{t:"Rarely — conversations usually end before they feel understood",w:2},{t:"Never — conversations either blow up or I shut them down before anything lands",w:3}]},
  {id:"SC-Q18", a:"passive",   sensitive:false, q:"When you say 'fine' or 'whatever' during a disagreement, what usually happens next?",                                                                                       h:"Surface agreement — then what you actually do after.",           ans:[{t:"I actually mean it — the issue is dropped and we move on",w:0},{t:"I'm a little off but shake it off within the hour",w:1},{t:"I go cold or distant for a while without saying why",w:2},{t:"I act fine on the surface but make small digs or 'forget' things that matter to them",w:3}]},
  {id:"SC-Q19", a:"passive",   sensitive:false, q:"When something is bothering you, do you tell your partner directly or do they have to figure it out from your behavior?",                                                   h:"Direct means you tell them. Indirect means they piece it together.",ans:[{t:"Directly — I tell them when something is bothering me",w:0},{t:"Mostly directly, occasional hints",w:1},{t:"Mostly indirect — they usually have to detect that something is wrong",w:2},{t:"Always indirect — and if they ask I say 'nothing' while the behavior continues",w:3}]},
  {id:"SC-Q20", a:"passive",   sensitive:false, q:"Have you ever agreed to do something and then not done it or done it badly as a way of expressing displeasure — without saying you were unhappy?",                          h:"This is different from forgetting. This feels intentional even if you wouldn't say that out loud.",ans:[{t:"No, if I agree to something I follow through",w:0},{t:"Occasionally I drop things but it doesn't feel pointed",w:1},{t:"Yes, there is usually a connection between a prior conflict and what gets 'forgotten'",w:2},{t:"Yes, consistently — it's a way I express displeasure without having to say it",w:3}]},
  {id:"SC-Q21", a:"identity",  sensitive:false, q:"Have you ever threatened — directly or indirectly — to expose something private about your partner without their consent?",                                                  h:"This includes implying you could share personal information as leverage.",ans:[{t:"No, never",w:0},{t:"I've made comments that may have felt like a warning but nothing direct",w:1},{t:"Yes, during arguments I've implied I could",w:2},{t:"Yes, explicitly — as leverage or punishment",w:3}]},
  {id:"SC-Q22", a:"identity",  sensitive:false, q:"Do you use who your partner is — their background, identity, insecurities, or how they present — against them during conflict?",                                            h:"Examples: 'No one else would want you,' 'You're lucky I put up with you.'",ans:[{t:"No, I respect and affirm who they are",w:0},{t:"Occasionally something slips that I regret",w:1},{t:"Yes, it comes up in ways I know feel diminishing",w:2},{t:"Yes, consistently — I use it to gain the upper hand",w:3}]},
  {id:"SC-Q23", a:"identity",  sensitive:false, q:"Does your partner feel like they can be fully themselves — in how they dress, speak, act, or express themselves — around you?",                                             h:"Fully themselves means without fear of criticism, mockery, or punishment from you.",ans:[{t:"Yes, completely — I celebrate who they are",w:0},{t:"Mostly, though they hold some things back",w:1},{t:"Probably not — I think they tone themselves down around me",w:2},{t:"No — I think they've lost a significant part of themselves in this relationship",w:3}]},
  // Self Part 2
  {id:"SC-P2-Q1", a:"narcissistic",sensitive:false,q:"When the conversation shifts to your partner — their achievements, problems, or needs — how do you typically respond?",                                                 h:"Think about a recent time they shared good news or needed support.",ans:[{t:"I engage genuinely — ask questions, celebrate with them, or offer support",w:0},{t:"I'm okay at it but sometimes redirect to myself",w:1},{t:"I usually find a way to make it about me within a few minutes",w:2},{t:"Their moments consistently get hijacked by me",w:3}]},
  {id:"SC-P2-Q2", a:"narcissistic",sensitive:false,q:"Do you hold yourself to the same rules and standards you expect of others — being on time, keeping commitments, waiting your turn?",                                    h:"Entitlement is often invisible to the person who has it.",      ans:[{t:"Yes, I hold myself to the same standard as everyone else",w:0},{t:"I have my moments but nothing that feels like a pattern",w:1},{t:"I regularly expect exceptions and get irritated when I don't get them",w:2},{t:"I genuinely believe certain rules don't apply to me and feel contempt when treated otherwise",w:3}]},
  {id:"SC-P2-Q3", a:"narcissistic",sensitive:false,q:"When you make a mistake that affects your partner, how do you typically handle it?",                                                                                    h:"Not a one-time situation — your consistent pattern.",           ans:[{t:"I own it and make a genuine effort to fix it",w:0},{t:"I acknowledge it but move on quickly without much repair",w:1},{t:"I minimize it or find a reason why it wasn't really my fault",w:2},{t:"I never fully acknowledge mistakes — my partner bringing it up turns into an attack on them",w:3}]},
  {id:"SC-P2-Q4", a:"financial", sensitive:false, q:"Does your partner have independent access to money — their own account, their own income, the ability to spend without reporting back to you?",                          h:"This is about their financial autonomy, not who earns more.",   ans:[{t:"Yes, fully — they manage their own finances freely",w:0},{t:"Mostly, with some shared oversight that feels fair",w:1},{t:"Limited — they feel like they need to justify purchases to me",w:2},{t:"No — I control the money and they have little to no independent access",w:3}]},
  {id:"SC-P2-Q5", a:"financial", sensitive:false, q:"Have you ever undermined your partner's ability to work, earn money, or maintain financial independence?",                                                                h:"This includes creating conflict around their job, pressuring them to quit, or interfering with their employment.",ans:[{t:"No, I support their financial independence",w:0},{t:"I've expressed preferences about their work but nothing that felt controlling",w:1},{t:"Yes, I've made working harder for them through conflict, guilt, or interference",w:2},{t:"Yes, deliberately — and it has affected their income or employment",w:3}]},
  {id:"SC-P2-Q6", a:"financial", sensitive:false, q:"Have you put debt in your partner's name, made financial decisions that affected them without their knowledge, or used money as a reward or punishment?",                  h:"Think about credit cards, loans, large purchases, or withholding money after conflict.",ans:[{t:"No, financial decisions are made together and transparently",w:0},{t:"There have been surprises but nothing that felt intentional or harmful",w:1},{t:"Yes, and it has created financial stress or consequences for them",w:2},{t:"Yes, repeatedly — I use money as control and I know it",w:3}]},
  {id:"SC-P2-Q7", a:"intimidation",sensitive:false,q:"Have you ever used your physical presence to make your partner feel unsafe — blocking a doorway, standing over them, or getting physically close in a threatening way?", h:"This does not require physical contact. It is about using size or proximity as intimidation.",ans:[{t:"No, never",w:0},{t:"Once or twice in a heated moment but it felt unintentional",w:1},{t:"Yes, and I knew it made them feel trapped or scared",w:2},{t:"Yes, regularly — I use my presence to assert dominance during conflict",w:3}]},
  {id:"SC-P2-Q8", a:"intimidation",sensitive:false,q:"Have you ever thrown, broken, or hit objects during an argument — even if you did not hit your partner?",                                                                h:"Destroying property during conflict is a form of intimidation regardless of whether contact was made.",ans:[{t:"No, never",w:0},{t:"Once, in an extreme moment I regret",w:1},{t:"Yes, more than once — I know it frightens them",w:2},{t:"Yes, regularly — I'm aware it communicates what I'm capable of",w:3}]},
  {id:"SC-P2-Q9", a:"intimidation",sensitive:false,q:"Do you think your partner has ever felt physically afraid of you — even briefly?",                                                                                       h:"Honest self-assessment. A gut fear response in them counts.",   ans:[{t:"No, I'm confident they have never felt physically afraid of me",w:0},{t:"Once, in an extreme situation I believe was isolated",w:1},{t:"Possibly — I've seen fear in their response to me occasionally",w:2},{t:"Yes — I am aware they manage their behavior around what I might do",w:3}]},
  {id:"SC-P2-Q10",a:"sexual",    sensitive:true,  q:"When your partner is not in the mood for intimacy, how do you respond?",                                                                                                  h:"A healthy response is acceptance. This question is about your pattern when they say no or not now.",ans:[{t:"I accept it without issue",w:0},{t:"I'm occasionally disappointed but I never make them feel bad about it",w:1},{t:"I sulk, guilt-trip, or make the rejection feel like a problem they created",w:2},{t:"I pressure, persist, or withdraw emotionally until they give in",w:3}]},
  {id:"SC-P2-Q11",a:"sexual",    sensitive:false, q:"Have you ever used sex or intimacy as a bargaining chip — withholding it as punishment or using it as a reward for compliance?",                                          h:"This is about weaponizing intimacy, not normal fluctuations in desire.",ans:[{t:"No, intimacy is never tied to their behavior or compliance",w:0},{t:"There have been dry periods after conflict but it wasn't deliberate",w:1},{t:"Yes, the pattern is real — I'm more intimate when they comply and less when they don't",w:2},{t:"Yes, explicitly — I use it as leverage and I know it",w:3}]},
  {id:"SC-P2-Q12",a:"sexual",    sensitive:false, q:"Has your partner ever felt pressured into sexual activity they didn't want — through your persistence, guilt, emotional withdrawal, or implied consequences?",             h:"They don't have to have said no out loud for this to count.",   ans:[{t:"No, they always feel free to decline without consequence",w:0},{t:"Possibly once or twice but I believe it felt minor",w:1},{t:"Yes, I think they've complied to avoid conflict or emotional punishment from me",w:2},{t:"Yes, regularly — I know genuine refusal doesn't feel safe for them",w:3}]},
  {id:"SC-P2-Q13",a:"isolation", sensitive:false, q:"Looking at your partner's life over the past year or two, has their circle of friends or family contact gotten smaller since being with you?",                            h:"Normal relationship changes happen. This is about disconnection that correlates with your behavior.",ans:[{t:"No, their relationships outside ours are healthy and maintained",w:0},{t:"Some drift, but it feels like normal life change not something I drove",w:1},{t:"Yes, and I can connect it to conflict, pressure, or tension I created around those relationships",w:2},{t:"Yes, significantly — I am their primary or only source of support and I know that",w:3}]},
  {id:"SC-P2-Q14",a:"isolation", sensitive:false, q:"Have you ever created conflict, told stories, or behaved in ways that damaged your partner's relationships with people they were close to?",                               h:"This includes turning their family against them, causing scenes in front of friends, or making them choose.",ans:[{t:"No, I support their outside relationships",w:0},{t:"There have been tensions but nothing that felt strategic on my part",w:1},{t:"Yes, and some of their relationships have been damaged or ended as a result",w:2},{t:"Yes, deliberately — I have worked to make them more dependent on me",w:3}]},
  {id:"SC-P2-Q15",a:"blame",     sensitive:false, q:"When conflict happens in your relationship, who ends up apologizing most of the time?",                                                                                   h:"Regardless of who started it or who was actually at fault.",    ans:[{t:"It varies — whoever was actually wrong apologizes",w:0},{t:"Usually them, but that's sometimes fair",w:1},{t:"Almost always them — even when I know I was wrong",w:2},{t:"Always them — I cannot recall genuinely apologizing first",w:3}]},
  {id:"SC-P2-Q16",a:"blame",     sensitive:false, q:"When your partner raises a concern about your behavior, does the conversation stay on the original issue or do you shift it back onto them?",                             h:"DARVO: Deny, Attack, Reverse Victim and Offender.",             ans:[{t:"It stays on the issue — I address what they brought up",w:0},{t:"It sometimes drifts but we usually come back to it",w:1},{t:"It almost always shifts — they end up explaining themselves instead",w:2},{t:"Every time — by the end they are the one who wronged me and the original issue is buried",w:3}]},
  {id:"SC-P2-Q17",a:"somatic",   sensitive:false, q:"Do you experience or report physical symptoms — chest pain, headaches, anxiety attacks — when conflict arises with your partner?",                                        h:"Real illness exists. This is about whether your symptoms consistently appear at moments of accountability.",ans:[{t:"No, my health and conflict are not connected in a pattern",w:0},{t:"I'm sometimes unwell during stress but it doesn't feel like a pattern",w:1},{t:"Yes, I notice symptoms tend to surface when my partner raises concerns",w:2},{t:"Yes, consistently — conflict triggers a health event that ends the discussion",w:3}]},
  {id:"SC-P2-Q18",a:"somatic",   sensitive:false, q:"Does your partner hold back concerns or needs because of your health?",                                                                                                   h:"This is about whether your health status has become a reason their needs cannot be addressed.",ans:[{t:"No, my health never enters into whether they can raise something",w:0},{t:"Sometimes they hold back but it feels like consideration not avoidance",w:1},{t:"Often — I think they pre-filter what they bring up based on my health state",w:2},{t:"Always — I think having needs around me feels dangerous for them",w:3}]},
  {id:"SC-P2-Q19",a:"somatic",   sensitive:false, q:"Have you ever recovered quickly from a health episode once a conflict was dropped or your partner gave in?",                                                              h:"Not about medical reality — about whether resolution of tension correlates with your recovery.",ans:[{t:"No, my health runs independently of our relationship dynamics",w:0},{t:"Hard to say — I haven't noticed a clear pattern",w:1},{t:"Yes, I tend to feel better once tension is resolved in my favor",w:2},{t:"Yes, consistently — I recover fast once they back down or give in",w:3}]},
  {id:"SC-P2-Q20",a:"jealousy",  sensitive:false, q:"Do you accuse your partner of cheating or being interested in others — without real evidence?",                                                                          h:"Occasional insecurity is normal. Persistent unfounded accusations are different.",ans:[{t:"No, I trust them",w:0},{t:"I get insecure occasionally but it passes without becoming an accusation",w:1},{t:"Yes, I regularly imply or accuse without real basis",w:2},{t:"Yes, constantly — no amount of reassurance changes my suspicion",w:3}]},
  {id:"SC-P2-Q21",a:"jealousy",  sensitive:false, q:"Do you react with anger, interrogation, or punishment when your partner interacts with certain people?",                                                                  h:"Think about your reaction pattern, not just whether you feel jealous.",ans:[{t:"No, I am comfortable with their interactions with others",w:0},{t:"I occasionally feel uncomfortable but handle it reasonably",w:1},{t:"Yes, certain interactions reliably trigger anger or interrogation from me",w:2},{t:"Yes, almost any interaction they have with others gets monitored and questioned",w:3}]},
  {id:"SC-P2-Q22",a:"jealousy",  sensitive:false, q:"Has your partner changed their behavior — who they talk to, what they post, how they dress — to avoid triggering your jealousy?",                                        h:"This is about self-censorship they practice because of your reaction pattern.",ans:[{t:"No, I don't think they change behavior because of my jealousy",w:0},{t:"Minor adjustments that feel like normal relationship consideration",w:1},{t:"Yes, I think they regularly filter their behavior to avoid triggering me",w:2},{t:"Yes, significantly — their social life and self-expression are shaped around my jealousy",w:3}]},
  {id:"SC-P2-Q23",a:"religious", sensitive:false, q:"Do you use religion, scripture, cultural tradition, or family honor to justify controlling your partner's behavior or dismissing their concerns?",                        h:"Faith and culture are meaningful. This is about using them as tools of control.",ans:[{t:"No, faith or culture is shared respectfully or not used at all",w:0},{t:"Occasionally referenced in ways that may feel off but not a consistent pattern",w:1},{t:"Yes, I regularly use religious or cultural framing to justify my behavior or dismiss theirs",w:2},{t:"Yes, consistently — I tell them their concerns are sinful, shameful, or a violation of duty",w:3}]},
  {id:"SC-P2-Q24",a:"religious", sensitive:false, q:"Have you used shared faith, community, or family expectations to prevent your partner from leaving, seeking help, or speaking to others about your relationship?",        h:"This includes threats of spiritual consequences, family shame, or community rejection.",ans:[{t:"No, faith or family is never used to restrict their options",w:0},{t:"There is some pressure but it feels more like genuine concern than control",w:1},{t:"Yes, I think leaving or seeking help feels costly for them because of faith or family dynamics I've reinforced",w:2},{t:"Yes, explicitly — I have told or implied they would be shamed or rejected spiritually for speaking out",w:3}]},
  {id:"SC-P2-Q25",a:"religious", sensitive:false, q:"Do you apply religious or cultural standards to your partner more than to yourself?",                                                                                    h:"Shared faith should feel like connection. This is about it functioning as a leash for them.",ans:[{t:"No, the same standards apply equally to both of us",w:0},{t:"Occasionally it feels lopsided but not deliberately so",w:1},{t:"Yes, I notice the rules apply to controlling them more than to how I behave",w:2},{t:"Yes, clearly — I use faith or culture to keep them compliant while holding myself to a different standard",w:3}]},
  {id:"SC-P2-Q26",a:"humiliation",sensitive:false,q:"Have you ever put your partner down, mocked them, or criticized them in front of other people?",                                                                          h:"This includes jokes at their expense, correcting them publicly, or sharing their failures with others.",ans:[{t:"No, I am respectful of them in public",w:0},{t:"Occasional teasing that crossed a line but I apologized",w:1},{t:"Yes, it happens regularly and I know it humiliates them",w:2},{t:"Yes, consistently — I dread how they feel but I do it anyway",w:3}]},
  {id:"SC-P2-Q27",a:"humiliation",sensitive:false,q:"Have you shared private information about your partner — their struggles, their body, their past, their mistakes — with others without their consent?",                  h:"This includes telling family, friends, or posting things online.",ans:[{t:"No, what they share with me stays private",w:0},{t:"Once or twice in a way that felt careless but not malicious",w:1},{t:"Yes, private information has been shared and it has affected how others see them",w:2},{t:"Yes, deliberately — their private life is social currency or punishment for me",w:3}]},
  {id:"SC-P2-Q28",a:"humiliation",sensitive:false,q:"Do you build yourself up by tearing your partner down — especially in front of others?",                                                                                  h:"This is about whether their diminishment is how you gain status or confidence.",ans:[{t:"No, I build them up or stay neutral in public",w:0},{t:"Occasionally I make myself look good at their expense but it doesn't feel deliberate",w:1},{t:"Yes, I notice they are frequently the example of what not to do in my stories",w:2},{t:"Yes, clearly — making them look small is how I make myself look big",w:3}]},
  {id:"SC-P2-Q29",a:"rage",      sensitive:false, q:"How would you describe your own anger during conflict?",                                                                                                                  h:"Not how you are on a normal day — how you get when you're genuinely angry.",ans:[{t:"Controlled — I get upset but stay regulated",w:0},{t:"I occasionally raise my voice but de-escalate fairly quickly",w:1},{t:"Unpredictable — I know a small conflict can turn into a big explosion",w:2},{t:"Explosive — my anger is disproportionate and I know it frightens my partner",w:3}]},
  {id:"SC-P2-Q30",a:"rage",      sensitive:false, q:"After an explosive outburst, how do you typically behave?",                                                                                                               h:"The cycle after the explosion matters as much as the explosion itself.",ans:[{t:"I reflect seriously and work to change the behavior",w:0},{t:"I apologize but the pattern repeats without real change",w:1},{t:"I act as if nothing happened or minimize what occurred",w:2},{t:"I become overly loving and remorseful — until the next explosion",w:3}]},
  {id:"SC-P2-Q31",a:"rage",      sensitive:false, q:"Has your partner changed how they behave — topics they avoid, timing of conversations, tone they use — specifically to avoid triggering an explosive reaction from you?",  h:"This is about the impact of your anger pattern on their behavior.",ans:[{t:"No, I don't think they manage their behavior around fear of my anger",w:0},{t:"Minor adjustments that feel like normal communication",w:1},{t:"Yes, I think they have a mental list of things too risky to bring up with me",w:2},{t:"Yes, significantly — I know they feel like they're managing a situation that could detonate",w:3}]},
  {id:"SC-P2-Q32",a:"gatekeeper",sensitive:false, q:"Have you withheld access to your children, used parenting time as leverage, or threatened to take the children away during conflict?",                                    h:"This includes both formal custody situations and day-to-day access within the home.",ans:[{t:"No, parenting is handled separately from our conflict",w:0},{t:"There has been tension around parenting during conflict but nothing deliberate",w:1},{t:"Yes, I have used access to the children as leverage",w:2},{t:"Yes, explicitly — the children are a direct tool of punishment or control for me",w:3}]},
  {id:"SC-P2-Q33",a:"gatekeeper",sensitive:false, q:"Have you said or done things to undermine your partner's relationship with your children — speaking negatively about them to the kids or positioning yourself as the good parent?",h:"This is about deliberate erosion of their relationship with their own children.",ans:[{t:"No, I support their relationship with our children",w:0},{t:"Occasional venting to the kids that felt inappropriate but isolated",w:1},{t:"Yes, I have said things to the kids that I know affect how they see my partner",w:2},{t:"Yes, consistently — I am working to become the preferred parent by undermining them",w:3}]},
  {id:"SC-P2-Q34",a:"gatekeeper",sensitive:false, q:"Do you use your partner's role as a parent to keep them in the relationship — implying they will lose the children or damage them if they leave?",                        h:"This is a form of coercion specific to co-parents.",            ans:[{t:"No, parenting and relationship decisions are kept separate",w:0},{t:"There have been comments but they came from fear not intent",w:1},{t:"Yes, I think leaving feels impossible for them partly because of things I've implied about the children",w:2},{t:"Yes, explicitly — I have told or made them feel they will lose the children if they leave",w:3}]},
];

// ─── UTILITIES ────────────────────────────────────────────────────────────────
function getSev(score, arc) {
  const thresh = (arc==="isolation"||arc==="blame") ? 5 : 9;
  if (score >= thresh) return { label:"severe",  display:"Severe",           color:"#C0392B" };
  if (score >= 7)      return { label:"address", display:"Worth addressing", color:"#E74C3C" };
  if (score >= 4)      return { label:"watch",   display:"Worth watching",   color:"#E67E22" };
  return                      { label:"healthy", display:"No red flags",     color:"#27AE60" };
}

function computeResult(scores, keys) {
  const ranked = keys.map(k => ({ k, s:scores[k]||0 })).sort((a,b) => b.s-a.s);
  const primary   = ranked.find(x => x.s > 3) || null;
  const secondary = ranked.filter(x => x.s > 1 && x.k !== primary?.k)[0] || null;
  const pk = primary?.k || null;
  const sk = secondary?.k || null;
  const combinedLabel = pk && sk ? ((COMBINED[pk]?.[sk])||(COMBINED[sk]?.[pk])||null) : null;
  const severity = pk ? getSev(primary.s, pk) : { label:"healthy", display:"No red flags", color:"#27AE60" };
  return { primary:pk, secondary:sk, combinedLabel, severity };
}

function reframe(text, rt) {
  if (rt==="current"||rt==="self") return text;
  if (rt==="ex") return text
    .replace(/\byour partner\b/gi,"your ex-partner").replace(/\bdoes your\b/gi,"did your")
    .replace(/\bdo you\b/gi,"did you").replace(/\bhave you\b/gi,"had you")
    .replace(/\byou feel\b/gi,"you felt").replace(/\bhas your\b/gi,"had your");
  if (rt==="new") return "In what you've seen so far: "+text.charAt(0).toLowerCase()+text.slice(1);
  return text;
}

// ─── STYLES ───────────────────────────────────────────────────────────────────
const S = {
  wrap:       { maxWidth:480, margin:"0 auto", padding:"0 0 60px", fontFamily:"var(--font-sans)", background:"var(--rf-bg)", minHeight:"100vh" },
  screen:     { padding:"20px 16px" },
  eyebrow:    { fontSize:11, fontWeight:500, letterSpacing:"0.1em", textTransform:"uppercase", color:"var(--rf-danger)", marginBottom:8, display:"block" },
  h1:         { fontFamily:"var(--font-serif)", fontSize:26, lineHeight:1.2, marginBottom:12, fontWeight:400, color:"var(--rf-text)" },
  h2:         { fontFamily:"var(--font-serif)", fontSize:20, lineHeight:1.25, marginBottom:10, fontWeight:400, color:"var(--rf-text)" },
  h3:         { fontSize:12, fontWeight:500, letterSpacing:"0.07em", textTransform:"uppercase", color:"var(--rf-text2)", marginBottom:8 },
  p:          { fontSize:14, lineHeight:1.7, color:"var(--rf-text2)", marginBottom:10 },
  card:       { background:"var(--rf-surface)", border:"0.5px solid var(--rf-border)", borderRadius:"var(--border-radius-lg)", padding:16, marginBottom:12 },
  btnDark:    { display:"flex", alignItems:"center", justifyContent:"center", gap:6, fontSize:14, fontWeight:500, borderRadius:50, border:"none", cursor:"pointer", padding:"12px 24px", width:"100%", marginBottom:10, fontFamily:"var(--font-sans)", background:"var(--rf-text)", color:"var(--rf-bg)" },
  btnRed:     { display:"flex", alignItems:"center", justifyContent:"center", gap:6, fontSize:14, fontWeight:500, borderRadius:50, border:"none", cursor:"pointer", padding:"12px 24px", width:"100%", marginBottom:10, fontFamily:"var(--font-sans)", background:"#C0392B", color:"#fff" },
  btnOutline: { display:"flex", alignItems:"center", justifyContent:"center", fontSize:14, fontWeight:500, borderRadius:50, cursor:"pointer", padding:"12px 24px", width:"100%", marginBottom:10, fontFamily:"var(--font-sans)", background:"transparent", border:"0.5px solid var(--rf-border2)", color:"var(--rf-text)" },
  btnGhost:   { background:"none", border:"none", cursor:"pointer", fontSize:13, color:"var(--rf-text2)", padding:"6px 0", fontFamily:"var(--font-sans)" },
  notice:     { padding:"10px 14px", borderLeft:"3px solid var(--rf-border)", background:"var(--rf-surface2)", fontSize:13, lineHeight:1.6, color:"var(--rf-text2)", marginBottom:14 },
  meta:       { fontSize:11, color:"var(--rf-text3)", textAlign:"center", marginTop:10, lineHeight:1.6 },
  divider:    { height:"0.5px", background:"var(--rf-border)", margin:"14px 0" },
};

function Badge({ sev }) {
  const c = { healthy:["#D5F5E3","#145A32"], watch:["#FDEBD0","#7B4A0A"], address:["#FADBD8","#7B1A13"], severe:["#C0392B","#fff"] };
  const [bg,fg] = c[sev.label] || c.healthy;
  return <span style={{ display:"inline-flex", alignItems:"center", padding:"3px 10px", borderRadius:50, fontSize:11, fontWeight:500, background:bg, color:fg }}>{sev.display}</span>;
}

function CrisisBox() {
  return (
    <div style={{ background:"#C0392B", color:"#fff", borderRadius:"var(--border-radius-lg)", padding:18, marginBottom:14, textAlign:"center" }}>
      <div style={{ fontSize:14, fontWeight:500, marginBottom:6 }}>Your safety matters.</div>
      <div style={{ fontSize:22, fontWeight:700, marginBottom:4 }}>1-800-799-7233</div>
      <div style={{ fontSize:12, opacity:.85, marginBottom:5 }}>National Domestic Violence Hotline — 24/7, free, confidential</div>
      <div style={{ fontSize:12, opacity:.75 }}>Text START to 88788</div>
    </div>
  );
}

function WarmAffirmation({ part }) {
  const copy = part === 2
    ? "You went the distance and found nothing significant. Your partner sounds like one of the good ones. That's not nothing — that's everything. Appreciate them."
    : "Based on your answers, your partner doesn't show significant red flag patterns in the areas you chose to explore. That's worth recognizing — healthy behavior deserves appreciation too.";
  return (
    <div style={{ background:"#D5F5E3", border:"0.5px solid #A9DFBF", borderRadius:"var(--border-radius-lg)", padding:20, marginBottom:16, textAlign:"center" }}>
      <div style={{ fontSize:22, marginBottom:10 }}>&#10003;</div>
      <p style={{ fontFamily:"var(--font-serif)", fontSize:16, color:"#145A32", margin:0, lineHeight:1.5 }}>{copy}</p>
    </div>
  );
}

function ArchetypeCard({ arcKey, score, isNew }) {
  const a = ARC[arcKey];
  const flagged = score > 3;
  const sev = getSev(score, arcKey);
  return (
    <div style={{ ...S.card, border:flagged?`1px solid ${sev.color}33`:"0.5px solid var(--rf-border)", opacity:flagged?1:0.5 }}>
      <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", gap:8, marginBottom:flagged?8:0 }}>
        <div>
          <div style={{ fontSize:flagged?15:13, fontWeight:500, color:"var(--rf-text)", marginBottom:2 }}>
            {a.street}
            {isNew && <span style={{ marginLeft:6, fontSize:10, background:"#EDE7F6", color:"#4A148C", borderRadius:50, padding:"1px 8px", fontWeight:500 }}>Newly discovered</span>}
          </div>
          <div style={{ fontSize:11, color:"var(--rf-text3)" }}>{a.clinical}</div>
        </div>
        {flagged ? <Badge sev={sev}/> : <span style={{ fontSize:11, color:"var(--rf-text3)", whiteSpace:"nowrap", marginTop:2 }}>Not detected</span>}
      </div>
      {flagged && <p style={{ fontSize:13, lineHeight:1.6, color:"var(--rf-text2)", margin:0 }}>{ARC_DESC[arcKey]}</p>}
    </div>
  );
}

function ResultSection({ title, scores, keys, newlyDiscovered=[], part=1 }) {
  const flagged = keys.filter(k=>(scores[k]||0)>3).sort((a,b)=>(scores[b]||0)-(scores[a]||0));
  const rest    = keys.filter(k=>(scores[k]||0)<=3);
  const allClean = flagged.length === 0;
  const pk = flagged[0]||null;
  const sk = flagged[1]||null;
  const combinedLabel = pk&&sk?((COMBINED[pk]?.[sk])||(COMBINED[sk]?.[pk])||null):null;
  const isSevere = flagged.some(k=>getSev(scores[k]||0,k).label==="severe");
  const intSevere = (scores.intimidation||0)>0 && getSev(scores.intimidation||0,"intimidation").label==="severe";
  return (
    <div style={{ marginBottom:8 }}>
      <h3 style={S.h3}>{title}</h3>
      {intSevere && <div style={{ ...S.notice, borderColor:"#C0392B", background:"#FADBD8", color:"#7B1A13", marginBottom:12 }}>Your physical safety matters. If you feel unsafe: <strong>1-800-799-7233</strong> or text START to 88788.</div>}
      {isSevere&&!intSevere&&<CrisisBox/>}
      {pk&&combinedLabel&&(
        <div style={{ background:"rgba(192,57,43,.07)", borderRadius:"var(--border-radius-md)", padding:"10px 14px", marginBottom:12 }}>
          <div style={{ fontSize:10, fontWeight:500, textTransform:"uppercase", letterSpacing:".08em", color:"#C0392B", marginBottom:2 }}>Combined pattern</div>
          <div style={{ fontSize:14, fontWeight:500, color:"#C0392B" }}>{combinedLabel}</div>
        </div>
      )}
      {allClean&&<WarmAffirmation part={part}/>}
      {[...flagged,...rest].map(k=><ArchetypeCard key={k} arcKey={k} score={scores[k]||0} isNew={newlyDiscovered.includes(k)}/>)}
    </div>
  );
}

// ─── SCREENS ──────────────────────────────────────────────────────────────────
function Landing({ onStart }) {
  return (
    <div style={S.screen}>
      <div style={{ width:42,height:42,background:"#C0392B",borderRadius:10,display:"flex",alignItems:"center",justifyContent:"center",marginBottom:18 }}>
        <svg width="20" height="20" viewBox="0 0 20 20" fill="none"><rect x="2" y="3" width="16" height="3" rx="1.5" fill="white"/><rect x="2" y="8.5" width="16" height="3" rx="1.5" fill="white" opacity=".7"/><rect x="2" y="14" width="16" height="3" rx="1.5" fill="white" opacity=".4"/></svg>
      </div>
      <span style={S.eyebrow}>RedFlag</span>
      <h1 style={S.h1}>Know what you're dealing with.</h1>
      <p style={S.p}>A structured way to identify behavioral patterns in your relationship. Clear language, not clinical jargon. Free, anonymous, nothing stored.</p>
      <button style={{ ...S.btnDark, marginTop:16 }} onClick={onStart}>Start the quiz →</button>
      <p style={S.meta}>Takes about 5 minutes · No account required</p>
    </div>
  );
}

function Onboarding({ onSelect }) {
  const [rel, setRel]   = useState(null);
  const [kids, setKids] = useState(null);
  const opts = [
    { k:"current", l:"My current partner",  s:"Questions in present tense" },
    { k:"ex",      l:"An ex-partner",        s:"Questions reframed to past tense" },
    { k:"new",     l:"Someone new",          s:"Early-stage framing" },
    { k:"self",    l:"Myself",               s:"Am I the problem? Self-assessment mode" },
  ];
  return (
    <div style={S.screen}>
      <span style={S.eyebrow}>Step 1 of 2</span>
      <h1 style={S.h1}>Who are you thinking about?</h1>
      {opts.map(o=>(
        <button key={o.k} onClick={()=>setRel(o.k)} style={{ display:"block",width:"100%",padding:"13px 16px",marginBottom:8,background:rel===o.k?"var(--rf-text)":"var(--rf-surface)",border:rel===o.k?"0.5px solid var(--rf-text)":"0.5px solid var(--rf-border)",borderRadius:"var(--border-radius-md)",cursor:"pointer",textAlign:"left",fontFamily:"var(--font-sans)",color:rel===o.k?"var(--rf-bg)":"var(--rf-text)",transition:"all .12s" }}>
          <div style={{ fontSize:14,fontWeight:500 }}>{o.l}</div>
          <div style={{ fontSize:12,opacity:.65,marginTop:3 }}>{o.s}</div>
        </button>
      ))}
      <div style={S.divider}/>
      <h2 style={{ ...S.h2, fontSize:16, marginBottom:12 }}>Are children involved in this relationship?</h2>
      <div style={{ display:"flex", gap:10, marginBottom:20 }}>
        {[{k:true,l:"Yes"},{k:false,l:"No"}].map(o=>(
          <button key={String(o.k)} onClick={()=>setKids(o.k)} style={{ flex:1,padding:"12px",background:kids===o.k?"var(--rf-text)":"var(--rf-surface)",border:kids===o.k?"0.5px solid var(--rf-text)":"0.5px solid var(--rf-border)",borderRadius:"var(--border-radius-md)",cursor:"pointer",fontFamily:"var(--font-sans)",fontSize:14,fontWeight:500,color:kids===o.k?"var(--rf-bg)":"var(--rf-text)",transition:"all .12s" }}>
            {o.l}
          </button>
        ))}
      </div>
      <button style={{ ...S.btnDark, opacity:(rel&&kids!==null)?1:0.35 }} onClick={()=>rel&&kids!==null&&onSelect(rel,kids)} disabled={!rel||kids===null}>Continue</button>
    </div>
  );
}

function SummaryScreen({ hasKids, isSelf, onConfirm }) {
  const [selected, setSelected] = useState(new Set());
  const available = Object.keys(ARC).filter(k => !ARC[k].kids || hasKids);
  const MIN=5, MAX=8;
  const count = selected.size;
  const canStart = count >= MIN && count <= MAX;

  function toggle(k) {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(k)) { next.delete(k); }
      else if (next.size < MAX) { next.add(k); }
      return next;
    });
  }

  return (
    <div style={S.screen}>
      <span style={S.eyebrow}>Choose your focus</span>
      <h1 style={{ ...S.h1, marginBottom:6 }}>Pick 5 to 8 patterns to explore first.</h1>
      <p style={{ ...S.p, marginBottom:4 }}>{isSelf?"Select the ones that might describe you. Be honest.":"Select the ones that resonate. The rest become Part 2."}</p>
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:14 }}>
        <span style={{ fontSize:12, color:"var(--rf-text3)" }}>Tap a row to select · min 5, max 8</span>
        <span style={{ fontSize:13, fontWeight:500, color:canStart?"#27AE60":count===0?"var(--rf-text3)":"var(--rf-danger)" }}>{count}/{MAX}</span>
      </div>
      {available.map(k=>{
        const a = ARC[k];
        const sel = selected.has(k);
        const locked = !sel && count >= MAX;
        return (
          <button key={k} onClick={()=>!locked&&toggle(k)}
            style={{ display:"flex", alignItems:"flex-start", gap:12, width:"100%", padding:"13px 14px", marginBottom:8,
              background:sel?"rgba(192,57,43,0.07)":"var(--rf-surface)",
              border:sel?"1px solid rgba(192,57,43,0.4)":"0.5px solid var(--rf-border)",
              borderRadius:"var(--border-radius-md)", cursor:locked?"not-allowed":"pointer",
              textAlign:"left", fontFamily:"var(--font-sans)", opacity:locked?0.4:1, transition:"all .12s" }}>
            <div style={{ width:18,height:18,borderRadius:4,border:`1.5px solid ${sel?"#C0392B":"var(--rf-border2)"}`,background:sel?"#C0392B":"transparent",flexShrink:0,marginTop:1,display:"flex",alignItems:"center",justifyContent:"center" }}>
              {sel&&<svg width="10" height="10" viewBox="0 0 10 10" fill="none"><path d="M2 5l2 2 4-4" stroke="#fff" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>}
            </div>
            <div>
              <div style={{ fontSize:14,fontWeight:500,color:"var(--rf-text)",lineHeight:1.3 }}>{a.street}</div>
              <div style={{ fontSize:12,color:"var(--rf-text2)",marginTop:3,lineHeight:1.5 }}>{a.one}</div>
            </div>
          </button>
        );
      })}
      <div style={{ position:"sticky", bottom:0, background:"var(--rf-bg)", paddingTop:12, paddingBottom:4, marginTop:8 }}>
        <button style={{ ...S.btnRed, opacity:canStart?1:0.35 }} onClick={()=>{if(!canStart)return;const p1=[...selected];const p2=available.filter(k=>!selected.has(k));onConfirm(p1,p2);}} disabled={!canStart}>
          {canStart?`Start with these ${count} →`:`Select ${Math.max(0,MIN-count)} more to continue`}
        </button>
        <p style={S.meta}>Unselected archetypes become Part 2.</p>
      </div>
    </div>
  );
}

function QuizScreen({ questions, relType, partLabel, onComplete, onBack }) {
  const [idx, setIdx]     = useState(0);
  const [answers, setAns] = useState([]);
  const [sel, setSel]     = useState(null);
  const [showSens, setShowSens] = useState(false);
  const [sensOk, setSensOk]     = useState(false);
  const q = questions[idx];
  const total = questions.length;

  if (q?.sensitive && !sensOk && !showSens) setShowSens(true);

  function next() {
    if (sel===null) return;
    const newAns = [...answers, { questionId:q.id, archetype:q.a, weight:q.ans[sel].w }];
    setAns(newAns); setSel(null);
    if (idx+1>=total) { onComplete(newAns); } else { setIdx(idx+1); }
  }
  function back() {
    if (idx===0) { onBack(); return; }
    setAns(answers.slice(0,-1)); setSel(null); setIdx(idx-1);
  }

  if (showSens&&!sensOk) return (
    <div style={S.screen}><div style={S.card}>
      <h2 style={S.h2}>A moment before we continue</h2>
      <p style={S.p}>The next questions cover sensitive topics including sexual coercion. Answer only what you feel comfortable with — it's okay to select the first option for any question you'd rather skip.</p>
      <button style={S.btnDark} onClick={()=>{setSensOk(true);setShowSens(false);}}>I understand, continue</button>
    </div></div>
  );

  return (
    <div style={S.screen}>
      <div style={{ height:3, background:"var(--rf-border)", borderRadius:2, marginBottom:18 }}>
        <div style={{ height:"100%", width:Math.round((idx/total)*100)+"%", background:"#C0392B", borderRadius:2, transition:"width .3s" }}/>
      </div>
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:18 }}>
        <button style={S.btnGhost} onClick={back}>← Back</button>
        <span style={{ fontSize:12, color:"var(--rf-text3)" }}>{partLabel} · {idx+1}/{total}</span>
      </div>
      <span style={S.eyebrow}>{ARC[q.a]?.street}</span>
      <h2 style={S.h2}>{reframe(q.q, relType)}</h2>
      {q.h&&<p style={{ fontSize:12,color:"var(--rf-text3)",fontStyle:"italic",marginBottom:14,lineHeight:1.6 }}>{q.h}</p>}
      {q.ans.map((ans,i)=>(
        <button key={i} onClick={()=>setSel(i)} style={{ display:"block",width:"100%",padding:"13px 16px",marginBottom:8,background:sel===i?"var(--rf-text)":"var(--rf-surface)",border:sel===i?"0.5px solid var(--rf-text)":"0.5px solid var(--rf-border)",borderRadius:"var(--border-radius-md)",cursor:"pointer",textAlign:"left",fontFamily:"var(--font-sans)",fontSize:14,lineHeight:1.5,color:sel===i?"var(--rf-bg)":"var(--rf-text)",transition:"all .12s" }}>
          {ans.t}
        </button>
      ))}
      <button style={{ ...S.btnDark, marginTop:10, opacity:sel!==null?1:0.3 }} onClick={next} disabled={sel===null}>
        {idx+1<total?"Next":"See results"}
      </button>
    </div>
  );
}

function WhatNow({ result, part2Result, onShare, onRestart }) {
  const [tab, setTab] = useState(0);
  const pk = (part2Result||result)?.primary;
  const tabs = ["Understand","What to say","Red vs green","Get support"];
  const scripts = SCRIPTS[pk] || DEFAULT_SCRIPTS;
  return (
    <div style={S.screen}>
      <span style={S.eyebrow}>What now</span>
      <h1 style={S.h1}>Here's where to go from here.</h1>
      <div style={S.notice}>RedFlag identifies patterns in behavior, not clinical conditions. Results are for self-reflection only, not professional mental health advice.</div>
      <div style={{ display:"flex", gap:3, background:"var(--rf-surface2)", borderRadius:50, padding:3, marginBottom:18 }}>
        {tabs.map((t,i)=>(
          <button key={i} onClick={()=>setTab(i)} style={{ flex:1,padding:"7px 6px",borderRadius:50,fontSize:12,fontWeight:500,cursor:"pointer",textAlign:"center",border:"none",background:tab===i?"var(--rf-surface)":"transparent",color:tab===i?"var(--rf-text)":"var(--rf-text2)",fontFamily:"var(--font-sans)",whiteSpace:"nowrap",transition:"all .2s" }}>{t}</button>
        ))}
      </div>
      {tab===0&&(<div><h3 style={S.h3}>What's actually happening</h3><p style={S.p}>The patterns identified are recognized behavioral dynamics in relationship psychology. They're not about bad days — they're about consistent behavior over time. Naming them matters. When you can see a pattern clearly, it's harder to rationalize away.</p>{pk&&<p style={S.p}><strong>{ARC[pk]?.street}</strong> ({ARC[pk]?.clinical}): {ARC_DESC[pk]}</p>}</div>)}
      {tab===1&&(<div><h3 style={S.h3}>Scripts to start with</h3><p style={{ ...S.p, fontSize:12 }}>Starting points, not scripts to memorize. Adapt to your voice.</p>{scripts.map((s,i)=><div key={i} style={{ background:"var(--rf-surface2)",borderRadius:"var(--border-radius-md)",padding:"12px 14px",marginBottom:8,fontSize:13,lineHeight:1.7,color:"var(--rf-text2)",fontStyle:"italic" }}>{s}</div>)}</div>)}
      {tab===2&&(<div>
        <h3 style={{ ...S.h3, color:"#27AE60" }}>Signs this can be worked on</h3>
        {["They acknowledge impact without defending intent.","They stay in hard conversations rather than shutting down.","They can say 'I was wrong' without making you feel guilty.","They celebrate your wins without redirecting to themselves."].map((g,i)=><p key={i} style={{ ...S.p, paddingLeft:12, borderLeft:"2px solid #D5F5E3" }}>{g}</p>)}
        <h3 style={{ ...S.h3, marginTop:16, color:"#C0392B" }}>Signs this may be more serious</h3>
        {["Conversations consistently end with you apologizing.","Your emotional responses are treated as weapons.","You feel less like yourself than before this relationship.","Raising issues feels more dangerous than staying silent."].map((r,i)=><p key={i} style={{ ...S.p, paddingLeft:12, borderLeft:"2px solid #FADBD8" }}>{r}</p>)}
      </div>)}
      {tab===3&&(<div>
        <h3 style={S.h3}>You don't have to figure this out alone</h3>
        <p style={S.p}>Therapy is not about being broken. It's about having a dedicated space to think clearly about something hard to see from the inside.</p>
        <div style={S.card}><div style={{ fontSize:13,fontWeight:500,marginBottom:2,color:"var(--rf-text)" }}>National Domestic Violence Hotline</div><div style={{ fontSize:22,fontWeight:700,color:"#C0392B",marginBottom:2 }}>1-800-799-7233</div><div style={{ fontSize:12,color:"var(--rf-text3)" }}>24/7 · Free · Confidential · Text START to 88788</div></div>
        <div style={S.card}><div style={{ fontSize:13,fontWeight:500,marginBottom:2,color:"var(--rf-text)" }}>Crisis Text Line</div><div style={{ fontSize:15,color:"var(--rf-text2)",marginBottom:2 }}>Text HOME to 741741</div><div style={{ fontSize:12,color:"var(--rf-text3)" }}>Free · Confidential · 24/7</div></div>
      </div>)}
      <div style={S.divider}/>
      <button style={S.btnDark} onClick={onShare}>Share my results card</button>
      <button style={S.btnOutline} onClick={onRestart}>Start over</button>
      <p style={S.meta}>RedFlag identifies patterns in behavior, not clinical conditions. Results are for self-reflection only.</p>
    </div>
  );
}

function ShareCard({ result, part2Result, onBack }) {
  const finalResult = part2Result||result;
  const pk = finalResult?.primary;
  const p = pk ? ARC[pk] : null;
  return (
    <div style={S.screen}>
      <button style={S.btnGhost} onClick={onBack}>← Back</button>
      <div style={{ marginTop:14 }}>
        <span style={S.eyebrow}>Share</span>
        <h1 style={S.h1}>Your result card.</h1>
        <div style={{ background:"#1A1209", color:"#F0EDE8", borderRadius:"var(--border-radius-lg)", padding:26, textAlign:"center", marginBottom:18 }}>
          <div style={{ fontSize:10,fontWeight:500,letterSpacing:".14em",textTransform:"uppercase",opacity:.45,marginBottom:14 }}>RedFlag Result</div>
          {p?(<>
            <div style={{ fontFamily:"var(--font-serif)",fontSize:24,lineHeight:1.2,marginBottom:8,fontWeight:400 }}>{p.street}</div>
            <div style={{ fontSize:12,opacity:.55,marginBottom:14 }}>{p.clinical}</div>
            {finalResult.combinedLabel&&<div style={{ background:"rgba(192,57,43,.25)",borderRadius:8,padding:"7px 14px",marginBottom:12,fontSize:13,fontWeight:500 }}>{finalResult.combinedLabel}</div>}
            <div style={{ display:"inline-flex",padding:"4px 14px",borderRadius:50,background:"rgba(255,255,255,.12)",fontSize:11,fontWeight:500 }}>{finalResult.severity.display}</div>
          </>):(<>
            <div style={{ fontFamily:"var(--font-serif)",fontSize:20,marginBottom:8,fontWeight:400 }}>No significant patterns detected</div>
            <div style={{ fontSize:13,opacity:.6 }}>Your responses reflect a healthy dynamic.</div>
          </>)}
          <div style={{ fontSize:10,opacity:.3,marginTop:18,letterSpacing:".06em" }}>redflag.app · Know what you're dealing with</div>
        </div>
        <p style={{ ...S.p, textAlign:"center", fontSize:12 }}>Save this image and share it to start a conversation. Results reflect your perception, not a clinical assessment.</p>
      </div>
    </div>
  );
}

// ─── APP ──────────────────────────────────────────────────────────────────────
const SCREENS = { LAND:"land", ONBOARD:"onboard", SUMMARY:"summary", Q1:"q1", R1:"r1", BRIDGE:"bridge", Q2:"q2", R2:"r2", WN:"wn", SHARE:"share" };

export default function App() {
  const [screen,    setScreen]    = useState(SCREENS.LAND);
  const [rel,       setRel]       = useState(null);
  const [hasKids,   setHasKids]   = useState(false);
  const [p1Keys,    setP1Keys]    = useState([]);
  const [p2Keys,    setP2Keys]    = useState([]);
  const [p1Scores,  setP1Scores]  = useState({});
  const [p1Result,  setP1Result]  = useState(null);
  const [p2Result,  setP2Result]  = useState(null);
  const [allScores, setAllScores] = useState({});
  const [dark,      setDark]      = useState(()=>{ try{return localStorage.getItem("rf-dark")==="1";}catch{return false;} });

  function toggleDark() { setDark(d=>{ const n=!d; try{localStorage.setItem("rf-dark",n?"1":"0");}catch{} return n; }); }
  function go(s) { setScreen(s); }
  function restart() { setScreen(SCREENS.LAND);setRel(null);setHasKids(false);setP1Keys([]);setP2Keys([]);setP1Scores({});setP1Result(null);setP2Result(null);setAllScores({}); }

  const isSelf = rel === "self";
  const allQ   = isSelf ? SELF_Q : PARTNER_Q;

  // Filter questions to only those for selected archetype keys, excluding gatekeeper when no kids
  const p1Q = allQ.filter(q => p1Keys.includes(q.a));
  const p2Q = allQ.filter(q => p2Keys.includes(q.a) && (hasKids || q.a !== "gatekeeper"));

  function onP1Done(answers) {
    const scores = {}; p1Keys.forEach(k=>{scores[k]=0;});
    answers.forEach(a=>{ if(scores[a.archetype]!==undefined) scores[a.archetype]+=a.weight; });
    setP1Scores(scores); setP1Result(computeResult(scores,p1Keys)); setAllScores(scores); go(SCREENS.R1);
  }

  function onP2Done(answers) {
    const scores = {}; p2Keys.forEach(k=>{scores[k]=0;});
    answers.forEach(a=>{ if(scores[a.archetype]!==undefined) scores[a.archetype]+=a.weight; });
    const combined = {}; [...p1Keys,...p2Keys].forEach(k=>{combined[k]=(p1Scores[k]||0)+(scores[k]||0);});
    const result = computeResult(combined,[...p1Keys,...p2Keys]);
    result.newlyDiscovered = p2Keys.filter(k=>(scores[k]||0)>3&&k!==p1Result?.primary&&k!==p1Result?.secondary);
    setP2Result(result); setAllScores(combined); go(SCREENS.R2);
  }

  const cssVars = dark ? DARK_VARS : LIGHT_VARS;

  return (
    <DarkCtx.Provider value={{ dark, toggle:toggleDark }}>
      <div style={{ ...cssVars, ...S.wrap }}>
        <DarkToggle/>
        {screen===SCREENS.LAND    && <Landing onStart={()=>go(SCREENS.ONBOARD)}/>}
        {screen===SCREENS.ONBOARD && <Onboarding onSelect={(r,k)=>{setRel(r);setHasKids(k);go(SCREENS.SUMMARY);}}/>}
        {screen===SCREENS.SUMMARY && <SummaryScreen hasKids={hasKids} isSelf={isSelf} onConfirm={(p1,p2)=>{setP1Keys(p1);setP2Keys(p2);go(SCREENS.Q1);}}/>}
        {screen===SCREENS.Q1 && <QuizScreen questions={p1Q} relType={rel} partLabel="Part 1" onComplete={onP1Done} onBack={()=>go(SCREENS.SUMMARY)}/>}
        {screen===SCREENS.R1 && (
          <div style={S.screen}>
            <span style={S.eyebrow}>Part 1 results</span>
            <h1 style={S.h1}>Here's what your answers reveal.</h1>
            <div style={S.notice}>RedFlag identifies patterns in behavior, not clinical conditions. Results are for self-reflection only, not professional mental health advice.</div>
            <ResultSection title="Your selected patterns" scores={p1Scores} keys={p1Keys} part={1}/>
            <button style={S.btnRed} onClick={()=>go(SCREENS.BRIDGE)}>Go deeper — Part 2</button>
            <button style={S.btnDark} onClick={()=>go(SCREENS.WN)}>What do I do now?</button>
          </div>
        )}
        {screen===SCREENS.BRIDGE && (
          <div style={S.screen}>
            <span style={S.eyebrow}>Part 1 complete</span>
            <h1 style={S.h1}>Want to check if any of these apply to {isSelf?"you":"your partner"}?</h1>
            <p style={S.p}>Part 2 covers {p2Keys.length} more patterns in {p2Q.length} questions. Here's exactly what you'd be exploring:</p>
            <div style={{ marginBottom:18 }}>
              {p2Keys.map(k=>(
                <div key={k} style={{ display:"flex", alignItems:"flex-start", gap:10, padding:"10px 0", borderBottom:"0.5px solid var(--rf-border)" }}>
                  <div style={{ width:6,height:6,borderRadius:"50%",background:"#C0392B",flexShrink:0,marginTop:6 }}/>
                  <div>
                    <div style={{ fontSize:14,fontWeight:500,color:"var(--rf-text)" }}>{ARC[k]?.street}</div>
                    <div style={{ fontSize:12,color:"var(--rf-text3)" }}>{ARC[k]?.one}</div>
                  </div>
                </div>
              ))}
            </div>
            <button style={S.btnRed} onClick={()=>go(SCREENS.Q2)}>Yes, go deeper — Part 2</button>
            <button style={S.btnOutline} onClick={()=>go(SCREENS.WN)}>I'm done for now — see results</button>
            <p style={S.meta}>Part 2 is optional. Your Part 1 results are complete and valid.</p>
          </div>
        )}
        {screen===SCREENS.Q2 && <QuizScreen questions={p2Q} relType={rel} partLabel="Part 2" onComplete={onP2Done} onBack={()=>go(SCREENS.BRIDGE)}/>}
        {screen===SCREENS.R2 && (
          <div style={S.screen}>
            <span style={S.eyebrow}>Full profile</span>
            <h1 style={S.h1}>Your complete picture.</h1>
            <div style={S.notice}>RedFlag identifies patterns in behavior, not clinical conditions. Results are for self-reflection only.</div>
            <ResultSection title="Part 2 — Deeper patterns" scores={allScores} keys={p2Keys} newlyDiscovered={p2Result?.newlyDiscovered||[]} part={2}/>
            <div style={S.divider}/>
            <ResultSection title="Part 1 — Your selections" scores={allScores} keys={p1Keys} part={1}/>
            <button style={S.btnDark} onClick={()=>go(SCREENS.WN)}>What do I do now?</button>
            <button style={S.btnOutline} onClick={()=>go(SCREENS.SHARE)}>Share my results card</button>
          </div>
        )}
        {screen===SCREENS.WN    && <WhatNow result={p1Result} part2Result={p2Result} onShare={()=>go(SCREENS.SHARE)} onRestart={restart}/>}
        {screen===SCREENS.SHARE && <ShareCard result={p1Result} part2Result={p2Result} onBack={()=>go(p2Result?SCREENS.R2:SCREENS.WN)}/>}
      </div>
    </DarkCtx.Provider>
  );
}
