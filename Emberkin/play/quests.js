/* ============================================================================
   EMBERKIN — quests & reflections (story + daily + weekly)
   Pure data. The main chain maps onto the existing story beats; each completion
   delivers a short in-world lesson (Tainer's voice) and files an Insight in the
   Journal. Daily/weekly quests pair a game task with a small real-world practice.

   These reflections are gentle life-skills practice inspired by stoicism and
   emotional intelligence — NOT medical or mental-health advice. That framing is
   surfaced in-game (Journal header) and in the docs.
   ========================================================================== */

/* trigger: the game event that completes a main quest (or 'auto' = shortly after
   it becomes active). insight: {theme, teaching, practice} filed in the Journal. */
export const MAIN_QUESTS = [
  { id:'m_cast', trigger:'fished',
    title:'The First Cast',
    objective:'Reach Willowmere and cast a line. (Move W A S D · look by dragging/mouse · press E at the water.)',
    lesson:"You looked so lost on that shore. But you didn't fix everything at once — you just cast one line. That's how every big thing begins: the next small step.",
    insight:{ theme:'Beginning', teaching:'When it all feels like too much, you don’t need the whole path — only the next small step.',
      practice:'Pick one tiny thing today and finish it.' },
    quiz:{ q:"When everything feels like too much, what's the wise first move?", options:['Wait until you feel ready', 'Do the next small thing', 'Solve the whole problem at once'], answer:1 },
    reward:10 },

  { id:'m_name', trigger:'firstElement',
    title:'Name the Flame',
    objective:'Climb to the Wardstone and attune your first element (press E). Then switch elements with Q and E, and attack (click / J) to fight.',
    lesson:"Feel how the element settled once you touched it? Feelings work the same way — wild and huge until you name them. Named, they’re something you can carry, even use.",
    insight:{ theme:'Emotional Intelligence', teaching:'A feeling you can name is a feeling you can carry.',
      practice:'When a big feeling comes, say it out loud: “I feel ___.”' },
    quiz:{ q:'What happens when you can NAME a big feeling?', options:['It disappears instantly', 'It becomes something you can carry', 'It gets stronger'], answer:1 },
    reward:12 },

  { id:'m_wall', trigger:'iceMelted',
    title:'The Warm Way Through',
    objective:'A wall of Rime blocks the road north. Find the way through.',
    lesson:"You didn’t smash that wall — you brought the right warmth. Some walls never move by force. They melt with patience and the right approach.",
    insight:{ theme:'Problem-Solving', teaching:'Not every wall breaks by force; some melt with patience and the right warmth.',
      practice:'With one stuck problem, ask: “what’s the gentler way in?”' },
    quiz:{ q:"You're stuck on a hard problem. What does Emberkin suggest?", options:['Push harder with force', 'Look for the gentler way in', 'Give up on it'], answer:1 },
    reward:14 },

  { id:'m_watch', trigger:'campPassed',
    title:'Walk Softly',
    objective:'Slip through the Stonekin camp unseen.',
    lesson:"Did you feel it? You watched first — learned their pattern before you moved. Reading the room before you step into it is a quiet kind of strength.",
    insight:{ theme:'Situational Awareness', teaching:'The wise watch first. Understand the pattern before you act.',
      practice:'Before reacting today, take one breath and notice what’s really happening.' },
    quiz:{ q:'What do the wise do before they act?', options:['Move fastest', 'Watch and learn the pattern', 'Ask for permission'], answer:1 },
    reward:16 },

  { id:'m_wind', trigger:'trialPassed',
    title:'Lean Into the Wind',
    objective:'Find Skywright Pell in the south meadow and pass the Windrider’s Trial.',
    lesson:"You were scared to fall. Then you leaned INTO the wind instead of fighting it — and you flew. Courage was never the absence of fear. It’s moving with it.",
    insight:{ theme:'Courage', teaching:'Courage isn’t the absence of fear — it’s leaning into the wind you were given.',
      practice:'Do one small brave thing you’ve been putting off.' },
    quiz:{ q:'What is courage, really?', options:['Never feeling afraid', 'Leaning into the wind you were given', 'Avoiding all risk'], answer:1 },
    reward:18 },

  { id:'m_space', trigger:'bossDefeated',
    title:'The Space Before the Strike',
    objective:'Face Hush, the Hollow Warden, in the sealed hollow.',
    lesson:"You didn’t flail at Hush — you waited for the slam, then struck the opening. Between what happens and what you do, there’s always a space. Your strength lives in that space.",
    insight:{ theme:'Stoicism · Response', teaching:'Between what happens to you and what you do, there is a space. Your power is there.',
      practice:'When something stings, pause one heartbeat before you answer.' },
    quiz:{ q:'Between something happening and what you do, there is…', options:['Nothing at all', 'A space where your power lives', 'Only luck'], answer:1 },
    reward:20 },

  { id:'m_control', trigger:'firstReaction',
    title:'What Answers to You',
    objective:'Master the elements — strike with one, then another, to spark a reaction.',
    lesson:"You can’t command the whole storm. But you choose which element you carry into it, and how you combine them. Spend your strength on what answers to you.",
    insight:{ theme:'Stoicism · Control', teaching:'Some things answer to you; most don’t. Spend your strength on the first, and let the rest be.',
      practice:'Name one thing you can’t control today — and loosen your grip on it.' },
    quiz:{ q:'How should you spend your strength?', options:['On the things that answer to you', 'On everything equally', 'On what others control'], answer:0 },
    reward:16 },

  { id:'m_dark', trigger:'descended',
    title:'Into the Dark',
    objective:'Forge an Iron Pick and descend the Sunken Barrow.',
    lesson:"Nobody wants to go down into the dark. But that’s where the crystal is. The hardest places are where the most precious things grow.",
    insight:{ theme:'Growth', teaching:'The precious things grow in the dark places we’d rather not go.',
      practice:'Sit with one uncomfortable feeling for a moment instead of rushing past it.' },
    quiz:{ q:'Where do the most precious things tend to grow?', options:["Only where it's easy", "In the dark places we'd rather avoid", 'Nowhere in particular'], answer:1 },
    reward:22 },

  { id:'m_wyrm', trigger:'dragonDefeated',
    title:'Meet the Wyrm',
    objective:'Face Vornrath, the Deepwyrm, at the bottom of the Delve.',
    lesson:"The Deepwyrm was never just a monster. It was every fear and grief you’d buried, grown huge in the dark. You didn’t beat it with hate — you met it fully. And look… its light drifts toward the one you’ve been seeking.",
    insight:{ theme:'Integration', teaching:'The monster is the pain we avoid. Meet it fully, and it turns back into light.',
      practice:'Name one hard thing you’ve been carrying. You just did the brave part.' },
    quiz:{ q:"What is the 'monster' usually made of?", options:['Pure evil', "The pain we've been avoiding", 'Bad luck'], answer:1 },
    reward:40 },

  { id:'m_light', trigger:'auto',
    title:'The Light Between Two',
    objective:'Understand what Mourne feared — and choose differently.',
    lesson:"Mourne wanted to freeze the world so nothing could ever be lost again. But a world that can’t change can’t grow, or love, or come home. You proved something braver: a life you can lose is still worth living — fully, with your whole heart.",
    insight:{ theme:'Meaning', teaching:'A life that can be lost is worth more than a stillness that can’t. So live it fully.',
      practice:'Tell someone today that you’re glad they’re here.' },
    quiz:{ q:"Why is a life you can lose worth more than a stillness you can't?", options:['Because it can grow, love, and change', "Because it's safer", "It isn't"], answer:0 },
    reward:60 },
];

/* ---------------------------------------------------------------- SIDE QUESTS
   Wisdom earned through play itself. Each completes on a gameplay milestone,
   files its own Insight, and must be SEALED by answering its question. */
export const SIDE_QUESTS = [
  { id:'s_craft', goal:{type:'craft',n:1}, title:'Made, Not Found',
    lesson:"You didn’t find that — you made it. Almost everything worth having gets built, a piece at a time.",
    insight:{ theme:'Creation', teaching:'Most good things are built, not stumbled upon.',
      practice:'Make or fix one small thing today instead of buying it.' },
    quiz:{ q:'Where do most good things come from?', options:['Luck','Being built piece by piece','Waiting'], answer:1 }, reward:12 },

  { id:'s_gather', goal:{type:'gather',n:50}, title:'Small Deposits',
    lesson:"Fifty little pickups. None felt like much — together they built your whole kit. That’s how real progress hides.",
    insight:{ theme:'Compounding', teaching:'Small repeated efforts quietly become something big.',
      practice:'Do one five-minute version of a goal you keep postponing.' },
    quiz:{ q:'How does real progress usually happen?', options:['One heroic burst','Small efforts repeated','All at once or never'], answer:1 }, reward:15 },

  { id:'s_build', goal:{type:'build',n:20}, title:'You Are Always Building',
    lesson:"Twenty blocks placed on purpose. You’re always building something — a habit, a friendship, a self. Better to build it deliberately.",
    insight:{ theme:'Habits', teaching:'You are always building something. Choose what, on purpose.',
      practice:'Name one habit you are building right now — and whether you chose it.' },
    quiz:{ q:'What does Emberkin say about habits?', options:['They build themselves','You are always building something — choose it','They cannot change'], answer:1 }, reward:15 },

  { id:'s_fight', goal:{type:'defeat',n:25}, title:'Steady Hands',
    lesson:"Twenty-five encounters and you kept your head. Composure isn’t being unbothered — it’s staying useful while bothered.",
    insight:{ theme:'Composure', teaching:'Composure isn’t feeling nothing — it’s staying useful while you feel it.',
      practice:'Next time you are rattled, name it and take one steady breath before acting.' },
    quiz:{ q:'What is composure?', options:['Feeling nothing','Staying useful while you feel it','Hiding your feelings'], answer:1 }, reward:18 },

  { id:'s_explore', goal:{type:'explore',n:60}, title:'Go and See',
    lesson:"You stopped guessing what was over the hill and went to look. Most fear shrinks when you actually go and see.",
    insight:{ theme:'Curiosity', teaching:'Going to see beats guessing from a distance.',
      practice:'Ask one question today instead of assuming the answer.' },
    quiz:{ q:'What beats guessing from a distance?', options:['Going to see for yourself','Assuming the worst','Asking no one'], answer:0 }, reward:14 },

  { id:'s_react', goal:{type:'react',n:8}, title:'Combinations',
    lesson:"Alone, each element is fine. Combined, they’re extraordinary. People work the same way.",
    insight:{ theme:'Collaboration', teaching:'Two ordinary things combined often beat one great thing alone.',
      practice:'Bring someone in on something you have been doing alone.' },
    quiz:{ q:'What does the reaction system teach?', options:['Work alone','Combining beats going it alone','Only power matters'], answer:1 }, reward:18 },

  { id:'s_dig', goal:{type:'dig',n:15}, title:'Turn the Soil',
    lesson:"Digging is dull right up until it isn’t. The boring stretch is usually where the treasure is buried.",
    insight:{ theme:'Persistence', teaching:'The boring stretch is usually where the reward is buried.',
      practice:'Spend ten unglamorous minutes on the thing you keep avoiding.' },
    quiz:{ q:'What is usually true of the boring stretch?', options:['It is wasted time','It is where the reward is buried','It should be skipped'], answer:1 }, reward:16 },

  { id:'s_master', goal:{type:'mastery',n:5}, title:'Depth Over Width',
    lesson:"You didn’t chase a better blade — you practised the one you had. That’s the whole secret, honestly.",
    insight:{ theme:'Deliberate Practice', teaching:'Depth in one thing beats dabbling in ten.',
      practice:'Pick one skill and give it fifteen honest minutes.' },
    quiz:{ q:'What makes you stronger in Emberkin — and in life?', options:['Finding better gear','Practising what you already hold','Doing many things at once'], answer:1 }, reward:20 },

  { id:'s_smelt', goal:{type:'smelt',n:5}, title:'Heat and Time',
    lesson:"Ore doesn’t become iron by wishing. It takes heat, and it takes time. So does a person.",
    insight:{ theme:'Transformation', teaching:'Change needs heat and time — discomfort and patience both.',
      practice:'Let one hard thing take longer than you want it to, without quitting.' },
    quiz:{ q:'What does real change require?', options:['Only willpower','Heat and time — discomfort and patience','Nothing but luck'], answer:1 }, reward:18 },

  { id:'s_heal', goal:{type:'consume',n:5}, title:'Tend Yourself',
    lesson:"You stopped to mend before pressing on. Looking after yourself isn’t quitting — it’s how you keep going.",
    insight:{ theme:'Self-Care', teaching:'Tending yourself isn’t quitting; it’s how you keep going.',
      practice:'Do one restful thing today without calling it lazy.' },
    quiz:{ q:'Taking care of yourself is…', options:['Weak','How you keep going','A waste of time'], answer:1 }, reward:14 },

  { id:'s_trap', goal:{type:'trap',n:5}, title:'Before the Storm',
    lesson:"You set those traps before you needed them. Preparing in calm is what makes chaos survivable.",
    insight:{ theme:'Foresight', teaching:'What you prepare in calm decides how you fare in chaos.',
      practice:'Do one small thing today that your future self will thank you for.' },
    quiz:{ q:'When is the best time to prepare?', options:['During the crisis','In the calm beforehand','Afterwards'], answer:1 }, reward:16 },

  { id:'s_chest', goal:{type:'chest',n:4}, title:'Curiosity Rewarded',
    lesson:"You went out of your way to look inside things. That instinct — wanting to know — is worth protecting.",
    insight:{ theme:'Wonder', teaching:'The urge to look inside things is worth protecting.',
      practice:'Follow one curiosity today with no goal attached.' },
    quiz:{ q:'What is worth protecting?', options:['Only useful knowledge','Your urge to wonder and look inside things','Being certain'], answer:1 }, reward:14 },
];

/* daily goals: {type, n, item?}  types: gather, defeat, explore, craft, react, element, build */
export const DAILY_POOL = [
  { id:'d_gather', title:'Gather 12 materials', goal:{type:'gather', n:12},
    practice:'Do one small useful thing before you rest today.', reward:15 },
  { id:'d_timber', title:'Gather 10 Timber', goal:{type:'gather', item:'timber', n:10},
    practice:'Tend one small thing that’s still growing.', reward:12 },
  { id:'d_defeat', title:'Defeat 6 Stonekin', goal:{type:'defeat', n:6},
    practice:'When frustration rises, take one breath before you act.', reward:15 },
  { id:'d_explore', title:'Discover 12 new places', goal:{type:'explore', n:12},
    practice:'Look up once today and notice something you’ve never seen.', reward:12 },
  { id:'d_craft', title:'Craft 3 things', goal:{type:'craft', n:3},
    practice:'Finish one thing you already started.', reward:15 },
  { id:'d_react', title:'Spark 3 elemental reactions', goal:{type:'react', n:3},
    practice:'Two small kindnesses can combine into something bigger — thank someone.', reward:18 },
  { id:'d_element', title:'Switch elements 5 times', goal:{type:'element', n:5},
    practice:'Name three feelings you noticed in yourself today.', reward:12 },
];

/* weekly goals add 'defeatBoss' and 'descend' types; reward is bigger, plus optional item */
export const WEEKLY_POOL = [
  { id:'w_boss', title:'Best a great foe (Hush or the Deepwyrm)', goal:{type:'defeatBoss', n:1},
    practice:'This week: name one thing you can control and one you can’t. Spend your energy on the first.',
    reward:60, item:'wardcharm' },
  { id:'w_ore', title:'Mine 20 ore', goal:{type:'gather', item:['iron_ore','gold_ore','crystal_ore'], n:20},
    practice:'This week: patience turns hard rock into treasure. Where can you be more patient?', reward:50 },
  { id:'w_build', title:'Place 30 blocks', goal:{type:'build', n:30},
    practice:'This week: you’re always building something — a habit, a friendship. Build one on purpose.', reward:45 },
  { id:'w_delve', title:'Descend the Delve and return', goal:{type:'descend', n:1},
    practice:'This week: the brave visit their dark places, and come back a little wiser.', reward:55 },
];

/* Wayfarer rank — the "from lost to wise" meter, by Insights collected (0–10). */
/* 22 sealed insights total (10 story + 12 side) */
export const WAYFARER_RANKS = [
  { at:0, name:'Lost Traveller' }, { at:1, name:'Seeker' }, { at:4, name:'Wanderer' },
  { at:8, name:'Steady' }, { at:12, name:'Kindled' }, { at:16, name:'Sage' },
  { at:20, name:'Lightbearer' }, { at:22, name:'Keeper of the Ember' },
];
export function wayfarerRank(n){
  let r = WAYFARER_RANKS[0];
  for (const w of WAYFARER_RANKS) if (n >= w.at) r = w;
  return r.name;
}
