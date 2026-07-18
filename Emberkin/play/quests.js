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
    reward:10 },

  { id:'m_name', trigger:'firstElement',
    title:'Name the Flame',
    objective:'Climb to the Wardstone and attune your first element (press E). Then switch elements with Q and E, and attack (click / J) to fight.',
    lesson:"Feel how the element settled once you touched it? Feelings work the same way — wild and huge until you name them. Named, they’re something you can carry, even use.",
    insight:{ theme:'Emotional Intelligence', teaching:'A feeling you can name is a feeling you can carry.',
      practice:'When a big feeling comes, say it out loud: “I feel ___.”' },
    reward:12 },

  { id:'m_wall', trigger:'iceMelted',
    title:'The Warm Way Through',
    objective:'A wall of Rime blocks the road north. Find the way through.',
    lesson:"You didn’t smash that wall — you brought the right warmth. Some walls never move by force. They melt with patience and the right approach.",
    insight:{ theme:'Problem-Solving', teaching:'Not every wall breaks by force; some melt with patience and the right warmth.',
      practice:'With one stuck problem, ask: “what’s the gentler way in?”' },
    reward:14 },

  { id:'m_watch', trigger:'campPassed',
    title:'Walk Softly',
    objective:'Slip through the Stonekin camp unseen.',
    lesson:"Did you feel it? You watched first — learned their pattern before you moved. Reading the room before you step into it is a quiet kind of strength.",
    insight:{ theme:'Situational Awareness', teaching:'The wise watch first. Understand the pattern before you act.',
      practice:'Before reacting today, take one breath and notice what’s really happening.' },
    reward:16 },

  { id:'m_space', trigger:'bossDefeated',
    title:'The Space Before the Strike',
    objective:'Face Hush, the Hollow Warden, in the sealed hollow.',
    lesson:"You didn’t flail at Hush — you waited for the slam, then struck the opening. Between what happens and what you do, there’s always a space. Your strength lives in that space.",
    insight:{ theme:'Stoicism · Response', teaching:'Between what happens to you and what you do, there is a space. Your power is there.',
      practice:'When something stings, pause one heartbeat before you answer.' },
    reward:20 },

  { id:'m_control', trigger:'firstReaction',
    title:'What Answers to You',
    objective:'Master the elements — strike with one, then another, to spark a reaction.',
    lesson:"You can’t command the whole storm. But you choose which element you carry into it, and how you combine them. Spend your strength on what answers to you.",
    insight:{ theme:'Stoicism · Control', teaching:'Some things answer to you; most don’t. Spend your strength on the first, and let the rest be.',
      practice:'Name one thing you can’t control today — and loosen your grip on it.' },
    reward:16 },

  { id:'m_wind', trigger:'trialPassed',
    title:'Lean Into the Wind',
    objective:'Earn the Windrider’s Mark from Skywright Pell.',
    lesson:"You were scared to fall. Then you leaned INTO the wind instead of fighting it — and you flew. Courage was never the absence of fear. It’s moving with it.",
    insight:{ theme:'Courage', teaching:'Courage isn’t the absence of fear — it’s leaning into the wind you were given.',
      practice:'Do one small brave thing you’ve been putting off.' },
    reward:18 },

  { id:'m_dark', trigger:'descended',
    title:'Into the Dark',
    objective:'Forge an Iron Pick and descend the Sunken Barrow.',
    lesson:"Nobody wants to go down into the dark. But that’s where the crystal is. The hardest places are where the most precious things grow.",
    insight:{ theme:'Growth', teaching:'The precious things grow in the dark places we’d rather not go.',
      practice:'Sit with one uncomfortable feeling for a moment instead of rushing past it.' },
    reward:22 },

  { id:'m_wyrm', trigger:'dragonDefeated',
    title:'Meet the Wyrm',
    objective:'Face Vornrath, the Deepwyrm, at the bottom of the Delve.',
    lesson:"The Deepwyrm was never just a monster. It was every fear and grief you’d buried, grown huge in the dark. You didn’t beat it with hate — you met it fully. And look… its light drifts toward the one you’ve been seeking.",
    insight:{ theme:'Integration', teaching:'The monster is the pain we avoid. Meet it fully, and it turns back into light.',
      practice:'Name one hard thing you’ve been carrying. You just did the brave part.' },
    reward:40 },

  { id:'m_light', trigger:'auto',
    title:'The Light Between Two',
    objective:'Understand what Mourne feared — and choose differently.',
    lesson:"Mourne wanted to freeze the world so nothing could ever be lost again. But a world that can’t change can’t grow, or love, or come home. You proved something braver: a life you can lose is still worth living — fully, with your whole heart.",
    insight:{ theme:'Meaning', teaching:'A life that can be lost is worth more than a stillness that can’t. So live it fully.',
      practice:'Tell someone today that you’re glad they’re here.' },
    reward:60 },
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
export const WAYFARER_RANKS = [
  { at:0, name:'Lost Traveller' }, { at:1, name:'Seeker' }, { at:3, name:'Wanderer' },
  { at:5, name:'Steady' }, { at:7, name:'Kindled' }, { at:9, name:'Sage' }, { at:10, name:'Lightbearer' },
];
export function wayfarerRank(n){
  let r = WAYFARER_RANKS[0];
  for (const w of WAYFARER_RANKS) if (n >= w.at) r = w;
  return r.name;
}
