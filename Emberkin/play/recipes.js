/* ============================================================================
   EMBERKIN — crafting recipes (Phase E). Pure data; item ids must exist in
   items.js. `station:'forge'` recipes require standing near a placed Forge.
   `unlock` gates a recipe behind a game flag (e.g. the dragon endgame). ======*/
export const RECIPES = [
  // --- tools & stations (basic) ---
  { id:'r_pick_stone', out:{id:'pick_stone',n:1}, in:[{id:'stone_chunk',n:3},{id:'timber',n:2}] },
  { id:'r_axe_stone',  out:{id:'axe_stone', n:1}, in:[{id:'stone_chunk',n:3},{id:'timber',n:2}] },
  { id:'r_forge',      out:{id:'block_forge',n:1}, in:[{id:'stone_chunk',n:8}] },

  // --- building blocks (basic) ---
  { id:'r_block_dirt',  out:{id:'block_dirt', n:4}, in:[{id:'dirt_clod',n:2}] },
  { id:'r_block_stone', out:{id:'block_stone',n:4}, in:[{id:'stone_chunk',n:2}] },
  { id:'r_block_plank', out:{id:'block_plank',n:4}, in:[{id:'timber',n:1}] },
  { id:'r_block_wall',  out:{id:'block_wall', n:2}, in:[{id:'stone_chunk',n:3}] },

  // --- traps (basic) ---
  { id:'r_trap_spike',  out:{id:'trap_spike',n:2}, in:[{id:'stone_chunk',n:2},{id:'timber',n:1}] },
  { id:'r_trap_frost',  out:{id:'trap_frost',n:2}, in:[{id:'stone_chunk',n:2},{id:'crystal_ore',n:1}], element:'rime' },
  { id:'r_trap_ember',  out:{id:'trap_ember',n:2}, in:[{id:'stone_chunk',n:2},{id:'iron_ore',n:1}],  element:'cinder' },

  // --- consumables ---
  { id:'r_emberjam',    out:{id:'emberjam',n:1},   in:[{id:'riverbud',n:3}] },

  // --- forge: smelting & iron gear ---
  { id:'r_iron_ingot',  out:{id:'iron_ingot',n:1}, in:[{id:'iron_ore',n:2}], station:'forge' },
  { id:'r_gold_ingot',  out:{id:'gold_ingot',n:1}, in:[{id:'gold_ore',n:2}], station:'forge' },
  { id:'r_pick_iron',   out:{id:'pick_iron',n:1},  in:[{id:'iron_ingot',n:3},{id:'timber',n:2}], station:'forge' },
  { id:'r_axe_iron',    out:{id:'axe_iron',n:1},   in:[{id:'iron_ingot',n:3},{id:'timber',n:2}], station:'forge' },
  { id:'r_wardcharm',   out:{id:'wardcharm',n:1},  in:[{id:'iron_ingot',n:3},{id:'crystal_ore',n:2}], station:'forge' },

  // --- endgame (unlocked by defeating the dragon) ---
  { id:'r_starcore',    out:{id:'gold_ingot',n:6}, in:[{id:'crystal_ore',n:1}], station:'forge', unlock:'dragonDefeated',
    label:'Wellspring Transmute — Crystal → 6 Gold' },
];
