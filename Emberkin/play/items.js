/* ============================================================================
   EMBERKIN — item registry (Phase A core framework)
   Pure data module: no imports, no DOM, no game-state. Every inventory,
   crafting, gathering, and building system reads item truth from here.
   ========================================================================== */

export const STACK_DEFAULT = 99;

/* type: material | consumable | tool | block | element
   Elements are hotbar-assignable pseudo-items (the attunements themselves
   live in game state); sigil/colour must match the game's ELEMENTS table. */
export const ITEMS = {
  /* -------- gathered materials (Phase C) -------- */
  timber:       { name:'Timber',        icon:'🪵', stack:99, type:'material', desc:'Cut from vale trees.' },
  stone_chunk:  { name:'Stone Chunk',   icon:'🪨', stack:99, type:'material', desc:'Broken from rock and crag.' },
  dirt_clod:    { name:'Dirt Clod',     icon:'🟤', stack:99, type:'material', desc:'Plain honest earth.' },
  sand_pile:    { name:'Sand',          icon:'🟡', stack:99, type:'material', desc:'Fine shore sand.' },
  clay_lump:    { name:'Clay',          icon:'🧱', stack:99, type:'material', desc:'Riverbank clay, good for firing.' },
  iron_ore:     { name:'Iron Ore',      icon:'⛓', stack:99, type:'material', desc:'Dull-veined stone. Smelts to iron.' },
  gold_ore:     { name:'Gold Ore',      icon:'🪙', stack:99, type:'material', desc:'A warm gleam in the rock.' },
  crystal_ore:  { name:'Crystal Ore',   icon:'💎', stack:99, type:'material', desc:'Hums faintly with Wellspring light.' },
  iron_ingot:   { name:'Iron Ingot',    icon:'🔩', stack:99, type:'material', desc:'Forge-refined iron.' },
  gold_ingot:   { name:'Gold Ingot',    icon:'🥇', stack:99, type:'material', desc:'Forge-refined gold.' },
  riverbud:     { name:'Riverbud',      icon:'🌼', stack:99, type:'material', desc:'A bright lakeside bloom.' },

  /* -------- consumables -------- */
  emberjam:     { name:'Emberjam',      icon:'🍯', stack:20, type:'consumable', heal:35,
                  desc:'Warm, sweet, restorative. Heals 35.' },

  /* -------- tools (Phase C/E — tiers gate gathering speed) -------- */
  pick_stone:   { name:'Stone Pick',    icon:'⛏', stack:1, type:'tool', tool:'pick', tier:1, desc:'Breaks soft stone and ore.' },
  pick_iron:    { name:'Iron Pick',     icon:'⛏', stack:1, type:'tool', tool:'pick', tier:2, desc:'Bites into hard rock.' },
  axe_stone:    { name:'Stone Axe',     icon:'🪓', stack:1, type:'tool', tool:'axe',  tier:1, desc:'Fells vale trees.' },
  axe_iron:     { name:'Iron Axe',      icon:'🪓', stack:1, type:'tool', tool:'axe',  tier:2, desc:'Fells anything with bark.' },

  /* -------- placeable blocks (Phase D/F) -------- */
  block_dirt:   { name:'Dirt Block',    icon:'🟫', stack:99, type:'block', hardness:1, desc:'Placeable earth.' },
  block_stone:  { name:'Stone Block',   icon:'⬜', stack:99, type:'block', hardness:3, desc:'Placeable stone.' },
  block_plank:  { name:'Plank Block',   icon:'🟧', stack:99, type:'block', hardness:2, desc:'Worked timber.' },

  /* -------- elements as hotbar entries (attunement checked by the game) -------- */
  elem_loam:    { name:'Loam',   icon:'⬡', stack:1, type:'element', elem:'loam' },
  elem_tide:    { name:'Tide',   icon:'≈', stack:1, type:'element', elem:'tide' },
  elem_cinder:  { name:'Cinder', icon:'✷', stack:1, type:'element', elem:'cinder' },
  elem_arc:     { name:'Arc',    icon:'ϟ', stack:1, type:'element', elem:'arc' },
  elem_rime:    { name:'Rime',   icon:'❈', stack:1, type:'element', elem:'rime' },
};

/* hasOwnProperty guard: a plain ITEMS[id] lookup would treat '__proto__' or
   'constructor' as valid ids (they resolve to Object.prototype members). */
const has = (id)=> typeof id === 'string' && Object.prototype.hasOwnProperty.call(ITEMS, id);
export function itemDef(id){ return has(id) ? ITEMS[id] : null; }
export function isValidItemId(id){ return has(id); }
export function stackLimit(id){ return has(id) ? (ITEMS[id].stack ?? STACK_DEFAULT) : 0; }
