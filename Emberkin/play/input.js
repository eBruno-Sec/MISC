/* ============================================================================
   EMBERKIN — input map (Phase A core framework)
   One table owns every binding so systems ask for ACTIONS, never raw keys.
   Rebinding later (settings UI, gamepad) only touches this module.
   ========================================================================== */

export const DEFAULT_BINDS = {
  'w':'move_fwd',  's':'move_back',  'a':'move_left',  'd':'move_right',
  ' ':'jump',      'shift':'sprint',
  'e':'interact',  'f':'mimic',      'j':'attack',
  'q':'cycle_element',
  'i':'inventory', 'tab':'inventory','m':'map','l':'log',
  'escape':'pause',
  '1':'slot1','2':'slot2','3':'slot3','4':'slot4','5':'slot5',
  '6':'slot6','7':'slot7','8':'slot8','9':'slot9','0':'slot10',
};

export function makeInput(binds = { ...DEFAULT_BINDS }){
  const reverse = {};                       // action -> key (first bound)
  for (const [k,a] of Object.entries(binds)) if (!(a in reverse)) reverse[a] = k;
  return {
    actionFor(key){ return binds[key] || null; },
    keyFor(action){ return reverse[action] || null; },
    rebind(key, action){
      for (const k of Object.keys(binds)) if (binds[k] === action) delete binds[k];
      binds[key] = action;
      reverse[action] = key;
    },
    slotIndex(action){
      const m = /^slot(\d+)$/.exec(action || '');
      return m ? parseInt(m[1], 10) - 1 : -1;   // slot1 -> 0 … slot10 -> 9
    },
  };
}
