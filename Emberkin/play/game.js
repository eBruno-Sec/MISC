/* ============================================================================
   EMBERKIN — A Light Between Two
   Fully-3D third-person vertical slice. Core three.js only (no addons).
   All proper nouns are original to this project. Family-friendly, accessible.
   ========================================================================== */
import * as THREE from 'three';
import { ITEMS, itemDef, isValidItemId, stackLimit } from './items.js';
import { makeInput } from './input.js';
import { RECIPES } from './recipes.js';
import { MAIN_QUESTS, SIDE_QUESTS, DAILY_POOL, WEEKLY_POOL, wayfarerRank } from './quests.js';

/* ------------------------------------------------------------------ consts */
const SCHEMA_VERSION = 6;          // v6: sealed insights + side quests; v1–v5 migrate
const PRODUCT_VERSION = '0.5.0-slice';
const INPUT = makeInput();
const SAVE_KEY = 'emberkin.save.v1';
const SETTINGS_KEY = 'emberkin.settings.v1';

const CLASSES = {
  sword:      { name:'Sword',        weapon:'Vale Blade',  range:2.6, arc:1.3, dmg:26, speed:0.42, ranged:false,
    desc:'Balanced close range. Reliable damage, versatile combos, and parry potential. A dependable first path.',
    stats:{Power:3,Speed:3,Range:2,Defense:3}, complexity:'Complexity: Low — a friendly place to start.' },
  bow:        { name:'Bow',          weapon:'Reed Bow',    range:40, arc:0.5, dmg:22, speed:0.5,  ranged:true,
    desc:'Ranged precision. Charged shots, weak-point hits, and long-range puzzle solving. Weaker up close.',
    stats:{Power:3,Speed:3,Range:5,Defense:1}, complexity:'Complexity: Medium — rewards good aim.' },
  greatsword: { name:'Greatsword',   weapon:'Cragcleaver', range:3.0, arc:1.7, dmg:46, speed:0.85, ranged:false,
    desc:'Slow, heavy, and huge. High stagger and impact, and the only thing that shatters weak stone.',
    stats:{Power:5,Speed:1,Range:3,Defense:2}, complexity:'Complexity: Medium — timing over speed.' },
  dual:       { name:'Dual Swords',  weapon:'Twin Fangs',  range:2.3, arc:1.4, dmg:15, speed:0.24, ranged:false,
    desc:'Fast combo chains and high mobility. Quick elemental build-up, evasion focus, lower damage per hit.',
    stats:{Power:2,Speed:5,Range:2,Defense:2}, complexity:'Complexity: Medium — fast and fluid.' },
  focus:      { name:'Psychic Focus',weapon:'Wander Rune', range:14, arc:0.9, dmg:20, speed:0.55, ranged:true,
    desc:'A floating rune. Telekinetic pushes, shields, and moving ancient mechanisms. Control over brute force.',
    stats:{Power:3,Speed:2,Range:4,Defense:3}, complexity:'Complexity: High — a thinker’s path.' },
};

/* Weapon tiers per class. Players only ever find weapons of their own class. */
/* Every weapon is unique grade — equal in worth, different in FEEL. Faster
   weapons hit lighter and slower ones hit harder, so damage-per-second stays
   comparable and the choice is about style, never strength.
   mods: dmg (per-hit ×), cd (seconds between swings), arc/reach (×), crit (+),
   perk (a signature trait). */
const WEAPONS = {
  sword: [
    {id:'sw1',name:'Vale Blade',  dmg:1.00,cd:0.28,arc:1.15,reach:1.00,crit:0,    perk:null,       blurb:'Forgiving — a wider, more generous swing arc.'},
    {id:'sw2',name:'Bramblefang', dmg:0.85,cd:0.20,arc:0.95,reach:0.85,crit:0,    perk:'comboUp',  blurb:'Swift — quick strikes, shorter reach, combo builds fast.'},
    {id:'sw3',name:'Dawnedge',    dmg:1.10,cd:0.32,arc:1.00,reach:1.30,crit:0.10, perk:null,       blurb:'Keen — long reach and a far higher crit chance.'},
  ],
  bow: [
    {id:'bw1',name:'Reed Bow',    dmg:0.85,cd:0.22,arc:1.00,reach:1.00,crit:0,    perk:null,       blurb:'Quick draw — rapid, lighter shots.'},
    {id:'bw2',name:'Galewhisper', dmg:1.00,cd:0.30,arc:1.00,reach:1.00,crit:0,    perk:'pierce',   blurb:'Piercing — arrows carry on through a second foe.'},
    {id:'bw3',name:'Sunstring',   dmg:1.35,cd:0.45,arc:1.00,reach:1.00,crit:0.05, perk:null,       blurb:'Heavy draw — slow, powerful shots.'},
  ],
  greatsword: [
    {id:'gs1',name:'Cragcleaver', dmg:1.00,cd:0.42,arc:1.00,reach:1.00,crit:0,    perk:'stagger',  blurb:'Crushing — sends foes reeling backward.'},
    {id:'gs2',name:'Bouldersong', dmg:0.90,cd:0.40,arc:1.55,reach:1.10,crit:0,    perk:null,       blurb:'Sweeping — carves a far wider arc through crowds.'},
    {id:'gs3',name:'Titanroot',   dmg:1.10,cd:0.45,arc:1.00,reach:1.00,crit:0,    perk:'stonebane',blurb:'Stonebane — devastating against the heavy Stonekin.'},
  ],
  dual: [
    {id:'du1',name:'Twin Fangs',  dmg:0.80,cd:0.18,arc:1.00,reach:0.95,crit:0,    perk:'comboUp',  blurb:'Relentless — the fastest strikes; combo builds double.'},
    {id:'du2',name:'Skydancers',  dmg:0.90,cd:0.22,arc:1.05,reach:1.00,crit:0.05, perk:'dash',     blurb:'Windborne — longer dash, nimble footwork.'},
    {id:'du3',name:'Emberfangs',  dmg:0.95,cd:0.24,arc:1.00,reach:1.00,crit:0,    perk:'elemental',blurb:'Emberbound — elemental reactions hit far harder.'},
  ],
  focus: [
    {id:'fo1',name:'Wander Rune', dmg:0.85,cd:0.24,arc:1.00,reach:1.00,crit:0,    perk:null,       blurb:'Swift bolts — light, rapid casts.'},
    {id:'fo2',name:'Lumen Coil',  dmg:0.95,cd:0.32,arc:1.00,reach:1.00,crit:0,    perk:'chain',    blurb:'Chaining — its light arcs on to a nearby foe.'},
    {id:'fo3',name:'Starheart',   dmg:1.35,cd:0.48,arc:1.00,reach:1.00,crit:0.05, perk:null,       blurb:'Starfall — slow, heavy, brilliant impact.'},
  ],
};
const WMOD_DEFAULT = { dmg:1, cd:0.28, arc:1, reach:1, crit:0, perk:null, blurb:'' };
function weaponMods(id){ return { ...WMOD_DEFAULT, ...(findWeapon(id) || {}) }; }
function equippedMods(){ return weaponMods(G.equipped); }
function hasPerk(p){ return equippedMods().perk === p; }
/* TIER_MULT removed in v5 — weapons no longer have power tiers (see mastery) */
/* Elemental variant counters: attack with the counter element for bonus damage.
   A variant resists its own element. Loam variants only resist Loam. */
const COUNTER = { cinder:'rime', rime:'cinder', arc:'tide', tide:'arc' };

const ELEMENTS = {
  loam:  { name:'Loam',  color:0xd9a24a, sigil:'⬡' },
  tide:  { name:'Tide',  color:0x41b6c4, sigil:'≈' },
  cinder:{ name:'Cinder',color:0xf0713b, sigil:'✷' },
  arc:   { name:'Arc',   color:0xb48bf0, sigil:'ϟ' },
  rime:  { name:'Rime',  color:0x8fd7f0, sigil:'❈' },
};

/* ------------------------------------------------------------------- state */
const G = {
  phase: 'loading',           // loading|title|sibling|class|cinematic|playing|paused|settings
  sibling: null,              // 'wren' | 'cael'
  klass: null,                // key of CLASSES
  hp: 100, maxHp: 100,
  stamina: 100, maxStam: 100,
  tokens: 0,
  weaponLevel: 1,             // legacy; migrated into mastery
  mastery: { sword:1, bow:1, greatsword:1, dual:1, focus:1 },
  owned: [], equipped: null,
  bag: [],                       // stackable items: [{id, n}]
  hotbar: new Array(10).fill(null),   // slots: null | {kind:'item'|'weapon'|'element', id}
  chests: {},
  mechs: { loam:false, tide:false, arc:false, rime:false },
  bossDefeated: false,
  build: [],                  // placed blocks: [{t, gx, gy, gz, trap}]
  underground: false,
  dragonDefeated: false,
  hardMode: false,
  critBonus: 0,               // Phase G upgrades
  combo: 0, comboT: 0,
  // quests & journal
  quest: { main:0, mainDone:[], insights:[], sealed:[], side:[], daily:[], weekly:[], dailyDate:'', weeklyKey:'' },
  elements: { loam:false, tide:false, cinder:false, arc:false, rime:false },
  activeElement: 'none',
  glideUnlocked: false,
  stage: 0,                   // quest progression index
  flags: { fished:false, firstKill:false, transformedOnce:false, campPassed:false, trialPassed:false, iceMelted:false },
  // mimic state machine
  mimic: { state:'Normal', hp:0, maxHp:0, orbHeld:false, cooldown:0, savedHp:100 },
};

const settings = {
  theme:'night', contrast:false, motion:false, ui:false,
  cam:1, invert:false, aim:true, vol:0.6,
  shoulder:'right',   // over-the-shoulder camera bias: right | left | center
};

/* --------------------------------------------------------------------- DOM */
const $ = (id) => document.getElementById(id);
const dom = {};
['loading','load-status','load-fill','load-fallback','hud','hero-name','hp-fill','hp-text',
 'mimic-bar-wrap','mimic-fill','mimic-text','stam-fill','token-count','net-state',
 'prompt','prompt-key','prompt-text','orb-status','weapon-chip','weapon-name','weapon-lvl',
 'objective-text','alert-state','alert-text','tainer','tainer-text','toast',
 'menu-title','menu-sibling','menu-class','cinematic','cine-art','cine-text','cine-next','cine-skip',
 'menu-pause','menu-settings','class-preview','class-title','class-weapon','class-desc','class-stats',
 'class-complexity','btn-confirm-class','file-input',
 'btn-new','btn-continue','btn-load','btn-settings-title','btn-resume','btn-settings-pause','btn-save',
 'btn-load-pause','btn-quit','btn-settings-back',
 'set-theme','set-contrast','set-motion','set-ui','set-cam','set-invert','set-aim','set-vol','set-shoulder','set-hard','set-hard-row',
 'boss-bar','boss-fill','menu-inv','inv-list','inv-tokens','btn-inv','btn-inv-back',
 'reticle','aim-dot','hotbar','inv-hotbar','bag-grid','elem-row','inv-hint','btn-sort',
 'elem-hud','elem-hud-sig','elem-hud-name','floaters','craft-list','craft-search','combo','combo-n',
 'minimap','menu-map','worldmap','map-title','btn-map-close','tracker',
 'touch-ui','tc-stick','tc-knob','tc-attack','tc-jump','tc-dash','tc-interact','tc-mimic','tc-elemL','tc-elemR','tc-map','tc-journal','tc-menu',
 'menu-journal','journal-rank','jtabs','jbody','btn-journal','btn-journal-close','mastery-list',
 'menu-reflect','reflect-kicker','reflect-title','reflect-lesson','reflect-theme','reflect-teaching','reflect-practice',
 'reflect-readbox','btn-reflect-read','btn-reflect-later','btn-reflect-later2','reflect-quizbox','reflect-q','reflect-opts','reflect-feedback'
].forEach(id => dom[id] = $(id));

/* ================================================================== AUDIO
   Fully synthesized with WebAudio — no asset files. Master volume follows the
   settings slider. The context can only start after a user gesture. */
let AC = null, master = null;
function initAudio(){
  if (AC) return;
  try { AC = new (window.AudioContext || window.webkitAudioContext)(); } catch(e){ return; }
  master = AC.createGain();
  master.gain.value = settings.vol * 0.5;
  master.connect(AC.destination);
  // soft wind bed: looped filtered noise, very quiet
  const buf = AC.createBuffer(1, AC.sampleRate * 2, AC.sampleRate);
  const d = buf.getChannelData(0);
  for (let i=0;i<d.length;i++) d[i] = Math.random()*2-1;
  const wind = AC.createBufferSource(); wind.buffer = buf; wind.loop = true;
  const lp = AC.createBiquadFilter(); lp.type='lowpass'; lp.frequency.value = 320;
  const wg = AC.createGain(); wg.gain.value = 0.05;
  wind.connect(lp); lp.connect(wg); wg.connect(master); wind.start();
  scheduleBird();
  startMusic();
}
/* gentle generative score: a slow I-vi-V-ii pad with a wandering pentatonic
   melody on top. Only plays in-game; volumes sit under the sound effects. */
const MUSIC_SCALE = [262, 294, 330, 392, 440, 523, 587, 659];
let musicOn = false;
function startMusic(){
  if (musicOn || !AC) return;
  musicOn = true;
  let step = 0;
  const bar = ()=>{
    if (G.phase === 'playing'){
      const root = MUSIC_SCALE[[0,5,4,1][Math.floor(step/4)%4]] / 2;
      tone(root,     2.6, {type:'sine', vol:0.035});
      tone(root*1.5, 2.6, {type:'sine', vol:0.02, delay:0.05});
      const mel = MUSIC_SCALE[(step*3 + step%5) % MUSIC_SCALE.length];
      tone(mel, 0.9, {type:'triangle', vol:0.028, delay:0.3 + Math.random()*0.4});
      step++;
    }
    setTimeout(bar, 2400);
  };
  bar();
}
function setMasterVol(){ if (master) master.gain.value = settings.vol * 0.5; }
function tone(freq, dur, {type='sine', vol=0.2, slide=null, delay=0}={}){
  if (!AC) return;
  const t0 = AC.currentTime + delay;
  const o = AC.createOscillator(); o.type = type;
  o.frequency.setValueAtTime(freq, t0);
  if (slide) o.frequency.exponentialRampToValueAtTime(Math.max(20, slide), t0+dur);
  const g = AC.createGain();
  g.gain.setValueAtTime(vol, t0);
  g.gain.exponentialRampToValueAtTime(0.001, t0+dur);
  o.connect(g); g.connect(master);
  o.start(t0); o.stop(t0+dur+0.02);
}
function noiseBurst(dur, {freq=1200, vol=0.25, delay=0}={}){
  if (!AC) return;
  const t0 = AC.currentTime + delay;
  const b = AC.createBuffer(1, Math.max(1, AC.sampleRate*dur), AC.sampleRate);
  const dd = b.getChannelData(0);
  for (let i=0;i<dd.length;i++) dd[i] = Math.random()*2-1;
  const n = AC.createBufferSource(); n.buffer = b;
  const f = AC.createBiquadFilter(); f.type='bandpass'; f.frequency.value=freq; f.Q.value=0.8;
  const g = AC.createGain();
  g.gain.setValueAtTime(vol, t0);
  g.gain.exponentialRampToValueAtTime(0.001, t0+dur);
  n.connect(f); f.connect(g); g.connect(master); n.start(t0);
}
function scheduleBird(){
  if (!AC) return;
  setTimeout(()=>{
    if (G.phase==='playing'){
      const f = 1400 + Math.random()*800;
      tone(f, 0.12, {vol:0.05, slide:f*1.5});
      tone(f*1.2, 0.1, {vol:0.04, slide:f*0.9, delay:0.15});
    }
    scheduleBird();
  }, 5000 + Math.random()*9000);
}
const sfx = {
  ui:       ()=> tone(660, 0.05, {type:'triangle', vol:0.07}),
  swing:    ()=> noiseBurst(0.12, {freq:900, vol:0.12}),
  hit:      ()=>{ tone(130, 0.09, {vol:0.3, slide:60}); noiseBurst(0.05, {freq:2400, vol:0.1}); },
  dissolve: ()=> [523,659,784].forEach((f,i)=> tone(f, 0.5, {vol:0.06, delay:i*0.06})),
  token:    ()=> tone(880, 0.09, {type:'square', vol:0.05, slide:1320}),
  orb:      ()=> [392,494,587,740].forEach((f,i)=> tone(f, 0.2, {type:'triangle', vol:0.08, delay:i*0.07})),
  transform:()=> noiseBurst(0.5, {freq:600, vol:0.2}),
  eject:    ()=>{ noiseBurst(0.3, {freq:1400, vol:0.15}); tone(740, 0.25, {vol:0.08, slide:370}); },
  attune:   ()=> [330,415,494,659].forEach((f,i)=> tone(f, 0.6, {vol:0.07, delay:i*0.05})),
  hurt:     ()=> tone(220, 0.15, {type:'sawtooth', vol:0.1, slide:110}),
  step:     ()=> noiseBurst(0.06, {freq:340, vol:0.04}),
};

/* ============================================================ THREE.JS CORE */
let renderer, scene, camera, clock;
let player, playerParts, tainerMesh, mimicMesh;
const enemies = [];
const orbs = [];
const wardstones = [];
const interactables = [];   // {pos, radius, label, key, onUse, cond}
const windZones = [];
const hoops = [];
const projectiles = [];
const enemyShots = [];      // boss/dragon projectiles aimed at the player
const particles = [];       // dissolve/vfx groups {mesh, life, max, vel[]}
let iceWall = null, campGoal = null, pellPos = null, lakePos = null;
const mechanisms = [];      // {id, elem, pos, r, done, apply(withVfx)}
const platforms = [];       // walkable tops: {x, z, hw, hd, topY}
let bossRef = null, bossChestSpawned = false;
let lakeFrozen = false;
let motes = null;           // drifting ambient light specks
const DEEP_WATER_R = 8.4;   // unswimmable centre of the lake until frozen
const harvestables = [];    // {mesh, kind, ore, hp, maxHp, drop, respawnAt, base}
const drops = [];           // {mesh, id, n, life, vy}  dropped items that magnet to the player
const placed = [];          // {key, type, mesh, hp, gx,gy,gz, trap}  player-placed blocks
const placedMap = new Map();// "gx,gy,gz" -> placed entry
const floaters = [];        // {el, pos, vy, life, max}  world-anchored damage/loot text
const POIS = [];            // {x,z,kind,name}  points of interest for the minimap (Phase H)
let activeSlot = 0;         // currently highlighted hotbar slot
const world = new THREE.Group();

let ok3d = true;

function initThree() {
  const canvas = dom_scene();
  try {
    renderer = new THREE.WebGLRenderer({ canvas, antialias:true, powerPreference:'high-performance' });
  } catch (e) { ok3d = false; return false; }
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  renderer.setSize(innerWidth, innerHeight);
  renderer.shadowMap.enabled = true;
  renderer.shadowMap.type = THREE.PCFSoftShadowMap;

  scene = new THREE.Scene();
  scene.background = new THREE.Color(0x9fd0e8);
  scene.fog = new THREE.Fog(0x9fd0e8, 60, 220);

  camera = new THREE.PerspectiveCamera(60, innerWidth/innerHeight, 0.1, 600);
  camera.position.set(0, 6, 10);

  clock = new THREE.Clock();
  addEventListener('resize', onResize);
  return true;
}
function dom_scene(){ return document.getElementById('scene'); }
function onResize(){ if(!renderer) return; camera.aspect = innerWidth/innerHeight; camera.updateProjectionMatrix(); renderer.setSize(innerWidth, innerHeight); }

/* ------------------------------------------------------------------ lights */
function buildLights() {
  const hemi = new THREE.HemisphereLight(0xdfefff, 0x556b3f, 0.9);
  scene.add(hemi);
  const sun = new THREE.DirectionalLight(0xfff2d6, 1.15);
  sun.position.set(40, 70, 20);
  sun.castShadow = true;
  sun.shadow.mapSize.set(2048, 2048);
  const s = 90; const c = sun.shadow.camera;
  c.left=-s;c.right=s;c.top=s;c.bottom=-s;c.near=1;c.far=250; c.updateProjectionMatrix();
  scene.add(sun);
  scene.add(new THREE.AmbientLight(0xffffff, 0.15));
}

/* ------------------------------------------------------------------ terrain
   Rolling hills from layered sines, flattened around every gameplay site so
   quests, camps, mechanisms, and arenas sit on level ground. terrainH(x,z) is
   the single source of truth for ground height — mesh, physics, AI, camera. */
const FLAT_ZONES = [];
function initFlatZones(){
  FLAT_ZONES.length = 0;
  const add = (x,z,r)=> FLAT_ZONES.push({x,z,r});
  add(-22,14,17);                                   // lake, shore, spawn, rime mech
  add(6,-6,10); add(14,-16,10);                     // first wardstone, ice wall
  add(26,-46,18); add(26,-70,12);                   // camp + goal
  add(26,-92,20); add(26,-78,10);                   // boss arena + gate
  add(-4,40,12); add(-4,58,10); add(-4,70,10); add(-2,82,10);   // Pell + trial corridor
  add(58,44,13); add(-48,-42,13);                   // basin, loam site
  add(34,-30,12); add(-40,-34,12); add(48,34,12); add(-10,60,12); // wardstones
  add(16,-22,8); add(30,-26,8); add(37,-33,8);      // variant packs
  add(-14,56,8); add(-7,64,8); add(44,30,8); add(-36,-28,8); add(-44,-30,8);
  add(9,2,10); add(13,5,8); add(4,8,8);             // starter grumbles
}
function terrainH(x,z){
  let h = Math.sin(x*0.045)*Math.cos(z*0.05)*1.8
        + Math.sin(x*0.012+1.7)*Math.sin(z*0.017+0.6)*2.6
        + Math.sin((x+z)*0.09)*0.5;
  h = Math.max(0, h + 0.6);
  let mask = 1;
  for (const f of FLAT_ZONES){
    const d = Math.hypot(x-f.x, z-f.z);
    if (d < f.r) return 0;
    const t = (d - f.r) / 12;
    if (t < 1) mask = Math.min(mask, t*t*(3-2*t));
  }
  return h * mask;
}

/* ------------------------------------------------------------ world builder */
const MAT = {}; // shared materials
function mkMat(){
  MAT.grass  = new THREE.MeshStandardMaterial({ color:0x6fae4e, roughness:0.95 });
  MAT.grass2 = new THREE.MeshStandardMaterial({ color:0x5a9a42, roughness:0.95 });
  MAT.dirt   = new THREE.MeshStandardMaterial({ color:0x8a6a44, roughness:1 });
  MAT.rock   = new THREE.MeshStandardMaterial({ color:0x8f96a3, roughness:0.9, flatShading:true });
  MAT.trunk  = new THREE.MeshStandardMaterial({ color:0x7a5230, roughness:1 });
  MAT.leaf   = new THREE.MeshStandardMaterial({ color:0x4f9d54, roughness:0.85, flatShading:true });
  MAT.leaf2  = new THREE.MeshStandardMaterial({ color:0x8ec06a, roughness:0.85, flatShading:true });
  MAT.stone  = new THREE.MeshStandardMaterial({ color:0xb9bfca, roughness:0.8, flatShading:true });
  MAT.stoneDark = new THREE.MeshStandardMaterial({ color:0x5b6270, roughness:0.9, flatShading:true });
  MAT.wood   = new THREE.MeshStandardMaterial({ color:0x6a4a2c, roughness:1 });
}

function buildWorld() {
  mkMat();
  initFlatZones();
  initBlockMats();
  scene.add(world);

  // rolling-hill ground: a displaced plane; terrainH is the same function
  // the physics, AI, and camera sample every frame
  const groundGeo = new THREE.PlaneGeometry(420, 420, 110, 110);
  const gp = groundGeo.attributes.position;
  for (let i=0; i<gp.count; i++){
    // after rotation.x = -PI/2: world x = local x, world z = -local y
    gp.setZ(i, terrainH(gp.getX(i), -gp.getY(i)));
  }
  groundGeo.computeVertexNormals();
  const ground = new THREE.Mesh(groundGeo, MAT.grass);
  ground.rotation.x = -Math.PI/2; ground.receiveShadow = true;
  world.add(ground);

  // lake (fishing spot) — a low disc of water
  lakePos = new THREE.Vector3(-22, 0, 14);
  const water = new THREE.Mesh(new THREE.CircleGeometry(11, 40),
    new THREE.MeshStandardMaterial({ color:0x3aa7c4, roughness:0.2, metalness:0.15, transparent:true, opacity:0.86 }));
  water.rotation.x = -Math.PI/2; water.position.set(lakePos.x, 0.06, lakePos.z);
  water.userData.water = true; world.add(water);
  const shore = new THREE.Mesh(new THREE.RingGeometry(11, 12.6, 40), MAT.dirt);
  shore.rotation.x = -Math.PI/2; shore.position.set(lakePos.x, 0.04, lakePos.z); world.add(shore);

  // trees ring
  for (let i=0;i<70;i++){
    const a = Math.random()*Math.PI*2, r = 26 + Math.random()*150;
    const x = Math.cos(a)*r, z = Math.sin(a)*r;
    if (Math.hypot(x-lakePos.x, z-lakePos.z) < 15) continue;
    world.add(makeTree(x, z, 0.8 + Math.random()*0.7));
  }

  // hills / mountains (backdrop, non-colliding but block camera)
  for (let i=0;i<9;i++){
    const a = (i/9)*Math.PI*2, r = 165;
    const m = new THREE.Mesh(new THREE.ConeGeometry(30+Math.random()*20, 45+Math.random()*35, 5),
      i%2? MAT.rock:MAT.stoneDark);
    m.position.set(Math.cos(a)*r, 18, Math.sin(a)*r); m.castShadow=true; world.add(m);
  }

  // Wardstones (element statues)
  addWardstone(new THREE.Vector3(6, 0, -6),  'cinder');   // first — near start
  addWardstone(new THREE.Vector3(34, 0, -30),'rime');
  addWardstone(new THREE.Vector3(-40, 0, -34),'loam');
  addWardstone(new THREE.Vector3(48, 0, 34), 'tide');
  addWardstone(new THREE.Vector3(-10, 0, 60),'arc');

  // Rime ice-wall blocking the path to the camp (element puzzle gate)
  iceWall = makeIceWall(new THREE.Vector3(14, 0, -16));
  world.add(iceWall);

  // Stonekin camp (stealth) — behind the ice wall
  buildCamp(new THREE.Vector3(26, 0, -46));
  campGoal = new THREE.Vector3(26, 0, -70);

  // Skywright Pell + Windrider's Trial hoops
  pellPos = new THREE.Vector3(-4, 0, 40);
  world.add(makeNPC(pellPos, 0xdcc36a));
  buildTrial();

  // Phase-2 content: elemental mechanisms, treasure, variants, and the boss arena
  buildMechanisms();
  buildBossArena();
  spawnVariantEnemies();

  // Phase-C content: rock/ore veins and lakeside plants
  scatterResources();
  // Phase-D content: the Sunken Barrow dig-down (cavern builds on first descent)
  buildDelve();
  // POIs for the map
  POIS.push({x:lakePos.x,z:lakePos.z,kind:'lake',name:'Willowmere'},
    {x:26,z:-46,kind:'camp',name:'Stonekin Camp'}, {x:26,z:-92,kind:'boss',name:'Hush'},
    {x:-4,z:40,kind:'npc',name:'Skywright Pell'});
  for (const ws of wardstones) POIS.push({x:ws.pos.x,z:ws.pos.z,kind:'ward',name:ELEMENTS[ws.elem].name});

  // ambient life: grass tufts (instanced, cheap) and drifting light motes
  const gGeo = new THREE.ConeGeometry(0.07, 0.4, 4);
  const gMat = new THREE.MeshStandardMaterial({ color:0x5f9c46, roughness:1, flatShading:true });
  const grass = new THREE.InstancedMesh(gGeo, gMat, 700);
  const m4 = new THREE.Matrix4(), q = new THREE.Quaternion(), v = new THREE.Vector3(), sc = new THREE.Vector3();
  const UP = new THREE.Vector3(0,1,0);
  let gi = 0;
  for (let i=0; i<1600 && gi<700; i++){
    const a = Math.random()*Math.PI*2, rr = 5 + Math.random()*150;
    const x = Math.cos(a)*rr, z = Math.sin(a)*rr;
    if (Math.hypot(x-lakePos.x, z-lakePos.z) < 14) continue;
    const s = 0.7 + Math.random()*0.9;
    q.setFromAxisAngle(UP, Math.random()*Math.PI);
    v.set(x, 0.18*s + terrainH(x,z), z); sc.set(1, s, 1);
    m4.compose(v, q, sc);
    grass.setMatrixAt(gi++, m4);
  }
  grass.count = gi;
  world.add(grass);

  const mCount = 130;
  const mPos = new Float32Array(mCount*3);
  for (let i=0;i<mCount;i++){
    const a = Math.random()*Math.PI*2, rr = Math.random()*120;
    const mx = Math.cos(a)*rr, mz = Math.sin(a)*rr;
    mPos[i*3] = mx; mPos[i*3+1] = terrainH(mx,mz) + 0.6 + Math.random()*4.5; mPos[i*3+2] = mz;
  }
  const mGeo = new THREE.BufferGeometry();
  mGeo.setAttribute('position', new THREE.BufferAttribute(mPos, 3));
  motes = new THREE.Points(mGeo, new THREE.PointsMaterial({ color:0xfff2c0, size:0.18, transparent:true, opacity:0.55 }));
  world.add(motes);

  // wandering Stonekin near start (first combat)
  spawnEnemy(new THREE.Vector3(9, 0, 2), 'grumble');
  spawnEnemy(new THREE.Vector3(13, 0, 5), 'grumble', true); // drops orb
  spawnEnemy(new THREE.Vector3(4, 0, 8), 'grumble');

  buildPlayer();
  buildTainer();
}

function makeTree(x,z,s){
  const g = new THREE.Group();
  const trunk = new THREE.Mesh(new THREE.CylinderGeometry(0.28*s,0.4*s,2.4*s,6), MAT.trunk);
  trunk.position.y = 1.2*s; trunk.castShadow=true; g.add(trunk);
  for (let i=0;i<3;i++){
    const blob = new THREE.Mesh(new THREE.IcosahedronGeometry((1.5-i*0.28)*s, 0), i%2?MAT.leaf:MAT.leaf2);
    blob.position.set((Math.random()-0.5)*s, (2.6+i*0.9)*s, (Math.random()-0.5)*s);
    blob.castShadow=true; g.add(blob);
  }
  g.position.set(x, terrainH(x,z), z);
  g.userData.collide = { r: 0.7*s }; // trunk collision
  const h = { mesh:g, kind:'tree', ore:false, hp:50, maxHp:50, drop:'timber',
    dropN:[2,4], minTier:0, respawnAt:0, base:g.position.clone() };
  harvestables.push(h);
  colliders.push({ x, z, r:0.7*s, harvest:h });
  return g;
}

function addWardstone(pos, elem){
  const g = new THREE.Group();
  const base = new THREE.Mesh(new THREE.CylinderGeometry(1.5,1.9,0.6,6), MAT.stoneDark);
  base.position.y=0.3; base.castShadow=true; g.add(base);
  const pillar = new THREE.Mesh(new THREE.BoxGeometry(1.2,4.2,1.0), MAT.stone);
  pillar.position.y=2.4; pillar.castShadow=true; g.add(pillar);
  // dormant sigil plane, lights up on unlock
  const sig = new THREE.Mesh(new THREE.PlaneGeometry(0.8,0.8),
    new THREE.MeshStandardMaterial({ color:0x2a2f38, emissive:0x000000 }));
  sig.position.set(0,3.0,0.52); g.add(sig);
  const glow = new THREE.PointLight(ELEMENTS[elem].color, 0, 10);
  glow.position.set(0,3.4,1.2); g.add(glow);
  g.position.copy(pos);
  world.add(g);
  colliders.push({ x:pos.x, z:pos.z, r:1.4 });
  const ws = { elem, pos:pos.clone(), sig, glow, group:g, unlocked:false };
  wardstones.push(ws);
  interactables.push({
    pos: pos.clone(), radius: 4.5, key:'E',
    label: () => `Attune ${ELEMENTS[elem].name}`,
    cond: () => !ws.unlocked,
    onUse: () => unlockElement(elem, ws),
  });
}

function makeIceWall(pos){
  const g = new THREE.Group();
  const mat = new THREE.MeshStandardMaterial({ color:0xbfeaf5, roughness:0.1, metalness:0.1, transparent:true, opacity:0.82, flatShading:true });
  for (let i=0;i<5;i++){
    const shard = new THREE.Mesh(new THREE.BoxGeometry(1.6, 4+Math.random()*2, 1.2), mat);
    shard.position.set(-3.2 + i*1.6, 2, 0); shard.rotation.y=(Math.random()-0.5)*0.3; shard.castShadow=true; g.add(shard);
  }
  g.position.copy(pos);
  g.userData.iceWall = true;
  // collision segment
  for (let i=0;i<5;i++) colliders.push({ x:pos.x-3.2+i*1.6, z:pos.z, r:1.1, tag:'ice' });
  return g;
}

function buildCamp(pos){
  const g = new THREE.Group();
  g.position.copy(pos); world.add(g);
  // tents / crates
  for (let i=0;i<4;i++){
    const tent = new THREE.Mesh(new THREE.ConeGeometry(2.2,2.6,4),
      new THREE.MeshStandardMaterial({ color:0x8a5a3a, roughness:1, flatShading:true }));
    const a=i/4*Math.PI*2; tent.position.set(Math.cos(a)*7, 1.3, Math.sin(a)*7); tent.rotation.y=a; tent.castShadow=true; g.add(tent);
  }
  const fire = new THREE.PointLight(0xff9a3c, 1.4, 18); fire.position.set(0,1.5,0); g.add(fire);
  const logs = new THREE.Mesh(new THREE.CylinderGeometry(1.1,1.1,0.5,8), MAT.wood); logs.position.y=0.25; g.add(logs);
  // two Boulderback guards
  spawnEnemy(new THREE.Vector3(pos.x-6, 0, pos.z+6), 'boulder', false, true);
  spawnEnemy(new THREE.Vector3(pos.x+6, 0, pos.z-2), 'boulder', false, true);
  // goal marker
  const goal = new THREE.Mesh(new THREE.TorusGeometry(1.4,0.18,8,20),
    new THREE.MeshStandardMaterial({ color:0x7bd3c6, emissive:0x2a6b60, emissiveIntensity:0.6 }));
  goal.rotation.x=Math.PI/2; goal.position.set(0,0.4,-24); g.add(goal);
  goal.userData.spin=true; spinners.push(goal);
}

function buildTrial(){
  // hoops descending along +z from near Pell
  const start = new THREE.Vector3(-4, 6, 46);
  for (let i=0;i<4;i++){
    const hoop = new THREE.Mesh(new THREE.TorusGeometry(2.4,0.22,10,28),
      new THREE.MeshStandardMaterial({ color:0xf5c168, emissive:0x7a5a10, emissiveIntensity:0.7, flatShading:true }));
    hoop.position.set(start.x + Math.sin(i*0.9)*6, start.y - i*1.2 + 3, start.z + i*12);
    hoop.userData.hoop = { idx:i, passed:false };
    world.add(hoop); hoops.push(hoop); spinners.push(hoop);
  }
  // wind updraft column near the launch
  windZones.push({ pos:new THREE.Vector3(-4,0,44), r:11, up:17 });
  // visual for wind
  const wind = new THREE.Mesh(new THREE.CylinderGeometry(6,6,20,16,1,true),
    new THREE.MeshBasicMaterial({ color:0xaee6ff, transparent:true, opacity:0.10, side:THREE.DoubleSide }));
  wind.position.set(-4,10,44); world.add(wind);
}

const colliders = []; // {x,z,r,tag,maxY?}  maxY: collider only applies below this height
const spinners = [];

/* ---------------------------------------------- Phase-2: chests & treasure */
function makeChest(id, pos, contents, radius=3.2, extraCond=null){
  const g = new THREE.Group();
  const base = new THREE.Mesh(new THREE.BoxGeometry(1.1,0.6,0.8),
    new THREE.MeshStandardMaterial({ color:0x7a5230, roughness:0.9 }));
  base.position.y=0.3; base.castShadow=true; g.add(base);
  const lid = new THREE.Mesh(new THREE.BoxGeometry(1.14,0.34,0.84),
    new THREE.MeshStandardMaterial({ color:0x8a6238, roughness:0.85 }));
  lid.position.set(0,0.72,-0.02); g.add(lid);
  const trim = new THREE.Mesh(new THREE.BoxGeometry(1.18,0.1,0.88),
    new THREE.MeshStandardMaterial({ color:0xe6c15a, metalness:0.5, roughness:0.4 }));
  trim.position.y=0.58; g.add(trim);
  g.position.copy(pos);
  if (G.chests[id]) lid.rotation.x = -1.1;   // already opened in this save
  world.add(g);
  interactables.push({
    id, pos: pos.clone(), radius, key:'E',
    label: () => 'Open chest',
    cond: () => !G.chests[id] && (!extraCond || extraCond()),
    onUse: () => {
      G.chests[id] = true;
      lid.rotation.x = -1.1;
      spawnBurst(pos.clone().add(new THREE.Vector3(0,1,0)), 0xf5c168, 22, 0.9, true);
      addTokens(contents.n);
      noteEvent('chest', 1);
      toast(`+${contents.n} Emberlight — spend it on Mastery!`, 'good', 3000);
      if (!G.flags.firstChest){ G.flags.firstChest = true;
        tainerSay('Emberlight! That’s what you pour into Mastery. Open your bag and advance whichever weapon style you love — the blade doesn’t get better, YOU do.', 6400); }
    },
  });
  return g;
}
/* ---------------------------------------------------------- weapons & mastery
   Design change from the original brief (deliberate, documented): every weapon
   is unique-grade, indestructible, and usable by anyone. There are no tiers to
   chase and nothing can be dismantled. Power comes from MASTERY per weapon
   type, bought with Emberlight — you invest in the discipline, not the object. */
const MASTERY_MAX = 10;
const WEAPON_TYPES = ['sword','bow','greatsword','dual','focus'];
function allWeapons(){
  const out=[];
  for (const t of WEAPON_TYPES) for (const w of (WEAPONS[t]||[])) out.push({...w, type:t});
  return out;
}
function findWeapon(id){ return allWeapons().find(w=>w.id===id) || null; }
function weaponType(id){ return findWeapon(id)?.type || G.klass || 'sword'; }
function equippedWeapon(){
  return findWeapon(G.equipped) || {...(WEAPONS[G.klass]?.[0] || {id:'?',name:'—',tier:1}), type:G.klass||'sword'};
}
function equippedType(){ return equippedWeapon().type || G.klass || 'sword'; }
/* the combat profile now follows the WEAPON in hand, not the starting class */
function activeProfile(){ return CLASSES[equippedType()] || CLASSES[G.klass] || CLASSES.sword; }
function masteryOf(t){ return Math.max(1, Math.min(MASTERY_MAX, (G.mastery && G.mastery[t]) || 1)); }
function masteryMult(lv){ return 1 + (lv-1)*0.22; }
function masteryCost(lv){ return 12 + (lv-1)*10; }
function weaponPower(w){
  const t = w.type || weaponType(w.id);
  const m = weaponMods(w.id);
  return Math.round((CLASSES[t]?.dmg || 20) * masteryMult(masteryOf(t)) * (m.dmg||1));
}
function advanceMastery(t){
  const lv = masteryOf(t);
  if (lv >= MASTERY_MAX){ toast(`${CLASSES[t].name} mastery is already complete.`, 'info', 2200); return false; }
  const cost = masteryCost(lv);
  if (G.tokens < cost){ toast(`Need ${cost} Emberlight to advance ${CLASSES[t].name} (${G.tokens} held).`, 'info', 2600); return false; }
  G.tokens -= cost; G.mastery[t] = lv+1;
  noteEvent('mastery', 1);
  sfx.attune();
  spawnFloater(`${CLASSES[t].name} Mastery ${lv+1}`, player.position.clone().add(new THREE.Vector3(0,2.2,0)), '#f5c168');
  toast(`${CLASSES[t].name} mastery → ${lv+1}. Power now ${Math.round(CLASSES[t].dmg*masteryMult(lv+1))}.`, 'good', 3200);
  if (!G.flags.firstMastery){ G.flags.firstMastery = true;
    tainerSay('That’s the real secret — you don’t get stronger by finding a better blade. You get stronger by practising the one in your hands.', 6000); }
  updateHUD();
  return true;
}
/* every weapon is available from the start; equipping swaps your combat style */
function unlockAllWeapons(){ G.owned = allWeapons().map(w=>w.id); }
function equipWeapon(id){
  if (!findWeapon(id)) return false;
  G.equipped = id;
  rebuildWeaponProp();
  tintWeapon(G.activeElement);
  updateHUD();
  return true;
}
function rebuildWeaponProp(){ attachWeaponProps(); }
/* parent the props to the arm meshes at hand height (arms are 0.72 tall with a
   centred origin, so the hand sits at local y = -0.36) */
function attachWeaponProps(){
  if (!player || !playerParts) return;
  const held = player.userData.weapons;
  if (held){ if (held.right) playerParts.armR.remove(held.right); if (held.left) playerParts.armL.remove(held.left); }
  const { right, left } = makeWeaponProp(equippedType(), G.equipped);
  right.position.set(0, -0.36, 0.06);
  playerParts.armR.add(right);
  if (left){ left.position.set(0, -0.36, 0.06); playerParts.armL.add(left); }
  player.userData.weapons = { right, left };
  player.userData.weapon = right;          // back-compat for tinting/float
  tintWeapon(G.activeElement);
}

/* ------------------------------------------- Phase-2: elemental mechanisms */
function mechMarkerMesh(elem){
  // a carved trigger stone with the element's sigil colour crystal — plus shape, never colour alone
  const g = new THREE.Group();
  const base = new THREE.Mesh(new THREE.CylinderGeometry(0.9,1.1,1.2,6), MAT.stoneDark);
  base.position.y=0.6; base.castShadow=true; g.add(base);
  const crystal = new THREE.Mesh(new THREE.OctahedronGeometry(0.45,0),
    new THREE.MeshStandardMaterial({ color:ELEMENTS[elem].color, emissive:ELEMENTS[elem].color, emissiveIntensity:0.35, flatShading:true }));
  crystal.position.y=1.6; g.add(crystal);
  g.userData.crystal = crystal;
  return g;
}
function addMechanism(id, elem, pos, marker, apply){
  world.add(marker); marker.position.copy(pos);
  const m = { id, elem, pos:pos.clone(), r:4.5, done:false, marker, apply };
  mechanisms.push(m);
  return m;
}
function activateMechanism(m, withVfx=true){
  if (m.done) return;
  m.done = true; G.mechs[m.id] = true;
  if (m.marker?.userData?.crystal) m.marker.userData.crystal.material.emissiveIntensity = 1.2;
  if (withVfx) spawnBurst(m.pos.clone().setY(1.6), ELEMENTS[m.elem].color, 30, 1.2);
  m.apply(withVfx);
}

function buildMechanisms(){
  /* RIME — freeze the deep lake to walk to the island hoard */
  const islePos = new THREE.Vector3(lakePos.x, 0, lakePos.z);
  const isle = new THREE.Mesh(new THREE.CylinderGeometry(2.4,2.8,0.5,10), MAT.dirt);
  isle.position.set(islePos.x, 0.1, islePos.z); world.add(isle);
  makeChest('chest-isle', new THREE.Vector3(islePos.x, 0.3, islePos.z), {type:'tokens', n:45});
  const iceMat = new THREE.MeshStandardMaterial({ color:0xcdeef8, roughness:0.15, transparent:true, opacity:0.9, flatShading:true });
  const discs = new THREE.Group(); discs.visible = false;
  for (let i=1;i<=3;i++){
    const d = new THREE.Mesh(new THREE.CylinderGeometry(1.7,1.9,0.24,10), iceMat);
    d.position.set(lakePos.x + 10 - i*2.6, 0.12, lakePos.z + 1.5 - i*0.5);
    discs.add(d);
  }
  world.add(discs);
  addMechanism('rime', 'rime',
    new THREE.Vector3(lakePos.x + 12.5, 0, lakePos.z + 3),
    mechMarkerMesh('rime'),
    (vfx)=>{ lakeFrozen = true; discs.visible = true;
      if (vfx){ toast('The deep water stills into ice — a path to the island!', 'good', 3200);
        tainerSay('Rime on open water! Now we can walk right out to that little island. I KNEW it was hiding something.', 5200); } });

  /* LOAM — raise stone steps to a high hoard near the Loam Wardstone */
  const plat = new THREE.Mesh(new THREE.BoxGeometry(7,5,7), MAT.rock);
  plat.position.set(-48, 2.5, -42); plat.castShadow=true; world.add(plat);
  colliders.push({ x:-48, z:-42, r:4.4, maxY:4.4 });
  platforms.push({ x:-48, z:-42, hw:3.5, hd:3.5, topY:5 });
  makeChest('chest-loam', new THREE.Vector3(-48, 5.3, -42), {type:'tokens', n:25});
  const steps = [];
  const stepDefs = [ {x:-42.6,z:-38.6,topY:1.7}, {x:-44.6,z:-40,topY:3.4}, {x:-46.4,z:-41.2,topY:5} ];
  for (const s of stepDefs){
    const st = new THREE.Mesh(new THREE.BoxGeometry(2.4, s.topY, 2.4), MAT.stone);
    st.position.set(s.x, s.topY/2 - 6, s.z);   // start sunken
    st.castShadow=true; world.add(st); steps.push({mesh:st, def:s});
  }
  addMechanism('loam', 'loam',
    new THREE.Vector3(-41.5, 0, -37),
    mechMarkerMesh('loam'),
    (vfx)=>{ for (const s of steps){ s.mesh.position.y = s.def.topY/2; platforms.push({ x:s.def.x, z:s.def.z, hw:1.2, hd:1.2, topY:s.def.topY }); }
      if (vfx){ toast('Stone steps rumble up from the earth!', 'good', 2800);
        tainerSay('Loam listens to you now. Up the steps — treasure never buries itself THAT well.', 4600); } });

  /* TIDE — flood the sealed basin so its hoard floats up to the rim */
  const bPos = new THREE.Vector3(58, 0, 44);
  const ring = new THREE.Mesh(new THREE.CylinderGeometry(3.4,3.7,3.4,10,1,true),
    new THREE.MeshStandardMaterial({ color:0x8f96a3, roughness:0.9, flatShading:true, side:THREE.DoubleSide }));
  ring.position.set(bPos.x,1.7,bPos.z); world.add(ring);
  for (let a=0;a<8;a++){ const ang=a/8*Math.PI*2; colliders.push({ x:bPos.x+Math.cos(ang)*3.4, z:bPos.z+Math.sin(ang)*3.4, r:0.9, maxY:3.2 }); }
  platforms.push({ x:bPos.x, z:bPos.z, hw:4.4, hd:4.4, topY:3.4 });          // rim walkway
  platforms.push({ x:bPos.x+5.4, z:bPos.z, hw:1.3, hd:1.3, topY:1.7 });      // outer step 1
  const stepA = new THREE.Mesh(new THREE.BoxGeometry(2.6,1.7,2.6), MAT.stone);
  stepA.position.set(bPos.x+5.4,0.85,bPos.z); world.add(stepA);
  const waterFill = new THREE.Mesh(new THREE.CylinderGeometry(3.2,3.2,0.2,16),
    new THREE.MeshStandardMaterial({ color:0x3aa7c4, roughness:0.2, transparent:true, opacity:0.85 }));
  waterFill.position.set(bPos.x,0.4,bPos.z); waterFill.visible=false; world.add(waterFill);
  const tideChest = makeChest('chest-tide', new THREE.Vector3(bPos.x, 0.4, bPos.z), {type:'tokens', n:30}, 5.2, ()=>G.mechs.tide);
  // chest starts at the bottom of the basin, unreachable until it floats up
  addMechanism('tide', 'tide',
    new THREE.Vector3(bPos.x - 5.2, 0, bPos.z + 1),
    mechMarkerMesh('tide'),
    (vfx)=>{ waterFill.visible = true; waterFill.position.y = 3.1; tideChest.position.y = 3.2;
      if (vfx){ toast('Water surges up the basin — the hoard floats to the rim!', 'good', 3200);
        tainerSay('Tide fills what stone seals. Climb the outer step and walk the rim!', 4800); } });

  /* ARC — power the sealed gate to the Hollow Warden's hollow (built in buildBossArena) */
}

/* -------------------------------------------------- Phase-2: boss — Hush */
const BOSS_POS = new THREE.Vector3(26, 0, -96);
let bossGateParts = null;
function buildBossArena(){
  // ring of crag walls with a gap facing the camp
  for (let i=0;i<10;i++){
    const ang = (i/10)*Math.PI*2;
    if (ang > Math.PI*0.35 && ang < Math.PI*0.65) continue;   // gap toward +z (the camp side)
    const rock = new THREE.Mesh(new THREE.ConeGeometry(2.6, 7+((i*37)%3)*1.5, 5), i%2?MAT.rock:MAT.stoneDark);
    const x = BOSS_POS.x + Math.cos(ang)*14, z = BOSS_POS.z + Math.sin(ang)*14;
    rock.position.set(x, 3, z); rock.castShadow=true; world.add(rock);
    colliders.push({ x, z, r:2.2 });
  }
  // gate: two sliding slabs in the gap
  const slabMat = new THREE.MeshStandardMaterial({ color:0x4a5162, roughness:0.85, flatShading:true });
  const gz = BOSS_POS.z + 14;
  const L = new THREE.Mesh(new THREE.BoxGeometry(3.4,6,1.2), slabMat); L.position.set(BOSS_POS.x-1.8,3,gz); world.add(L);
  const R = new THREE.Mesh(new THREE.BoxGeometry(3.4,6,1.2), slabMat); R.position.set(BOSS_POS.x+1.8,3,gz); world.add(R);
  colliders.push({ x:BOSS_POS.x-1.8, z:gz, r:1.8, tag:'bossgate' });
  colliders.push({ x:BOSS_POS.x+1.8, z:gz, r:1.8, tag:'bossgate' });
  bossGateParts = { L, R, gz };
  addMechanism('arc', 'arc',
    new THREE.Vector3(BOSS_POS.x + 5.5, 0, gz + 2.5),
    mechMarkerMesh('arc'),
    (vfx)=>{
      L.position.x = BOSS_POS.x - 5.4; R.position.x = BOSS_POS.x + 5.4;
      for (let i=colliders.length-1;i>=0;i--) if (colliders[i].tag==='bossgate') colliders.splice(i,1);
      if (!G.bossDefeated) spawnBoss();
      if (vfx){ toast('The conduit crackles — the gate grinds open!', 'good', 3000);
        tainerSay('Something in that hollow has been very, very quiet. That’s Hush — one of Mourne’s Hollow Wardens. We can do this. Watch for the slam, then strike the crystal on its back!', 7200); } });
  // if this save already defeated Hush, its reward chest must still exist
  if (G.bossDefeated && !bossChestSpawned){
    bossChestSpawned = true;
    makeChest('chest-boss', new THREE.Vector3(BOSS_POS.x, 0, BOSS_POS.z), {type:'tokens', n:90});
  }
}

function makeWarden(){
  const g = new THREE.Group();
  const bodyMat = new THREE.MeshStandardMaterial({ color:0x3a3f52, roughness:0.85, flatShading:true });
  const body = new THREE.Mesh(new THREE.BoxGeometry(2.1,3.1,1.5), bodyMat);
  body.position.y=2.2; body.castShadow=true; g.add(body);
  const head = new THREE.Mesh(new THREE.BoxGeometry(1.1,0.9,1.0), bodyMat);
  head.position.y=4.2; g.add(head);
  const eyeMat = new THREE.MeshStandardMaterial({ color:0xd9c8f5, emissive:0xb9a0e8, emissiveIntensity:0.9 });
  const eL=new THREE.Mesh(new THREE.BoxGeometry(0.2,0.12,0.06),eyeMat); eL.position.set(-0.25,4.25,0.53); g.add(eL);
  const eR=eL.clone(); eR.position.x=0.25; g.add(eR);
  const armGeo = new THREE.BoxGeometry(0.7,2.6,0.7);
  const aL=new THREE.Mesh(armGeo,bodyMat); aL.position.set(-1.6,2.4,0); aL.castShadow=true; g.add(aL);
  const aR=new THREE.Mesh(armGeo,bodyMat); aR.position.set(1.6,2.4,0); aR.castShadow=true; g.add(aR);
  const legGeo = new THREE.BoxGeometry(0.8,1.4,0.8);
  const lL=new THREE.Mesh(legGeo,MAT.stoneDark); lL.position.set(-0.6,0.7,0); g.add(lL);
  const lR=new THREE.Mesh(legGeo,MAT.stoneDark); lR.position.set(0.6,0.7,0); g.add(lR);
  const crystal = new THREE.Mesh(new THREE.OctahedronGeometry(0.6,0),
    new THREE.MeshStandardMaterial({ color:0x7bd3c6, emissive:0x2a6b60, emissiveIntensity:0.4, flatShading:true }));
  crystal.position.set(0,3.1,-1.0); g.add(crystal);
  g.userData.arms = {aL,aR}; g.userData.crystal = crystal;
  return g;
}
function spawnBoss(){
  const mesh = makeWarden();
  mesh.position.copy(BOSS_POS);
  scene.add(mesh);
  bossRef = {
    mesh, kind:'warden', boss:true, guard:false, dropsOrb:false, elem:null,
    hp:320, maxHp:320, dmg:24, speed:3.0, r:1.9,
    home:BOSS_POS.clone(), state:'idle', target:null,
    telegraph:0, slamCd:2, weak:0, phase:1,
    atkCd:0, hitCd:0, alive:true, wobble:0,
  };
  enemies.push(bossRef);
}
function updateBoss(e, dt, pPos, transformed){
  e.weak = Math.max(0, e.weak - dt);
  e.slamCd = Math.max(0, e.slamCd - dt);
  if (e.hitCd>0) e.hitCd-=dt;
  const cr = e.mesh.userData.crystal;
  cr.material.emissiveIntensity = e.weak>0 ? 1.6 : 0.4;
  const d = Math.hypot(pPos.x-e.mesh.position.x, pPos.z-e.mesh.position.z);

  // phase 2 at half health
  if (e.phase===1 && e.hp < e.maxHp/2){
    e.phase=2; e.speed=3.9;
    spawnEnemy(e.mesh.position.clone().add(new THREE.Vector3(3,0,2)), 'grumble');
    spawnEnemy(e.mesh.position.clone().add(new THREE.Vector3(-3,0,2)), 'grumble');
    tainerSay('It’s calling Stonekin to it — keep moving! After the slam, the crystal! The CRYSTAL!', 4600);
  }

  const arms = e.mesh.userData.arms;
  if (e.telegraph > 0){
    // wind-up: arms rise, body pulses — the readable warning before the slam
    e.telegraph -= dt;
    arms.aL.rotation.x = arms.aR.rotation.x = -2.2 * (1 - e.telegraph);
    if (e.telegraph <= 0){
      arms.aL.rotation.x = arms.aR.rotation.x = 0.6;
      spawnBurst(e.mesh.position.clone().add(new THREE.Vector3(0,0.4,0)), 0xb9a0e8, 26, 1.6);
      if (!settings.motion) shake(0.35);
      if (d < 5.4){ if (transformed) damageMimic(e.dmg); else damagePlayer(e.dmg); }
      e.weak = 2.6;                 // crystal exposed — bonus-damage window
      e.slamCd = e.phase===2 ? 2.2 : 3.2;
    }
  } else {
    arms.aL.rotation.x = arms.aR.rotation.x = 0;
    if (d < 40){
      const to = new THREE.Vector3(pPos.x-e.mesh.position.x,0,pPos.z-e.mesh.position.z);
      const dist = to.length();
      e.mesh.rotation.y = Math.atan2(to.x, to.z);
      if (dist > 4.0){
        to.normalize();
        e.mesh.position.x += to.x*e.speed*dt;
        e.mesh.position.z += to.z*e.speed*dt;
      } else if (e.slamCd<=0){
        e.telegraph = e.phase===2 ? 0.65 : 0.95;
      }
    }
  }

  // boss bar
  if (d < 45 && e.alive) showBossBar('Hush, the Hollow Warden', e.hp/e.maxHp);
  else hide(dom['boss-bar']);
}
function bossDefeatedFlow(e){
  G.bossDefeated = true;
  hide(dom['boss-bar']);
  advanceMain('bossDefeated');
  noteEvent('defeatBoss', 1);
  addTokens(40);
  dissolve(e.mesh); dissolve(e.mesh);   // extra-big send-off, still just light
  if (!bossChestSpawned){ bossChestSpawned = true;
    makeChest('chest-boss', new THREE.Vector3(BOSS_POS.x, 0, BOSS_POS.z), {type:'tokens', n:90}); }
  G.stage = 6;
  setObjective('The vale is safe. The trail of the Lost Sibling leads beyond Willowmere… To be continued.');
  toast('Hush, the Hollow Warden, dissolves into light. +40 Emberlight', 'good', 4600);
  tainerSay('You did it… the stillness is lifting! Look — the light it was holding is drifting off the way your sibling went. The search goes on, and now nothing in this vale can stop us.', 8000);
}

/* --------------------------------------- Phase-2: elemental Stonekin packs */
function spawnVariantEnemies(){
  spawnEnemy(new THREE.Vector3(30,0,-26), 'grumble', false, false, 'rime');
  spawnEnemy(new THREE.Vector3(37,0,-33), 'grumble', true,  false, 'rime');
  spawnEnemy(new THREE.Vector3(16,0,-22), 'grumble', false, false, 'cinder');
  spawnEnemy(new THREE.Vector3(-14,0,56), 'grumble', false, false, 'arc');
  spawnEnemy(new THREE.Vector3(-7,0,64),  'grumble', true,  false, 'arc');
  spawnEnemy(new THREE.Vector3(44,0,30),  'grumble', false, false, 'tide');
  spawnEnemy(new THREE.Vector3(-36,0,-28),'grumble', false, false, 'loam');
  spawnEnemy(new THREE.Vector3(-44,0,-30),'boulder', false, false, 'loam');
}

/* -------------------------------------------------------------- characters */
function humanoid(tunic, skin=0xf0c9a0){
  const g = new THREE.Group();
  const bodyMat = new THREE.MeshStandardMaterial({ color:tunic, roughness:0.7, flatShading:true });
  const skinMat = new THREE.MeshStandardMaterial({ color:skin, roughness:0.8 });
  const darkMat = new THREE.MeshStandardMaterial({ color:0x2c2f3a, roughness:0.9 });

  const torso = new THREE.Mesh(new THREE.BoxGeometry(0.66,0.8,0.36), bodyMat);
  torso.position.y=1.15; torso.castShadow=true; g.add(torso);
  const hips = new THREE.Mesh(new THREE.BoxGeometry(0.6,0.34,0.34), darkMat);
  hips.position.y=0.72; g.add(hips);
  const head = new THREE.Mesh(new THREE.BoxGeometry(0.42,0.44,0.42), skinMat);
  head.position.y=1.82; head.castShadow=true; g.add(head);
  // simple face — two eyes
  const eyeMat = new THREE.MeshStandardMaterial({ color:0x20242e });
  const eL = new THREE.Mesh(new THREE.BoxGeometry(0.07,0.09,0.03), eyeMat); eL.position.set(-0.1,1.86,0.22); g.add(eL);
  const eR = eL.clone(); eR.position.x=0.1; g.add(eR);
  // hair cap
  const hair = new THREE.Mesh(new THREE.BoxGeometry(0.46,0.18,0.46),
    new THREE.MeshStandardMaterial({ color: tunic===0x2f7d78?0x3a2f24:0x2a1f16 }));
  hair.position.y=2.02; g.add(hair);
  // arms
  const armGeo = new THREE.BoxGeometry(0.18,0.72,0.18);
  const armL = new THREE.Mesh(armGeo, bodyMat); armL.position.set(-0.44,1.2,0); armL.castShadow=true; g.add(armL);
  const armR = new THREE.Mesh(armGeo, bodyMat); armR.position.set(0.44,1.2,0); armR.castShadow=true; g.add(armR);
  // legs
  const legGeo = new THREE.BoxGeometry(0.22,0.72,0.22);
  const legL = new THREE.Mesh(legGeo, darkMat); legL.position.set(-0.16,0.36,0); legL.castShadow=true; g.add(legL);
  const legR = new THREE.Mesh(legGeo, darkMat); legR.position.set(0.16,0.36,0); legR.castShadow=true; g.add(legR);

  g.userData.parts = { armL, armR, legL, legR, torso, head };
  return g;
}

function buildPlayer(){
  const tunic = G.sibling==='wren' ? 0x2f7d78 : 0x8a561f;
  player = humanoid(tunic);
  player.position.set(-18, 0, 10);
  playerParts = player.userData.parts;
  // weapon props are parented to the HANDS so they swing with the arms
  attachWeaponProps();
  scene.add(player);
}

/* Returns {right, left} props to be parented to the HANDS (the arm meshes), so
   a weapon actually travels with the swing. Dual wield returns two blades. */
function makeWeaponProp(klass, wid){
  const steel = new THREE.MeshStandardMaterial({ color:0xcdd6e6, roughness:0.35, metalness:0.6, flatShading:true });
  const gold  = new THREE.MeshStandardMaterial({ color:0xe6c15a, roughness:0.4, metalness:0.5 });
  const wood  = new THREE.MeshStandardMaterial({ color:0x8a5a2c, roughness:0.8 });
  // per-weapon flourish so the three of a type don't look identical
  const idx = Math.max(0, (WEAPONS[klass]||[]).findIndex(w=>w.id===wid));
  const accent = [0xe6c15a, 0x7bd3c6, 0xf0713b][idx] || 0xe6c15a;
  const accentMat = new THREE.MeshStandardMaterial({ color:accent, emissive:accent, emissiveIntensity:0.35, roughness:0.4, metalness:0.5 });
  const blade = (len, w=0.08, th=0.02)=>{
    const g = new THREE.Group();
    const b = new THREE.Mesh(new THREE.BoxGeometry(w,len,th), steel); b.position.y = len/2; g.add(b);
    const h = new THREE.Mesh(new THREE.BoxGeometry(w*3.4,0.08,0.08), accentMat); g.add(h);
    const p = new THREE.Mesh(new THREE.BoxGeometry(w*0.9,0.1,0.09), gold); p.position.y=-0.1; g.add(p);
    return g;
  };
  let right = new THREE.Group(), left = null;
  if (klass==='sword'){ right = blade(1.1 + idx*0.12); }
  else if (klass==='greatsword'){ right = blade(1.7 + idx*0.1, 0.18, 0.05); }
  else if (klass==='dual'){ right = blade(0.8, 0.06); left = blade(0.8, 0.06); }   // TWO blades
  else if (klass==='bow'){
    const b = new THREE.Mesh(new THREE.TorusGeometry(0.5,0.04,6,12,Math.PI*1.2), wood);
    b.rotation.z = Math.PI/2; right.add(b);
    const str = new THREE.Mesh(new THREE.BoxGeometry(0.01,0.86,0.01), accentMat); str.position.z=0.02; right.add(str);
  }
  else if (klass==='focus'){
    const b = new THREE.Mesh(new THREE.OctahedronGeometry(0.26 + idx*0.03,0), accentMat);
    b.position.set(0,0.05,0.25); right.add(b); right.userData.float = b;
  }
  return { right, left };
}

function makeNPC(pos, color){
  const g = humanoid(color, 0xe8c69a);
  g.position.copy(pos);
  // hat to distinguish mentor
  const hat = new THREE.Mesh(new THREE.ConeGeometry(0.4,0.5,7),
    new THREE.MeshStandardMaterial({ color:0x5a7d4a, flatShading:true }));
  hat.position.y=2.2; g.add(hat);
  colliders.push({ x:pos.x, z:pos.z, r:0.6 });
  interactables.push({
    pos: pos.clone(), radius:4, key:'E',
    label: () => G.flags.trialPassed ? 'Talk to Skywright Pell' : 'Begin the Windrider’s Trial',
    cond: () => true,
    onUse: () => startTrial(),
  });
  return g;
}

function buildTainer(){
  tainerMesh = new THREE.Group();
  const core = new THREE.Mesh(new THREE.IcosahedronGeometry(0.28,1),
    new THREE.MeshStandardMaterial({ color:0xffe9a8, emissive:0xf5b64a, emissiveIntensity:0.9, flatShading:true }));
  tainerMesh.add(core);
  const halo = new THREE.Mesh(new THREE.TorusGeometry(0.42,0.03,6,18),
    new THREE.MeshBasicMaterial({ color:0xfff0c0, transparent:true, opacity:0.7 }));
  halo.rotation.x=Math.PI/2; tainerMesh.add(halo);
  const light = new THREE.PointLight(0xffd98a, 0.8, 8); tainerMesh.add(light);
  tainerMesh.position.set(-18, 2, 12);
  tainerMesh.visible = false; // appears after fishing
  scene.add(tainerMesh);
}

/* ------------------------------------------------------------------ enemies */
function makeStonekin(kind, elem=null){
  const g = new THREE.Group();
  const big = kind==='boulder';
  const s = big ? 1.7 : 1.0;
  const rockMat = new THREE.MeshStandardMaterial({ color: big?0x7c8494:0x9aa2ae, roughness:0.95, flatShading:true });
  const body = new THREE.Mesh(new THREE.DodecahedronGeometry(0.8*s,0), rockMat);
  body.position.y = 0.85*s; body.castShadow=true; g.add(body);
  // moss
  const moss = new THREE.Mesh(new THREE.SphereGeometry(0.82*s,8,6,0,Math.PI*2,0,0.7),
    new THREE.MeshStandardMaterial({ color:0x5c8a3a, roughness:1, flatShading:true }));
  moss.position.y=0.85*s; g.add(moss);
  // eyes
  const eyeMat = new THREE.MeshStandardMaterial({ color:0xffe08a, emissive:0xffcf5a, emissiveIntensity:0.8 });
  const eL=new THREE.Mesh(new THREE.SphereGeometry(0.1*s,8,8),eyeMat); eL.position.set(-0.22*s,0.95*s,0.62*s); g.add(eL);
  const eR=eL.clone(); eR.position.x=0.22*s; g.add(eR);
  // stubby legs
  const legMat = MAT.stoneDark;
  for (const sx of [-0.32,0.32]){ const l=new THREE.Mesh(new THREE.BoxGeometry(0.2*s,0.4*s,0.2*s),legMat);
    l.position.set(sx*s,0.2*s,0); g.add(l); }
  // elemental variant: glowing crystal shards in the variant's colour (plus resist behaviour)
  if (elem){
    const cMat = new THREE.MeshStandardMaterial({ color:ELEMENTS[elem].color, emissive:ELEMENTS[elem].color, emissiveIntensity:0.6, flatShading:true });
    for (const [cx,cy,cz,cs] of [[-0.35,1.4,0,0.22],[0.3,1.5,-0.2,0.18],[0,1.6,0.25,0.16]]){
      const shard = new THREE.Mesh(new THREE.OctahedronGeometry(cs*s,0), cMat);
      shard.position.set(cx*s, cy*s, cz*s); g.add(shard);
    }
  }
  g.userData.eyes=[eL,eR];
  return g;
}

function spawnEnemy(pos, kind, dropsOrb=false, guard=false, elem=null){
  const mesh = makeStonekin(kind, elem);
  mesh.position.copy(pos);
  scene.add(mesh);
  const big = kind==='boulder';
  const hm = G.hardMode ? 1.5 : 1;             // Deepened mode: tougher foes
  const baseHp = ((big?120:48) + (elem?14:0)) * hm;
  const e = {
    mesh, kind, guard, dropsOrb, elem,
    hp: baseHp, maxHp: baseHp,
    dmg: (big?18:10)*hm, speed: big?2.0:2.6,
    home: pos.clone(), state:'idle', target:null,
    atkCd:0, hitCd:0, alive:true, wobble:Math.random()*10,
    r: big?1.3:0.9,
  };
  enemies.push(e);
  return e;
}

/* ================================================================= CONTROLS */
const keys = {};
let yaw = Math.PI, pitch = 0.35, camDist = 8;
let pointerLocked = false;
let attackHeld = false;
let usingTouch = false;
const touch = { moveId:null, ox:0, oy:0, mx:0, my:0, sprint:false, lookId:null, lx:0, ly:0 };

function bindInput(){
  // browsers only allow audio after a user gesture — start it on the first one
  const kick = ()=>{ initAudio(); removeEventListener('mousedown', kick); removeEventListener('keydown', kick); };
  addEventListener('mousedown', kick);
  addEventListener('keydown', kick);
  // soft click on any button press
  addEventListener('click', (e)=>{ if (e.target.closest('button')) sfx.ui(); }, true);
  addEventListener('keydown', (e)=>{
    const k = e.key.toLowerCase();
    keys[k] = true;
    if (k===' ' || k==='tab') e.preventDefault();
    const act = INPUT.actionFor(k);
    if (G.phase==='playing'){
      if (act==='interact'){
        // E is context-sensitive: interact when a prompt is showing,
        // otherwise cycle elements leftward (Q cycles rightward)
        if (!dom.prompt.classList.contains('hidden')) tryInteract();
        else cycleElement(-1);
      }
      else if (act==='mimic') tryMimic();
      else if (act==='cycle_element') cycleElement(1);
      else if (act==='attack'){ chargeT=0; charged=false; doAttack(); }
      else if (act==='jump'){ if (!e.repeat) queueJump(); }
      else if (act && act.startsWith('move_') && !e.repeat){
        // double-tap a direction to dash
        const now = performance.now();
        if (lastTap[act] && now-lastTap[act] < 280){ tryDash(dirForAction(act)); lastTap[act]=0; }
        else lastTap[act] = now;
      }
      else if (act==='pause') pause();
      else if (act==='map') openMap();
      else if (act==='log') openJournal();
      else if (act==='inventory') { pause(); openInventory(); }
      else {
        const slot = INPUT.slotIndex(act);
        if (slot >= 0) selectHotbar(slot);
      }
    } else if (act==='pause' && G.phase==='paused') resume();
    else if ((act==='map'||act==='pause') && G.phase==='map') closeMap();
    else if ((act==='log'||act==='pause') && G.phase==='journal') closeJournal();
    else if (act==='pause' && G.phase==='reflect') closeReflection();
    else if (G.phase==='inventory'){
      const slot = INPUT.slotIndex(act);
      if (slot >= 0 && assignPick) assignToSlot(slot);
      else if (act==='pause' || act==='inventory') closeInventory();
    }
  });
  addEventListener('keyup', (e)=>{ keys[e.key.toLowerCase()] = false; });

  const canvas = dom_scene();
  canvas.addEventListener('mousedown', (e)=>{
    if (G.phase!=='playing') return;
    if (usingTouch) return;   // touch devices use the on-screen controls, not pointer lock
    if (e.button===0){ doAttack(); attackHeld=true; if(!pointerLocked) canvas.requestPointerLock?.(); }
  });
  addEventListener('mouseup', ()=>{ attackHeld=false; });
  document.addEventListener('pointerlockchange', ()=>{
    const was = pointerLocked;
    pointerLocked = document.pointerLockElement===canvas;
    // Esc releases the browser's pointer lock WITHOUT delivering a keydown to the
    // page — treat that release as the pause gesture so the cursor and the menu
    // arrive together instead of leaving the game running with a free mouse.
    if (was && !pointerLocked && G.phase==='playing'){ pause(); lockOnResume = true; }
  });
  addEventListener('mousemove', (e)=>{
    if (G.phase!=='playing') return;
    if (pointerLocked){
      yaw   -= e.movementX * 0.0022 * settings.cam;
      pitch -= e.movementY * 0.0022 * settings.cam * (settings.invert?-1:1);
    } else if (e.buttons & 1){
      yaw   -= e.movementX * 0.004 * settings.cam;
      pitch -= e.movementY * 0.004 * settings.cam * (settings.invert?-1:1);
    }
    pitch = Math.max(-0.2, Math.min(1.1, pitch));
  });
  addEventListener('wheel', (e)=>{ if(G.phase==='playing'){ camDist = Math.max(4, Math.min(14, camDist - Math.sign(e.deltaY))); }},{passive:true});
  bindTouch(canvas);
}

/* ------------------------------------------------- touch controls (mobile) */
function enableTouch(){
  if (usingTouch) return;
  usingTouch = true;
  document.body.setAttribute('data-touch','on');
  // the centre crosshair stays — it's the aim reference for the drag-camera
}
function bindTouch(canvas){
  const STICK_R = 52;
  const stick = dom['tc-stick'], knob = dom['tc-knob'];
  // canvas touches: left half = move joystick, right half = camera look
  canvas.addEventListener('touchstart', (e)=>{
    enableTouch();
    for (const t of e.changedTouches){
      if (t.clientX < innerWidth*0.5 && touch.moveId===null){
        touch.moveId = t.identifier; touch.ox = t.clientX; touch.oy = t.clientY; touch.mx=0; touch.my=0;
        if (stick){ stick.style.left=t.clientX+'px'; stick.style.top=t.clientY+'px'; show(stick); if(knob) knob.style.transform='translate(0,0)'; }
      } else if (touch.lookId===null){
        touch.lookId = t.identifier; touch.lx = t.clientX; touch.ly = t.clientY;
      }
    }
    e.preventDefault();
  }, {passive:false});
  canvas.addEventListener('touchmove', (e)=>{
    for (const t of e.changedTouches){
      if (t.identifier===touch.moveId){
        let dx=t.clientX-touch.ox, dy=t.clientY-touch.oy;
        const len=Math.hypot(dx,dy)||1; const cl=Math.min(len,STICK_R);
        dx=dx/len*cl; dy=dy/len*cl;
        touch.mx = dx/STICK_R; touch.my = dy/STICK_R;
        touch.sprint = (cl/STICK_R) > 0.92;
        if (knob) knob.style.transform=`translate(${dx}px,${dy}px)`;
      } else if (t.identifier===touch.lookId && G.phase==='playing'){
        yaw   -= (t.clientX-touch.lx) * 0.006 * settings.cam;
        pitch -= (t.clientY-touch.ly) * 0.006 * settings.cam * (settings.invert?-1:1);
        pitch = Math.max(-0.2, Math.min(1.1, pitch));
        touch.lx=t.clientX; touch.ly=t.clientY;
      }
    }
    e.preventDefault();
  }, {passive:false});
  const endTouch = (e)=>{
    for (const t of e.changedTouches){
      if (t.identifier===touch.moveId){ touch.moveId=null; touch.mx=0; touch.my=0; touch.sprint=false; if(stick) hide(stick); }
      if (t.identifier===touch.lookId){ touch.lookId=null; }
    }
  };
  canvas.addEventListener('touchend', endTouch);
  canvas.addEventListener('touchcancel', endTouch);
  // action buttons — a press-and-hold helper so Attack can charge
  const hold = (id, onDown, onUp)=>{
    const el = dom[id]; if (!el) return;
    el.addEventListener('touchstart', (e)=>{ enableTouch(); e.preventDefault(); e.stopPropagation(); onDown&&onDown(); }, {passive:false});
    el.addEventListener('touchend',   (e)=>{ e.preventDefault(); e.stopPropagation(); onUp&&onUp(); });
  };
  hold('tc-attack', ()=>{ if(G.phase==='playing'){ chargeT=0; charged=false; doAttack(); attackHeld=true; } }, ()=>{ attackHeld=false; });
  // hold the jump button to GLIDE — gliding needs a held input, and a one-shot
  // tap made the Windrider's Trial impossible to finish on a phone
  hold('tc-jump',
    ()=>{ keys[' '] = true; queueJump(); },
    ()=>{ keys[' '] = false; });
  hold('tc-dash',   ()=>{ if(G.phase==='playing') tryDash(new THREE.Vector3(-Math.sin(player.rotation.y),0,-Math.cos(player.rotation.y))); });
  hold('tc-interact',()=>{ if(G.phase==='playing'){ if(!dom.prompt.classList.contains('hidden')) tryInteract(); else cycleElement(-1); } });
  hold('tc-mimic',  ()=>{ if(G.phase==='playing') tryMimic(); });
  hold('tc-elemL',  ()=>{ if(G.phase==='playing') cycleElement(-1); });
  hold('tc-elemR',  ()=>{ if(G.phase==='playing') cycleElement(1); });
  hold('tc-map',    ()=>{ if(G.phase==='playing') openMap(); else if(G.phase==='map') closeMap(); });
  hold('tc-journal',()=>{ if(G.phase==='playing') openJournal(); else if(G.phase==='journal') closeJournal(); });
  hold('tc-menu',   ()=>{ if(G.phase==='playing') pause(); else if(G.phase==='paused') resume();
                          else if(G.phase==='reflect') closeReflection(); });
}

/* ============================================================ GAME FLOW / UI */
function show(el){ el && el.classList.remove('hidden'); }
function hide(el){ el && el.classList.add('hidden'); }

function toast(msg, kind='info', ms=2200){
  const t = dom.toast; t.textContent = msg; t.className = 'toast '+kind; t.classList.remove('hidden','out');
  clearTimeout(t._t1); clearTimeout(t._t2);
  t._t1 = setTimeout(()=>t.classList.add('out'), ms);
  t._t2 = setTimeout(()=>t.classList.add('hidden'), ms+320);
}

let tainerQueue = [], tainerActive = false;
function tainerSay(text, ms=4200){
  tainerQueue.push([text, ms]);
  if (!tainerActive) nextTainer();
}
function nextTainer(){
  if (!tainerQueue.length){ tainerActive=false; hide(dom.tainer); return; }
  tainerActive = true;
  const [text, ms] = tainerQueue.shift();
  dom['tainer-text'].textContent = text;
  show(dom.tainer);
  clearTimeout(nextTainer._t);
  nextTainer._t = setTimeout(nextTainer, ms);
}

/* -------- title / menus -------- */
function goTitle(){
  G.phase='title';
  hide(dom.hud); hide(dom['menu-sibling']); hide(dom['menu-class']); hide(dom.cinematic);
  hide(dom['menu-pause']); hide(dom['menu-settings']);
  show(dom['menu-title']);
  dom['btn-continue'].disabled = !localStorage.getItem(SAVE_KEY);
  document.exitPointerLock?.();
}

function newGame(){
  hide(dom['menu-title']);
  // full reset — G is a module singleton, so a second New Journey must not inherit old state
  Object.assign(G, {
    sibling:null, klass:null, hp:100, maxHp:100, stamina:100, tokens:0, weaponLevel:1,
    owned:[], equipped:null, bag:[], hotbar:new Array(10).fill(null),
    mastery:{ sword:1, bow:1, greatsword:1, dual:1, focus:1 },
    chests:{}, mechs:{loam:false,tide:false,arc:false,rime:false},
    bossDefeated:false, build:[], underground:false, dragonDefeated:false, hardMode:false,
    critBonus:0, combo:0, comboT:0,
    quest:{ main:0, mainDone:[], insights:[], sealed:[], side:[], daily:[], weekly:[], dailyDate:'', weeklyKey:'' },
    elements:{loam:false,tide:false,cinder:false,arc:false,rime:false}, activeElement:'none',
    glideUnlocked:false, stage:0,
    flags:{fished:false,firstKill:false,transformedOnce:false,campPassed:false,trialPassed:false,iceMelted:false,resistHinted:false},
    mimic:{state:'Normal',hp:0,maxHp:0,orbHeld:false,cooldown:0,savedHp:100},
  });
  worldBuilt = false;
  assignPick = null;
  refreshHotbarUI();
  G.phase='sibling'; show(dom['menu-sibling']);
}

/* sibling */
dom['menu-sibling'].addEventListener('click', (e)=>{
  const card = e.target.closest('.pick-card'); if(!card) return;
  document.querySelectorAll('.pick-card').forEach(c=>c.classList.remove('sel'));
  card.classList.add('sel');
  G.sibling = card.dataset.sib;
  G.phase = 'sibling-picked';
  setTimeout(()=>{
    if (G.phase !== 'sibling-picked') return;   // flow already moved on
    hide(dom['menu-sibling']); openClassSelect();
  }, 260);
});

/* class */
let previewClass = null;
function openClassSelect(){ G.phase='class'; show(dom['menu-class']); selectClass('sword'); }
function selectClass(key){
  previewClass = key;
  document.querySelectorAll('.class-item').forEach(i=>i.classList.toggle('sel', i.dataset.class===key));
  const c = CLASSES[key];
  dom['class-title'].textContent = c.name;
  dom['class-weapon'].textContent = 'Starting weapon: '+c.weapon;
  dom['class-desc'].textContent = c.desc;
  dom['class-stats'].innerHTML = Object.entries(c.stats).map(([k,v])=>
    `<li><span style="min-width:64px">${k}</span><span class="stat-track"><i style="width:${v/5*100}%"></i></span></li>`).join('');
  dom['class-complexity'].textContent = c.complexity;
  dom['btn-confirm-class'].disabled = false;
  // preview swatch
  dom['class-preview'].style.background = `radial-gradient(120% 120% at 50% 10%, ${classColor(key)}33, var(--panel))`;
  dom['class-preview'].innerHTML = `<div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:2.6rem">${classGlyph(key)}</div>`;
}
function classColor(k){ return {sword:'#cdd6e6',bow:'#8a5a2c',greatsword:'#9aa2ae',dual:'#7bd3c6',focus:'#b48bf0'}[k]; }
function classGlyph(k){ return {sword:'⚔️',bow:'\u{1f3f9}',greatsword:'\u{1f5e1}️',dual:'⚔️',focus:'\u{1f52e}'}[k]; }
dom['menu-class'].addEventListener('click',(e)=>{ const it=e.target.closest('.class-item'); if(it) selectClass(it.dataset.class); });
dom['btn-confirm-class'].addEventListener('click', ()=>{
  G.klass = previewClass;
  // every weapon is available from the start; your chosen discipline just
  // begins one Mastery rank ahead and is what you start holding
  unlockAllWeapons();
  G.mastery = { sword:1, bow:1, greatsword:1, dual:1, focus:1 };
  G.mastery[G.klass] = 2;
  G.equipped = WEAPONS[G.klass][0].id;
  G.hotbar[0] = { kind:'weapon', id:G.equipped };
  addItem('emberjam', 2);                              // starter snack — shows the consumable loop
  hotbarAutoAdd({ kind:'item', id:'emberjam' });
  refreshHotbarUI();
  hide(dom['menu-class']);
  startOpening();
});

/* -------- opening cinematic -------- */
const OPENING = [
  ()=>[`Two of you set out from Willowmere at first light — ${sibName()} and ${lostName()}, side by side as always.`, cineScene('dawn')],
  ()=>[`Then the sky went quiet. Not calm — *still*. And from that stillness stepped Mourne, the Stillard, who believes a world that never changes can never suffer.`, cineScene('mourne')],
  ()=>[`“Be still,” he said, almost kindly — and the ground split between you. When the light cleared, ${lostName()} was gone.`, cineScene('split')],
  ()=>[`Seasons turned. You searched every road back to the vale, and found only its lake, glittering as if it were hiding something.`, cineScene('time')],
  ()=>[`So you did the only thing left to do. You sat at the water’s edge... and you cast a line.`, cineScene('fish')],
];
let cineIdx = 0;
function startOpening(){
  hide(dom['menu-sibling']);       // regardless of how fast the flow got here
  G.phase='cinematic'; cineIdx=0; show(dom.cinematic); playCine();
}
function playCine(){
  if (cineIdx >= OPENING.length){ endOpening(); return; }
  const [text, art] = OPENING[cineIdx]();
  dom['cine-text'].innerHTML = fmt(text);
  dom['cine-art'].style.background = art;
}
function fmt(s){ return s.replace(/\*(.+?)\*/g,'<em>$1</em>'); }
function cineScene(kind){
  const g = {
    dawn:  'linear-gradient(180deg,#ffd18a,#ff9a6b 60%,#6b4a7a)',
    mourne:'radial-gradient(circle at 50% 40%,#3a2f55,#0a0a12)',
    split: 'linear-gradient(90deg,#20304a 48%,#0a0a12 48% 52%,#3a2a20 52%)',
    time:  'linear-gradient(180deg,#7fb0c8,#cfe6ef)',
    fish:  'linear-gradient(180deg,#bfe3ef,#3aa7c4 70%,#1d6b82)',
  }[kind];
  return g;
}
dom['cine-next'].addEventListener('click', ()=>{ cineIdx++; playCine(); });
dom['cine-skip'].addEventListener('click', ()=>{ endOpening(); });

function endOpening(){
  hide(dom.cinematic);
  enterWorld();
}

function sibName(){ return G.sibling==='wren'?'Wren':'Cael'; }
function lostName(){ return G.sibling==='wren'?'Cael':'Wren'; }

/* -------- enter world -------- */
function enterWorld(){
  ensureWorld();
  G.phase='playing';
  show(dom.hud); dom.hud.setAttribute('aria-hidden','false');
  applySettings();
  updateHUD();
  refreshElementWheel();
  ensureQuests();
  refreshObjective();
  // position player at lakeside
  player.position.set(lakePos.x + 12, 0, lakePos.z + 2);
  yaw = Math.PI*0.5;
  tainerSay(`Psst — down here! ...okay you can’t hear me yet. Go on, ${sibName()}. Cast your line at the lake.`, 5200);
  toast('Click the game to capture the mouse and look around. Esc frees the cursor (and pauses). Scroll to zoom.', 'info', 5200);
}

/* ------------------------------------------------------------- interaction */
let currentInteract = null;
function updateInteract(){
  if (G.phase!=='playing'){ hide(dom.prompt); return; }
  // fishing prompt at lake
  let best=null, bestD=1e9;
  // lake fishing (stage 0)
  if (!G.flags.fished){
    // any shoreline spot works. (The old 10.5–13.5 ring silently vanished the
    // moment you stepped toward the water — deep water already stops you at ~9.)
    const d = Math.hypot(player.position.x-lakePos.x, player.position.z-lakePos.z);
    if (d < 15){ best = { kind:'fish' }; bestD=0; }
  }
  for (const it of interactables){
    if (it.cond && !it.cond()) continue;
    const d = Math.hypot(player.position.x-it.pos.x, player.position.z-it.pos.z);
    if (d < it.radius && d < bestD){ best=it; bestD=d; }
  }
  currentInteract = best;
  if (best){
    dom['prompt-key'].textContent = best.key || 'E';
    dom['prompt-text'].textContent = best.kind==='fish' ? 'Cast your line' : best.label();
    show(dom.prompt);
  } else hide(dom.prompt);
}
function tryInteract(){
  if (!currentInteract) return;
  if (currentInteract.kind==='fish'){ doFishing(); return; }
  currentInteract.onUse();
}

function doFishing(){
  G.flags.fished = true;
  hide(dom.prompt);
  toast('You feel a tug on the line...', 'info', 2000);
  // little splash particles
  spawnBurst(new THREE.Vector3(lakePos.x, 0.4, lakePos.z), 0x8fd7f0, 26);
  setTimeout(()=>{
    tainerMesh.visible = true;
    tainerMesh.position.set(player.position.x, 2.2, player.position.z + 2);
    tainerSay('Whoa — hi! You pulled me right out of the reeds! I’m Tainer. A Glimmer. A... a spark of the first light, if you want the long version.', 6000);
    setTimeout(()=>tainerSay('You’re looking for someone. I can feel it. I’ll help — that’s kind of what I’m for. First, that carved stone up the hill? Touch it. Trust me.', 6500), 6200);
    G.stage = 1;
    advanceMain('fished');
    // point player toward first wardstone
  }, 1400);
}

/* ------------------------------------------------------------- elements */
function unlockElement(elem, ws){
  if (G.elements[elem]) return;
  G.elements[elem] = true;
  ws.unlocked = true;
  ws.sig.material.color.set(ELEMENTS[elem].color);
  ws.sig.material.emissive.set(ELEMENTS[elem].color);
  ws.sig.material.emissiveIntensity = 1;
  ws.glow.intensity = 1.6;
  sfx.attune();
  spawnBurst(ws.pos.clone().setY(3), ELEMENTS[elem].color, 34);
  setActiveElement(elem);
  refreshElementWheel();
  toast(`${ELEMENTS[elem].name} attuned!  Switch elements with Q (next) and E (previous).`, 'good', 3200);
  tainerSay(`${ELEMENTS[elem].name}! Feel that? Now your strikes carry it. Switch elements with Q and E. Some things only answer to the right one.`, 5600);
  advanceMain('firstElement');
  if (elem==='cinder' && G.stage===1){
    G.stage = 2;
    tainerSay('See that ice wall? Cinder melts Rime. Equip Cinder (Q/E) and give it a few good hits!', 4600);
  }
}
function setActiveElement(elem){
  const changed = G.activeElement !== elem;
  G.activeElement = elem;
  tintWeapon(elem);
  updateHUD();          // syncs the element indicator, hotbar highlights, and weapon chip
  if (changed && elem !== 'none') noteEvent('element', 1);
}
function tintWeapon(elem){
  const held = player?.userData?.weapons; if(!held) return;
  const col = elem==='none' ? 0xcdd6e6 : ELEMENTS[elem].color;
  for (const wp of [held.right, held.left]){
    if (!wp) continue;
    wp.traverse(o=>{ if(o.isMesh && o.material && o.material.emissive){ o.material.emissive.setHex(elem==='none'?0x000000:col); o.material.emissiveIntensity = elem==='none'?0:0.5; }});
  }
}
function cycleElement(dir){
  const avail = ['none', ...Object.keys(ELEMENTS).filter(e=>G.elements[e])];
  if (avail.length<=1){ toast('No elements attuned yet.', 'info', 1600); return; }
  let i = avail.indexOf(G.activeElement); i = (i+dir+avail.length)%avail.length;
  setActiveElement(avail[i]);
}
/* ---------------------------------------------- bag (stackable inventory) */
function addItem(id, n=1){
  if (!isValidItemId(id) || n<=0) return 0;
  const lim = stackLimit(id);
  let left = n;
  for (const s of G.bag){
    if (s.id===id && s.n<lim){ const take=Math.min(left, lim-s.n); s.n+=take; left-=take; if(!left) break; }
  }
  while (left>0){
    if (G.bag.length>=60){ toast('Your bag is full!','bad',2200); break; }
    const take=Math.min(left,lim); G.bag.push({id, n:take}); left-=take;
  }
  const added = n-left;
  if (added>0){ toast(`+${added} ${itemDef(id).name}`, 'good', 1500); if (dom.tracker) updateHUD();
    if (itemDef(id).type==='material') noteEvent('gather', added, id); }   // material guard prevents reward recursion
  return added;
}
function countItem(id){ return G.bag.reduce((a,s)=>a+(s.id===id?s.n:0),0); }
function removeItem(id, n=1){
  let need=n;
  for (let i=G.bag.length-1; i>=0 && need>0; i--){
    const s=G.bag[i]; if (s.id!==id) continue;
    const take=Math.min(need,s.n); s.n-=take; need-=take; if(!s.n) G.bag.splice(i,1);
  }
  return n-need;
}
function useItem(id){
  const d=itemDef(id); if(!d) return;
  if (d.type==='consumable' && d.heal){
    if (countItem(id)<1){ toast(`No ${d.name} left.`,'info',1500); return; }
    if (G.hp>=G.maxHp){ toast('Already at full health.','info',1500); return; }
    removeItem(id,1);
    G.hp=Math.min(G.maxHp, G.hp+d.heal);
    sfx.token();
    spawnBurst(player.position.clone().add(new THREE.Vector3(0,1.2,0)), 0x8fe6a0, 14, 0.8, true);
    updateHUD();
    noteEvent('consume', 1);
    toast(`${d.name}: +${d.heal} health.`, 'good', 1800);
  } else if (d.type==='consumable' && d.maxhp){
    if (countItem(id)<1){ toast(`No ${d.name} left.`,'info',1500); return; }
    removeItem(id,1);
    G.maxHp += d.maxhp; G.hp = Math.min(G.maxHp, G.hp + d.maxhp);
    sfx.attune();
    spawnBurst(player.position.clone().add(new THREE.Vector3(0,1.2,0)), 0xfff2c0, 20, 1, true);
    updateHUD();
    toast(`${d.name}: max health now ${G.maxHp}!`, 'good', 2400);
  } else if (d.type==='tool'){
    toast(`${d.name} — put it on your hotbar (1–0) and swing to dig or gather.`, 'info', 3000);
  } else toast(`${d.name} can't be used yet.`, 'info', 1600);
}

/* -------------------------------------------------------- crafting (Phase E) */
function nearForge(){
  if (!player) return false;
  for (const f of forges) if (Math.hypot(player.position.x-f.x, player.position.z-f.z) < 4.5) return true;
  return false;
}
function recipeAvailable(r){
  if (r.station==='forge' && !nearForge()) return { ok:false, why:'Stand near a Forge' };
  if (r.unlock && !G[r.unlock]) return { ok:false, why:'Locked' };
  if (r.element && G.activeElement!==r.element) return { ok:false, why:`Equip ${ELEMENTS[r.element].name}` };
  for (const ing of r.in) if (countItem(ing.id) < ing.n) return { ok:false, why:'Need materials' };
  return { ok:true };
}
function craft(r){
  const a = recipeAvailable(r);
  if (!a.ok){ toast(a.why, 'info', 1800); return false; }
  for (const ing of r.in) removeItem(ing.id, ing.n);
  const added = addItem(r.out.id, r.out.n);
  sfx.attune();
  spawnFloater('+'+r.out.n+' '+itemDef(r.out.id).name, player.position.clone().add(new THREE.Vector3(0,2,0)), '#8fe6a0');
  noteEvent('craft', 1);
  if (r.station==='forge') noteEvent('smelt', 1);
  // tools and blocks go straight to the hotbar so they're findable
  const outDef = itemDef(r.out.id);
  if (outDef && (outDef.type==='tool' || outDef.type==='block')) hotbarAutoAdd({ kind:'item', id:r.out.id });
  if (outDef && outDef.type==='tool')
    tainerSay(`${outDef.name} made! It's on your hotbar — press its number, then swing at the ground to dig or at nodes to gather.`, 6000);
  if (!G.flags.firstCraft){ G.flags.firstCraft=true;
    tainerSay('You made something! Tools speed up gathering, blocks let you build, and a Forge unlocks iron. Keep at it.', 5200); }
  return added>0 || r.out.id.startsWith('block_');
}

/* hotbar: filled slots act (weapon/element/consumable). Elements are normally
   cycled with Q/E, but saved element entries remain usable. */
function selectHotbar(i){
  activeSlot = i;
  const entry = G.hotbar[i];
  if (!entry){ refreshHotbarUI(); return; }
  if (entry.kind==='element'){
    const d = itemDef(entry.id);
    if (d && G.elements[d.elem]) setActiveElement(d.elem);
    else toast('Not attuned yet.', 'info', 1400);
  } else if (entry.kind==='weapon'){
    if (G.owned.includes(entry.id)){ G.equipped=entry.id; tintWeapon(G.activeElement); updateHUD(); toast(`${findWeapon(entry.id).name} equipped.`,'good',1200); }
  } else if (entry.kind==='item'){
    const d = itemDef(entry.id);
    if (d && d.type==='tool'){
      toast(`${d.name} ready — swing at bare ground to dig, or at trees / rock / ore to gather.`, 'info', 3000);
      if (!G.flags.toolHint){ G.flags.toolHint = true;
        tainerSay(`Pick in hand! Face open ground and swing to dig. Swing at trees for Timber, rock and ore for Stone and metal.`, 5600); }
    }
    else if (d && d.type==='block') toast(`${d.name} ready — attack to place it in front of you.`, 'info', 2600);
    else useItem(entry.id);
  }
  refreshHotbarUI();
}

/* ------------------------------------------------------- hotbar UI (HUD) */
const CLASS_GLYPH = { sword:'🗡️', bow:'🏹', greatsword:'⚔️', dual:'🗡️', focus:'🔮' };
let assignPick = null;      // {kind,id} chosen in the inventory, awaiting a slot
function elemColorCss(elem){ return '#'+ELEMENTS[elem].color.toString(16).padStart(6,'0'); }
function slotVisual(btn, entry, idx){
  btn.className = 'hslot';
  btn.innerHTML = `<span class="hkey">${(idx+1)%10}</span>`;
  if (idx===activeSlot && G.phase==='playing') btn.classList.add('sel');
  if (assignPick && G.phase==='inventory') btn.classList.add('assignable');
  if (!entry){ btn.classList.add('empty'); btn.title = 'Empty slot'; return; }
  if (entry.kind==='weapon'){
    const w = findWeapon(entry.id);
    if (!w){ btn.classList.add('empty'); return; }
    const wt = weaponType(entry.id);
    btn.innerHTML += (CLASS_GLYPH[wt]||'🗡️') + `<span class="htier">M${masteryOf(wt)}</span>`;
    btn.title = `${w.name} — ${CLASSES[wt]?.name||''} · ${w.blurb||''}`;
    if (G.equipped===entry.id) btn.classList.add('active');
  } else if (entry.kind==='element'){
    const d = itemDef(entry.id);
    btn.innerHTML += `<span style="color:${elemColorCss(d.elem)}">${d.icon}</span>`;
    btn.title = `${d.name} — element`;
    if (G.activeElement===d.elem) btn.classList.add('active');
    if (!G.elements[d.elem]) btn.classList.add('dim');
  } else {
    const d = itemDef(entry.id), n = countItem(entry.id);
    btn.innerHTML += d.icon + `<span class="hcount">${n}</span>`;
    btn.title = `${d.name}${d.desc ? ' — '+d.desc : ''}`;
    if (!n) btn.classList.add('dim');
  }
}
function refreshHotbarUI(){
  if (dom.hotbar) [...dom.hotbar.children].forEach((b,i)=> slotVisual(b, G.hotbar[i], i));
  if (dom['inv-hotbar'] && G.phase==='inventory')
    [...dom['inv-hotbar'].children].forEach((b,i)=> slotVisual(b, G.hotbar[i], i));
}
let dragFromSlot = null;      // set while dragging an entry from one slot to another
function assignToSlot(i){
  if (!assignPick) return false;
  G.hotbar[i] = assignPick; assignPick = null;
  if (dragFromSlot!=null && dragFromSlot!==i) G.hotbar[dragFromSlot] = null;   // moved, not copied
  dragFromSlot = null;
  sfx.ui(); renderInv(); refreshHotbarUI();
  toast('Assigned.', 'good', 1200);
  return true;
}
function buildHotbarUI(){
  for (const holder of [dom.hotbar, dom['inv-hotbar']]){
    if (!holder) continue;
    holder.innerHTML = '';
    for (let i=0;i<10;i++){
      const b = document.createElement('button');
      b.type='button'; b.dataset.slot = i;
      b.onclick = ()=>{
        if (assignPick){ assignToSlot(i); return; }
        if (G.phase==='playing') selectHotbar(i);
        else if (G.phase==='inventory' && G.hotbar[i]){
          G.hotbar[i]=null; renderInv(); refreshHotbarUI();   // click a filled slot to clear it
        }
      };
      b.draggable = true;
      b.addEventListener('dragstart', ()=>{
        if (G.hotbar[i]){ assignPick = G.hotbar[i]; dragFromSlot = i; refreshHotbarUI(); }
      });
      b.addEventListener('dragend', ()=>{
        // drop already handled placement; this only clears an abandoned drag
        if (dragFromSlot!=null){ dragFromSlot = null; assignPick = null; refreshHotbarUI(); }
      });
      b.addEventListener('dragover', e=>{ if (assignPick) e.preventDefault(); });
      b.addEventListener('drop', e=>{ e.preventDefault(); assignToSlot(i); });
      holder.appendChild(b);
    }
  }
  refreshHotbarUI();
}
function hotbarAutoAdd(entry){
  if (G.hotbar.some(s=>s && s.kind===entry.kind && s.id===entry.id)) return;
  const i = G.hotbar.findIndex(s=>!s);
  if (i>=0){ G.hotbar[i]=entry; refreshHotbarUI(); }
}

function refreshElementWheel(){
  // the standalone element wheel was replaced by the unified hotbar (Phase B);
  // element state now renders through refreshHotbarUI
  refreshHotbarUI();
}

/* ------------------------------------------------------------- combat */
let atkAnim = 0;
let swingSide = 0;        // dual wield alternates hands for a combo feel
let playerAtkCd = 0;      // per-weapon swing cooldown (weapon "speed")
function doAttack(){
  if (G.phase!=='playing') return;
  // placing a block from the active hotbar slot takes priority over swinging
  if (G.mimic.state!=='Transformed' && tryPlaceFromHotbar()) return;
  // a TOOL on the active hotbar slot turns the swing into gather / dig / break,
  // so every class (including ranged ones) can work the world
  if (G.mimic.state!=='Transformed' && tryToolSwing()) return;
  const inMimic = G.mimic.state==='Transformed';
  const c = activeProfile();
  const mods = equippedMods();
  if (!inMimic){
    if (playerAtkCd > 0) return;            // weapon speed gates the swing
    playerAtkCd = mods.cd;
  }
  const dmgBase = inMimic ? 22 : weaponPower(equippedWeapon());
  atkAnim = 1;
  if (!inMimic && equippedType()==='dual') swingSide ^= 1;   // alternate hands
  sfx.swing();
  if (!inMimic && c.ranged){
    fireProjectile(dmgBase);
  } else {
    // small committed lunge toward the strike
    const lf = new THREE.Vector3(Math.sin(player.rotation.y), 0, Math.cos(player.rotation.y));
    pv.x += lf.x*2.4; pv.z += lf.z*2.4;
    meleeHit(inMimic ? 3.0 : c.range*mods.reach, inMimic ? 1.6 : c.arc*mods.arc, dmgBase);
  }
}
/* the tool currently selected on the hotbar, if any (pick / axe) */
function activeToolDef(){
  const e = G.hotbar[activeSlot];
  if (!e || e.kind!=='item') return null;
  const d = itemDef(e.id);
  return (d && d.type==='tool') ? d : null;
}
/* tool swing: gather a node in front, else break a placed block, else dig ground */
function tryToolSwing(){
  const tool = activeToolDef();
  if (!tool) return false;
  atkAnim = 1; sfx.swing();
  const fwd = new THREE.Vector3(Math.sin(player.rotation.y),0,Math.cos(player.rotation.y));
  swingVfx(fwd);
  if (harvestHit(player.position, fwd, G.activeElement)) return true;
  tryBreakOrDig(fwd);
  return true;
}
function meleeHit(range, arc, dmg){
  const fwd = new THREE.Vector3(Math.sin(player.rotation.y),0,Math.cos(player.rotation.y));
  // ice wall melt
  if (iceWall && G.activeElement==='cinder' && !G.flags.iceMelted){
    const d = Math.hypot(player.position.x-iceWall.position.x, player.position.z-iceWall.position.z);
    const to = new THREE.Vector3().subVectors(iceWall.position, player.position).setY(0).normalize();
    if (d<4.5 && fwd.dot(to)>0.3){ meltIce(); }
  }
  // elemental mechanisms: strike with the matching element
  for (const m of mechanisms){
    if (m.done) continue;
    const d = Math.hypot(player.position.x-m.pos.x, player.position.z-m.pos.z);
    if (d > m.r) continue;
    const to = new THREE.Vector3().subVectors(m.pos, player.position).setY(0).normalize();
    if (d>2 && fwd.dot(to)<0.2) continue;
    if (G.activeElement === m.elem) activateMechanism(m);
    else toast(`This mechanism answers only to ${ELEMENTS[m.elem].name} (${ELEMENTS[m.elem].sigil}).`, 'info', 2400);
  }
  let struck = false;
  for (const e of enemies){
    if (!e.alive) continue;
    const to = new THREE.Vector3().subVectors(e.mesh.position, player.position).setY(0);
    const d = to.length(); if (d>range+e.r) continue;
    to.normalize();
    if (fwd.dot(to) < Math.cos(arc)) continue;
    damageEnemy(e, dmg); struck = true;
  }
  // no enemy hit? the same swing gathers a node, else breaks a block / digs
  if (!struck){
    if (!harvestHit(player.position, fwd, G.activeElement)) tryBreakOrDig(fwd);
  }
  swingVfx(fwd);
}
function fireProjectile(dmg){
  const fwd = new THREE.Vector3(Math.sin(player.rotation.y),0,Math.cos(player.rotation.y));
  const muzzle = player.position.clone().add(new THREE.Vector3(0,1.3,0));
  // aim assist: nudge toward nearest enemy in front. Shots are flat-flying, so
  // aim in TRUE 3D at the target's torso — otherwise, on rolling terrain, a
  // target standing lower than the shooter gets sailed straight over.
  if (settings.aim){
    let best=null,bd=1e9;
    for (const e of enemies){ if(!e.alive) continue;
      const to=new THREE.Vector3().subVectors(e.mesh.position,player.position).setY(0); const d=to.length();
      if (d<40 && fwd.dot(to.clone().normalize())>0.7 && d<bd){best=e;bd=d;} }
    if (best){
      const aimAt = best.mesh.position.clone().add(new THREE.Vector3(0, best.boss?2.2:0.9, 0));
      fwd.copy(aimAt.sub(muzzle).normalize());
    }
  }
  const col = G.activeElement==='none'?0xffe6a0:ELEMENTS[G.activeElement].color;
  const m = new THREE.Mesh(new THREE.SphereGeometry(0.16,8,8),
    new THREE.MeshStandardMaterial({color:col,emissive:col,emissiveIntensity:1}));
  m.position.copy(muzzle).add(fwd.clone().multiplyScalar(0.8));
  scene.add(m);
  projectiles.push({ mesh:m, vel:fwd.multiplyScalar(38), life:1.6, dmg, elem:G.activeElement,
    pierce: hasPerk('pierce') ? 1 : 0, hitList:null });
}
function swingVfx(fwd){
  const col = G.activeElement==='none'?0xffffff:ELEMENTS[G.activeElement].color;
  spawnBurst(player.position.clone().add(new THREE.Vector3(0,1.2,0)).add(fwd.clone().multiplyScalar(1.4)), col, 8, 0.5);
}
function damageEnemy(e, dmg){
  if (!e.alive) return;
  let mult = 1;
  if (e.elem){
    if (G.activeElement === e.elem) mult = 0.25;                       // resists its own element
    else if (COUNTER[e.elem] && G.activeElement === COUNTER[e.elem]) mult = 1.75;   // weak to its counter
    if (mult < 1 && !G.flags.resistHinted){
      G.flags.resistHinted = true;
      tainerSay('Its crystals drink that element! Try the opposite one — Cinder against Rime, Tide against Arc.', 5200);
    }
  }
  if (e.boss && e.weak > 0) mult *= 2;                                 // crystal exposed after the slam
  // combo: consecutive player hits add a small ramping bonus ('comboUp' doubles it)
  G.combo += hasPerk('comboUp') ? 2 : 1;
  G.comboT = 2; mult *= 1 + Math.min(G.combo,12)*0.03;
  updateCombo();
  // 'stonebane' — brutal against the heavy Stonekin
  if (hasPerk('stonebane') && (e.kind==='boulder' || e.elem==='loam')) mult *= 1.4;
  // crit: a chance for bonus damage (scales with weapon level)
  let crit = false;
  if (Math.random() < critChance()){ mult *= 1.8; crit = true; }
  e.hitCd = 0.12;
  e.state='chase'; e.target=player;
  hitstop = Math.max(hitstop, e.boss ? 0.06 : 0.04);   // impact freeze-frame
  const fxCol = crit ? 0xffd24a : (mult>1 ? 0xfff0a0 : (mult<1 ? 0x8a90a0 : 0xffffff));
  applyEnemyDamage(e, dmg*mult, fxCol, crit);
  // 'stagger' — heavy knockback
  if (hasPerk('stagger') && e.alive && !e.boss){
    const away = new THREE.Vector3().subVectors(e.mesh.position, player.position).setY(0).normalize();
    e.mesh.position.x += away.x*1.6; e.mesh.position.z += away.z*1.6;
    spawnBurst(e.mesh.position.clone().setY(1), 0xd6dae0, 8, 0.8);
  }
  // 'chain' — the strike arcs on to a nearby foe
  if (hasPerk('chain') && !chaining){
    chaining = true;
    let best=null, bd=1e9;
    for (const o of enemies){ if(o===e||!o.alive) continue;
      const d=o.mesh.position.distanceTo(e.mesh.position); if(d<6 && d<bd){bd=d;best=o;} }
    if (best){ spawnBurst(best.mesh.position.clone().setY(1), 0xb48bf0, 10, 0.8);
      applyEnemyDamage(best, dmg*mult*0.5, 0xb48bf0); }
    chaining = false;
  }
  // reactions (Phase G): a different element than the one already on the target
  tryReaction(e);
}
let chaining = false;   // guards the chain perk against recursing
/* core damage: floating number, particles, defeat. Shared by swings, projectiles,
   traps, statuses, and reactions so damage numbers appear everywhere. */
function applyEnemyDamage(e, dmg, col=0xffffff, crit=false){
  if (!e.alive) return;
  e.hp -= dmg;
  sfx.hit();
  spawnFloater((crit?'✦':'')+Math.round(dmg), e.mesh.position.clone().add(new THREE.Vector3(0,1.5,0)), colCss(col));
  spawnBurst(e.mesh.position.clone().add(new THREE.Vector3(0,1,0)), col, crit?12:6, 0.5);
  if (e.hp<=0) defeatEnemy(e);
}
function colCss(c){ return '#'+c.toString(16).padStart(6,'0'); }
function critChance(){ return 0.10 + (masteryOf(equippedType())-1)*0.02 + (equippedMods().crit||0) + (G.critBonus||0); }

/* ------------------------------------------------ elemental reactions (orig.)
   Hitting a creature stamps your element on it briefly; landing a *different*
   element triggers a named reaction. Original to Emberkin — not copied. */
const REACTIONS = {
  'cinder+tide':  { name:'Steambloom',      col:0xd8f0f5, kind:'aoe',   dmg:26 },
  'cinder+rime':  { name:'Thermal Shatter', col:0xfff0a0, kind:'heavy', dmg:50 },
  'arc+tide':     { name:'Galvanize',       col:0xcdb4ff, kind:'chain', dmg:22, status:'shock' },
  'cinder+loam':  { name:'Emberforge',      col:0xf0a24a, kind:'heavy', dmg:34 },
  'loam+rime':    { name:'Frostcrack',      col:0x9fe6f5, kind:'aoe',   dmg:24, status:'chill' },
  'arc+rime':     { name:'Static Frost',    col:0xbfe6ff, kind:'chain', dmg:26, status:'shock' },
  'loam+tide':    { name:'Bloomsurge',      col:0x9fe0a0, kind:'aoe',   dmg:20 },
  'arc+loam':     { name:'Groundfault',     col:0xd0c060, kind:'heavy', dmg:30, status:'shock' },
  'arc+cinder':   { name:'Firestorm',       col:0xff9a5a, kind:'aoe',   dmg:28, status:'burn' },
  'rime+tide':    { name:'Deepfreeze',      col:0x8fd7f0, kind:'heavy', dmg:28, status:'chill' },
};
function pairKey(a,b){ return [a,b].sort().join('+'); }
function reactionCore(e){
  const el = G.activeElement;
  if (el==='none') return;
  const prev = (e.aura && e.aura.t>0) ? e.aura.elem : null;
  if (prev && prev!==el){
    const rx = REACTIONS[pairKey(prev, el)];
    e.aura = null;
    if (rx) triggerReaction(e, rx);
  } else {
    e.aura = { elem:el, t:4 };
  }
}
function triggerReaction(e, rx){
  spawnFloater(rx.name, e.mesh.position.clone().add(new THREE.Vector3(0,2.2,0)), colCss(rx.col));
  spawnBurst(e.mesh.position.clone().setY(1), rx.col, 22, 1.3, true);
  if (!settings.motion) shake(0.22);
  sfx.attune();
  applyEnemyDamage(e, rx.dmg * (hasPerk('elemental') ? 1.35 : 1), rx.col);   // 'elemental' perk
  if (rx.status) applyStatus(e, rx.status, 3);
  if (rx.kind==='aoe' || rx.kind==='chain'){
    const rad = rx.kind==='chain' ? 7 : 5;
    for (const o of enemies){
      if (o===e || !o.alive) continue;
      if (o.mesh.position.distanceTo(e.mesh.position) < rad){
        applyEnemyDamage(o, rx.dmg*0.6, rx.col);
        if (rx.status) applyStatus(o, rx.status, 2.4);
      }
    }
  }
  noteEvent('react', 1);
  if (!G.flags.firstReaction){ G.flags.firstReaction=true;
    advanceMain('firstReaction');
    tainerSay(`A reaction! Hit with one element, then a different one — ${rx.name}! Mix elements for big bonus damage.`, 5600); }
}
/* tryReaction: called from damageEnemy after the base hit lands. */
function tryReaction(e){ reactionCore(e); }
/* ------------------------------------------------- exploration (Phase H) */
const FOG_CELL = 14;
const explored = new Set();
const POI_STYLE = {
  lake:['#41b6c4','~'], camp:['#ef5f6b','▲'], boss:['#b48bf0','☠'], npc:['#f5c168','✦'],
  ward:['#7bd3c6','◆'], barrow:['#8a6a45','▼'], cavern:['#8fe0e6','◈'],
};
function markExplored(){
  if (!player) return;
  const cx = Math.round(player.position.x/FOG_CELL), cz = Math.round(player.position.z/FOG_CELL);
  const before = explored.size;
  for (let dx=-1;dx<=1;dx++) for (let dz=-1;dz<=1;dz++) explored.add((cx+dx)+','+(cz+dz));
  const gained = explored.size - before;
  if (gained > 0) noteEvent('explore', gained);
}
function isExplored(x,z){ return explored.has(Math.round(x/FOG_CELL)+','+Math.round(z/FOG_CELL)); }
function drawMinimap(){
  const cv = dom.minimap; if (!cv || G.phase!=='playing') return;
  const ctx = cv.getContext('2d'), W=cv.width, H=cv.height, cxp=W/2, cyp=H/2;
  const RANGE = 62, scale = (W/2)/RANGE;
  ctx.clearRect(0,0,W,H);
  ctx.fillStyle = G.underground ? '#0c0a10' : '#12331f'; ctx.fillRect(0,0,W,H);
  const px = player.position.x, pz = player.position.z;
  // POIs
  for (const p of POIS){
    const dx=(p.x-px)*scale, dz=(p.z-pz)*scale;
    if (Math.hypot(dx,dz) > W/2-4) continue;
    if (!isExplored(p.x,p.z)) continue;
    const st = POI_STYLE[p.kind]||['#cccccc','•'];
    ctx.fillStyle = st[0]; ctx.font='9px sans-serif'; ctx.textAlign='center'; ctx.textBaseline='middle';
    ctx.fillText(st[1], cxp+dx, cyp+dz);
  }
  // enemies
  ctx.fillStyle = '#ef5f6b';
  for (const e of enemies){ if(!e.alive)continue;
    const dx=(e.mesh.position.x-px)*scale, dz=(e.mesh.position.z-pz)*scale;
    if (Math.hypot(dx,dz) > W/2-3) continue;
    ctx.beginPath(); ctx.arc(cxp+dx, cyp+dz, e.boss?3:1.8, 0, 7); ctx.fill();
  }
  // forges
  ctx.fillStyle = '#f0713b';
  for (const f of forges){ const dx=(f.x-px)*scale, dz=(f.z-pz)*scale; if(Math.hypot(dx,dz)<W/2-3){ ctx.fillRect(cxp+dx-1.5,cyp+dz-1.5,3,3); } }
  // player arrow — points along the true heading. The map is world-locked
  // (world +x → screen right, world +z → screen down), and the player faces
  // world dir (sin θ, cos θ), so the arrow tip goes exactly there.
  drawHeadingArrow(ctx, cxp, cyp, player.rotation.y, 6, '#eef3ff');
  ctx.strokeStyle='rgba(255,255,255,.15)'; ctx.strokeRect(0.5,0.5,W-1,H-1);
}
function drawHeadingArrow(ctx, cx, cy, rotY, len, color){
  const fx = Math.sin(rotY), fy = Math.cos(rotY);   // screen-space facing (unit)
  const pxp = -fy, pyp = fx;                          // perpendicular
  ctx.fillStyle = color;
  ctx.beginPath();
  ctx.moveTo(cx + fx*len, cy + fy*len);                        // tip = heading
  ctx.lineTo(cx - fx*len*0.7 + pxp*len*0.6, cy - fy*len*0.7 + pyp*len*0.6);
  ctx.lineTo(cx - fx*len*0.7 - pxp*len*0.6, cy - fy*len*0.7 - pyp*len*0.6);
  ctx.closePath(); ctx.fill();
}
function drawWorldMap(){
  const cv = dom.worldmap; if (!cv) return;
  const ctx = cv.getContext('2d'), W=cv.width, H=cv.height;
  ctx.clearRect(0,0,W,H); ctx.fillStyle='#0a0f18'; ctx.fillRect(0,0,W,H);
  // map covers the current region
  const under = G.underground;
  const cxw = under?CAVERN.x:0, czw = under?CAVERN.z:0, span = under?130:200;
  const toX = (x)=> (x-cxw)/span*0.5*W + W/2;
  const toY = (z)=> (z-czw)/span*0.5*H + H/2;
  // explored fog: draw revealed cells
  ctx.fillStyle = under ? '#1a1622' : '#1f4a2c';
  for (const key of explored){
    const [gx,gz] = key.split(',').map(Number);
    const wx = gx*FOG_CELL, wz = gz*FOG_CELL;
    if (Math.abs(wx-cxw)>span || Math.abs(wz-czw)>span) continue;
    const s = FOG_CELL/span*0.5*W;
    ctx.fillRect(toX(wx)-s/2, toY(wz)-s/2, s+1, s+1);
  }
  // POIs (only explored)
  for (const p of POIS){
    if (!isExplored(p.x,p.z)) continue;
    if (Math.abs(p.x-cxw)>span || Math.abs(p.z-czw)>span) continue;
    const st = POI_STYLE[p.kind]||['#ccc','•'];
    ctx.fillStyle=st[0]; ctx.font='16px sans-serif'; ctx.textAlign='center'; ctx.textBaseline='middle';
    ctx.fillText(st[1], toX(p.x), toY(p.z));
    ctx.fillStyle='rgba(238,243,255,.7)'; ctx.font='9px sans-serif';
    ctx.fillText(p.name, toX(p.x), toY(p.z)+12);
  }
  // player — same world-locked heading arrow as the minimap
  drawHeadingArrow(ctx, toX(player.position.x), toY(player.position.z), player.rotation.y, 11, '#f5c168');
  ctx.strokeStyle='rgba(255,255,255,.12)'; ctx.strokeRect(0.5,0.5,W-1,H-1);
}
/* ------------------------------------------------------- journal / quest UI */
let journalTab = 'story';
const GUIDE = [
  ['Move &amp; look', 'Walk with <b>W A S D</b>. Sprint <b>Shift</b>. Look with the <b>mouse</b> (or drag on touch). Jump <b>Space</b> — again in the air to <b>double-jump</b>. <b>Double-tap</b> a move key to <b>dash</b>.'],
  ['Fight', 'Attack with <b>left-click</b> or <b>J</b>. <b>Hold</b> attack to unleash a <b>charged strike</b>. Land hits in a row to build a <b>combo</b>.'],
  ['Elements &amp; reactions', 'Attune elements at Wardstones, then switch with <b>Q</b> (next) and <b>E</b> (previous). Hit a foe with one element, then a <b>different</b> one, to trigger a <b>reaction</b> for bonus damage.'],
  ['Gather', 'Swing at <b>trees</b> for Timber and <b>rock</b> for Stone. <b>Ore</b> needs a <b>pick</b> of the right tier. Drops fly to you on their own.'],
  ['Craft &amp; forge', 'Open <b>Inventory</b> (<b>I</b> or pause menu) and use the <b>Crafting</b> list to make tools, blocks, and traps. Place a <b>Forge</b> and stand near it to <b>smelt</b> ore into iron.'],
  ['Dig', '<b>1.</b> Craft a <b>Stone Pick</b> (3 Stone + 2 Timber) in the Inventory’s Crafting list. <b>2.</b> It lands on your <b>hotbar</b> — press its number (<b>1–0</b>) to hold it. <b>3.</b> Face <b>open ground</b> and <b>attack</b> to dig up Dirt, Stone and Clay. Holding the pick also mines rock and ore. Works for every class.'],
  ['Build', 'Put a <b>block on your hotbar</b> and press attack to <b>place</b> it in front of you. Attack a placed block (while <em>not</em> holding a block) to <b>break</b> it and get it back.'],
  ['Traps', 'Craft and place <b>Spike / Frost / Ember</b> traps to defend a base — enemies that step on them take damage or a status.'],
  ['The Delve', 'Forge an <b>Iron Pick</b>, then use it at the <b>Sunken Barrow</b> to descend into the crystal cavern — and whatever waits at the bottom.'],
  ['Get around', 'Open the <b>Map</b> with <b>M</b>, this <b>Journal</b> with <b>L</b>, and pause with <b>Esc</b>. Progress autosaves; download a <b>.json</b> from the pause menu for a real backup.'],
  ['Insights &amp; your rank', 'Story beats and <b>Lessons</b> (things you learn by doing — crafting, digging, building, fighting) each hand you an <b>Insight</b>: a real-world idea worth keeping. Read it, then answer one question to <b>seal</b> it. Get it wrong and you simply read it again — nothing is lost. Your <b>Wayfarer rank</b> counts sealed insights only, so the reading is the progression. Left one unsealed? It waits in <b>Insights</b> with a <b>Read &amp; seal</b> button.'],
];
function renderJournal(){
  const rankEl = dom['journal-rank'];
  const nSeal = sealedCount(), nIns = G.quest.insights.length;
  if (rankEl) rankEl.textContent =
    `Rank: ${wisdomTitle()} · ${nSeal} / ${ALL_LESSONS.length} insights sealed`
    + (nIns > nSeal ? ` · ${nIns-nSeal} awaiting you` : '');
  [...dom.jtabs.children].forEach(b=> b.classList.toggle('sel', b.dataset.tab===journalTab));
  const body = dom.jbody; body.innerHTML = '';
  const esc = (s)=> s.replace(/&/g,'&amp;').replace(/</g,'&lt;');
  if (journalTab==='story'){
    MAIN_QUESTS.forEach((q,i)=>{
      const done = G.quest.mainDone.includes(q.id);
      const active = i===G.quest.main && !done;
      if (i > G.quest.main) return;                         // don't spoil unreached beats
      const c = document.createElement('div');
      c.className = 'qcard'+(active?' active':'')+(done?' done':'');
      c.innerHTML = `<div class="qh">${esc(q.title)} ${active?'<span class="tag now">Current</span>':(done?'<span class="tag ok">✓</span>':'')}</div>
        <div class="qd">${q.objective}</div>${done?`<div class="qlesson">“${esc(q.lesson)}”</div>`:''}`;
      body.appendChild(c);
    });
  } else if (journalTab==='daily' || journalTab==='weekly'){
    const arr = journalTab==='daily'?G.quest.daily:G.quest.weekly;
    const pool = journalTab==='daily'?DAILY_POOL:WEEKLY_POOL;
    const when = journalTab==='daily'?'Refreshes each day.':'Refreshes each week.';
    body.insertAdjacentHTML('beforeend', `<p class="guide-row" style="color:var(--muted)">${when}</p>`);
    if (!arr.length) body.insertAdjacentHTML('beforeend','<p class="guide-row">None right now — come back later.</p>');
    for (const e of arr){
      const def = pool.find(p=>p.id===e.id); if (!def) continue;
      const c = document.createElement('div'); c.className='qcard'+(e.done?' done':'');
      const frac = Math.min(1, e.prog/def.goal.n);
      c.innerHTML = `<div class="qh">${esc(def.title)} ${e.done?'<span class="tag ok">✓</span>':`<span class="tag now">+${def.reward}✦</span>`}</div>
        <div class="qbar"><i style="width:${frac*100}%"></i></div>
        <div class="qd">${e.prog} / ${def.goal.n}</div>
        <div class="qpractice">Practice — ${esc(def.practice)}</div>`;
      body.appendChild(c);
    }
  } else if (journalTab==='side'){
    ensureSideQuests();
    body.insertAdjacentHTML('beforeend','<p class="guide-row" style="color:var(--muted)">Lessons the vale teaches by doing. These never expire.</p>');
    for (const e of G.quest.side){
      const def = SIDE_QUESTS.find(s=>s.id===e.id); if (!def) continue;
      const c = document.createElement('div'); c.className='qcard'+(e.done?' done':'');
      const frac = Math.min(1, e.prog/def.goal.n);
      c.innerHTML = `<div class="qh">${esc(def.title)} ${e.done
          ? (isSealed(def.id)?'<span class="tag ok">✓ sealed</span>':'<span class="seal-tag no">unsealed</span>')
          : `<span class="tag now">+${def.reward}✦</span>`}</div>
        <div class="qbar"><i style="width:${frac*100}%"></i></div>
        <div class="qd">${Math.min(e.prog, def.goal.n)} / ${def.goal.n}</div>
        ${e.done?`<div class="qlesson">“${esc(def.lesson)}”</div>`:''}`;
      body.appendChild(c);
    }
  } else if (journalTab==='journal'){
    if (!G.quest.insights.length) body.insertAdjacentHTML('beforeend','<p class="guide-row">Your insights will gather here as your story unfolds.</p>');
    for (const id of G.quest.insights){
      const q = lessonById(id); if (!q||!q.insight) continue;
      const sealed = isSealed(id);
      const c = document.createElement('div'); c.className='qcard insight'+(sealed?'':' unsealed');
      c.innerHTML = `<div class="ith">${esc(q.insight.theme)}
          <span class="seal-tag ${sealed?'ok':'no'}">${sealed?'sealed':'unsealed'}</span></div>
        <div class="itt">“${esc(q.insight.teaching)}”</div>
        <div class="itp">Try this — ${esc(q.insight.practice)}</div>`;
      if (!sealed && q.quiz){
        const b = document.createElement('button');
        b.className='btn primary'; b.type='button'; b.style.marginTop='.6rem';
        b.textContent='Read & seal this insight';
        b.addEventListener('click', ()=> openReflection(q));
        c.appendChild(b);
      }
      body.appendChild(c);
    }
  } else {
    for (const [h, t] of GUIDE){
      body.insertAdjacentHTML('beforeend', `<div class="guide-h">${h}</div><div class="guide-row">${t}</div>`);
    }
  }
}
function openJournal(){
  if (G.phase!=='playing' && G.phase!=='paused') return;
  cameFromPause = (G.phase==='paused');
  hide(dom['menu-pause']);
  G.phase='journal'; document.exitPointerLock?.();
  show(dom['menu-journal']); renderJournal();
}
function closeJournal(){
  if (G.phase!=='journal') return;
  hide(dom['menu-journal']);
  if (cameFromPause){ G.phase='paused'; show(dom['menu-pause']); }
  else G.phase='playing';
}
let cameFromPause = false;

function openMap(){
  if (G.phase!=='playing') return;
  G.phase='map'; document.exitPointerLock?.();
  dom['map-title'].textContent = G.underground ? 'The Deep' : 'Willowmere Vale';
  show(dom['menu-map']); drawWorldMap();
}
function closeMap(){ if (G.phase!=='map') return; hide(dom['menu-map']); G.phase='playing'; }

function updateCombo(){
  if (!dom.combo) return;
  if (G.combo>=2){ dom['combo-n'].textContent = G.combo+'×'; show(dom.combo);
    if (!settings.motion){ dom.combo.classList.remove('bump'); void dom.combo.offsetWidth; dom.combo.classList.add('bump'); } }
  else hide(dom.combo);
}
function tickCombo(dt){
  if (G.comboT>0){ G.comboT-=dt; if (G.comboT<=0 && G.combo>0){ G.combo=0; updateCombo(); } }
}

/* ---------------------------------------------------- combat moves (Phase G) */
let jumpsUsed=0, jumpQueued=false, dashCd=0, dashT=0, dashDir=new THREE.Vector3(), chargeT=0, charged=false;
const lastTap = {};
function dirForAction(act){
  const f = new THREE.Vector3(-Math.sin(yaw),0,-Math.cos(yaw));
  const rt = new THREE.Vector3(Math.cos(yaw),0,-Math.sin(yaw));
  if (act==='move_fwd') return f;
  if (act==='move_back') return f.clone().negate();
  if (act==='move_left') return rt.clone().negate();
  return rt;   // move_right
}
function queueJump(){
  if (G.phase!=='playing' || G.mimic.state==='Transformed') return;
  if (grounded){ pv.y=9.2; grounded=false; jumpsUsed=1; }
  else if (jumpsUsed<2 && !glideActive){ pv.y=8.6; jumpsUsed=2;
    spawnBurst(player.position.clone().setY(player.position.y+0.2), 0xcfe6ff, 12, 0.8); sfx.swing(); }
}
function tryDash(dir){
  if (dashCd>0 || G.phase!=='playing') return;
  const nimble = hasPerk('dash');                 // 'dash' perk: longer, more frequent
  dashCd = nimble ? 0.6 : 0.9; dashT = nimble ? 0.26 : 0.18; dashDir.copy(dir).normalize();
  spawnBurst(player.position.clone().setY(player.position.y+0.6), 0xffffff, 10, 0.7);
  sfx.swing();
}
function doChargedAttack(){
  const c = activeProfile();
  const inMimic = G.mimic.state==='Transformed';
  const dmg = (inMimic ? 22 : weaponPower(equippedWeapon())) * 2.3;
  atkAnim = 1; sfx.hit(); if(!settings.motion) shake(0.28);
  const fwd = new THREE.Vector3(Math.sin(player.rotation.y),0,Math.cos(player.rotation.y));
  spawnBurst(player.position.clone().add(new THREE.Vector3(0,1.2,0)).add(fwd.clone().multiplyScalar(1.5)),
    G.activeElement==='none'?0xffe6a0:ELEMENTS[G.activeElement].color, 26, 1.4, true);
  if (!inMimic && c.ranged){ fireProjectile(dmg); }
  else {
    let struck=false;
    for (const e of enemies){ if(!e.alive)continue;
      const to=new THREE.Vector3().subVectors(e.mesh.position,player.position).setY(0); const d=to.length();
      if (d>c.range+1.4+e.r) continue; to.normalize();
      if (fwd.dot(to) < Math.cos((c.arc||1)*1.5)) continue;
      damageEnemy(e, dmg);
      // knockback
      e.mesh.position.x += to.x*1.4; e.mesh.position.z += to.z*1.4; struck=true;
    }
    if (!struck && !harvestHit(player.position, fwd, G.activeElement)) tryBreakOrDig(fwd);
  }
  toast('Charged strike!', 'good', 900);
}

/* ---------------------------------------- status effects (traps + reactions) */
function applyStatus(e, type, dur){ e.status = e.status || {}; e.status[type] = Math.max(e.status[type]||0, dur); }
function updateStatus(e, dt){
  if (e.aura){ e.aura.t -= dt; if (e.aura.t<=0) e.aura=null; }
  if (!e.status) return 1;
  let slow = 1;
  if (e.status.chill>0){ e.status.chill-=dt; slow = 0.42; }
  if (e.status.shock>0){ e.status.shock-=dt; slow = 0; }              // stunned
  if (e.status.burn>0){
    e.status.burn-=dt; e._burnT=(e._burnT||0)+dt;
    if (e._burnT>0.5){ e._burnT=0; applyEnemyDamage(e, 7, 0xf0713b); }
  }
  return slow;
}
function defeatEnemy(e){
  e.alive=false;
  dissolve(e.mesh);                      // non-graphic: dissolve into motes of light
  scene.remove(e.mesh);
  if (e.dragon){ dragonDefeatedFlow(e); return; }
  if (e.boss){ bossDefeatedFlow(e); return; }
  noteEvent('defeat', 1);
  const reward = (e.kind==='boulder'?12:5) + (e.elem?4:0);
  addTokens(reward);
  // heal on kill — a small reward that keeps aggressive play alive
  if (G.hp < G.maxHp){ G.hp = Math.min(G.maxHp, G.hp + 5);
    spawnFloater('+5', player.position.clone().add(new THREE.Vector3(0,2,0)), '#8fe6a0'); updateHUD(); }
  if (e.dropsOrb){ dropOrb(e.mesh.position.clone()); }
  if (!G.flags.firstKill){
    G.flags.firstKill=true;
    tainerSay('See? No harm done — Stonekin just come apart into light and drift home to the Wellspring. Nothing here truly dies.', 5200);
  }
  // camp guards defeated? (optional path)
}
function dissolve(mesh){
  const p = mesh.position.clone().add(new THREE.Vector3(0,0.8,0));
  spawnBurst(p, 0xfff0c0, 30, 1.2, true);
  spawnBurst(p, 0xffd98a, 18, 1.6, true);
  sfx.dissolve();
}

/* ============================================================ PHASE C: GATHER
   Harvestable nodes (trees/rock/ore/plants), dropped items that magnet to the
   player, and world-anchored floating damage/loot text. Gathering reuses the
   attack input: swinging (or a projectile) at a node damages it; the right tool
   tier speeds it up, and ore requires at least a stone pick. ==================*/
const DROP_COLORS = { timber:0x8a5a2b, stone_chunk:0x9098a4, dirt_clod:0x8a6a45, sand_pile:0xd8c78a,
  clay_lump:0xb07050, iron_ore:0xb9c2cc, gold_ore:0xe6c15a, crystal_ore:0x8fe0e6, riverbud:0xf5c168 };

function bestToolTier(kind){
  let tier = 0;
  const scan = (id)=>{ const d=itemDef(id); if (d && d.type==='tool' && d.tool===kind) tier=Math.max(tier,d.tier); };
  for (const s of G.bag) scan(s.id);
  for (const h of G.hotbar) if (h && h.kind==='item') scan(h.id);
  return tier;
}
function spawnFloater(text, pos, color='#eef3ff'){
  if (!dom.floaters) return;
  const el = document.createElement('div');
  el.className = 'floater'; el.textContent = text; el.style.color = color;
  dom.floaters.appendChild(el);
  floaters.push({ el, pos: pos.clone(), vy: 1.4, life: 1.1, max: 1.1 });
  if (floaters.length > 40){ const old = floaters.shift(); old.el.remove(); }
}
function updateFloaters(dt){
  for (let i=floaters.length-1;i>=0;i--){
    const f = floaters[i]; f.life -= dt; f.pos.y += f.vy*dt;
    if (f.life<=0){ f.el.remove(); floaters.splice(i,1); continue; }
    const v = f.pos.clone().project(camera);
    if (v.z>1){ f.el.style.display='none'; continue; }
    f.el.style.display='block';
    f.el.style.left = ((v.x*0.5+0.5)*innerWidth)+'px';
    f.el.style.top  = ((-v.y*0.5+0.5)*innerHeight)+'px';
    f.el.style.opacity = Math.min(1, f.life/0.4);
  }
}
function spawnDrop(id, n, pos){
  if (!isValidItemId(id) || n<=0) return;
  const col = DROP_COLORS[id] || 0xffe6a0;
  const m = new THREE.Mesh(new THREE.IcosahedronGeometry(0.22,0),
    new THREE.MeshStandardMaterial({ color:col, emissive:col, emissiveIntensity:0.25, flatShading:true }));
  m.position.copy(pos).add(new THREE.Vector3((Math.random()-0.5)*0.8, 0.6, (Math.random()-0.5)*0.8));
  scene.add(m);
  drops.push({ mesh:m, id, n, life:60, vy:2.5 });
}
function updateDrops(dt){
  const pp = (G.mimic.state==='Transformed'&&mimicMesh?mimicMesh:player).position;
  for (let i=drops.length-1;i>=0;i--){
    const d = drops[i]; d.life -= dt;
    d.vy -= 9*dt; d.mesh.position.y += d.vy*dt;
    const gy = terrainH(d.mesh.position.x, d.mesh.position.z) + 0.2;
    if (d.mesh.position.y < gy){ d.mesh.position.y = gy; d.vy = 0; }
    d.mesh.rotation.y += dt*2;
    const dist = d.mesh.position.distanceTo(pp);
    if (dist < 4.5){                                   // magnet
      d.mesh.position.lerp(pp.clone().setY(pp.y+1), 1-Math.pow(0.001,dt));
      if (dist < 1.3){
        const got = addItem(d.id, d.n);
        if (got>0){ spawnFloater('+'+got+' '+itemDef(d.id).name, d.mesh.position, '#f5c168'); sfx.token(); }
        scene.remove(d.mesh); drops.splice(i,1); continue;
      }
    }
    if (d.life<=0){ scene.remove(d.mesh); drops.splice(i,1); }
  }
}
function makeHarvestNode(kind, x, z, opts){
  // rock/ore/plant nodes (trees are converted in makeTree). opts: {ore,drop,hp,minTier,scale}
  const g = new THREE.Group();
  const s = opts.scale || 1;
  if (kind==='plant'){
    const stem = new THREE.Mesh(new THREE.CylinderGeometry(0.05,0.07,0.7*s,5), MAT.leaf);
    stem.position.y=0.35*s; g.add(stem);
    const flower = new THREE.Mesh(new THREE.IcosahedronGeometry(0.26*s,0),
      new THREE.MeshStandardMaterial({ color:0xf5c168, emissive:0x7a5a10, emissiveIntensity:0.4, flatShading:true }));
    flower.position.y=0.8*s; g.add(flower);
  } else {
    const rock = new THREE.Mesh(new THREE.DodecahedronGeometry(0.9*s,0), MAT.rock);
    rock.position.y=0.6*s; rock.castShadow=true; g.add(rock);
    if (opts.ore){
      const col = DROP_COLORS[opts.drop] || 0xffffff;
      for (const [ox,oy,oz] of [[-0.4,0.7,0.3],[0.35,0.9,-0.2],[0.1,1.05,0.35]]){
        const v = new THREE.Mesh(new THREE.OctahedronGeometry(0.2*s,0),
          new THREE.MeshStandardMaterial({ color:col, emissive:col, emissiveIntensity:0.5, flatShading:true }));
        v.position.set(ox*s,oy*s,oz*s); g.add(v);
      }
    }
  }
  g.position.set(x, terrainH(x,z), z);
  world.add(g);
  const h = { mesh:g, kind, ore:!!opts.ore, hp:opts.hp, maxHp:opts.hp,
    drop:opts.drop, dropN:opts.dropN||[1,3], minTier:opts.minTier||0, respawnAt:0,
    base:g.position.clone() };
  harvestables.push(h);
  if (kind!=='plant') colliders.push({ x, z, r:0.75*s, harvest:h });
  return h;
}
/* returns true if the swing/projectile was consumed by a harvest node */
function harvestHit(pos, fwd, elem){
  let best=null, bd=1e9;
  for (const h of harvestables){
    if (h.respawnAt>0) continue;
    const to = new THREE.Vector3().subVectors(h.mesh.position, pos).setY(0);
    const d = to.length(); if (d>3.4) continue;
    if (fwd){ to.normalize(); if (fwd.dot(to) < 0.35 && d>1.6) continue; }
    if (d<bd){ bd=d; best=h; }
  }
  if (!best) return false;
  damageHarvest(best);
  return true;
}
function damageHarvest(h){
  const toolKind = (h.kind==='tree') ? 'axe' : 'pick';
  const tier = bestToolTier(toolKind);
  if (h.minTier>0 && tier < h.minTier){
    const need = h.minTier>=2 ? 'an Iron Pick' : 'a Stone Pick';
    toast(`You need ${need} to break this.`, 'info', 2200);
    return;
  }
  const dmg = h.kind==='plant' ? h.maxHp : (10 + tier*22 + (toolKind==='axe'&&tier===0?0:0));
  h.hp -= Math.max(dmg, tier>0?dmg:8);
  sfx.hit();
  spawnBurst(h.mesh.position.clone().add(new THREE.Vector3(0,0.9,0)),
    h.ore?(DROP_COLORS[h.drop]||0xffffff):0xcdb89a, 6, 0.5);
  h.mesh.scale.setScalar(0.92 + 0.08*Math.max(0,h.hp/h.maxHp));
  if (h.hp<=0) breakHarvest(h);
}
function breakHarvest(h){
  const n = h.dropN[0] + Math.floor(Math.random()*(h.dropN[1]-h.dropN[0]+1));
  spawnDrop(h.drop, n, h.mesh.position.clone().setY(h.mesh.position.y+0.6));
  spawnBurst(h.mesh.position.clone().add(new THREE.Vector3(0,0.8,0)), 0xd9d0b8, 14, 1);
  sfx.dissolve();
  h.mesh.visible = false; h.respawnAt = 45;            // regrows later (regen-ready per brief)
  if (!G.flags.firstGather){ G.flags.firstGather=true;
    tainerSay('Nice haul! The vale gives back — nodes regrow in time. Gather Timber and Stone; you’ll want to craft soon.', 5200); }
}
function updateHarvest(dt){
  for (const h of harvestables){
    if (h.respawnAt>0){
      h.respawnAt -= dt;
      if (h.respawnAt<=0){ h.hp=h.maxHp; h.mesh.visible=true; h.mesh.scale.setScalar(1);
        spawnBurst(h.mesh.position.clone().add(new THREE.Vector3(0,0.6,0)), 0x8ec06a, 8, 0.6); }
    } else if (h.kind==='plant'){
      h.mesh.rotation.y += dt*0.4;
    }
  }
}
function scatterResources(){
  // rock + ore veins across the wilds, plants near water
  for (let i=0;i<26;i++){
    const a=Math.random()*Math.PI*2, r=30+Math.random()*140;
    const x=Math.cos(a)*r, z=Math.sin(a)*r;
    if (Math.hypot(x-lakePos.x,z-lakePos.z)<15) continue;
    if (terrainH(x,z) < 0.05 && Math.random()<0.5) continue;   // prefer hilly/rocky ground
    makeHarvestNode('rock', x, z, { drop:'stone_chunk', hp:60, dropN:[2,4], scale:0.9+Math.random()*0.5 });
  }
  const oreDefs = [
    { drop:'iron_ore', hp:80, minTier:1, dropN:[1,3], n:9 },
    { drop:'gold_ore', hp:100, minTier:1, dropN:[1,2], n:5 },
    { drop:'crystal_ore', hp:130, minTier:2, dropN:[1,2], n:4 },
  ];
  for (const od of oreDefs) for (let i=0;i<od.n;i++){
    const a=Math.random()*Math.PI*2, r=45+Math.random()*130;
    makeHarvestNode('rock', Math.cos(a)*r, Math.sin(a)*r,
      { ore:true, drop:od.drop, hp:od.hp, minTier:od.minTier, dropN:od.dropN, scale:0.85 });
  }
  for (let i=0;i<10;i++){
    const a=Math.random()*Math.PI*2, r=13+Math.random()*8;
    makeHarvestNode('plant', lakePos.x+Math.cos(a)*r, lakePos.z+Math.sin(a)*r,
      { drop:'riverbud', hp:1, dropN:[1,2], scale:1 });
  }
}

/* ============================================================ PHASE D: BUILD
   Grid-snapped block placement/breaking and ground digging, plus the Sunken
   Barrow that descends into an underground cavern. Blocks are 1m cubes on an
   integer grid; each carries its own collider + platform so you can build and
   stand on structures. The heightfield stays authoritative for the open world
   (approved hybrid overlay) — voxels exist only where the player builds/digs. */
const BLOCK_MAT = {};
const MAX_PLACED = 320;
let pitCount = 0;
const CAVERN = new THREE.Vector3(0, 0, -360);   // flat, enclosed, dark region
function blockKey(gx,gy,gz){ return gx+','+gy+','+gz; }
function initBlockMats(){
  BLOCK_MAT.block_dirt  = new THREE.MeshStandardMaterial({ color:0x8a6a45, roughness:1, flatShading:true });
  BLOCK_MAT.block_stone = new THREE.MeshStandardMaterial({ color:0x8f96a3, roughness:0.95, flatShading:true });
  BLOCK_MAT.block_plank = new THREE.MeshStandardMaterial({ color:0xb07d45, roughness:0.9, flatShading:true });
  BLOCK_MAT.block_wall  = new THREE.MeshStandardMaterial({ color:0x767d88, roughness:0.95, flatShading:true });
  BLOCK_MAT.block_forge = new THREE.MeshStandardMaterial({ color:0x3a2f2a, roughness:0.8, emissive:0xf0713b, emissiveIntensity:0.5, flatShading:true });
  BLOCK_MAT.spike       = new THREE.MeshStandardMaterial({ color:0x9aa2ad, roughness:0.6, metalness:0.3, flatShading:true });
  BLOCK_MAT.frost       = new THREE.MeshStandardMaterial({ color:0x8fd7f0, roughness:0.3, emissive:0x41b6c4, emissiveIntensity:0.4, flatShading:true });
  BLOCK_MAT.ember       = new THREE.MeshStandardMaterial({ color:0xf0713b, roughness:0.6, emissive:0xf0713b, emissiveIntensity:0.6, flatShading:true });
}
const forges = [];   // {x,z} positions of placed forges
function aimCell(){
  // the grid cell just in front of the player, at the top of any stack there
  const fwd = new THREE.Vector3(Math.sin(player.rotation.y),0,Math.cos(player.rotation.y));
  const p = player.position.clone().add(fwd.multiplyScalar(2.0));
  const gx = Math.round(p.x), gz = Math.round(p.z);
  let gy = Math.round(terrainH(gx,gz));           // integer ground level
  while (placedMap.has(blockKey(gx,gy,gz))) gy++;  // stack on top of existing blocks
  return { gx, gy, gz };
}
function placeBlock(type, gx, gy, gz, trap=null, fromLoad=false){
  const key = blockKey(gx,gy,gz);
  if (placedMap.has(key)) return false;
  if (placed.length >= MAX_PLACED){ if(!fromLoad) toast('Build limit reached here.', 'info', 2000); return false; }
  let geo, yoff = 0.5;
  if (trap==='spike'){ geo = new THREE.ConeGeometry(0.42, 0.9, 4); yoff = 0.45; }
  else if (trap){ geo = new THREE.BoxGeometry(0.96, 0.18, 0.96); yoff = 0.09; }  // flat trap plate
  else geo = new THREE.BoxGeometry(0.98, 0.98, 0.98);
  const mesh = new THREE.Mesh(geo, BLOCK_MAT[trap||type] || BLOCK_MAT.block_stone);
  mesh.position.set(gx, gy + yoff, gz);
  mesh.castShadow = true; mesh.receiveShadow = true;
  world.add(mesh);
  const collider = { x:gx, z:gz, r:0.62, maxY: gy+0.9 };
  const platform = { x:gx, z:gz, hw:0.5, hd:0.5, topY: gy+1 };
  if (!trap){ colliders.push(collider); platforms.push(platform); }
  const entry = { key, type, trap, mesh, hp: itemDef(type)?.hardness ? itemDef(type).hardness*30 : 40,
    gx, gy, gz, collider: trap?null:collider, platform: trap?null:platform, cooldown:0 };
  placed.push(entry); placedMap.set(key, entry);
  if (type==='block_forge') forges.push({ x:gx, z:gz });
  if (!fromLoad){ sfx.hit(); spawnBurst(mesh.position.clone(), 0xd9d0b8, 5, 0.4);
    noteEvent('build', 1); if (trap) noteEvent('trap', 1); }
  return true;
}
function removeBlock(entry, drop=true){
  world.remove(entry.mesh);
  placed.splice(placed.indexOf(entry),1); placedMap.delete(entry.key);
  if (entry.collider){ const i=colliders.indexOf(entry.collider); if(i>=0) colliders.splice(i,1); }
  if (entry.platform){ const i=platforms.indexOf(entry.platform); if(i>=0) platforms.splice(i,1); }
  if (entry.type==='block_forge'){ const i=forges.findIndex(f=>f.x===entry.gx&&f.z===entry.gz); if(i>=0) forges.splice(i,1); }
  if (drop){ spawnDrop(entry.type, 1, entry.mesh.position.clone()); }
  spawnBurst(entry.mesh.position.clone(), 0xcdb89a, 8, 0.6); sfx.hit();
}
/* place from the active hotbar block; returns true if it consumed the attack */
function tryPlaceFromHotbar(){
  const entry = G.hotbar[activeSlot];
  if (!entry || entry.kind!=='item') return false;
  const d = itemDef(entry.id);
  if (!d || (d.type!=='block')) return false;
  if (countItem(entry.id) < 1){ toast(`No ${d.name} left.`, 'info', 1400); return true; }
  const c = aimCell();
  if (placeBlock(entry.id, c.gx, c.gy, c.gz, d.trap || null)){ removeItem(entry.id, 1); refreshHotbarUI(); }
  return true;
}
/* break a placed block in front, or dig the ground with a pick */
function tryBreakOrDig(fwd){
  const p = player.position.clone().add(fwd.clone().multiplyScalar(1.6));
  // nearest placed block within reach
  let best=null, bd=1e9;
  for (const e of placed){
    const d = Math.hypot(e.gx-p.x, e.gz-p.z) + Math.abs(e.gy - player.position.y)*0.3;
    if (d<bd && d<1.6){ bd=d; best=e; }
  }
  if (best){ removeBlock(best, true); return true; }
  // else dig the ground (needs a pick)
  return digGround();
}
function digGround(){
  if (bestToolTier('pick') < 1){ toast('You need a pick to dig here.', 'info', 1800); return false; }
  const fwd = new THREE.Vector3(Math.sin(player.rotation.y),0,Math.cos(player.rotation.y));
  const p = player.position.clone().add(fwd.multiplyScalar(1.4));
  const rocky = terrainH(p.x,p.z) > 1.2;
  const id = rocky ? 'stone_chunk' : 'dirt_clod';
  spawnDrop(id, 1 + (Math.random()<0.4?1:0), p.clone().setY(terrainH(p.x,p.z)+0.3));
  if (Math.random()<0.12) spawnDrop('clay_lump', 1, p.clone().setY(terrainH(p.x,p.z)+0.3));
  spawnBurst(p.clone().setY(terrainH(p.x,p.z)+0.2), 0x8a6a45, 8, 0.6);
  sfx.hit();
  noteEvent('dig', 1);
  // cosmetic divot (bounded pool)
  if (pitCount < 40){
    pitCount++;
    const pit = new THREE.Mesh(new THREE.CircleGeometry(0.6, 8),
      new THREE.MeshStandardMaterial({ color:0x3a2c1c, roughness:1 }));
    pit.rotation.x = -Math.PI/2; pit.position.set(p.x, terrainH(p.x,p.z)+0.03, p.z); world.add(pit);
  }
  return true;
}

/* -------------------------------------------------- the Sunken Barrow / delve */
/* a solid placed block directly in an enemy's path (so it attacks structures) */
function blockAhead(pos, dir){
  const ax = pos.x + dir.x*0.9, az = pos.z + dir.z*0.9;
  let best=null, bd=1e9;
  for (const e of placed){
    if (e.trap) continue;
    const d = Math.hypot(e.gx-ax, e.gz-az);
    if (d<0.8 && d<bd){ bd=d; best=e; }
  }
  return best;
}
function damageBlock(entry, dmg){
  entry.hp -= dmg;
  spawnBurst(entry.mesh.position.clone(), 0xcdb89a, 4, 0.4);
  entry.mesh.position.x += (Math.random()-0.5)*0.05;   // shudder
  if (entry.hp<=0) removeBlock(entry, false);
}
function updateTraps(dt){
  for (const t of placed){
    if (!t.trap) continue;
    if (t.cooldown>0){ t.cooldown-=dt; continue; }
    for (const e of enemies){
      if (!e.alive) continue;
      if (Math.abs(e.mesh.position.x-t.gx)<0.75 && Math.abs(e.mesh.position.z-t.gz)<0.75){
        t.cooldown = t.trap==='spike'?0.7:1.5;
        if (t.trap==='spike'){ applyEnemyDamage(e, 34, 0xd6dae0); }
        else if (t.trap==='frost'){ applyEnemyDamage(e, 8, 0x8fd7f0); applyStatus(e,'chill',3.2);
          spawnBurst(t.mesh.position.clone().setY(0.6), 0x8fd7f0, 8, 0.6); }
        else if (t.trap==='ember'){ applyEnemyDamage(e, 8, 0xf0713b); applyStatus(e,'burn',3.2);
          spawnBurst(t.mesh.position.clone().setY(0.6), 0xf0713b, 8, 0.6); }
        break;                                    // one enemy per pulse
      }
    }
  }
}

let cavernBuilt = false, delveReturn = null;
function buildDelve(){
  // surface: a dark cracked mound with a descent prompt (needs an Iron Pick)
  const barrow = new THREE.Vector3(-96, 0, -96);
  const mound = new THREE.Group();
  for (let i=0;i<7;i++){
    const rk = new THREE.Mesh(new THREE.DodecahedronGeometry(1.4+Math.random(),0), MAT.stoneDark);
    const a=i/7*Math.PI*2; rk.position.set(Math.cos(a)*2.2, 0.6+Math.random()*0.6, Math.sin(a)*2.2);
    rk.castShadow=true; mound.add(rk);
  }
  const maw = new THREE.Mesh(new THREE.CircleGeometry(1.6, 16),
    new THREE.MeshStandardMaterial({ color:0x05070c }));
  maw.rotation.x=-Math.PI/2; maw.position.y=0.05; mound.add(maw);
  mound.position.set(barrow.x, terrainH(barrow.x,barrow.z), barrow.z); world.add(mound);
  colliders.push({ x:barrow.x, z:barrow.z, r:2.2 });
  interactables.push({
    pos: barrow.clone(), radius: 4.2, key:'E',
    label: () => bestToolTier('pick')>=2 ? 'Descend into the Sunken Barrow' : 'Sunken Barrow — need an Iron Pick',
    cond: () => true,
    onUse: () => {
      if (bestToolTier('pick') < 2){ toast('The stone is too hard — forge an Iron Pick first.', 'info', 2600); return; }
      descend();
    },
  });
  // POI for the minimap (Phase H)
  POIS.push({ x:barrow.x, z:barrow.z, kind:'barrow', name:'Sunken Barrow' });
}
function buildCavern(){
  if (cavernBuilt) return; cavernBuilt = true;
  const cx=CAVERN.x, cz=CAVERN.z;
  // dark floor
  const floor = new THREE.Mesh(new THREE.CircleGeometry(60, 40),
    new THREE.MeshStandardMaterial({ color:0x2a2622, roughness:1 }));
  floor.rotation.x=-Math.PI/2; floor.position.set(cx,0.02,cz); floor.receiveShadow=true; world.add(floor);
  // ceiling
  const ceil = new THREE.Mesh(new THREE.CircleGeometry(62, 40),
    new THREE.MeshStandardMaterial({ color:0x14100e, roughness:1, side:THREE.DoubleSide }));
  ceil.rotation.x=Math.PI/2; ceil.position.set(cx,20,cz); world.add(ceil);
  // wall ring
  for (let i=0;i<28;i++){
    const a=i/28*Math.PI*2;
    const col = new THREE.Mesh(new THREE.ConeGeometry(5, 22, 5), i%2?MAT.stoneDark:MAT.rock);
    col.position.set(cx+Math.cos(a)*58, 9, cz+Math.sin(a)*58); world.add(col);
    colliders.push({ x:cx+Math.cos(a)*58, z:cz+Math.sin(a)*58, r:4 });
  }
  // ambient glow crystals + a light
  const cl = new THREE.PointLight(0x8fe0e6, 0.8, 90); cl.position.set(cx,12,cz); world.add(cl);
  // crystal-rich ore veins (the reward for digging deep)
  for (let i=0;i<10;i++){
    const a=Math.random()*Math.PI*2, r=8+Math.random()*44;
    makeHarvestNode('rock', cx+Math.cos(a)*r, cz+Math.sin(a)*r,
      { ore:true, drop:'crystal_ore', hp:110, minTier:2, dropN:[2,3], scale:0.9 });
  }
  for (let i=0;i<6;i++){
    const a=Math.random()*Math.PI*2, r=8+Math.random()*44;
    makeHarvestNode('rock', cx+Math.cos(a)*r, cz+Math.sin(a)*r, { drop:'iron_ore', hp:90, minTier:1, dropN:[2,3], scale:0.85 });
  }
  // underground lake
  const ul = new THREE.Mesh(new THREE.CircleGeometry(9, 30),
    new THREE.MeshStandardMaterial({ color:0x1c4a63, roughness:0.15, metalness:0.2, transparent:true, opacity:0.9 }));
  ul.rotation.x=-Math.PI/2; ul.position.set(cx-30,0.06,cz+22); world.add(ul);
  // ruined pillars (environmental storytelling)
  for (const [px,pz,ph] of [[cx+26,cz-18,6],[cx+30,cz-14,3.5],[cx+22,cz-22,5]]){
    const pil = new THREE.Mesh(new THREE.CylinderGeometry(1.1,1.3,ph,8), MAT.stone);
    pil.position.set(px, ph/2, pz); pil.castShadow=true; world.add(pil);
    colliders.push({ x:px, z:pz, r:1.2 });
  }
  // secret room: a hidden alcove chest behind the pillars
  makeChest('chest-delve', new THREE.Vector3(cx+30, 0, cz-24), {type:'tokens', n:60});
  FLAT_ZONES.push({ x:cx, z:cz, r:60 });   // keep the cavern floor flat
  // ascend shaft (a lit pillar of light back to the surface)
  const shaft = new THREE.Mesh(new THREE.CylinderGeometry(1.4,1.4,20,12,1,true),
    new THREE.MeshStandardMaterial({ color:0xfff2c0, emissive:0xf5c168, emissiveIntensity:0.5, transparent:true, opacity:0.3, side:THREE.DoubleSide }));
  shaft.position.set(cx+50, 10, cz); world.add(shaft);
  interactables.push({
    pos: new THREE.Vector3(cx+50,0,cz), radius: 3.5, key:'E',
    label: ()=> 'Rise to the surface', cond: ()=> G.underground,
    onUse: ()=> ascend(),
  });
  buildDragon(new THREE.Vector3(cx, 0, cz-30));   // Phase I boss, dormant
}
function setAmbiance(under){
  if (!scene) return;
  if (under){ scene.background = new THREE.Color(0x07060a); if(scene.fog){ scene.fog.color.set(0x07060a); scene.fog.near=8; scene.fog.far=70; } }
  else { scene.background = new THREE.Color(0x9fd0e8); if(scene.fog){ scene.fog.color.set(0x9fd0e8); scene.fog.near=40; scene.fog.far=260; } }
}
function descend(){
  buildCavern();
  G.underground = true;
  G.flags.descendedEver = true;
  advanceMain('descended');
  noteEvent('descend', 1);
  const barrow = interactables.find(x=>x.label&&/Barrow/.test(x.label()));
  delveReturn = { x:-96, z:-92 };
  player.position.set(CAVERN.x+50, 0, CAVERN.z);
  setAmbiance(true);
  sfx.transform();
  toast('You squeeze down into a vast, glimmering dark…', 'info', 3600);
  tainerSay('Whoa. This goes DEEP. Crystal everywhere — and… something breathing down here. Stay sharp.', 5200);
  if (POIS.every(p=>p.kind!=='cavern')) POIS.push({ x:CAVERN.x, z:CAVERN.z, kind:'cavern', name:'The Deep' });
}
function ascend(){
  G.underground = false;
  player.position.set(delveReturn?.x ?? -96, 0, delveReturn?.z ?? -92);
  setAmbiance(false);
  sfx.eject();
  toast('You climb back into daylight.', 'good', 2600);
}

/* ============================================================ PHASE I: DRAGON
   Vornrath, the Deepwyrm — the endgame boss asleep at the bottom of the Delve.
   Multi-phase, reaction-driven; defeating it unlocks the Wellspring Transmute,
   legendary loot, and the Deepened (harder) mode. Original design. ===========*/
let dragonHome = null, dragonRef = null;
function buildDragon(pos){ dragonHome = pos.clone(); }
function makeDragonMesh(){
  const g = new THREE.Group();
  const bodyMat = new THREE.MeshStandardMaterial({ color:0x2a2230, roughness:0.7, flatShading:true });
  const bellyMat = new THREE.MeshStandardMaterial({ color:0x5a2a2a, roughness:0.8, flatShading:true });
  const body = new THREE.Mesh(new THREE.CapsuleGeometry(2.0, 5, 4, 8), bodyMat);
  body.rotation.z = Math.PI/2; body.position.y=3; body.castShadow=true; g.add(body);
  const neck = new THREE.Mesh(new THREE.CylinderGeometry(0.8,1.3,3.4,6), bodyMat);
  neck.position.set(3.4,4.4,0); neck.rotation.z=-0.7; g.add(neck);
  const head = new THREE.Mesh(new THREE.BoxGeometry(2.3,1.5,1.5), bodyMat); head.position.set(5.2,5.5,0); g.add(head);
  const jaw = new THREE.Mesh(new THREE.BoxGeometry(1.9,0.5,1.3), bellyMat); jaw.position.set(5.4,4.85,0); g.add(jaw);
  const eyeMat = new THREE.MeshStandardMaterial({ color:0xff7a3a, emissive:0xff5a1a, emissiveIntensity:1.3 });
  for (const s of [-0.5,0.5]){ const e=new THREE.Mesh(new THREE.SphereGeometry(0.22,8,8),eyeMat); e.position.set(5.9,5.8,s); g.add(e); }
  const wingMat = new THREE.MeshStandardMaterial({ color:0x3a2a3a, roughness:0.9, flatShading:true, transparent:true, opacity:0.92, side:THREE.DoubleSide });
  const wingGeo = new THREE.ConeGeometry(4,0.35,3);
  const wL = new THREE.Mesh(wingGeo, wingMat); wL.position.set(0,5,-3.2); wL.rotation.z=Math.PI/2; wL.scale.set(1,3,1); g.add(wL);
  const wR = wL.clone(); wR.position.z=3.2; g.add(wR);
  const tail = new THREE.Mesh(new THREE.ConeGeometry(1.5, 6, 6), bodyMat); tail.position.set(-5,3,0); tail.rotation.z=-Math.PI/2; g.add(tail);
  const cMat = new THREE.MeshStandardMaterial({ color:0x8fe0e6, emissive:0x2a6b60, emissiveIntensity:0.7, flatShading:true });
  for (const x of [-1.2,0.8,2.6]){ const c=new THREE.Mesh(new THREE.OctahedronGeometry(0.7,0),cMat); c.position.set(x,5.3,0); g.add(c); }
  g.userData.wings={wL,wR};
  return g;
}
function spawnDragon(){
  const mesh = makeDragonMesh();
  mesh.position.copy(dragonHome);
  scene.add(mesh);
  const hp = G.hardMode?1500:950;
  dragonRef = { mesh, dragon:true, boss:true, guard:false, dropsOrb:false, elem:null,
    hp, maxHp:hp, dmg: G.hardMode?34:26, speed:5.4, r:3.4, home:dragonHome.clone(),
    telegraph:0, atkCd:2.2, breatheCd:3, phase:1, alive:true, wobble:0 };
  enemies.push(dragonRef);
  toast('The Deepwyrm stirs — Vornrath wakes!', 'bad', 3800);
  tainerSay('THAT’S what was breathing! Vornrath, the Deepwyrm. Reactions hurt it most — stack two elements! And watch its fire breath.', 6800);
}
function maybeAwakenDragon(){
  if (!G.underground || !dragonHome || dragonRef || G.dragonDefeated) return;
  if (player.position.distanceTo(dragonHome) < 30) spawnDragon();
}
function updateDragon(e, dt, pPos, transformed){
  e.wobble += dt; e.atkCd -= dt; e.breatheCd -= dt;
  if (e.phase===1 && e.hp < e.maxHp/2){ e.phase=2; e.speed=7.2; e.dmg*=1.15;
    spawnBurst(e.mesh.position.clone().setY(5), 0xff7a3a, 30, 2, true);
    tainerSay('It’s enraged — faster and fiercer! Keep stacking reactions and don’t stop moving!', 4600); }
  const d = Math.hypot(pPos.x-e.mesh.position.x, pPos.z-e.mesh.position.z);
  const to = new THREE.Vector3(pPos.x-e.mesh.position.x,0,pPos.z-e.mesh.position.z);
  if (to.lengthSq()>0.01) e.mesh.rotation.y = Math.atan2(to.x,to.z) - Math.PI/2;   // head is +x local
  if (e.telegraph>0){
    e.telegraph -= dt;
    e.mesh.position.y = terrainH(e.mesh.position.x,e.mesh.position.z) + Math.sin((0.8-e.telegraph)*4)*0.6;
    if (e.telegraph<=0){
      spawnBurst(e.mesh.position.clone().setY(0.5), 0xf0713b, 34, 2); if(!settings.motion) shake(0.4);
      if (d<8){ if(transformed) damageMimic(e.dmg); else damagePlayer(e.dmg); }
      e.atkCd = e.phase===2?1.6:2.6;
    }
  } else {
    if (d>8){ to.normalize(); e.mesh.position.x+=to.x*e.speed*dt; e.mesh.position.z+=to.z*e.speed*dt; }
    else if (e.atkCd<=0){ e.telegraph=0.8; }
    if (e.breatheCd<=0 && d>6 && d<44){ e.breatheCd = e.phase===2?2.2:3.6; dragonBreath(e, pPos); }
    e.mesh.position.y = terrainH(e.mesh.position.x,e.mesh.position.z);
  }
  const fl = Math.sin(e.wobble*4)*0.35;
  if (e.mesh.userData.wings){ e.mesh.userData.wings.wL.rotation.x=fl; e.mesh.userData.wings.wR.rotation.x=-fl; }
  if (d<55 && e.alive) showBossBar('Vornrath, the Deepwyrm', e.hp/e.maxHp); else hide(dom['boss-bar']);
}
function dragonBreath(e, pPos){
  const dir = new THREE.Vector3(pPos.x-e.mesh.position.x,0,pPos.z-e.mesh.position.z).normalize();
  const col=0xf0713b;
  const m = new THREE.Mesh(new THREE.SphereGeometry(0.55,8,8),
    new THREE.MeshStandardMaterial({ color:col, emissive:col, emissiveIntensity:1 }));
  m.position.copy(e.mesh.position).add(new THREE.Vector3(0,4,0)).add(dir.clone().multiplyScalar(4));
  scene.add(m);
  enemyShots.push({ mesh:m, vel:dir.multiplyScalar(22), life:2.6, dmg:Math.round(e.dmg*0.7) });
  sfx.transform();
}
function updateEnemyShots(dt){
  const pp = (G.mimic.state==='Transformed'&&mimicMesh?mimicMesh:player).position;
  for (let i=enemyShots.length-1;i>=0;i--){
    const s=enemyShots[i]; s.life-=dt; s.mesh.position.addScaledVector(s.vel,dt);
    s.mesh.rotation.y+=dt*4;
    if (s.mesh.position.distanceTo(pp)<1.4){
      if (G.mimic.state==='Transformed') damageMimic(s.dmg); else damagePlayer(s.dmg);
      spawnBurst(s.mesh.position.clone(), 0xf0713b, 10, 1);
      scene.remove(s.mesh); enemyShots.splice(i,1); continue;
    }
    if (s.life<=0 || s.mesh.position.y < terrainH(s.mesh.position.x,s.mesh.position.z)){
      spawnBurst(s.mesh.position.clone(), 0xf0713b, 6, 0.8);
      scene.remove(s.mesh); enemyShots.splice(i,1);
    }
  }
}
function dragonDefeatedFlow(e){
  G.dragonDefeated = true; dragonRef = null; hide(dom['boss-bar']);
  advanceMain('dragonDefeated');
  noteEvent('defeatBoss', 1);
  dissolve(e.mesh); dissolve(e.mesh);
  scene.remove(e.mesh);
  spawnDrop('crystal_ore', 12, e.mesh.position.clone().setY(1));
  spawnDrop('gold_ore', 8, e.mesh.position.clone().setY(1));
  addItem('wardcharm', 2);
  addTokens(120);
  toast('Vornrath dissolves into a river of light! The Wellspring Transmute is unlocked.', 'good', 6000);
  tainerSay('You DID it! The Deepwyrm is light again. The Wellspring’s waking — endless crystal if you Transmute at a Forge, and a Deepened mode if you ever want a real challenge. Turn it on in Settings.', 9000);
  setObjective('The Deepwyrm is undone. Transmute crystal at a Forge, or brave Deepened mode. Your search for the Lost Sibling continues beyond the vale…');
}
function showBossBar(name, frac){
  const bn = dom['boss-bar'].querySelector('.boss-name');
  if (bn) bn.textContent = name;
  dom['boss-fill'].style.width = Math.max(0,frac*100)+'%';
  show(dom['boss-bar']);
}

/* ------------------------------------------------------------- mimic orb */
function dropOrb(pos){
  const m = new THREE.Mesh(new THREE.OctahedronGeometry(0.5,0),
    new THREE.MeshStandardMaterial({ color:0xc9b1f0, emissive:0x7a5ac0, emissiveIntensity:1.1, flatShading:true, transparent:true, opacity:0.95 }));
  m.position.copy(pos).setY(1.1);
  const light = new THREE.PointLight(0x9a7bd0, 1.2, 8); m.add(light);
  scene.add(m);
  orbs.push({ mesh:m, bob:0 });
  toast('A Mimic Orb drifts free! Walk into it to pick it up.', 'good', 3000);
  tainerSay('Ooh! A Mimic Orb. Grab it and you can Mirrorstep — become that creature! Press F when you’re holding one.', 5600);
}
function collectOrb(o){
  scene.remove(o.mesh);
  orbs.splice(orbs.indexOf(o),1);
  G.mimic.orbHeld = true;
  sfx.orb();
  setMimicState('OrbAvailable');
  show(dom['orb-status']);
  toast('Mimic Orb held. Press F to Mirrorstep.', 'good', 2600);
  if (G.stage===2 || G.stage===3){
    G.stage=3;
    toast('Press F to Mirrorstep into a Grumble, then slip past the camp guards.', 'info', 4200);
  }
}

/* Mimic Orb state machine:
   Normal -> OrbAvailable -> TransformationPending -> Transforming -> Transformed
   -> EjectionPending -> Ejecting -> Cooldown -> Normal   (InvalidOrRecovery on error) */
function setMimicState(s){ G.mimic.state = s; updateHUD(); }

function tryMimic(){
  const m = G.mimic;
  if (m.state==='Transformed'){ beginEject(false); return; }
  if (m.state==='OrbAvailable' && m.orbHeld){ beginTransform(); return; }
  if (!m.orbHeld) toast('You need a Mimic Orb first.', 'info', 1800);
}
function beginTransform(){
  const m = G.mimic;
  setMimicState('TransformationPending');
  sfx.transform();
  // subtle local anticipation, then "server-confirmed" (local authority stand-in)
  spawnBurst(player.position.clone().add(new THREE.Vector3(0,1,0)), 0x9a7bd0, 24, 1);
  setMimicState('Transforming');
  setTimeout(()=>{
    m.savedHp = G.hp;                    // preserve exact player health
    m.orbHeld = false; hide(dom['orb-status']);
    m.maxHp = 70; m.hp = 70;
    // swap model: hide humanoid, show grumble
    player.visible = false;
    mimicMesh = makeStonekin('grumble');
    mimicMesh.position.copy(player.position);
    scene.add(mimicMesh);
    show(dom['mimic-bar-wrap']);
    setMimicState('Transformed');
    tainerSay('You’re a Grumble now! Your own powers are tucked away safe — you’ve only got stone-kin moves. The guards won’t look twice. Press F to step back out any time.', 6500);
    G.flags.transformedOnce = true;
    updateHUD();
  }, 420);
}
function beginEject(auto){
  const m = G.mimic;
  if (m.state!=='Transformed') return;
  setMimicState('EjectionPending');
  sfx.eject();
  const pos = mimicMesh ? mimicMesh.position.clone() : player.position.clone();
  spawnBurst(pos.clone().add(new THREE.Vector3(0,1,0)), 0xc9b1f0, 24, 1.1);
  setMimicState('Ejecting');
  if (mimicMesh){ scene.remove(mimicMesh); player.position.copy(mimicMesh.position); mimicMesh=null; }
  player.visible = true;
  hide(dom['mimic-bar-wrap']);
  G.hp = m.savedHp;                       // return with EXACT pre-transform health
  m.hp = 0; m.maxHp = 0;
  setMimicState('Cooldown');
  m.cooldown = 1.2;
  toast(auto ? 'Mimic form broke — you return unharmed.' : 'Mirrorstep ended. Your health is exactly as you left it.', auto?'bad':'info', 2600);
  if (auto) tainerSay('The form gave out — but look, you’re right back to how you were. That’s the trick of it: your real self is never in danger.', 5200);
  updateHUD();
  // check stealth objective completion happens in stealth update
}
function tickMimicCooldown(dt){
  const m = G.mimic;
  if (m.state==='Cooldown'){ m.cooldown -= dt; if (m.cooldown<=0){ setMimicState(m.orbHeld?'OrbAvailable':'Normal'); } }
}

/* ------------------------------------------------------------- stealth */
let alertLevel = 0; // 0 safe .. 3 detected
function updateStealth(dt){
  const transformed = G.mimic.state==='Transformed';
  const pos = transformed && mimicMesh ? mimicMesh.position : player.position;
  // Reaching the goal must be checked FIRST. It used to sit below the early
  // returns, so a *successful* infiltration — outrunning the guards or killing
  // them — never registered, permanently blocking the story.
  if (campGoal && !G.flags.campPassed){
    if (Math.hypot(pos.x-campGoal.x, pos.z-campGoal.z) < 3.5){ campPassed(); }
  }
  const guards = enemies.filter(e=>e.alive && e.guard);
  if (!guards.length){ hide(dom['alert-state']); return; }
  // only surface the stealth indicator when actually near the camp
  const nearestGuard = Math.min(...guards.map(g=>Math.hypot(pos.x-g.mesh.position.x, pos.z-g.mesh.position.z)));
  if (nearestGuard > 18){ alertLevel = 0; hide(dom['alert-state']); return; }
  let seen=false, near=false;
  for (const g of guards){
    const d = Math.hypot(pos.x-g.mesh.position.x, pos.z-g.mesh.position.z);
    if (d<11){ near=true;
      // facing check
      const to=new THREE.Vector3().subVectors(pos,g.mesh.position).setY(0).normalize();
      const fwd=new THREE.Vector3(Math.sin(g.mesh.rotation.y),0,Math.cos(g.mesh.rotation.y));
      if (!transformed && (d<5 || fwd.dot(to)>0.4)) seen=true;
    }
  }
  if (transformed){ setAlert(near?1:0); }         // disguised: guards merely observe
  else if (seen){ alertLevel = Math.min(3, alertLevel + dt*1.4); }
  else if (near){ alertLevel = Math.min(2, alertLevel + dt*0.5); }
  else { alertLevel = Math.max(0, alertLevel - dt*1.2); }
  setAlert(Math.round(alertLevel));

  if (Math.round(alertLevel)>=3 && !transformed){
    // spotted: guards give chase; nudge player back a bit
    for (const g of guards){ g.state='chase'; g.target=player; }
  }
}
function setAlert(lv){
  const el = dom['alert-state'];
  if (G.phase!=='playing' || (!enemies.some(e=>e.alive&&e.guard))){ hide(el); return; }
  const map = ['safe','observed','suspicious','detected'];
  const label = ['Safe','Observed','Suspicious','Detected!'];
  el.className = 'alert-state '+map[lv];
  dom['alert-text'].textContent = label[lv];
  show(el);
}
function campPassed(){
  G.flags.campPassed = true;
  hide(dom['alert-state']);
  advanceMain('campPassed');
  addTokens(15);
  toast('You slipped through the camp! +15 Emberlight', 'good', 3200);
  tainerSay('You walked right through them! Okay okay — next: Skywright Pell, past the meadow. He teaches gliding, and honestly we are going to need it.', 6000);
  G.stage=4;
  refreshObjective();
}

/* ------------------------------------------------------------- gliding */
let trialActive=false, trialRelaunch=0.5, trialTimer=0;
function startTrial(){
  if (G.flags.trialPassed){ tainerSay('Pell says the winds are yours now. Hold Space in the air to glide anywhere!', 4200); return; }
  trialActive = true; trialTimer = 40; trialRelaunch = 0.5;
  hoops.forEach(h=>h.userData.hoop.passed=false);
  G.glideUnlocked = true; // trial glide granted
  // launch: place player on updraft and give upward pop
  player.position.set(-4, 0.2, 43);
  pv.set(0, 12, 4);
  toast('Windrider’s Trial: fly through all 4 rings. You glide automatically — just steer!', 'info', 5000);
  tainerSay('Ride the updraft! You’ll glide on your own — just steer with the stick or W A S D. If you land, the wind lifts you again. Take your time.', 6200);
  setObjective('Windrider’s Trial: steer through all 4 rings. Landing is fine — the wind relaunches you.');
}
function updateTrial(){
  if (!trialActive) return;
  let passed=0;
  for (const h of hoops){
    const d = player.position.distanceTo(h.position);
    // generous ring radius — this is a joyful first flight, not a precision test
    if (!h.userData.hoop.passed && d<6.5){ h.userData.hoop.passed=true; spawnBurst(h.position.clone(),0xf5c168,20,0.9);
      h.material.color.set(0x7bd3c6); h.material.emissive.set(0x2a6b60); toast('Ring!','good',900); }
    if (h.userData.hoop.passed) passed++;
  }
  if (passed>=hoops.length){ trialActive=false; trialPass(); return; }
  // Landing no longer fails and never revokes the glider. Touch down and you
  // simply get launched back up to try the remaining rings.
  if (grounded && player.position.y < 0.4){
    trialRelaunch -= 1/60;
    if (trialRelaunch <= 0){
      trialRelaunch = 1.2;
      player.position.set(-4, 0.3, 43);
      pv.set(0, 11, 4);
      toast(`Up you go again — ${hoops.length-passed} ring${hoops.length-passed===1?'':'s'} to go.`, 'info', 2200);
    }
  } else trialRelaunch = 0.5;
}
function trialPass(){
  G.flags.trialPassed=true; G.glideUnlocked=true;
  advanceMain('trialPassed');
  addTokens(20);
  spawnBurst(player.position.clone(),0x7bd3c6,40,1.4);
  toast('You earned the Windrider’s Mark! Gliding unlocked. +20 Emberlight', 'good', 4200);
  tainerSay('That was BEAUTIFUL! The Windrider’s Mark is yours — hold Space whenever you’re falling. The whole vale is open now. Let’s go find them.', 6500);
  G.stage=5;
  refreshObjective();
}

/* ============================================================ QUESTS & JOURNAL
   Main chain teaches a reflective skill at each existing story beat; daily/weekly
   pair a game task with a small real-world practice; the Journal collects Insights
   into a Wayfarer rank. See quests.js for content + the "not therapy" framing. */
function todayKey(){ return new Date().toISOString().slice(0,10); }
function weekKey(){
  const d = new Date(); const day = (d.getDay()+6)%7;           // Mon=0
  const monday = new Date(d); monday.setDate(d.getDate()-day);
  return monday.toISOString().slice(0,10);
}
function rollPool(pool, n){
  const ids = pool.map(p=>p.id); const out=[];
  while (out.length<n && ids.length){ out.push(ids.splice(Math.floor(Math.random()*ids.length),1)[0]); }
  return out.map(id=>({ id, prog:0, done:false }));
}
function ensureQuests(){
  const q = G.quest;
  if (q.dailyDate !== todayKey()){ q.dailyDate = todayKey(); q.daily = rollPool(DAILY_POOL, 3); }
  if (q.weeklyKey !== weekKey()){ q.weeklyKey = weekKey(); q.weekly = rollPool(WEEKLY_POOL, 2); }
  if (!Array.isArray(q.sealed)) q.sealed = [];
  if (!Array.isArray(q.side)) q.side = [];
  ensureSideQuests();
}
/* Derived from what's actually completed, never a separate index — beats can
   complete out of order (catch-up), which desynced a standalone pointer. */
function activeMainQuest(){
  const q = MAIN_QUESTS.find(x => !G.quest.mainDone.includes(x.id)) || null;
  G.quest.main = q ? MAIN_QUESTS.indexOf(q) : MAIN_QUESTS.length;   // keep the saved index honest
  return q;
}
function refreshObjective(){
  const q = activeMainQuest();
  if (q) setObjective(q.objective);
  else if (G.quest.mainDone.length >= MAIN_QUESTS.length) setObjective('Your legend is written — roam free, help the vale, and carry what you’ve learned.');
}
const firedTriggers = new Set();
function advanceMain(trigger){
  firedTriggers.add(trigger);
  const q = activeMainQuest();
  if (q && q.trigger === trigger) completeMain(q);
  else setTimeout(reconcileQuests, 250);   // out-of-order milestone: catch up
}
function completeMain(q, quiet){
  if (G.quest.mainDone.includes(q.id)) return;
  G.quest.mainDone.push(q.id);
  grantInsight(q);
  if (q.reward) addTokens(q.reward);
  if (!quiet){
    sfx.attune();
    toast(`Story: “${q.title}” — insight earned. +${q.reward} Emberlight`, 'good', 4200);
    tainerSay(q.lesson, 8000);
    queueReflection(q);              // read it, then answer for it — that's the seal
  }
  refreshObjective(); updateHUD();
  // chain forward: the capstone auto-completes, and any beat whose trigger
  // already fired this session (out-of-order play) completes too
  const next = activeMainQuest();
  if (next){
    if (next.trigger === 'auto') setTimeout(()=>{ if (activeMainQuest()===next) completeMain(next); }, 9000);
    else if (firedTriggers.has(next.trigger)) setTimeout(()=>{ if (activeMainQuest()===next) completeMain(next); }, 400);
  }
}
function grantInsight(q){
  if (!q.insight || G.quest.insights.includes(q.id)) return;
  G.quest.insights.push(q.id);
}
function reconstructMainFromFlags(){
  // resume the story at the right beat for a save made before quests existed
  const f = G.flags||{};
  const done = [];
  const mark = (id,cond)=>{ if(cond) done.push(id); };
  mark('m_cast', f.fished);
  mark('m_name', Object.values(G.elements||{}).some(Boolean));
  mark('m_wall', f.iceMelted);
  mark('m_watch', f.campPassed);
  mark('m_space', G.bossDefeated);
  mark('m_control', f.firstReaction);
  mark('m_wind', f.trialPassed || G.glideUnlocked);
  mark('m_dark', G.dragonDefeated);   // if the dragon's dead they surely descended
  mark('m_wyrm', G.dragonDefeated);
  mark('m_light', G.dragonDefeated);
  G.quest.mainDone = MAIN_QUESTS.filter(q=>done.includes(q.id)).map(q=>q.id);
  G.quest.insights = [...G.quest.mainDone];
  // active = first not-done
  let idx = MAIN_QUESTS.findIndex(q=>!G.quest.mainDone.includes(q.id));
  G.quest.main = idx<0 ? MAIN_QUESTS.length : idx;
}
function noteEvent(type, n=1, item=null){
  const bump = (arr, pool)=>{
    for (const e of arr){
      if (e.done) continue;
      const def = pool.find(p=>p.id===e.id); if (!def) continue;
      const g = def.goal;
      if (g.type !== type) continue;
      if (g.item){ const ok = Array.isArray(g.item) ? g.item.includes(item) : g.item===item; if (!ok) continue; }
      e.prog += n;
      if (e.prog >= g.n){ e.done=true; e.prog=g.n;
        if (def.reward) addTokens(def.reward);
        if (def.item) addItem(def.item, 1);
        sfx.token();
        toast(`Quest done: ${def.title}  ·  +${def.reward} Emberlight`, 'good', 3600);
        if (def.practice) tainerSay(`A small practice for the world beyond the vale — ${def.practice}`, 6000);
      }
    }
  };
  bump(G.quest.daily, DAILY_POOL);
  bump(G.quest.weekly, WEEKLY_POOL);

  // side quests are permanent milestone lessons, not rotating goals
  ensureSideQuests();
  for (const e of G.quest.side){
    if (e.done) continue;
    const def = SIDE_QUESTS.find(s=>s.id===e.id); if (!def) continue;
    const g = def.goal;
    if (g.type !== type) continue;
    if (g.item){ const ok = Array.isArray(g.item) ? g.item.includes(item) : g.item===item; if (!ok) continue; }
    e.prog += n;
    if (e.prog >= g.n) completeSide(def, e);
  }
}
/* ------------------------------------------------------ reflections & seals
   An insight is *earned* by playing, but only SEALED by proving you read it.
   Rank counts sealed insights only — that's what makes the reading matter.
   The modal is escapable on purpose: being trapped mid-fight would be worse
   than an unsealed insight, and the Journal lets you seal it any time. */
const ALL_LESSONS = [...MAIN_QUESTS, ...SIDE_QUESTS];
function lessonById(id){ return ALL_LESSONS.find(q=>q.id===id) || null; }
function isSealed(id){ return G.quest.sealed.includes(id); }
function sealedCount(){ return G.quest.sealed.length; }

let reflectQueue = [], reflectCur = null, reflectAttempts = 0, reflectReturn = 'playing';
function queueReflection(q){
  if (!q || !q.insight || !q.quiz || isSealed(q.id)) return;
  if (reflectCur === q || reflectQueue.includes(q)) return;
  reflectQueue.push(q);
  if (!reflectCur) setTimeout(nextReflection, 900);   // let the completion toast land first
}
function nextReflection(){
  if (reflectCur) return;
  if (G.phase!=='playing' && G.phase!=='journal' && G.phase!=='paused') return;
  const q = reflectQueue.shift();
  if (!q) return;
  if (isSealed(q.id)) return nextReflection();
  openReflection(q);
}
function openReflection(q){
  reflectCur = q; reflectAttempts = 0;
  reflectReturn = (G.phase==='journal') ? 'journal' : 'playing';
  if (G.phase==='journal') hide(dom['menu-journal']);
  G.phase = 'reflect';
  document.exitPointerLock?.();
  dom['reflect-kicker'].textContent = SIDE_QUESTS.includes(q) ? 'A Lesson From The Doing' : 'A Reflection';
  dom['reflect-title'].textContent    = q.title;
  dom['reflect-lesson'].textContent   = '“'+q.lesson+'”';
  dom['reflect-theme'].textContent    = q.insight.theme;
  dom['reflect-teaching'].textContent = q.insight.teaching;
  dom['reflect-practice'].textContent = 'Try this — ' + q.insight.practice;
  show(dom['reflect-readbox']); hide(dom['reflect-quizbox']);
  dom['btn-reflect-read'].textContent = "I've read it — ask me";
  hide(dom['reflect-feedback']);
  show(dom['menu-reflect']);
  sfx.attune?.();
}
function showReflectQuiz(){
  const q = reflectCur; if (!q) return;
  hide(dom['reflect-readbox']); show(dom['reflect-quizbox']);
  dom['reflect-q'].textContent = q.quiz.q;
  const box = dom['reflect-opts']; box.innerHTML = '';
  q.quiz.options.forEach((opt, i)=>{
    const b = document.createElement('button');
    b.className = 'btn'; b.type = 'button'; b.textContent = opt;
    b.addEventListener('click', ()=> answerReflection(i));
    box.appendChild(b);
  });
}
function answerReflection(i){
  const q = reflectCur; if (!q) return;
  const fb = dom['reflect-feedback'];
  if (i === q.quiz.answer){
    if (!G.quest.sealed.includes(q.id)) G.quest.sealed.push(q.id);
    fb.className = 'reflect-feedback good';
    fb.textContent = 'Sealed. That one is yours now.';
    show(fb);
    sfx.token?.();
    setTimeout(()=>{ closeReflection(); toast(`Insight sealed — ${q.insight.theme}. Rank: ${wisdomTitle()}`, 'good', 3600); }, 1100);
  } else {
    reflectAttempts++;
    fb.className = 'reflect-feedback bad';
    fb.textContent = 'Not quite — read it once more, then try again.';
    show(fb);
    sfx.hit?.();
    // send them back to the teaching; that re-read IS the point
    setTimeout(()=>{
      if (reflectCur !== q) return;
      hide(dom['reflect-quizbox']); show(dom['reflect-readbox']);
      dom['btn-reflect-read'].textContent = reflectAttempts>=2 ? 'Alright — ask me again' : 'Read again — ask me';
      hide(fb);
    }, 1500);
  }
}
function closeReflection(){
  if (G.phase!=='reflect') return;
  const q = reflectCur;
  hide(dom['menu-reflect']);
  reflectCur = null;
  if (q && !isSealed(q.id)) toast('Insight unsealed — open the Journal (L) to seal it.', 'warn', 3400);
  if (reflectReturn==='journal'){ G.phase='journal'; show(dom['menu-journal']); renderJournal(); }
  else { G.phase='playing'; updateHUD(); }
  if (reflectQueue.length) setTimeout(nextReflection, 600);
}

/* --------------------------------------------------------------- side quests */
function ensureSideQuests(){
  const have = new Set(G.quest.side.map(e=>e.id));
  for (const s of SIDE_QUESTS) if (!have.has(s.id)) G.quest.side.push({ id:s.id, prog:0, done:false });
  // drop entries for quests that no longer exist
  const ids = new Set(SIDE_QUESTS.map(s=>s.id));
  G.quest.side = G.quest.side.filter(e=>ids.has(e.id));
}
function completeSide(def, entry){
  entry.done = true; entry.prog = def.goal.n;
  if (!G.quest.insights.includes(def.id)) G.quest.insights.push(def.id);
  if (def.reward) addTokens(def.reward);
  sfx.token?.();
  toast(`Insight earned: “${def.title}”  ·  +${def.reward}✦`, 'good', 3800);
  queueReflection(def);
}

function wisdomTitle(){ return wayfarerRank(sealedCount()); }

/* Self-healing chain. The story is linear, but the world isn't — a player can
   descend or slay the Deepwyrm before beating Hush, and those are one-shot
   events. Without this, finishing content out of order permanently orphaned the
   remaining beats. Any active quest whose milestone has ALREADY happened
   completes itself, cascading forward. */
const TRIGGER_SATISFIED = {
  fished:        ()=> !!G.flags.fished,
  firstElement:  ()=> Object.values(G.elements||{}).some(Boolean),
  iceMelted:     ()=> !!G.flags.iceMelted,
  campPassed:    ()=> !!G.flags.campPassed,
  trialPassed:   ()=> !!(G.flags.trialPassed || G.glideUnlocked),
  bossDefeated:  ()=> !!G.bossDefeated,
  firstReaction: ()=> !!G.flags.firstReaction,
  descended:     ()=> !!(G.flags.descendedEver || G.dragonDefeated),
  dragonDefeated:()=> !!G.dragonDefeated,
};
function reconcileQuests(){
  for (let guard=0; guard<MAIN_QUESTS.length+2; guard++){
    const q = activeMainQuest();
    if (!q) return;
    const sat = TRIGGER_SATISFIED[q.trigger];
    if (sat && sat()) completeMain(q, true);      // silent catch-up
    else return;
  }
}

/* ------------------------------------------------------------- progression */
function addTokens(n){ G.tokens += n; sfx.token(); updateHUD(); }
/* upgradeWeapon() is gone — power now comes from advanceMastery() per weapon type */

/* ------------------------------------------------------------- particles */
function spawnBurst(pos, color, count=20, spread=1, rise=false){
  const geo = new THREE.SphereGeometry(0.08, 6, 6);
  const grp = new THREE.Group();
  const mat = new THREE.MeshStandardMaterial({ color, emissive:color, emissiveIntensity:1, transparent:true });
  const vel=[];
  for (let i=0;i<count;i++){
    const m = new THREE.Mesh(geo, mat.clone());
    m.position.copy(pos);
    grp.add(m);
    const v = new THREE.Vector3((Math.random()-0.5)*spread*3, rise?Math.random()*3+1:(Math.random()*2), (Math.random()-0.5)*spread*3);
    vel.push(v);
  }
  scene.add(grp);
  particles.push({ grp, vel, life:1, max:1 });
}
function updateParticles(dt){
  for (let i=particles.length-1;i>=0;i--){
    const p = particles[i]; p.life -= dt* (settings.motion?1.6:1.1);
    p.grp.children.forEach((m,idx)=>{
      m.position.addScaledVector(p.vel[idx], dt);
      p.vel[idx].y -= 4*dt;
      m.material.opacity = Math.max(0, p.life);
      m.scale.setScalar(Math.max(0.01, p.life));
    });
    if (p.life<=0){ scene.remove(p.grp); particles.splice(i,1); }
  }
}
function meltIce(){
  if (G.flags.iceMelted) return;
  G.flags.iceMelted = true;
  advanceMain('iceMelted');
  spawnBurst(iceWall.position.clone().setY(2), 0x8fd7f0, 40, 1.4, true);
  spawnBurst(iceWall.position.clone().setY(2), 0xf0713b, 20, 1.2);
  // remove ice colliders
  for (let i=colliders.length-1;i>=0;i--) if (colliders[i].tag==='ice') colliders.splice(i,1);
  world.remove(iceWall);
  toast('The Rime wall melts away!', 'good', 2600);
  tainerSay('Ha! Told you. The path north is open — that’s the Stonekin camp. We’ll want a disguise for that...', 5200);
  if (G.stage<3){ toast('Defeat a Stonekin to earn a Mimic Orb, then sneak through the camp.', 'info', 4200); }
}

/* ================================================================= PHYSICS */
const pv = new THREE.Vector3(); // player velocity
let grounded = true;
let glideActive = false;

function updatePlayer(dt){
  if (G.phase!=='playing') { return; }
  const transformed = G.mimic.state==='Transformed';
  const body = transformed && mimicMesh ? mimicMesh : player;
  const baseSpeed = transformed ? 5.5 : 6.5;
  const sprint = (keys['shift'] || touch.sprint) && G.stamina>0 && !transformed;
  const speed = baseSpeed * (sprint?1.7:1);

  // camera-relative input — the camera sits at +[sin(yaw),cos(yaw)] from the
  // player, so screen-forward (into the scene) is the negation of that vector
  const f = new THREE.Vector3(-Math.sin(yaw),0,-Math.cos(yaw));
  const r = new THREE.Vector3(Math.cos(yaw),0,-Math.sin(yaw));   // screen-right
  const move = new THREE.Vector3();
  if (keys['w']) move.add(f);
  if (keys['s']) move.sub(f);
  if (keys['a']) move.sub(r);
  if (keys['d']) move.add(r);
  // analog touch joystick (up on the stick = forward)
  if (usingTouch && (touch.mx || touch.my)){
    move.copy(f).multiplyScalar(-touch.my).addScaledVector(r, touch.mx);
  }
  // arrow keys rotate camera (accessibility/no-mouse fallback)
  if (keys['arrowleft']) yaw += 1.6*dt*settings.cam;
  if (keys['arrowright']) yaw -= 1.6*dt*settings.cam;
  if (keys['arrowup']) pitch = Math.min(1.1, pitch+1.2*dt);
  if (keys['arrowdown']) pitch = Math.max(-0.2, pitch-1.2*dt);

  const moving = move.lengthSq()>0.01;
  if (moving){
    move.normalize();
    pv.x = move.x*speed; pv.z = move.z*speed;
  } else { pv.x*=0.7; pv.z*=0.7; }
  // The character faces where the CAMERA looks: the mouse turns the body,
  // WASD only translates it (strafe scheme). Attacks aim at the view centre.
  body.rotation.y = Math.atan2(f.x, f.z);

  // stamina
  if (sprint && moving) G.stamina = Math.max(0, G.stamina - 26*dt);
  else G.stamina = Math.min(G.maxStam, G.stamina + 16*dt);

  playerAtkCd = Math.max(0, playerAtkCd - dt);
  // dash: a short burst of speed
  dashCd = Math.max(0, dashCd-dt);
  if (dashT>0){ dashT-=dt; pv.x = dashDir.x*22; pv.z = dashDir.z*22; }

  // jump / glide (double-jump handled via queueJump on keydown)
  const windUp = windLift(body.position);
  if (grounded) jumpsUsed = 0;
  // During the Trial you glide automatically while falling — no held input
  // needed, which is what made it unplayable on a phone.
  if (!grounded && G.glideUnlocked && pv.y < 1.5 && (keys[' '] || trialActive)) glideActive=true;
  else if (!keys[' '] && !trialActive) glideActive=false;

  // charged attack: hold the attack button to unleash a heavy strike
  if ((attackHeld || keys['j']) && dashT<=0){
    chargeT += dt;
    if (chargeT>0.6 && !charged){ charged=true; doChargedAttack(); }
  } else { chargeT=0; charged=false; }

  // gravity
  if (glideActive && !grounded){
    pv.y = Math.max(pv.y - 6*dt, -2.2);  // slow descent
    // glide gives forward push in facing dir
    const gf = new THREE.Vector3(Math.sin(body.rotation.y),0,Math.cos(body.rotation.y));
    pv.x += gf.x*10*dt; pv.z += gf.z*10*dt;
    pv.x*=0.98; pv.z*=0.98;
  } else {
    pv.y -= 22*dt;
  }
  pv.y += windUp*dt;

  // integrate with collision (XZ)
  const nextX = body.position.x + pv.x*dt;
  const nextZ = body.position.z + pv.z*dt;
  const res = resolveCollision(body.position.x, body.position.z, nextX, nextZ, transformed?1.0:0.6, body.position.y);
  body.position.x = res.x; body.position.z = res.z;
  body.position.y += pv.y*dt;

  // ground = terrain height, or the top of any platform we're above and falling onto
  let groundY = terrainH(body.position.x, body.position.z);
  for (const pf of platforms){
    if (Math.abs(body.position.x-pf.x)<=pf.hw && Math.abs(body.position.z-pf.z)<=pf.hd &&
        body.position.y >= pf.topY-0.45 && pv.y<=0) groundY = Math.max(groundY, pf.topY);
  }
  if (body.position.y <= groundY){ body.position.y=groundY; if(pv.y<0){ pv.y=0; grounded=true; glideActive=false; } }
  else grounded=false;

  // keep within bounds — the open world (radius 195 from origin) or, underground,
  // inside the cavern (radius 55 from its centre, which sits far off at CAVERN)
  if (G.underground){
    const dx=body.position.x-CAVERN.x, dz=body.position.z-CAVERN.z, R=Math.hypot(dx,dz);
    if (R>55){ body.position.x=CAVERN.x+dx/R*55; body.position.z=CAVERN.z+dz/R*55; }
  } else {
    const R = Math.hypot(body.position.x, body.position.z);
    if (R>195){ body.position.x*=195/R; body.position.z*=195/R; }
  }

  // if transformed, keep player group synced (for eject position + attack facing)
  if (transformed && mimicMesh){ player.position.copy(mimicMesh.position); player.rotation.y = mimicMesh.rotation.y; }

  animateLimbs(body, moving, dt);

  // footsteps
  if (moving && grounded){ stepT += dt * (sprint?1.5:1);
    if (stepT > 0.34){ stepT = 0; sfx.step(); } }
  else stepT = 0.3;

  // orb pickups
  for (let i=orbs.length-1;i>=0;i--){
    const o=orbs[i]; if (body.position.distanceTo(o.mesh.position)<1.6) collectOrb(o);
  }

  // interact prompt
  updateInteract();
}

function windLift(pos){
  let up=0;
  for (const w of windZones){ if (Math.hypot(pos.x-w.pos.x,pos.z-w.pos.z)<w.r && pos.y<26) up=Math.max(up,w.up); }
  return up;
}

function resolveCollision(x,z,nx,nz,pr,y=0){
  for (const c of colliders){
    if (c.maxY!=null && y > c.maxY) continue;   // standing above this obstacle
    const dx=nx-c.x, dz=nz-c.z; const d=Math.hypot(dx,dz); const min=c.r+pr;
    if (d<min && d>0.0001){ const push=(min-d); nx += dx/d*push; nz += dz/d*push; }
  }
  // the lake's deep centre is unswimmable until frozen (gliding over it is allowed)
  if (!lakeFrozen && lakePos && y < 2.5){
    const dx=nx-lakePos.x, dz=nz-lakePos.z; const d=Math.hypot(dx,dz);
    if (d < DEEP_WATER_R && d > 0.001){ const push=DEEP_WATER_R-d; nx += dx/d*push; nz += dz/d*push; }
  }
  return { x:nx, z:nz };
}

function animateLimbs(body, moving, dt){
  const parts = body===player ? playerParts : (body.userData?.parts);
  if (body===player && parts){
    const t = performance.now()*0.01;
    const sw = moving ? Math.sin(t)* (settings.motion?0.4:0.7) : 0;
    parts.legL.rotation.x = sw; parts.legR.rotation.x = -sw;
    parts.armL.rotation.x = -sw*0.7; parts.armR.rotation.x = sw*0.7;
    // body language: run bob + lean, gentle idle breathing
    parts.torso.position.y = 1.15 + (moving ? Math.abs(Math.sin(t))*0.05 : Math.sin(t*0.4)*0.015);
    parts.torso.rotation.x = moving ? 0.09 : 0;
    parts.head.position.y = 1.82 + (moving ? Math.abs(Math.sin(t))*0.04 : 0);
    // ---- attack animation: the weapon travels with the arm it's held in ----
    const style = equippedType();
    if (atkAnim>0){
      atkAnim = Math.max(0, atkAnim - dt*(3.2/Math.max(0.12, equippedMods().cd)) * 0.28);
      const a = atkAnim;                    // 1 → 0 across the swing
      const arc = -2.3*a + 0.55*(1-a);      // wind up behind, follow through forward
      if (style==='greatsword'){            // two-handed overhead chop
        parts.armR.rotation.x = arc*1.15; parts.armL.rotation.x = arc*1.05;
        parts.armR.rotation.z = -0.25*a;    parts.armL.rotation.z = 0.25*a;
        parts.torso.rotation.x = 0.22*(1-a);
      } else if (style==='dual'){           // alternating left/right combo
        if (swingSide===0){ parts.armR.rotation.x = arc;      parts.armL.rotation.x = 0.5*a; }
        else              { parts.armL.rotation.x = arc;      parts.armR.rotation.x = 0.5*a; }
        parts.torso.rotation.y = (swingSide===0? -0.3 : 0.3) * a;
      } else if (style==='bow'){            // draw and loose
        parts.armL.rotation.x = -1.45;      parts.armR.rotation.x = -0.9 - 0.5*a;
        parts.armR.rotation.z = 0.35;
      } else if (style==='focus'){          // thrust the rune forward
        parts.armR.rotation.x = -1.5*a - 0.2; parts.armR.rotation.z = -0.2*a;
      } else {                              // sword
        parts.armR.rotation.x = arc; parts.armR.rotation.z = -0.3*a;
        parts.torso.rotation.y = -0.22*a;
      }
    } else {
      parts.torso.rotation.y = 0;
      if (style==='bow'){ parts.armL.rotation.x = -1.2; parts.armL.rotation.z = 0; }  // bow held ready
    }
    if (glideActive){ parts.armL.rotation.z=0.9; parts.armR.rotation.z=-0.9; parts.armL.rotation.x=0; parts.armR.rotation.x=0; }
    else if (atkAnim<=0 && style!=='bow'){ parts.armL.rotation.z=0; parts.armR.rotation.z=0; }
  }
  // the Psychic Focus rune drifts and spins in hand
  const rune = body.userData?.weapon?.userData?.float;
  if (rune){ rune.rotation.y += dt*2.2; rune.rotation.x += dt*1.1;
    rune.position.y = 0.05 + Math.sin(performance.now()*0.004)*0.07; }
}

/* ================================================================= ENEMIES AI */
function updateEnemies(dt){
  const transformed = G.mimic.state==='Transformed';
  const pPos = transformed && mimicMesh ? mimicMesh.position : player.position;
  for (const e of enemies){
    if (!e.alive) continue;
    if (e.dragon){ updateDragon(e, dt, pPos, transformed); continue; }
    if (e.boss){ updateBoss(e, dt, pPos, transformed); continue; }
    e.wobble += dt;
    e.atkCd = Math.max(0, e.atkCd-dt);
    if (e.hitCd>0) e.hitCd-=dt;
    if (e.blockCd>0) e.blockCd-=dt;
    const slow = updateStatus(e, dt);
    if (!e.alive) continue;                       // burn may have finished it
    const spd = e.speed * slow;
    const d = Math.hypot(pPos.x-e.mesh.position.x, pPos.z-e.mesh.position.z);

    // guards ignore disguised player
    const hostile = !(transformed && e.guard);
    if (e.guard && !e.target){
      // slow patrol rotation
      e.mesh.rotation.y += dt*0.4*(e.wobble%6<3?1:-1);
    }
    if (hostile && d<14 && (e.target || d<9)){ e.state='chase'; e.target=player; }

    if (e.state==='chase' && e.target && hostile){
      const to = new THREE.Vector3(pPos.x-e.mesh.position.x,0,pPos.z-e.mesh.position.z);
      const dist=to.length();
      if (dist>e.r+1.1){
        to.normalize();
        // a placed block in the way gets attacked instead of walked through
        const block = blockAhead(e.mesh.position, to);
        if (block){ if (!(e.blockCd>0)){ e.blockCd=0.9; damageBlock(block, 12); } }
        else {
          const nx=e.mesh.position.x+to.x*spd*dt, nz=e.mesh.position.z+to.z*spd*dt;
          e.mesh.position.x=nx; e.mesh.position.z=nz;
        }
        e.mesh.rotation.y=Math.atan2(to.x,to.z);
      } else if (e.atkCd<=0){
        e.atkCd = 1.4;
        // hit whichever body is active
        if (transformed){ damageMimic(e.dmg); } else { damagePlayer(e.dmg); }
        spawnBurst(pPos.clone().add(new THREE.Vector3(0,1,0)), 0xff8a6a, 6, 0.5);
      }
    } else {
      // drift home
      const to=new THREE.Vector3(e.home.x-e.mesh.position.x,0,e.home.z-e.mesh.position.z);
      if (to.length()>1){ to.normalize(); e.mesh.position.x+=to.x*spd*0.4*dt; e.mesh.position.z+=to.z*spd*0.4*dt; }
    }
    // chill/burn visual tint on the eyes
    if (e.status && (e.status.chill>0||e.status.burn>0) && e.mesh.userData.eyes){
      const c = e.status.chill>0 ? 0x8fd7f0 : 0xf0713b;
      for (const ey of e.mesh.userData.eyes) ey.material.emissive?.setHex?.(c);
    }
    // ground-follow + idle bob
    e.mesh.position.y = terrainH(e.mesh.position.x, e.mesh.position.z) + Math.abs(Math.sin(e.wobble*3))*0.08;
    if (e.hitCd>0) e.mesh.scale.setScalar(1.12); else e.mesh.scale.setScalar(1);
  }
}
function damagePlayer(dmg){
  if (G.mimic.state==='Transformed') return;
  if (window.__dmgLog) window.__dmgLog.push(['player', dmg, new Error().stack.split('\n')[2]?.trim()]);
  sfx.hurt();
  G.hp = Math.max(0, G.hp - dmg);
  updateHUD();
  if (!settings.motion) shake(0.25);
  if (G.hp<=0) playerDown();
}
function damageMimic(dmg){
  const m=G.mimic; if (m.state!=='Transformed') return;
  m.hp = Math.max(0, m.hp - dmg);
  updateHUD();
  if (m.hp<=0) beginEject(true);   // AUTOMATIC eject at zero monster health
}
function playerDown(){
  toast('You fall to your knees... a warm light gathers you up.', 'bad', 3000);
  tainerSay('I’ve got you! Deep breath. The vale won’t let you go that easily.', 4200);
  G.hp = G.maxHp; // gentle, child-friendly: full recover near spawn
  player.position.set(lakePos.x + 12, 0, lakePos.z + 2);
  updateHUD();
}

/* ============================================================ CAMERA UPDATE */
let shakeAmt = 0;
function shake(a){ shakeAmt = Math.min(0.6, shakeAmt + a); }
function updateCamera(dt){
  const target = (G.mimic.state==='Transformed' && mimicMesh) ? mimicMesh : player;
  const focus = target.position.clone().add(new THREE.Vector3(0,1.5,0));
  // over-the-shoulder bias: slide the whole camera track sideways so the
  // character stands off-centre and the crosshair has a clear line of sight
  const sh = settings.shoulder==='center' ? 0 : (settings.shoulder==='left' ? -0.85 : 0.85);
  focus.x += Math.cos(yaw)*sh;
  focus.z += -Math.sin(yaw)*sh;
  const off = new THREE.Vector3(
    Math.sin(yaw)*Math.cos(pitch),
    Math.sin(pitch)+0.2,
    Math.cos(yaw)*Math.cos(pitch)
  ).multiplyScalar(camDist);
  let desired = focus.clone().add(off);

  // camera collision: pull in if blocked by colliders
  const dir = new THREE.Vector3().subVectors(desired, focus);
  const dist = dir.length(); dir.normalize();
  let hitDist = dist;
  for (const c of colliders){
    // approximate: distance from camera ray to collider center
    const toC = new THREE.Vector3(c.x-focus.x, 0, c.z-focus.z);
    const proj = toC.dot(dir);
    if (proj>0 && proj<hitDist){
      const closest = focus.clone().add(dir.clone().multiplyScalar(proj));
      const dd = Math.hypot(closest.x-c.x, closest.z-c.z);
      if (dd < c.r+0.6) hitDist = Math.min(hitDist, proj-0.4);
    }
  }
  const camPos = focus.clone().add(dir.multiplyScalar(Math.max(2.2, hitDist)));
  camPos.y = Math.max(camPos.y, terrainH(camPos.x, camPos.z) + 0.5);   // never sink under a hill

  camera.position.lerp(camPos, 1-Math.pow(0.001, dt));
  if (shakeAmt>0){ camera.position.x += (Math.random()-0.5)*shakeAmt; camera.position.y += (Math.random()-0.5)*shakeAmt; shakeAmt=Math.max(0,shakeAmt-dt*2); }
  camera.lookAt(focus);
}

/* ------------------------------------------------------------ aim reticle */
const _aimEnd = new THREE.Vector3();
function updateAim(){
  if (G.phase!=='playing'){ hide(dom.reticle); hide(dom['aim-dot']); return; }
  show(dom.reticle);
  const c = activeProfile();
  if (!c || !c.ranged || G.mimic.state==='Transformed'){ hide(dom['aim-dot']); return; }
  // march along the facing line to the first enemy, hillside, or max range —
  // this is where an arrow or rune bolt will actually land
  const oy = player.position.y + 1.3;
  const dx = Math.sin(player.rotation.y), dz = Math.cos(player.rotation.y);
  let found = false;
  for (let d=2; d<=40 && !found; d+=0.5){
    const px = player.position.x + dx*d, pz = player.position.z + dz*d;
    for (const e of enemies){
      if (e.alive && Math.hypot(px-e.mesh.position.x, pz-e.mesh.position.z) < e.r+0.4){
        _aimEnd.set(px, e.mesh.position.y+1, pz); found = true; break;
      }
    }
    if (!found && terrainH(px,pz) > oy){ _aimEnd.set(px, terrainH(px,pz), pz); found = true; }
    if (!found && d>=40) _aimEnd.set(px, oy, pz);
  }
  if (!found) _aimEnd.set(player.position.x+dx*40, oy, player.position.z+dz*40);
  const v = _aimEnd.project(camera);
  if (v.z > 1){ hide(dom['aim-dot']); return; }
  dom['aim-dot'].style.left = ((v.x*0.5+0.5)*innerWidth)+'px';
  dom['aim-dot'].style.top  = ((-v.y*0.5+0.5)*innerHeight)+'px';
  show(dom['aim-dot']);
}

/* ================================================================= HUD SYNC */
function setObjective(t){ dom['objective-text'].textContent = t; }
function updateHUD(){
  dom['hero-name'].textContent = G.sibling ? sibName() : '—';
  const hpPct = G.maxHp? (G.hp/G.maxHp*100):0;
  dom['hp-fill'].style.width = hpPct+'%';
  dom['hp-text'].textContent = Math.ceil(G.hp);
  dom['stam-fill'].style.width = (G.stamina/G.maxStam*100)+'%';
  dom['token-count'].textContent = G.tokens;
  dom['weapon-name'].textContent = G.klass ? equippedWeapon().name : '—';
  dom['weapon-lvl'].textContent = G.klass ? ('M'+masteryOf(equippedType())) : '—';
  const ed = ELEMENTS[G.activeElement];
  dom['elem-hud-sig'].textContent = ed ? ed.sigil : '○';
  dom['elem-hud-name'].textContent = ed ? ed.name : 'None';
  dom['elem-hud-sig'].style.color = ed ? elemColorCss(G.activeElement) : '';
  // resource tracker: key materials the player has gathered
  if (dom.tracker){
    const track = ['timber','stone_chunk','iron_ingot','crystal_ore'];
    dom.tracker.innerHTML = track.filter(id=>countItem(id)>0)
      .map(id=>`<span class="trk">${itemDef(id).icon} ${countItem(id)}</span>`).join('');
  }
  refreshHotbarUI();
  // mimic bar
  if (G.mimic.state==='Transformed'){
    show(dom['mimic-bar-wrap']);
    dom['mimic-fill'].style.width = (G.mimic.hp/G.mimic.maxHp*100)+'%';
    dom['mimic-text'].textContent = 'Grumble  '+Math.ceil(G.mimic.hp)+'/'+G.mimic.maxHp;
  } else hide(dom['mimic-bar-wrap']);
  dom['orb-status'].classList.toggle('hidden', !G.mimic.orbHeld);
}

/* ================================================================= PAUSE/SET */
let lockOnResume = false;
function pause(){ if(G.phase!=='playing') return; lockOnResume = pointerLocked; G.phase='paused'; show(dom['menu-pause']); document.exitPointerLock?.(); }
function resume(){
  if(G.phase!=='paused') return;
  hide(dom['menu-pause']); G.phase='playing';
  if (lockOnResume) dom_scene().requestPointerLock?.();   // give the mouse back to the camera
}

/* ------------------------------------------------------ inventory (gear) */
function openInventory(){
  if (G.phase!=='paused') return;
  G.phase='inventory'; hide(dom['menu-pause']); show(dom['menu-inv']); renderInv();
}
function closeInventory(){
  if (G.phase!=='inventory') return;
  assignPick = null; markPicked(null);
  hide(dom['menu-inv']); G.phase='paused'; show(dom['menu-pause']);
}
function markPicked(el){
  document.querySelectorAll('.bag-item.picked,.elem-chip.picked,.inv-row.picked').forEach(x=>x.classList.remove('picked'));
  if (el) el.classList.add('picked');
  refreshHotbarUI();
}
function renderInv(){
  refreshHotbarUI();
  // bag grid
  const bg = dom['bag-grid'];
  bg.innerHTML = '';
  if (!G.bag.length) bg.innerHTML = '<span class="bag-empty">Nothing gathered yet — the vale provides to those who wander.</span>';
  for (const s of G.bag){
    const d = itemDef(s.id); if (!d) continue;
    const b = document.createElement('button');
    b.type = 'button'; b.className = 'bag-item'; b.draggable = true;
    b.innerHTML = `${d.icon}<span class="hcount">${s.n}</span>`;
    b.title = `${d.name} ×${s.n}${d.desc ? ' — '+d.desc : ''}`;
    const pick = ()=>{
      assignPick = { kind:'item', id:s.id }; markPicked(b);
      toast(`Assign ${d.name}: click a hotbar slot (or press 1–0).`, 'info', 2600);
    };
    b.onclick = pick;
    b.addEventListener('dragstart', pick);
    bg.appendChild(b);
  }
  // attuned element chips
  const er = dom['elem-row'];
  er.innerHTML = '';
  for (const [elem, def] of Object.entries(ELEMENTS)){
    if (!G.elements[elem]) continue;
    const c = document.createElement('button');
    c.type='button'; c.className='elem-chip'+(G.activeElement===elem?' on':'');
    c.innerHTML = `<span style="color:${elemColorCss(elem)}">${def.sigil}</span> ${def.name}`;
    c.title = `Switch to ${def.name} (or cycle with Q / E in play)`;
    c.onclick = ()=>{ setActiveElement(elem); renderInv(); };
    er.appendChild(c);
  }
  if (!er.children.length) er.innerHTML = '<span class="bag-empty">Touch a Wardstone to attune an element.</span>';
  // mastery — where power actually comes from now
  renderMastery();
  // weapons: every weapon, every type, all unique-grade and indestructible
  const list = dom['inv-list'];
  list.innerHTML = '';
  for (const t of WEAPON_TYPES){
    const prof = CLASSES[t];
    const head = document.createElement('div');
    head.className = 'wtype-head';
    head.innerHTML = `${prof.name} <span class="wtype-m">Mastery ${masteryOf(t)} · Power ${Math.round(prof.dmg*masteryMult(masteryOf(t)))}</span>${t===G.klass?' <span class="inv-badge">Your discipline</span>':''}`;
    list.appendChild(head);
    for (const w of (WEAPONS[t]||[])){
      const id = w.id, isEq = id === G.equipped;
      const row = document.createElement('div');
      row.className = 'inv-row'+(isEq?' equipped':'');
      row.setAttribute('role','listitem');
      row.draggable = true;
      const pickW = ()=>{
        assignPick = { kind:'weapon', id }; markPicked(row);
        toast(`Assign ${w.name}: drop it on a slot (or press 1–0).`, 'info', 2600);
      };
      row.addEventListener('dragstart', pickW);
      row.addEventListener('click', ev=>{ if (ev.target.tagName!=='BUTTON') pickW(); });
      row.innerHTML = `
        <div class="inv-info">
          <div class="inv-name">${w.name} <span class="inv-tier">Unique</span>${isEq?' <span class="inv-badge">Equipped</span>':''}</div>
          <div class="inv-stats">Power ${weaponPower({...w, type:t})} · ${w.cd<=0.22?'Fast':(w.cd>=0.40?'Heavy':'Balanced')}${w.crit?` · +${Math.round(w.crit*100)}% crit`:''}${w.reach!==1?` · ${w.reach>1?'long':'short'} reach`:''}</div>
          <div class="inv-blurb">${w.blurb}</div>
        </div>
        <div class="inv-actions"></div>`;
      const actions = row.querySelector('.inv-actions');
      if (!isEq){
        const eqBtn = document.createElement('button');
        eqBtn.className='btn small'; eqBtn.textContent='Equip';
        eqBtn.onclick = ()=>{ equipWeapon(id); renderInv(); toast(`${w.name} equipped — ${prof.name} style.`, 'good', 2000); };
        actions.appendChild(eqBtn);
      }
      list.appendChild(row);
    }
  }
  renderCrafting();
  dom['inv-tokens'].textContent = `✦ ${G.tokens} Emberlight held. Every weapon is yours and none can be broken — spend Emberlight on Mastery to grow stronger.`;
}
function renderMastery(){
  const box = dom['mastery-list']; if (!box) return;
  box.innerHTML = '';
  for (const t of WEAPON_TYPES){
    const prof = CLASSES[t], lv = masteryOf(t), max = lv>=MASTERY_MAX;
    const cost = masteryCost(lv);
    const row = document.createElement('div');
    row.className = 'inv-row';
    row.innerHTML = `
      <div class="inv-info">
        <div class="inv-name">${prof.name}${t===G.klass?' <span class="inv-badge">Discipline</span>':''}</div>
        <div class="qbar"><i style="width:${lv/MASTERY_MAX*100}%"></i></div>
        <div class="inv-stats">Mastery ${lv} / ${MASTERY_MAX} · Power ${Math.round(prof.dmg*masteryMult(lv))}</div>
      </div>
      <div class="inv-actions"></div>`;
    const b = document.createElement('button');
    b.className = 'btn small';
    b.textContent = max ? 'Mastered' : `Advance (✦${cost})`;
    b.disabled = max || G.tokens < cost;
    b.onclick = ()=>{ if (advanceMastery(t)) renderInv(); };
    row.querySelector('.inv-actions').appendChild(b);
    box.appendChild(row);
  }
}
function renderCrafting(){
  const list = dom['craft-list']; if (!list) return;
  const q = (dom['craft-search']?.value || '').toLowerCase();
  list.innerHTML = '';
  const forge = nearForge();
  for (const r of RECIPES){
    if (r.unlock && !G[r.unlock]) continue;                 // hidden until unlocked
    const outDef = itemDef(r.out.id);
    const label = r.label || `${outDef.name}${r.out.n>1?' ×'+r.out.n:''}`;
    if (q && !label.toLowerCase().includes(q) && !outDef.name.toLowerCase().includes(q)) continue;
    const avail = recipeAvailable(r);
    const row = document.createElement('div');
    row.className = 'craft-row'+(avail.ok?'':' locked');
    const cost = r.in.map(ing=>{
      const have = countItem(ing.id), ok = have>=ing.n;
      return `<span class="${ok?'have':'short'}">${itemDef(ing.id).name} ${have}/${ing.n}</span>`;
    }).join(', ');
    const stationNote = r.station==='forge' ? (forge?'':' · <em>needs Forge</em>') : '';
    const elemNote = r.element ? ` · <em>${ELEMENTS[r.element].name}</em>` : '';
    row.innerHTML = `<span class="craft-out">${outDef.icon} ${label}</span>
      <span class="craft-cost">${cost}${stationNote}${elemNote}</span>`;
    const btn = document.createElement('button');
    btn.className = 'btn small'; btn.textContent = 'Craft'; btn.disabled = !avail.ok;
    btn.title = avail.ok ? '' : avail.why;
    btn.onclick = ()=>{ if (craft(r)){ renderInv(); } };
    row.appendChild(btn);
    list.appendChild(row);
  }
}

function openSettings(from){ settingsReturn=from; hide(dom['menu-title']); hide(dom['menu-pause']); G.phase='settings'; show(dom['menu-settings']); syncSettingsUI(); }
let settingsReturn='title';
function closeSettings(){ hide(dom['menu-settings']); if(settingsReturn==='pause'){ G.phase='paused'; show(dom['menu-pause']); } else goTitle(); }

function syncSettingsUI(){
  dom['set-theme'].value=settings.theme; dom['set-contrast'].checked=settings.contrast;
  dom['set-motion'].checked=settings.motion; dom['set-ui'].checked=settings.ui;
  dom['set-cam'].value=settings.cam; dom['set-invert'].checked=settings.invert;
  dom['set-shoulder'].value=settings.shoulder;
  if (dom['set-hard-row']){ dom['set-hard-row'].style.display = G.dragonDefeated ? 'flex' : 'none';
    dom['set-hard'].checked = !!G.hardMode; }
  dom['set-aim'].checked=settings.aim; dom['set-vol'].value=settings.vol;
}
function applySettings(){
  document.body.dataset.theme = settings.theme;
  document.body.dataset.motion = settings.motion?'reduced':'full';
  document.body.dataset.ui = settings.ui?'large':'normal';
  document.body.dataset.contrast = settings.contrast?'high':'normal';
  saveSettings();
}
function saveSettings(){ try{ localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings)); }catch(e){} }
function loadSettings(){
  try{ const s=JSON.parse(localStorage.getItem(SETTINGS_KEY)||'null'); if(s&&typeof s==='object') Object.assign(settings,s); }catch(e){}
}

/* ================================================================= SAVE/LOAD */
function serialize(){
  // deep-copied at the end so the snapshot can never alias live state
  const raw = {
    schemaVersion: SCHEMA_VERSION, product: PRODUCT_VERSION, savedAt: new Date().toISOString(),
    id: 'local-'+(G.sibling||'x'),
    payload: {
      sibling:G.sibling, klass:G.klass, hp:G.hp, maxHp:G.maxHp, tokens:G.tokens,
      weaponLevel:G.weaponLevel, mastery:G.mastery, elements:G.elements, activeElement:G.activeElement,
      glideUnlocked:G.glideUnlocked, stage:G.stage, flags:G.flags,
      owned:G.owned, equipped:G.equipped, chests:G.chests, mechs:G.mechs,
      bossDefeated:G.bossDefeated,
      bag:G.bag, hotbar:G.hotbar,
      build:placed.map(e=>({t:e.type, gx:e.gx, gy:e.gy, gz:e.gz, trap:e.trap||null})),
      dragonDefeated:G.dragonDefeated, hardMode:G.hardMode,
      quest:G.quest,
      pos:{x:player?.position.x||0, z:player?.position.z||0},
    }
  };
  return JSON.parse(JSON.stringify(raw));
}
function autosave(){ try{ localStorage.setItem(SAVE_KEY, JSON.stringify(serialize())); }catch(e){} dom['btn-continue'].disabled=false; }

function downloadSave(){
  const data = serialize();
  const blob = new Blob([JSON.stringify(data,null,2)], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const d = new Date().toISOString().slice(0,10);
  a.href=url; a.download=`EMBERKIN_backup_${d}.json`; a.click();
  URL.revokeObjectURL(url);
  toast('Progress downloaded. (Local backup only — not authoritative.)','good',3000);
}

const GENERIC_INVALID = 'Invalid or corrupted progress file';
function validateSave(raw){
  // size guard handled by caller; here: structure + semantics
  if (typeof raw!=='object' || raw===null) throw 0;
  // prototype-pollution guard
  const bad = ['__proto__','constructor','prototype'];
  const scan = (o)=>{ if(o&&typeof o==='object'){ for(const k of Object.keys(o)){ if(bad.includes(k)) throw 0; scan(o[k]); } } };
  scan(raw);
  if (typeof raw.schemaVersion!=='number') throw 0;
  if (raw.schemaVersion>SCHEMA_VERSION) throw 0;      // reject unsupported future version
  const p = raw.payload;
  if (!p || typeof p!=='object') throw 0;
  if (p.sibling && !['wren','cael'].includes(p.sibling)) throw 0;
  if (p.klass && !CLASSES[p.klass]) throw 0;
  if (p.hp!=null && (typeof p.hp!=='number' || p.hp<0 || p.hp>10000)) throw 0;
  if (p.elements && typeof p.elements!=='object') throw 0;
  return p;
}
function hydrate(p){
  // transactional: build a full next-state, only commit if all good
  const next = {
    sibling: p.sibling||'wren', klass: p.klass||'sword',
    hp: clamp(p.hp??100,0,999), maxHp: clamp(p.maxHp??100,1,999),
    tokens: clamp(p.tokens??0,0,999999)|0, weaponLevel: clamp(p.weaponLevel??1,1,99)|0,
    elements: {loam:!!p.elements?.loam,tide:!!p.elements?.tide,cinder:!!p.elements?.cinder,arc:!!p.elements?.arc,rime:!!p.elements?.rime},
    activeElement: ELEMENTS[p.activeElement]?p.activeElement:'none',
    glideUnlocked: !!p.glideUnlocked, stage: clamp(p.stage??0,0,9)|0,
    flags: Object.assign({fished:false,firstKill:false,transformedOnce:false,campPassed:false,trialPassed:false,iceMelted:false,resistHinted:false}, (p.flags&&typeof p.flags==='object')?p.flags:{}),
    pos: p.pos && typeof p.pos.x==='number' ? p.pos : null,
  };
  // v2 fields — v1 saves migrate to sensible defaults for their class
  const roster = WEAPONS[next.klass] || WEAPONS.sword;
  const starter = roster[0].id;
  // v5: every weapon is unlocked for everyone, so `owned` is always the full set
  const owned = allWeapons().map(w=>w.id);
  const equipped = (typeof p.equipped==='string' && owned.includes(p.equipped)) ? p.equipped : starter;
  const boolMap = (src, keys) => { const o={}; for (const k of keys) o[k] = !!(src && src[k]); return o; };
  next.owned = owned; next.equipped = equipped;
  // mastery: use saved values, else convert a pre-v5 weaponLevel into the
  // player's own discipline so old saves keep the power they earned
  next.mastery = { sword:1, bow:1, greatsword:1, dual:1, focus:1 };
  const mp = (p.mastery && typeof p.mastery==='object') ? p.mastery : null;
  if (mp){
    for (const t of WEAPON_TYPES){
      const v = Number(mp[t]);
      next.mastery[t] = Number.isFinite(v) ? Math.max(1, Math.min(MASTERY_MAX, Math.floor(v))) : 1;
    }
  } else {
    const lv = Math.max(1, Math.min(MASTERY_MAX, Number(p.weaponLevel)||1));
    next.mastery[next.klass] = Math.max(2, lv);   // discipline keeps its head start
  }
  next.chests = {}; if (p.chests && typeof p.chests==='object'){ for (const k of Object.keys(p.chests)){ if (/^chest-[a-z-]{1,24}$/.test(k)) next.chests[k]=!!p.chests[k]; } }
  next.mechs = boolMap(p.mechs, ['loam','tide','arc','rime']);
  next.bossDefeated = !!p.bossDefeated;
  // v3 fields — older saves get empty defaults
  next.bag = [];
  if (Array.isArray(p.bag)) for (const s of p.bag){
    if (s && isValidItemId(s.id) && next.bag.length < 60){
      const n = clamp(s.n, 1, 999)|0;
      if (n > 0) next.bag.push({ id:s.id, n:Math.min(n, stackLimit(s.id)) });
    }
  }
  next.hotbar = new Array(10).fill(null);
  if (Array.isArray(p.hotbar)) p.hotbar.slice(0,10).forEach((h,i)=>{
    if (!h || typeof h !== 'object') return;
    if (h.kind==='weapon' && roster.some(w=>w.id===h.id)) next.hotbar[i] = {kind:'weapon', id:h.id};
    else if ((h.kind==='item' || h.kind==='element') && isValidItemId(h.id)){
      const t = itemDef(h.id).type;
      if ((h.kind==='element') === (t==='element')) next.hotbar[i] = {kind:h.kind, id:h.id};
    }
  });
  // pre-hotbar saves (v1/v2): seed the bar with the equipped weapon
  // (elements are cycled with Q/E, not slotted)
  if (next.hotbar.every(s=>!s)) next.hotbar[0] = { kind:'weapon', id:equipped };
  // placed structures (validated: known block types + integer coords)
  next.build = [];
  if (Array.isArray(p.build)) for (const b of p.build){
    if (b && isValidItemId(b.t) && itemDef(b.t).type==='block'
        && Number.isFinite(b.gx) && Number.isFinite(b.gy) && Number.isFinite(b.gz)
        && Math.abs(b.gx)<300 && Math.abs(b.gz)<500 && next.build.length<MAX_PLACED){
      next.build.push({ t:b.t, gx:b.gx|0, gy:b.gy|0, gz:b.gz|0, trap:(typeof b.trap==='string'?b.trap:null) });
    }
  }
  next.dragonDefeated = !!p.dragonDefeated;
  next.hardMode = !!p.hardMode;
  next.underground = false;
  // quests (v4). Sanitize against the known quest/pool ids; older saves reconstruct below.
  const mainIds = MAIN_QUESTS.map(q=>q.id);
  const sideIds = SIDE_QUESTS.map(s=>s.id);
  const lessonIds = [...mainIds, ...sideIds];       // v6: insights come from both
  const dailyIds = DAILY_POOL.map(d=>d.id), weeklyIds = WEEKLY_POOL.map(w=>w.id);
  const sanEntries = (arr, ids)=> Array.isArray(arr) ? arr.filter(e=>e&&ids.includes(e.id))
    .map(e=>({ id:e.id, prog:Math.max(0,Math.min(9999, e.prog|0)), done:!!e.done })) : [];
  const qp = (p.quest && typeof p.quest==='object') ? p.quest : null;
  if (qp){
    next.quest = {
      main: Math.max(0, Math.min(MAIN_QUESTS.length, qp.main|0)),
      mainDone: Array.isArray(qp.mainDone) ? qp.mainDone.filter(id=>mainIds.includes(id)) : [],
      insights: Array.isArray(qp.insights) ? qp.insights.filter(id=>lessonIds.includes(id)) : [],
      // v5-and-older saves never took a quiz; their earned insights start unsealed
      // and the Journal invites them to seal each one.
      sealed: Array.isArray(qp.sealed) ? qp.sealed.filter(id=>lessonIds.includes(id)) : [],
      side: sanEntries(qp.side, sideIds),
      daily: sanEntries(qp.daily, dailyIds), weekly: sanEntries(qp.weekly, weeklyIds),
      dailyDate: typeof qp.dailyDate==='string' ? qp.dailyDate.slice(0,10) : '',
      weeklyKey: typeof qp.weeklyKey==='string' ? qp.weeklyKey.slice(0,10) : '',
    };
  } else {
    next.quest = { main:0, mainDone:[], insights:[], sealed:[], side:[], daily:[], weekly:[], dailyDate:'', weeklyKey:'' };
    next._reconstructQuest = true;   // pre-v4 save: rebuild story progress from flags after assign
  }
  Object.assign(G, {
    sibling:next.sibling, klass:next.klass, hp:next.hp, maxHp:next.maxHp,
    tokens:next.tokens, weaponLevel:next.weaponLevel, elements:next.elements,
    activeElement:next.activeElement, glideUnlocked:next.glideUnlocked, stage:next.stage, flags:next.flags,
    owned:next.owned, equipped:next.equipped, mastery:next.mastery, chests:next.chests, mechs:next.mechs,
    bossDefeated:next.bossDefeated,
    bag:next.bag, hotbar:next.hotbar,
    build:next.build, dragonDefeated:next.dragonDefeated, hardMode:next.hardMode, underground:false,
    quest:next.quest,
  });
  if (next._reconstructQuest) reconstructMainFromFlags();
  ensureQuests();                 // roll today's daily/weekly if missing or stale
  reconcileQuests();              // catch the chain up to whatever already happened
  return next;
}
function clamp(v,a,b){ v=Number(v); if(!isFinite(v))v=a; return Math.max(a,Math.min(b,v)); }

function loadFromObject(raw){
  let p;
  try { p = validateSave(raw); } catch(e){ toast(GENERIC_INVALID,'bad',3600); return false; }
  const next = hydrate(p);
  // rebuild world with loaded sibling/class
  startLoadedGame(next);
  return true;
}
function loadFromFile(file){
  if (!file) return;
  if (file.size > 512*1024){ toast(GENERIC_INVALID,'bad',3600); return; }
  const reader = new FileReader();
  reader.onload = ()=>{ let obj; try{ obj=JSON.parse(reader.result); }catch(e){ toast(GENERIC_INVALID,'bad',3600); return; } loadFromObject(obj); };
  reader.onerror = ()=> toast(GENERIC_INVALID,'bad',3600);
  reader.readAsText(file);
}
function continueSave(){
  try{ const obj=JSON.parse(localStorage.getItem(SAVE_KEY)||'null'); if(!obj){ toast('No saved journey found.','info',2000); return; } loadFromObject(obj); }
  catch(e){ toast(GENERIC_INVALID,'bad',3600); }
}

function startLoadedGame(next){
  // fresh scene build
  hideAllMenus();
  buildFreshWorldFor(next);
  G.phase='playing'; show(dom.hud);
  applySettings(); refreshElementWheel(); updateHUD();
  // reflect unlocked wardstones visually
  for (const ws of wardstones){ if (G.elements[ws.elem]){ ws.unlocked=true; ws.sig.material.color.set(ELEMENTS[ws.elem].color); ws.sig.material.emissive.set(ELEMENTS[ws.elem].color); ws.sig.material.emissiveIntensity=1; ws.glow.intensity=1.6; } }
  if (G.flags.iceMelted && iceWall){ for(let i=colliders.length-1;i>=0;i--) if(colliders[i].tag==='ice') colliders.splice(i,1); world.remove(iceWall); }
  // re-apply completed mechanisms (opens gate / freezes lake / raises steps; respawns boss if undefeated)
  for (const m of mechanisms){ if (G.mechs[m.id]) activateMechanism(m, false); }
  // rebuild placed structures
  for (const b of (G.build||[])) placeBlock(b.t, b.gx, b.gy, b.gz, b.trap||null, true);
  setActiveElement(G.activeElement);
  if (next.pos){
    // saved underground? surface safely at the barrow (avoids loading into an unbuilt cavern)
    if (next.pos.z < -200){ player.position.set(-96, terrainH(-96,-92), -92); }
    else player.position.set(next.pos.x, terrainH(next.pos.x, next.pos.z), next.pos.z);
  }
  refreshObjective();
  tainerSay('Back on the road! I kept your place. Let’s keep looking.', 4200);
  // pre-v6 saves carry earned-but-unsealed insights; say so rather than letting
  // the rank quietly look like it went backwards
  const pending = G.quest.insights.filter(id=>!isSealed(id)).length;
  if (pending) setTimeout(()=>{
    toast(`${pending} insight${pending>1?'s':''} awaiting you — open the Journal (L) to read and seal ${pending>1?'them':'it'}.`, 'info', 6000);
  }, 5000);
}

/* ============================================================ WORLD REBUILD */
function clearWorld(){
  // remove dynamic actors
  for (const e of enemies){ scene.remove(e.mesh); } enemies.length=0;
  for (const o of orbs){ scene.remove(o.mesh); } orbs.length=0;
  for (const p of projectiles){ scene.remove(p.mesh); } projectiles.length=0;
  for (const s of enemyShots){ scene.remove(s.mesh); } enemyShots.length=0;
  for (const p of particles){ scene.remove(p.grp); } particles.length=0;
  wardstones.length=0; interactables.length=0; windZones.length=0; hoops.length=0; spinners.length=0; colliders.length=0;
  mechanisms.length=0; platforms.length=0; bossRef=null; bossChestSpawned=false; lakeFrozen=false; motes=null; hide(dom['boss-bar']);
  harvestables.length=0; placed.length=0; placedMap.clear(); POIS.length=0; forges.length=0;
  cavernBuilt=false; pitCount=0; dragonRef=null; dragonHome=null; G.underground=false; explored.clear();
  for (const d of drops) scene?.remove(d.mesh); drops.length=0;
  for (const f of floaters) f.el.remove(); floaters.length=0;
  setAmbiance(false);
  if (player){ scene.remove(player); player=null; }
  if (tainerMesh){ scene.remove(tainerMesh); tainerMesh=null; }
  if (mimicMesh){ scene.remove(mimicMesh); mimicMesh=null; }
  scene.remove(world);
  while(world.children.length) world.remove(world.children[0]);
}
function buildFreshWorldFor(next){
  clearWorld();
  // reset transient
  G.mimic = { state:'Normal', hp:0, maxHp:0, orbHeld:false, cooldown:0, savedHp:G.hp };
  pv.set(0,0,0); grounded=true; glideActive=false; trialActive=false; alertLevel=0;
  buildWorld();
  if (G.flags.fished && tainerMesh) tainerMesh.visible=true;
  worldBuilt=true;
}

function hideAllMenus(){
  [dom['menu-title'],dom['menu-sibling'],dom['menu-class'],dom.cinematic,dom['menu-pause'],dom['menu-settings'],dom['menu-map'],dom['menu-inv'],dom['menu-journal'],dom['menu-reflect'],dom.loading].forEach(hide);
  reflectQueue = []; reflectCur = null;
}

/* first-time (new game) world build after class confirm */
function startFreshWorld(){
  buildFreshWorldFor({pos:null});
}

/* ================================================================= BUTTONS */
function bindButtons(){
  dom['btn-new'].onclick = ()=> newGame();
  dom['btn-continue'].onclick = ()=> continueSave();
  dom['btn-load'].onclick = ()=> dom['file-input'].click();
  dom['btn-load-pause'].onclick = ()=> dom['file-input'].click();
  dom['btn-settings-title'].onclick = ()=> openSettings('title');
  dom['btn-settings-pause'].onclick = ()=> openSettings('pause');
  dom['btn-settings-back'].onclick = ()=> closeSettings();
  dom['btn-resume'].onclick = ()=> resume();
  dom['btn-inv'].onclick = ()=> openInventory();
  dom['btn-inv-back'].onclick = ()=> closeInventory();
  const TYPE_ORDER = { consumable:0, tool:1, block:2, element:3, material:4 };
  dom['btn-sort'].onclick = ()=>{
    G.bag.sort((a,b)=>{
      const da=itemDef(a.id), db=itemDef(b.id);
      return (TYPE_ORDER[da.type]-TYPE_ORDER[db.type]) || da.name.localeCompare(db.name) || b.n-a.n;
    });
    renderInv();
  };
  if (dom['craft-search']) dom['craft-search'].oninput = ()=> renderCrafting();
  if (dom['btn-map-close']) dom['btn-map-close'].onclick = ()=> closeMap();
  if (dom['btn-journal']) dom['btn-journal'].onclick = ()=> openJournal();
  if (dom['btn-journal-close']) dom['btn-journal-close'].onclick = ()=> closeJournal();
  if (dom['btn-reflect-read']) dom['btn-reflect-read'].onclick = ()=> showReflectQuiz();
  for (const id of ['btn-reflect-later','btn-reflect-later2'])
    if (dom[id]) dom[id].onclick = ()=> closeReflection();
  if (dom.jtabs) [...dom.jtabs.children].forEach(b=> b.onclick = ()=>{ journalTab=b.dataset.tab; renderJournal(); });
  buildHotbarUI();
  dom['btn-save'].onclick = ()=> downloadSave();
  dom['btn-quit'].onclick = ()=> { hide(dom['menu-pause']); goTitle(); };
  dom['file-input'].onchange = (e)=> { loadFromFile(e.target.files[0]); e.target.value=''; };

  // settings live bindings
  dom['set-theme'].onchange = e=>{ settings.theme=e.target.value; applySettings(); };
  dom['set-contrast'].onchange = e=>{ settings.contrast=e.target.checked; applySettings(); };
  dom['set-motion'].onchange = e=>{ settings.motion=e.target.checked; applySettings(); };
  dom['set-ui'].onchange = e=>{ settings.ui=e.target.checked; applySettings(); };
  dom['set-cam'].oninput = e=>{ settings.cam=parseFloat(e.target.value); saveSettings(); };
  dom['set-invert'].onchange = e=>{ settings.invert=e.target.checked; saveSettings(); };
  dom['set-shoulder'].onchange = e=>{ settings.shoulder=e.target.value; saveSettings(); };
  dom['set-hard'].onchange = e=>{ G.hardMode = e.target.checked && G.dragonDefeated;
    if (e.target.checked && !G.dragonDefeated){ e.target.checked=false; toast('Defeat the Deepwyrm to unlock Deepened mode.', 'info', 2600); } };
  dom['set-aim'].onchange = e=>{ settings.aim=e.target.checked; saveSettings(); };
  dom['set-vol'].oninput = e=>{ settings.vol=parseFloat(e.target.value); setMasterVol(); saveSettings(); };
}

/* hook class-confirm to build the world before opening cinematic already done;
   we build world lazily at enterWorld via ensureWorld */
let worldBuilt=false;
function ensureWorld(){ if(!worldBuilt){ startFreshWorld(); worldBuilt=true; } }

/* ================================================================= MAIN LOOP */
let autosaveT = 0;
let mmT = 0;        // minimap redraw throttle
let stepT = 0;      // footstep cadence
let hitstop = 0;    // brief freeze-frame on landed hits (impact feel)
function loop(){
  requestAnimationFrame(loop);
  const dt = Math.min(0.05, clock?clock.getDelta():0.016);
  if (hitstop > 0){ hitstop -= dt; if (renderer) renderer.render(scene, camera); return; }
  if (G.phase==='playing'){
    updatePlayer(dt);
    updateEnemies(dt);
    updateProjectiles(dt);
    updateStealth(dt);
    updateTrial();
    tickMimicCooldown(dt);
    updateTainerFollow(dt);
    updateDrops(dt);
    updateHarvest(dt);
    updateTraps(dt);
    updateEnemyShots(dt);
    maybeAwakenDragon();
    tickCombo(dt);
    markExplored();
    mmT += dt; if (mmT>0.12){ mmT=0; drawMinimap(); }
    updateCamera(dt);
    // autosave every 12s
    autosaveT += dt; if (autosaveT>12){ autosaveT=0; if(G.klass) autosave(); }
  }
  updateParticles(dt);
  updateFloaters(dt);
  for (const s of spinners) s.rotation.z += dt*1.2;
  if (motes && !settings.motion){
    motes.rotation.y += dt*0.008;
    motes.position.y = Math.sin(performance.now()*0.0004)*0.35;
  }
  updateAim();
  if (renderer) renderer.render(scene, camera);
}
function updateProjectiles(dt){
  for (let i=projectiles.length-1;i>=0;i--){
    const p=projectiles[i]; p.life-=dt; p.mesh.position.addScaledVector(p.vel,dt);
    let hit=false;
    // hit test in the horizontal plane with a torso-height band. A plain 3D
    // distance check sat exactly on the threshold (shots fly at y≈1.3 while
    // enemy origins sit on the ground), so ranged hits were unreliable.
    for (const e of enemies){
      if (!e.alive) continue;
      const hx = p.mesh.position.x - e.mesh.position.x, hz = p.mesh.position.z - e.mesh.position.z;
      const hy = p.mesh.position.y - (e.mesh.position.y + (e.boss?2.2:0.9));
      if (Math.hypot(hx,hz) < e.r + 0.5 && Math.abs(hy) < (e.boss?3.0:1.7)){
        if (p.hitList && p.hitList.includes(e)) continue;      // already pierced this one
        damageEnemy(e,p.dmg);
        if (p.pierce > 0){ p.pierce--; (p.hitList = p.hitList||[]).push(e); }   // carry on through
        else hit = true;
        break;
      }
    }
    if (!hit) for (const m of mechanisms){
      if (m.done) continue;
      if (Math.hypot(p.mesh.position.x-m.pos.x, p.mesh.position.z-m.pos.z) < 1.6){
        if (p.elem === m.elem) activateMechanism(m);
        else toast(`This mechanism answers only to ${ELEMENTS[m.elem].name} (${ELEMENTS[m.elem].sigil}).`, 'info', 2400);
        hit=true; break;
      }
    }
    if (!hit && iceWall && !G.flags.iceMelted && p.elem==='cinder' &&
        Math.hypot(p.mesh.position.x-iceWall.position.x, p.mesh.position.z-iceWall.position.z) < 3.2){ meltIce(); hit=true; }
    if (!hit) for (const h of harvestables){
      if (h.respawnAt>0) continue;
      if (Math.hypot(p.mesh.position.x-h.mesh.position.x, p.mesh.position.z-h.mesh.position.z) < 1.0
          && Math.abs(p.mesh.position.y - (h.mesh.position.y+0.8)) < 1.4){ damageHarvest(h); hit=true; break; }
    }
    if (!hit && p.mesh.position.y < terrainH(p.mesh.position.x, p.mesh.position.z) + 0.1){
      spawnBurst(p.mesh.position.clone(), 0xd9d0b8, 5, 0.4); hit=true;   // arrows bury into hillsides
    }
    if (hit||p.life<=0){ scene.remove(p.mesh); projectiles.splice(i,1); }
  }
}
function updateTainerFollow(dt){
  if (!tainerMesh || !tainerMesh.visible) return;
  const target = (G.mimic.state==='Transformed'&&mimicMesh?mimicMesh:player).position.clone()
    .add(new THREE.Vector3(-1.4, 2.2 + Math.sin(performance.now()*0.002)*0.2, -0.6));
  tainerMesh.position.lerp(target, 1-Math.pow(0.002,dt));
}

/* ================================================================= BOOT */
function setLoad(pct, msg){ if(dom['load-fill']) dom['load-fill'].style.width=pct+'%'; if(msg&&dom['load-status']) dom['load-status'].textContent=msg; }

function boot(){
  loadSettings();
  applySettings();
  bindInput();
  bindButtons();
  // wire class confirm to also build world
  const origConfirm = dom['btn-confirm-class'];
  setLoad(20,'Waking the renderer…');
  if (!initThree()){
    dom['load-fallback'].textContent = 'This browser could not start WebGL. Try a recent Chrome, Edge, or Firefox with hardware acceleration on.';
    return;
  }
  setLoad(55,'Shaping Willowmere Vale…');
  buildLights();
  setLoad(85,'Kindling the light…');
  clock = new THREE.Clock();
  loop();
  setLoad(100,'Ready.');
  setTimeout(()=>{ hide(dom.loading); goTitle(); }, 500);
  if (location.search.includes('dev')) installDevHooks();
}

/* Testing/QA hook — only active with ?dev=1. Never exposed in normal play. */
function installDevHooks(){
  window.__EMBER = {
    get G(){ return G; },
    state: ()=> ({ phase:G.phase, hp:G.hp, tokens:G.tokens, weaponLevel:G.weaponLevel,
      mimic:{...G.mimic}, elements:{...G.elements}, activeElement:G.activeElement,
      glide:G.glideUnlocked, aliveEnemies:enemies.filter(e=>e.alive).length,
      pos: player?{x:+player.position.x.toFixed(2),z:+player.position.z.toFixed(2)}:null }),
    giveOrb: ()=>{ G.mimic.orbHeld=true; setMimicState('OrbAvailable'); show(dom['orb-status']); updateHUD(); },
    transform: ()=> beginTransform(),
    eject: (auto)=> beginEject(!!auto),
    hurtMimic: (n)=> damageMimic(n),
    hurtPlayer: (n)=> damagePlayer(n),
    setHp: (n)=>{ G.hp=n; updateHUD(); },
    spawnNear: ()=>{ const f=new THREE.Vector3(Math.sin(player.rotation.y),0,Math.cos(player.rotation.y));
      return spawnEnemy(player.position.clone().add(f.multiplyScalar(3)),'grumble',true); },
    killNearest: ()=>{ let b=null,bd=1e9; for(const e of enemies){ if(!e.alive) continue;
      const d=player.position.distanceTo(e.mesh.position); if(d<bd){bd=d;b=e;} } if(b) defeatEnemy(b); return !!b; },
    unlockAll: ()=>{ for(const ws of wardstones) unlockElement(ws.elem, ws); },
    orbCount: ()=> orbs.length,
    save: ()=> serialize(),
    loadObj: (o)=> loadFromObject(o),
    validate: (o)=>{ try { validateSave(o); return 'valid'; } catch(e){ return GENERIC_INVALID; } },
    // Phase-2 hooks
    mech: (id)=>{ const m=mechanisms.find(x=>x.id===id); if(m) activateMechanism(m); return !!m; },
    mechs: ()=> ({...G.mechs}),
    boss: ()=> bossRef ? { alive:bossRef.alive, hp:Math.round(bossRef.hp), maxHp:bossRef.maxHp, phase:bossRef.phase, weak:+bossRef.weak.toFixed(2) } : null,
    hurtBoss: (n)=>{ if(bossRef&&bossRef.alive) damageEnemy(bossRef,n); },
    mastery: ()=> ({...G.mastery}),
    advanceMastery: (t)=> advanceMastery(t),
    equippedType: ()=> equippedType(),
    allWeaponIds: ()=> allWeapons().map(w=>w.id),
    rig: ()=>{
      const held = player?.userData?.weapons || {};
      const wp = new THREE.Vector3(), lp = new THREE.Vector3();
      if (held.right) held.right.getWorldPosition(wp);
      if (held.left) held.left.getWorldPosition(lp);
      return {
        type: equippedType(),
        rightParentIsArm: held.right ? held.right.parent === playerParts.armR : false,
        leftParentIsArm:  held.left  ? held.left.parent  === playerParts.armL : null,
        hasLeftBlade: !!held.left,
        weaponWorldY: held.right ? +wp.y.toFixed(3) : null,
        weaponWorldZ: held.right ? +wp.z.toFixed(3) : null,
        leftWorldY: held.left ? +lp.y.toFixed(3) : null,
        armR: +playerParts.armR.rotation.x.toFixed(3),
        armL: +playerParts.armL.rotation.x.toFixed(3),
        atkAnim: +atkAnim.toFixed(2), swingSide, atkCd: +playerAtkCd.toFixed(2),
      };
    },
    mods: ()=> equippedMods(),
    hoopList: ()=> hoops.map(h=>({x:+h.position.x.toFixed(1), y:+h.position.y.toFixed(1), z:+h.position.z.toFixed(1), passed:!!h.userData.hoop.passed})),
    trialActive: ()=> trialActive,
    startTrial: ()=> startTrial(),
    projCount: ()=> projectiles.length,
    projList: ()=> projectiles.map(p=>({x:+p.mesh.position.x.toFixed(2), y:+p.mesh.position.y.toFixed(2), z:+p.mesh.position.z.toFixed(2), life:+p.life.toFixed(2)})),
    equip: (id)=>{ if(G.owned.includes(id)){ G.equipped=id; updateHUD(); return true; } return false; },
    gear: ()=> ({ owned:[...G.owned], equipped:G.equipped, power:weaponPower(equippedWeapon()) }),
    warp: (x,z)=>{ player.position.set(x,0,z); },
    chestsState: ()=> ({...G.chests}),
    interact: ()=> tryInteract(),
    pos: ()=> player ? { x:+player.position.x.toFixed(3), y:+player.position.y.toFixed(3), z:+player.position.z.toFixed(3) } : null,
    setYaw: (y)=>{ yaw = y; return yaw; },
    // glide is driven by a HELD input; expose it so touch-vs-key parity is testable
    glideState: ()=> ({ spaceHeld: !!keys[' '], gliding: glideActive, unlocked: G.glideUnlocked,
      grounded, vy:+pv.y.toFixed(3), y:+(player?player.position.y:0).toFixed(3) }),
    chestList: ()=> interactables.filter(i=>/chest/.test(i.id||'')).map(i=>({id:i.id, x:i.pos.x, z:i.pos.z, open:!!G.chests[i.id]})),
    // wisdom / reflection harness
    reflect: ()=> ({ open:G.phase==='reflect', cur:reflectCur?.id||null, attempts:reflectAttempts,
      queued:reflectQueue.map(q=>q.id), quizShown:!dom['reflect-quizbox'].classList.contains('hidden'),
      lesson:dom['reflect-teaching'].textContent, question:dom['reflect-q'].textContent,
      options:[...dom['reflect-opts'].children].map(b=>b.textContent) }),
    reflectRead: ()=> showReflectQuiz(),
    reflectAnswer: (i)=> answerReflection(i),
    reflectClose: ()=> closeReflection(),
    wisdom: ()=> ({ rank:wisdomTitle(), sealed:[...G.quest.sealed], earned:[...G.quest.insights],
      total:ALL_LESSONS.length,
      side:G.quest.side.map(e=>({id:e.id, prog:e.prog, done:e.done})) }),
    noteEvent: (t,n)=> noteEvent(t, n||1),
    viewYaw: ()=> yaw,
    view: ()=> ({ yaw:+yaw.toFixed(3), pitch:+pitch.toFixed(3), camDist }),
    facing: ()=> player ? +player.rotation.y.toFixed(3) : null,
    height: (x,z)=> +terrainH(x,z).toFixed(2),
    playerY: ()=> player ? +player.position.y.toFixed(2) : null,
    // Phase A framework hooks
    bag: ()=> JSON.parse(JSON.stringify(G.bag)),
    hotbarState: ()=> JSON.parse(JSON.stringify(G.hotbar)),
    give: (id,n)=> addItem(id,n),
    use: (id)=> useItem(id),
    count: (id)=> countItem(id),
    setSlot: (i,entry)=>{ G.hotbar[i]=entry; return true; },
    pressSlot: (i)=> selectHotbar(i),
    action: (k)=> INPUT.actionFor(k),
    // Phase C
    harvestCount: ()=> harvestables.filter(h=>h.respawnAt<=0).length,
    dropCount: ()=> drops.length,
    nearestHarvest: (kind)=>{ const p=player.position;
      let best=null,bd=1e9; for(const h of harvestables){ if(h.respawnAt>0)continue;
        if(kind==='stone'){ if(h.kind!=='rock'||h.ore) continue; }
        else if(kind&&h.kind!==kind&&!(kind==='ore'&&h.ore))continue;
        const d=p.distanceTo(h.mesh.position); if(d<bd){bd=d;best=h;} } return best?{kind:best.kind,ore:best.ore,drop:best.drop,x:+best.mesh.position.x.toFixed(1),z:+best.mesh.position.z.toFixed(1),d:+bd.toFixed(1)}:null; },
    warpToHarvest: (kind)=>{ const p=player.position; let best=null,bd=1e9;
      for(const h of harvestables){ if(h.respawnAt>0)continue; if(kind==='ore'&&!h.ore)continue; if(kind&&kind!=='ore'&&h.kind!==kind)continue;
        const d=p.distanceTo(h.mesh.position); if(d<bd){bd=d;best=h;} }
      if(best){ player.position.set(best.mesh.position.x, terrainH(best.mesh.position.x,best.mesh.position.z), best.mesh.position.z-2.4);
        const dx=best.mesh.position.x-player.position.x, dz=best.mesh.position.z-player.position.z, L=Math.hypot(dx,dz)||1;
        yaw = Math.atan2(-dx/L, -dz/L); return true; } return false; },
    swing: ()=> doAttack(),
    // Phase D
    placedCount: ()=> placed.length,
    placeAhead: (type)=>{ const c=aimCell(); return placeBlock(type, c.gx, c.gy, c.gz, itemDef(type)?.trap||null); },
    dig: ()=> digGround(),
    descend: ()=> descend(),
    ascend: ()=> ascend(),
    underground: ()=> G.underground,
    cavernBuilt: ()=> cavernBuilt,
    setActiveSlot: (i)=>{ activeSlot=i; refreshHotbarUI(); },
    // Phase E
    craft: (rid)=>{ const r=RECIPES.find(x=>x.id===rid); return r?craft(r):false; },
    canCraft: (rid)=>{ const r=RECIPES.find(x=>x.id===rid); return r?recipeAvailable(r):null; },
    nearForge: ()=> nearForge(),
    recipes: ()=> RECIPES.map(r=>r.id),
    // Phase F
    spawnEnemyAt: (x,z,kind)=> spawnEnemy(new THREE.Vector3(x,0,z), kind||'grumble'),
    enemyStatus: (i)=>{ const e=enemies.filter(x=>x.alive)[i]; return e?{...(e.status||{}),hp:Math.round(e.hp)}:null; },
    aliveEnemyList: ()=> enemies.filter(e=>e.alive).map(e=>({kind:e.kind,hp:Math.round(e.hp),x:+e.mesh.position.x.toFixed(1),z:+e.mesh.position.z.toFixed(1)})),
    placedList: ()=> placed.map(e=>({type:e.type,trap:e.trap||null,x:e.gx,y:e.gy,z:e.gz,hp:Math.round(e.hp)})),
    placeAt: (type,gx,gy,gz)=> placeBlock(type,gx,gy,gz,itemDef(type)?.trap||null),
    blockHp: (gx,gz)=>{ const e=placed.find(p=>p.gx===gx&&p.gz===gz); return e?Math.round(e.hp):null; },
    hurtNearest: (n)=>{ let best=null,bd=1e9; for(const e of enemies){ if(!e.alive)continue; const d=player.position.distanceTo(e.mesh.position); if(d<bd){bd=d;best=e;} } if(best){ damageEnemy(best,n); return true;} return false; },
    enemyStatusFor: (x,z)=>{ let best=null,bd=1e9; for(const e of enemies){ if(!e.alive)continue; const d=Math.hypot(e.mesh.position.x-x,e.mesh.position.z-z); if(d<bd){bd=d;best=e;} } return best?{...(best.status||{}),hp:Math.round(best.hp),d:+bd.toFixed(1)}:null; },
    // Phase G
    setElement: (el)=> setActiveElement(el),
    reactOn: (x,z)=>{ let best=null,bd=1e9; for(const e of enemies){ if(!e.alive)continue; const d=Math.hypot(e.mesh.position.x-x,e.mesh.position.z-z); if(d<bd){bd=d;best=e;} }
      if(!best) return null; const before=Math.round(best.hp); damageEnemy(best, 1); return { hpBefore:before, hpAfter:Math.round(best.hp), aura:best.aura?best.aura.elem:null }; },
    combo: ()=> G.combo,
    charged: ()=> doChargedAttack(),
    jumpsUsed: ()=> jumpsUsed, queueJump: ()=> queueJump(),
    dash: (dx,dz)=> tryDash(new THREE.Vector3(dx,0,dz)),
    playerY2: ()=> +player.position.y.toFixed(2),
    // Phase H
    openMap: ()=> openMap(), closeMap: ()=> closeMap(),
    exploredCount: ()=> explored.size,
    poiCount: ()=> POIS.length,
    faceToward: (x,z)=>{ const dx=x-player.position.x, dz=z-player.position.z; yaw=Math.atan2(-dx,-dz); },
    // the on-screen heading-arrow direction (unit, screen space: +x right, +y down)
    arrowDir: ()=> ({ x:+Math.sin(player.rotation.y).toFixed(3), z:+Math.cos(player.rotation.y).toFixed(3) }),
    lakePos: ()=> lakePos ? { x:lakePos.x, z:lakePos.z } : null,
    // Phase I
    dragon: ()=> dragonRef ? { alive:dragonRef.alive, hp:Math.round(dragonRef.hp), maxHp:dragonRef.maxHp, phase:dragonRef.phase,
      x:+dragonRef.mesh.position.x.toFixed(1), z:+dragonRef.mesh.position.z.toFixed(1), r:dragonRef.r } : null,
    awakenDragon: ()=>{ if(!dragonRef && dragonHome && !G.dragonDefeated){ spawnDragon(); return true; } return false; },
    hurtDragon: (n)=>{ if(dragonRef&&dragonRef.alive){ const d=dragonRef; damageEnemy(d,n); return d.alive?Math.round(d.hp):'defeated';} return null; },
    dragonDefeated: ()=> G.dragonDefeated,
    hardMode: ()=> G.hardMode,
    enemyShotCount: ()=> enemyShots.length,
    // touch controls
    enableTouch: ()=> enableTouch(),
    usingTouch: ()=> usingTouch,
    setStick: (x,y,sprint)=>{ touch.mx=x; touch.my=y; touch.sprint=!!sprint; },
    touchState: ()=> ({ usingTouch, mx:touch.mx, my:touch.my, sprint:touch.sprint }),
    // quests & journal
    questState: ()=> ({ main:G.quest.main, active:activeMainQuest()?.id||null,
      done:[...G.quest.mainDone], insights:G.quest.insights.length, rank:wisdomTitle(),
      daily:G.quest.daily.map(d=>({id:d.id,prog:d.prog,done:d.done})),
      weekly:G.quest.weekly.map(w=>({id:w.id,prog:w.prog,done:w.done})) }),
    fireTrigger: (t)=> advanceMain(t),
    noteEvent: (type,n,item)=> noteEvent(type,n,item),
    openJournal: ()=> openJournal(), closeJournal: ()=> closeJournal(),
    setTab: (t)=>{ journalTab=t; if(G.phase==='journal') renderJournal(); },
    // deterministic simulation stepping — RAF is throttled in background tabs,
    // so QA drives the same per-frame updates the real loop uses
    step: (sec=1)=>{
      const dt = 1/60, n = Math.round(sec/dt);
      for (let i=0;i<n;i++){
        if (G.phase==='playing'){
          updatePlayer(dt); updateEnemies(dt); updateProjectiles(dt);
          updateStealth(dt); updateTrial(); tickMimicCooldown(dt); updateTainerFollow(dt);
          updateDrops(dt); updateHarvest(dt); updateTraps(dt); updateEnemyShots(dt);
          maybeAwakenDragon(); tickCombo(dt); markExplored(); updateCamera(dt);
        }
        updateParticles(dt); updateFloaters(dt);
      }
      updateAim();
      return `stepped ${sec}s (${n} frames)`;
    },
  };
  console.log('[Emberkin] dev hooks installed: window.__EMBER');
}

boot();
