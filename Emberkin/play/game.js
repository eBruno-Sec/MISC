/* ============================================================================
   EMBERKIN — A Light Between Two
   Fully-3D third-person vertical slice. Core three.js only (no addons).
   All proper nouns are original to this project. Family-friendly, accessible.
   ========================================================================== */
import * as THREE from 'three';

/* ------------------------------------------------------------------ consts */
const SCHEMA_VERSION = 2;          // v2 adds weapons/chests/mechanisms/boss; v1 saves migrate
const PRODUCT_VERSION = '0.2.0-slice';
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
const WEAPONS = {
  sword:      [ {id:'sw1',name:'Vale Blade',tier:1},  {id:'sw2',name:'Bramblefang',tier:2}, {id:'sw3',name:'Dawnedge',tier:3} ],
  bow:        [ {id:'bw1',name:'Reed Bow',tier:1},    {id:'bw2',name:'Galewhisper',tier:2}, {id:'bw3',name:'Sunstring',tier:3} ],
  greatsword: [ {id:'gs1',name:'Cragcleaver',tier:1}, {id:'gs2',name:'Bouldersong',tier:2}, {id:'gs3',name:'Titanroot',tier:3} ],
  dual:       [ {id:'du1',name:'Twin Fangs',tier:1},  {id:'du2',name:'Skydancers',tier:2},  {id:'du3',name:'Emberfangs',tier:3} ],
  focus:      [ {id:'fo1',name:'Wander Rune',tier:1}, {id:'fo2',name:'Lumen Coil',tier:2},  {id:'fo3',name:'Starheart',tier:3} ],
};
const TIER_MULT = { 1:1, 2:1.4, 3:1.85 };
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
  weaponLevel: 1,
  owned: [], equipped: null,
  chests: {},
  mechs: { loam:false, tide:false, arc:false, rime:false },
  bossDefeated: false,
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
};

/* --------------------------------------------------------------------- DOM */
const $ = (id) => document.getElementById(id);
const dom = {};
['loading','load-status','load-fill','load-fallback','hud','hero-name','hp-fill','hp-text',
 'mimic-bar-wrap','mimic-fill','mimic-text','stam-fill','token-count','net-state','element-wheel',
 'prompt','prompt-key','prompt-text','orb-status','weapon-chip','weapon-name','weapon-lvl',
 'objective-text','alert-state','alert-text','tainer','tainer-text','toast',
 'menu-title','menu-sibling','menu-class','cinematic','cine-art','cine-text','cine-next','cine-skip',
 'menu-pause','menu-settings','class-preview','class-title','class-weapon','class-desc','class-stats',
 'class-complexity','btn-confirm-class','file-input',
 'btn-new','btn-continue','btn-load','btn-settings-title','btn-resume','btn-settings-pause','btn-save',
 'btn-load-pause','btn-quit','btn-settings-back',
 'set-theme','set-contrast','set-motion','set-ui','set-cam','set-invert','set-aim','set-vol',
 'boss-bar','boss-fill','menu-inv','inv-list','inv-tokens','btn-inv','btn-inv-back'
].forEach(id => dom[id] = $(id));

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
const particles = [];       // dissolve/vfx groups {mesh, life, max, vel[]}
let iceWall = null, campGoal = null, pellPos = null, lakePos = null;
const mechanisms = [];      // {id, elem, pos, r, done, apply(withVfx)}
const platforms = [];       // walkable tops: {x, z, hw, hd, topY}
let bossRef = null, bossChestSpawned = false;
let lakeFrozen = false;
const DEEP_WATER_R = 8.4;   // unswimmable centre of the lake until frozen
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
  scene.add(world);

  // ground
  const groundGeo = new THREE.CircleGeometry(200, 64);
  const ground = new THREE.Mesh(groundGeo, MAT.grass);
  ground.rotation.x = -Math.PI/2; ground.receiveShadow = true;
  world.add(ground);

  // subtle patches
  for (let i=0;i<40;i++){
    const r = 8 + Math.random()*160, a = Math.random()*Math.PI*2;
    const patch = new THREE.Mesh(new THREE.CircleGeometry(3+Math.random()*7, 12), MAT.grass2);
    patch.rotation.x = -Math.PI/2; patch.position.set(Math.cos(a)*r, 0.02, Math.sin(a)*r);
    world.add(patch);
  }

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
  g.position.set(x,0,z);
  g.userData.collide = { r: 0.7*s }; // trunk collision
  colliders.push({ x, z, r:0.7*s });
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
  windZones.push({ pos:new THREE.Vector3(-4,0,44), r:6, up:14 });
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
    pos: pos.clone(), radius, key:'E',
    label: () => 'Open chest',
    cond: () => !G.chests[id] && (!extraCond || extraCond()),
    onUse: () => {
      G.chests[id] = true;
      lid.rotation.x = -1.1;
      spawnBurst(pos.clone().add(new THREE.Vector3(0,1,0)), 0xf5c168, 22, 0.9, true);
      if (contents.type==='weapon') grantWeapon(contents.tier);
      else { addTokens(contents.n); toast(`+${contents.n} Emberlight!`, 'good', 2400); }
    },
  });
  return g;
}
function grantWeapon(tier){
  const w = WEAPONS[G.klass][tier-1];
  if (G.owned.includes(w.id)){ addTokens(15); toast(`A duplicate ${w.name} shimmers into 15 Emberlight.`, 'good', 3000); return; }
  G.owned.push(w.id);
  toast(`New weapon: ${w.name} (Tier ${tier})! Equip it from the pause menu.`, 'good', 4200);
  tainerSay(`Oooh, ${w.name}! That one sings. Check Weapons & Gear when you get a breath.`, 4800);
}
function findWeapon(id){ return (WEAPONS[G.klass]||[]).find(w=>w.id===id) || null; }
function equippedWeapon(){ return findWeapon(G.equipped) || WEAPONS[G.klass]?.[0] || {id:'?',name:'—',tier:1}; }

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
  makeChest('chest-isle', new THREE.Vector3(islePos.x, 0.3, islePos.z), {type:'weapon', tier:2});
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
    makeChest('chest-boss', new THREE.Vector3(BOSS_POS.x, 0, BOSS_POS.z), {type:'weapon', tier:3});
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
  if (d < 45 && e.alive){
    show(dom['boss-bar']);
    dom['boss-fill'].style.width = (e.hp/e.maxHp*100)+'%';
  } else hide(dom['boss-bar']);
}
function bossDefeatedFlow(e){
  G.bossDefeated = true;
  hide(dom['boss-bar']);
  addTokens(40);
  dissolve(e.mesh); dissolve(e.mesh);   // extra-big send-off, still just light
  if (!bossChestSpawned){ bossChestSpawned = true;
    makeChest('chest-boss', new THREE.Vector3(BOSS_POS.x, 0, BOSS_POS.z), {type:'weapon', tier:3}); }
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
  // weapon prop in right hand
  const wp = makeWeaponProp(G.klass);
  wp.position.set(0.5, 1.15, 0.1);
  player.add(wp); player.userData.weapon = wp;
  scene.add(player);
}

function makeWeaponProp(klass){
  const g = new THREE.Group();
  const steel = new THREE.MeshStandardMaterial({ color:0xcdd6e6, roughness:0.35, metalness:0.6, flatShading:true });
  const gold  = new THREE.MeshStandardMaterial({ color:0xe6c15a, roughness:0.4, metalness:0.5 });
  if (klass==='sword'){ const b=new THREE.Mesh(new THREE.BoxGeometry(0.08,1.1,0.02),steel); b.position.y=0.55; g.add(b);
    const h=new THREE.Mesh(new THREE.BoxGeometry(0.3,0.08,0.08),gold); g.add(h); }
  else if (klass==='greatsword'){ const b=new THREE.Mesh(new THREE.BoxGeometry(0.18,1.7,0.05),steel); b.position.y=0.85; g.add(b);
    const h=new THREE.Mesh(new THREE.BoxGeometry(0.5,0.1,0.1),gold); g.add(h); }
  else if (klass==='dual'){ const b=new THREE.Mesh(new THREE.BoxGeometry(0.06,0.8,0.02),steel); b.position.y=0.4; g.add(b); }
  else if (klass==='bow'){ const b=new THREE.Mesh(new THREE.TorusGeometry(0.5,0.04,6,12,Math.PI*1.2),
      new THREE.MeshStandardMaterial({color:0x8a5a2c,roughness:0.8})); b.rotation.z=Math.PI/2; g.add(b); }
  else if (klass==='focus'){ const b=new THREE.Mesh(new THREE.OctahedronGeometry(0.28,0),
      new THREE.MeshStandardMaterial({color:0xb48bf0,emissive:0x5a3a8a,emissiveIntensity:0.7,flatShading:true}));
    b.position.set(0.2,0.2,0); g.add(b); g.userData.float=b; }
  return g;
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
  const baseHp = (big?120:48) + (elem?14:0);   // variants are a little tougher
  const e = {
    mesh, kind, guard, dropsOrb, elem,
    hp: baseHp, maxHp: baseHp,
    dmg: big?18:10, speed: big?2.0:2.6,
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

function bindInput(){
  addEventListener('keydown', (e)=>{
    const k = e.key.toLowerCase();
    keys[k] = true;
    if (k===' ') e.preventDefault();
    if (G.phase==='playing'){
      if (k==='e') tryInteract();
      if (k==='f') tryMimic();
      if (k==='q') cycleElement(1);
      if (k>='1'&&k<='5') pickElementByIndex(parseInt(k));
      if (k==='j') doAttack();
      if (k==='escape') pause();
    } else if (k==='escape' && G.phase==='paused') resume();
    else if (k==='escape' && G.phase==='inventory') closeInventory();
  });
  addEventListener('keyup', (e)=>{ keys[e.key.toLowerCase()] = false; });

  const canvas = dom_scene();
  canvas.addEventListener('mousedown', (e)=>{
    if (G.phase!=='playing') return;
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
    owned:[], equipped:null, chests:{}, mechs:{loam:false,tide:false,arc:false,rime:false},
    bossDefeated:false,
    elements:{loam:false,tide:false,cinder:false,arc:false,rime:false}, activeElement:'none',
    glideUnlocked:false, stage:0,
    flags:{fished:false,firstKill:false,transformedOnce:false,campPassed:false,trialPassed:false,iceMelted:false,resistHinted:false},
    mimic:{state:'Normal',hp:0,maxHp:0,orbHeld:false,cooldown:0,savedHp:100},
  });
  worldBuilt = false;
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
  G.owned = [WEAPONS[G.klass][0].id];
  G.equipped = G.owned[0];
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
  setObjective('Reach the lake and cast a line.  (Walk with W A S D, hold to swim close, press E at the water.)');
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
    const d = Math.hypot(player.position.x-lakePos.x, player.position.z-lakePos.z);
    if (d < 13.5 && d > 10.5){ best = { kind:'fish' }; bestD=0; }
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
    setObjective('Touch the glowing Wardstone up the hill to attune your first element. (Press E near it)');
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
  spawnBurst(ws.pos.clone().setY(3), ELEMENTS[elem].color, 34);
  setActiveElement(elem);
  refreshElementWheel();
  toast(`${ELEMENTS[elem].name} attuned!  Switch elements with Q or 1–5.`, 'good', 3200);
  tainerSay(`${ELEMENTS[elem].name}! Feel that? Now your strikes carry it. Some things in this world only answer to the right element.`, 5000);
  if (elem==='cinder' && G.stage===1){
    G.stage = 2;
    setObjective('A wall of Rime ice blocks the path north. Equip Cinder and strike it to melt through. Clear the Stonekin if they trouble you.');
    tainerSay('See that ice wall? Cinder melts Rime. Give it a few good hits!', 4600);
  }
}
function setActiveElement(elem){
  G.activeElement = elem;
  refreshElementWheel();
  tintWeapon(elem);
}
function tintWeapon(elem){
  const wp = player?.userData?.weapon; if(!wp) return;
  const col = elem==='none' ? 0xcdd6e6 : ELEMENTS[elem].color;
  wp.traverse(o=>{ if(o.isMesh && o.material && o.material.emissive){ o.material.emissive.setHex(elem==='none'?0x000000:col); o.material.emissiveIntensity = elem==='none'?0:0.5; }});
}
function cycleElement(dir){
  const avail = ['none', ...Object.keys(ELEMENTS).filter(e=>G.elements[e])];
  if (avail.length<=1){ toast('No elements attuned yet.', 'info', 1600); return; }
  let i = avail.indexOf(G.activeElement); i = (i+dir+avail.length)%avail.length;
  setActiveElement(avail[i]);
}
function pickElementByIndex(n){
  const order = ['loam','tide','cinder','arc','rime'];
  const elem = order[n-1];
  if (!elem) return;
  if (!G.elements[elem]){ toast(`${ELEMENTS[elem].name} not attuned yet.`, 'info', 1600); return; }
  setActiveElement(elem);
}
function refreshElementWheel(){
  dom['element-wheel'].querySelectorAll('.elem').forEach(btn=>{
    const el = btn.dataset.elem;
    const locked = el!=='none' && !G.elements[el];
    btn.classList.toggle('locked', locked);
    btn.classList.toggle('active', G.activeElement===el);
    btn.onclick = ()=>{ if(el==='none') setActiveElement('none'); else if(!locked) setActiveElement(el); };
  });
}

/* ------------------------------------------------------------- combat */
let atkAnim = 0;
function doAttack(){
  if (G.phase!=='playing') return;
  const inMimic = G.mimic.state==='Transformed';
  const c = CLASSES[G.klass];
  const dmgBase = inMimic ? 22 : Math.round(c.dmg * TIER_MULT[equippedWeapon().tier]) + (G.weaponLevel-1)*8;
  atkAnim = 1;
  if (!inMimic && c.ranged){
    fireProjectile(dmgBase);
  } else {
    meleeHit(inMimic ? 3.0 : c.range, inMimic ? 1.6 : c.arc, dmgBase);
  }
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
  for (const e of enemies){
    if (!e.alive) continue;
    const to = new THREE.Vector3().subVectors(e.mesh.position, player.position).setY(0);
    const d = to.length(); if (d>range+e.r) continue;
    to.normalize();
    if (fwd.dot(to) < Math.cos(arc)) continue;
    damageEnemy(e, dmg);
  }
  swingVfx(fwd);
}
function fireProjectile(dmg){
  const fwd = new THREE.Vector3(Math.sin(player.rotation.y),0,Math.cos(player.rotation.y));
  // aim assist: nudge toward nearest enemy in front
  if (settings.aim){
    let best=null,bd=1e9;
    for (const e of enemies){ if(!e.alive) continue;
      const to=new THREE.Vector3().subVectors(e.mesh.position,player.position).setY(0); const d=to.length();
      if (d<40 && fwd.dot(to.clone().normalize())>0.7 && d<bd){best=e;bd=d;} }
    if (best){ fwd.copy(new THREE.Vector3().subVectors(best.mesh.position,player.position).setY(0).normalize()); }
  }
  const col = G.activeElement==='none'?0xffe6a0:ELEMENTS[G.activeElement].color;
  const m = new THREE.Mesh(new THREE.SphereGeometry(0.16,8,8),
    new THREE.MeshStandardMaterial({color:col,emissive:col,emissiveIntensity:1}));
  m.position.copy(player.position).add(new THREE.Vector3(0,1.3,0)).add(fwd.clone().multiplyScalar(0.8));
  scene.add(m);
  projectiles.push({ mesh:m, vel:fwd.multiplyScalar(38), life:1.6, dmg, elem:G.activeElement });
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
  e.hp -= dmg * mult;
  e.hitCd = 0.12;
  e.state='chase'; e.target=player;
  const fxCol = mult>1 ? 0xfff0a0 : (mult<1 ? 0x8a90a0 : 0xffffff);
  spawnBurst(e.mesh.position.clone().add(new THREE.Vector3(0,1,0)), fxCol, mult>1?12:6, 0.5);
  if (e.hp<=0) defeatEnemy(e);
}
function defeatEnemy(e){
  e.alive=false;
  dissolve(e.mesh);                      // non-graphic: dissolve into motes of light
  scene.remove(e.mesh);
  if (e.boss){ bossDefeatedFlow(e); return; }
  const reward = (e.kind==='boulder'?12:5) + (e.elem?4:0);
  addTokens(reward);
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
  setMimicState('OrbAvailable');
  show(dom['orb-status']);
  toast('Mimic Orb held. Press F to Mirrorstep.', 'good', 2600);
  if (G.stage===2 || G.stage===3){
    G.stage=3;
    setObjective('Press F to Mirrorstep into a Grumble, then slip past the camp guards to the far marker.');
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
  // reach goal
  if (campGoal && !G.flags.campPassed){
    const d = Math.hypot(pos.x-campGoal.x, pos.z-campGoal.z);
    if (d<3){ campPassed(); }
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
  addTokens(15);
  toast('You slipped through the camp! +15 Emberlight', 'good', 3200);
  tainerSay('You walked right through them! Okay okay — next: Skywright Pell, past the meadow. He teaches gliding, and honestly we are going to need it.', 6000);
  G.stage=4;
  setObjective('Find Skywright Pell (south meadow) and pass the Windrider’s Trial.');
}

/* ------------------------------------------------------------- gliding */
let trialActive=false, trialTimer=0;
function startTrial(){
  if (G.flags.trialPassed){ tainerSay('Pell says the winds are yours now. Hold Space in the air to glide anywhere!', 4200); return; }
  trialActive = true; trialTimer = 40;
  hoops.forEach(h=>h.userData.hoop.passed=false);
  G.glideUnlocked = true; // trial glide granted
  // launch: place player on updraft and give upward pop
  player.position.set(-4, 0.2, 43);
  pv.set(0, 10, 4);
  toast('Windrider’s Trial: fly through all 4 rings! Hold Space to glide.', 'info', 4200);
  tainerSay('Ride the updraft, then hold Space and steer with W A S D. Thread every ring!', 5000);
  setObjective('Windrider’s Trial: glide through all 4 rings before you land.');
}
function updateTrial(){
  if (!trialActive) return;
  let passed=0;
  for (const h of hoops){
    const d = player.position.distanceTo(h.position);
    if (!h.userData.hoop.passed && d<2.6){ h.userData.hoop.passed=true; spawnBurst(h.position.clone(),0xf5c168,20,0.9);
      h.material.color.set(0x7bd3c6); h.material.emissive.set(0x2a6b60); toast('Ring!','good',900); }
    if (h.userData.hoop.passed) passed++;
  }
  if (passed>=hoops.length){ trialActive=false; trialPass(); }
  // fail if landed before finishing
  if (grounded && player.position.y<0.3 && passed<hoops.length){
    trialActive=false;
    if (!G.flags.trialPassed){ G.glideUnlocked=false; toast('Touched down early — talk to Pell to try again.', 'bad', 3200); }
  }
}
function trialPass(){
  G.flags.trialPassed=true; G.glideUnlocked=true;
  addTokens(20);
  spawnBurst(player.position.clone(),0x7bd3c6,40,1.4);
  toast('You earned the Windrider’s Mark! Gliding unlocked. +20 Emberlight', 'good', 4200);
  tainerSay('That was BEAUTIFUL! The Windrider’s Mark is yours — hold Space whenever you’re falling. The whole vale is open now. Let’s go find them.', 6500);
  G.stage=5;
  setObjective('Attune the remaining Wardstones, strike the four elemental mechanisms, and open the Arc-sealed gate beyond the camp — something waits in the hollow.');
}

/* ------------------------------------------------------------- progression */
function addTokens(n){ G.tokens += n; updateHUD(); }
function upgradeWeapon(){
  const cost = 10 + (G.weaponLevel-1)*8;
  if (G.tokens < cost){ toast(`Need ${cost} Emberlight to upgrade (${G.tokens} held).`, 'info', 2400); return; }
  G.tokens -= cost; G.weaponLevel++;
  toast(`${CLASSES[G.klass].weapon} upgraded to Lv ${G.weaponLevel}! (+8 power)`, 'good', 3000);
  updateHUD();
}

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
  spawnBurst(iceWall.position.clone().setY(2), 0x8fd7f0, 40, 1.4, true);
  spawnBurst(iceWall.position.clone().setY(2), 0xf0713b, 20, 1.2);
  // remove ice colliders
  for (let i=colliders.length-1;i>=0;i--) if (colliders[i].tag==='ice') colliders.splice(i,1);
  world.remove(iceWall);
  toast('The Rime wall melts away!', 'good', 2600);
  tainerSay('Ha! Told you. The path north is open — that’s the Stonekin camp. We’ll want a disguise for that...', 5200);
  if (G.stage<3){ setObjective('Defeat a Stonekin to earn a Mimic Orb, then use it to sneak through the camp.'); }
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
  const sprint = keys['shift'] && G.stamina>0 && !transformed;
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
  // arrow keys rotate camera (accessibility/no-mouse fallback)
  if (keys['arrowleft']) yaw += 1.6*dt*settings.cam;
  if (keys['arrowright']) yaw -= 1.6*dt*settings.cam;
  if (keys['arrowup']) pitch = Math.min(1.1, pitch+1.2*dt);
  if (keys['arrowdown']) pitch = Math.max(-0.2, pitch-1.2*dt);

  const moving = move.lengthSq()>0.01;
  if (moving){
    move.normalize();
    pv.x = move.x*speed; pv.z = move.z*speed;
    body.rotation.y = Math.atan2(move.x, move.z);
  } else { pv.x*=0.7; pv.z*=0.7; }

  // stamina
  if (sprint && moving) G.stamina = Math.max(0, G.stamina - 26*dt);
  else G.stamina = Math.min(G.maxStam, G.stamina + 16*dt);

  // jump / glide
  const windUp = windLift(body.position);
  if (keys[' ']){
    if (grounded){ pv.y = 9.2; grounded=false; }
    else if (G.glideUnlocked && pv.y < 1.5){ glideActive=true; }
  } else glideActive=false;

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

  // ground = 0, or the top of any platform we're above and falling onto
  let groundY = 0;
  for (const pf of platforms){
    if (Math.abs(body.position.x-pf.x)<=pf.hw && Math.abs(body.position.z-pf.z)<=pf.hd &&
        body.position.y >= pf.topY-0.45 && pv.y<=0) groundY = Math.max(groundY, pf.topY);
  }
  if (body.position.y <= groundY){ body.position.y=groundY; if(pv.y<0){ pv.y=0; grounded=true; glideActive=false; } }
  else grounded=false;

  // keep within world
  const R = Math.hypot(body.position.x, body.position.z);
  if (R>195){ body.position.x*=195/R; body.position.z*=195/R; }

  // if transformed, keep player group synced (for eject position + attack facing)
  if (transformed && mimicMesh){ player.position.copy(mimicMesh.position); player.rotation.y = mimicMesh.rotation.y; }

  animateLimbs(body, moving, dt);

  // orb pickups
  for (let i=orbs.length-1;i>=0;i--){
    const o=orbs[i]; if (body.position.distanceTo(o.mesh.position)<1.6) collectOrb(o);
  }

  // interact prompt
  updateInteract();
}

function windLift(pos){
  let up=0;
  for (const w of windZones){ if (Math.hypot(pos.x-w.pos.x,pos.z-w.pos.z)<w.r && pos.y<22) up=Math.max(up,w.up); }
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
    // attack swing
    if (atkAnim>0){ atkAnim=Math.max(0,atkAnim-dt*4); parts.armR.rotation.x = -1.4*atkAnim; }
    if (glideActive){ parts.armL.rotation.z=0.9; parts.armR.rotation.z=-0.9; parts.armL.rotation.x=0; parts.armR.rotation.x=0; }
    else { parts.armL.rotation.z=0; parts.armR.rotation.z=0; }
  }
  if (body.userData?.float){ body.userData.float.rotation.y += dt*2; body.userData.float.position.y=0.2+Math.sin(performance.now()*0.004)*0.06; }
}

/* ================================================================= ENEMIES AI */
function updateEnemies(dt){
  const transformed = G.mimic.state==='Transformed';
  const pPos = transformed && mimicMesh ? mimicMesh.position : player.position;
  for (const e of enemies){
    if (!e.alive) continue;
    if (e.boss){ updateBoss(e, dt, pPos, transformed); continue; }
    e.wobble += dt;
    e.atkCd = Math.max(0, e.atkCd-dt);
    if (e.hitCd>0) e.hitCd-=dt;
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
        const nx=e.mesh.position.x+to.x*e.speed*dt, nz=e.mesh.position.z+to.z*e.speed*dt;
        e.mesh.position.x=nx; e.mesh.position.z=nz;
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
      if (to.length()>1){ to.normalize(); e.mesh.position.x+=to.x*e.speed*0.4*dt; e.mesh.position.z+=to.z*e.speed*0.4*dt; }
    }
    // idle bob
    e.mesh.position.y = Math.abs(Math.sin(e.wobble*3))*0.08;
    if (e.hitCd>0) e.mesh.scale.setScalar(1.12); else e.mesh.scale.setScalar(1);
  }
}
function damagePlayer(dmg){
  if (G.mimic.state==='Transformed') return;
  if (window.__dmgLog) window.__dmgLog.push(['player', dmg, new Error().stack.split('\n')[2]?.trim()]);
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
  if (desired.y<0.6) desired.y=0.6;
  const camPos = focus.clone().add(dir.multiplyScalar(Math.max(2.2, hitDist)));

  camera.position.lerp(camPos, 1-Math.pow(0.001, dt));
  if (shakeAmt>0){ camera.position.x += (Math.random()-0.5)*shakeAmt; camera.position.y += (Math.random()-0.5)*shakeAmt; shakeAmt=Math.max(0,shakeAmt-dt*2); }
  camera.lookAt(focus);
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
  dom['weapon-lvl'].textContent = 'Lv '+G.weaponLevel;
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
  hide(dom['menu-inv']); G.phase='paused'; show(dom['menu-pause']);
}
function weaponPower(w){ return Math.round(CLASSES[G.klass].dmg * TIER_MULT[w.tier]) + (G.weaponLevel-1)*8; }
function renderInv(){
  const list = dom['inv-list'];
  list.innerHTML = '';
  const eq = equippedWeapon();
  const upCost = 10 + (G.weaponLevel-1)*8;
  for (const id of G.owned){
    const w = findWeapon(id); if (!w) continue;
    const isEq = id === G.equipped;
    const pw = weaponPower(w);
    const delta = pw - weaponPower(eq);
    const row = document.createElement('div');
    row.className = 'inv-row'+(isEq?' equipped':'');
    row.setAttribute('role','listitem');
    row.innerHTML = `
      <div class="inv-info">
        <div class="inv-name">${w.name} <span class="inv-tier">Tier ${w.tier}</span>${isEq?' <span class="inv-badge">Equipped</span>':''}</div>
        <div class="inv-stats">Power ${pw}${isEq?'':` <span class="${delta>=0?'up':'down'}">(${delta>=0?'+':''}${delta} vs equipped)</span>`}</div>
      </div>
      <div class="inv-actions"></div>`;
    const actions = row.querySelector('.inv-actions');
    if (isEq){
      const up = document.createElement('button');
      up.className='btn small'; up.textContent=`Upgrade (✦${upCost})`;
      up.disabled = G.tokens < upCost;
      up.onclick = ()=>{ upgradeWeapon(); renderInv(); };
      actions.appendChild(up);
    } else {
      const eqBtn = document.createElement('button');
      eqBtn.className='btn small'; eqBtn.textContent='Equip';
      eqBtn.onclick = ()=>{ G.equipped=id; tintWeapon(G.activeElement); updateHUD(); renderInv(); toast(`${w.name} equipped.`, 'good', 1800); };
      actions.appendChild(eqBtn);
      const dis = document.createElement('button');
      dis.className='btn small danger'; dis.textContent=`Dismantle (+✦${6*w.tier})`;
      dis.onclick = ()=>{
        if (dis.dataset.confirm){ G.owned = G.owned.filter(x=>x!==id); addTokens(6*w.tier); renderInv(); toast(`${w.name} dismantled into ${6*w.tier} Emberlight.`, 'info', 2600); }
        else { dis.dataset.confirm='1'; dis.textContent='Really dismantle?'; setTimeout(()=>{ delete dis.dataset.confirm; if(dis.isConnected) dis.textContent=`Dismantle (+✦${6*w.tier})`; }, 2600); }
      };
      actions.appendChild(dis);
    }
    list.appendChild(row);
  }
  dom['inv-tokens'].textContent = `✦ ${G.tokens} Emberlight held. Dismantling a spare grants 6 × its tier. Your class finds stronger weapons in chests.`;
}

function openSettings(from){ settingsReturn=from; hide(dom['menu-title']); hide(dom['menu-pause']); G.phase='settings'; show(dom['menu-settings']); syncSettingsUI(); }
let settingsReturn='title';
function closeSettings(){ hide(dom['menu-settings']); if(settingsReturn==='pause'){ G.phase='paused'; show(dom['menu-pause']); } else goTitle(); }

function syncSettingsUI(){
  dom['set-theme'].value=settings.theme; dom['set-contrast'].checked=settings.contrast;
  dom['set-motion'].checked=settings.motion; dom['set-ui'].checked=settings.ui;
  dom['set-cam'].value=settings.cam; dom['set-invert'].checked=settings.invert;
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
  return {
    schemaVersion: SCHEMA_VERSION, product: PRODUCT_VERSION, savedAt: new Date().toISOString(),
    id: 'local-'+(G.sibling||'x'),
    payload: {
      sibling:G.sibling, klass:G.klass, hp:G.hp, maxHp:G.maxHp, tokens:G.tokens,
      weaponLevel:G.weaponLevel, elements:G.elements, activeElement:G.activeElement,
      glideUnlocked:G.glideUnlocked, stage:G.stage, flags:G.flags,
      owned:G.owned, equipped:G.equipped, chests:G.chests, mechs:G.mechs,
      bossDefeated:G.bossDefeated,
      pos:{x:player?.position.x||0, z:player?.position.z||0},
    }
  };
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
  let owned = Array.isArray(p.owned) ? p.owned.filter(id=>roster.some(w=>w.id===id)) : [];
  if (!owned.length) owned = [starter];
  let equipped = (typeof p.equipped==='string' && owned.includes(p.equipped)) ? p.equipped : owned[0];
  const boolMap = (src, keys) => { const o={}; for (const k of keys) o[k] = !!(src && src[k]); return o; };
  next.owned = owned; next.equipped = equipped;
  next.chests = {}; if (p.chests && typeof p.chests==='object'){ for (const k of Object.keys(p.chests)){ if (/^chest-[a-z-]{1,24}$/.test(k)) next.chests[k]=!!p.chests[k]; } }
  next.mechs = boolMap(p.mechs, ['loam','tide','arc','rime']);
  next.bossDefeated = !!p.bossDefeated;
  Object.assign(G, {
    sibling:next.sibling, klass:next.klass, hp:next.hp, maxHp:next.maxHp,
    tokens:next.tokens, weaponLevel:next.weaponLevel, elements:next.elements,
    activeElement:next.activeElement, glideUnlocked:next.glideUnlocked, stage:next.stage, flags:next.flags,
    owned:next.owned, equipped:next.equipped, chests:next.chests, mechs:next.mechs,
    bossDefeated:next.bossDefeated,
  });
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
  setActiveElement(G.activeElement);
  if (next.pos){ player.position.set(next.pos.x, 0, next.pos.z); }
  setObjective(G.stage>=5?'Free roam: explore, attune Wardstones, and continue the search.':'Continue your journey.');
  tainerSay('Back on the road! I kept your place. Let’s keep looking.', 4200);
}

/* ============================================================ WORLD REBUILD */
function clearWorld(){
  // remove dynamic actors
  for (const e of enemies){ scene.remove(e.mesh); } enemies.length=0;
  for (const o of orbs){ scene.remove(o.mesh); } orbs.length=0;
  for (const p of projectiles){ scene.remove(p.mesh); } projectiles.length=0;
  for (const p of particles){ scene.remove(p.grp); } particles.length=0;
  wardstones.length=0; interactables.length=0; windZones.length=0; hoops.length=0; spinners.length=0; colliders.length=0;
  mechanisms.length=0; platforms.length=0; bossRef=null; bossChestSpawned=false; lakeFrozen=false; hide(dom['boss-bar']);
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
  [dom['menu-title'],dom['menu-sibling'],dom['menu-class'],dom.cinematic,dom['menu-pause'],dom['menu-settings'],dom.loading].forEach(hide);
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
  dom['set-aim'].onchange = e=>{ settings.aim=e.target.checked; saveSettings(); };
  dom['set-vol'].oninput = e=>{ settings.vol=parseFloat(e.target.value); saveSettings(); };
}

/* hook class-confirm to build the world before opening cinematic already done;
   we build world lazily at enterWorld via ensureWorld */
let worldBuilt=false;
function ensureWorld(){ if(!worldBuilt){ startFreshWorld(); worldBuilt=true; } }

/* ================================================================= MAIN LOOP */
let autosaveT = 0;
function loop(){
  requestAnimationFrame(loop);
  const dt = Math.min(0.05, clock?clock.getDelta():0.016);
  if (G.phase==='playing'){
    updatePlayer(dt);
    updateEnemies(dt);
    updateProjectiles(dt);
    updateStealth(dt);
    updateTrial();
    tickMimicCooldown(dt);
    updateTainerFollow(dt);
    updateCamera(dt);
    // autosave every 12s
    autosaveT += dt; if (autosaveT>12){ autosaveT=0; if(G.klass) autosave(); }
  }
  updateParticles(dt);
  for (const s of spinners) s.rotation.z += dt*1.2;
  if (renderer) renderer.render(scene, camera);
}
function updateProjectiles(dt){
  for (let i=projectiles.length-1;i>=0;i--){
    const p=projectiles[i]; p.life-=dt; p.mesh.position.addScaledVector(p.vel,dt);
    let hit=false;
    for (const e of enemies){ if(!e.alive)continue; if(p.mesh.position.distanceTo(e.mesh.position)<e.r+0.4){ damageEnemy(e,p.dmg); hit=true; break; } }
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
    giveWeapon: (tier)=> grantWeapon(tier),
    equip: (id)=>{ if(G.owned.includes(id)){ G.equipped=id; updateHUD(); return true; } return false; },
    gear: ()=> ({ owned:[...G.owned], equipped:G.equipped, power:weaponPower(equippedWeapon()) }),
    warp: (x,z)=>{ player.position.set(x,0,z); },
    chestsState: ()=> ({...G.chests}),
    viewYaw: ()=> yaw,
    view: ()=> ({ yaw:+yaw.toFixed(3), pitch:+pitch.toFixed(3), camDist }),
    // deterministic simulation stepping — RAF is throttled in background tabs,
    // so QA drives the same per-frame updates the real loop uses
    step: (sec=1)=>{
      const dt = 1/60, n = Math.round(sec/dt);
      for (let i=0;i<n;i++){
        if (G.phase==='playing'){
          updatePlayer(dt); updateEnemies(dt); updateProjectiles(dt);
          updateStealth(dt); updateTrial(); tickMimicCooldown(dt); updateTainerFollow(dt);
        }
        updateParticles(dt);
      }
      return `stepped ${sec}s (${n} frames)`;
    },
  };
  console.log('[Emberkin] dev hooks installed: window.__EMBER');
}

boot();
