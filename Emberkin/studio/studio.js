/* ============================================================================
   EMBERKIN STUDIO — kid-friendly creator sandbox (local only, nothing published)
   Grid-snapped placement, erase, undo, limits, validated save/load, and an
   instant playtest that preserves the editor context. Core three.js only.
   ========================================================================== */
import * as THREE from 'three';

const SCHEMA_VERSION = 1;
const SAVE_KEY = 'emberkin.studio.v1';
const MAX_OBJECTS = 200;          // execution/asset limit, per the safety design
const GRID = 2;
const TYPES = ['tree','rock','bloom','grumble','chest','hoop','flag'];
const GENERIC_INVALID = 'Invalid or corrupted progress file';

/* ------------------------------------------------------------------- state */
const S = {
  mode: 'place',                  // place | erase | playtest
  placeType: 'tree',
  rot: 0,
  objects: [],                    // {type,x,z,rot,mesh}
  undoStack: [],                  // {op:'add'|'del'|'clear', data}
};

/* ------------------------------------------------------------------- three */
const canvas = document.getElementById('scene');
const renderer = new THREE.WebGLRenderer({ canvas, antialias:true });
renderer.setPixelRatio(Math.min(devicePixelRatio,2));
renderer.setSize(innerWidth, innerHeight);
renderer.shadowMap.enabled = true;

const scene = new THREE.Scene();
scene.background = new THREE.Color(0x9fd0e8);
scene.fog = new THREE.Fog(0x9fd0e8, 80, 240);

const camera = new THREE.PerspectiveCamera(60, innerWidth/innerHeight, 0.1, 500);
const clock = new THREE.Clock();

scene.add(new THREE.HemisphereLight(0xdfefff, 0x556b3f, 0.95));
const sun = new THREE.DirectionalLight(0xfff2d6, 1.1);
sun.position.set(40,70,20); sun.castShadow = true;
sun.shadow.mapSize.set(1024,1024);
const sc = sun.shadow.camera; sc.left=-80; sc.right=80; sc.top=80; sc.bottom=-80; sc.far=220; sc.updateProjectionMatrix();
scene.add(sun);

const ground = new THREE.Mesh(new THREE.CircleGeometry(70,48),
  new THREE.MeshStandardMaterial({ color:0x6fae4e, roughness:0.95 }));
ground.rotation.x = -Math.PI/2; ground.receiveShadow = true;
scene.add(ground);
const grid = new THREE.GridHelper(140, 70, 0x4a6b3a, 0x5d8a48);
grid.material.opacity = 0.25; grid.material.transparent = true;
scene.add(grid);

addEventListener('resize', ()=>{ camera.aspect=innerWidth/innerHeight; camera.updateProjectionMatrix(); renderer.setSize(innerWidth,innerHeight); });

/* -------------------------------------------------------------- mesh kits */
const MAT = {
  trunk: new THREE.MeshStandardMaterial({ color:0x7a5230, roughness:1 }),
  leaf:  new THREE.MeshStandardMaterial({ color:0x4f9d54, roughness:0.85, flatShading:true }),
  leaf2: new THREE.MeshStandardMaterial({ color:0x8ec06a, roughness:0.85, flatShading:true }),
  rock:  new THREE.MeshStandardMaterial({ color:0x8f96a3, roughness:0.9, flatShading:true }),
  dark:  new THREE.MeshStandardMaterial({ color:0x5b6270, roughness:0.9, flatShading:true }),
  wood:  new THREE.MeshStandardMaterial({ color:0x6a4a2c, roughness:1 }),
  gold:  new THREE.MeshStandardMaterial({ color:0xe6c15a, metalness:0.5, roughness:0.4 }),
};
function buildMesh(type){
  const g = new THREE.Group();
  if (type==='tree'){
    const t = new THREE.Mesh(new THREE.CylinderGeometry(0.3,0.42,2.4,6), MAT.trunk); t.position.y=1.2; t.castShadow=true; g.add(t);
    for (let i=0;i<3;i++){ const b=new THREE.Mesh(new THREE.IcosahedronGeometry(1.5-i*0.3,0), i%2?MAT.leaf:MAT.leaf2);
      b.position.y=2.6+i*0.9; b.castShadow=true; g.add(b); }
  } else if (type==='rock'){
    const r = new THREE.Mesh(new THREE.DodecahedronGeometry(1.1,0), MAT.rock); r.position.y=0.7; r.castShadow=true; g.add(r);
  } else if (type==='bloom'){
    const s = new THREE.Mesh(new THREE.CylinderGeometry(0.05,0.07,0.8,5), MAT.leaf); s.position.y=0.4; g.add(s);
    const f = new THREE.Mesh(new THREE.IcosahedronGeometry(0.28,0),
      new THREE.MeshStandardMaterial({ color:0xf5c168, emissive:0x7a5a10, emissiveIntensity:0.4, flatShading:true }));
    f.position.y=0.95; g.add(f);
  } else if (type==='grumble'){
    const b = new THREE.Mesh(new THREE.DodecahedronGeometry(0.8,0), MAT.rock); b.position.y=0.85; b.castShadow=true; g.add(b);
    const eM = new THREE.MeshStandardMaterial({ color:0xffe08a, emissive:0xffcf5a, emissiveIntensity:0.8 });
    const eL = new THREE.Mesh(new THREE.SphereGeometry(0.1,8,8), eM); eL.position.set(-0.22,0.95,0.62); g.add(eL);
    const eR = eL.clone(); eR.position.x=0.22; g.add(eR);
  } else if (type==='chest'){
    const b = new THREE.Mesh(new THREE.BoxGeometry(1.1,0.6,0.8), MAT.wood); b.position.y=0.3; b.castShadow=true; g.add(b);
    const l = new THREE.Mesh(new THREE.BoxGeometry(1.14,0.34,0.84), MAT.wood); l.position.set(0,0.72,-0.02); g.add(l);
    const tr = new THREE.Mesh(new THREE.BoxGeometry(1.18,0.1,0.88), MAT.gold); tr.position.y=0.58; g.add(tr);
    g.userData.lid = l;
  } else if (type==='hoop'){
    const h = new THREE.Mesh(new THREE.TorusGeometry(1.6,0.16,10,24),
      new THREE.MeshStandardMaterial({ color:0xf5c168, emissive:0x7a5a10, emissiveIntensity:0.6, flatShading:true }));
    h.position.y=2.4; g.add(h); g.userData.spin = h;
  } else if (type==='flag'){
    const p = new THREE.Mesh(new THREE.CylinderGeometry(0.06,0.08,2.4,6), MAT.dark); p.position.y=1.2; g.add(p);
    const f = new THREE.Mesh(new THREE.PlaneGeometry(1.0,0.6),
      new THREE.MeshStandardMaterial({ color:0x7bd3c6, side:THREE.DoubleSide }));
    f.position.set(0.55,2.0,0); g.add(f);
  }
  return g;
}

/* ghost preview */
let ghost = null;
function refreshGhost(){
  if (ghost){ scene.remove(ghost); ghost = null; }
  if (S.mode!=='place') return;
  ghost = buildMesh(S.placeType);
  ghost.traverse(o=>{ if(o.isMesh){ o.material = o.material.clone(); o.material.transparent=true; o.material.opacity=0.45; o.castShadow=false; } });
  ghost.visible = false;
  scene.add(ghost);
}

/* ------------------------------------------------------------- editor cam */
let yaw = 0.8, pitch = 0.75, dist = 42;
const target = new THREE.Vector3(0,0,0);
function updateEditorCam(){
  const off = new THREE.Vector3(Math.sin(yaw)*Math.cos(pitch), Math.sin(pitch), Math.cos(yaw)*Math.cos(pitch)).multiplyScalar(dist);
  camera.position.copy(target).add(off);
  camera.lookAt(target);
}

/* -------------------------------------------------------------- placement */
const ray = new THREE.Raycaster();
const ndc = new THREE.Vector2();
function groundPoint(ev){
  ndc.x = (ev.clientX/innerWidth)*2-1; ndc.y = -(ev.clientY/innerHeight)*2+1;
  ray.setFromCamera(ndc, camera);
  const hit = ray.intersectObject(ground, false)[0];
  if (!hit) return null;
  const x = Math.round(hit.point.x/GRID)*GRID, z = Math.round(hit.point.z/GRID)*GRID;
  if (Math.hypot(x,z) > 66) return null;
  return {x,z};
}
function objectAt(x,z){ return S.objects.find(o=>o.x===x && o.z===z); }
function pickObject(ev){
  ndc.x = (ev.clientX/innerWidth)*2-1; ndc.y = -(ev.clientY/innerHeight)*2+1;
  ray.setFromCamera(ndc, camera);
  const meshes = [];
  for (const o of S.objects) o.mesh.traverse(m=>{ if(m.isMesh){ m.userData.owner=o; meshes.push(m); } });
  const hit = ray.intersectObjects(meshes, false)[0];
  return hit ? hit.object.userData.owner : null;
}

function addObject(type, x, z, rot, recordUndo=true){
  if (S.objects.length >= MAX_OBJECTS){ toast(`Limit reached: ${MAX_OBJECTS} pieces. Erase something first!`, 'bad'); return null; }
  if (type==='flag'){ const old = S.objects.find(o=>o.type==='flag'); if (old) removeObject(old, false); }
  if (objectAt(x,z)){ toast('That square is taken — pick a free one.', 'bad'); return null; }
  const mesh = buildMesh(type);
  mesh.position.set(x,0,z); mesh.rotation.y = rot;
  scene.add(mesh);
  const o = { type, x, z, rot, mesh };
  S.objects.push(o);
  if (recordUndo){ S.undoStack.push({op:'add', data:o}); trimUndo(); }
  syncCount(); autosaveSoon();
  return o;
}
function removeObject(o, recordUndo=true){
  scene.remove(o.mesh);
  S.objects = S.objects.filter(x=>x!==o);
  if (recordUndo){ S.undoStack.push({op:'del', data:{type:o.type,x:o.x,z:o.z,rot:o.rot}}); trimUndo(); }
  syncCount(); autosaveSoon();
}
function trimUndo(){ if (S.undoStack.length>60) S.undoStack.shift(); }
function undo(){
  const u = S.undoStack.pop();
  if (!u){ toast('Nothing to undo.', ''); return; }
  if (u.op==='add'){ if (S.objects.includes(u.data)) removeObject(u.data, false); }
  else if (u.op==='del'){ addObject(u.data.type, u.data.x, u.data.z, u.data.rot, false); }
  else if (u.op==='clear'){ for (const d of u.data) addObject(d.type,d.x,d.z,d.rot,false); }
}
function clearAll(){
  if (!S.objects.length) return;
  S.undoStack.push({op:'clear', data:S.objects.map(o=>({type:o.type,x:o.x,z:o.z,rot:o.rot}))}); trimUndo();
  for (const o of [...S.objects]) removeObject(o, false);
  toast('Glade cleared. Undo brings it back.', '');
}

/* ------------------------------------------------------------------- UI */
const $ = id=>document.getElementById(id);
function toast(msg, kind='ok', ms=2400){
  const t=$('toast'); t.textContent=msg; t.className='toast '+kind;
  clearTimeout(t._t); t._t=setTimeout(()=>t.classList.add('hidden'), ms);
}
function syncCount(){ $('count').textContent = `${S.objects.length} / ${MAX_OBJECTS}`; }
function setMode(mode, type){
  S.mode = mode;
  if (type) S.placeType = type;
  document.querySelectorAll('[data-place]').forEach(b=>b.classList.toggle('sel', mode==='place' && b.dataset.place===S.placeType));
  $('btn-erase').classList.toggle('sel', mode==='erase');
  $('hint').textContent = mode==='erase' ? 'Erase mode: click a piece to remove it.'
    : 'Pick a piece, then click the ground to place it. Drag to look around, scroll to zoom.';
  refreshGhost();
}
document.querySelectorAll('[data-place]').forEach(b=> b.onclick = ()=> setMode('place', b.dataset.place));
$('btn-erase').onclick = ()=> setMode(S.mode==='erase'?'place':'erase');
$('btn-rotate').onclick = ()=>{ S.rot = (S.rot + Math.PI/2) % (Math.PI*2); if (ghost) ghost.rotation.y = S.rot; };
$('btn-undo').onclick = ()=> undo();
$('btn-clear').onclick = ()=> clearAll();

/* ------------------------------------------------------------ save / load */
function serialize(){
  return { schemaVersion:SCHEMA_VERSION, product:'studio-0.1', savedAt:new Date().toISOString(),
    payload:{ objects: S.objects.map(o=>({type:o.type,x:o.x,z:o.z,rot:+o.rot.toFixed(3)})) } };
}
function validate(raw){
  if (typeof raw!=='object' || raw===null) throw 0;
  const bad=['__proto__','constructor','prototype'];
  const scan=(o)=>{ if(o&&typeof o==='object'){ for(const k of Object.keys(o)){ if(bad.includes(k)) throw 0; scan(o[k]); } } };
  scan(raw);
  if (typeof raw.schemaVersion!=='number' || raw.schemaVersion>SCHEMA_VERSION) throw 0;
  const p=raw.payload; if (!p || !Array.isArray(p.objects)) throw 0;
  if (p.objects.length > MAX_OBJECTS) throw 0;
  for (const o of p.objects){
    if (!TYPES.includes(o.type)) throw 0;
    if (typeof o.x!=='number' || typeof o.z!=='number' || !isFinite(o.x) || !isFinite(o.z)) throw 0;
    if (Math.abs(o.x)>70 || Math.abs(o.z)>70) throw 0;
  }
  return p;
}
function hydrate(p){
  for (const o of [...S.objects]) removeObject(o, false);
  S.undoStack.length = 0;
  for (const o of p.objects) addObject(o.type, Math.round(o.x/GRID)*GRID, Math.round(o.z/GRID)*GRID, Number(o.rot)||0, false);
}
let autosaveT=null;
function autosaveSoon(){ clearTimeout(autosaveT); autosaveT=setTimeout(()=>{ try{ localStorage.setItem(SAVE_KEY, JSON.stringify(serialize())); }catch(e){} }, 800); }
$('btn-save').onclick = ()=>{
  const blob = new Blob([JSON.stringify(serialize(),null,2)], {type:'application/json'});
  const a=document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download=`EMBERKIN_STUDIO_backup_${new Date().toISOString().slice(0,10)}.json`; a.click();
  URL.revokeObjectURL(a.href);
  toast('Glade saved to a .json file.', 'ok');
};
$('btn-load').onclick = ()=> $('file-input').click();
$('file-input').onchange = (e)=>{
  const f=e.target.files[0]; e.target.value='';
  if (!f) return;
  if (f.size > 256*1024){ toast(GENERIC_INVALID, 'bad', 3200); return; }
  const r=new FileReader();
  r.onload=()=>{ let obj; try{ obj=JSON.parse(r.result); }catch(err){ toast(GENERIC_INVALID,'bad',3200); return; }
    try{ hydrate(validate(obj)); toast('Glade loaded!', 'ok'); }catch(err){ toast(GENERIC_INVALID,'bad',3200); } };
  r.onerror=()=> toast(GENERIC_INVALID,'bad',3200);
  r.readAsText(f);
};

/* ------------------------------------------------------------- playtest */
const P = { active:false, kid:null, vel:new THREE.Vector3(), grounded:true, yaw:0, pitch:0.35,
  savedCam:null, wander:[] };
function buildKid(){
  const g = new THREE.Group();
  const body = new THREE.MeshStandardMaterial({ color:0x2f7d78, roughness:0.7, flatShading:true });
  const skin = new THREE.MeshStandardMaterial({ color:0xf0c9a0, roughness:0.8 });
  const dark = new THREE.MeshStandardMaterial({ color:0x2c2f3a });
  const torso=new THREE.Mesh(new THREE.BoxGeometry(0.66,0.8,0.36),body); torso.position.y=1.15; torso.castShadow=true; g.add(torso);
  const head=new THREE.Mesh(new THREE.BoxGeometry(0.42,0.44,0.42),skin); head.position.y=1.82; g.add(head);
  const aL=new THREE.Mesh(new THREE.BoxGeometry(0.18,0.72,0.18),body); aL.position.set(-0.44,1.2,0); g.add(aL);
  const aR=aL.clone(); aR.position.x=0.44; g.add(aR);
  const lL=new THREE.Mesh(new THREE.BoxGeometry(0.22,0.72,0.22),dark); lL.position.set(-0.16,0.36,0); g.add(lL);
  const lR=lL.clone(); lR.position.x=0.16; g.add(lR);
  return g;
}
function startPlaytest(){
  if (P.active) return;
  P.active = true;
  autosaveSoon();                                  // checkpoint the draft first
  P.savedCam = { yaw, pitch, dist, target: target.clone(), mode:S.mode, type:S.placeType };
  document.body.classList.add('playtest');
  $('btn-return').classList.remove('hidden');
  if (ghost) ghost.visible=false;
  const flag = S.objects.find(o=>o.type==='flag');
  P.kid = buildKid();
  P.kid.position.set(flag?flag.x:0, 0, flag?flag.z:0);
  scene.add(P.kid);
  P.vel.set(0,0,0); P.yaw = 0;
  P.wander = S.objects.filter(o=>o.type==='grumble').map(o=>({o, dir:Math.random()*Math.PI*2, t:0}));
  toast('Playtest! WASD to walk, Space to jump, drag to look.', 'ok', 3400);
}
function endPlaytest(){
  if (!P.active) return;
  P.active = false;
  scene.remove(P.kid); P.kid = null;
  document.body.classList.remove('playtest');
  $('btn-return').classList.add('hidden');
  // restore the exact editor context
  yaw = P.savedCam.yaw; pitch = P.savedCam.pitch; dist = P.savedCam.dist; target.copy(P.savedCam.target);
  setMode(P.savedCam.mode, P.savedCam.type);
  toast('Back to editing — right where you left off.', 'ok');
}
$('btn-play').onclick = ()=> startPlaytest();
$('btn-return').onclick = ()=> endPlaytest();

/* -------------------------------------------------------------- input */
const keys = {};
addEventListener('keydown', e=>{
  keys[e.key.toLowerCase()]=true;
  if (e.key===' ') e.preventDefault();
  if (e.key.toLowerCase()==='r' && !P.active) $('btn-rotate').click();
  if ((e.ctrlKey||e.metaKey) && e.key.toLowerCase()==='z'){ e.preventDefault(); if(!P.active) undo(); }
  if (e.key==='Escape' && P.active) endPlaytest();
});
addEventListener('keyup', e=>{ keys[e.key.toLowerCase()]=false; });

let dragging=false, dragMoved=false;
canvas.addEventListener('mousedown', e=>{ dragging=true; dragMoved=false; });
addEventListener('mousemove', e=>{
  if (dragging && (e.buttons&1)){
    if (Math.abs(e.movementX)+Math.abs(e.movementY) > 1) dragMoved=true;
    yaw -= e.movementX*0.005; pitch = Math.max(0.15, Math.min(1.35, pitch + e.movementY*0.005));
    if (P.active){ P.yaw = yaw; }
  }
  if (!P.active && S.mode==='place' && ghost){
    const gp = groundPoint(e);
    if (gp){ ghost.visible=true; ghost.position.set(gp.x,0,gp.z); ghost.rotation.y=S.rot; }
    else ghost.visible=false;
  }
});
addEventListener('mouseup', e=>{
  if (!dragging) return; dragging=false;
  if (dragMoved || P.active) return;
  if (S.mode==='erase'){ const o=pickObject(e); if(o){ removeObject(o); toast('Removed.', ''); } return; }
  const gp = groundPoint(e);
  if (gp) addObject(S.placeType, gp.x, gp.z, S.rot);
});
addEventListener('wheel', e=>{ if(!P.active){ dist=Math.max(14,Math.min(80,dist-Math.sign(e.deltaY)*3)); } }, {passive:true});

/* -------------------------------------------------------------- loop */
function tick(){
  requestAnimationFrame(tick);
  const dt = Math.min(0.05, clock.getDelta());
  for (const o of S.objects){ if (o.mesh.userData.spin) o.mesh.userData.spin.rotation.z += dt; }
  if (P.active && P.kid){
    // walk — camera sits at +[sin(yaw),cos(yaw)] from the kid, so screen-forward is the negation
    const f = new THREE.Vector3(-Math.sin(yaw),0,-Math.cos(yaw));
    const r = new THREE.Vector3(Math.cos(yaw),0,-Math.sin(yaw));   // screen-right
    const mv = new THREE.Vector3();
    if (keys['w']) mv.add(f); if (keys['s']) mv.sub(f);
    if (keys['a']) mv.sub(r); if (keys['d']) mv.add(r);
    if (mv.lengthSq()>0.01){ mv.normalize(); P.kid.position.addScaledVector(mv, 6*dt); P.kid.rotation.y=Math.atan2(mv.x,mv.z); }
    if (keys[' '] && P.grounded){ P.vel.y=8.5; P.grounded=false; }
    P.vel.y -= 22*dt; P.kid.position.y += P.vel.y*dt;
    if (P.kid.position.y<=0){ P.kid.position.y=0; P.vel.y=0; P.grounded=true; }
    const R = Math.hypot(P.kid.position.x,P.kid.position.z);
    if (R>66){ P.kid.position.x*=66/R; P.kid.position.z*=66/R; }
    // grumbles wander gently
    for (const w of P.wander){
      w.t -= dt; if (w.t<=0){ w.t = 1.6+Math.random()*1.6; w.dir = Math.random()*Math.PI*2; }
      const m = w.o.mesh; m.position.x += Math.cos(w.dir)*1.2*dt; m.position.z += Math.sin(w.dir)*1.2*dt;
      m.rotation.y = -w.dir + Math.PI/2;
      const rr = Math.hypot(m.position.x,m.position.z); if (rr>64){ m.position.x*=64/rr; m.position.z*=64/rr; }
      m.position.y = Math.abs(Math.sin(performance.now()*0.004 + w.dir))*0.1;
    }
    // chests sparkle open when touched
    for (const o of S.objects){
      if (o.type!=='chest' || o.mesh.userData.opened) continue;
      if (P.kid.position.distanceTo(o.mesh.position) < 1.6){
        o.mesh.userData.opened = true;
        if (o.mesh.userData.lid) o.mesh.userData.lid.rotation.x = -1.1;
        toast('✨ Treasure!', 'ok', 1400);
      }
    }
    // follow cam
    const focus = P.kid.position.clone().add(new THREE.Vector3(0,1.5,0));
    const off = new THREE.Vector3(Math.sin(yaw)*Math.cos(pitch), Math.sin(pitch)+0.2, Math.cos(yaw)*Math.cos(pitch)).multiplyScalar(8);
    camera.position.lerp(focus.clone().add(off), 1-Math.pow(0.001,dt));
    camera.lookAt(focus);
  } else {
    // editor pan with WASD
    const pan = new THREE.Vector3();
    const f = new THREE.Vector3(Math.sin(yaw),0,Math.cos(yaw));
    const r = new THREE.Vector3(Math.sin(yaw+Math.PI/2),0,Math.cos(yaw+Math.PI/2));
    if (keys['w']) pan.sub(f); if (keys['s']) pan.add(f);
    if (keys['a']) pan.sub(r); if (keys['d']) pan.add(r);
    if (pan.lengthSq()>0.01){ target.addScaledVector(pan.normalize(), 24*dt);
      target.x=Math.max(-60,Math.min(60,target.x)); target.z=Math.max(-60,Math.min(60,target.z)); }
    updateEditorCam();
  }
  renderer.render(scene, camera);
}

/* -------------------------------------------------------------- boot */
try{
  const saved = JSON.parse(localStorage.getItem(SAVE_KEY)||'null');
  if (saved) hydrate(validate(saved));
}catch(e){ /* corrupted autosave: start fresh, never crash */ }
setMode('place','tree');
syncCount();
updateEditorCam();
tick();

/* QA hooks, gated exactly like the game's (?dev=1) */
if (location.search.includes('dev')){
  window.__STUDIO = {
    count: ()=> S.objects.length,
    add: (type,x,z)=> !!addObject(type,x,z,0),
    undo: ()=> undo(),
    clear: ()=> clearAll(),
    save: ()=> serialize(),
    validate: (o)=>{ try{ validate(o); return 'valid'; }catch(e){ return GENERIC_INVALID; } },
    loadObj: (o)=>{ try{ hydrate(validate(o)); return true; }catch(e){ return false; } },
    play: ()=> startPlaytest(),
    stop: ()=> endPlaytest(),
    mode: ()=> ({ mode:S.mode, type:S.placeType, playtest:P.active }),
    kidPos: ()=> P.kid ? {x:+P.kid.position.x.toFixed(2), z:+P.kid.position.z.toFixed(2)} : null,
  };
  console.log('[Emberkin Studio] dev hooks: window.__STUDIO');
}
