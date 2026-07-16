# ROUND TABLE. CAVEMAN BOOK.

Big rock smash. This book for small brain. Me help you.

Round Table is hunting spear for bug bounty. You point spear at website. Spear
look. Spear poke. Spear find weak spot. Spear DRAW YOU MAP how to hit.

Spear NOT throw rock for you. Spear only show where door weak and how to smash.
You throw rock. You the hunter. This the rule of tribe. (Pentester rule. Bug
bounty rule.)

---

## GET THE SPEAR AND MAKE IT GO

You need DOCKER. Docker is magic cave that hold spear. Get Docker first.

Then three word:

```bash
git clone https://github.com/eBruno-Sec/MISC.git
cd MISC/round-table
./roundtable.sh
```

Wait. Spear build itself. Drink water. When done, spear say:

```
open http://localhost:3000
```

Open that in browser. You see the round table. No install tool. No make
database. All inside. You do nothing. Good caveman.

Stop the spear:  `./roundtable.sh --stop`
Watch spear talk: `./roundtable.sh --logs`

---

## HUNT IN FIVE POKE

1. TYPE THE DOOR. Big box say "Target". Put target. Push **Launch Mission**.
2. WATCH. Overview page show live feed. Spear talk while it hunt.
3. READ PLAYBOOK. Click **Playbooks**. Each card = one weak door + how to smash.
4. SEE MAP. Click **Topology**. Picture of all door. Red door = juicy.
5. THROW ROCK. Click **cURL Console**. Craft rock. Throw. See what break.

Then click **Report**. Take stone tablet home (HTML, word, json).

---

## THREE KIND OF FINDING. KNOW DIFFERENCE.

```
CONFIRMED   spear SURE. spear already saw door break. trust much.
HUNCH       spear THINK maybe weak. spear point. you check by hand.
ADVISORY    spear WARN. door look like other doors that break. good idea to test.
```

Confirmed is best meat. But hunch find secret door other hunter miss. Read all
three.

---

## WHEN SPEAR FIND OLD BROKEN TOOL (library, technology)

Website built from many small tool. Old tool = cracked tool. Spear sniff them
like Wappalyzer dog. When spear find old cracked tool (like AngularJS 1.7.7),
the playbook now tell you:

```
POTENTIAL RISK:  what bad thing happen if hit  (and how bad. HIGH? MEDIUM?)
CVE:             the tribe number for this crack
PAYLOAD:         the EXACT rock to throw    e.g. {{constructor.constructor('alert(1)')()}}
HOW:             step one, step two, where to throw, what you see when it break
FIX:             how website owner patch it
```

So YES — old broken tool findings show danger AND show how to smash. You still
throw the rock yourself. Spear only hand you the rock and point at the door.

---

## MAKE HUNT BETTER. IMPORTANT. READ THIS.

Small change = spear find much more meat. Do these:

**1. GIVE EXACT DOOR.**
Not just `juice-shop`. Say the room too: `juice-shop:3000`. Spear go straight
to right room. For real target on internet, `ginandjuice.shop` work great (that
one PortSwigger say everyone allowed to hunt — no permission needed).

**2. PICK RIGHT MODE.**
```
PASSIVE  only look from far. no poke. safe anywhere. finds least.
ACTIVE   walk up, poke door. finds more.
FULL     poke everything. finds MOST.  <-- use this when you want all meat
```
Want spear to find all weak spot? Use **FULL**.

**3. TURN ON THE LOOP.**
Open "Scan options". Check the box **"3-step iterative recon loop"**. Now spear
look, then LEARN from what it saw, then look AGAIN with new eyes. Three time.
Find hidden door the one-look hunt miss. This the single best switch. Turn on.

**4. GO SLOW WHEN YOU CAN.**
In options, pick **Slow** not Fast. Slow spear knock every door careful. Fast
spear skip some. Slow find more. Fast when you in hurry only.

**5. FEED THE SMART BRAIN (optional but good).**
Spear think better with brain juice. Brain juice = AI. It make the HUNCH
findings (spear gut feeling). Get free key:

```
https://openrouter.ai/keys        key look like  sk-or-v1-longnoise
```

Put in `.env` file (copy `.env.example` to `.env` first):
```env
AI_PROVIDER=openrouter
AI_API_KEY=sk-or-v1-longnoise
AI_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free
AI_BASE_URL=https://openrouter.ai/api/v1
```
Then `./roundtable.sh --rebuild`. No key? Spear still hunt fine. Key just add gut
feeling. Free key may show your hunt to strangers — on real secret target use
paid brain and keep quiet.

**6. ONE APP AT A TIME FOR DEEP HUNT.**
Spear can hunt many target in one go (type them with comma). But for DEEPEST
hunt, point at ONE app. Spear dig deeper when it not split between many.

**7. LET HUNT FINISH.**
Do not close browser while feed still moving. Let spear finish all step. Then
read report.

**8. PRACTICE ON TRIBE DUMMY FIRST.**
Repo carry a cave of broken practice apps. Safe to smash. Learn here first:
```bash
docker compose -f targets/docker-compose.yml up -d
```
Then hunt `host.docker.internal:42000` (Juice Shop) and friends. See
`targets/README.md`.

---

## GAWAIN FIGHT PLAN. HOW TO USE.

Each playbook card is a fight plan:

```
WHAT TO TEST:  the weak thing
HOW TO TEST:   step one. step two. slow. careful.
PAYLOAD:       exact rock (click copy button, rock jump to your hand)
TOOL:          which tool throw this rock best
cURL:          exact throw, copy paste, or push into cURL Console
CONFIDENCE:    how sure spear is
REFERENCE:     OWASP scroll, PortSwigger scroll — learn deeper
```

Do step one. Watch what happen. Do step two. You in control. Spear never throw
for you.

---

## RULE OF TRIBE. DO NOT BREAK.

- PASSIVE always safe. Target never know spear there.
- ACTIVE and FULL send rock at target. Only smash door you ALLOWED to smash.
  Bug bounty scope. Written permission. You break rule, big trouble, ranger come.
- Spear ask before it poke (pre-authorize checkbox). Say no if you not sure.
- Practice dummies in `targets/` bound to your own cave only. Not on internet.
  Safe. Smash all you want.

---

Erwin Bruno make spear. Good hunter.

Now go hunt. Turn on the loop. Use FULL. Smash bug. Get shiny rock.
