# ROUND TABLE. CAVEMAN BOOK.

Big rock smash. This book for small brain. Me help you.

Round Table is hunting spear for bug bounty. You point spear at website. Spear find weak spot. Spear tell you where to hit.

Five knight do work. You say one word. All knight go.

```
PERCIVAL   look at target from far. no touch. safe.
GALAHAD    walk up. poke target. find open door.
LANCELOT   smart brain. say what is worth hitting.
GAWAIN     give you fight plan. step one. step two. you swing.
EXCALIBUR  write it all on stone tablet. txt. word. json.
```

MERLIN is chief. MERLIN wake all knight. You only talk to MERLIN.

---

## GET THE SPEAR

You use KALI. Good. Kali is best rock.

```bash
git clone https://github.com/eBruno-Sec/MISC.git
cd MISC/round-table
python3 merlin.py --setup-only -t dummy.com
```

That last line make MERLIN fix everything. MERLIN:

- clean your cave (update system)
- get all tool (subfinder, nmap, nuclei, all of them)
- get word list for smashing doors
- make config file for you

You do nothing. MERLIN do. Wait. Drink water.

---

## FEED THE SMART BRAIN

LANCELOT and GAWAIN need brain juice. Brain juice come from OpenRouter. One key. Works with all AI.

STEP 1. Go here. Make account. Get key.

```
https://openrouter.ai/keys
```

Key look like this: `sk-or-v1-longnoise`

STEP 2. Open config file.

```bash
nano config.yaml
```

STEP 3. Find this line:

```yaml
api_key: "YOUR_KEY_HERE"
```

Put your key. Like this:

```yaml
api_key: "sk-or-v1-longnoise"
```

STEP 4. Press CTRL and O. Then ENTER. Then CTRL and X. Key saved. Good caveman.

FREE brain juice (no shiny rock cost):

```
meta-llama/llama-3.3-70b-instruct:free
```

STRONG brain juice (cost tiny shiny rock, keep secret safe):

```
anthropic/claude-sonnet-4-6
```

Free brain juice may show your hunt to others. On real target, use strong brain. Keep secret.

---

## HUNT

Point spear. Full hunt. Look. Poke. Think. Plan. Write.

```bash
python3 merlin.py -t target.com
```

Only look. No poke. Safe hunt.

```bash
python3 merlin.py -t target.com --passive
```

MERLIN stop before poke. MERLIN ask you first: "poke now? y or n". You say y only if target say you allowed. No poke where not allowed. Bad. Tribe angry. Ranger come.

Pick different brain for one hunt:

```bash
python3 merlin.py -t target.com --model openai/gpt-4o
```

Skip clean cave. Faster:

```bash
python3 merlin.py -t target.com --skip-update
```

Skip fight plan:

```bash
python3 merlin.py -t target.com --no-playbook
```

---

## WHERE STONE TABLET GO

All hunt result go in `output/` cave. Folder have target name and time.

```
output/target.com_20250702_143022/
   report_target.com.txt      the big story
   report_target.com.docx     word story for tribe elder
   subdomains.txt             all door found
   live_hosts.txt             door that open
   nuclei_results.txt         weak spot found
```

Read the txt. GAWAIN fight plan inside. Do step one. See what happen. Do step two.

---

## GAWAIN FIGHT PLAN. IMPORTANT.

GAWAIN not poke target. GAWAIN only talk. GAWAIN give list.

```
STEP 1: hit this door
  TARGET:   the exact door
  WHY:      why door weak
  DO:       exact rock to throw, exact way to throw
  LOOK FOR: what you see when door break
  IF FOUND: what it mean, what next
```

You throw rock yourself. One step. Then next step. Slow. Careful. You in control. Spear not throw for you.

---

## RULE OF TRIBE

PERCIVAL only look from far. Always safe. No target know you there.

GALAHAD walk up and poke. This send rock at target. Only do this where target say ok. Bug bounty scope. You read rule first. You break rule, big trouble.

MERLIN always ask before GALAHAD poke. Say n if you not sure.

---

## KNIGHT LIST

```
PERCIVAL   look far      DNS, crt.sh, WHOIS, headers
GALAHAD    poke close    subfinder, amass, nmap, ffuf, nuclei
LANCELOT   think         rank weak spot, make attack chain
GAWAIN     plan          step by step fight list, you swing
EXCALIBUR  write         txt, word, json tablet
```

Erwin Bruno make spear. Good hunter.

Now go hunt. Smash bug. Get shiny rock.
