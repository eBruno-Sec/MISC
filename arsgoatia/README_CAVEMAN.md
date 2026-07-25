# ARSGOATIA — CAVEMAN GUIDE

```
UGH. ME WANT HACK STUFF THE RIGHT WAY.
ME HAVE PERMISSION.
ME WANT PROOF FOR EVERYTHING.
ME USE ARSGOATIA. 🐐
```

---

## WHAT IS THIS

You give it a target you are ALLOWED to test. It does the attack step by step.
It writes down PROOF for every step. It never does anything the rules say no.
It remembers everything even if computer falls down.

Other tools in this cave: find one bug, tell you, done.
ARSGOATIA: find bug, PROVE bug, keep the KEY the bug gives you, use key to open
next door, draw a MAP of all the doors. Big brain hacking.

---

## THE BIG RULES (goat never breaks these)

```
ROBOT ONLY SUGGESTS.        robot never pushes the button itself
HUMAN PUSHES BIG BUTTONS.   scary actions wait for you to say YES
EVERY HIT LEAVES PROOF.     saved in a box nobody can change
NO PERMISSION = NO TOUCH.   fence checks every target, says NO when unsure
SECRETS STAY SECRET.        robot brain never sees your passwords
```

---

## WHAT YOU NEED

**Two things.**

1. Docker (computer helper that runs programs in boxes)
2. A target you are ALLOWED to test (goat scans practice target: Juice Shop)

Optional:
- AI key (makes robot suggest smarter. not required. goat still works without it)

---

## HOW TO START

```
copy .env.example  ->  .env
docker compose --profile lab up --build -d
```

Then look:

```
robot brain map   ->  http://localhost:8088   (Temporal, watch the workflow)
proof boxes       ->  http://localhost:9101   (MinIO, the evidence)
control panel     ->  http://localhost:8080/api/v1
```

---

## WHAT IS DONE NOW

Goat is still being built. Right now: the SKELETON and the RULE BOOK
(the shapes of every message, the box stack, the test robot). Next: the brain,
the recon nose, the fence, the IDOR poke, the proof box, the map.

Small steps. Each step tested. See `README.md` for the grown-up words.

---

## DO NOT

```
DO NOT scan thing you not allowed. caveman go to jail.
DO NOT skip permission paper. goat refuses anyway.
```
