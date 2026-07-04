# OLYMPUS — CAVEMAN GUIDE

```
UGH. ME WANT HACK STUFF.
ME HAVE PERMISSION.
ME USE OLYMPUS.
```

---

## WHAT IS THIS

You give it a website. It looks at website. It finds problems with website. It shows you what it found. You fix problems or tell client to fix problems.

Seven helpers. Named after old gods. They each do one job.

```
ZEUS        boss. tells everyone what to do
ATHENA      smart one. uses AI brain to plan
HERMES      sneaky one. looks around quietly
ARES        fighter. pokes website with sticks
HEPHAESTUS  builder. makes tools for poking
HADES       death god. finds how bad the damage is
APOLLO      artist. makes pretty report
```

---

## WHAT YOU NEED

**Two things. That is it.**

1. Docker (computer helper that runs programs in boxes)
2. A website you are ALLOWED to scan (very important. caveman who scans without permission go to jail)

Optionally:
- Anthropic API key (makes the AI brain work better. not required)

---

## HOW TO GET DOCKER

You don't have to. The script installs it for you.

Run `./setup.sh`. It will ask: "Install Docker now?" Say Y. It downloads, installs, and sets everything up.

If you are on a Mac or Windows, you still need Docker Desktop (the script will tell you):
- Mac: https://docs.docker.com/desktop/mac/install/
- Windows: https://docs.docker.com/desktop/windows/install/

If you are on Kali Linux or any Linux: just say Y and wait.

---

## HOW TO INSTALL OLYMPUS

**Step 1: Get the code**

```bash
git clone https://github.com/eBruno-Sec/MISC.git
cd MISC/olympus
```

**Step 2: Run the magic script**

```bash
./setup.sh
```

Script will:
- Check if Docker is installed. If not, ask to install it. Say Y.
- Check if Docker Compose is installed. If not, ask to install it. Say Y.
- Ask for your Anthropic API key (or press Enter to skip)
- Download and build everything
- Open the website for you

**Wait 3-5 minutes on first run. This is normal. Computer is downloading tools.**

---

## SCOPE UPLOAD

You have a list from HackerOne or Bugcrowd that says what is allowed and what is not. You can upload it.

**Step 1:** In the launch screen, look for the SCOPE RULES section.

**Step 2:** Click UPLOAD CSV and drop your file. Or click PASTE and type targets yourself.

**Step 3:** You will see a green list (allowed) and red list (not allowed).

**Step 4:** Launch mission. OLYMPUS will only touch the green targets.

**Plain text format if you do it manually:**
```
example.com
*.example.com
- do-not-touch.example.com
```

Lines starting with `-` are excluded. Everything else is fair game.

---

## HOW TO USE

**Step 1:** Go to http://localhost:3000

**Step 2:** Click big button that says `+ NEW MISSION`

**Step 3:** Type website you want to scan (example: `tesla.com`)

**Step 4:** Pick how hard you want to scan:

```
PASSIVE    just look. very sneaky. no touching.
ACTIVE     look AND poke. more findings.
FULL       look, poke, AND shake. most findings. most dangerous.
```

**Step 5:** Click `LAUNCH MISSION`

**Step 6:** Watch gods do their thing. Terminal shows what they are doing.

**Step 7:** When program asks you to click AUTHORIZE button, that means a god wants to do something more aggressive. You decide yes or no. This is important. You are the boss, not the computer.

**Step 8:** When APOLLO finishes, click `VIEW REPORT` button. Pretty report appears with all the problems organized by how bad they are.

---

## WHAT THE COLORS MEAN

```
RED        very bad problem. fix immediately.
ORANGE     bad problem. fix soon.
YELLOW     medium problem. fix eventually.
BLUE       small problem. nice to fix.
GREY       information. just telling you stuff.
```

---

## COMMANDS FOR CAVEMAN

```bash
# Start OLYMPUS
./setup.sh

# See what is happening inside boxes
docker compose logs -f

# Stop OLYMPUS (keeps your data)
docker compose down

# Stop OLYMPUS AND DELETE EVERYTHING
docker compose down -v

# Start again after stopping
docker compose up -d

# Make OLYMPUS fresh (if something broken)
./setup.sh --rebuild
```

---

## THINGS CAVEMAN MUST KNOW

**IMPORTANT THING 1:** You must have permission to scan. Always. No exceptions.

If you scan someone without permission:
- You go to court
- You pay money
- You go to jail maybe
- Your career is over probably

**IMPORTANT THING 2:** Some scans make lots of noise. The website owner might notice. Tell them you are doing a pentest first.

**IMPORTANT THING 3:** HITL gates (the approve/deny buttons) exist because some actions are aggressive. Take 10 seconds to read what ARES wants to do before clicking AUTHORIZE.

---

## SOMETHING BROKEN?

**Backend not starting:**
```bash
docker compose logs backend
```
Look at the error. Google the error. Fix the error.

**Port already used by something:**
```bash
# See what is using port 3000
lsof -Pi :3000
# Kill it or just use different port
```

**AI features not working:**
Make sure your API key is in the `.env` file. Open `.env` with any text editor. Find the line that says `ANTHROPIC_API_KEY=`. Put your key after the equals sign.

**Docker install fails with "kali-rolling Release" error (Kali Linux):**
```bash
sudo rm -f /etc/apt/sources.list.d/docker.list /etc/apt/keyrings/docker.asc
git pull
./setup.sh
```
Old broken file. Delete it. Pull new script. Run again.

**Frontend build fails (npm error about lockfile):**
```bash
git pull
docker compose up --build -d
```
Old code had a bug. New code is fixed. Pull and rebuild.

**Everything is broken and you don't know why:**
```bash
./setup.sh --rebuild
```
This deletes and rebuilds everything. Usually fixes it.

---

## WHERE ARE MY REPORTS

Reports live at:
```
http://localhost:8000/api/missions/MISSION-ID/report
```

Or click the `VIEW REPORT` button. It is the obvious glowing button.

---

## CAVEMAN DONE

You got this. Go find bugs. Write report. Get paid. Repeat.

```
⚡ OLYMPUS GO BRRRRRR
```

---

*OLYMPUS — by eBruno-Sec*
