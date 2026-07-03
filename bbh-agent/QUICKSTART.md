# BBH Agent — Quick Start (Plain English)

Follow these steps in order. Do not skip any.

---

## Step 1: Get the code

Open a terminal and run:

```bash
git clone https://github.com/eBruno-Sec/MISC.git
cd MISC/bbh-agent
```

---

## Step 2: Run the installer

```bash
chmod +x install.sh
./install.sh
```

The installer will:
- Install Docker if you do not have it
- Ask for your Anthropic API key (get one at console.anthropic.com)
- Build everything automatically
- Open `http://localhost:8000` in your browser

First build takes 10-15 minutes. That is normal. It only happens once.

---

## Step 3: Use it

1. Type in the program name (e.g. `Shopify`)
2. Paste the in-scope domains (e.g. `*.shopify.com`)
3. Click **Start Hunt**
4. Watch it work
5. When it finishes, click **View Report** and copy the markdown

---

## Update

```bash
cd MISC/bbh-agent
./update.sh
```

---

## Stop

```bash
docker compose down
```

## Start again

```bash
docker compose up -d
```

Then go to `http://localhost:8000`.

---

## Something broke

```bash
docker compose logs -f
```

Copy the output and bring it here.
