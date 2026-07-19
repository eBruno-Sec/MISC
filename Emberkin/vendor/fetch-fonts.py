"""Fetch true static per-weight latin-subset woff2 files from Google Fonts.

The previous vendoring pass requested the modern css2 endpoint, which serves a
VARIABLE font: the same file URL for every weight. It saved that one file under
four different names, so Nunito 600/700/800 all rendered identically (measured
at 728.91px each). Using a UA that predates variable-font support makes Google
serve genuine static files, one per weight.
"""
import re
import sys
import urllib.request

# Chrome 50: supports woff2, predates variable-font serving.
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36")

FAMILIES = {
    "baloo2": ("Baloo+2", [500, 600, 700, 800]),
    "nunito": ("Nunito", [400, 600, 700, 800]),
    "spacegrotesk": ("Space+Grotesk", [500, 700]),
}

OUT = sys.argv[1].rstrip("/")


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def latin_url(css_text):
    """Pick the @font-face block whose unicode-range is the plain latin subset.

    Google emits several subsets per weight (cyrillic, latin-ext, latin, ...).
    The latin one always covers U+0000-00FF; latin-ext does not.
    """
    blocks = re.findall(r"@font-face\s*\{(.*?)\}", css_text, re.S)
    fallback = None
    for b in blocks:
        m = re.search(r"src:\s*url\((https://[^)]+\.woff2)\)", b)
        if not m:
            continue
        fallback = fallback or m.group(1)
        ur = re.search(r"unicode-range:\s*([^;]+);", b)
        if ur and "U+0000-00FF" in ur.group(1).replace(" ", "").upper():
            return m.group(1)
    return fallback


report = []
for slug, (family, weights) in FAMILIES.items():
    seen = {}
    for w in weights:
        css = get(f"https://fonts.googleapis.com/css2?family={family}:wght@{w}&display=swap").decode()
        url = latin_url(css)
        if not url:
            raise SystemExit(f"no woff2 found for {family} {w}")
        data = get(url)
        path = f"{OUT}/{slug}-{w}.woff2"
        with open(path, "wb") as f:
            f.write(data)
        import hashlib
        h = hashlib.sha256(data).hexdigest()[:12]
        seen.setdefault(h, []).append(w)
        report.append(f"{slug}-{w}.woff2  {len(data):>7,}B  sha {h}")
    dupes = {h: ws for h, ws in seen.items() if len(ws) > 1}
    if dupes:
        report.append(f"  !! {slug}: STILL DUPLICATED across weights {dupes}")
    else:
        report.append(f"  ok {slug}: all {len(weights)} weights are distinct files")

print("\n".join(report))
