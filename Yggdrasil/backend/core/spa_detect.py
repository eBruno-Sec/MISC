"""
SPA / catch-all detection.

Many modern apps (Angular/React/Vue single-page apps, and some API gateways)
serve the SAME 200 response, the app shell, for EVERY unmatched path and every
unknown query parameter. A scanner that only checks status codes or reflection
then (a) reports that shell as a real hit for dozens of paths (/.git, /.env,
/admin all "200 -> reachable") and (b) sees identical responses for every
injection probe and concludes "nothing." Juice Shop is the textbook case:
/totally-random-xyz returns the exact same 9.9KB index.html as /.

This module detects that catch-all behavior from a few known-nonexistent probes
and classifies whether a later response IS just the shell, so callers can
suppress shell responses (kill false positives) and focus real testing on
endpoints that actually behave differently (the JSON API).

Pure/deterministic, no I/O: the caller does the HTTP and hands (status, body)
pairs here, so every function is directly unit-testable.
"""
import re
from difflib import SequenceMatcher

_CMP_CAP = 20000  # cap body comparison length; SPA shells differ in the first KB if at all


def _norm(body):
    """Whitespace-collapsed body for stable comparison across minor formatting."""
    return re.sub(r"\s+", " ", (body or "")).strip()


def similarity(a, b):
    """0..1 similarity. Length-ratio short-circuit avoids an expensive
    SequenceMatcher pass on bodies that are obviously different sizes."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    la, lb = len(a), len(b)
    ratio = min(la, lb) / max(la, lb)
    if ratio < 0.5:
        return ratio
    return SequenceMatcher(None, a[:_CMP_CAP], b[:_CMP_CAP]).ratio()


class CatchAll:
    """Fingerprint of a detected catch-all/shell response."""
    def __init__(self, status, sample):
        self.status = status
        self.sample = sample            # normalized shell body
        self.length = len(sample)

    def matches(self, status, body, threshold=0.9):
        """True when (status, body) is just the app shell. A near-identical
        length is a fast strong signal for a static shell; otherwise fall back
        to a strict similarity check."""
        if status != self.status:
            return False
        n = _norm(body)
        if not n:
            return False
        if self.length and abs(len(n) - self.length) <= max(48, self.length * 0.05) \
                and similarity(self.sample, n) >= threshold:
            return True
        return similarity(self.sample, n) >= max(threshold, 0.95)


def detect_catch_all(samples, min_len=64):
    """samples: list of (status, body) fetched from KNOWN-NONEXISTENT paths.
    Returns a CatchAll if the app answered them with a uniform, non-trivial
    shell (same status, mutually near-identical bodies), else None. Requires at
    least 2 agreeing samples so a single fluke doesn't trip it."""
    norm = [(s, _norm(b)) for s, b in (samples or []) if b is not None]
    norm = [(s, b) for s, b in norm if len(b) >= min_len]
    if len(norm) < 2:
        return None
    if len({s for s, _ in norm}) != 1:
        return None
    first = norm[0][1]
    if all(similarity(first, b) >= 0.9 for _, b in norm[1:]):
        return CatchAll(norm[0][0], first)
    return None


def looks_like_json(body, content_type=""):
    """Heuristic: does this response look like a JSON API payload (as opposed to
    the HTML shell)? Used to pick real API endpoints worth injecting."""
    if "application/json" in (content_type or "").lower():
        return True
    stripped = (body or "").lstrip()
    return stripped[:1] in ("{", "[")
