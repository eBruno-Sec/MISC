"""Q-175. Wrapped minifier output: every line long, no line huge.

MEASURED on mutillidae's phpMyAdmin copy of jQuery 1.6.2 (92,285 bytes):

    lines 180   longest line 567   MEAN 512.7

Minified and then wrapped at ~500 chars, an ordinary minifier setting. The geometry rule requires
`maxline >= 2000 AND meanline >= 200`, so it failed on maxline, the file was treated as maintained
source, and it produced "Predictable randomness: Math.random()" at confidence=confirmed against a
vendored library -- the same false positive Q-171 fixed for the OTHER jQuery on the same host.

The conjunction is right for what it was written for: ONE long line is an embedded blob, not a
minifier, and that case is still pinned here. It just never covered the inverse.

The MEAN is the discriminating signal and this file's own baseline says so: first-party max
observed meanline is 51 (juice-shop lib/insecurity.ts), the Java benchmark ~45. The threshold is
300 -- six times the highest first-party mean ever measured for this project.
"""
import codeintel


def _wrapped_minified(nlines=180, width=512):
    """Long every line, none huge: exactly the geometry the AND rule misses."""
    return "\n".join(("a=b;" * (width // 4))[:width] for _ in range(nlines))


def test_wrapped_minifier_output_is_classified_generated():
    kind, evidence = codeintel.not_maintained_source("js/jquery/jquery-1.6.2.js",
                                                     _wrapped_minified())
    assert kind == "generated", "wrapped minifier output read as maintained source"
    assert "mean line" in evidence, evidence


def test_the_evidence_quotes_the_measurement():
    _kind, evidence = codeintel.not_maintained_source("js/lib.js", _wrapped_minified())
    assert "180 lines" in evidence, evidence


def test_first_party_source_is_not_classified():
    """THE negative control. Demoting real application code is the worse defect."""
    src = "\n".join(["function handle(req, res) {",
                     "    const t = req.body.token;",
                     "    return res.send(t);",
                     "}"] * 40)
    assert codeintel.not_maintained_source("routes/captcha.ts", src) == ("", "")


def test_one_long_line_alone_is_still_not_generated():
    """The original conjunction's whole purpose: a blob is not a minifier. Still true."""
    src = "\n".join(["const CONFIG = {};", "x" * 5000] + ["const a = 1;"] * 60)
    kind, _ev = codeintel.not_maintained_source("app/config.ts", src)
    assert kind == "", "a single embedded blob must not make a file generated"


def test_a_tiny_file_with_a_high_mean_is_not_generated():
    """The line-count floor: two long lines are a blob, not minifier output."""
    src = "\n".join(["y" * 600, "z" * 600])
    assert codeintel.not_maintained_source("app/data.js", src)[0] == ""


def test_a_cache_busting_query_does_not_defeat_the_name_rules():
    """`rel` is a URL in the live lane; the query is not part of the filename."""
    src = "\n".join(["var a=1;"] * 20)
    kind, ev = codeintel.not_maintained_source("js/app.min.js?ts=1526333067", src)
    assert kind == "generated", (kind, ev)
    assert "app.min.js" in ev and "?ts=" not in ev, ev
