"""Design-level remediation (T5) — BSRS Ch.5/6/8/9.

The risk with a remediation section is not that it is wrong, it is that it is FILLER. Advice that applies
to every finding, or that restates the tactical fix at greater length, trains readers to skip the whole
section — including the parts that matter. So the load-bearing tests here are the quality ones:

  * no entry may restate the tactical `_FAMILY_FIX` line for the same family
  * no entry may be generic enough to apply to an unrelated family
  * every family without an entry must have a RECORDED REASON, so omission is a decision, not an oversight
"""
import remediation_depth as rd
import report

FIELDS = ("structural", "blast_radius", "recovery", "verify")


def test_every_entry_has_all_four_dimensions():
    """A partial entry is worse than none — it looks answered."""
    for fam, d in rd.DEPTH.items():
        assert set(d) == set(FIELDS), (fam, sorted(d))
        for k in FIELDS:
            assert d[k].strip() and len(d[k]) > 80, "%s.%s is too thin to be design guidance" % (fam, k)


def test_no_entry_merely_restates_the_tactical_fix():
    """THE anti-filler check. The tactical line already ships in report._FAMILY_FIX; repeating it here in
    more words adds length, not information."""
    for fam, d in rd.DEPTH.items():
        tactical = report._FAMILY_FIX.get(fam)
        if not tactical:
            continue
        # Compare on content words, ignoring boilerplate, and require the design text to be substantially
        # different rather than a paraphrase.
        tac = {w for w in _words(tactical) if len(w) > 4}
        for k in FIELDS:
            body = {w for w in _words(d[k]) if len(w) > 4}
            overlap = len(tac & body) / max(len(tac), 1)
            assert overlap < 0.6, "%s.%s is a paraphrase of the tactical fix (%.0f%% overlap)" % (
                fam, k, overlap * 100)


def _words(s):
    import re
    return set(re.findall(r"[a-z]+", s.lower()))


def test_recovery_actually_assumes_compromise():
    """Ch.9 is the field with no equivalent elsewhere in the platform, and the easiest to fumble into
    another 'fix it' sentence. It must talk about what to do AFTER, not how to prevent."""
    posture = ("assume", "rotate", "invalidate", "disclosed", "compromised", "audit", "review",
               "preserve", "purge", "rebuild", "notify", "revoke", "determine", "enumerate")
    for fam, d in rd.DEPTH.items():
        r = d["recovery"].lower()
        assert any(w in r for w in posture), "%s recovery reads as prevention, not response: %s" % (fam, r)


def test_entries_are_specific_to_their_family():
    """Generic advice would score as plausible for a family it was not written for. Each entry must name
    something concrete to its own class."""
    markers = {
        "sqli": ("sql", "database", "query", "schema"),
        "xss": ("escap", "csp", "content-security", "httponly", "template"),
        "idor": ("object", "authoriz", "tenant", "persona", "id"),
        "ssrf": ("egress", "metadata", "imds", "dns", "outbound"),
        "path_traversal": ("path", "director", "file", "traver"),
        "cmdi": ("shell", "command", "exec", "host"),
        "deserialization": ("deserial", "gadget", "type", "gadget chain"),
        "git_exposure": ("git", "histor", "repositor", "commit"),
        "csrf": ("token", "samesite", "forged", "state-changing"),
        "default_credentials": ("credential", "default", "account", "management"),
        "vulnerable_component": ("depend", "version", "sbom", "advisor", "component"),
        "session_fixation": ("session", "identifier", "login", "regenerat"),
        "weak_session_token": ("token", "entropy", "csprng", "session"),
        "bfla": ("role", "privileg", "administrat", "polic"),
        "exposure": ("file", "artifact", "backup", "web root"),
    }
    for fam, d in rd.DEPTH.items():
        assert fam in markers, "new family %s: add its specificity markers" % fam
        blob = " ".join(d.values()).lower()
        assert any(m in blob for m in markers[fam]), fam


def test_omissions_are_recorded_decisions():
    """A family with no entry must say WHY, so the gap can be challenged instead of assumed intentional."""
    assert rd.NO_DEPTH_REASON
    for fam, why in rd.NO_DEPTH_REASON.items():
        assert fam not in rd.DEPTH, "%s is both covered and excused" % fam
        assert len(why) > 25, "%s: reason is too thin" % fam


def test_covers_the_families_apolaki_most_often_confirms():
    """Coverage where it counts. These are the classes with confirming oracles and real exploitability."""
    required = {"sqli", "xss", "idor", "bfla", "ssrf", "path_traversal", "cmdi", "deserialization"}
    assert required <= set(rd.DEPTH), sorted(required - set(rd.DEPTH))


def test_depth_for_reads_either_family_field():
    assert rd.depth_for({"family": "sqli"})["structural"]
    assert rd.depth_for({"vuln_class": "xss"})["recovery"]
    assert rd.depth_for({}, family="idor")["verify"]


def test_an_uncovered_family_returns_nothing_not_filler():
    """Returning generic advice would be the failure mode this module exists to avoid."""
    assert rd.depth_for({"family": "security_headers"}) == {}
    assert rd.depth_for({"family": "totally_unknown_family"}) == {}
    assert rd.markdown({"family": "security_headers"}) == ""


def test_markdown_renders_all_four_labelled_dimensions():
    md = rd.markdown({"family": "sqli"})
    assert md.startswith("**Design-level remediation**")
    for label in ("Remove the class", "Bound the blast radius", "Assume it was already exploited",
                  "Verify the fix"):
        assert label in md, label


def test_depth_for_returns_a_copy_callers_cannot_corrupt():
    a = rd.depth_for({"family": "sqli"})
    a["structural"] = "mutated"
    assert rd.depth_for({"family": "sqli"})["structural"] != "mutated"


def test_pure_and_deterministic():
    f = {"family": "ssrf"}
    assert rd.depth_for(f) == rd.depth_for(f)
    assert rd.markdown(f) == rd.markdown(f)


# ── report integration: both renderers, or the export format changes the answer ──────────────────

def test_the_markdown_report_renders_the_block():
    """Without a consumer this module is an island by Apolaki's own doctrine."""
    lines = report._remediation_depth_md({"family": "sqli"})
    assert lines and "**Design-level remediation**" in lines[0]
    assert any("Assume it was already exploited" in l for l in lines)


def test_the_html_report_renders_the_block_too():
    """The markdown and HTML reports are SEPARATE renderers. Shipping this in one only would give two
    different answers to the same question depending on export format."""
    html = report._remediation_depth_html({"family": "sqli"}, lambda s: str(s))
    assert "<h4>Design-level remediation</h4>" in html
    for label in ("Remove the class", "Bound the blast radius", "Assume it was already exploited",
                  "Verify the fix"):
        assert label in html, label


def test_html_escapes_through_the_callers_escaper():
    """The escaper is injected so this cannot emit raw text. Prove it is actually applied."""
    calls = []

    def esc(s):
        calls.append(s)
        return "ESCAPED"
    html = report._remediation_depth_html({"family": "sqli"}, esc)
    assert calls, "escaper was never called"
    assert "ESCAPED" in html


def test_a_finding_carrying_only_a_cwe_still_resolves():
    """Findings do not always carry `family`; `_family_of` maps the CWE. Without reusing it, the block
    would silently never render for those."""
    assert report._remediation_depth_md({"cwe": "CWE-639"}), "CWE-only IDOR should resolve"


def test_uncovered_families_add_nothing_to_either_renderer():
    assert report._remediation_depth_md({"family": "security_headers"}) == []
    assert report._remediation_depth_html({"family": "security_headers"}, lambda s: s) == ""


def test_neither_renderer_raises_on_a_junk_finding():
    """Report generation must never die on a malformed finding — a lost report is worse than a thin one."""
    for junk in ({}, {"family": None}, {"cwe": 12345}, {"family": ["not", "a", "string"]}):
        assert isinstance(report._remediation_depth_md(junk), list)
        assert isinstance(report._remediation_depth_html(junk, lambda s: str(s)), str)
