"""Dataflow lane: trust-boundary violation (CWE-501) by PROVENANCE, not by sink call.

THE WHOLE TICKET IS THE NEGATIVE CONTROLS. Every case in the OWASP Benchmark `trustbound`
category calls a session sink -- 126 of 126 in Java, 37 of 37 in Python -- and the suite contains
493 MORE clean session sinks outside the category (the `rememberMe` boilerplate every securecookie
and weakrand case carries). A detector that fires on `HttpSession.setAttribute` scores 100% TPR and
100% FPR, and it passes every positive test anyone would think to write.

So the assertions that matter are the ones where a session sink IS called and the answer is still
"no finding":

  - the value came from a helper that returns a constant (the benchmark's own `getTheValue`)
  - the value came out of a map at the key that never received the tainted value
  - the value came from the constant arm of a branch whose condition folds
  - the StringBuilder that reached the sink only ever appended constants
  - the value is `request.path` under a static route, which is pinned to a literal

and the positive: a request parameter through any of those same launderers must still flag.

The launderer shapes here are the real ones, read out of the benchmark, but nothing in these tests
or in the analyzer names a case id, a file name or a per-case fingerprint. The predicates below are
the suite's own constants precisely because the same predicate text folds BOTH ways depending on a
number declared eight lines earlier -- `(7*42) - 86 > 200` is true and `(7*42) - 106 > 200` is
false. That pair is the reason a textual rule cannot do this job.
"""
import codereview as cr


# ---------------------------------------------------------------- helpers

def _java(body, extra=""):
    """A servlet whose doPost is `body`. Structure only -- no case identity."""
    return """package com.example.app;
import javax.servlet.http.*;
public class Handler extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
%s
    }
%s
}
""" % (body, extra)


def _flags(text, source="Handler.java", summaries=None):
    return cr.scan_trust_boundary(text, source, summaries)


def _py(body, route="/app/save", extra=""):
    return """from flask import request
import flask
%s
def init(app):
    @app.route('%s', methods=['POST'])
    def handler():
%s
        return "ok"
""" % (extra, route, body)


# ================================================================ CONTROL 1
# A value that reaches the sink from a CONSTANT, not from the request.

def test_control1_java_constant_returning_helper_does_not_flag():
    src = _java("""
        SeparateClassRequest scr = new SeparateClassRequest(request);
        String param = scr.getTheValue("name");
        request.getSession().setAttribute(param, "10340");
""")
    helper = """package com.example.app;
public class SeparateClassRequest {
    private HttpServletRequest request;
    public SeparateClassRequest(HttpServletRequest request) { this.request = request; }
    public String getTheParameter(String p) { return request.getParameter(p); }
    public String getTheValue(String p) { return "bar"; }
}
"""
    summaries = cr.summarize_units(helper, "SeparateClassRequest.java")
    assert _flags(src, summaries=summaries) == []


def test_control1_twin_the_same_helper_object_reading_the_request_DOES_flag():
    """The receiver is identical; only the METHOD's return provenance differs. If this does not
    flag, control 1 is passing for the wrong reason -- because nothing resolves at all."""
    src = _java("""
        SeparateClassRequest scr = new SeparateClassRequest(request);
        String param = scr.getTheParameter("name");
        request.getSession().setAttribute(param, "10340");
""")
    helper = """package com.example.app;
public class SeparateClassRequest {
    public String getTheParameter(String p) { return request.getParameter(p); }
    public String getTheValue(String p) { return "bar"; }
}
"""
    summaries = cr.summarize_units(helper, "SeparateClassRequest.java")
    assert len(_flags(src, summaries=summaries)) == 1


def test_control1_python_constant_returning_helper_does_not_flag():
    src = _py("""
        scr = wrapper(request)
        param = scr.get_safe_value("name")
        flask.session[param] = '12345'
""")
    helper = """class wrapper:
    def __init__(self, request):
        self.request = request
    def get_query_parameter(self, name):
        return self.request.args.get(name)
    def get_safe_value(self, name):
        return "bar"
"""
    summaries = cr.summarize_units(helper, "separate_request.py")
    assert cr.scan_trust_boundary(src, "case.py", summaries) == []


def test_control1_python_twin_the_request_reading_method_DOES_flag():
    src = _py("""
        scr = wrapper(request)
        param = scr.get_query_parameter("name")
        flask.session[param] = '12345'
""")
    helper = """class wrapper:
    def __init__(self, request):
        self.request = request
    def get_query_parameter(self, name):
        return self.request.args.get(name)
    def get_safe_value(self, name):
        return "bar"
"""
    summaries = cr.summarize_units(helper, "separate_request.py")
    assert len(cr.scan_trust_boundary(src, "case.py", summaries)) == 1


# ================================================================ CONTROL 2
# map.put("keyA", CONST); map.put("keyB", param); ... get("keyA") -> clean.
# The clean twin ALSO reads keyB first, so "does get(keyB) appear" flags both.

def test_control2_java_map_read_back_at_the_safe_key_does_not_flag():
    src = _java("""
        String param = request.getParameter("name");
        String bar = "safe!";
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA-1", "a_Value");
        map.put("keyB-1", param);
        map.put("keyC", "another_Value");
        bar = (String) map.get("keyB-1");
        bar = (String) map.get("keyA-1");
        request.getSession().setAttribute("userid", bar);
""")
    assert _flags(src) == []


def test_control2_java_map_read_back_at_the_tainted_key_DOES_flag():
    src = _java("""
        String param = request.getParameter("name");
        String bar = "safe!";
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA-1", "a_Value");
        map.put("keyB-1", param);
        map.put("keyC", "another_Value");
        bar = (String) map.get("keyB-1");
        request.getSession().setAttribute("userid", bar);
""")
    assert len(_flags(src)) == 1


def test_control2_python_dict_and_configparser_slots():
    clean = _py("""
        param = request.args.get("name")
        import configparser
        bar = 'safe!'
        conf = configparser.ConfigParser()
        conf.add_section('s')
        conf.set('s', 'keyA-1', 'a_Value')
        conf.set('s', 'keyB-1', param)
        bar = conf.get('s', 'keyA-1')
        flask.session['userid'] = bar
""")
    dirty = _py("""
        param = request.args.get("name")
        import configparser
        bar = 'safe!'
        conf = configparser.ConfigParser()
        conf.add_section('s')
        conf.set('s', 'keyA-1', 'a_Value')
        conf.set('s', 'keyB-1', param)
        bar = conf.get('s', 'keyB-1')
        flask.session['userid'] = bar
""")
    assert cr.scan_trust_boundary(clean, "case.py") == []
    assert len(cr.scan_trust_boundary(dirty, "case.py")) == 1


# ================================================================ CONTROL 3
# A ternary / if whose branch is decided by constant folding.
# THE PREDICATE TEXT IS IDENTICAL IN BOTH DIRECTIONS. Only `num` differs.

def test_control3_java_folded_branch_taking_the_constant_does_not_flag():
    src = _java("""
        String param = request.getParameter("name");
        String bar;
        int num = 86;
        if ((7 * 42) - num > 200) bar = "This_should_always_happen";
        else bar = param;
        request.getSession().putValue("userid", bar);
""")
    assert _flags(src) == []


def test_control3_java_the_same_predicate_with_a_different_constant_DOES_flag():
    src = _java("""
        String param = request.getParameter("name");
        String bar;
        int num = 106;
        bar = (7 * 42) - num > 200 ? "This should never happen" : param;
        request.getSession().setAttribute(bar, "10340");
""")
    assert len(_flags(src)) == 1


def test_control3_java_integer_division_is_integer():
    """`500 / 42` is 11 in Java, not 11.9. The suite folds `(500 / 42) + num > 200` with
    num = 196 -- 207, true -- and the true arm is the TAINTED one here."""
    src = _java("""
        String param = request.getParameter("name");
        String bar;
        int num = 196;
        if ((500 / 42) + num > 200) bar = param;
        else bar = "This should never happen";
        request.getSession().putValue("userid", bar);
""")
    assert len(_flags(src)) == 1


def test_control3_java_switch_on_a_folded_character():
    safe = _java("""
        String param = request.getParameter("name");
        String bar;
        String guess = "ABC";
        char switchTarget = guess.charAt(1);
        switch (switchTarget) {
            case 'A': bar = param; break;
            case 'B': bar = "bob"; break;
            case 'C': case 'D': bar = param; break;
            default: bar = "bobs_your_uncle"; break;
        }
        request.getSession().putValue("userid", bar);
""")
    dirty = safe.replace("guess.charAt(1)", "guess.charAt(2)")
    assert _flags(safe) == []
    assert len(_flags(dirty)) == 1


def test_control3_python_folded_ternary_and_string_predicate():
    safe = _py("""
        param = request.args.get("name")
        num = 106
        bar = "This_should_always_happen" if 7 * 18 + num > 200 else param
        flask.session[bar] = '12345'
""")
    # `'should' not in TestParam` is False, so the ELSE arm -- the tainted one -- is taken.
    dirty = _py("""
        param = request.args.get("name")
        TestParam = "This should never happen"
        if 'should' not in TestParam:
            bar = "Ifnot case passed"
        else:
            bar = param
        flask.session[bar] = '12345'
""")
    assert cr.scan_trust_boundary(safe, "case.py") == []
    assert len(cr.scan_trust_boundary(dirty, "case.py")) == 1


def test_control3_an_unfoldable_condition_keeps_the_taint():
    """Folding is an optimisation, never an excuse. When the condition does NOT fold, both arms
    are live and a tainted arm still reaches the sink."""
    src = _java("""
        String param = request.getParameter("name");
        String bar = "";
        if (param != null) bar = param.split(" ")[0];
        request.getSession().setAttribute("userid", bar);
""")
    assert len(_flags(src)) == 1


# ================================================================ CONTROL 4
# A StringBuilder that appends only constants.

def test_control4_java_stringbuilder_of_only_constants_does_not_flag():
    src = _java("""
        String param = request.getParameter("name");
        StringBuilder sb = new StringBuilder("prefix");
        sb.append("_SafeStuff");
        String bar = sb.toString();
        request.getSession().setAttribute("userid", bar);
""")
    assert _flags(src) == []


def test_control4_java_stringbuilder_holding_the_parameter_DOES_flag():
    """Every StringBuilder in the benchmark's trustbound category is built FROM param, so this
    direction is the one the category actually exercises -- and treating a StringBuilder as a
    launderer would be a false NEGATIVE, not the false positive the old comment feared."""
    src = _java("""
        String param = request.getParameter("name");
        StringBuilder sb = new StringBuilder(param);
        String bar = sb.append("_SafeStuff").toString();
        request.getSession().setAttribute("userid", bar);
""")
    assert len(_flags(src)) == 1


def test_control4_python_constant_accumulator_alias_does_not_flag():
    """Two aliases of the same empty string; one receives the taint, the other reaches the sink."""
    src = _py("""
        param = request.args.get("name")
        string = ''
        copy = string
        string = ''
        string += param
        copy += 'SomeOKString'
        bar = copy
        flask.session['userid'] = bar
""")
    assert cr.scan_trust_boundary(src, "case.py") == []


# ================================================================ CONTROL 5
# The true positive: a request parameter reaching the sink through each launderer.

def test_control5_request_parameter_through_every_launderer_flags():
    launderers = [
        "String bar = param;",
        "String bar = param.substring(0, param.length() - 1);",
        "String bar = param.split(\" \")[0];",
        "String bar = new String(Base64.decodeBase64(Base64.encodeBase64(param.getBytes())));",
        "String bar = new StringBuilder(param).append(\"_SafeStuff\").toString();",
        "String bar = org.apache.commons.lang.StringEscapeUtils.escapeHtml(param);",
        "String bar = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);",
    ]
    for launder in launderers:
        src = _java("""
        String param = request.getParameter("name");
        %s
        request.getSession().setAttribute("userid", bar);
""" % launder)
        assert len(_flags(src)) == 1, "missed taint through: %s" % launder


def test_control5_every_http_source_is_a_source():
    sources = [
        'String param = request.getParameter("name");',
        'String param = request.getHeader("X-Thing");',
        'String param = request.getQueryString();',
        'String param = request.getParameterValues("name")[0];',
        'String param = (String) request.getParameterMap().get("name")[0];',
    ]
    for src_line in sources:
        src = _java("""
        %s
        request.getSession().setAttribute("userid", param);
""" % src_line)
        assert len(_flags(src)) == 1, "missed source: %s" % src_line


def test_control5_the_tainted_argument_may_be_the_KEY_or_the_VALUE():
    """`setAttribute(bar, "10340")` and `setAttribute("userid", bar)` are both in the category.
    An argument-position rule is no more use than a call-name rule."""
    for sink in ['request.getSession().setAttribute(bar, "10340");',
                 'request.getSession().setAttribute("userid", bar);',
                 'request.getSession().putValue(bar, "10340");',
                 'request.getSession().putValue("userid", bar);']:
        src = _java("""
        String param = request.getParameter("name");
        String bar = param;
        %s
""" % sink)
        assert len(_flags(src)) == 1, "missed sink: %s" % sink


# ================================================================ the sink is not the defect
# This is the assertion the whole lane exists to satisfy.

def test_a_session_sink_with_no_request_provenance_does_not_flag():
    """The `rememberMe` boilerplate: 493 files in the Java suite carry this exact shape OUTSIDE
    the trustbound category. A sink-matching detector reports every one of them."""
    src = _java("""
        String fullClassName = this.getClass().getName();
        String testCaseNumber = fullClassName.substring(fullClassName.lastIndexOf('.') + 1);
        String cookieName = "rememberMe" + testCaseNumber;
        String rememberMeKey = Long.toString(new java.security.SecureRandom().nextLong());
        request.getSession().setAttribute(cookieName, rememberMeKey);
""")
    assert _flags(src) == []


def test_a_request_read_that_never_reaches_the_sink_does_not_flag():
    src = _java("""
        String param = request.getParameter("name");
        response.getWriter().println(param);
        request.getSession().setAttribute("userid", "constant");
""")
    assert _flags(src) == []


# ================================================================ intra-file interprocedural
# 85 of 126 Java cases route the transform through a private helper or an inner class.

def test_a_private_helper_carries_the_taint_through():
    src = _java("""
        String param = request.getParameter("name");
        String bar = doSomething(request, param);
        request.getSession().putValue("userid", bar);
""", extra="""
    private static String doSomething(HttpServletRequest request, String param) {
        String bar = param;
        return bar;
    }
""")
    assert len(_flags(src)) == 1


def test_a_private_helper_that_folds_to_a_constant_does_not_flag():
    src = _java("""
        String param = request.getParameter("name");
        String bar = new Test().doSomething(request, param);
        request.getSession().putValue("userid", bar);
""", extra="""
    private class Test {
        public String doSomething(HttpServletRequest request, String param) {
            String bar;
            int num = 86;
            if ((7 * 42) - num > 200) bar = "This_should_always_happen";
            else bar = param;
            return bar;
        }
    }
""")
    assert _flags(src) == []


def test_an_unresolved_call_propagates_taint_rather_than_dropping_it():
    """A method this analysis cannot see must be assumed taint-preserving. Dropping taint at an
    unknown call is how a dataflow engine reports a vulnerable file clean."""
    src = _java("""
        String param = request.getParameter("name");
        String bar = com.somewhere.Unknown.transform(param);
        request.getSession().setAttribute("userid", bar);
""")
    assert len(_flags(src)) == 1


# ================================================================ list slots

def test_list_index_arithmetic_after_a_removal():
    clean = _java("""
        String param = request.getParameter("name");
        String bar = "alsosafe";
        if (param != null) {
            java.util.List<String> valuesList = new java.util.ArrayList<String>();
            valuesList.add("safe");
            valuesList.add(param);
            valuesList.add("moresafe");
            valuesList.remove(0);
            bar = valuesList.get(1);
        }
        request.getSession().setAttribute("userid", bar);
""")
    dirty = clean.replace("bar = valuesList.get(1);", "bar = valuesList.get(0);")
    assert _flags(clean) == []
    assert len(_flags(dirty)) == 1


# ================================================================ Python-specific provenance

def test_python_static_route_pins_request_path_to_a_literal():
    """`request.path.split('/')[1]` under a route with no converters is the constant path segment.
    112 cases in the Python suite use exactly this source; every one indexes [1]."""
    src = _py("""
        parts = request.path.split("/")
        param = parts[1]
        bar = param
        flask.session[bar] = '12345'
""", route="/benchmark/trustbound-00/Case")
    assert cr.scan_trust_boundary(src, "case.py") == []


def test_python_a_route_with_a_converter_does_not_pin_the_path():
    """The refinement is only sound when the route is a literal. A `<name>` converter puts an
    attacker back in control of the path, and the same code must flag."""
    src = _py("""
        parts = request.path.split("/")
        param = parts[2]
        bar = param
        flask.session[bar] = '12345'
""", route="/benchmark/<thing>/Case")
    assert len(cr.scan_trust_boundary(src, "case.py")) == 1


def test_python_slicing_a_constant_wrapped_parameter_keeps_the_taint():
    src = _py("""
        param = request.args.get("name")
        superstring = f'12345{param}abcd'
        bar = superstring[len('12345'):len(superstring)-5]
        flask.session['userid'] = bar
""")
    assert len(cr.scan_trust_boundary(src, "case.py")) == 1


def test_python_list_slot_and_match_statement():
    clean = _py("""
        param = request.headers.get("X-Thing")
        possible = "ABC"
        guess = possible[1]
        match guess:
            case 'A':
                bar = param
            case 'B':
                bar = 'bob'
            case 'C' | 'D':
                bar = param
            case _:
                bar = 'bobs_your_uncle'
        flask.session['userid'] = bar
""")
    dirty = clean.replace("guess = possible[1]", "guess = possible[0]")
    assert cr.scan_trust_boundary(clean, "case.py") == []
    assert len(cr.scan_trust_boundary(dirty, "case.py")) == 1


def test_python_escaping_does_not_sanitize_a_trust_boundary():
    """CWE-501 is about TRUST, not about output context. HTML entity encoding is CWE-116
    mitigation for an HTML sink; a session is not an HTML sink and the key is still
    attacker-chosen. Recorded in docs/handoff/dataflow.md BEFORE any score was taken."""
    src = _py("""
        param = request.args.get("name")
        import markupsafe
        bar = markupsafe.escape(param)
        flask.session[bar] = '12345'
""")
    assert len(cr.scan_trust_boundary(src, "case.py")) == 1


def test_python_iterating_a_tainted_collection_yields_tainted_elements():
    src = _py("""
        param = ""
        for name in request.headers.keys():
            if request.headers.get_all(name):
                param = name
                break
        bar = param
        flask.session['userid'] = bar
""")
    assert len(cr.scan_trust_boundary(src, "case.py")) == 1


# ================================================================ the REAL declaration shape
# The synthetic servlets above use a one-line signature and no annotation. Every real servlet in
# the benchmark has both an `@Override` and a `throws` clause wrapped onto the next line, and the
# first version of the method finder matched neither -- 34 green tests and ZERO findings on 126
# real Java cases. A helper that recognises no real declaration is worse than no helper.

def test_a_real_servlet_declaration_is_recognised():
    src = """package org.owasp.benchmark.testcode;
import javax.servlet.http.*;
@WebServlet(value = "/trustbound-00/Case")
public class Case extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        java.util.Map<String, String[]> map = request.getParameterMap();
        String param = "";
        if (!map.isEmpty()) {
            String[] values = map.get("Case");
            if (values != null) param = values[0];
        }
        request.getSession().putValue("userid", param);
    }
}
"""
    units = cr._java_units(cr.mask_source(src)[0])
    assert "doPost" in units and "doGet" in units
    assert units["doPost"][1] == ["request", "response"]
    assert len(_flags(src, source="Case.java")) == 1


def test_control_structures_are_not_mistaken_for_declarations():
    src = _java("""
        String param = request.getParameter("name");
        String bar = "safe";
        for (int i = 0; i < 3; i++) { bar = "still safe"; }
        while (false) { bar = param; }
        try { bar = "safe"; } catch (Exception e) { bar = "safe"; }
        switch (2) { case 1: bar = param; break; default: break; }
        request.getSession().setAttribute("userid", bar);
""")
    units = cr._java_units(cr.mask_source(src)[0])
    assert "if" not in units and "for" not in units and "while" not in units
    assert "catch" not in units and "switch" not in units
    assert _flags(src) == []


# ================================================================ one name, two methods

def test_a_same_named_method_with_a_different_signature_is_not_inlined():
    """A file that defines `doSomething(request, param)` and also calls `thing.doSomething(param)`
    on an interface from another file has TWO methods with one name. Inlining the local one for
    the foreign call binds the arguments to the wrong parameters and DROPS the taint. All 16 Java
    misses in the first sealed measurement were this."""
    src = _java("""
        String param = request.getParameter("name");
        Thing thing = ThingFactory.createThing();
        String bar = thing.doSomething(param);
        request.getSession().setAttribute("userid", bar);
""", extra="""
    private static String doSomething(HttpServletRequest request, String param) {
        return "This is a different method that happens to share a name";
    }
""")
    assert len(_flags(src)) == 1


def test_merge_summaries_retracts_a_name_left_undecided_elsewhere():
    """A verdict is only usable if EVERY definition of that name agrees. A name that is provably
    constant in one file and undecided in another must fall back to taint-preserving; reading only
    the entries that carry a verdict lets one accidental constant helper vouch for the tree."""
    decided = {"getValue": "const", "other": "source"}
    undecided = {"getValue": None}
    assert cr.merge_summaries([decided]) == {"getValue": "const", "other": "source"}
    assert cr.merge_summaries([decided, undecided]) == {"other": "source"}
    assert cr.merge_summaries([decided, {"getValue": "source"}]) == {"other": "source"}


def test_summarize_units_reports_undecided_units_too():
    helper = """package com.example.app;
public class Helper {
    public String constant(String p) { return "bar"; }
    public String passthrough(String p) { return p; }
}
"""
    s = cr.summarize_units(helper, "Helper.java")
    assert s["constant"] == "const"
    assert "passthrough" in s and s["passthrough"] is None


# ================================================================ findings are well formed

def test_the_finding_names_the_source_and_the_sink_not_just_the_line():
    src = _java("""
        String param = request.getHeader("X-Thing");
        String bar = param;
        request.getSession().setAttribute("userid", bar);
""")
    hits = _flags(src)
    assert len(hits) == 1
    h = hits[0]
    assert h["cwe"] == "CWE-501"
    assert "getHeader" in h["source"]
    assert "setAttribute" in h["api"]
    assert h["line"] > 0
    assert h["resolved_from"] == "dataflow"


def test_review_source_emits_the_trust_boundary_family():
    src = _java("""
        String param = request.getParameter("name");
        request.getSession().setAttribute(param, "10340");
""")
    fams = [f["family"] for f in cr.review_source(src, "Handler.java")]
    assert "trust_boundary" in fams
    f = [x for x in cr.review_source(src, "Handler.java") if x["family"] == "trust_boundary"][0]
    assert f["lane"] == "code-assisted"
    assert f["provenance"] == "source-derived"
    assert f["confidence"] == "confirmed"


def test_one_finding_per_sink_not_one_per_path():
    """A value that reaches the same sink twice over is one defect, not two."""
    src = _java("""
        String param = request.getParameter("name");
        String bar = param + param;
        request.getSession().setAttribute("userid", bar);
""")
    assert len(_flags(src)) == 1
