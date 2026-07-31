"""Tests for autonomous authenticated scanning: credential DISCOVERY (harvest published/leaked creds,
reject prose), the CSRF-form login fallback, credential redaction, and the exposed_credentials technique
being registered + autonomously planned. Pure -- no network."""
from __future__ import annotations

import auth
import intel
import techniques as T
import technique_planner as TP


def _creds(text):
    s = intel.IntelStore()
    intel.harvest_credentials(text, "x", s)
    return s.get("credential")


def test_harvest_published_and_inline_credentials():
    # zero-width/space obfuscated published test account (Gin & Juice style)
    assert _creds("ACCOUNT LOGIN DETAILS Username ​ c​ a​ r​ l​ o​ s "
                  "Password ​ h​ u​ n​ t​ e​ r​ 2 Path") == ["carlos:hunter2"]
    # explicit key:value with a special-char password (kept intact)
    assert _creds("username: admin password: s3cr3t!") == ["admin:s3cr3t!"]


def test_prose_does_not_yield_phantom_credentials():
    assert _creds("The user can reset a password by email.") == []
    assert _creds("A user should choose a strong password.") == []


def test_credential_password_is_redacted_at_rest():
    s = intel.IntelStore()
    s.add("credential", "carlos:hunter2", "src")
    red = s.to_dict(redact_secrets=True)["candidates"]["credential"]
    assert red == ["carlos:<redacted>"]                       # username kept, password never at rest
    assert s.to_dict(redact_secrets=False)["candidates"]["credential"] == ["carlos:hunter2"]


def test_login_form_fallback_picks_login_csrf_not_register():
    html = ('<form action="/register"><input type=hidden name=csrf value=REG>'
            '<input name=username><input name=email></form>'
            '<form action="/login"><input type=hidden name=csrf value=LOGIN>'
            '<input name=username></form>')
    hidden, action = auth._hidden_and_action(html, "https://t/login", "https://t/login")
    assert action == "https://t/login" and hidden.get("csrf") == "LOGIN"   # the login form, not register


def test_exposed_credentials_is_a_registered_planned_technique():
    assert "exposed_credentials" in T.TECHNIQUES
    assert T.TECHNIQUES["exposed_credentials"]["validated_on"] == ["ginandjuice"]
    # autonomously planned the moment recon has exposed a credential
    plan = TP.plan({"credentials_exposed"}, TP.registry_seed())
    assert any(a["id"] == "exposed_credentials" for a in plan)
