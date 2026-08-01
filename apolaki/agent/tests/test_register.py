"""Registration engine — pure form discovery / payload / policy-adaptation / blocker detection.
No network (register() itself is the only networked fn and is covered by the auth-artery
integration tests)."""
from __future__ import annotations

import re
import string

import register as R


_LOGIN_AND_SIGNUP = """
<html><body>
<form action="/login" method="post">
  <input type="hidden" name="csrf" value="L1">
  <input type="text" name="username">
  <input type="password" name="password">
</form>
<form action="/register" method="post">
  <input type="hidden" name="csrf" value="R2">
  <input type="text" name="username">
  <input type="email" name="email">
  <input type="password" name="password">
  <input type="password" name="passwordRepeat">
  <input type="checkbox" name="acceptTerms">
</form>
</body></html>
"""


def test_parse_register_form_picks_signup_not_login():
    form = R.parse_register_form(_LOGIN_AND_SIGNUP, "https://t.example")
    assert form is not None
    assert form["action"] == "https://t.example/register"
    assert form["email_field"] == "email"
    assert form["pass_field"] == "password"
    assert form["confirm_field"] == "passwordRepeat"
    assert "csrf" in form["hidden"] and form["hidden"]["csrf"] == "R2"
    assert "acceptTerms" in form["checkboxes"]


def test_login_only_page_is_not_a_register_form():
    login_only = """<form action="/login" method="post">
      <input name="username"><input type="password" name="password"></form>"""
    # a single login form scores negative (no confirm/email/register-action, /login penalty) so
    # parse_register_form finds nothing to register with.
    assert R.parse_register_form(login_only, "https://t.example") is None


def test_registration_rejection_markers():
    # a sub-400 response is not proof of creation — 200 validation-error pages are rejected
    assert R._registration_rejected("The e-mail is already registered.")
    assert R._registration_rejected("Password must be at least 8 characters")
    assert R._registration_rejected("Passwords do not match")
    assert R._registration_rejected("Invalid email address")
    assert not R._registration_rejected("Welcome! Your account has been created.")
    assert not R._registration_rejected("")


def test_detect_blockers():
    assert "captcha" in R.detect_blockers('<div class="g-recaptcha"></div>')
    assert "mfa" in R.detect_blockers("Enter your verification code from the authenticator app")
    assert "email_verification" in R.detect_blockers("We sent a confirmation email, check your inbox")
    assert "invite_code" in R.detect_blockers("You need an invite code to join")
    assert R.detect_blockers("<form action=/register>plain signup</form>") == []


def test_adapt_password_meets_policy():
    pw = R.adapt_password("Your password must be at least 16 characters long")
    assert len(pw) >= 16
    assert any(c.isupper() for c in pw) and any(c.islower() for c in pw)
    assert any(c.isdigit() for c in pw) and any(c in R._PW_SYMBOLS for c in pw)


def test_adapt_password_default_is_strong():
    pw = R.adapt_password("")
    assert len(pw) >= 12
    classes = [any(c.isupper() for c in pw), any(c.islower() for c in pw),
               any(c.isdigit() for c in pw), any(c in R._PW_SYMBOLS for c in pw)]
    assert all(classes)


def test_gen_account_unique_and_greppable():
    a = R.gen_account("user_a")
    b = R.gen_account("user_b")
    assert a["email"] != b["email"]
    assert a["username"].startswith("apolaki_usera_")
    assert b["username"].startswith("apolaki_userb_")
    assert "@" in a["email"]


def test_build_payload_fills_everything():
    form = R.parse_register_form(_LOGIN_AND_SIGNUP, "https://t.example")
    acct = {"username": "apolaki_x", "email": "apolaki_x@t.local", "password": "P@ssw0rd1234"}
    data = R.build_registration_payload(form, acct)
    assert data["username"] == "apolaki_x"
    assert data["email"] == "apolaki_x@t.local"
    assert data["password"] == "P@ssw0rd1234"
    assert data["passwordRepeat"] == "P@ssw0rd1234"   # confirm field mirrored
    assert data["csrf"] == "R2"                        # hidden carried
    assert data["acceptTerms"] == "on"                 # consent ticked
