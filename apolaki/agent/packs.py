"""
Reusable technique packs — target-AGNOSTIC investigation workflows per vulnerability class.

Each pack is a workflow (see workflow.py) parameterized entirely by `inputs` the operator or
LLM supplies at run time (login URLs, credentials, target URLs, parameters). Nothing here is
target-specific: the same idor_read pack works on Juice Shop, DVWA, or a real REST API — only
the input values differ. This is how a confirmed CTF technique becomes a reusable vuln-class
workflow instead of a hardcoded answer.
"""
from __future__ import annotations

PACKS = {
    "idor_read": {
        "id": "idor_read",
        "class": "idor",
        "summary": "Confirm IDOR/BOLA: two identities, attacker reads the victim's object.",
        "inputs_required": ["login_url", "victim_email", "victim_password",
                            "attacker_email", "attacker_password", "target_url"],
        "steps": [
            {"do": "acquire_session", "login_url": "{login_url}", "email": "{victim_email}",
             "password": "{victim_password}", "role": "victim"},
            {"do": "acquire_session", "login_url": "{login_url}", "email": "{attacker_email}",
             "password": "{attacker_password}", "role": "attacker"},
            {"do": "confirm_idor", "target_url": "{target_url}",
             "owner_session": "victim", "attacker_session": "attacker"},
        ],
        "assert": {"field": "confirmed", "equals": True},
        "produces": ["capability:foreign_object_read"],
    },
    "bfla_privileged_action": {
        "id": "bfla_privileged_action",
        "class": "bfla",
        "summary": "Broken function-level authz: a low-privilege session reaches a privileged endpoint.",
        "inputs_required": ["login_url", "email", "password", "privileged_url"],
        "steps": [
            {"do": "acquire_session", "login_url": "{login_url}", "email": "{email}",
             "password": "{password}", "role": "lowpriv"},
            {"do": "http_read", "url": "{privileged_url}", "as": "lowpriv"},
        ],
        "assert": {"field": "status", "equals": 200},
        "produces": [],
    },
    "price_quantity_tamper": {
        "id": "price_quantity_tamper",
        "class": "business_logic",
        "summary": "Business-logic: does the server accept out-of-range quantity/price/amount?",
        "inputs_required": ["login_url", "email", "password", "action_url", "numeric_param"],
        "steps": [
            {"do": "acquire_session", "login_url": "{login_url}", "email": "{email}",
             "password": "{password}", "role": "buyer"},
            {"do": "test_numeric_abuse", "url": "{action_url}", "param": "{numeric_param}", "as": "buyer"},
        ],
        "assert": {},
        "produces": [],
    },
    "object_id_sweep": {
        "id": "object_id_sweep",
        "class": "idor",
        "summary": "Enumerate accessible objects by id under one session (then confirm ownership).",
        "inputs_required": ["login_url", "email", "password", "url_template"],
        "steps": [
            {"do": "acquire_session", "login_url": "{login_url}", "email": "{email}",
             "password": "{password}", "role": "user"},
            {"do": "enumerate_ids", "url_template": "{url_template}", "start": 1, "end": 20, "as": "user"},
        ],
        "assert": {},
        "produces": [],
    },
}


def list_packs() -> list:
    return [{"id": p["id"], "class": p["class"], "summary": p["summary"],
             "inputs_required": p["inputs_required"]} for p in PACKS.values()]


def get(pack_id: str):
    return PACKS.get(pack_id)
