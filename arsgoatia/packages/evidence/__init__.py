"""Evidence: immutable, content-addressed artifacts (§16).

poc.py    — ported redaction + reproduction rendering (olympus/core/poc.py)
store.py  — S3/MinIO put/get with sha256 verification and the §16 key layout
profiles.py — evidence-profile completeness (e.g. authorization_differential)
"""
