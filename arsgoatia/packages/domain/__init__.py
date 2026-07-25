"""Canonical persistence layer.

models.py holds the SQLAlchemy 2.0 ORM; the authoritative DDL (tables, RLS
policies, append-only/immutability triggers) lives in Alembic migrations. The
repository layer routes all writes so immutable/append-only rules hold above the
database as well as inside it.
"""
