-- ArsGoatia PostgreSQL initialization
-- Run once against a fresh database to install extensions and create schemas.

-- Extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Domain schemas
CREATE SCHEMA IF NOT EXISTS iam;
CREATE SCHEMA IF NOT EXISTS governance;
CREATE SCHEMA IF NOT EXISTS knowledge;
CREATE SCHEMA IF NOT EXISTS reasoning;
CREATE SCHEMA IF NOT EXISTS execution;
CREATE SCHEMA IF NOT EXISTS evidence;
CREATE SCHEMA IF NOT EXISTS findings;
CREATE SCHEMA IF NOT EXISTS reporting;
CREATE SCHEMA IF NOT EXISTS remediation;
CREATE SCHEMA IF NOT EXISTS audit;

-- Row-Level Security helper: set the current tenant for RLS policies.
CREATE OR REPLACE FUNCTION set_tenant(p_tenant_id uuid)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('app.tenant_id', p_tenant_id::text, true);
END;
$$;
