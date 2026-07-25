-- ArsGoatia database initialization (runs once, on first cluster init).
--
-- Extensions used across the canonical schema. The tables themselves, their
-- row-level-security policies, and the append-only/immutability triggers are
-- created by Alembic migrations (see packages/domain + migrations/), not here,
-- so the schema stays versioned and migration-validated (spec §33).

CREATE EXTENSION IF NOT EXISTS pgcrypto;    -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Temporal's own databases (temporal, temporal_visibility) are created by the
-- temporalio/auto-setup container, not here.
