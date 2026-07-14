from sqlalchemy import text

# Each statement is executed on its own. The asyncpg driver runs queries through
# PostgreSQL's extended (prepared-statement) protocol, which allows only ONE
# command per execute() — a single semicolon-joined batch raises
# "cannot insert multiple commands into a prepared statement" and would abort
# backend startup. The DO $$...$$ block is one statement and stays whole.
_COMPAT_STATEMENTS = (
    # Findings gain a confidence label (Aang): every finding is reported, labeled
    # by how sure we are. Added WITHOUT a DDL default so existing rows come out
    # NULL and the severity-based backfill below actually applies (a DEFAULT would
    # pre-fill every legacy row 'medium' and the backfill would match nothing).
    # New rows get the model-side default; _finding_dict coalesces any NULL.
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS confidence VARCHAR",
    "UPDATE findings SET confidence = 'high' WHERE confidence IS NULL AND severity IN ('critical','high')",
    "UPDATE findings SET confidence = 'medium' WHERE confidence IS NULL AND severity = 'medium'",
    "UPDATE findings SET confidence = 'low' WHERE confidence IS NULL",
    "ALTER TABLE http_exchanges ADD COLUMN IF NOT EXISTS status_code INTEGER",
    "ALTER TABLE http_exchanges ADD COLUMN IF NOT EXISTS duration_ms INTEGER",
    "ALTER TABLE http_exchanges ADD COLUMN IF NOT EXISTS source VARCHAR",
    "ALTER TABLE http_exchanges ADD COLUMN IF NOT EXISTS notes TEXT",
    "ALTER TABLE http_exchanges ADD COLUMN IF NOT EXISTS redacted BOOLEAN DEFAULT TRUE",
    "ALTER TABLE http_exchanges ADD COLUMN IF NOT EXISTS created_at TIMESTAMP",
    "ALTER TABLE http_exchanges ALTER COLUMN redacted SET DEFAULT TRUE",
    # Backfill the new columns from legacy names when an old Docker volume still
    # carries them. Each UPDATE is guarded by an IF EXISTS on the legacy column so
    # plpgsql never plans an UPDATE against a column that isn't there.
    """
    DO $$
    BEGIN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'http_exchanges'
              AND column_name = 'response_status'
        ) THEN
            UPDATE http_exchanges
            SET status_code = response_status
            WHERE status_code IS NULL
              AND response_status IS NOT NULL;
        END IF;

        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'http_exchanges'
              AND column_name = 'timestamp'
        ) THEN
            UPDATE http_exchanges
            SET created_at = timestamp
            WHERE created_at IS NULL
              AND timestamp IS NOT NULL;
        END IF;

        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'http_exchanges'
              AND column_name = 'label'
        ) THEN
            UPDATE http_exchanges
            SET source = label
            WHERE source IS NULL
              AND label IS NOT NULL;
        END IF;
    END $$
    """,
    "UPDATE http_exchanges SET redacted = TRUE WHERE redacted IS NULL",
    "UPDATE http_exchanges SET created_at = NOW() WHERE created_at IS NULL",
)


async def ensure_schema_compatibility(conn) -> None:
    """Apply small compatibility migrations for pre-Alembic Docker volumes.

    PostgreSQL only. Statements run one at a time because the asyncpg driver
    rejects multiple commands in a single prepared statement."""
    if conn.dialect.name != "postgresql":
        return

    for statement in _COMPAT_STATEMENTS:
        await conn.execute(text(statement))
