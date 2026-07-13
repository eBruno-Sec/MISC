from sqlalchemy import text


async def ensure_schema_compatibility(conn) -> None:
    """Apply small compatibility migrations for pre-Alembic Docker volumes."""
    if conn.dialect.name != "postgresql":
        return

    await conn.execute(text("""
        ALTER TABLE http_exchanges ADD COLUMN IF NOT EXISTS status_code INTEGER;
        ALTER TABLE http_exchanges ADD COLUMN IF NOT EXISTS duration_ms INTEGER;
        ALTER TABLE http_exchanges ADD COLUMN IF NOT EXISTS source VARCHAR;
        ALTER TABLE http_exchanges ADD COLUMN IF NOT EXISTS notes TEXT;
        ALTER TABLE http_exchanges ADD COLUMN IF NOT EXISTS redacted BOOLEAN DEFAULT TRUE;
        ALTER TABLE http_exchanges ADD COLUMN IF NOT EXISTS created_at TIMESTAMP;
        ALTER TABLE http_exchanges ALTER COLUMN redacted SET DEFAULT TRUE;

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
        END $$;

        UPDATE http_exchanges SET redacted = TRUE WHERE redacted IS NULL;
        UPDATE http_exchanges SET created_at = NOW() WHERE created_at IS NULL;
    """))
