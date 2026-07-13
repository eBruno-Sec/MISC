from datetime import datetime, timezone


def utcnow() -> datetime:
    """Timezone-naive UTC timestamp — a drop-in for the deprecated
    ``datetime.utcnow()`` (removed-in-future in Python 3.12+).

    Returns a *naive* UTC datetime on purpose: the ``DateTime`` columns in
    ``core.models`` are naive, and the rest of the app (e.g. ``core.backup``)
    compares against naive datetimes, so this keeps identical value semantics
    while dropping the deprecation warning."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
