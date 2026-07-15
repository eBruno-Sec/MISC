"""
Recon engine.

Wraps the existing Round Table Knights (Percival passive, Galahad active) as
importable phase functions and streams progress into the mission event feed.
The knights are the proven recon logic; the engine adds orchestration, events,
and structured output for the web platform.
"""
import sys
from pathlib import Path

# Make the sibling `knights/` package importable inside the container/repo.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_KNIGHTS = _REPO_ROOT / "knights"
if _KNIGHTS.is_dir() and str(_KNIGHTS) not in sys.path:
    sys.path.insert(0, str(_KNIGHTS))
