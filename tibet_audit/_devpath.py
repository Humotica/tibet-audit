"""Optional dev-source fallback — no hardcoded absolute paths ship in the package.

The published package relies on its installed dependencies (tibet-mux, tibet-cbom).
For monorepo development without an editable install, set TIBET_AUDIT_DEV_SRC to a
pathsep-separated list of local `src` directories; only existing dirs are added.

This exists so a fresh `pip install tibet-audit` never carries a path like
`/srv/...` that means nothing on someone else's machine. Sovereign, local-only,
no surprises.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def add_dev_src() -> None:
    """Add TIBET_AUDIT_DEV_SRC entries to sys.path (opt-in, existing dirs only)."""
    for p in os.environ.get("TIBET_AUDIT_DEV_SRC", "").split(os.pathsep):
        if p and p not in sys.path and Path(p).is_dir():
            sys.path.insert(0, p)


def repo_posture_path() -> Path | None:
    """Resolve repo_posture.json without a hardcoded path.

    Order: TIBET_AUDIT_REPO_POSTURE env -> ./repo-posture/repo_posture.json in the
    current working tree. Returns None if not found (the Stack pane degrades
    honestly rather than pointing at someone else's filesystem).
    """
    env = os.environ.get("TIBET_AUDIT_REPO_POSTURE", "").strip()
    if env and Path(env).is_file():
        return Path(env)
    local = Path.cwd() / "repo-posture" / "repo_posture.json"
    if local.is_file():
        return local
    return None
