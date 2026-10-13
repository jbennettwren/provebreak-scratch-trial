"""ProveBreak culprit Action v1.0.0. Engine vendored from jbennettwren/sentinel-lab into provebreak_culprit._engine; pinned in ENGINE_LOCK.json (see ENGINE_PROVENANCE.md)."""
__version__ = "1.0.0"
from provebreak_culprit._provenance import ENGINE_COMMIT, ENGINE_ID, ENGINE_SOURCE_REPO  # noqa: E402,F401


def provenance() -> str:
    """Single provenance string: Action version + exact engine commit (never the upstream engine __version__)."""
    return f"provebreak-culprit {__version__} (engine {ENGINE_SOURCE_REPO}@{ENGINE_COMMIT})"
