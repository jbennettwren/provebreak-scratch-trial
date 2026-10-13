"""Confirm-the-culprit: binary search over commits, re-running failing tests.

Watch-only, opt-in, fail-soft. Never pushes to customer repos. Never hangs
(hard time + step budgets). When evidence is weak, report not_proven / flaky
rather than naming a culprit.

Security: pytest on historical checkouts runs with a scrubbed env — never
inherits GITHUB_TOKEN or other secrets, and never inherits the real HOME
(fresh temp HOME + XDG_* per eval; GIT_ASKPASS/SSH_AUTH_SOCK/netrc stripped).
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Protocol

import tomllib

DEFAULT_TIME_BUDGET_SEC = 180  # hard wall-clock default (fail-soft abstain)
DEFAULT_STEP_BUDGET = 24  # log2(1000)≈10 + tip/base/confirm buffer
DEFAULT_FLAKY_RERUNS = 3
BISECT_LINEAR_THRESHOLD = 4
MAX_COMMITS = 1000  # safety cap; budget decides feasibility below this
MAX_NODE_ID_LEN = 512
# Submodule fetch shares the bisect budget, but 45s is shorter than a public
# submodule clone. A timeout still abstains; it does not name a culprit.
CHECKOUT_FIDELITY_SEC = 180.0

# --- scrubbed subprocess env -------------------------------------------------
_ENV_ALLOW_EXACT = frozenset(
    {
        "PATH",
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "LC_MESSAGES",
        "USER",
        "LOGNAME",
        "TMPDIR",
        "TMP",
        "TEMP",
        "TERM",
        "TZ",
        "CI",
        "CONTINUOUS_INTEGRATION",
        "RUNNER_OS",
        "RUNNER_ARCH",
        "RUNNER_TEMP",
        "RUNNER_TOOL_CACHE",
        "GITHUB_WORKSPACE",
        "GITHUB_ACTIONS",
        "GITHUB_JOB",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_REPOSITORY",
        "GITHUB_SHA",
        "GITHUB_REF",
        "GITHUB_EVENT_NAME",
        "GITHUB_SERVER_URL",
        "GITHUB_API_URL",
        "NO_COLOR",
        "FORCE_COLOR",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONUNBUFFERED",
        "PYTHONIOENCODING",
        "PYTHONHASHSEED",
        "VIRTUAL_ENV",
    }
)
_ENV_ALLOW_PREFIX = (
    "PYTHON",
    "PYTEST_",
    "PIP_",
    "CONDA_",
    "VIRTUAL_ENV",
    "UV_",
)
# Never pass these even if somehow allowlisted
_ENV_DENY_EXACT = frozenset(
    {
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "SENTINEL_TOKEN",
        "INPUT_GITHUB_TOKEN",
        "PROVEBREAK_LICENSE_KEY",
        "NODE_AUTH_TOKEN",
        "NPM_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS",
        # Credential / agent surfaces (self-hosted runner residual risk)
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
        "NETRC",
        "CURL_HOME",
        "GIT_CREDENTIAL_HELPER",
        "GH_ENTERPRISE_TOKEN",
        "GH_HOST",
    }
)
_ENV_DENY_PREFIX = (
    "ACTIONS_",
    "AWS_",
    "AZURE_",
    "GCLOUD_",
    "GOOGLE_",
    "NPM_CONFIG_",
)
_ENV_DENY_SUBSTR = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "PRIVATE_KEY",
    "API_KEY",
    "ACCESS_KEY",
    "AUTH_KEY",
    "BEARER",
    "LICENSE",
)


def _env_key_denied(key: str) -> bool:
    k = key.upper()
    if k in _ENV_DENY_EXACT or key in _ENV_DENY_EXACT:
        return True
    if any(k.startswith(p) for p in _ENV_DENY_PREFIX):
        return True
    if any(s in k for s in _ENV_DENY_SUBSTR):
        return True
    return False


# Job-env names that execute code or redirect imports when Python starts.
# The PYTHON* allow prefix would otherwise copy them into historical tests.
# bisect_env already refuses the same names. PYTHONDONTWRITEBYTECODE is not
# here: this process sets it itself after the allowlist.
_PYTHON_INJECTION_EXACT = frozenset(
    {
        "PYTHONSTARTUP",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONUSERBASE",
        "PYTHONUSERSITE",
        "PYTHONBREAKPOINT",
        "PYTHONINSPECT",
        "PYTHONEXECUTABLE",
        "PYTHONPLATLIBDIR",
    }
)


def _python_injection_key(key: str) -> bool:
    return key.upper() in _PYTHON_INJECTION_EXACT


def _env_key_allowed(key: str) -> bool:
    if _env_key_denied(key) or _python_injection_key(key):
        return False
    if key in _ENV_ALLOW_EXACT:
        return True
    return any(key.startswith(p) or key.upper().startswith(p) for p in _ENV_ALLOW_PREFIX)


def build_scrubbed_env(
    base: dict[str, str] | None = None,
    *,
    extra: dict[str, str] | None = None,
    home: str | None = None,
) -> dict[str, str]:
    """Minimal env for subprocesses on untrusted historical checkouts.

    Allowlists PATH/LANG/PYTHON*/PYTEST*/CI-ish vars. Strips every
    *TOKEN* / *SECRET* / *PASSWORD* / *LICENSE* / API_KEY, ACTIONS_*,
    GITHUB_TOKEN, PROVEBREAK_LICENSE_KEY, GIT_ASKPASS, SSH_AUTH_SOCK,
    NETRC, and cloud credential vars — including keys present only in
    ``extra``. Also strips Python startup hooks (``PYTHONSTARTUP``,
    ``PYTHONPATH``, ``PYTHONHOME``, ``PYTHONBREAKPOINT``, and the other
    names in ``_PYTHON_INJECTION_EXACT``) so a job env cannot inject code.
    ``PYTHONNOUSERSITE`` and ``PYTHONSAFEPATH`` are forced on.

    ``HOME`` is NEVER inherited from the parent. Pass ``home=`` for an
    isolated sandbox directory (pytest children), or a throwaway path for
    our own git plumbing.
    """
    src = dict(base if base is not None else os.environ)
    out: dict[str, str] = {}
    for k, v in src.items():
        if v is None:
            continue
        if k.upper() == "HOME" or k.upper().startswith("XDG_"):
            continue  # never inherit real HOME / XDG dirs
        if _env_key_allowed(k):
            out[k] = str(v)
    if extra:
        for k, v in extra.items():
            if v is None:
                continue
            if _env_key_denied(k) or _python_injection_key(k):
                continue  # never inject secrets or Python startup hooks via overlay
            if k.upper() == "HOME" or k.upper().startswith("XDG_"):
                continue  # caller must use home= for sandbox
            # Non-secret overlays (e.g. HELDOUT_BREAK) are permitted for harnesses
            out[k] = str(v)
    # Essential defaults — HOME is always explicit, never parent
    out.setdefault("PATH", os.environ.get("PATH", "/usr/bin:/bin"))
    out["HOME"] = home if home else "/tmp"
    out.setdefault("LANG", os.environ.get("LANG", "C.UTF-8"))
    out.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    # Do not load a user site or a job-supplied startup file. The runner adds
    # the worktree to PYTHONPATH after this returns.
    for drop in _PYTHON_INJECTION_EXACT:
        out.pop(drop, None)
    out["PYTHONNOUSERSITE"] = "1"
    out["PYTHONSAFEPATH"] = "1"
    # Make git unable to use parent credential helpers / prompts / askpass
    out["GIT_TERMINAL_PROMPT"] = "0"
    out["GIT_CONFIG_GLOBAL"] = os.devnull
    out["GIT_CONFIG_SYSTEM"] = os.devnull
    out["GIT_CONFIG_NOSYSTEM"] = "1"
    # Explicitly clear agent / askpass even if somehow allowlisted later
    for drop in (
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
        "NETRC",
        "CURL_HOME",
        "GIT_CREDENTIAL_HELPER",
    ):
        out.pop(drop, None)
    return out


# --- bisect_env: explicit, name-only passthrough of job env into test runs (NB2) ------------
_BISECT_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
# Names ProveBreak itself controls (or that change how interpreters / git / the runner behave).
_BISECT_ENV_RESERVED_EXACT = frozenset({
    "PATH", "HOME", "SHELL", "USER", "LOGNAME", "PWD", "OLDPWD", "IFS", "ENV", "BASH_ENV",
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONDONTWRITEBYTECODE", "PYTHONSAFEPATH",
    "PYTHONUSERBASE", "PYTHONUSERSITE", "PYTHONBREAKPOINT", "PYTHONINSPECT",
    "PYTHONEXECUTABLE", "PYTHONPLATLIBDIR", "PYTHONNOUSERSITE",
    "NODE_OPTIONS", "NODE_PATH", "GOFLAGS", "GOCACHE", "GOMODCACHE", "GOPATH", "GOTOOLCHAIN",
    "CI", "FORCE_COLOR", "NO_COLOR", "LANG",
})
_BISECT_ENV_RESERVED_PREFIX = ("GITHUB_", "RUNNER_", "ACTIONS_", "GIT_", "XDG_", "SENTINEL_",
                               "PROVEBREAK_", "LD_", "DYLD_", "SSH_", "INPUT_", "STATE_")
MAX_BISECT_ENV = 32


def parse_bisect_env(
    raw: str | Sequence[str] | None, environ: dict[str, str] | None = None
) -> tuple[dict[str, str], list[str], list[tuple[str, str]]]:
    """Resolve the ``bisect_env`` input: a list of variable NAMES (comma / space / newline).

    Returns ``(values, passed_names, refused)`` where ``values`` maps each accepted name
    to its value from the job env (``environ``, default ``os.environ``), and ``refused``
    lists ``(name, why)``. Values are never returned in ``refused`` and must never be
    printed. Secret-looking names (``*TOKEN*``, ``*SECRET*``, ``*PASSWORD*`` …) are refused:
    the bisect job runs untrusted historical code and must hold no secrets.
    """
    env = dict(os.environ if environ is None else environ)
    if raw is None:
        return {}, [], []
    names = raw if isinstance(raw, (list, tuple)) else re.split(r"[\s,]+", str(raw))
    values: dict[str, str] = {}
    passed: list[str] = []
    refused: list[tuple[str, str]] = []
    # MSBuild hook names are reserved in any case. The property bag is case-insensitive.
    from provebreak_culprit._engine.machine_preflight import _msbuild_env_hook

    for n in names:
        n = str(n).strip()
        if not n or n in passed or any(r[0] == n for r in refused):
            continue
        if not _BISECT_ENV_NAME.match(n):
            refused.append((n[:40], "not_a_variable_name"))
            continue
        up = n.upper()
        if (
            up in _BISECT_ENV_RESERVED_EXACT
            or up.startswith(_BISECT_ENV_RESERVED_PREFIX)
            or _msbuild_env_hook(n)
        ):
            refused.append((n, "reserved_name"))
            continue
        if _env_key_denied(n):
            refused.append((n, "secret_looking_name"))
            continue
        if len(passed) >= MAX_BISECT_ENV:
            refused.append((n, "too_many_names"))
            continue
        if n not in env:
            refused.append((n, "not_set_in_job_env"))
            continue
        values[n] = str(env[n])
        passed.append(n)
    return values, passed, refused


# Names the Actions runner injects, plus the public-repo license key. Unset from
# this process before historical tests start so a child cannot read them from
# /proc/<pid>/environ of the bisect process. The shell that launches bisect
# must unset the same names; this covers the Python process itself.
_JOB_SECRET_EXACT = frozenset(
    {
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "SENTINEL_TOKEN",
        "INPUT_GITHUB_TOKEN",
        "PROVEBREAK_LICENSE_KEY",
        # Present when the job has id-token: write. A test must not mint an OIDC token.
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
    }
)


def drop_job_secrets(environ: dict[str, str] | None = None) -> list[str]:
    """Remove job credentials from ``environ`` (default: this process).

    Returns the names removed. Values are never returned and must not be printed.
    """
    env = os.environ if environ is None else environ
    removed: list[str] = []
    for key in list(env):
        up = key.upper()
        if up in _JOB_SECRET_EXACT or "LICENSE_KEY" in up:
            env.pop(key, None)
            removed.append(key)
    return removed


def _writable_site_dirs(python: str) -> list[Path]:
    """Writable site-packages for this interpreter. Never the stdlib, never usersite."""
    code = (
        "import json, os, site\n"
        "dirs = []\n"
        "for p in site.getsitepackages():\n"
        "    if not p or not os.path.isdir(p) or not os.access(p, os.W_OK):\n"
        "        continue\n"
        "    if 'site-packages' in p or 'dist-packages' in p:\n"
        "        dirs.append(p)\n"
        "print(json.dumps(dirs))\n"
    )
    try:
        r = subprocess.run(
            [python, "-c", code],
            capture_output=True, text=True, timeout=30, env=build_scrubbed_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if r.returncode != 0:
        return []
    import json

    try:
        raw = json.loads(r.stdout or "[]")
    except json.JSONDecodeError:
        return []
    return [Path(p) for p in raw if isinstance(p, str)]


def _restore_tree(src: Path, dst: Path) -> None:
    """Make dst match src, including deletions of files a test planted."""
    import shutil

    rsync = shutil.which("rsync")
    if rsync:
        # -I: size and mtime are not enough. A test can rewrite a file to the
        # same length inside the same timestamp granule. Without -I, rsync
        # leaves that edit in place and --delete only removes new files.
        subprocess.run(
            [rsync, "-aI", "--delete", str(src) + "/", str(dst) + "/"],
            capture_output=True, timeout=180,
        )
        return
    for child in list(dst.iterdir()):
        if child.is_symlink() or not child.is_dir():
            child.unlink()
        else:
            shutil.rmtree(child, ignore_errors=True)
    for child in src.iterdir():
        target = dst / child.name
        if child.is_dir() and not child.is_symlink():
            shutil.copytree(child, target, symlinks=True)
        else:
            shutil.copy2(child, target, follow_symlinks=False)


def _site_lock_path(python: str) -> Path:
    """One lock file per interpreter, so parallel bisects share a venv safely."""
    import hashlib
    import tempfile

    digest = hashlib.sha256(str(python).encode()).hexdigest()[:16]
    root = Path(tempfile.gettempdir()) / "sentinel-site-locks"
    root.mkdir(parents=True, exist_ok=True)
    return root / digest


class _SiteGuard:
    """Snapshot writable site-packages once, restore them after every evaluation.

    A test can write the first SHA it sees into site-packages. The tip is
    evaluated first, so that file stays red only on the tip and green on every
    later commit. Restoring the tree between evaluations removes the plant.

    Restore uses ``rsync --delete``. Two evaluations of the same interpreter
    must not overlap that delete, or one of them loses ``pytest`` mid-import
    and abstains. ``hold`` / ``release`` take an exclusive lock for the whole
    evaluation, including the snapshot.
    """

    def __init__(self) -> None:
        self.ready = False
        self.root: Path | None = None
        self.dirs: list[Path] = []
        self._lock_fh = None

    def hold(self, python: str) -> None:
        """Block until this interpreter's site-packages are not being restored.

        The wait is another evaluation's test. It is credited back to this
        scenario's bisect budget so two workers sharing one interpreter do
        not turn a fit-in-budget bisect into an early abstain.
        """
        import fcntl

        if self._lock_fh is not None:
            return
        fh = open(_site_lock_path(python), "a+")
        waited_from = time.monotonic()
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        note_budget_credit(time.monotonic() - waited_from)
        self._lock_fh = fh

    def release(self) -> None:
        import fcntl

        fh = self._lock_fh
        self._lock_fh = None
        if fh is None:
            return
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        finally:
            fh.close()

    def ensure(self, python: str) -> None:
        if self.ready:
            return
        self.ready = True
        import shutil
        import tempfile

        self.dirs = _writable_site_dirs(python)
        if not self.dirs:
            return
        self.root = Path(tempfile.mkdtemp(prefix="sentinel-site-"))
        for i, directory in enumerate(self.dirs):
            shutil.copytree(directory, self.root / str(i), symlinks=True)

    def restore(self) -> None:
        if self.root is None:
            return
        for i, directory in enumerate(self.dirs):
            src = self.root / str(i)
            if src.is_dir() and directory.is_dir():
                try:
                    _restore_tree(src, directory)
                except (OSError, subprocess.TimeoutExpired):
                    pass

    def close(self) -> None:
        import shutil

        self.release()
        if self.root is not None and self.root.exists():
            shutil.rmtree(self.root, ignore_errors=True)
        self.root = None
        self.dirs = []


def make_isolated_home(prefix: str = "sentinel-bisect-home-") -> Path:
    """Fresh HOME with empty XDG_* dirs for one pytest evaluation."""
    import tempfile

    root = Path(tempfile.mkdtemp(prefix=prefix))
    for name in ("xdg-config", "xdg-cache", "xdg-data", "xdg-state", ".ssh", ".config"):
        (root / name).mkdir(parents=True, exist_ok=True)
    return root


def apply_isolated_home(env: dict[str, str], home: Path) -> dict[str, str]:
    """Point HOME + XDG_* at an isolated sandbox (mutates and returns env)."""
    home = Path(home)
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / "xdg-config")
    env["XDG_CACHE_HOME"] = str(home / "xdg-cache")
    env["XDG_DATA_HOME"] = str(home / "xdg-data")
    env["XDG_STATE_HOME"] = str(home / "xdg-state")
    return env



# Time a worker spent blocked on another evaluation's site-packages lock.
# That wait is the other scenario's test, so it is added back when measuring
# this scenario's budget. Uncontended locks are not recorded.
_budget_credit_sec = 0.0
_BUDGET_CREDIT_MIN_SEC = 0.05


def budget_credit() -> float:
    return _budget_credit_sec


def note_budget_credit(seconds: float) -> None:
    global _budget_credit_sec
    if seconds >= _BUDGET_CREDIT_MIN_SEC:
        _budget_credit_sec += seconds


def reset_budget_credit() -> None:
    """Drop credit from an earlier scenario in this process.

    A lab worker runs several scenarios in one process. Credit is only the
    waits inside the scenario whose deadline is open.
    """
    global _budget_credit_sec
    _budget_credit_sec = 0.0


def remaining_budget(deadline: float | None) -> float:
    if deadline is None:
        return float("inf")
    return deadline + _budget_credit_sec - time.monotonic()


def charged_seconds(started: float, credit_at_start: float) -> float:
    """Seconds of this scenario's own work since ``started``.

    Waiting for another evaluation to finish with the shared site-packages
    tree is not charged.
    """
    waited = budget_credit() - credit_at_start
    return max(0.0, time.monotonic() - started - waited)


def _host_mirror_dir() -> Path:
    """A directory outside /tmp where this user can keep a bind-mount mirror.

    Uses the passwd home, not $HOME. Tests point $HOME at a folder under /tmp,
    and that must not become the mirror (the mirror has to outlive the private /tmp).
    """
    import pwd

    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    cand = home / ".cache" / "sentinel-tmp-mirrors"
    cand.mkdir(parents=True, exist_ok=True)
    return cand


def _materialize_tmp_path(raw: str) -> Path | None:
    """Follow directory symlinks that stay under /tmp. Do not follow a file symlink out.

    ``/tmp/pyhunt`` -> a real venv must be mounted at the real directory, or
    ``mount --bind`` exits 98. ``venv/bin/python`` -> ``/usr/bin/python3`` must
    NOT be resolved: that path leaves /tmp, the venv drops out of the bind
    list, and the private /tmp then hides the interpreter.
    """
    path = Path(raw)
    try:
        resolved = path.resolve()
    except OSError:
        return path
    if str(resolved).startswith("/tmp/"):
        return resolved
    # The final component is a symlink to something outside /tmp (the venv
    # interpreter). Keep the directory that holds that symlink, and follow
    # directory symlinks in that directory.
    holder = path if path.is_dir() else path.parent
    try:
        holder_resolved = holder.resolve()
    except OSError:
        return holder
    if str(holder_resolved).startswith("/tmp/"):
        return holder_resolved
    return None


def _bind_root_for(raw: str) -> Path | None:
    """Directory under /tmp that must stay visible for this path, or None.

    A virtualenv is bound at its root so ``bin/python`` can see ``lib/``.
    The bind stops at that root (or at the path itself). It does not widen to
    ``/tmp/<one-component>``, so a venv at ``/tmp/work/venv`` does not reveal
    ``/tmp/work/poison`` or ``/tmp/other-flag``.
    """
    if not raw.startswith("/tmp/"):
        return None
    path = _materialize_tmp_path(raw)
    if path is None or not str(path).startswith("/tmp/"):
        return None
    cursor = path if path.is_dir() else path.parent
    if cursor == Path("/tmp"):
        return None
    probe = cursor
    while str(probe).startswith("/tmp/") and probe != Path("/tmp"):
        # The checkout root, so a package subdirectory can still see node_modules.
        if (probe / ".git").exists():
            return probe
        if (probe / "pyvenv.cfg").is_file():
            return probe
        if probe.parent == Path("/tmp"):
            break
        probe = probe.parent
    while cursor != Path("/tmp") and not cursor.exists():
        cursor = cursor.parent
    if cursor == Path("/tmp") or not cursor.is_dir():
        return None
    return cursor


def _tmp_bind_dirs(
    env: dict[str, str] | None,
    cwd: str | Path | None,
    cmd: Sequence[str] | None = None,
) -> list[str]:
    """Host directories under /tmp that the child must still see.

    Everything else under /tmp, /var/tmp, and /dev/shm is a fresh tmpfs, so a
    test cannot leave a flag that the next commit's run will observe.
    """
    raws: list[str] = []
    for value in (env or {}).values():
        if isinstance(value, str):
            raws.append(value)
    if cwd is not None:
        raws.append(str(cwd))
    for arg in cmd or ():
        if isinstance(arg, str) and arg.startswith("/tmp/"):
            raws.append(arg)
    found: list[str] = []
    for raw in raws:
        candidate = _bind_root_for(raw)
        if candidate is None:
            continue
        text = str(candidate)
        if text not in found:
            found.append(text)
    return found


_PRIVATE_TMP_SCRIPT = r"""
mirror="$SENTINEL_HOST_TMP"
binds="$SENTINEL_TMP_BINDS"
unset SENTINEL_HOST_TMP SENTINEL_TMP_BINDS
mount --bind /tmp "$mirror" || exit 97
mount -t tmpfs -o mode=1777 tmpfs /tmp || exit 97
mount -t tmpfs -o mode=1777 tmpfs /var/tmp || true
if [ -d /dev/shm ]; then mount -t tmpfs -o mode=1777 tmpfs /dev/shm || true; fi
printf '%s\n' "$binds" | while IFS= read -r p; do
  [ -n "$p" ] || continue
  rel="${p#/tmp/}"
  mkdir -p "/tmp/$rel"
  mount --bind "$mirror/$rel" "/tmp/$rel" || exit 98
done
exec "$@"
"""


_private_tmp_ok: bool | None = None


def _private_tmp_setup_failed(rc: int, stderr: str) -> bool:
    """True when the private-/tmp wrapper died during its own mounts.

    Exit 97 is the initial bind or tmpfs. Exit 98 is a bind of a path the
    child needs (often a symlink). That text must not be scored as the test.
    """
    if rc in (97, 98):
        return True
    text = stderr or ""
    if "mount:" in text and ("special device" in text or "No such file" in text):
        return True
    # The wrapper replaced /tmp and then bash could not exec the command.
    # That is a setup failure, not the test's own result.
    return "sentinel-run:" in text and "No such file or directory" in text


def _unshare_rejected(stderr: str) -> bool:
    """True when the unshare binary exists but user namespaces are blocked.

    GitHub-hosted runners return ``unshare: write failed /proc/self/uid_map:
    Operation not permitted``. That must not be reported as the test result.
    """
    text = stderr or ""
    if "uid_map" in text or "gid_map" in text:
        return True
    return "unshare:" in text and "Operation not permitted" in text


def private_tmp_available() -> bool:
    """Whether ``unshare --user --mount --map-root-user`` actually works.

    The binary being on ``PATH`` is not enough. A failed probe is cached so
    later test runs do not keep paying for a wrapper that cannot start.
    """
    global _private_tmp_ok
    if _private_tmp_ok is not None:
        return _private_tmp_ok
    if os.environ.get("SENTINEL_SHARE_TMP") == "1":
        _private_tmp_ok = False
        return False
    import shutil

    if shutil.which("unshare") is None or shutil.which("bash") is None:
        _private_tmp_ok = False
        return False
    try:
        probe = subprocess.run(
            ["unshare", "--user", "--mount", "--map-root-user", "true"],
            capture_output=True,
            text=True,
            timeout=8,
        )
        _private_tmp_ok = probe.returncode == 0 and not _unshare_rejected(probe.stderr or "")
    except (OSError, subprocess.TimeoutExpired):
        _private_tmp_ok = False
    return bool(_private_tmp_ok)


def _disable_private_tmp() -> None:
    global _private_tmp_ok
    _private_tmp_ok = False


def _private_tmp_argv(cmd: list[str], env: dict[str, str], cwd: str | Path | None) -> tuple[list[str], dict[str, str]]:
    """Wrap cmd so it sees a fresh /tmp. No-op when user namespaces do not work."""
    import shutil
    import tempfile

    if os.environ.get("SENTINEL_SHARE_TMP") == "1":
        return cmd, env
    if not private_tmp_available():
        return cmd, env
    if shutil.which("bash") is None:
        return cmd, env
    try:
        mirror = Path(tempfile.mkdtemp(prefix="m-", dir=str(_host_mirror_dir())))
    except OSError:
        return cmd, env
    child_env = dict(env)
    child_env["SENTINEL_HOST_TMP"] = str(mirror)
    child_env["SENTINEL_TMP_BINDS"] = "\n".join(_tmp_bind_dirs(env, cwd, cmd))
    wrapped = [
        "unshare", "--user", "--mount", "--map-root-user",
        "bash", "-c", _PRIVATE_TMP_SCRIPT, "sentinel-run",
        *cmd,
    ]
    return wrapped, child_env


def run_capped(
    cmd: list[str],
    *,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float,
) -> tuple[int, str, str]:
    """Run a subprocess with a hard timeout; kill the whole process group on expiry.

    The command runs with a private /tmp, /var/tmp, and /dev/shm. Directories the
    parent already handed the child (HOME, a report path, the worktree when it
    lives under /tmp) are bind-mounted back. A flag planted at an absolute /tmp
    path does not survive into the next run.
    """
    import shutil

    timeout = max(0.05, float(timeout))
    base_env = dict(os.environ if env is None else env)
    argv, child_env = _private_tmp_argv(cmd, base_env, cwd)
    wrapped = argv is not cmd

    def _spawn(argv_now: list[str], env_now: dict[str, str]) -> tuple[int, str, str]:
        mirror_now = env_now.get("SENTINEL_HOST_TMP") if argv_now is not cmd else None
        proc = subprocess.Popen(
            argv_now,
            cwd=str(cwd) if cwd else None,
            env=env_now,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            try:
                out, err = proc.communicate(timeout=timeout)
                return int(proc.returncode or 0), out or "", err or ""
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    try:
                        proc.kill()
                    except (ProcessLookupError, OSError):
                        pass
                try:
                    out, err = proc.communicate(timeout=5)
                except Exception:  # noqa: BLE001
                    out, err = "", ""
                raise subprocess.TimeoutExpired(cmd, timeout, output=out, stderr=err)
        finally:
            if mirror_now:
                shutil.rmtree(mirror_now, ignore_errors=True)

    rc, out, err = _spawn(argv, child_env)
    if wrapped and rc != 0 and (_unshare_rejected(err) or _private_tmp_setup_failed(rc, err)):
        # The probe can pass in one environment and fail on a hosted runner.
        # Drop the wrapper and run the real command instead of blaming unshare.
        _disable_private_tmp()
        bare = {k: v for k, v in child_env.items() if k not in ("SENTINEL_HOST_TMP", "SENTINEL_TMP_BINDS")}
        return _spawn(cmd, bare)
    return rc, out, err


def estimate_bisect_evals(n_commits: int) -> int:
    """Approx *search* evals after tip+base: tip-parent/search steps (1 run each)."""
    n = max(1, int(n_commits))
    search = max(1, math.ceil(math.log2(n))) if n > 1 else 1
    # tip-parent check + binary search window
    return 1 + search


def confirmation_fresh_runs(confirm_reruns: int) -> int:
    """Fresh confirmation runs per boundary side after one clean search hit.

    The search evaluates the parent and the culprit once before confirmation.
    Those runs count toward ``confirm_reruns``. A 1-run confirmation is
    unchanged, so a proof is never the search probe by itself.
    """
    n = int(confirm_reruns)
    if n <= 1:
        return n
    # One search hit counts, but the fresh batch stays at least 2 runs.
    # A worktree is cleaned between evaluations, so a flake that shows up
    # only inside one multi-run evaluate (a marker file, for example) is
    # invisible if confirmation is a single run. Do not shrink that batch to 1.
    return max(2, n - 1)


def estimate_remaining_seconds(
    *,
    n_commits: int,
    tip_elapsed: float,
    base_elapsed: float,
    confirm_reruns: int,
) -> tuple[float, str]:
    """Split cost: 1-run search steps vs fresh confirmation runs.

    Confirmation does not repeat the search's look at the boundary. A 90s
    test over 20 commits used to be charged 6 search runs plus 3 tip and 3
    parent runs (~1082s) after tip and base had already left ~1020s. Charging
    2 fresh runs per side fits that case in the 1200s budget.
    """
    search_steps = estimate_bisect_evals(n_commits)
    fresh = confirmation_fresh_runs(confirm_reruns)
    # Green/base-like steps are usually much cheaper than a slow failing tip
    search_unit = max(0.05, min(float(base_elapsed), float(tip_elapsed)))
    parent_unit = max(0.05, float(base_elapsed))
    # Parent confirm ~ base cost; culprit confirm ~ tip cost
    confirm_cost = fresh * float(tip_elapsed) + fresh * parent_unit
    search_cost = search_steps * search_unit
    total = search_cost + confirm_cost
    detail = (
        f"~{search_steps} search×{search_unit:.2f}s + "
        f"{fresh}×tip({tip_elapsed:.2f}s) + {fresh}×parent({parent_unit:.2f}s) "
        f"≈ {total:.1f}s"
    )
    return total, detail


# --- node id validation ------------------------------------------------------

# Path portion (before .py::): ASCII-ish path segments only — no spaces/brackets.
_NODE_ID_PATH = re.compile(r"^[\w./\-]+\.py$")


def _node_id_rest_ok(rest: str) -> str | None:
    """Validate pytest node id after ``.py::``.

    Allows nested parametrize brackets, spaces, and unicode in names/ids.
    Still blocks option-like segments (leading ``-``) and unbalanced brackets.
    Callers pass ids as an argv list after ``--`` (no shell).
    """
    if not rest:
        return "node_id_empty_name"
    if rest.startswith("-"):
        return "node_id_looks_like_pytest_option"
    # No ASCII controls / NULs (newlines would also break log parsing)
    if any(ord(c) < 32 for c in rest):
        return "node_id_control_chars"
    depth = 0
    max_depth = 0
    for c in rest:
        if c == "[":
            depth += 1
            max_depth = max(max_depth, depth)
            if depth > 8:
                return "node_id_brackets_too_deep"
        elif c == "]":
            depth -= 1
            if depth < 0:
                return "node_id_unbalanced_brackets"
    if depth != 0:
        return "node_id_unbalanced_brackets"
    # Every :: segment must look like a name, not a CLI flag
    for seg in rest.split("::"):
        if not seg:
            return "node_id_empty_segment"
        if seg.startswith("-"):
            return "node_id_looks_like_pytest_option"
    return None


def validate_node_ids(tests: Sequence[str]) -> tuple[list[str], str | None]:
    """Return (clean_ids, error_reason). error_reason set => refuse bisect."""
    if not tests:
        return [], "no_failing_tests_provided"
    clean: list[str] = []
    for raw in tests:
        t = str(raw).strip()
        if not t:
            continue
        if len(t) > MAX_NODE_ID_LEN:
            return [], f"node_id_too_long:{t[:40]}"
        if t.startswith("-"):
            return [], f"node_id_looks_like_pytest_option:{t[:40]}"
        if ".." in t.replace("::", ""):
            return [], f"node_id_path_traversal:{t[:40]}"
        if ".py::" not in t:
            return [], f"node_id_must_contain_py_and_colons:{t[:40]}"
        path_part, _, rest = t.partition(".py::")
        path = path_part + ".py"
        if not _NODE_ID_PATH.match(path):
            return [], f"node_id_bad_path:{path[:40]}"
        why = _node_id_rest_ok(rest)
        if why:
            return [], f"{why}:{t[:40]}"
        clean.append(t)
    if not clean:
        return [], "no_failing_tests_provided"
    return clean, None


# Fixed card strings (5.2.0). ``outside_cause`` now only means "git lists no commit between
# last green and the red commit"; a red last-green is ``inconclusive_env``.
INCONCLUSIVE_ENV_REASON = "last_green_also_fails"
INCONCLUSIVE_ENV_LINE = (
    "Not proven: inconclusive (environment) — the last green commit also fails here, likely environment "
    "(the bisect job's env differs from CI: pass needed variables with bisect_env, add services)"
)
# Parent does not contain the test, the tip fails an assertion, and the same
# commit also changes a non-test file (product code or a golden/fixture).
ADDED_ASSERTION_REASON = "added_test_fails_assertion"


def proven_line(
    short: str,
    tests: str,
    reproductions,
    attempts,
    *,
    parent_short: str = "",
    added_assertion: bool = False,
) -> str:
    """One-line proven wording. The added-assertion form does not say the parent passed."""
    k = reproductions or 0
    n = attempts or k
    if added_assertion:
        parent = parent_short or "unknown"
        return (
            f"Proven culprit: {short} (this commit added {tests}, which fails an assertion "
            f"in files this commit also changed; the test was not present on parent {parent}; "
            f"reproduced {k}/{n})"
        )
    return (
        f"Proven culprit: {short} (failing test {tests} passes on parent, "
        f"fails on this commit, reproduced {k}/{n} times)"
    )


_COMPILER_FILE = re.compile(r"((?:[\w.+-]+/)*[\w.+-]+\.go:\d+)")
_SETUP_QUOTE = re.compile(
    r"(relation \"[A-Za-z0-9_]+\" does not exist"
    r"|pq: [A-Za-z0-9_ \"'.:-]{1,120}"
    r"|no such table: [A-Za-z0-9_]+"
    r"|dial tcp[^\n|]{0,80}"
    r"|connection refused"
    r"|No module named '(?:_black_version|_version|[A-Za-z0-9_.]+)'"
    r"|ModuleNotFoundError: No module named '(?:_black_version|_version|[A-Za-z0-9_.]+)'"
    r"|Failed to import filter module '[A-Za-z0-9_.]+'"
    r"|PytestConfigWarning: [^\n|]{0,140})"
)
_VERSION_MODULE = re.compile(r"No module named '(_black_version|_version|[\w.]*_version)'")
_PYTEST_INTERNAL_IMPORT = re.compile(
    r"apply_warning_filters|filterwarnings|_pytest/(?:config|warning)",
    re.I,
)


def compiler_location(text: str | None) -> str:
    """A ``file.go:line`` token, or ''."""
    m = _COMPILER_FILE.search(text or "")
    if not m:
        return ""
    loc = m.group(1)
    if len(loc) > 120 or ".." in loc.split("/"):
        return ""
    return loc


def setup_error_quote(*texts: str | None) -> str:
    """A short shared setup/SQL/import error, or ''. Never returns arbitrary log text."""
    blob = "\n".join(t or "" for t in texts)
    m = _SETUP_QUOTE.search(blob)
    if not m:
        return ""
    quote = " ".join(m.group(1).split())
    return quote[:160]


def other_os_sentence(card: dict | None) -> str:
    """Say when every failed CI job is Windows or macOS.

    ``ci_linux_was_green`` is set by the sweep when a Linux job on the same run
    succeeded. Without that flag the sentence does not claim Linux was green.
    """
    if not isinstance(card, dict):
        return ""
    jobs = [j for j in (card.get("failed_jobs") or []) if isinstance(j, dict)]
    found: set[str] = set()
    for job in jobs:
        blob = f"{job.get('name') or ''} {job.get('os') or ''}"
        if re.search(r"windows|win-", blob, re.I):
            found.add("Windows")
        elif re.search(r"macos|darwin|mac-", blob, re.I):
            found.add("macOS")
        elif re.search(r"ubuntu|linux", blob, re.I):
            found.add("Linux")
    if not found or "Linux" in found or not found <= {"Windows", "macOS"}:
        explicit = str(card.get("ci_os_only") or "").lower()
        if explicit in ("windows", "macos", "darwin"):
            found = {"Windows" if explicit == "windows" else "macOS"}
        else:
            return ""
    which = " and ".join(sorted(found))
    if card.get("ci_linux_was_green") is True:
        return f"CI was red only on {which}; a Linux job on that run succeeded."
    return f"CI was red only on {which}. This bisect ran on Linux."


def _test_source_path(path: str) -> bool:
    base = path.rsplit("/", 1)[-1]
    if base.endswith("_test.go") or base.endswith("_test.py"):
        return True
    if re.search(r"\.(?:test|spec)\.[cm]?[jt]sx?$", base):
        return True
    return False


def _id_matches_path(tests: Sequence[str], path: str) -> bool:
    """True when ``path`` is the test file, or sits in the Go package the id names."""
    norm = path.replace("\\", "/")
    for raw in tests:
        t = str(raw or "")
        if ".py::" in t or t.endswith(".py"):
            file = t.split("::", 1)[0]
            if norm == file or norm.endswith("/" + file):
                return True
        if " > " in t:
            file = t.split(" > ", 1)[0].strip()
            if norm == file or norm.endswith("/" + file):
                return True
        if "::" in t:
            pkg = t.split("::", 1)[0]
            rel = pkg[2:] if pkg.startswith("./") else ""
            if rel and (norm == rel or norm.startswith(rel.rstrip("/") + "/")):
                return True
    return False


def _commit_name_status(repo: Path, sha: str) -> list[tuple[str, str]]:
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "diff-tree", "--no-commit-id", "--name-status",
             "-r", "-m", "--first-parent", sha],
            capture_output=True, text=True, timeout=20, env=build_scrubbed_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if r.returncode != 0:
        return []
    rows: list[tuple[str, str]] = []
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0] and parts[-1]:
            rows.append((parts[0][:1], parts[-1].replace("\\", "/")))
    return rows


def _shared_setup_reason(*details: str | None) -> str:
    """``last_green_also_fails`` plus a safe quote of the shared setup error."""
    quote = setup_error_quote(*details)
    reason = INCONCLUSIVE_ENV_REASON
    if quote:
        reason = f"{reason}: {quote}"
    if quote and 'relation "' in quote and os.environ.get("CODER_PG_CONNECTION_URL"):
        reason += (
            " Coder tests migrate a private database only when CODER_PG_CONNECTION_URL is unset;"
            " this job set it."
        )
    return reason


def _new_test_kwargs(
    repo: Path, culprit: str, parent: str, tests: Sequence[str], cul_er: EvalResult, parent_kind: str,
) -> dict:
    """Missing on the parent. Proven only when this commit added the test and it fails an assertion in other files."""
    shown = ", ".join(list(tests)[:3]) or "unknown test"
    common = dict(
        culprit_sha=culprit,
        parent_sha=parent,
        reproductions=cul_er.fails,
        reproduction_attempts=cul_er.runs,
    )
    if added_test_fails_assertion(repo, culprit, tests, cul_er):
        return {
            **common,
            "status": "proven",
            "evidence": (
                f"commit {culprit[:12]} added {shown}, which fails an assertion in files this commit "
                f"also changed; the test was not present on parent {parent[:12]} "
                f"({cul_er.fails}/{cul_er.runs})"
            ),
            "reason": (
                f"{ADDED_ASSERTION_REASON}: parent {parent[:12]} {parent_kind}; "
                "tip fails an assertion in files this commit also changed"
            ),
        }
    return {
        **common,
        "status": "introduced_failing_test",
        "evidence": (
            f"failing test {shown} does not collect on parent "
            f"{parent[:12]} ({parent_kind}) but fails on {culprit[:12]} "
            f"({cul_er.fails}/{cul_er.runs})"
        ),
        "reason": (
            f"test_introduced_already_failing: parent {parent[:12]} "
            f"{parent_kind}; culprit red"
        ),
    }


def added_test_fails_assertion(repo: Path, sha: str, tests: Sequence[str], er: EvalResult) -> bool:
    """Helm-style proof: the test was added here and fails an assertion in other files this commit changed.

    A test file with no non-test diff stays "already failing". No git evidence means no promotion.
    """
    if not _failure_is_assertion(er):
        return False
    rows = _commit_name_status(repo, sha)
    if not rows:
        return False
    test_hit = False
    other = False
    for status, path in rows:
        # Added or renamed onto this path, or an existing file that gains the
        # test name (Helm adds subtests inside chart_test.go). A modified test
        # file that does not introduce the name is not "this commit added it".
        if _test_source_path(path) and _id_matches_path(tests, path) and status in ("A", "R", "M"):
            if status in ("A", "R") or _diff_adds_test_name(repo, sha, path, tests):
                test_hit = True
        elif not _test_source_path(path) and status != "D":
            other = True
    return test_hit and other


def _test_leaf_names(tests: Sequence[str]) -> list[str]:
    """Last identifier of each id, long enough that a diff line can name it."""
    found: list[str] = []
    for raw in tests:
        leaf = str(raw or "").replace("\\", "/").split("::")[-1]
        leaf = leaf.split(">")[-1].split("/")[-1].split("[")[0].strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{5,80}", leaf) and leaf not in found:
            found.append(leaf)
    return found


def _diff_adds_test_name(repo: Path, sha: str, path: str, tests: Sequence[str]) -> bool:
    """True when a line added in ``path`` contains the test's own name."""
    needles = _test_leaf_names(tests)
    if not needles:
        return False
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "diff", "-U0", f"{sha}^1", sha, "--", path],
            capture_output=True, text=True, timeout=20, env=build_scrubbed_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if r.returncode != 0:
        return False
    for line in r.stdout.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        if any(name in line[1:] for name in needles):
            return True
    return False


def _failure_is_assertion(er: EvalResult) -> bool:
    if getattr(er, "failure", "") == "assertion":
        return True
    if getattr(er, "label", "") != "red":
        return False
    text = getattr(er, "detail", "") or ""
    if re.search(r"\bpanic:", text, re.I):
        return False
    return bool(re.search(
        r"AssertionError|Not equal|Error Trace:|--- FAIL:|Error:|@@ |golden|\.go:\d+:",
        text,
    ))


_LFS_POINTER = re.compile(
    rb"^version https://git-lfs.github.com/spec/v1\noid sha256:[0-9a-fA-F]+\nsize [0-9]+\n"
)


def _git_text(wt: Path, args: list[str], timeout: float) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            ["git", "-C", str(wt), *args],
            capture_output=True,
            text=True,
            timeout=max(0.5, timeout),
            env=build_scrubbed_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _lfs_pointer_files(wt: Path, timeout: float) -> list[str]:
    """Tracked files that are still Git LFS pointers (smudge did not run)."""
    found_cmd = _git_text(
        wt,
        ["grep", "-I", "-l", "-e", "version https://git-lfs.github.com/spec/v1"],
        timeout,
    )
    if found_cmd is None or found_cmd.returncode not in (0, 1):
        return []
    found: list[str] = []
    for rel in (found_cmd.stdout or "").splitlines():
        rel = rel.strip()
        if not rel or ".." in rel.split("/"):
            continue
        path = wt / rel
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024:
                continue
            blob = path.read_bytes()
        except OSError:
            continue
        if _LFS_POINTER.match(blob):
            found.append(rel)
    return found


def _gitlink_paths(wt: Path, timeout: float) -> list[str]:
    listed = _git_text(wt, ["ls-files", "-s"], timeout)
    if listed is None or listed.returncode != 0:
        return []
    paths: list[str] = []
    for line in (listed.stdout or "").splitlines():
        if not line.startswith("160000 "):
            continue
        rel = line.split("\t", 1)[-1].strip()
        if rel and ".." not in rel.split("/"):
            paths.append(rel)
    return paths


def _submodule_populated(wt: Path, rel: str) -> bool:
    directory = wt / rel
    if not directory.is_dir():
        return False
    try:
        for child in directory.iterdir():
            if child.name != ".git":
                return True
    except OSError:
        return False
    return False


_SUBMODULE_SSH_ORG = re.compile(
    r"(?m)^[ \t]*url[ \t]*=[ \t]*git@github\.com:([A-Za-z0-9_.-]+)/"
)


def use_https_github_submodules(wt: Path) -> None:
    """Fetch ``git@github.com`` submodule URLs over HTTPS.

    Actions checks out with HTTPS. An SSH URL waits for a key that this job
    does not have, and the checkout then times out before any test runs.
    A private submodule still fails; that stays an abstain, not a culprit.

    A local ``insteadOf`` that rewrites every ``git@github.com:`` URL through
    an installation token is the same length as a generic HTTPS rewrite, so
    git does not prefer HTTPS. A per-organization prefix is longer and wins,
    and the submodule is fetched without that token.
    """
    env = build_scrubbed_env()
    text = ""
    try:
        text = (wt / ".gitmodules").read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    pairs = [
        ("url.https://github.com/.insteadOf", "git@github.com:"),
        ("url.https://github.com/.insteadOf", "ssh://git@github.com/"),
    ]
    for org in dict.fromkeys(_SUBMODULE_SSH_ORG.findall(text)):
        pairs.append((f"url.https://github.com/{org}/.insteadOf", f"git@github.com:{org}/"))
        pairs.append((f"url.https://github.com/{org}/.insteadOf", f"ssh://git@github.com/{org}/"))
    for key, src in pairs:
        current = subprocess.run(
            ["git", "-C", str(wt), "config", "--local", "--get-all", key],
            capture_output=True, text=True, timeout=10, env=env,
        )
        if src in set((current.stdout or "").split()):
            continue
        subprocess.run(
            ["git", "-C", str(wt), "config", "--local", "--add", key, src],
            capture_output=True, timeout=10, env=env,
        )


def github_https_submodule_env(base: dict[str, str]) -> dict[str, str]:
    """Env that rewrites GitHub SSH URLs inside ``git submodule``'s child clone.

    ``submodule--helper clone`` runs ``git clone`` with ``GIT_DIR`` pointed at
    the new submodule, so the parent repo's ``insteadOf`` is not visible.
    ``GIT_CONFIG_KEY_*`` is inherited by that child. A private submodule still
    fails closed; that stays an abstain.
    """
    env = dict(base)
    pairs = (
        ("url.https://github.com/.insteadOf", "git@github.com:"),
        ("url.https://github.com/.insteadOf", "ssh://git@github.com/"),
    )
    env["GIT_CONFIG_COUNT"] = str(len(pairs))
    for i, (key, value) in enumerate(pairs):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    return env


def checkout_fidelity(wt: Path, *, timeout: float) -> str | None:
    """Init submodules and smudge Git LFS, or say the checkout is not CI's tree.

    A proof on a pointer file or an empty submodule directory disagrees with a
    job that runs ``git lfs checkout`` or ``submodule update``. When those
    steps cannot be finished, the caller abstains instead of naming a culprit.
    """
    budget = max(1.0, float(timeout))
    links = _gitlink_paths(wt, min(15.0, budget))
    if links:
        try:
            use_https_github_submodules(wt)
            subprocess.run(
                ["git", "-C", str(wt), "submodule", "update", "--init", "--recursive"],
                capture_output=True,
                text=True,
                timeout=budget,
                env=github_https_submodule_env(build_scrubbed_env()),
            )
        except subprocess.TimeoutExpired:
            return "submodule_not_inited:timeout"
        except OSError as exc:
            return f"submodule_not_inited:{type(exc).__name__}"
        missing = [rel for rel in links if not _submodule_populated(wt, rel)]
        if missing:
            return "submodule_not_inited:" + missing[0][:120]
    pointers = _lfs_pointer_files(wt, min(20.0, budget))
    if not pointers:
        return None
    try:
        subprocess.run(
            ["git", "-C", str(wt), "lfs", "checkout"],
            capture_output=True,
            text=True,
            timeout=min(budget, 30.0),
            env=build_scrubbed_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        pass
    still = _lfs_pointer_files(wt, min(15.0, budget))
    if still:
        return "lfs_not_smudged:" + still[0][:120]
    return None


_CLEAN_EXCLUDES = (
    # .pytest_cache is not excluded. A test can plant a flag there, and the
    # next checkout would still see it. Version modules and node_modules stay.
    "node_modules",
    ".sentinel-cache",
    "_black_version.py",
    "**/_black_version.py",
    "**/_version.py",
    "**/*_version.py",
    "*_version.py",
)


def git_clean_worktree(wt: Path, *, timeout: float) -> None:
    """Remove untracked files but keep generated version modules and install trees.

    ``git clean -fdx`` deletes hatch-vcs ``_black_version`` / ``_version`` modules
    that are not in git. The next pytest import then dies before any test runs.
    """
    cmd = ["git", "-C", str(wt), "clean", "-fdx"]
    for pat in _CLEAN_EXCLUDES:
        cmd.extend(["-e", pat])
    subprocess.run(
        cmd, capture_output=True, timeout=max(0.5, timeout), env=build_scrubbed_env(),
    )


def _pytest_assertion(blob: str) -> bool:
    if re.search(r"\bpanic:", blob or "", re.I):
        return False
    return bool(re.search(r"AssertionError|E\s+assert |===+\s+FAILURES\s+===+|FAILED\s+\S+\.py::", blob or ""))


def _pytest_env_crash(blob: str) -> bool:
    """Collection died inside pytest while importing the project, or a generated version module is missing."""
    text = blob or ""
    if _VERSION_MODULE.search(text):
        return True
    if _PYTEST_INTERNAL_IMPORT.search(text) and re.search(
        r"Error|Exception|Warning|ModuleNotFoundError|ImportError", text
    ):
        return True
    return False


def pytest_id_fallbacks(node_id: str) -> list[str]:
    """Narrower node ids to try when the CI id collects nothing.

    Order is fixed. The original id is not included. Parametrize brackets and a
    ``+`` driver suffix (SQLAlchemy's generated class name) are stripped. A
    trailing ``_token`` before ``+`` is dropped once (``AsyncCancellationTest_sqlite``
    → ``AsyncCancellationTest``).
    """
    path, sep, rest = str(node_id).partition("::")
    if not sep or not rest:
        return []
    found: list[str] = []

    def add(item: str) -> None:
        item = item.strip()
        if item and item != node_id and item not in found and "::" in item:
            found.append(item)

    bare = re.sub(r"\[[^\]]*\]", "", rest)
    if bare and bare != rest:
        add(f"{path}::{bare}")
    parts = rest.split("::")
    cls = parts[0]
    plus = cls.find("+")
    bracket = cls.find("[")
    cut = None
    dropped_plus = False
    if plus > 0 and (bracket < 0 or plus < bracket):
        cut = plus
        dropped_plus = True
    elif bracket > 0:
        cut = bracket
    if cut:
        head = cls[:cut].rstrip("_")
        variants = [head]
        # ``Class_sqlite+driver`` → also try ``Class``. A ``[param]`` cut does not.
        if dropped_plus and "_" in head:
            variants.append(head.rsplit("_", 1)[0])
        tail = "::".join(parts[1:])
        tail = re.sub(r"\[[^\]]*\]", "", tail)
        for variant in variants:
            if not variant or variant.startswith("-"):
                continue
            new_rest = variant if not tail else f"{variant}::{tail}"
            add(f"{path}::{new_rest}")
    return found


def pytest_k_token(node_id: str) -> str:
    """Last test function name, or '' when it is not a plain identifier."""
    rest = str(node_id).split("::")[-1]
    name = rest.split("[", 1)[0]
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,120}", name):
        return name
    return ""


# Drivers SQLAlchemy's pytest plugin accepts via ``--dbdriver``. The token is
# taken from a CI class name (``Class_sqlite+aiosqlite_...``), never from
# arbitrary log text.
_SQLA_DB_DRIVERS = frozenset({
    "aiosqlite", "asyncpg", "psycopg", "psycopg2", "pg8000",
    "pymysql", "mysqldb", "aiomysql", "asyncmy", "oracledb",
    "cx_oracle", "pyodbc", "pymssql", "mariadbconnector",
})
# SQLAlchemy's asyncio dialect imports greenlet when the driver connects.
# These names are fixed. They are never taken from a log or a node id.
_ASYNCIO_DRIVERS = frozenset({"aiosqlite", "asyncpg", "aiomysql", "asyncmy"})
# hatch ``version-file``, setuptools-scm ``version_file``, and ``write_to``.
# Indented TOML and either quote style. The path is a relative .py file.
_VERSION_FILE_DECL = re.compile(
    r'(?m)^[ \t]*(?:version-file|version_file|write_to)\s*=\s*'
    r'["\']([A-Za-z0-9_./+-]+\.py)["\']'
)
# Optional imports a checkout may name. The pip name is this map, never a
# string taken from the test id or the log. Installed only when that name
# also appears in the project's own optional dependencies or requirements.
_DECLARED_IMPORTS = {
    "IPython": "ipython",
    "tokenize_rt": "tokenize-rt",
    "uvloop": "uvloop",
    "trio": "trio",
}
_IMPORTORSKIP = re.compile(
    r"""importorskip\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""
)
_REDIS_IMAGE = re.compile(
    r"(?im)^[ \t]*image:[ \t]*['\"]?(?:docker\.io/)?(?:library/)?redis(?:[:@][\w./-]+)?['\"]?[ \t]*$"
)
_POSTGRES_IMAGE = re.compile(
    r"(?im)^[ \t]*image:[ \t]*['\"]?(?:docker\.io/)?(?:library/)?postgres(?:[:@][\w./-]+)?['\"]?[ \t]*$"
)


def pytest_dbdriver(node_id: str) -> str:
    """``AsyncCancellationTest_sqlite+aiosqlite_async_3_37_2`` → ``aiosqlite``.

    Empty when the id does not name an allowlisted driver. The returned token
    is safe to pass as ``--dbdriver`` and as a pip package name.
    """
    rest = str(node_id).split("::", 1)[-1] if "::" in str(node_id) else ""
    cls = rest.split("::", 1)[0]
    plus = cls.find("+")
    if plus < 0:
        return ""
    token = cls[plus + 1:].split("_", 1)[0].split("[", 1)[0]
    if token in _SQLA_DB_DRIVERS:
        return token
    return ""


def _vcs_version(wt: Path) -> str:
    """Nearest tag on this checkout, or ``0.0.0`` when the repo has no tags."""
    try:
        r = subprocess.run(
            ["git", "-C", str(wt), "describe", "--tags", "--abbrev=0"],
            capture_output=True, text=True, timeout=10, env=build_scrubbed_env(),
        )
        tag = (r.stdout or "").strip().lstrip("vV")
    except (OSError, subprocess.TimeoutExpired):
        tag = ""
    m = re.match(r"(\d+(?:\.\d+){0,3})", tag)
    return m.group(1) if m else "0.0.0"


def _write_version_module(dest: Path, version: str) -> None:
    parts: list[str] = []
    for piece in version.split("."):
        parts.append(piece if piece.isdigit() else repr(piece))
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        "# generated by sentinel; hatch-vcs writes this and git clean removes it\n"
        f"version = {version!r}\n"
        "__version__ = version\n"
        f"__version_tuple__ = version_tuple = ({', '.join(parts)})\n"
        "commit_id = None\n"
        "__commit_id__ = commit_id\n",
        encoding="utf-8",
    )


def _looks_like_import_root(path: Path) -> bool:
    """True when ``path`` contains an importable module or package."""
    try:
        children = list(path.iterdir())
    except OSError:
        return False
    for child in children:
        if child.name.startswith(".") or child.name == "__pycache__":
            continue
        if child.suffix == ".py":
            return True
        if child.is_dir() and (child / "__init__.py").is_file():
            return True
    return False


def _pytest_import_roots(wt: Path) -> list[str]:
    """Directories a pytest child should import this checkout from.

    ``src`` covers the src layout. ``lib`` covers projects such as SQLAlchemy.
    Their conftest inserts ``lib`` only when user site is enabled. The bisect
    sets ``PYTHONNOUSERSITE``, so that insert does not run and the checkout's
    package would be invisible. A ``lib`` that is not an import root is left off
    the path.
    """
    parts = [str(wt)]
    src = wt / "src"
    if src.is_dir():
        parts.append(str(src))
    lib = wt / "lib"
    if _looks_like_import_root(lib):
        parts.insert(0, str(lib))
    return parts


_REQ_FILES = (
    "requirements-test.txt",
    "requirements_test.txt",
    "test-requirements.txt",
    "requirements/test.txt",
    "requirements/tests.txt",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements/dev.txt",
)
_TEST_EXTRA_NAMES = ("test", "tests", "testing", "dev")
_SPEC_BAD = re.compile(r"[\n\r|&`$\\]|://|\.\.")
_MAX_DEP_SPECS = 40
_NOX_INSTALL = re.compile(r"session\.install\(([^)]*)\)")
_QUOTED = re.compile(r"""["']([^"']+)["']""")


def _accept_dep_spec(spec: str) -> bool:
    spec = (spec or "").strip()
    if not spec or len(spec) > 200 or spec.startswith(("-", "#")):
        return False
    if _SPEC_BAD.search(spec):
        return False
    return bool(re.match(r"^[A-Za-z0-9]", spec))


def _add_spec(found: list[str], spec: object) -> None:
    if not isinstance(spec, str):
        return
    text = spec.strip()
    if _accept_dep_spec(text) and text not in found and len(found) < _MAX_DEP_SPECS:
        found.append(text)


def _req_file_specs(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    found: list[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-r", "-c", "--")):
            continue
        _add_spec(found, line)
    return found


def _tox_dep_specs(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    in_env = False
    in_deps = False
    found: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_env = stripped in ("[testenv]", "[testenv:py]", "[testenv:test]")
            in_deps = False
            continue
        if not in_env:
            continue
        if re.match(r"^deps\s*=", stripped):
            in_deps = True
            rest = stripped.split("=", 1)[1].strip().rstrip("\\").strip()
            if rest:
                _add_spec(found, rest)
            continue
        if in_deps and (line.startswith((" ", "\t")) or stripped.endswith("\\")):
            _add_spec(found, stripped.rstrip("\\").strip())
            continue
        in_deps = False
    return found


def _nox_dep_specs(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    found: list[str] = []
    for match in _NOX_INSTALL.finditer(text):
        body = match.group(1)
        # ``dependency_groups(pyproject, "tests")`` quotes a group name.
        # Installing that name as a package drops the real requirements.
        if "dependency_groups" in body:
            continue
        for spec in _QUOTED.findall(body):
            _add_spec(found, spec)
    return found


def _driver_import_name(spec: str) -> str:
    """Distribution name from a requirement, or empty when it is not a plain import.

    Only ``[a-z][a-z0-9_]{0,40}`` is returned. That token is interpolated into
    ``import <name>``. Specs from a checkout cannot smuggle other code.
    """
    name = re.split(r"[<>=!\[;]", spec, maxsplit=1)[0].strip().replace("-", "_")
    if re.fullmatch(r"[a-z][a-z0-9_]{0,40}", name):
        return name
    return ""


def driver_install_specs(root: Path, driver: str) -> list[str]:
    """Packages an allowlisted ``--dbdriver`` needs, taken from that extra.

    ``sqlalchemy[asyncio]`` expands to the checkout's own extra (greenlet).
    The project under test is not installed from PyPI; it is already on
    ``PYTHONPATH``.
    """
    if driver not in _SQLA_DB_DRIVERS:
        return []
    found = [driver]
    path = Path(root) / "pyproject.toml"
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, tomllib.TOMLDecodeError):
        return found
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    name = str(project.get("name") or "").lower().replace("_", "-")
    extras = project.get("optional-dependencies") if isinstance(project.get("optional-dependencies"), dict) else {}

    def expand(extra_name: str, seen: set[str]) -> None:
        if extra_name in seen:
            return
        seen.add(extra_name)
        for spec in extras.get(extra_name) or []:
            if not isinstance(spec, str):
                continue
            text = spec.strip()
            match = re.match(r"^([A-Za-z0-9_.-]+)\[([A-Za-z0-9_,.-]+)\]", text)
            if match and match.group(1).lower().replace("_", "-") == name:
                for part in match.group(2).split(","):
                    expand(part.strip(), seen)
                continue
            _add_spec(found, text)

    expand(driver, set())
    return found


def _pyproject_dep_specs(path: Path) -> list[str]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    found: list[str] = []
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    for spec in project.get("dependencies") or []:
        _add_spec(found, spec)
    extras = project.get("optional-dependencies") if isinstance(project.get("optional-dependencies"), dict) else {}
    groups = data.get("dependency-groups") if isinstance(data.get("dependency-groups"), dict) else {}
    for name in _TEST_EXTRA_NAMES:
        for spec in extras.get(name) or []:
            _add_spec(found, spec)
        for spec in groups.get(name) or []:
            _add_spec(found, spec)
    return found


def _dist_name(spec: str) -> str:
    base = (spec or "").split("[", 1)[0].strip()
    base = re.split(r"[<>=!~;\s]", base, maxsplit=1)[0]
    return re.sub(r"[-_.]+", "-", base).lower()


def _project_dist_name(root: Path) -> str:
    """Distribution name of the checkout, so pip does not install that wheel over it."""
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8", errors="replace"))
        except (OSError, tomllib.TOMLDecodeError):
            data = {}
        project = data.get("project") if isinstance(data.get("project"), dict) else {}
        name = project.get("name")
        if isinstance(name, str) and name.strip():
            return _dist_name(name)
    setup = root / "setup.cfg"
    if setup.is_file():
        try:
            text = setup.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        match = re.search(r"(?m)^name\s*=\s*(\S+)", text)
        if match:
            return _dist_name(match.group(1))
    return ""


def _setup_py_dep_specs(path: Path) -> list[str]:
    """String specs in ``install_requires`` from a setup.py that has no pyproject deps."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    found: list[str] = []
    blocks: list[str] = []
    for match in re.finditer(r"install_requires\s*=\s*\[([^\]]*)\]", text, re.S):
        blocks.append(match.group(1))
    named = re.search(r"install_requires\s*=\s*([A-Za-z_][A-Za-z0-9_]*)", text)
    if named:
        var = named.group(1)
        assigned = re.search(rf"{var}\s*=\s*\[([^\]]*)\]", text, re.S)
        if assigned:
            blocks.append(assigned.group(1))
    for block in blocks:
        for spec in _QUOTED.findall(block):
            _add_spec(found, spec)
    return found


def project_test_dep_specs(root: Path) -> list[str]:
    """Third-party packages the checkout's tests import.

    Runtime dependencies, test extras, test dependency-groups, requirements
    files (including ``requirements.txt``), tox ``deps``, and string literals
    in ``session.install``. URLs, path specs, and the checkout's own
    distribution name are dropped. The checkout itself stays on ``PYTHONPATH``.
    """
    found: list[str] = []
    for spec in _pyproject_dep_specs(root / "pyproject.toml"):
        _add_spec(found, spec)
    for rel in _REQ_FILES:
        for spec in _req_file_specs(root / rel):
            _add_spec(found, spec)
    for spec in _tox_dep_specs(root / "tox.ini"):
        _add_spec(found, spec)
    for spec in _nox_dep_specs(root / "noxfile.py"):
        _add_spec(found, spec)
    for spec in _setup_py_dep_specs(root / "setup.py"):
        _add_spec(found, spec)
    own = _project_dist_name(root)
    if own:
        found = [spec for spec in found if _dist_name(spec) != own]
    return found


def declared_python_ceiling(root: Path) -> int | None:
    """Highest Python 3 minor the checkout says it supports.

    Classifiers and a ``requires-python`` / ``python_requires`` upper bound
    are the ceiling. A lower bound alone is not one: ``>=3.8`` still allows
    the job's interpreter.
    """
    chunks: list[str] = []
    for rel in ("pyproject.toml", "setup.cfg", "setup.py"):
        path = root / rel
        if not path.is_file():
            continue
        try:
            chunks.append(path.read_text(encoding="utf-8", errors="replace")[:200_000])
        except OSError:
            continue
    blob = "\n".join(chunks)
    minors = [int(item) for item in re.findall(r"Programming Language :: Python :: 3\.(\d+)\b", blob)]
    ceiling = max(minors) if minors else None
    for match in re.finditer(
        r"""(?m)^[ \t]*(?:requires-python|python_requires)\s*=\s*['\"]([^'\"]+)['\"]""",
        blob,
    ):
        spec = match.group(1)
        upper = re.search(r"<=\s*3\.(\d+)", spec)
        if upper:
            bound = int(upper.group(1))
        else:
            upper = re.search(r"<\s*3\.(\d+)", spec)
            bound = int(upper.group(1)) - 1 if upper else None
        if bound is not None and bound >= 0:
            ceiling = bound if ceiling is None else min(ceiling, bound)
    return ceiling


def _python_minor(executable: str) -> int | None:
    if os.path.abspath(executable) == os.path.abspath(sys.executable) or executable == sys.executable:
        return sys.version_info[1] if sys.version_info[0] == 3 else None
    try:
        proc = subprocess.run(
            [executable, "-c", "import sys; print(sys.version_info[0], sys.version_info[1])"],
            capture_output=True, text=True, timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    parts = (proc.stdout or "").split()
    if proc.returncode != 0 or len(parts) != 2 or parts[0] != "3":
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def resolve_python_bin(minor: int) -> str | None:
    """A ``python3.N`` binary. ``uv`` installs one when it is already on ``PATH``."""
    if minor < 8 or minor > 13:
        return None
    found = shutil.which(f"python3.{minor}")
    if found:
        return found
    uv = shutil.which("uv")
    if not uv:
        return None

    def _find() -> str | None:
        try:
            proc = subprocess.run(
                [uv, "python", "find", f"3.{minor}"],
                capture_output=True, text=True, timeout=40,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if proc.returncode != 0:
            return None
        lines = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
        if not lines:
            return None
        candidate = lines[-1]
        return candidate if Path(candidate).is_file() else None

    got = _find()
    if got:
        return got
    try:
        installed = subprocess.run(
            [uv, "python", "install", f"3.{minor}"],
            capture_output=True, text=True, timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if installed.returncode != 0:
        return None
    return _find()


def interpreter_for_checkout(root: Path, current: str) -> str:
    """Use the checkout's declared Python when the job interpreter is newer.

    A historical commit whose classifiers stop at 3.11 has no cp312 wheels.
    Staying on the job's 3.12 then fails every SHA the same way. When ``uv``
    or ``python3.N`` can supply the declared minor, that interpreter is used.
    """
    ceiling = declared_python_ceiling(root)
    minor = _python_minor(current)
    if ceiling is None or minor is None or minor <= ceiling:
        return current
    return resolve_python_bin(ceiling) or current


def ensure_pytest_on(python: str, env: dict[str, str], deadline: float | None, dest: Path) -> None:
    """Install pytest into ``dest`` when this interpreter does not have it.

    A uv-managed interpreter refuses ``pip install`` into its own prefix
    (PEP 668). ``--target`` lands pytest on ``PYTHONPATH`` beside the other
    test dependencies.
    """
    rem = remaining_budget(deadline)
    if rem < 2:
        return
    try:
        rc, _, _ = run_capped(
            [python, "-c", "import pytest"],
            cwd=Path("."), env=env, timeout=min(20.0, rem),
        )
    except (OSError, subprocess.TimeoutExpired):
        return
    if rc == 0:
        return
    dest.mkdir(parents=True, exist_ok=True)
    try:
        run_capped(
            [
                python, "-m", "pip", "install", "-q", "--disable-pip-version-check",
                "--target", str(dest), "pytest",
            ],
            cwd=Path("."), env=env, timeout=min(120.0, remaining_budget(deadline)),
        )
    except (OSError, subprocess.TimeoutExpired):
        return
    prev = env.get("PYTHONPATH", "")
    if str(dest) not in prev.split(os.pathsep):
        env["PYTHONPATH"] = str(dest) + (os.pathsep + prev if prev else "")
        env["SENTINEL_TOOL_PYDEPS"] = str(dest)


def _commit_iso(root: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "log", "-1", "--format=%cI"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    text = (proc.stdout or "").strip()
    return text if proc.returncode == 0 and len(text) >= 10 else ""


def _pypi_version_before(name: str, commit_iso: str, cache: Path) -> str | None:
    """Newest release of ``name`` uploaded before ``commit_iso``.

    An open lower bound (``Jinja2>=2.4``) otherwise installs today's release.
    Historical checkouts then fail on every SHA for the same missing API.
    """
    if not commit_iso or not re.fullmatch(r"[A-Za-z0-9_.-]+", name or ""):
        return None
    dest = cache / "pypi-meta" / f"{name}.json"
    try:
        if dest.is_file() and dest.stat().st_size > 20:
            payload = json.loads(dest.read_text(encoding="utf-8"))
        else:
            import urllib.request

            req = urllib.request.Request(
                f"https://pypi.org/pypi/{name}/json",
                headers={"User-Agent": "sentinel-bisect"},
            )
            with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - host is pypi.org, name is a dist name
                raw = resp.read(8_000_000)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
            payload = json.loads(raw.decode("utf-8", "replace"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    releases = payload.get("releases") if isinstance(payload, dict) else None
    if not isinstance(releases, dict):
        return None
    try:
        from packaging.version import Version
    except ImportError:
        return None
    best: tuple | None = None
    best_name = ""
    cutoff = commit_iso[:19]
    for version, files in releases.items():
        if not isinstance(files, list) or not files:
            continue
        uploaded = ""
        for item in files:
            if isinstance(item, dict):
                uploaded = str(item.get("upload_time_iso_8601") or item.get("upload_time") or "")
                if uploaded:
                    break
        if not uploaded or uploaded[:19] > cutoff:
            continue
        try:
            parsed = Version(version)
        except Exception:  # noqa: BLE001 - packaging rejects yanked junk
            continue
        if parsed.is_prerelease:
            continue
        if best is None or parsed > best:
            best = parsed
            best_name = version
    return best_name or None


def _pin_unbounded_specs(specs: list[str], root: Path, cache: Path) -> list[str]:
    commit_iso = _commit_iso(root)
    if not commit_iso:
        return specs
    pinned: list[str] = []
    for spec in specs:
        if any(tok in spec for tok in ("==", "<", "~=", "!=")):
            pinned.append(spec)
            continue
        version = _pypi_version_before(_dist_name(spec), commit_iso, cache)
        if version:
            pinned.append(f"{_dist_name(spec)}=={version}")
        else:
            pinned.append(spec)
    return pinned


def install_project_test_deps(
    root: Path,
    cache: Path,
    python: str,
    env: dict[str, str],
    deadline: float | None,
) -> str | None:
    """Install this checkout's test dependencies into a cached target directory.

    ``None`` means there was nothing to install, or the target is on
    ``PYTHONPATH``. A string is a pip failure. The caller keeps going: a
    dependency miss stays a collection error, and a pip hiccup does not turn
    a real failure into an environment abstain.
    """
    specs = _pin_unbounded_specs(project_test_dep_specs(root), root, cache)
    if not specs:
        return None
    rem = remaining_budget(deadline)
    if rem < 2:
        return "budget_exhausted"
    py_tag = _python_minor(python) or 0
    digest = hashlib.sha256(f"py3.{py_tag}\n".encode() + "\n".join(specs).encode()).hexdigest()[:16]
    dest = cache / "pydeps" / digest
    marker = dest / ".sentinel-installed"
    if not marker.is_file():
        dest.mkdir(parents=True, exist_ok=True)

        def _pip(batch: list[str], timeout: float) -> tuple[int, str, str]:
            cmd = [
                python, "-m", "pip", "install", "-q", "--disable-pip-version-check",
                "--target", str(dest), *batch,
            ]
            return run_capped(cmd, cwd=root, env=env, timeout=timeout)

        try:
            rc, out, err = _pip(specs, min(180.0, rem))
        except subprocess.TimeoutExpired:
            return "test_deps_timeout"
        except OSError as exc:
            return "test_deps_failed:" + type(exc).__name__
        if rc != 0 and len(specs) > 1:
            # One native package (no wheel, no compiler) must not drop the rest.
            failed: list[str] = []
            for spec in specs:
                one_rem = remaining_budget(deadline)
                if one_rem < 2:
                    failed.append(spec)
                    continue
                try:
                    one_rc, one_out, one_err = _pip([spec], min(90.0, one_rem))
                except subprocess.TimeoutExpired:
                    failed.append(spec)
                    continue
                except OSError:
                    failed.append(spec)
                    continue
                if one_rc != 0:
                    failed.append(spec)
                    out, err = one_out, one_err
            if len(failed) == len(specs):
                quote = setup_error_quote(out, err) or _scrub_reason((err or out)[-160:], max_len=120)
                return "test_deps_failed:" + (quote or "all_specs_failed")
            rc = 0
        if rc != 0:
            quote = setup_error_quote(out, err) or _scrub_reason((err or out)[-160:], max_len=120)
            return "test_deps_failed:" + (quote or f"exit_{rc}")
        marker.write_text("ok\n", encoding="utf-8")
    env["SENTINEL_TOOL_PYDEPS"] = str(dest)
    prev = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(dest) + (os.pathsep + prev if prev else "")
    return None


def ensure_vcs_version_files(wt: Path) -> None:
    """Rewrite untracked hatch-vcs version modules declared in pyproject.toml.

    ``git clean`` and a fresh worktree both omit these files. The project
    imports them at startup (``_black_version``, ``urllib3._version``).
    A path that git already tracks is left alone.
    """
    pyproject = wt / "pyproject.toml"
    if not pyproject.is_file():
        return
    try:
        text = pyproject.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    rels = _VERSION_FILE_DECL.findall(text)
    if not rels:
        return
    version = _vcs_version(wt)
    root = wt.resolve()
    for rel in rels:
        dest = (wt / rel).resolve()
        if root != dest and root not in dest.parents:
            continue
        try:
            tracked = subprocess.run(
                ["git", "-C", str(wt), "ls-files", "--error-unmatch", "--", rel],
                capture_output=True, timeout=10, env=build_scrubbed_env(),
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if tracked.returncode == 0:
            continue
        try:
            _write_version_module(dest, version)
        except OSError:
            continue


def project_declares_pip(root: Path, pip_name: str) -> bool:
    """True when the checkout names ``pip_name`` in optional deps or requirements.

    A test file that mentions a package is not enough. The project has to
    list it. The name is an allowlisted token, matched as a whole word.
    """
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,40}", pip_name or ""):
        return False
    chunks: list[str] = []
    for rel in ("pyproject.toml", "setup.cfg", "requirements.txt", "requirements-test.txt", "requirements-dev.txt"):
        try:
            chunks.append((root / rel).read_text(encoding="utf-8", errors="replace")[:400_000])
        except OSError:
            continue
    blob = "\n".join(chunks)
    return re.search(rf"(?i)(?<![A-Za-z0-9_.-]){re.escape(pip_name)}(?![A-Za-z0-9_.-])", blob) is not None


def optional_pips_for_tests(root: Path, node_ids: Sequence[str]) -> list[str]:
    """Allowlisted pip extras this checkout declares and these tests ask for.

    A bracket token (``[asyncio+uvloop]``) or ``pytest.importorskip("IPython")``
    in the named file. Anything else is ignored.
    """
    wanted: list[str] = []
    seen: set[str] = set()

    def add(pip_name: str) -> None:
        if pip_name in seen:
            return
        if not project_declares_pip(root, pip_name):
            return
        seen.add(pip_name)
        wanted.append(pip_name)

    for nid in node_ids:
        bracket = nid.split("[", 1)[1] if "[" in nid else ""
        for imp, pip_name in _DECLARED_IMPORTS.items():
            if imp in bracket or pip_name in bracket:
                add(pip_name)
        rel = nid.split("::", 1)[0]
        if not rel.endswith(".py") or ".." in rel.split("/"):
            continue
        path = root / rel
        try:
            body = path.read_text(encoding="utf-8", errors="replace")[:80_000]
        except OSError:
            continue
        for match in _IMPORTORSKIP.finditer(body):
            pip_name = _DECLARED_IMPORTS.get(match.group(1))
            if pip_name:
                add(pip_name)
    return wanted


def _port_open(host: str, port: int) -> bool:
    sock = socket.socket()
    try:
        sock.settimeout(0.3)
        return sock.connect_ex((host, port)) == 0
    except OSError:
        return False
    finally:
        sock.close()


def workflow_service_images(root: Path) -> set[str]:
    """Service image names declared in ``.github/workflows`` (``redis``, ``postgres``).

    The workflow file is not executed. Only an ``image:`` line is read.
    """
    found: set[str] = set()
    directory = root / ".github" / "workflows"
    try:
        paths = list(directory.glob("*.yml")) + list(directory.glob("*.yaml"))
    except OSError:
        return found
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:500_000]
        except OSError:
            continue
        if _REDIS_IMAGE.search(text):
            found.add("redis")
        if _POSTGRES_IMAGE.search(text):
            found.add("postgres")
    return found


def ensure_declared_services(root: Path, env: dict[str, str]) -> None:
    """Start a local Redis when CI's workflow asks for one and the port is closed.

    Postgres is not started here. When it is already listening, the tests use
    it. A service that cannot be started leaves the test result as an
    environment abstain. This never names a culprit.
    """
    images = workflow_service_images(root)
    if "redis" in images and not env.get("REDIS_URL"):
        if not _port_open("127.0.0.1", 6379):
            import shutil

            binary = shutil.which("redis-server")
            if binary:
                subprocess.Popen(
                    [
                        binary, "--bind", "127.0.0.1", "--port", "6379",
                        "--daemonize", "yes", "--save", "", "--appendonly", "no",
                        "--protected-mode", "no",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                for _ in range(20):
                    if _port_open("127.0.0.1", 6379):
                        break
                    time.sleep(0.05)
        if _port_open("127.0.0.1", 6379):
            env.setdefault("REDIS_URL", "redis://127.0.0.1:6379/0")
    if "postgres" in images and _port_open("127.0.0.1", 5432):
        env.setdefault("PGHOST", "127.0.0.1")
        env.setdefault("PGPORT", "5432")
        env.setdefault("PGUSER", "postgres")


OUTSIDE_CAUSE_REASONS = frozenset({"empty_commit_range"})
OUTSIDE_CAUSE_LINE = (
    "Not proven: outside cause — no code change between the last green run and this one (empty commit range)"
)


def _scrub_reason(text: str | None, *, max_len: int = 200) -> str:
    try:
        from provebreak_culprit._engine.sanitize import scrub_text

        return scrub_text(text or "", max_len=max_len)
    except Exception:  # noqa: BLE001
        s = re.sub(r"[\x00-\x1f\x7f]", "", str(text or ""))[:max_len]
        return s


@dataclass
class BisectResult:
    """Result of confirm-culprit bisect. Always safe to serialize."""

    status: str  # proven | introduced_failing_test | not_proven | inconclusive_flaky | inconclusive_build | inconclusive_git | inconclusive_env | outside_cause | budget_exhausted | skipped | error
    culprit_sha: str | None = None
    parent_sha: str | None = None
    failing_tests: list[str] = field(default_factory=list)
    reproductions: int = 0
    reproduction_attempts: int = 0
    steps_used: int = 0
    elapsed_sec: float = 0.0
    reason: str | None = None
    evidence: str = ""
    evaluations: list[dict] = field(default_factory=list)
    upstream: dict | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        # Never embed raw pytest blobs; reasons already scrubbed at set sites
        if d.get("reason"):
            d["reason"] = _scrub_reason(d["reason"])
        if d.get("evidence"):
            d["evidence"] = _scrub_reason(d["evidence"], max_len=400)
        if not d.get("upstream"):
            d.pop("upstream", None)
        return d

    def card_line(self) -> str:
        from provebreak_culprit._engine.verdict import classify
        from provebreak_culprit._engine.verdict import parent_or_head_disagrees

        payload = self.to_dict()
        if parent_or_head_disagrees(payload, None):
            verdict = classify(payload, None)
            if verdict and verdict.get("headline"):
                return str(verdict["headline"])
        if self.status == "proven" and self.culprit_sha:
            tests = ", ".join(self.failing_tests[:3]) or "unknown test"
            short = self.culprit_sha[:12]
            k = self.reproductions
            n = self.reproduction_attempts or k
            return proven_line(
                short, tests, k, n,
                parent_short=(self.parent_sha or "")[:12],
                added_assertion=str(self.reason or "").startswith(ADDED_ASSERTION_REASON),
            )
        if self.status == "introduced_failing_test" and self.culprit_sha:
            tests = ", ".join(self.failing_tests[:3]) or "unknown test"
            short = self.culprit_sha[:12]
            return (
                f"Failing test was introduced (already failing) in commit {short} "
                f"({tests}; not present or not collectable on parent "
                f"{(self.parent_sha or '')[:12] or 'unknown'})"
            )
        from provebreak_culprit._engine.verdict import classify

        verdict = classify(self.to_dict(), None)
        if verdict:
            return verdict["headline"]
        if self.status == "inconclusive_git":
            return f"Not proven: inconclusive (git error) — {_scrub_reason(self.reason) or 'commit range unavailable in this clone'}"
        if self.status == "inconclusive_build":
            return f"Not proven: inconclusive (a commit could not build) — {_scrub_reason(self.reason) or 'build failed at a commit the proof needs'}"
        if self.status == "inconclusive_flaky":
            from provebreak_culprit._engine.flaky_tip import NOT_THIS_COMMIT_HEADLINE
            from provebreak_culprit._engine.flaky_tip import tip_passed_rerun

            evs = self.evaluations or []
            head = str(evs[0].get("sha") or "") if evs and isinstance(evs[0], dict) else ""
            if tip_passed_rerun(self.to_dict(), head):
                return NOT_THIS_COMMIT_HEADLINE
            return f"Not proven: inconclusive (flaky) — {_scrub_reason(self.reason) or 'results disagreed on re-run'}"
        if self.status == "inconclusive_env":
            return INCONCLUSIVE_ENV_LINE
        if self.status == "outside_cause":
            return OUTSIDE_CAUSE_LINE
        if self.status == "budget_exhausted":
            return f"Not proven: budget exhausted — {_scrub_reason(self.reason) or 'time or step budget hit'}"
        if self.status == "skipped":
            return f"Not proven: skipped — {_scrub_reason(self.reason) or 'confirm-culprit disabled'}"
        if self.status == "error":
            return f"Not proven: error — {_scrub_reason(self.reason) or 'internal error (fail-soft)'}"
        return f"Not proven: {_scrub_reason(self.reason) or self.status}"


class TestRunner(Protocol):
    def evaluate(
        self,
        sha: str,
        tests: Sequence[str],
        *,
        reruns: int,
        deadline: float | None = None,
    ) -> EvalResult:
        ...


@dataclass
class EvalResult:
    """Outcome of evaluating one commit against failing tests.

    label:
      green — collected and all passed
      red — collected and failed (assertion / test failure)
      flaky — mixed pass/fail across reruns
      error — not-found, collection/import error, timeout, checkout failure
               (MUST NOT be treated as red for bisect decisions)

    kind ``build_error`` (go/vitest/jest runners only; pytest never emits it):
    the commit could not compile / install / load the test file. The search
    skips such commits and never names a culprit whose parent is unbuildable.
    """

    label: str
    passes: int = 0
    fails: int = 0
    runs: int = 0
    detail: str = ""
    kind: str = ""  # pass|fail|not_found|collection_error|timeout|checkout|os|mixed|unknown|env_setup|unresolved_node_id|build_error
    # ``assertion`` when the failure is a test assertion (golden diff, Error:,
    # AssertionError), not a panic or a compile error. Empty otherwise.
    failure: str = ""


_NOT_FOUND_RE = re.compile(
    r"(ERROR:\s*not found:|not found:\s*|ERROR collecting|ImportError|ModuleNotFoundError|"
    r"no tests (ran|collected)|collected 0 items|file or directory not found)",
    re.IGNORECASE,
)


# Outcome markers pytest prints when tests actually ran and failed/errored.
_FAILURE_MARKER_RE = re.compile(
    r"^(?:FAILED|ERROR)\s+\S+::|"  # short test summary lines (node ids)
    r"^FAILED\b|"
    r"=+ (?:FAILURES|ERRORS) =+|"
    r"\b\d+ (?:failed|errors?)\b",  # "1 failed in 0.03s", "2 failed, 3 passed", "1 error in"
    re.M | re.I,
)


def classify_pytest_outcome(returncode: int, stdout: str, stderr: str) -> tuple[str, str, str]:
    """Map pytest result → (label, kind, detail_snippet).

    Collection / not-found / usage errors are ``error``, never ``red``.
    """
    out = (stdout or "") + "\n" + (stderr or "")
    detail = _scrub_reason(out[-400:] if out else "", max_len=200)

    if returncode == 0:
        # Guard: "no tests ran" with exit 0 is rare but treat as error if seen
        if re.search(r"no tests ran|collected 0 items", out, re.I):
            return "error", "not_found", detail or "no_tests_collected"
        return "green", "pass", detail or "pass"

    # Pytest: 4 = usage error, 5 = no tests collected
    if returncode in (4, 5) or _NOT_FOUND_RE.search(out):
        kind = "not_found" if returncode == 5 or re.search(r"not found|no tests|collected 0", out, re.I) else "collection_error"
        return "error", kind, detail or kind

    if returncode in (2, 3):
        return "error", "collection_error", detail or f"pytest_exit_{returncode}"

    # returncode 1: real test failures — but only if pytest printed an outcome marker
    # (FAILED line, FAILURES/ERRORS section, or an "N failed"/"N error" summary).
    if returncode == 1:
        if _FAILURE_MARKER_RE.search(out):
            return "red", "fail", detail or "fail"
        # Ambiguous non-zero without failure markers (e.g. "No module named pytest",
        # interpreter/plugin crash) → abstain as error, never red.
        if _NOT_FOUND_RE.search(out):
            return "error", "not_found", detail
        return "error", "no_failure_markers", detail or "exit_1_no_failure_markers"

    # Other codes → error (ambiguous)
    return "error", "unknown", detail or f"pytest_exit_{returncode}"


def _junit_case_for_request(req: str, cases: dict[str, str]) -> str | None:
    """The JUnit node id for ``req``, including a class the CI id dropped."""
    if req in cases:
        return req
    file, sep, rest = req.partition("::")
    if not sep or not rest:
        return None
    func = rest.split("::")[-1]
    hits: list[str] = []
    for key in cases:
        kf, ksep, kr = key.partition("::")
        if not ksep or kf != file or not kr:
            continue
        if kr == rest or kr.endswith("::" + rest):
            hits.append(key)
            continue
        if rest == func and "::" in kr and kr.split("::")[-1] == func:
            hits.append(key)
    if len(hits) == 1:
        return hits[0]
    return None


def _align_pytest_with_junit(
    label: str,
    kind: str,
    detail: str,
    junit_path: Path,
    requested: list[str],
) -> tuple[str, str, str]:
    """Prefer the node id rebuilt from JUnit over a shortened CI id.

    A pass in JUnit while pytest exited non-zero stays an error: another test
    in the file may have failed, or the report may be truncated. A failure
    element for the requested test (or its class-qualified form) is red.
    """
    try:
        text = junit_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return label, kind, detail
    from provebreak_culprit._engine.logs import parse_junit

    cases = parse_junit(text)
    if not cases or not requested:
        return label, kind, detail
    matched: list[str] = []
    for req in requested:
        hit = _junit_case_for_request(req, cases)
        if hit is None:
            return label, kind, detail
        matched.append(cases[hit])
    if any(s == "fail" for s in matched):
        if kind in ("collection_error", "env_setup", "timeout", "checkout", "checkout_incomplete"):
            return label, kind, detail
        return "red", "fail", detail or "junit_fail"
    if all(s == "pass" for s in matched):
        if label == "red":
            return "error", "package_fail", "exit_1_with_target_passed"
        if label == "error":
            return label, kind, detail
        return "green", "pass", detail or "junit_pass"
    return label, kind, detail


@dataclass
class PytestGitRunner:
    """Check out ``sha`` in a git worktree and run pytest nodeids.

    Fail-soft: checkout/run/collection errors → label ``error`` (never ``red``).
    Subprocess env is scrubbed (no GITHUB_TOKEN / secrets).
    """

    repo: Path
    python: str = "python3"
    per_run_timeout_sec: float = 60.0
    worktree_dir: Path | None = None
    env: dict[str, str] | None = None  # non-secret overlays only (secrets stripped)
    db_reset_command: Sequence[str] | None = None
    cache_dir: Path | None = None
    # Relpath → file text copied onto every checkout after ``git clean``.
    # The backport grade uses the fix commit's test. The main grade leaves this empty.
    file_overlay: dict[str, str] | None = None

    def __post_init__(self) -> None:
        self.repo = Path(self.repo).resolve()
        if self.worktree_dir is None:
            self.worktree_dir = self.repo.parent / f".sentinel-bisect-wt-{os.getpid()}"
        self.worktree_dir = Path(self.worktree_dir)
        # Extra pytest args discovered while resolving a CI id (for example
        # ``--dbdriver aiosqlite``). Empty until a collection retry needs them.
        self._pytest_prefix: list[str] = []
        self._site_guard = _SiteGuard()

    def _ensure_worktree(self, sha: str) -> Path | None:
        wt = self.worktree_dir
        # Refuse to use the primary checkout as worktree (clean -fdx would be catastrophic)
        try:
            if wt.resolve() == self.repo.resolve():
                return None
        except OSError:
            return None
        try:
            if wt.exists():
                r = subprocess.run(
                    ["git", "-C", str(wt), "checkout", "--force", "--detach", sha],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env=build_scrubbed_env(),
                )
                if r.returncode != 0:
                    subprocess.run(
                        ["git", "-C", str(self.repo), "worktree", "remove", "--force", str(wt)],
                        capture_output=True,
                        timeout=30,
                        env=build_scrubbed_env(),
                    )
                    if wt.exists():
                        import shutil

                        shutil.rmtree(wt, ignore_errors=True)
                    r2 = subprocess.run(
                        ["git", "-C", str(self.repo), "worktree", "add", "--detach", str(wt), sha],
                        capture_output=True,
                        text=True,
                        timeout=60,
                        env=build_scrubbed_env(),
                    )
                    if r2.returncode != 0:
                        return None
                return wt
            r = subprocess.run(
                ["git", "-C", str(self.repo), "worktree", "add", "--detach", str(wt), sha],
                capture_output=True,
                text=True,
                timeout=60,
                env=build_scrubbed_env(),
            )
            if r.returncode != 0:
                return None
            return wt
        except (OSError, subprocess.TimeoutExpired):
            return None

    def cleanup(self) -> None:
        guard = getattr(self, "_site_guard", None)
        if guard is not None:
            guard.close()
        wt = self.worktree_dir
        if not wt or not Path(wt).exists():
            return
        try:
            if wt.resolve() == self.repo.resolve():
                return
        except OSError:
            return
        try:
            subprocess.run(
                ["git", "-C", str(self.repo), "worktree", "remove", "--force", str(wt)],
                capture_output=True,
                timeout=30,
                env=build_scrubbed_env(),
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
        import shutil

        shutil.rmtree(wt, ignore_errors=True)

    def _apply_file_overlay(self, wt: Path) -> None:
        overlay = self.file_overlay or {}
        if not overlay:
            return
        root = wt.resolve()
        for rel, contents in overlay.items():
            rel_path = Path(str(rel))
            if rel_path.is_absolute() or ".." in rel_path.parts:
                continue
            dest = (wt / rel_path).resolve()
            if dest != root and root not in dest.parents:
                continue
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(contents, encoding="utf-8")
            except OSError:
                continue

    def _reset_db(self, wt: Path, sha: str, env: dict[str, str], deadline: float | None) -> str | None:
        cmd = getattr(self, "db_reset_command", None)
        if not cmd:
            return None
        from provebreak_culprit._engine.runners import apply_db_reset
        from provebreak_culprit._engine.runners import default_cache_dir

        cache = Path(self.cache_dir) if getattr(self, "cache_dir", None) else default_cache_dir()
        return apply_db_reset(list(cmd), cwd=wt, env=env, deadline=deadline, sha=sha, cache=cache)

    def _child_env(self, wt: Path, *, home: Path) -> dict[str, str]:
        parts = _pytest_import_roots(wt)
        extra = dict(self.env or {})
        # A runner constructed with PYTHONPATH (a lab wheel) is applied after the
        # scrub. The job environment's PYTHONPATH is already dropped, and
        # bisect_env refuses that name.
        harness_path = str(extra.get("PYTHONPATH") or "")
        # PYTHONPATH from worktree; HOME forced to isolated sandbox (never parent)
        env = build_scrubbed_env(extra=extra, home=str(home))
        apply_isolated_home(env, home)
        prev = env.get("PYTHONPATH", "")
        path = os.pathsep.join(parts) + ((os.pathsep + prev) if prev else "")
        if harness_path and harness_path not in path.split(os.pathsep):
            path = path + os.pathsep + harness_path
        env["PYTHONPATH"] = path
        return env

    def evaluate(
        self,
        sha: str,
        tests: Sequence[str],
        *,
        reruns: int,
        deadline: float | None = None,
    ) -> EvalResult:
        if not tests:
            return EvalResult(label="error", detail="no_tests", kind="unknown")
        if remaining_budget(deadline) < 0.05:
            return EvalResult(label="error", detail="budget_exhausted", kind="timeout")
        # Validate before invoking pytest (defense in depth; confirm_culprit also validates)
        clean, err = validate_node_ids(tests)
        if err:
            return EvalResult(label="error", detail=err, kind="unknown")
        # Cap worktree setup against remaining budget
        setup_timeout = min(30.0, max(0.5, remaining_budget(deadline)))
        wt = self._ensure_worktree(sha)
        if wt is None:
            return EvalResult(label="error", detail=f"checkout_failed:{sha[:12]}", kind="checkout")
        if remaining_budget(deadline) < 0.05:
            return EvalResult(label="error", detail="budget_exhausted", kind="timeout")
        try:
            if wt.resolve() == self.repo.resolve():
                return EvalResult(label="error", detail="refuse_clean_primary_checkout", kind="checkout")
            git_clean_worktree(wt, timeout=min(30.0, max(0.5, remaining_budget(deadline))))
            ensure_vcs_version_files(wt)
            subprocess.run(
                ["git", "-C", str(wt), "reset", "--hard", "HEAD"],
                capture_output=True,
                timeout=min(30.0, max(0.5, remaining_budget(deadline))),
                env=build_scrubbed_env(),
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
        fidelity = checkout_fidelity(
            wt, timeout=min(CHECKOUT_FIDELITY_SEC, max(1.0, remaining_budget(deadline))),
        )
        if fidelity:
            return EvalResult(label="error", detail=fidelity, kind="checkout_incomplete")
        self._apply_file_overlay(wt)

        import shutil

        chosen = interpreter_for_checkout(wt, self.python)
        saved_python = self.python
        self.python = chosen
        sandbox_home = make_isolated_home()
        self._site_guard.hold(self.python)
        self._site_guard.ensure(self.python)
        try:
            env = self._child_env(wt, home=sandbox_home)
            dep_cache = Path(self.cache_dir) if getattr(self, "cache_dir", None) else None
            if dep_cache is None:
                from provebreak_culprit._engine.runners import default_cache_dir

                dep_cache = default_cache_dir()
            install_project_test_deps(wt, dep_cache, self.python, env, deadline)
            ensure_declared_services(wt, env)
            for pip_name in optional_pips_for_tests(wt, clean):
                module = next(imp for imp, pip in _DECLARED_IMPORTS.items() if pip == pip_name)
                self._ensure_import(module, env, deadline, pip_name=pip_name)
            # The job interpreter is not assumed to have pytest. User-site
            # pytest is invisible under PYTHONNOUSERSITE, and that used to
            # come back as no_failure_markers instead of a test result.
            py_dest = Path(env.get("SENTINEL_TOOL_PYDEPS") or (dep_cache / "pydeps" / "pytest-runner"))
            ensure_pytest_on(self.python, env, deadline, py_dest)
            db_err = self._reset_db(wt, sha, env, deadline)
            if db_err:
                kind = "timeout" if "budget" in db_err or db_err == "db_reset_timeout" else "env_setup"
                return EvalResult(label="error", detail=db_err, kind=kind)
            result = self._run_pytest_reruns(
                clean=clean,
                wt=wt,
                env=env,
                reruns=reruns,
                deadline=deadline,
            )
            if result.label == "error" and result.kind in ("not_found", "collection_error", "env_setup"):
                recovered = self._recover_pytest(wt, env, clean, result, reruns, deadline)
                if recovered is not None:
                    return recovered
            return result
        finally:
            try:
                self._site_guard.restore()
            finally:
                self._site_guard.release()
            self.python = saved_python
            shutil.rmtree(sandbox_home, ignore_errors=True)

    def _recover_pytest(
        self,
        wt: Path,
        env: dict[str, str],
        clean: list[str],
        first: EvalResult,
        reruns: int,
        deadline: float | None,
    ) -> EvalResult | None:
        """One retry: editable install for a generated version module, else a narrower node id.

        A CI id that collects many tests is not bisected. That would blame a commit
        for a different test. The result says the id did not resolve.
        """
        if remaining_budget(deadline) < 0.5:
            return None
        detail = first.detail or ""
        if _VERSION_MODULE.search(detail) or "No module named" in detail:
            if self._editable_install(wt, env, deadline):
                again = self._run_pytest_reruns(
                    clean=clean, wt=wt, env=env, reruns=reruns, deadline=deadline,
                )
                if again.label != "error" or again.kind not in ("not_found", "collection_error", "env_setup"):
                    return again
                first = again
        if first.kind not in ("not_found", "collection_error"):
            return first if first.kind == "env_setup" else None
        driver = pytest_dbdriver(clean[0]) if len(clean) == 1 else ""
        if driver:
            self._ensure_driver(driver, wt, env, deadline)
            self._pytest_prefix = ["--dbdriver", driver]
        chosen, why = self._resolve_pytest_ids(wt, env, clean, deadline)
        if why == "many":
            return EvalResult(
                label="error",
                detail="ci_node_id_did_not_resolve",
                kind="unresolved_node_id",
            )
        if not chosen or chosen == clean:
            if _pytest_env_crash(first.detail or ""):
                return EvalResult(
                    label="error", detail=first.detail, kind="env_setup", runs=first.runs or 1,
                )
            return None
        return self._run_pytest_reruns(
            clean=chosen, wt=wt, env=env, reruns=reruns, deadline=deadline,
        )

    def _ensure_import(
        self,
        module: str,
        env: dict[str, str],
        deadline: float | None,
        *,
        pip_name: str | None = None,
    ) -> bool:
        """Import ``module`` in the job interpreter, installing it when it is missing.

        ``module`` is a fixed token from an allowlist, never a string from the
        checkout or the test log. ``pip_name`` defaults to ``module`` and must
        be that same token or an allowlisted package name (``tokenize-rt``).
        """
        pip_spec = pip_name or module
        module_ok = module in _DECLARED_IMPORTS or bool(
            re.fullmatch(r"[a-z][a-z0-9_]{0,40}", module)
        )
        pip_ok = pip_spec in set(_DECLARED_IMPORTS.values()) or bool(
            re.fullmatch(r"[a-z][a-z0-9_]{0,40}", pip_spec)
        )
        if not module_ok or not pip_ok or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,40}", module):
            return False
        rem = remaining_budget(deadline)
        if rem < 2:
            return False
        try:
            rc, _, _ = run_capped(
                [self.python, "-c", f"import {module}"],
                cwd=self.repo, env=env, timeout=min(20.0, rem),
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if rc == 0:
            return True
        try:
            rc, _, _ = run_capped(
                [self.python, "-m", "pip", "install", "-q", pip_spec, "--disable-pip-version-check"],
                cwd=self.repo, env=env, timeout=min(120.0, remaining_budget(deadline)),
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return rc == 0

    def _ensure_driver(self, driver: str, wt: Path, env: dict[str, str], deadline: float | None) -> bool:
        """Install an allowlisted DBAPI onto the child's ``PYTHONPATH``.

        A user-site install is invisible: the child sets ``PYTHONNOUSERSITE``.
        Specs go into the same target as the checkout's other test dependencies.
        Async drivers also need ``greenlet`` when the checkout extra does not
        already name it. SQLAlchemy raises ImportError at connect time without
        it, and collection then never sees the test.
        """
        if driver not in _SQLA_DB_DRIVERS:
            return False
        specs = driver_install_specs(wt, driver)
        if driver in _ASYNCIO_DRIVERS and not any(
            _driver_import_name(spec) == "greenlet" for spec in specs
        ):
            specs.append("greenlet")
        if not specs:
            return False
        rem = remaining_budget(deadline)
        if rem < 2:
            return False

        def _imports() -> bool:
            names = [name for name in (_driver_import_name(spec) for spec in specs) if name]
            if not names:
                return False
            code = "; ".join(f"import {name}" for name in names)
            try:
                rc, _, _ = run_capped(
                    [self.python, "-c", code],
                    cwd=wt, env=env, timeout=min(20.0, remaining_budget(deadline)),
                )
            except (OSError, subprocess.TimeoutExpired):
                return False
            return rc == 0

        if _imports():
            return True
        target = env.get("SENTINEL_TOOL_PYDEPS") or ""
        if not target:
            from provebreak_culprit._engine.runners import default_cache_dir

            cache = Path(self.cache_dir) if getattr(self, "cache_dir", None) else default_cache_dir()
            dest = cache / "pydeps" / f"driver-{driver}"
            dest.mkdir(parents=True, exist_ok=True)
            target = str(dest)
            env["SENTINEL_TOOL_PYDEPS"] = target
            prev = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = target + (os.pathsep + prev if prev else "")
        try:
            rc, _, _ = run_capped(
                [
                    self.python, "-m", "pip", "install", "-q", "--disable-pip-version-check",
                    "--target", target, *specs,
                ],
                cwd=wt, env=env, timeout=min(120.0, remaining_budget(deadline)),
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if rc != 0:
            return False
        return _imports()

    def _editable_install(self, wt: Path, env: dict[str, str], deadline: float | None) -> bool:
        if not ((wt / "pyproject.toml").is_file() or (wt / "setup.py").is_file() or (wt / "setup.cfg").is_file()):
            return False
        rem = remaining_budget(deadline)
        if rem < 2:
            return False
        cmd = [self.python, "-m", "pip", "install", "-e", ".", "--disable-pip-version-check", "--no-deps"]
        try:
            rc, _out, _err = run_capped(cmd, cwd=wt, env=env, timeout=min(180.0, rem))
        except (OSError, subprocess.TimeoutExpired):
            return False
        return rc == 0

    def _collect_ids(
        self, wt: Path, env: dict[str, str], args: list[str], deadline: float | None,
        options: list[str] | None = None,
    ) -> list[str] | None:
        """Collected node ids, or None when collection itself crashed.

        ``options`` (for example ``-k name``) stay before ``--``. Node ids and
        paths stay after it, so a test name cannot inject a flag.
        """
        rem = remaining_budget(deadline)
        if rem < 0.3:
            return None
        cmd = [
            self.python, "-m", "pytest", "--collect-only", "-q", "--no-header",
            # Project addopts often force ``-v``, which prints a tree instead of
            # node ids. Collection has to see ``file.py::test`` lines.
            "--override-ini=addopts=",
            *self._pytest_prefix, *(options or []), "--", *args,
        ]
        try:
            rc, stdout, stderr = run_capped(cmd, cwd=wt, env=env, timeout=min(60.0, rem))
        except (OSError, subprocess.TimeoutExpired):
            return None
        blob = (stdout or "") + "\n" + (stderr or "")
        if rc not in (0, 5) and "error" in blob.lower() and ".py::" not in stdout:
            return None
        ids = []
        for line in (stdout or "").splitlines():
            line = line.strip()
            if ".py::" in line and not line.startswith(("=", "E ", "F ")):
                nid = line.split(" ", 1)[0]
                if ".py::" in nid:
                    ids.append(nid)
        return ids

    def _resolve_pytest_ids(
        self, wt: Path, env: dict[str, str], clean: list[str], deadline: float | None,
    ) -> tuple[list[str] | None, str]:
        """(ids, '') when exactly one test matches; ('', 'many') when a fallback is ambiguous."""
        relocated = self._relocate_pytest_files(wt, clean)
        candidates = list(relocated)
        for nid in relocated:
            for alt in pytest_id_fallbacks(nid):
                if alt not in candidates:
                    candidates.append(alt)
        saw_many = False
        for cand in candidates:
            got = self._collect_ids(wt, env, [cand], deadline)
            if got is None:
                continue
            if len(got) == 1:
                # Run the id we asked for. The collected id can contain ``+``
                # (SQLAlchemy's generated class name). Pytest will not select
                # that string again: ``+`` is part of its node-id syntax.
                return [cand], ""
            if len(got) > 1:
                saw_many = True
        token = pytest_k_token(clean[0]) if len(clean) == 1 else ""
        file_part = clean[0].split("::", 1)[0] if clean else ""
        if token and file_part and (wt / file_part).is_file():
            got = self._collect_ids(wt, env, [file_part], deadline, options=["-k", token])
            if got is not None and len(got) == 1:
                if "+" in got[0]:
                    # Keep the file plus ``-k``. The expanded id is not selectable.
                    extra = ["-k", token]
                    if extra != self._pytest_prefix[-2:]:
                        self._pytest_prefix = [*self._pytest_prefix, *extra]
                    return [file_part], ""
                return got, ""
            if got is not None and len(got) > 1:
                saw_many = True
        if saw_many:
            return None, "many"
        return None, ""

    def _relocate_pytest_files(self, wt: Path, clean: list[str]) -> list[str]:
        """If the CI path is gone and exactly one tracked file has that basename, use it."""
        out: list[str] = []
        index: dict[str, list[str]] | None = None
        for nid in clean:
            path, sep, rest = nid.partition("::")
            if not sep or (wt / path).is_file():
                out.append(nid)
                continue
            if index is None:
                index = {}
                try:
                    r = subprocess.run(
                        ["git", "-C", str(wt), "ls-files", "*.py"],
                        capture_output=True, text=True, timeout=20, env=build_scrubbed_env(),
                    )
                    for line in r.stdout.splitlines():
                        base = line.rsplit("/", 1)[-1]
                        index.setdefault(base, []).append(line)
                except (OSError, subprocess.TimeoutExpired):
                    index = {}
            hits = index.get(path.rsplit("/", 1)[-1], [])
            if len(hits) == 1:
                out.append(f"{hits[0]}::{rest}")
            else:
                out.append(nid)
        return out

    def _run_pytest_reruns(
        self,
        *,
        clean: list[str],
        wt: Path,
        env: dict[str, str],
        reruns: int,
        deadline: float | None,
    ) -> EvalResult:
        passes = fails = errors = 0
        last_detail = ""
        last_kind = "unknown"
        last_failure = ""
        for _ in range(max(1, reruns)):
            rem = remaining_budget(deadline)
            if rem < 0.05:
                errors += 1
                last_detail = "budget_exhausted"
                last_kind = "timeout"
                break
            run_timeout = min(float(self.per_run_timeout_sec), rem)
            junit_path = wt / ".sentinel-junit.xml"
            try:
                junit_path.unlink()
            except OSError:
                pass
            try:
                cmd = [
                    self.python,
                    "-m",
                    "pytest",
                    "-q",
                    "--tb=line",
                    "--no-header",
                    f"--junitxml={junit_path}",
                    *self._pytest_prefix,
                    "--",  # end of options — node ids cannot inject flags
                    *clean,
                ]
                rc, stdout, stderr = run_capped(
                    cmd, cwd=wt, env=env, timeout=run_timeout
                )
                label, kind, detail = classify_pytest_outcome(rc, stdout, stderr)
                label, kind, detail = _align_pytest_with_junit(label, kind, detail, junit_path, clean)
                blob = (stdout or "") + "\n" + (stderr or "")
                if label == "error" and _pytest_env_crash(blob):
                    kind = "env_setup"
                    detail = setup_error_quote(blob) or detail
                last_detail = detail
                last_kind = kind
                last_failure = "assertion" if label == "red" and _pytest_assertion(blob) else ""
                if label == "green":
                    passes += 1
                elif label == "red":
                    fails += 1
                else:
                    errors += 1
            except subprocess.TimeoutExpired:
                errors += 1
                last_detail = "timeout"
                last_kind = "timeout"
                # Hard wall-clock: do not continue reruns after a budget/timeout kill
                if remaining_budget(deadline) < 0.05:
                    break
            except OSError as e:
                return EvalResult(label="error", detail=f"os:{type(e).__name__}", kind="os")

        runs = passes + fails + errors
        if runs == 0:
            return EvalResult(label="error", detail="no_runs", kind="unknown")
        # Any error in the batch → overall error (ambiguous); do not call it red/flaky
        if errors:
            if passes == 0 and fails == 0:
                return EvalResult(
                    label="error",
                    passes=passes,
                    fails=fails,
                    runs=runs,
                    detail=last_detail,
                    kind=last_kind,
                )
            # Mixed error + pass/fail → still ambiguous
            return EvalResult(
                label="error",
                passes=passes,
                fails=fails,
                runs=runs,
                detail=last_detail or "ambiguous_with_errors",
                kind=last_kind or "unknown",
            )
        if passes == runs:
            return EvalResult(label="green", passes=passes, fails=fails, runs=runs, detail=last_detail, kind="pass")
        if fails == runs:
            return EvalResult(
                label="red", passes=passes, fails=fails, runs=runs,
                detail=last_detail, kind="fail", failure=last_failure,
            )
        return EvalResult(
            label="flaky",
            passes=passes,
            fails=fails,
            runs=runs,
            detail=last_detail,
            kind="mixed",
        )


@dataclass
class CommitRange:
    shas: list[str]
    total_count: int
    truncated: bool
    first_parent: bool
    # Set when git could not produce the range (unknown SHA, unfetched fork head,
    # shallow clone, timeout). An error is NEVER an empty range.
    error: str | None = None


def list_commits_between(
    repo: Path,
    good_sha: str,
    bad_sha: str,
    *,
    limit: int = MAX_COMMITS,
    first_parent: bool = True,
) -> CommitRange:
    """Commits after good_sha up to and including bad_sha (oldest first).

    Default ``first_parent=True`` for mainline triage.
    ``truncated`` is True only when total exceeds the safety ``limit`` (default 1000).
    confirm_culprit uses wall-clock budget (not a 64-commit hard abstain) to decide
    whether a range is feasible.
    """
    def failed(why: str) -> CommitRange:
        return CommitRange(shas=[], total_count=0, truncated=False, first_parent=first_parent,
                           error=_scrub_reason(why, max_len=160) or "git_error")

    for label, sha in (("good", good_sha), ("bad", bad_sha)):
        if not sha_in_repo(repo, sha):
            return failed(f"{label} SHA {str(sha)[:12]} not in this clone (unfetched fork head / deleted branch / shallow?)")
    try:
        cmd = ["git", "-C", str(repo), "rev-list", "--reverse"]
        if first_parent:
            cmd.append("--first-parent")
        cmd.append(f"{good_sha}..{bad_sha}")
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=build_scrubbed_env())
    except (OSError, subprocess.TimeoutExpired) as e:
        return failed(f"git rev-list {type(e).__name__}")
    if r.returncode != 0:
        tail = (r.stderr or "").strip().splitlines()[-1:] or [f"exit {r.returncode}"]
        return failed(f"git rev-list failed: {tail[0]}")
    shas = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
    total = len(shas)
    truncated = total > limit
    return CommitRange(
        shas=shas[:limit] if truncated else shas,
        total_count=total,
        truncated=truncated,
        first_parent=first_parent,
    )


def sha_in_repo(repo: Path, sha: str) -> bool:
    """True only if ``sha`` names a commit object present in this clone."""
    s = str(sha or "").strip()
    if not s or s.startswith("-") or not re.fullmatch(r"[0-9A-Za-z_./^~@{}\-]{1,200}", s):
        return False
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "-e", f"{s}^{{commit}}"],
            capture_output=True, text=True, timeout=15, env=build_scrubbed_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def _same_commit(a: str | None, b: str | None) -> bool:
    """True when two SHA strings name the same commit (full or unique prefix)."""
    if not a or not b:
        return False
    left, right = a.strip().lower(), b.strip().lower()
    if left == right:
        return True
    short, long = (left, right) if len(left) <= len(right) else (right, left)
    return len(short) >= 7 and long.startswith(short)


def _history_not_anchored(
    repo: Path,
    good_sha: str,
    bad_sha: str,
    commits: Sequence[str],
    *,
    first_parent: bool,
) -> str | None:
    """Why ``good`` is not the base of this range, or None when the range is anchored.

    ``git rev-list good..bad`` still returns commits when the two histories never
    meet (a force-push onto an orphan root, a rewritten branch). The oldest
    commit in that list is not a child of ``good``. Proving "parent passed" with
    that unrelated SHA as the parent blames a commit that did not regress
    ``good``. Walking one parent per commit in the range must land on ``good``.
    """
    n = len(commits)
    cur = str(bad_sha)
    for _ in range(n):
        nxt = parent_of(repo, cur, first_parent=first_parent)
        if not nxt:
            return (
                f"good {str(good_sha)[:12]} is not on the history of {str(bad_sha)[:12]} "
                "(unrelated history, force-push, or missing parent)"
            )
        cur = nxt
    if _same_commit(cur, str(good_sha)):
        return None
    return (
        f"good {str(good_sha)[:12]} is not the base of {str(bad_sha)[:12]} "
        f"(walked history base is {cur[:12]}; unrelated history or force-push)"
    )


def parent_of(repo: Path, sha: str, *, first_parent: bool = True) -> str | None:
    spec = f"{sha}^" if first_parent else f"{sha}^1"
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", spec],
            capture_output=True,
            text=True,
            timeout=15,
            env=build_scrubbed_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.strip() or None


_DOC_BASENAME = re.compile(
    r"(?i)^(readme|changelog|changes|history|license|copying|authors|contributing|code_of_conduct)(\.[a-z0-9]+)?$"
)


def _path_is_doc(path: str) -> bool:
    """True for a file that cannot, by itself, change what a test executes."""
    name = path.replace("\\", "/").lstrip("./")
    lower = name.lower()
    if lower.startswith("docs/") or "/docs/" in f"/{lower}":
        return True
    base = lower.rsplit("/", 1)[-1]
    if _DOC_BASENAME.match(base):
        return True
    return base.endswith((".md", ".markdown", ".rst", ".adoc"))


def culprit_diff_is_docs_only(repo: Path, parent: str, culprit: str) -> bool:
    """A green/red split on an empty or docs-only diff is not that commit.

    README-only noise can confirm 3/3 by chance when the test is flaky on
    every commit. An empty diff is the same fact. A code, test, or lockfile
    change still counts.
    """
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "diff", "--name-only", parent, culprit],
            capture_output=True,
            text=True,
            timeout=30,
            env=build_scrubbed_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if r.returncode != 0:
        return False
    files = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
    if not files:
        return True
    return all(_path_is_doc(f) for f in files)


def is_shallow_repo(repo: Path) -> bool:
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--is-shallow-repository"],
            capture_output=True,
            text=True,
            timeout=10,
            env=build_scrubbed_env(),
        )
        return r.returncode == 0 and r.stdout.strip().lower() == "true"
    except (OSError, subprocess.TimeoutExpired):
        return False


def confirm_culprit(
    *,
    repo: Path | str,
    good_sha: str,
    bad_sha: str,
    failing_tests: Sequence[str],
    runner: TestRunner | None = None,
    time_budget_sec: float = DEFAULT_TIME_BUDGET_SEC,
    step_budget: int = DEFAULT_STEP_BUDGET,
    flaky_reruns: int = DEFAULT_FLAKY_RERUNS,
    confirm_reruns: int | None = None,
    deadline: float | None = None,
    enabled: bool = True,
    first_parent: bool = True,
    max_commits: int = MAX_COMMITS,
    expected_commit_count: int | None = None,
) -> BisectResult:
    """Prove which commit introduced failing tests, or abstain honestly.

    ``expected_commit_count``: how many commits the card itself listed for this
    range. If the card saw commits but git gives none, that is a git problem
    (``inconclusive_git``), never "no code change".
    """
    reset_budget_credit()
    started = time.monotonic()
    # Hard wall-clock: never exceed time_budget_sec from start (even if deadline looser)
    hard_deadline = started + max(1.0, float(time_budget_sec))
    if deadline is None:
        deadline = hard_deadline
    else:
        deadline = min(deadline, hard_deadline)

    confirm_reruns = confirm_reruns if confirm_reruns is not None else flaky_reruns
    repo = Path(repo)

    if not enabled:
        return BisectResult(status="skipped", reason="confirm_culprit_disabled")

    # Runner-specific id validation (go / vitest / jest runners expose validate_ids);
    # pytest runners and fakes keep the original pytest node-id validation.
    _validator = getattr(runner, "validate_ids", None) if runner is not None else None
    if callable(_validator):
        tests, nerr = _validator(failing_tests)
    else:
        tests, nerr = validate_node_ids(failing_tests)
    if nerr:
        return BisectResult(
            status="not_proven",
            reason=nerr,
            failing_tests=list(failing_tests)[:5] if failing_tests else [],
            elapsed_sec=time.monotonic() - started,
        )

    own_runner = False
    if runner is None:
        runner = PytestGitRunner(repo=repo)
        own_runner = True

    evaluations: list[dict] = []
    steps = 0
    observed_run_sec: list[float] = []  # per single test run, from completed evals

    def timed_out() -> bool:
        return remaining_budget(deadline) <= 0

    def budget_left_steps() -> bool:
        return steps < step_budget

    def adaptive_reruns(requested: int) -> int:
        """Shrink reruns so the next eval cannot blow the remaining wall-clock."""
        rem = remaining_budget(deadline)
        if rem < 0.05:
            return 0
        per = 60.0
        if hasattr(runner, "per_run_timeout_sec"):
            try:
                per = float(runner.per_run_timeout_sec or 60.0)
            except (TypeError, ValueError):
                per = 60.0
        per = max(1.0, per)
        # Use the slowest single run actually observed (x1.5 + 2s margin) when that is
        # below the worst-case timeout, so a 300s timeout does not starve confirmation
        # reruns of a 20s test. Unobserved → worst case (the timeout).
        if observed_run_sec:
            per = max(1.0, min(per, max(observed_run_sec) * 1.5 + 2.0))
        # Full per-run slots remaining (avoid rem//rem==1 when rem≈per)
        slots = int(rem // per)
        if slots < 1:
            # Still allow a single attempt if any wall time remains
            return 1 if requested >= 1 else 0
        return max(1, min(int(requested), slots))

    def eval_sha(sha: str, *, reruns: int) -> EvalResult:
        nonlocal steps
        if timed_out() or not budget_left_steps():
            return EvalResult(label="error", detail="budget_exhausted", kind="timeout")
        actual = adaptive_reruns(reruns)
        if actual <= 0:
            return EvalResult(label="error", detail="budget_exhausted", kind="timeout")
        steps += 1
        _t0 = time.monotonic()
        _credit = budget_credit()
        # Support runners that ignore deadline kwarg (older fakes)
        try:
            er = runner.evaluate(sha, tests, reruns=actual, deadline=deadline)
        except TypeError:
            er = runner.evaluate(sha, tests, reruns=actual)
        _runs = int(getattr(er, "runs", 0) or 0)
        if _runs > 0 and er.label in ("green", "red", "flaky"):
            observed_run_sec.append(charged_seconds(_t0, _credit) / _runs)
        row = {
            "sha": sha,
            "label": er.label,
            "kind": er.kind,
            "passes": er.passes,
            "fails": er.fails,
            "runs": er.runs,
        }
        mode = str(getattr(runner, "install_mode", "") or "")
        if mode in ("non_frozen", "unlocked"):
            row["install_mode"] = mode
        evaluations.append(row)
        return er

    def finish(**kwargs) -> BisectResult:
        kwargs.setdefault("failing_tests", list(tests))
        kwargs.setdefault("steps_used", steps)
        kwargs.setdefault("elapsed_sec", time.monotonic() - started)
        kwargs.setdefault("evaluations", evaluations)
        modes = {
            item.get("install_mode")
            for item in evaluations
            if isinstance(item, dict) and item.get("install_mode") in ("non_frozen", "unlocked")
        }
        # An unlocked install is not a lockfile reproduce. Say that even when
        # another commit in the same search reused a frozen tree.
        recorded = "unlocked" if "unlocked" in modes else ("non_frozen" if "non_frozen" in modes else "")
        if recorded:
            evidence = str(kwargs.get("evidence") or "")
            prefix = f"install_mode: {recorded}"
            if prefix not in evidence:
                kwargs["evidence"] = (prefix + " " + evidence).strip()
        if "reason" in kwargs and kwargs["reason"]:
            kwargs["reason"] = _scrub_reason(kwargs["reason"])
        return BisectResult(**kwargs)

    def fidelity_stop(er: EvalResult) -> BisectResult | None:
        """A fallback that is not the commit's own install does not name a commit."""
        detail = er.detail or ""
        if er.label == "error" and (
            detail.startswith("install_unfaithful:") or detail.startswith("peer_deps_blocked:")
        ):
            reason = _scrub_reason(detail, max_len=180)
            return finish(status="inconclusive_env", reason=reason, evidence=reason)
        return None

    try:
        kind = str(getattr(runner, "kind_name", "") or "")
        if kind in ("dotnet", "junit"):
            from provebreak_culprit._engine.machine_preflight import CUSTOMER_LINE
            from provebreak_culprit._engine.machine_preflight import preflight_reason

            dotnet_bin = getattr(runner, "dotnet_bin", None) if kind == "dotnet" else None
            hit = preflight_reason(
                kind, repo, dotnet_bin=dotnet_bin, runner_env=getattr(runner, "env", None),
            )
            if hit:
                return finish(
                    status="not_proven",
                    reason=hit,
                    culprit_sha=None,
                    evidence=CUSTOMER_LINE,
                )
        if not good_sha or not bad_sha:
            return finish(status="not_proven", reason="missing_good_or_bad_sha")
        if timed_out():
            return finish(status="budget_exhausted", reason="time_budget_before_start")

        cr = list_commits_between(
            repo, good_sha, bad_sha, limit=max_commits, first_parent=first_parent
        )
        if cr.error:
            # The prefix is a hint that history is missing. A full clone that
            # failed for another reason does not get it.
            note = "shallow_clone;" if is_shallow_repo(repo) else ""
            return finish(
                status="inconclusive_git",
                reason=f"{note}commit range unavailable: {cr.error}",
            )
        if cr.truncated:
            return finish(
                status="not_proven",
                reason=(
                    f"commit_range_exceeds_max ({cr.total_count} > {max_commits}); "
                    "safety cap — not proven"
                ),
            )
        commits = cr.shas
        if not commits and expected_commit_count:
            return finish(
                status="inconclusive_git",
                reason=(
                    f"git lists no commits in {str(good_sha)[:12]}..{str(bad_sha)[:12]} but the card "
                    f"lists {int(expected_commit_count)}; not treating this as 'no code change'"
                ),
            )
        if not commits:
            return finish(
                status="outside_cause",
                reason="empty_commit_range",
            )
        anchor_err = _history_not_anchored(
            repo, good_sha, bad_sha, commits, first_parent=first_parent,
        )
        if anchor_err:
            return finish(status="inconclusive_git", reason=anchor_err)

        # Always evaluate the real tip (bad_sha), never a truncated stand-in
        if timed_out() or not budget_left_steps():
            return finish(status="budget_exhausted", reason="budget before tip check")

        tip_sha = bad_sha
        # --- Phase A: 1-run probe of tip + base (search cost model) ---
        # Search stays one run. A first probe that is not a stable red pays for
        # N re-runs at that same commit before any "not your commit" or
        # "outside the repo" sentence. N is at least the default confirmation
        # count, and higher when the workflow asked for more.
        SEARCH_RERUNS = 1
        witness_runs = max(int(confirm_reruns), DEFAULT_FLAKY_RERUNS)

        def totals(sha: str) -> tuple[int, int, int, set[str]]:
            passes = fails = runs = 0
            labels: set[str] = set()
            for ev in evaluations:
                if ev.get("sha") != sha:
                    continue
                passes += int(ev.get("passes") or 0)
                fails += int(ev.get("fails") or 0)
                runs += int(ev.get("runs") or 0)
                labels.add(str(ev.get("label") or ""))
            return passes, fails, runs, labels

        def mixed(passes: int, fails: int, labels: set[str]) -> bool:
            return "flaky" in labels or (passes > 0 and fails > 0) or ({"green", "red"} <= labels)

        def clean_prior_runs(sha: str, expect: str) -> int:
            """Runs already stored for sha that are uniformly ``expect``."""
            passes, fails, runs, labels = totals(sha)
            if runs <= 0 or labels != {expect}:
                return 0
            if expect == "red" and passes == 0 and fails == runs:
                return runs
            if expect == "green" and fails == 0 and passes == runs:
                return runs
            return 0

        def confirm_request(sha: str, expect: str) -> int:
            """Top up to confirm_reruns. One fresh run even when the search already has enough.

            One clean search hit counts, so a 3-run confirmation asks for 2 fresh
            runs. The fresh batch never drops below 2 when more than one run was
            requested: a worktree is cleaned between evaluations, and a one-run
            confirmation cannot show a flake that appears only inside one batch.
            """
            have = clean_prior_runs(sha, expect)
            if have <= 0 or confirm_reruns <= 1:
                return confirm_reruns
            topup = max(1, int(confirm_reruns) - have)
            # Keep a 2-run batch. A single fresh run cannot show a within-worktree flake.
            if confirm_reruns >= 2:
                return max(2, topup)
            return topup

        def witness(sha: str) -> EvalResult | None:
            """Re-run sha until it has witness_runs. None when that already happened.

            An error result is returned so the caller abstains instead of
            inventing a pass or a fail.
            """
            _passes, _fails, runs, _labels = totals(sha)
            if runs >= witness_runs:
                return None
            er = eval_sha(sha, reruns=witness_runs)
            if er.label == "error":
                return er
            return None

        tip_t0 = time.monotonic()
        tip_credit = budget_credit()
        tip = eval_sha(tip_sha, reruns=SEARCH_RERUNS)
        tip_elapsed = max(0.001, charged_seconds(tip_t0, tip_credit))
        if tip.label in ("flaky", "green"):
            err = witness(tip_sha)
            if err is not None:
                if err.kind == "timeout" or "budget_exhausted" in (err.detail or ""):
                    return finish(
                        status="budget_exhausted",
                        reason=f"tip {tip_sha[:12]} hit wall-clock budget during re-run",
                    )
                return finish(
                    status="not_proven",
                    reason=(
                        f"tip {tip_sha[:12]} not evaluable on re-run "
                        f"({err.kind or 'error'}: {_scrub_reason(err.detail, max_len=120)})"
                    ),
                )
            passes, fails, _runs, labels = totals(tip_sha)
            if mixed(passes, fails, labels):
                # The tip flipped. Re-run the base in its own fresh batch so the
                # card can show pass and fail counts on both commits.
                err = witness(good_sha)
                if err is not None:
                    if err.kind == "timeout" or "budget_exhausted" in (err.detail or ""):
                        return finish(
                            status="budget_exhausted",
                            reason=f"base {good_sha[:12]} hit wall-clock budget during re-run",
                        )
                    return finish(
                        status="not_proven",
                        reason=(
                            f"base {good_sha[:12]} not evaluable on re-run "
                            f"({err.kind or 'error'}: {_scrub_reason(err.detail, max_len=120)})"
                        ),
                    )
                b_passes, b_fails, _b_runs, _b_labels = totals(good_sha)
                return finish(
                    status="inconclusive_flaky",
                    reason=(
                        f"tip {tip_sha[:12]} disagreed on re-run ({passes} pass / {fails} fail); "
                        f"base {good_sha[:12]} re-ran {b_passes} pass / {b_fails} fail"
                    ),
                    parent_sha=good_sha,
                )
            if fails == 0 and "red" not in labels and "flaky" not in labels:
                # Stable pass on HEAD. The CI failure does not reproduce.
                # That is an abstain. It is not a flaky flip and it names no culprit.
                return finish(
                    status="not_proven",
                    reason=(
                        f"failure_does_not_reproduce_at_head: tip {tip_sha[:12]} passed; "
                        "the reported failure does not reproduce on HEAD"
                    ),
                )
            # The first probe was not stable. The re-runs are red, so keep searching.
        elif tip.label == "error":
            stopped = fidelity_stop(tip)
            if stopped is not None:
                return stopped
            if tip.detail == "filter_selected_no_tests":
                # The exact filter selected nothing at the bad commit, so the
                # named test did not fail there. That is not a culprit.
                return finish(
                    status="not_proven",
                    reason=(
                        f"filter_selected_no_tests: tip {tip_sha[:12]} "
                        "exact filter selected no tests, so the selected test did not fail"
                    ),
                )
            if tip.kind == "timeout" or "budget_exhausted" in (tip.detail or ""):
                return finish(
                    status="budget_exhausted",
                    reason=f"tip {tip_sha[:12]} hit wall-clock budget during eval",
                )
            if tip.kind == "build_error":
                loc = compiler_location(tip.detail)
                quoted = f"{loc}: " if loc and loc not in (tip.detail or "") else ""
                return finish(
                    status="inconclusive_build",
                    reason=(
                        f"tip {tip_sha[:12]} could not build/load the failing test locally "
                        f"({quoted}{_scrub_reason(tip.detail, max_len=120)})"
                    ),
                )
            if tip.kind == "env_setup":
                quote = setup_error_quote(tip.detail) or _scrub_reason(tip.detail, max_len=120)
                return finish(
                    status="inconclusive_env",
                    reason=f"setup_error: {quote}" if quote else "setup_error",
                )
            if tip.kind == "checkout_incomplete":
                return finish(
                    status="not_proven",
                    reason=(
                        f"tip {tip_sha[:12]} checkout is not what CI would test "
                        f"({_scrub_reason(tip.detail, max_len=160)})"
                    ),
                )
            if tip.kind == "unresolved_node_id":
                return finish(
                    status="not_proven",
                    reason=(
                        f"ci_node_id_did_not_resolve: tip {tip_sha[:12]} "
                        "the CI id did not match a single local test"
                    ),
                )
            # shallow_clone only when this checkout failed AND the clone is shallow.
            note = "shallow_clone;" if tip.kind == "checkout" and is_shallow_repo(repo) else ""
            return finish(
                status="not_proven",
                reason=(
                    f"{note}tip {tip_sha[:12]} not evaluable as failing test "
                    f"({tip.kind or 'error'}: {_scrub_reason(tip.detail, max_len=120)})"
                ),
            )

        if timed_out() or not budget_left_steps():
            return finish(status="budget_exhausted", reason="budget before base check")
        base_t0 = time.monotonic()
        base_credit = budget_credit()
        base = eval_sha(good_sha, reruns=SEARCH_RERUNS)
        base_elapsed = max(0.001, charged_seconds(base_t0, base_credit))
        base_missing_tests = False
        if base.label in ("red", "flaky"):
            # The last green commit failed or flipped on the first probe. Re-run
            # that same commit. All red: something outside the repo changed
            # (status stays inconclusive_env). A mix is not your commit. A
            # stable green means the first probe was not the verdict.
            err = witness(good_sha)
            if err is not None:
                if err.kind == "timeout" or "budget_exhausted" in (err.detail or ""):
                    return finish(
                        status="budget_exhausted",
                        reason=f"base {good_sha[:12]} hit wall-clock budget during re-run",
                    )
                return finish(
                    status="not_proven",
                    reason=(
                        f"base {good_sha[:12]} not evaluable on re-run "
                        f"({err.kind or 'error'}: {_scrub_reason(err.detail, max_len=120)})"
                    ),
                )
            passes, fails, _runs, labels = totals(good_sha)
            if mixed(passes, fails, labels):
                return finish(
                    status="inconclusive_flaky",
                    reason=(
                        f"base {good_sha[:12]} disagreed on re-run ({passes} pass / {fails} fail)"
                    ),
                    parent_sha=good_sha,
                )
            if fails > 0 and passes == 0 and "green" not in labels and "flaky" not in labels:
                # Status stays inconclusive_env. outside_cause is only an empty range.
                # parent_sha is the last green commit so the card can show its counts.
                # A package is attached only after a pin re-run; a failure here
                # leaves the outside-the-repo line unchanged.
                # The reason still quotes a shared setup error when both sides
                # failed for the same import/SQL cause (real-sweep abstain).
                upstream = _attribute_upstream(
                    repo=repo,
                    good_sha=good_sha,
                    bad_sha=bad_sha,
                    tests=list(tests),
                    runner=runner,
                    deadline=deadline,
                )
                return finish(
                    status="inconclusive_env",
                    reason=_shared_setup_reason(base.detail, tip.detail),
                    parent_sha=good_sha,
                    upstream=upstream,
                )
        elif base.label == "error":
            stopped = fidelity_stop(base)
            if stopped is not None:
                return stopped
            if base.kind == "timeout" or "budget_exhausted" in (base.detail or ""):
                return finish(
                    status="budget_exhausted",
                    reason=f"base {good_sha[:12]} hit wall-clock budget",
                )
            if base.kind == "build_error":
                return finish(
                    status="inconclusive_build",
                    reason=(
                        f"last green {good_sha[:12]} could not build locally "
                        f"({_scrub_reason(base.detail, max_len=120)})"
                    ),
                )
            if base.kind == "not_found":
                # The test file is absent on the declared good SHA. That is
                # soft-green for search (it did not fail yet). A later not_found
                # on the tip parent can be introduced_failing_test.
                base_missing_tests = True
                base_elapsed = max(0.05, base_elapsed)
            elif base.kind == "checkout_incomplete":
                return finish(
                    status="not_proven",
                    reason=(
                        f"base {good_sha[:12]} checkout is not what CI would test "
                        f"({_scrub_reason(base.detail, max_len=160)})"
                    ),
                )
            elif base.kind == "collection_error":
                # Collection crashed. The tests may already be in the tree and
                # already failing; we never saw them pass. That is not "new test".
                return finish(
                    status="not_proven",
                    reason=(
                        f"base {good_sha[:12]} collection failed; not treating that as a missing test "
                        f"({_scrub_reason(base.detail, max_len=120)})"
                    ),
                )
            else:
                return finish(
                    status="not_proven",
                    reason=(
                        f"base {good_sha[:12]} not evaluable ({base.kind or 'error'}: "
                        f"{_scrub_reason(base.detail, max_len=120)})"
                    ),
                )

        # Budget gate using split cost model (search cheap, tip confirms expensive)
        need, need_detail = estimate_remaining_seconds(
            n_commits=len(commits),
            tip_elapsed=tip_elapsed,
            base_elapsed=base_elapsed,
            confirm_reruns=confirm_reruns,
        )
        rem = remaining_budget(deadline)
        if need > rem:
            short = need - rem
            return finish(
                status="budget_exhausted",
                reason=(
                    f"insufficient_wall_clock_budget: {need_detail}; "
                    f"{rem:.1f}s left, would need ~{short:.1f}s more"
                ),
            )

        if commits[-1] != tip_sha and tip_sha not in commits:
            commits = list(commits) + [tip_sha]

        n = len(commits)
        tip_idx = commits.index(tip_sha) if tip_sha in commits else n - 1

        def eval_search(sha: str) -> EvalResult:
            """One-run search step."""
            return eval_sha(sha, reruns=SEARCH_RERUNS)

        tip_parent = good_sha if tip_idx == 0 else commits[tip_idx - 1]
        if timed_out() or not budget_left_steps():
            return finish(status="budget_exhausted", reason="budget before tip-parent check")
        tp = eval_search(tip_parent)
        # Commits that could not build (go/vitest/jest runners only). Never blamed,
        # never used as the green side of a proof; the search routes around them.
        unbuildable: set[int] = set()
        if tp.label == "error" and tp.kind == "build_error" and tip_idx > 0:
            unbuildable.add(tip_idx - 1)
        elif tp.label == "error" and tp.kind == "build_error":
            return finish(
                status="inconclusive_build",
                reason=f"tip parent {tip_parent[:12]} could not build",
            )
        elif tp.label == "error":
            stopped = fidelity_stop(tp)
            if stopped is not None:
                return stopped
            if tp.kind == "timeout" or "budget_exhausted" in (tp.detail or ""):
                return finish(status="budget_exhausted", reason=f"tip parent {tip_parent[:12]} budget")
            if tp.kind == "collection_error":
                return finish(
                    status="not_proven",
                    reason=(
                        f"tip parent {tip_parent[:12]} collection failed; "
                        "not treating that as a missing test "
                        f"({_scrub_reason(tp.detail, max_len=120)})"
                    ),
                )
            if tp.kind == "not_found":
                # Tip red + parent does not have the test ⇒ test introduced already failing
                if timed_out() or not budget_left_steps():
                    return finish(
                        status="budget_exhausted",
                        reason=(
                            f"tip parent missing tests; would need ~{confirm_reruns * tip_elapsed:.1f}s "
                            "more to confirm tip"
                        ),
                    )
                tip_conf = eval_sha(tip_sha, reruns=confirm_reruns)
                if tip_conf.label == "red":
                    return finish(**_new_test_kwargs(
                        repo, tip_sha, tip_parent, tests, tip_conf, tp.kind,
                    ))
                if tip_conf.label == "flaky":
                    return finish(
                        status="inconclusive_flaky",
                        reason=f"tip {tip_sha[:12]} flaky while parent missing tests",
                        parent_sha=tip_parent,
                    )
                return finish(
                    status="not_proven",
                    reason=(
                        f"tip parent {tip_parent[:12]} missing tests ({tp.kind}) but tip "
                        f"not stably red ({tip_conf.label})"
                    ),
                )
            return finish(
                status="not_proven",
                reason=f"tip parent {tip_parent[:12]} eval error ({tp.kind})",
            )
        # flaky impossible with 1 run from PytestGitRunner; FakeRunner may still emit it
        if tp.label == "flaky":
            return finish(
                status="inconclusive_flaky",
                reason=f"tip parent {tip_parent[:12]} flaky",
                parent_sha=tip_parent,
            )

        if tp.label == "green":
            culprit_idx = tip_idx
            parent = tip_parent
        else:
            lo = 0
            hi = tip_idx
            while lo < hi:
                if timed_out() or not budget_left_steps():
                    return finish(
                        status="budget_exhausted",
                        reason=(
                            f"stopped with range [{commits[lo][:12]}..{commits[hi][:12]}]; "
                            f"wall left {remaining_budget(deadline):.1f}s, "
                            f"would need ~{max(0.0, tip_elapsed * max(1, hi - lo)):.1f}s more"
                        ),
                    )
                mid = lo if (hi - lo + 1) <= BISECT_LINEAR_THRESHOLD else (lo + hi) // 2
                if unbuildable:
                    cands = [i for i in range(lo, hi) if i not in unbuildable]
                    if not cands:
                        return finish(
                            status="inconclusive_build",
                            reason=(
                                f"first failing commit is in [{commits[lo][:12]}..{commits[hi][:12]}] "
                                "but the commits in between could not build; not proven"
                            ),
                        )
                    mid = min(cands, key=lambda i: (abs(i - mid), i))
                er = eval_search(commits[mid])
                if er.label == "flaky":
                    return finish(
                        status="inconclusive_flaky",
                        reason=f"commit {commits[mid][:12]} inconclusive during search",
                    )
                if er.label == "error":
                    stopped = fidelity_stop(er)
                    if stopped is not None:
                        return stopped
                    if er.kind == "timeout" or "budget_exhausted" in (er.detail or ""):
                        return finish(
                            status="budget_exhausted",
                            reason=(
                                f"search hit budget at {commits[mid][:12]}; "
                                f"would need ~{tip_elapsed:.1f}s more per remaining step"
                            ),
                        )
                    if er.kind == "build_error":
                        unbuildable.add(mid)
                        continue
                    if er.kind == "not_found":
                        # Test not present yet ⇒ behave like green for first-bad search
                        lo = mid + 1
                        continue
                    if er.kind == "collection_error":
                        return finish(
                            status="not_proven",
                            reason=(
                                f"collection failed at {commits[mid][:12]}; boundary unclear "
                                f"({_scrub_reason(er.detail, max_len=120)})"
                            ),
                        )
                    return finish(
                        status="not_proven",
                        reason=f"eval error at {commits[mid][:12]} ({er.kind})",
                    )
                if er.label == "red":
                    hi = mid
                else:
                    lo = mid + 1
            culprit_idx = lo
            parent = good_sha if culprit_idx == 0 else commits[culprit_idx - 1]

            # Monotonicity spot-check (1 run); contradiction → confirm-rerun that step
            need_repair = False
            if culprit_idx < tip_idx:
                mid_i = (culprit_idx + tip_idx) // 2
                if mid_i in unbuildable:
                    alts = [i for i in range(culprit_idx + 1, tip_idx) if i not in unbuildable]
                    mid_i = min(alts, key=lambda i: (abs(i - mid_i), i)) if alts else culprit_idx
                if mid_i > culprit_idx:
                    if timed_out() or not budget_left_steps():
                        return finish(status="budget_exhausted", reason="budget during monotonicity check")
                    mid_er = eval_search(commits[mid_i])
                    if mid_er.label == "green":
                        need_repair = True
                    elif mid_er.label == "flaky":
                        return finish(
                            status="inconclusive_flaky",
                            reason=f"mid {commits[mid_i][:12]} flaky during monotonicity check",
                        )
                    elif mid_er.label == "error":
                        stopped = fidelity_stop(mid_er)
                        if stopped is not None:
                            return stopped
                        return finish(
                            status="inconclusive_build" if mid_er.kind == "build_error" else "not_proven",
                            reason=f"mid {commits[mid_i][:12]} eval error ({mid_er.kind})",
                        )
                    elif mid_er.label == "red":
                        # Consistent with red suffix — ok
                        pass
            if need_repair:
                found = False
                for i in range(tip_idx, culprit_idx - 1, -1):
                    if timed_out() or not budget_left_steps():
                        break
                    p_sha = good_sha if i == 0 else commits[i - 1]
                    cached = {e["sha"]: e["label"] for e in evaluations}
                    p_lab = cached.get(p_sha)
                    c_lab = cached.get(commits[i])
                    if p_lab is None:
                        er = eval_search(p_sha)
                        stopped = fidelity_stop(er)
                        if stopped is not None:
                            return stopped
                        if er.label in ("flaky", "error"):
                            return finish(
                                status="inconclusive_flaky" if er.label == "flaky" else (
                                    "inconclusive_build" if er.kind == "build_error" else "not_proven"),
                                reason=f"repair walk {p_sha[:12]}: {er.label}",
                            )
                        p_lab = er.label
                    if c_lab is None:
                        er = eval_search(commits[i])
                        stopped = fidelity_stop(er)
                        if stopped is not None:
                            return stopped
                        if er.label in ("flaky", "error"):
                            return finish(
                                status="inconclusive_flaky" if er.label == "flaky" else (
                                    "inconclusive_build" if er.kind == "build_error" else "not_proven"),
                                reason=f"repair walk {commits[i][:12]}: {er.label}",
                            )
                        c_lab = er.label
                    if p_lab == "green" and c_lab == "red":
                        # Confirm this edge with flake reruns (contradicted earlier monotonicity)
                        if timed_out() or not budget_left_steps():
                            return finish(status="budget_exhausted", reason="budget confirming repair edge")
                        p_conf = eval_sha(p_sha, reruns=confirm_reruns)
                        c_conf = eval_sha(commits[i], reruns=confirm_reruns)
                        if p_conf.label == "green" and c_conf.label == "red":
                            culprit_idx = i
                            parent = p_sha
                            found = True
                            break
                        return finish(
                            status="not_proven",
                            reason=(
                                f"non-monotonic edge {p_sha[:12]}→{commits[i][:12]} "
                                f"unstable under confirmation ({p_conf.label}/{c_conf.label})"
                            ),
                        )
                if not found:
                    return finish(
                        status="not_proven",
                        reason="non-monotonic history; green→red edge near tip not confirmed",
                    )

        culprit = commits[culprit_idx]

        # --- Phase B: flake-confirmation reruns on parent + culprit only ---
        # The search already ran each side once. Those runs count, so a
        # 3-run confirmation asks for 2 fresh runs instead of 3.
        parent_req = confirm_request(parent, "green")
        cul_req = confirm_request(culprit, "red")
        if timed_out() or steps + 2 > step_budget:
            return finish(
                status="not_proven",
                reason=(
                    f"candidate {culprit[:12]} found but confirmation budget exhausted "
                    f"(would need ~{(parent_req * max(0.05, base_elapsed) + cul_req * tip_elapsed):.1f}s more)"
                ),
                culprit_sha=culprit,
                parent_sha=parent,
            )

        parent_er = eval_sha(parent, reruns=parent_req)
        cul_er = eval_sha(culprit, reruns=cul_req)

        if (
            parent_er.label == "error"
            and parent_er.kind == "collection_error"
            and cul_er.label == "red"
        ):
            return finish(
                status="not_proven",
                reason=(
                    f"parent {parent[:12]} collection failed; not a missing test "
                    f"({_scrub_reason(parent_er.detail, max_len=120)})"
                ),
                culprit_sha=culprit,
                parent_sha=parent,
            )
        if (
            parent_er.label == "error"
            and parent_er.kind == "not_found"
            and cul_er.label == "red"
        ):
            return finish(**_new_test_kwargs(
                repo, culprit, parent, tests, cul_er, parent_er.kind,
            ))

        def _reverify_boundary() -> tuple[EvalResult, EvalResult] | BisectResult:
            """If confirmation disagrees, one local re-check; abstain if still unclear."""
            if timed_out() or not budget_left_steps():
                return finish(
                    status="budget_exhausted",
                    reason=(
                        f"confirmation disagreed; would need ~{tip_elapsed:.1f}s more to re-verify"
                    ),
                    culprit_sha=culprit,
                    parent_sha=parent,
                )
            p2 = eval_sha(parent, reruns=max(1, min(2, confirm_reruns)))
            c2 = eval_sha(culprit, reruns=max(1, min(2, confirm_reruns)))
            if p2.label == "green" and c2.label == "red":
                return (p2, c2)
            return finish(
                status="not_proven",
                reason=(
                    f"confirmation disagreed (parent={parent_er.label}/{p2.label}, "
                    f"culprit={cul_er.label}/{c2.label}); boundary unclear — not proven"
                ),
                culprit_sha=culprit,
                parent_sha=parent,
            )

        # A search hit that the fresh batch contradicts is a flake. Do not
        # re-verify that into a proof.
        p_passes, p_fails, _p_runs, p_labels = totals(parent)
        c_passes, c_fails, _c_runs, c_labels = totals(culprit)
        if (
            parent_er.label == "flaky"
            or cul_er.label == "flaky"
            or mixed(p_passes, p_fails, p_labels)
            or mixed(c_passes, c_fails, c_labels)
        ):
            return finish(
                status="inconclusive_flaky",
                reason=(
                    f"flaky at confirmation "
                    f"(parent={parent_er.label}, culprit={cul_er.label})"
                ),
                parent_sha=parent,
            )

        if parent_er.label != "green" or cul_er.label != "red":
            rev = _reverify_boundary()
            if isinstance(rev, BisectResult):
                return rev
            parent_er, cul_er = rev

        # Search probes count. A later confirm that flips the other way is a
        # flake, even when the fresh batch itself is uniform.
        p_passes, p_fails, _p_runs, p_labels = totals(parent)
        c_passes, c_fails, c_runs, c_labels = totals(culprit)
        if mixed(p_passes, p_fails, p_labels) or mixed(c_passes, c_fails, c_labels):
            return finish(
                status="inconclusive_flaky",
                reason=(
                    f"flaky at confirmation "
                    f"(parent={parent_er.label}, culprit={cul_er.label})"
                ),
                parent_sha=parent,
            )

        if culprit_diff_is_docs_only(repo, parent, culprit):
            return finish(
                status="inconclusive_flaky",
                reason=(
                    f"candidate {culprit[:12]} does not change code under test "
                    f"(docs-only or empty diff against {parent[:12]}); not blaming it"
                ),
                parent_sha=parent,
            )

        evidence = (
            f"failing test {', '.join(tests[:3])} passes on parent {parent[:12]}, "
            f"fails on {culprit[:12]}, reproduced {c_fails}/{c_runs} times"
        )
        return finish(
            status="proven",
            culprit_sha=culprit,
            parent_sha=parent,
            reproductions=c_fails,
            reproduction_attempts=c_runs,
            evidence=evidence,
        )
    except Exception as e:  # noqa: BLE001
        return BisectResult(
            status="error",
            reason=_scrub_reason(type(e).__name__),
            failing_tests=list(tests),
            steps_used=steps,
            elapsed_sec=time.monotonic() - started,
            evaluations=evaluations,
        )
    finally:
        if own_runner and hasattr(runner, "cleanup"):
            try:
                runner.cleanup()  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                pass


_LOG_GH_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z ?")
_LOG_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_LOG_WF = re.compile(r"^##\[[A-Za-z]+\]\s?")
_LOG_CI_ROOT = re.compile(r"^(?:/home/runner/work/[^/]+/[^/]+/|/__w/[^/]+/[^/]+/)")
# ``file.py:line:`` counts even when nothing follows the colon. Pytest -q prints
# the test frame that way (``tests/test_calc.py:5: ``) before a helper frame.
_LOG_QUIET_LOC = re.compile(r"^(\S+\.py):\d+:\s*(.*)$")
_LOG_IN_FUNC = re.compile(r"^in\s+(\S+)\s*$")
_LOG_UNITTEST = re.compile(r"^(?:FAIL|ERROR):\s+(test[A-Za-z0-9_]+)\s+\(([\w.]+)\)\s*$")
_LOG_UNITTEST_FILE = re.compile(r'File "([^"]+\.py)", line \d+, in (test[A-Za-z0-9_]+)\s*$')
_LOG_UNITTEST_OK = re.compile(r"^OK(?:\s*\(.*\))?\s*$")
_LOG_UNITTEST_FAILED = re.compile(r"^FAILED\s+\((.*)\)\s*$")
# Quiet progress (``F``, ``.``, ``FF [100%]``, ``tests/test_a.py .``). Not a
# verbose ``file.py::test FAILED [ 50%]`` line.
_LOG_PY_PROGRESS = re.compile(
    r"^(?:[FEsxXpP.]{1,}|\S+\.py\s+[FEsxXpP.])(?:\s+\[\s*\d+%\])?\s*$"
)
_LOG_PY_COUNT = re.compile(
    r"^(?:=+\s*)?(?:(\d+)\s+failed(?:\s*,\s*|\s+))?(?:(\d+)\s+passed(?:\s*,\s*|\s+))?.*?\bin\s+[\d.]+s\s*(?:=+)?\s*$"
)
# Short-summary lines: "FAILED <nodeid>[ - msg]" / "ERROR <nodeid>[ - msg]".
_LOG_SUMMARY = re.compile(r"^(?:FAILED|ERROR) +(\S+?\.py::.*)$")
# FAILURES/ERRORS section header: "_____ name _____" or "_____ ERROR at setup of name _____".
_LOG_HEADER = re.compile(r"^_{3,} +(?:ERROR at \w+ of )?(.+?) +_{3,}$")
# Verbose status line (used only to resolve bare-name headers; never a source on its own).
_LOG_VERBOSE_FAIL = re.compile(r"^(\S+?\.py::.+?) +(?:FAILED|ERROR)(?: +\[ *\d+%\])?$")


def _take_node_id(text: str) -> str | None:
    """Read a node id from the start of *text*; spaces allowed only inside [...]."""
    depth = 0
    for i, c in enumerate(text):
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth < 0:
                return None
        elif c.isspace() and depth == 0:
            return text[:i]
    return text if depth == 0 else None


def _clean_pytest_line(raw: str) -> str:
    return _clean_pytest_keep(raw).rstrip()


def _clean_pytest_keep(raw: str) -> str:
    """Like ``_clean_pytest_line`` but keep trailing spaces.

    A pytest exception line is ``E`` plus two spaces. A blank one rstrips to
    ``E``, which is also a quiet progress character.
    """
    line = raw.lstrip("\ufeff")
    for _ in range(4):
        nxt = _LOG_WF.sub("", _LOG_GH_TS.sub("", _LOG_ANSI.sub("", line)))
        if nxt == line:
            break
        line = nxt
    return line.rstrip("\r")


def _is_py_progress(kept: str) -> bool:
    """Quiet progress, not an ``E  `` exception line."""
    if re.match(r"^E(?:[ \t]|$)", kept) and not re.search(r"\[\s*\d+%\]\s*$", kept):
        if kept != "E":
            return False
    return bool(_LOG_PY_PROGRESS.match(kept.strip()))


def _relative_py(path: str) -> str | None:
    text = (path or "").strip().replace("\\", "/")
    text = _LOG_CI_ROOT.sub("", text)
    if text.startswith("./"):
        text = text[2:]
    if not text or text.startswith("/") or ".." in text.split("/") or "site-packages" in text:
        return None
    if not _NODE_ID_PATH.match(text):
        return None
    return text


def _pytest_failed_count(line: str) -> int | None:
    """Failed-count from a pytest summary line, or None when it is not one.

    ``2 failed in 0.01s`` is 2. ``1 failed, 1 passed in 0.01s`` is 1.
    ``1 passed in 0.01s`` is 0. A libtest ``finished in`` line is not a count.
    """
    text = line.strip()
    if "test result:" in text or "finished in" in text:
        return None
    matched = _LOG_PY_COUNT.match(text)
    if not matched or (matched.group(1) is None and matched.group(2) is None):
        return None
    if "failed" not in text and "passed" not in text:
        return None
    if matched.group(1) is not None:
        return int(matched.group(1))
    return 0


def _unittest_failure_total(line: str) -> int | None:
    matched = _LOG_UNITTEST_FAILED.match(line.strip())
    if not matched:
        return None
    total = 0
    seen = False
    for key in ("failures", "errors"):
        count = re.search(rf"{key}=(\d+)", matched.group(1))
        if count:
            seen = True
            total += int(count.group(1))
    return total if seen else None


def _norm_pytest_header(head: str) -> str:
    if "[" in head:
        name, _, param = head.partition("[")
        return name.replace(".", "::") + "[" + param
    return head.replace(".", "::")


def pytest_summary_gate(lines: list[str], ids: list[str]) -> tuple[list[str], str | None]:
    """Pass, count, and FAILURES-header checks for ids another parser already found."""
    progress_at = -1
    counts: list[tuple[int, int]] = []
    for i, ln in enumerate(lines):
        if _is_py_progress(ln):
            progress_at = i
        count = _pytest_failed_count(ln)
        if count is not None:
            counts.append((i, count))
    if len(counts) > 1:
        return [], "test_ids_multiple_summaries"
    failed_n = counts[0][1] if counts else None
    count_at = counts[0][0] if counts else -1
    if failed_n and failed_n > 0 and any(_LOG_SUMMARY.match(ln.strip()) for ln in lines[count_at + 1:]):
        return [], "test_ids_multiple_summaries"
    session = lines[progress_at + 1:] if progress_at >= 0 else lines
    unit_n = None
    saw_unit = False
    headers: list[str] = []
    summaries: list[str] = []
    for ln in session:
        text = ln.strip()
        if _LOG_UNITTEST.match(text) or text.startswith("Ran "):
            saw_unit = True
        if _LOG_UNITTEST_OK.match(text):
            unit_n = 0
        total = _unittest_failure_total(text)
        if total is not None:
            unit_n = total
        header = _LOG_HEADER.match(text)
        if header and ".py::" not in header.group(1):
            headers.append(_norm_pytest_header(header.group(1).strip()))
        summary = _LOG_SUMMARY.match(text)
        if summary:
            nid = _take_node_id(summary.group(1).strip())
            if nid and ".py::" in nid:
                summaries.append(nid.split(".py::", 1)[1])
    if failed_n == 0 or (failed_n is None and unit_n == 0 and saw_unit):
        return [], "summary_reports_pass"
    if headers and summaries and set(headers) != set(summaries):
        return [], "test_ids_result_disagreed"
    count = failed_n if failed_n is not None else unit_n
    if count is None:
        if ids or headers or summaries or any(re.match(r"^=+\s*(?:FAILURES|ERRORS)\s*=+$", ln.strip()) for ln in session):
            return [], "test_ids_no_summary"
        return [], None
    if len(ids) != count:
        return [], "test_ids_count_mismatch"
    return list(ids), None


def _ids_from_quiet_pytest_or_unittest(lines: list[str]) -> tuple[list[str], str | None]:
    """Pytest ``-q`` sections and unittest failures, with a named abstain.

    A header is used only when every location file is the test's own file: an
    empty ``file.py:line:`` frame or ``in <test>``, or one failure line in that
    same file. A helper ``in check`` frame is not that file. Two sections that
    share a header abstain ``test_ids_duplicate_header``. A truncated name is
    ``test_ids_truncated``. Two files or a helper-only frame is
    ``test_ids_ambiguous_location``. One bad section drops the rest.
    """
    found: list[str] = []
    reason: str | None = None
    headers: list[str] = []
    in_fail = False
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.match(r"^=+\s*(?:FAILURES|ERRORS)\s*=+$", line):
            in_fail = True
            i += 1
            continue
        if line.startswith("===="):
            in_fail = False
        header = _LOG_HEADER.match(line) if in_fail else None
        unit = _LOG_UNITTEST.match(line.strip())
        if header and ".py::" not in header.group(1):
            head = header.group(1).strip()
            headers.append(head)
            block: list[str] = []
            i += 1
            while i < len(lines) and not _LOG_HEADER.match(lines[i]) and not lines[i].startswith("===="):
                block.append(lines[i])
                i += 1
            nid, err = _id_from_quiet_header(head, block)
            if err:
                reason = err if reason is None else reason
            elif nid and nid not in found:
                found.append(nid)
            continue
        if unit:
            block = []
            i += 1
            while i < len(lines) and not _LOG_UNITTEST.match(lines[i].strip()) and not lines[i].startswith("===="):
                block.append(lines[i])
                i += 1
            nid, err = _id_from_unittest(unit.group(1), unit.group(2), block)
            if err:
                reason = err if reason is None else reason
            elif nid and nid not in found:
                found.append(nid)
            continue
        i += 1
    if len(headers) != len(set(headers)):
        return [], "test_ids_duplicate_header"
    if reason:
        return [], reason
    return found, None


def _id_from_quiet_header(head: str, block: list[str]) -> tuple[str | None, str | None]:
    if not head or "…" in head or head.endswith("..."):
        return None, "test_ids_truncated"
    if head.count("[") != head.count("]"):
        return None, "test_ids_truncated"
    locs: list[tuple[str, str]] = []
    for ln in block:
        matched = _LOG_QUIET_LOC.match(ln.strip())
        if not matched:
            continue
        rel = _relative_py(matched.group(1))
        if rel is None:
            return None, "test_ids_ambiguous_location"
        locs.append((rel, matched.group(2).strip()))
    if "[" in head:
        name, _, param = head.partition("[")
        suffix = name.replace(".", "::") + "[" + param
        method = name.split(".")[-1]
    else:
        suffix = head.replace(".", "::")
        method = head.split(".")[-1]
    if not re.fullmatch(r"test[A-Za-z0-9_]+", method):
        return None, "test_ids_ambiguous_location"
    if not any(re.search(rf"\bdef\s+{re.escape(method)}\b", ln) for ln in block):
        return None, "test_ids_ambiguous_location"
    if not locs:
        return None, "test_ids_ambiguous_location"
    own: list[str] = []
    helper = False
    for rel, msg in locs:
        called = _LOG_IN_FUNC.match(msg)
        if msg == "" or (called and called.group(1) == method):
            own.append(rel)
        elif called:
            helper = True
    files = list(dict.fromkeys(rel for rel, _msg in locs))
    own_files = list(dict.fromkeys(own))
    if own_files:
        if len(own_files) != 1 or any(rel != own_files[0] for rel in files):
            return None, "test_ids_ambiguous_location"
        file = own_files[0]
    elif helper or len(files) != 1:
        return None, "test_ids_ambiguous_location"
    else:
        file = files[0]
    clean, err = validate_node_ids([f"{file}::{suffix}"])
    if err or not clean:
        return None, "test_ids_ambiguous_location"
    return clean[0], None


def _id_from_unittest(method: str, qual: str, block: list[str]) -> tuple[str | None, str | None]:
    if "…" in method or "…" in qual or method.endswith("...") or qual.endswith("..."):
        return None, "test_ids_truncated"
    parts = [part for part in qual.split(".") if part]
    if len(parts) >= 3 and parts[-1] == method and parts[-2][:1].isupper():
        class_name = parts[-2]
        module = ".".join(parts[:-2])
    elif len(parts) >= 2 and parts[-1][:1].isupper():
        class_name = parts[-1]
        module = ".".join(parts[:-1])
    else:
        return None, "test_ids_ambiguous_location"
    if not module or not re.fullmatch(r"test[A-Za-z0-9_]+", method):
        return None, "test_ids_ambiguous_location"
    expect = module.replace(".", "/") + ".py"
    if not _relative_py(expect):
        return None, "test_ids_ambiguous_location"
    files: list[str] = []
    disagreed = False
    for ln in block:
        matched = _LOG_UNITTEST_FILE.search(ln)
        if not matched:
            continue
        if matched.group(2) != method:
            disagreed = True
            continue
        rel = _relative_py(matched.group(1))
        if rel is None or rel != expect:
            disagreed = True
            continue
        files.append(rel)
    if disagreed or len(set(files)) != 1:
        return None, "test_ids_ambiguous_location"
    clean, err = validate_node_ids([f"{expect}::{class_name}::{method}"])
    if err or not clean:
        return None, "test_ids_ambiguous_location"
    return clean[0], None


@dataclass
class PytestLog:
    ids: list[str]
    error: str | None = None


def _py_done(log_text: str, ids: list[str], error: str | None) -> PytestLog:
    from provebreak_culprit._engine.summary_gate import finish

    kept, err = finish("pytest", log_text, ids, error)
    return PytestLog(kept, err)


def extract_pytest_log(log_text: str, *, limit: int = 20) -> PytestLog:
    """Pytest ids, or a named abstain when the log does not prove them.

    A ``FAILED``/``ERROR`` line, a ``FAILURES`` section, or a unittest ``FAIL``
    printed before the last quiet progress mark is the test's own stdout, not
    the session report. Ids kept from the session must match the pytest failed
    count when that line is present, and a unittest ``OK`` does not confirm a
    ``FAIL`` block. A mismatch is ``test_ids_result_disagreed`` and yields no
    ids. Ambiguous quiet sections use ``test_ids_duplicate_header``,
    ``test_ids_truncated``, or ``test_ids_ambiguous_location``.
    """
    if not log_text:
        return _py_done(log_text, [], None)
    keeps = [_clean_pytest_keep(raw) for raw in log_text.splitlines()]
    from provebreak_culprit._engine.summary_gate import _mask

    keeps, err = _mask("pytest", keeps)
    if err:
        return _py_done(log_text, [], err)
    lines = [ln.rstrip() for ln in keeps]
    progress_at = -1
    count_at = -1
    failed_n: int | None = None
    for i, ln in enumerate(lines):
        if _is_py_progress(keeps[i]):
            progress_at = i
        count = _pytest_failed_count(ln)
        if count is not None:
            count_at = i
            failed_n = count

    def in_session(index: int) -> bool:
        return progress_at < 0 or index > progress_at

    found: list[str] = []
    extra: list[str] = []
    seen: set[str] = set()

    def add(bucket: list[str], nid: str | None) -> None:
        if not nid:
            return
        clean, err = validate_node_ids([nid])
        if err or not clean or clean[0] in seen:
            return
        seen.add(clean[0])
        bucket.append(clean[0])

    for i, ln in enumerate(lines):
        if not in_session(i):
            continue
        matched = _LOG_SUMMARY.match(ln)
        if not matched:
            continue
        bucket = extra if count_at >= 0 and i > count_at else found
        add(bucket, _take_node_id(matched.group(1)))

    reason: str | None = None
    if not found and not extra:
        session = [ln for i, ln in enumerate(lines) if in_session(i) and (count_at < 0 or i <= count_at)]
        verbose_failed: list[str] = []
        for ln in session:
            matched = _LOG_VERBOSE_FAIL.match(ln)
            if matched:
                verbose_failed.append(matched.group(1))
        for ln in session:
            matched = _LOG_HEADER.match(ln)
            if not matched:
                continue
            head = matched.group(1).strip()
            if ".py::" in head:
                nid = _take_node_id(head)
                if nid == head:
                    add(found, nid)
                continue
            tail = "::" + head.replace(".", "::") if "[" not in head else None
            if tail is None:
                name, _, param = head.partition("[")
                tail = "::" + name.replace(".", "::") + "[" + param
            matches = sorted({item for item in verbose_failed if item.endswith(tail)})
            if len(matches) == 1:
                add(found, matches[0])
        if not found:
            quiet, reason = _ids_from_quiet_pytest_or_unittest(session)
            for nid in quiet:
                add(found, nid)

    if reason and not found and not extra:
        return _py_done(log_text, [], reason)
    kept = (found + extra)[:limit]
    return _py_done(log_text, kept, None)


def extract_failing_tests_from_log(log_text: str, *, limit: int = 20) -> list[str]:
    """Best-effort parse of a pytest log for FAILED/ERROR node ids.

    Sources, in order: ``FAILED``/``ERROR`` short-summary lines, then
    ``____ name ____`` FAILURES/ERRORS section headers (full node id, or a bare
    name resolved against that test's own verbose ``FAILED``/``ERROR`` line).
    When those are absent, a quiet ``FAILURES`` header with one relative
    ``file.py:line`` (including an empty message) and a matching ``def``, or a
    unittest ``FAIL``/``ERROR`` whose traceback file is that module. A
    truncated name, two headers, a helper location, or a summary that
    disagrees yields no ids. Verbose ``PASSED`` lines and bare node ids are
    never treated as failures. ``extract_pytest_log`` reports the named reason.
    """
    return extract_pytest_log(log_text, limit=limit).ids


def _attribute_upstream(
    *,
    repo: Path,
    good_sha: str,
    bad_sha: str,
    tests: list[str],
    runner: TestRunner,
    deadline: float | None,
) -> dict | None:
    """Outside-the-repo package lookup. Never changes the status and never raises."""
    try:
        from provebreak_culprit._engine.upstream import attribute

        log_text = str(getattr(runner, "log_text", "") or "")
        if not log_text:
            log_path = os.environ.get("SENTINEL_RUNNER_LOG") or ""
            if log_path and "\n" not in log_path and len(log_path) < 400:
                try:
                    p = Path(log_path)
                    if p.is_file() and p.stat().st_size <= 2_000_000:
                        log_text = p.read_text(encoding="utf-8", errors="replace")[:500_000]
                except OSError:
                    log_text = ""
        return attribute(
            repo=repo,
            good_sha=good_sha,
            bad_sha=bad_sha,
            tests=tests,
            runner=runner,
            deadline=deadline,
            log_text=log_text,
        )
    except Exception:  # noqa: BLE001
        return None


def confirm_culprit_safe(**kwargs) -> BisectResult:
    """Public fail-soft wrapper — never raises."""
    try:
        return confirm_culprit(**kwargs)
    except Exception as e:  # noqa: BLE001
        return BisectResult(status="error", reason=_scrub_reason(type(e).__name__))
