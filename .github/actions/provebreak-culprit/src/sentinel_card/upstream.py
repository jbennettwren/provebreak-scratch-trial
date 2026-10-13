"""Attribute a stably red last-green commit to a change outside the repo.

Lookups are metadata only: ``pip index versions``, ``npm view <pkg> time``,
the Go module proxy, lockfile text, and the runner image line in logs.
Package names and versions travel in argv or in a GET. Repository source is
never posted, and redirects are refused. A package is "proven" only when a
re-run passes with the old pin and fails with the new pin. Anything short of
that stays "likely", or is dropped when the re-run disproves it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from datetime import timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.error import URLError
from urllib.parse import unquote
from urllib.parse import urlparse
from urllib.request import build_opener
from urllib.request import HTTPRedirectHandler
from urllib.request import Request

ARROW = "\u2192"
_PROVEN = "Your code didn't change. {pkg} {old}" + ARROW + "{new} (released {date}) broke {test}."
_LIKELY = "Your code didn't change. Likely {pkg} {old}" + ARROW + "{new} (released {date}). Not proven by a re-run."
_LIKELY_NODATE = "Your code didn't change. Likely {pkg} {old}" + ARROW + "{new}. Not proven by a re-run."
_LIKELY_RUNNER = "Your code didn't change. Likely the runner image changed ({old}" + ARROW + "{new}). Not proven by a re-run."
_LIKELY_ACTION = "Your code didn't change. Likely {pkg} resolves 'latest'. Not proven by a re-run."
_LIKELY_DOCKER = "Your code didn't change. Likely {pkg} uses a floating tag. Not proven by a re-run."

_PKG = re.compile(r"^[A-Za-z0-9_.@/-]{1,120}$")
_VER = re.compile(r"^v?[0-9A-Za-z._+-]{1,40}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_KINDS = frozenset({"python", "npm", "go", "runner", "action", "docker"})
_PUBLIC_HOSTS = frozenset({
    "pypi.org",
    "files.pythonhosted.org",
    "pypi.python.org",
    "registry.npmjs.org",
    "proxy.golang.org",
    "localhost",
    "127.0.0.1",
})
_BLOCK_HOST = ("provebreak",)
_REQ_FILES = ("requirements.txt", "requirements.in", "requirements-dev.txt")
_PY_LOCKS = ("poetry.lock", "uv.lock", "Pipfile.lock")
_JS_LOCKS = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")
_NAME_SPEC = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*(?:\[.*?\])?\s*(.*?)\s*$"
)
# `go run module@latest` and the Go form exec.Command("go", "run", "module@latest").
_LATEST = re.compile(
    r"\b([A-Za-z0-9][A-Za-z0-9_.~+/-]*[./][A-Za-z0-9_.~+/-]*)@latest\b"
)
_SETUP_LATEST = re.compile(
    r"(?im)^[ \t]*(python-version|node-version|go-version):\s*['\"]?latest['\"]?\s*$"
)
_USES = re.compile(r"uses:\s*(actions/setup-[A-Za-z0-9_-]+)@")
_DOCKER = re.compile(
    r"(?im)^[ \t]*image:\s*['\"]?([A-Za-z0-9][A-Za-z0-9_.:/-]{0,120})['\"]?\s*$"
)
_IMAGE = re.compile(r"(?m)^Image:\s*(\S.*?)\s*$")
_IMAGE_VER = re.compile(r"(?m)^Image Version:\s*(\S+)")
_PROOF_FLOOR_SEC = 25.0
_MAX_PROOFS = 3


def _scrub(text: str, max_len: int = 200) -> str:
    s = re.sub(r"[\x00-\x1f\x7f]", "", str(text or ""))
    return s[:max_len]


def _show_token(text: str) -> str:
    s = str(text or "").replace("*", "").replace(">", "").replace("<", "")
    s = re.sub(r"[\x00-\x1f\x7f]", "", s)
    return re.sub(r"\s+", " ", s).strip()


def _pkg_ok(name: str) -> bool:
    if not name or len(name) > 120 or ".." in name or name.startswith(("-", "/")):
        return False
    return _PKG.fullmatch(name) is not None


def _ver_ok(ver: str) -> bool:
    return bool(ver) and ".." not in ver and _VER.fullmatch(ver) is not None


def _argv_ok(argv: list[str]) -> bool:
    if not argv or len(argv) > 24:
        return False
    for arg in argv:
        if not isinstance(arg, str) or "\n" in arg or "\x00" in arg or len(arg) > 240:
            return False
        if arg.startswith("-") and arg not in {
            "--json", "--index-url", "--no-deps", "--disable-pip-version-check",
            "--no-input", "--only-binary=:all:", "--target", "--prefix",
            "--ignore-scripts", "--no-audit", "--no-fund", "--registry",
            "--cache", "-m", "-q", "--tb=no", "-json", "-count=1", "-run",
        } and not arg.startswith("--timeout=") and not arg.startswith("-timeout="):
            # version specs and paths are not flags; a leading dash is refused
            if not arg.startswith("--"):
                return False
    return sum(len(a) for a in argv) <= 2000


def _host_allowed(host: str | None, configured: set[str]) -> bool:
    if not host:
        return False
    h = host.lower().rstrip(".")
    if any(b in h for b in _BLOCK_HOST):
        return False
    if h in _PUBLIC_HOSTS or h.endswith(".localhost"):
        return True
    return h in configured


def _safe_url(url: str, configured: set[str]) -> str | None:
    if not url or "\n" in url or len(url) > 300:
        return None
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https", "file"}:
        return None
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        return None
    if parsed.scheme == "file":
        return url.strip()
    if not _host_allowed(parsed.hostname, configured):
        return None
    return url.strip()


def _configured_hosts(*urls: str) -> set[str]:
    hosts: set[str] = set()
    for url in urls:
        if not url:
            continue
        host = urlparse(url).hostname
        if host and not any(b in host.lower() for b in _BLOCK_HOST):
            hosts.add(host.lower())
    return hosts


class _NoRedirect(HTTPRedirectHandler):
    """Refuse redirects. Metadata is one GET, with no body."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        raise HTTPError(req.full_url, code, "redirect_refused", headers, fp)


def metadata_get(url: str, configured: set[str], timeout: float = 8.0) -> bytes:
    """GET metadata. No body, no redirects, allowlisted host only."""
    safe = _safe_url(url, configured)
    if not safe:
        raise OSError("url_refused")
    parsed = urlparse(safe)
    if parsed.scheme == "file":
        path = Path(unquote(parsed.path))
        if not path.is_file() or path.stat().st_size > 1_000_000:
            raise OSError("file_refused")
        return path.read_bytes()
    req = Request(safe, method="GET")  # noqa: S310 — host checked above; GET only
    opener = build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:  # noqa: S310
            return resp.read(1_000_000)
    except HTTPError as exc:
        raise OSError("redirect_or_http") from exc
    except URLError as exc:
        raise OSError("metadata_get_failed") from exc


def headline_for(up: dict | None) -> str | None:
    """The card's first line, or None when this result should keep the outside line."""
    if not isinstance(up, dict):
        return None
    kind = str(up.get("kind") or "")
    pkg = _show_token(up.get("package") or "")
    old = _show_token(up.get("old") or "")
    new = _show_token(up.get("new") or "")
    date = str(up.get("released") or "")
    test = _show_token(up.get("test") or "")
    if up.get("confidence") == "proven":
        if not (pkg and old and new and test and _DATE.fullmatch(date)):
            return None
        sentence = _PROVEN.format(pkg=pkg, old=old, new=new, date=date, test=test)
        if "broke" not in sentence:
            return None
        return sentence
    if up.get("confidence") != "likely":
        return None
    if kind == "runner" and old and new and old != new:
        return _LIKELY_RUNNER.format(old=old, new=new)
    if kind == "action" and pkg:
        return _LIKELY_ACTION.format(pkg=pkg)
    if kind == "docker" and pkg:
        return _LIKELY_DOCKER.format(pkg=pkg)
    if not (pkg and old and new):
        return None
    if _DATE.fullmatch(date):
        return _LIKELY.format(pkg=pkg, old=old, new=new, date=date)
    return _LIKELY_NODATE.format(pkg=pkg, old=old, new=new)


def clean_upstream(raw: object, allowed_tests: set[str] | None) -> dict | None:
    """Strict shape. Invalid input is dropped, never raised."""
    try:
        return _clean_upstream(raw, allowed_tests)
    except Exception:  # noqa: BLE001
        return None


def _clean_one(raw: dict, allowed_tests: set[str] | None, *, primary: bool) -> dict | None:
    if not isinstance(raw, dict):
        return None
    confidence = raw.get("confidence")
    if confidence not in {"proven", "likely"}:
        return None
    kind = raw.get("kind")
    if kind not in _KINDS:
        return None
    package = str(raw.get("package") or "")
    old = str(raw.get("old") or "")
    new = str(raw.get("new") or "")
    released = str(raw.get("released") or "")
    test = str(raw.get("test") or "")
    if kind in {"python", "npm", "go"} and not _pkg_ok(package):
        return None
    if kind == "runner":
        package = package or "runner-image"
    elif kind == "action" and not _pkg_ok(package):
        return None
    elif kind == "docker" and not _pkg_ok(package):
        return None
    if old and not _ver_ok(old) and kind != "action":
        return None
    if new and not _ver_ok(new) and kind != "action":
        return None
    if kind == "action":
        old, new = "latest", "latest"
    if released and not _DATE.fullmatch(released):
        return None
    if confidence == "proven":
        if kind not in {"python", "npm", "go"} or not released or not test:
            return None
        if not _ver_ok(old) or not _ver_ok(new) or old == new:
            return None
    if test:
        if allowed_tests is not None and test not in allowed_tests:
            return None
        if len(test) > 300 or "\n" in test:
            return None
    evidence_in = raw.get("evidence") if primary else []
    evidence: list[str] = []
    if evidence_in:
        if not isinstance(evidence_in, list):
            return None
        for item in evidence_in[:6]:
            if not isinstance(item, str):
                return None
            evidence.append(_scrub(item, 200))
    out = {
        "confidence": confidence,
        "package": package,
        "old": old,
        "new": new,
        "released": released,
        "test": test,
        "kind": kind,
        "evidence": evidence,
    }
    return out


def _clean_upstream(raw: object, allowed_tests: set[str] | None) -> dict | None:
    if not isinstance(raw, dict):
        return None
    main = _clean_one(raw, allowed_tests, primary=True)
    if not main:
        return None
    also_in = raw.get("also") or []
    also: list[dict] = []
    if also_in:
        if not isinstance(also_in, list):
            return None
        for item in also_in[:3]:
            one = _clean_one(item, allowed_tests, primary=False)
            if one and one.get("confidence") != "proven":
                one["confidence"] = "likely"
                one.pop("evidence", None)
                also.append(one)
    if also:
        main["also"] = also
    return main


def grade_upstream_claim(
    scenario: dict,
    *,
    status: str,
    culprit: str | None,
    upstream: dict | None,
) -> dict | None:
    """Override a lab grade when a package was named.

    A proven package on a scenario that did not ask for that package is
    wrong-confident. Missing a proof is a miss, not a wrong culprit.
    Returns None when upstream attribution is not part of this grade.
    """
    expect = scenario.get("upstream_expect") if isinstance(scenario, dict) else None
    up = upstream if isinstance(upstream, dict) else None
    proven = bool(up and up.get("confidence") == "proven")
    if not expect and not proven:
        return None
    if status in {"proven", "introduced_failing_test"} or culprit:
        return {"exact": False, "wrong_confident": True}
    if proven:
        ok = (
            isinstance(expect, dict)
            and expect.get("confidence") == "proven"
            and expect.get("package") == up.get("package")
            and str(expect.get("old")) == str(up.get("old"))
            and str(expect.get("new")) == str(up.get("new"))
            and status == "inconclusive_env"
        )
        return {"exact": ok, "wrong_confident": not ok}
    if isinstance(expect, dict) and expect.get("confidence") == "proven":
        return {"exact": False, "wrong_confident": False}
    if (
        isinstance(expect, dict)
        and up
        and up.get("confidence") == "likely"
        and up.get("package") == expect.get("package")
    ):
        return {"exact": True, "wrong_confident": False}
    if isinstance(expect, dict):
        return {"exact": False, "wrong_confident": False}
    return None


@dataclass
class _Cand:
    kind: str
    package: str
    spec: str = ""
    transitive: bool = False
    old: str = ""
    new: str = ""
    released: str = ""
    evidence: list[str] = field(default_factory=list)


def attribute(
    *,
    repo: Path | str,
    good_sha: str,
    bad_sha: str,
    tests: list[str],
    runner: object,
    deadline: float | None = None,
    log_text: str = "",
    resolvers: object | None = None,
    prove: Callable[..., str] | None = None,
) -> dict | None:
    """Fail-soft. None means the outside-the-repo line stays as it is."""
    try:
        return _attribute(
            repo=Path(repo),
            good_sha=str(good_sha),
            bad_sha=str(bad_sha),
            tests=list(tests or []),
            runner=runner,
            deadline=deadline,
            log_text=log_text or "",
            resolvers=resolvers,
            prove=prove,
        )
    except Exception:  # noqa: BLE001
        return None


def _git(repo: Path, args: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str] | None:
    from sentinel_card.bisect import build_scrubbed_env

    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=build_scrubbed_env(),
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _inside_repo(repo: Path) -> bool:
    proc = _git(repo, ["rev-parse", "--is-inside-work-tree"])
    return bool(proc and proc.returncode == 0 and proc.stdout.strip() == "true")


def _show(repo: Path, sha: str, path: str) -> str | None:
    if not path or path.startswith("/") or ".." in path.split("/"):
        return None
    proc = _git(repo, ["show", f"{sha}:{path}"])
    if not proc or proc.returncode != 0:
        return None
    if len(proc.stdout) > 200_000:
        return None
    return proc.stdout


def _tracked(repo: Path, sha: str) -> list[str]:
    proc = _git(repo, ["ls-tree", "-r", "--name-only", sha])
    if not proc or proc.returncode != 0:
        return []
    return [ln for ln in proc.stdout.splitlines() if ln and ".." not in ln.split("/")][:400]


def _since(repo: Path, sha: str) -> datetime | None:
    proc = _git(repo, ["show", "-s", "--format=%cI", sha])
    if not proc or proc.returncode != 0:
        return None
    return _parse_time(proc.stdout.strip())


def _parse_time(text: str) -> datetime | None:
    raw = (text or "").strip().replace("Z", "+00:00")
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        day = _day(text)
        if not day:
            return None
        return datetime.fromisoformat(day + "T00:00:00+00:00")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _day(text: str) -> str:
    match = re.match(r"(\d{4}-\d{2}-\d{2})", (text or "").strip())
    return match.group(1) if match else ""


def _norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_requirements(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")) or "://" in line or "@" in line:
            continue
        match = _NAME_SPEC.match(line)
        if not match:
            continue
        name, spec = match.group(1), (match.group(2) or "").strip()
        if not _pkg_ok(name):
            continue
        out[_norm_py(name)] = spec
    return out


def _py_pinned(spec: str) -> bool:
    for part in (spec or "").split(","):
        token = part.strip()
        if token.startswith("==="):
            return True
        if token.startswith("=="):
            return True
    return False


def _parse_package_json(text: str) -> dict[str, str]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    out: dict[str, str] = {}
    if not isinstance(data, dict):
        return out
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if isinstance(name, str) and isinstance(spec, str) and _pkg_ok(name):
                out[name] = spec.strip()
    return out


def _js_pinned(spec: str) -> bool:
    spec = (spec or "").strip()
    if not spec or spec in {"*", "latest", "x"}:
        return False
    if spec[0] in "^~><*" or spec.startswith(">=") or spec.startswith("<="):
        return False
    return bool(re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?", spec))


def _locked(names: list[str], *texts: str | None) -> bool:
    blob = "\n".join(t for t in texts if t)
    if not blob:
        return False
    return any(name and name in blob for name in names)


def _parse_ver_tuple(ver: str) -> tuple[int, ...] | None:
    raw = ver[1:] if ver.startswith("v") and len(ver) > 1 and ver[1].isdigit() else ver
    raw = raw.split("-", 1)[0].split("+", 1)[0]
    parts: list[int] = []
    for piece in raw.split("."):
        if not piece.isdigit():
            return None
        parts.append(int(piece))
    if not parts:
        return None
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _cmp(a: str, b: str) -> int:
    ta, tb = _parse_ver_tuple(a), _parse_ver_tuple(b)
    if ta is None or tb is None:
        return 0
    return (ta > tb) - (ta < tb)


def _satisfies(spec: str, version: str) -> bool:
    if _parse_ver_tuple(version) is None:
        return False
    if "-" in version.split("+", 1)[0] and "-" not in (spec or ""):
        return False
    spec = (spec or "").strip()
    if spec in {"", "*", "latest", "x"}:
        return True
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    if not parts:
        return True
    return all(_one_spec(part, version) for part in parts)


def _one_spec(part: str, version: str) -> bool:
    if part.startswith("^"):
        return _caret(part[1:], version)
    if part.startswith("~"):
        return _tilde(part[1:], version)
    for op in ("===", ">=", "<=", "!=", "==", ">", "<"):
        if part.startswith(op):
            other = part[len(op):].strip()
            cmp = _cmp(version, other)
            if op == "===" or op == "==":
                return version == other
            if op == "!=":
                return version != other
            if op == ">=":
                return cmp >= 0
            if op == "<=":
                return cmp <= 0
            if op == ">":
                return cmp > 0
            if op == "<":
                return cmp < 0
    if _parse_ver_tuple(part) and version == part:
        return True
    return False


def _caret(base: str, version: str) -> bool:
    if _cmp(version, base) < 0:
        return False
    parts = _parse_ver_tuple(base)
    if not parts:
        return False
    major, minor, patch = parts
    if major > 0:
        ceiling = (major + 1, 0, 0)
    elif minor > 0:
        ceiling = (0, minor + 1, 0)
    else:
        ceiling = (0, 0, patch + 1)
    got = _parse_ver_tuple(version)
    return bool(got and got < ceiling)


def _tilde(base: str, version: str) -> bool:
    if _cmp(version, base) < 0:
        return False
    parts = _parse_ver_tuple(base)
    if not parts:
        return False
    ceiling = (parts[0], parts[1] + 1, 0)
    got = _parse_ver_tuple(version)
    return bool(got and got < ceiling)


def _runner_proof_kind(runner: object) -> str:
    kind = str(getattr(runner, "kind_name", "") or "")
    framework = str(getattr(runner, "framework", "") or "")
    if kind == "go":
        return "go"
    if kind in {"node", "js"} or framework in {"vitest", "jest", "mocha"}:
        return "npm" if kind == "node" else ""
    if type(runner).__name__ == "PytestGitRunner" or getattr(runner, "python", None):
        return "python"
    return ""


def _index_url(runner: object) -> str:
    env = getattr(runner, "env", None) or {}
    for key in ("PIP_INDEX_URL", "PIP_INDEX"):
        if isinstance(env, dict) and env.get(key):
            return str(env[key])
    return os.environ.get("PIP_INDEX_URL", "")


def _npm_registry(runner: object) -> str:
    env = getattr(runner, "env", None) or {}
    if isinstance(env, dict) and env.get("NPM_CONFIG_REGISTRY"):
        return str(env["NPM_CONFIG_REGISTRY"])
    return os.environ.get("NPM_CONFIG_REGISTRY", "") or "https://registry.npmjs.org"


def _go_proxy(runner: object) -> str:
    env = getattr(runner, "env", None) or {}
    if isinstance(env, dict) and env.get("GOPROXY"):
        return str(env["GOPROXY"]).split(",")[0].strip()
    return (os.environ.get("GOPROXY") or "https://proxy.golang.org").split(",")[0].strip()


class _DefaultResolvers:
    """Local subprocess and file reads. No repository source in the request."""

    def pip_versions(self, pkg: str, index_url: str) -> list[str]:
        if not _pkg_ok(pkg):
            return []
        cmd = ["python3", "-m", "pip", "index", "versions", "--disable-pip-version-check", pkg]
        if index_url:
            cmd[5:5] = ["--index-url", index_url]
        if not _argv_ok(cmd):
            return []
        from sentinel_card.bisect import build_scrubbed_env

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15, shell=False,
                env=build_scrubbed_env(),
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        text = (proc.stdout or "") + "\n" + (proc.stderr or "")
        match = re.search(r"Available versions:\s*(.+)", text)
        if not match:
            return []
        return [v.strip() for v in match.group(1).split(",") if _ver_ok(v.strip())]

    def release_times(self, pkg: str, index_url: str) -> dict[str, str]:
        if not index_url or not _pkg_ok(pkg):
            return self._pypi_times(pkg, index_url)
        parsed = urlparse(index_url)
        if parsed.scheme == "file":
            root = Path(unquote(parsed.path))
            for candidate in (root.parent / "release-times.json", root / "release-times.json"):
                if candidate.is_file():
                    try:
                        data = json.loads(candidate.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError):
                        return {}
                    block = data.get(pkg) or data.get(_norm_py(pkg)) or {}
                    if isinstance(block, dict):
                        return {str(k): str(v) for k, v in block.items()}
            return {}
        return self._pypi_times(pkg, index_url)

    def _pypi_times(self, pkg: str, index_url: str) -> dict[str, str]:
        host = urlparse(index_url).hostname if index_url else "pypi.org"
        if host and host not in {"pypi.org", "pypi.python.org", "files.pythonhosted.org"}:
            return {}
        configured = _configured_hosts(index_url, "https://pypi.org")
        try:
            raw = metadata_get(f"https://pypi.org/pypi/{pkg}/json", configured)
            data = json.loads(raw.decode("utf-8", "replace"))
        except (OSError, json.JSONDecodeError, UnicodeError):
            return {}
        releases = data.get("releases") if isinstance(data, dict) else None
        out: dict[str, str] = {}
        if not isinstance(releases, dict):
            return out
        for ver, files in releases.items():
            if not isinstance(files, list) or not files:
                continue
            uploaded = files[0].get("upload_time") if isinstance(files[0], dict) else ""
            if uploaded:
                out[str(ver)] = str(uploaded)
        return out

    def requires(self, pkg: str, version: str, index_url: str) -> list[tuple[str, str]]:
        if not _pkg_ok(pkg) or not _ver_ok(version):
            return []
        parsed = urlparse(index_url or "")
        if parsed.scheme != "file":
            return self._pypi_requires(pkg, version, index_url)
        root = Path(unquote(parsed.path))
        folder = root / _norm_py(pkg)
        dist = _norm_py(pkg).replace("-", "_")
        wheels = sorted(folder.glob(f"{dist}-{version}-*.whl")) if folder.is_dir() else []
        if not wheels:
            return []
        try:
            with zipfile.ZipFile(wheels[-1]) as zf:
                meta_name = next(n for n in zf.namelist() if n.endswith(".dist-info/METADATA"))
                text = zf.read(meta_name).decode("utf-8", "replace")
        except (OSError, StopIteration, zipfile.BadZipFile):
            return []
        out: list[tuple[str, str]] = []
        for line in text.splitlines():
            if not line.startswith("Requires-Dist:"):
                continue
            body = line.split(":", 1)[1].strip()
            if "extra ==" in body:
                continue
            body = body.split(";", 1)[0].strip()
            match = _NAME_SPEC.match(body.replace("(", " ").replace(")", ""))
            if not match:
                continue
            name, spec = match.group(1), (match.group(2) or "").strip()
            if _pkg_ok(name):
                out.append((_norm_py(name), spec))
        return out

    def _pypi_requires(self, pkg: str, version: str, index_url: str) -> list[tuple[str, str]]:
        host = urlparse(index_url).hostname if index_url else "pypi.org"
        if host and host not in {"pypi.org", "pypi.python.org", "files.pythonhosted.org"}:
            return []
        configured = _configured_hosts(index_url, "https://pypi.org")
        try:
            raw = metadata_get(f"https://pypi.org/pypi/{pkg}/{version}/json", configured)
            data = json.loads(raw.decode("utf-8", "replace"))
        except (OSError, json.JSONDecodeError, UnicodeError):
            return []
        info = data.get("info") if isinstance(data, dict) else None
        reqs = info.get("requires_dist") if isinstance(info, dict) else None
        if not isinstance(reqs, list):
            return []
        out: list[tuple[str, str]] = []
        for body in reqs:
            if not isinstance(body, str) or "extra ==" in body:
                continue
            body = body.split(";", 1)[0].strip().replace("(", " ").replace(")", "")
            match = _NAME_SPEC.match(body)
            if not match:
                continue
            name, spec = match.group(1), (match.group(2) or "").strip()
            if _pkg_ok(name):
                out.append((_norm_py(name), spec))
        return out

    def npm_time(self, pkg: str, registry: str) -> dict[str, str]:
        if not _pkg_ok(pkg):
            return {}
        cmd = ["npm", "view", pkg, "time", "--json", "--registry", registry]
        if not _argv_ok(cmd):
            return {}
        from sentinel_card.bisect import build_scrubbed_env

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15, shell=False,
                env=build_scrubbed_env(),
            )
        except (OSError, subprocess.TimeoutExpired):
            return {}
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return {}
        if not isinstance(data, dict):
            return {}
        return {
            str(k): str(v) for k, v in data.items()
            if k not in {"created", "modified"} and _ver_ok(str(k))
        }

    def go_versions(self, module: str, proxy: str) -> list[tuple[str, str]]:
        if not _pkg_ok(module):
            return []
        parsed = urlparse(proxy)
        if parsed.scheme == "file":
            root = Path(unquote(parsed.path))
            base = root / _proxy_escape(module) / "@v"
            list_file = base / "list"
            if not list_file.is_file():
                return []
            out: list[tuple[str, str]] = []
            for ver in list_file.read_text(encoding="utf-8").splitlines():
                ver = ver.strip()
                if not _ver_ok(ver):
                    continue
                info = base / f"{ver}.info"
                when = ""
                if info.is_file():
                    try:
                        when = str(json.loads(info.read_text(encoding="utf-8")).get("Time") or "")
                    except (OSError, json.JSONDecodeError):
                        when = ""
                out.append((ver, when))
            return out
        configured = _configured_hosts(proxy)
        if not _safe_url(proxy, configured):
            return []
        try:
            listing = metadata_get(proxy.rstrip("/") + "/" + module + "/@v/list", configured).decode()
        except OSError:
            return []
        out = []
        for ver in listing.splitlines():
            ver = ver.strip()
            if not _ver_ok(ver):
                continue
            when = ""
            try:
                info = json.loads(metadata_get(
                    proxy.rstrip("/") + "/" + module + "/@v/" + ver + ".info", configured
                ).decode())
                when = str(info.get("Time") or "")
            except (OSError, json.JSONDecodeError, UnicodeError):
                when = ""
            out.append((ver, when))
        return out


def _proxy_escape(module: str) -> str:
    return "".join("!" + ch.lower() if ch.isupper() else ch for ch in module)


def _window(versions: list[tuple[str, str]], spec: str, since: datetime) -> tuple[str, str, str] | None:
    """Return (old, new, release-day) for versions inside the spec."""
    chosen: list[tuple[str, datetime]] = []
    for ver, raw in versions:
        if not (_satisfies(spec, ver) or _satisfies(spec, ver[1:] if ver.startswith("v") else ver)):
            continue
        when = _parse_time(raw)
        if when is None:
            continue
        chosen.append((ver, when))
    if not chosen:
        return None
    newest = max(chosen, key=lambda item: (_parse_ver_tuple(item[0]) or (0,), item[1]))
    if newest[1] <= since:
        return None
    older = [item for item in chosen if item[1] <= since]
    if not older:
        return None
    old = max(older, key=lambda item: (_parse_ver_tuple(item[0]) or (0,), item[1]))
    if old[0] == newest[0]:
        return None
    return old[0], newest[0], _day(newest[1].isoformat())


def _collect(repo: Path, good: str, bad: str) -> list[_Cand]:
    good_files = set(_tracked(repo, good))
    bad_files = set(_tracked(repo, bad))
    cands: list[_Cand] = []
    py_locks = []
    for name in _PY_LOCKS:
        if name in good_files and name in bad_files:
            py_locks.append(_show(repo, good, name))
    for rel in _REQ_FILES:
        if rel not in good_files or rel not in bad_files:
            continue
        gtext, btext = _show(repo, good, rel), _show(repo, bad, rel)
        if gtext is None or btext is None:
            continue
        gspecs, bspecs = _parse_requirements(gtext), _parse_requirements(btext)
        for name, spec in gspecs.items():
            if bspecs.get(name) != spec or _py_pinned(spec):
                continue
            if _locked([name, name.replace("-", "_")], *py_locks):
                continue
            cands.append(_Cand("python", name, spec, evidence=[f"unpinned {name} {spec or 'any'} in {rel}"]))
    pyproject_g = _show(repo, good, "pyproject.toml") if "pyproject.toml" in good_files else None
    pyproject_b = _show(repo, bad, "pyproject.toml") if "pyproject.toml" in bad_files else None
    if pyproject_g and pyproject_b:
        for name, spec in _deps_from_pyproject(pyproject_g).items():
            if _deps_from_pyproject(pyproject_b).get(name) != spec or _py_pinned(spec):
                continue
            if _locked([name], *py_locks):
                continue
            if any(c.package == name and c.kind == "python" for c in cands):
                continue
            cands.append(_Cand("python", name, spec, evidence=[f"unpinned {name} {spec or 'any'} in pyproject.toml"]))
    js_locks = []
    for name in _JS_LOCKS:
        if name in good_files and name in bad_files:
            js_locks.append(_show(repo, good, name))
    if "package.json" in good_files and "package.json" in bad_files:
        gjson, bjson = _show(repo, good, "package.json"), _show(repo, bad, "package.json")
        if gjson and bjson:
            for name, spec in _parse_package_json(gjson).items():
                if _parse_package_json(bjson).get(name) != spec or _js_pinned(spec):
                    continue
                if _locked([name, f"node_modules/{name}"], *js_locks):
                    continue
                cands.append(_Cand("npm", name, spec, evidence=[f"range {name}@{spec} is not locked"]))
    go_sum = _show(repo, good, "go.sum") if "go.sum" in good_files else ""
    for rel in sorted(good_files & bad_files):
        if not rel.endswith(".go"):
            continue
        gtext, btext = _show(repo, good, rel), _show(repo, bad, rel)
        if not gtext or not btext:
            continue
        for module in sorted(set(_LATEST.findall(gtext)) & set(_LATEST.findall(btext))):
            if not _pkg_ok(module):
                continue
            if go_sum and f"{module} " in go_sum and "@latest" not in (gtext + btext):
                continue
            if any(c.package == module and c.kind == "go" for c in cands):
                continue
            cands.append(_Cand("go", module, "", evidence=[f"{module}@latest in {rel}"]))
    return cands


def _deps_from_pyproject(text: str) -> dict[str, str]:
    """Dependencies in a [project] table. Enough for a flat list, not a TOML parser."""
    lines = text.splitlines()
    in_deps = False
    buf: list[str] = []
    for line in lines:
        if re.match(r"^\[project\]\s*$", line.strip()):
            in_deps = False
            continue
        if line.strip().startswith("dependencies") and "=" in line and "[" in line:
            buf.append(line.split("[", 1)[1])
            if "]" in line:
                buf[-1] = buf[-1].split("]", 1)[0]
                break
            in_deps = True
            continue
        if in_deps:
            if "]" in line:
                buf.append(line.split("]", 1)[0])
                break
            buf.append(line)
    blob = " ".join(buf)
    out: dict[str, str] = {}
    for quoted in re.findall(r'"([^"]+)"', blob):
        parsed = _parse_requirements(quoted)
        out.update(parsed)
    return out


def _expand_transitive(cands: list[_Cand], index_url: str, resolvers: _DefaultResolvers) -> list[_Cand]:
    extra: list[_Cand] = []
    for cand in list(cands):
        if cand.kind != "python" or cand.transitive:
            continue
        versions = resolvers.pip_versions(cand.package, index_url)
        if not versions:
            continue
        newest = max(versions, key=lambda v: _parse_ver_tuple(v) or (0,))
        for name, spec in resolvers.requires(cand.package, newest, index_url):
            if _py_pinned(spec):
                continue
            if any(c.package == name and c.kind == "python" for c in cands + extra):
                continue
            extra.append(_Cand(
                "python", name, spec, transitive=True,
                evidence=[f"transitive of {cand.package} ({name} {spec or 'any'}, not locked)"],
            ))
    return cands + extra


def _tool_candidates(repo: Path, good: str, bad: str, log_text: str) -> list[_Cand]:
    out: list[_Cand] = []
    versions = _IMAGE_VER.findall(log_text or "")
    images = _IMAGE.findall(log_text or "")
    if len(versions) >= 2 and versions[0] != versions[-1] and all(_ver_ok(v) for v in (versions[0], versions[-1])):
        image = images[0] if images else "runner-image"
        out.append(_Cand(
            "runner", image if _pkg_ok(image.replace(":", "-")) else "runner-image",
            old=versions[0], new=versions[-1],
            evidence=[f"Image Version {versions[0]} then {versions[-1]}"],
        ))
    good_files = set(_tracked(repo, good))
    bad_files = set(_tracked(repo, bad))
    for rel in sorted(good_files & bad_files):
        if not (rel.startswith(".github/workflows/") or rel == "Dockerfile" or rel.endswith("/Dockerfile")):
            continue
        gtext, btext = _show(repo, good, rel) or "", _show(repo, bad, rel) or ""
        if not gtext or not btext:
            continue
        if _SETUP_LATEST.search(gtext) and _SETUP_LATEST.search(btext):
            uses = _USES.findall(gtext)
            if uses and uses[0] in btext and _pkg_ok(uses[0]):
                out.append(_Cand(
                    "action", uses[0], old="latest", new="latest",
                    evidence=[f"{uses[0]} with version latest in {rel}"],
                ))
        for image in _DOCKER.findall(gtext):
            if image not in btext:
                continue
            name, _, tag = image.partition(":")
            if tag and tag != "latest":
                continue
            pkg = name if _pkg_ok(name) else ""
            if not pkg:
                continue
            out.append(_Cand(
                "docker", pkg, old="latest", new="latest",
                evidence=[f"image {image} has no pinned tag in {rel}"],
            ))
    return out


def _remaining(deadline: float | None) -> float:
    if deadline is None:
        return 10**6
    return deadline - time.monotonic()


def _attribute(
    *,
    repo: Path,
    good_sha: str,
    bad_sha: str,
    tests: list[str],
    runner: object,
    deadline: float | None,
    log_text: str,
    resolvers: object | None,
    prove: Callable[..., str] | None,
) -> dict | None:
    if not _inside_repo(repo):
        return None
    since = _since(repo, good_sha)
    if since is None:
        return None
    res = resolvers or _DefaultResolvers()
    cands = _collect(repo, good_sha, bad_sha)
    index_url = _index_url(runner)
    if any(c.kind == "python" for c in cands):
        cands = _expand_transitive(cands, index_url, res)  # type: ignore[arg-type]
    tools = _tool_candidates(repo, good_sha, bad_sha, log_text)
    if not cands and not tools:
        return None
    proof_kind = _runner_proof_kind(runner)
    resolved: list[_Cand] = []
    for cand in cands:
        if len(resolved) >= 8:
            break
        if cand.kind == "python":
            versions = [(v, "") for v in res.pip_versions(cand.package, index_url)]  # type: ignore[attr-defined]
            times = res.release_times(cand.package, index_url)  # type: ignore[attr-defined]
            versions = [(v, times.get(v, "")) for v, _ in versions]
            cand.evidence.append(f"pip index versions {cand.package}")
        elif cand.kind == "npm":
            times = res.npm_time(cand.package, _npm_registry(runner))  # type: ignore[attr-defined]
            versions = list(times.items())
            cand.evidence.append(f"npm view {cand.package} time")
        elif cand.kind == "go":
            versions = res.go_versions(cand.package, _go_proxy(runner))  # type: ignore[attr-defined]
            cand.evidence.append(f"go proxy {cand.package}/@v/list")
        else:
            continue
        window = _window(versions, cand.spec, since)
        if not window:
            continue
        cand.old, cand.new, cand.released = window
        if not cand.released:
            continue
        resolved.append(cand)
    resolved.sort(key=lambda c: (0 if c.transitive else 1, c.package))
    test = tests[0] if tests else ""
    proven: _Cand | None = None
    likely: list[_Cand] = []
    attempts = 0
    prover = prove or _prove
    for cand in resolved:
        if cand.kind != proof_kind:
            likely.append(cand)
            continue
        if attempts >= _MAX_PROOFS or _remaining(deadline) < _PROOF_FLOOR_SEC:
            likely.append(cand)
            continue
        attempts += 1
        try:
            outcome = prover(
                cand, repo=repo, sha=bad_sha, tests=tests, runner=runner, deadline=deadline,
            )
        except Exception:  # noqa: BLE001
            outcome = "incomplete"
        if outcome == "proven":
            cand.evidence.append(f"re-run {cand.old} passed; {cand.new} failed")
            proven = cand
            break
        if outcome == "disproven":
            continue
        cand.evidence.append("re-run did not finish; not claimed as the cause")
        likely.append(cand)
    for tool in tools:
        likely.append(tool)
    if proven:
        return _pack(proven, "proven", test, likely[:3])
    if likely:
        return _pack(likely[0], "likely", test, likely[1:4])
    return None


def _pack(cand: _Cand, confidence: str, test: str, also: list[_Cand]) -> dict | None:
    raw = {
        "confidence": confidence,
        "package": cand.package,
        "old": cand.old,
        "new": cand.new,
        "released": cand.released,
        "test": test if cand.kind in {"python", "npm", "go"} else "",
        "kind": cand.kind,
        "evidence": cand.evidence[:6],
        "also": [
            {
                "confidence": "likely",
                "package": item.package,
                "old": item.old,
                "new": item.new,
                "released": item.released,
                "test": "",
                "kind": item.kind,
                "evidence": [],
            }
            for item in also
            if item.package != cand.package
        ],
    }
    return clean_upstream(raw, {test} if test else set())


def _prove(cand: _Cand, *, repo: Path, sha: str, tests: list[str], runner: object, deadline: float | None) -> str:
    if cand.kind == "python":
        return _prove_python(cand, repo=repo, sha=sha, tests=tests, runner=runner, deadline=deadline)
    if cand.kind == "npm":
        return _prove_npm(cand, repo=repo, sha=sha, tests=tests, runner=runner, deadline=deadline)
    if cand.kind == "go":
        return _prove_go(cand, repo=repo, sha=sha, tests=tests, runner=runner, deadline=deadline)
    return "incomplete"


def _worktree(repo: Path, sha: str) -> Path | None:
    from sentinel_card.bisect import build_scrubbed_env

    root = Path(tempfile.mkdtemp(prefix="sentinel-upstream-"))
    wt = root / "wt"
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "worktree", "add", "--detach", str(wt), sha],
            capture_output=True, text=True, timeout=30, shell=False, env=build_scrubbed_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        shutil.rmtree(root, ignore_errors=True)
        return None
    if proc.returncode != 0 or not wt.is_dir():
        shutil.rmtree(root, ignore_errors=True)
        return None
    return wt


def _drop_worktree(repo: Path, wt: Path | None) -> None:
    if wt is None:
        return
    from sentinel_card.bisect import build_scrubbed_env

    try:
        subprocess.run(
            ["git", "-C", str(repo), "worktree", "remove", "--force", str(wt)],
            capture_output=True, timeout=20, shell=False, env=build_scrubbed_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        pass
    shutil.rmtree(wt.parent, ignore_errors=True)


def _run(cmd: list[str], *, cwd: Path | None, env: dict[str, str], timeout: float) -> subprocess.CompletedProcess[str] | None:
    if not _argv_ok(cmd) or timeout < 0.5:
        return None
    try:
        return subprocess.run(
            cmd, cwd=str(cwd) if cwd else None, env=env, capture_output=True, text=True,
            timeout=timeout, shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _prove_python(cand: _Cand, *, repo: Path, sha: str, tests: list[str], runner: object, deadline: float | None) -> str:
    from sentinel_card.bisect import build_scrubbed_env
    from sentinel_card.bisect import classify_pytest_outcome

    index = _safe_url(_index_url(runner), _configured_hosts(_index_url(runner)))
    if not index or not tests:
        return "incomplete"
    py = str(getattr(runner, "python", None) or "python3")
    wt = _worktree(repo, sha)
    if wt is None:
        return "incomplete"
    home = Path(tempfile.mkdtemp(prefix="sentinel-upstream-home-"))
    try:
        labels = []
        for ver in (cand.old, cand.new):
            if _remaining(deadline) < 8:
                return "incomplete"
            target = Path(tempfile.mkdtemp(prefix="sentinel-upstream-py-"))
            cmd = [
                py, "-m", "pip", "install", "--target", str(target), "--index-url", index,
                "--no-deps", "--disable-pip-version-check", "--no-input", "--only-binary=:all:",
                f"{cand.package}=={ver}",
            ]
            env = build_scrubbed_env(home=str(home))
            proc = _run(cmd, cwd=wt, env=env, timeout=min(25.0, _remaining(deadline)))
            if proc is None or proc.returncode != 0:
                return "incomplete"
            test_env = build_scrubbed_env(extra={"PYTHONPATH": str(target)}, home=str(home))
            test_env["PYTHONPATH"] = str(target) + os.pathsep + str(wt)
            test_cmd = [py, "-m", "pytest", "-q", "--tb=no", *tests[:5]]
            ran = _run(test_cmd, cwd=wt, env=test_env, timeout=min(20.0, _remaining(deadline)))
            if ran is None:
                return "incomplete"
            label, _kind, _detail = classify_pytest_outcome(ran.returncode, ran.stdout or "", ran.stderr or "")
            labels.append(label)
            shutil.rmtree(target, ignore_errors=True)
        if labels == ["green", "red"]:
            return "proven"
        if len(labels) == 2 and labels[0] in {"green", "red"} and labels[1] in {"green", "red"}:
            return "disproven"
        return "incomplete"
    finally:
        shutil.rmtree(home, ignore_errors=True)
        _drop_worktree(repo, wt)


def _node_file(test_id: str) -> tuple[str, str] | None:
    if "::" not in test_id:
        return None
    path, _, name = test_id.partition("::")
    if not path.endswith((".js", ".mjs", ".cjs")) or ".." in path.split("/"):
        return None
    return path, name


def _classify_node(text: str, returncode: int) -> str:
    fail = re.search(r"^# fail (\d+)\s*$", text, re.M)
    if fail is None:
        fail = re.search(r"ℹ fail (\d+)", text)
    failed = int(fail.group(1)) if fail else (1 if returncode else 0)
    if failed == 0 and returncode == 0:
        return "green"
    if failed > 0:
        return "red"
    return "error"


def _prove_npm(cand: _Cand, *, repo: Path, sha: str, tests: list[str], runner: object, deadline: float | None) -> str:
    from sentinel_card.bisect import build_scrubbed_env

    registry = _safe_url(_npm_registry(runner), _configured_hosts(_npm_registry(runner)))
    parsed = _node_file(tests[0]) if tests else None
    if not registry or not parsed:
        return "incomplete"
    rel, _name = parsed
    node = str(getattr(runner, "node_bin", None) or "node")
    wt = _worktree(repo, sha)
    if wt is None:
        return "incomplete"
    home = Path(tempfile.mkdtemp(prefix="sentinel-upstream-home-"))
    try:
        labels = []
        for ver in (cand.old, cand.new):
            if _remaining(deadline) < 8:
                return "incomplete"
            prefix = Path(tempfile.mkdtemp(prefix="sentinel-upstream-npm-"))
            cache = prefix / "cache"
            cache.mkdir()
            cmd = [
                "npm", "install", f"{cand.package}@{ver}", "--prefix", str(prefix),
                "--ignore-scripts", "--no-audit", "--no-fund", "--registry", registry,
                "--cache", str(cache),
            ]
            env = build_scrubbed_env(home=str(home))
            proc = _run(cmd, cwd=wt, env=env, timeout=min(30.0, _remaining(deadline)))
            if proc is None or proc.returncode != 0:
                return "incomplete"
            test_env = build_scrubbed_env(
                extra={"NODE_PATH": str(prefix / "node_modules")}, home=str(home),
            )
            ran = _run(
                [node, "--test", "--test-reporter=tap", rel],
                cwd=wt, env=test_env, timeout=min(20.0, _remaining(deadline)),
            )
            if ran is None:
                return "incomplete"
            labels.append(_classify_node((ran.stdout or "") + "\n" + (ran.stderr or ""), ran.returncode))
            shutil.rmtree(prefix, ignore_errors=True)
        if labels == ["green", "red"]:
            return "proven"
        if len(labels) == 2 and set(labels) <= {"green", "red"}:
            return "disproven"
        return "incomplete"
    finally:
        shutil.rmtree(home, ignore_errors=True)
        _drop_worktree(repo, wt)


def _filter_proxy(src: Path, module: str, version: str, dest: Path) -> bool:
    base = src / _proxy_escape(module) / "@v"
    if not (base / f"{version}.zip").is_file():
        return False
    out = dest / _proxy_escape(module) / "@v"
    out.mkdir(parents=True)
    for ext in (".info", ".mod", ".zip"):
        shutil.copy(base / f"{version}{ext}", out / f"{version}{ext}")
    (out / "list").write_text(version + "\n", encoding="utf-8")
    return True


def _prove_go(cand: _Cand, *, repo: Path, sha: str, tests: list[str], runner: object, deadline: float | None) -> str:
    from sentinel_card.bisect import build_scrubbed_env
    from sentinel_card.runners import classify_go_json

    proxy = _go_proxy(runner)
    parsed = urlparse(proxy)
    if parsed.scheme != "file" or not tests or "::" not in tests[0]:
        return "incomplete"
    src = Path(unquote(parsed.path))
    pkg, _, name = tests[0].rpartition("::")
    if not re.fullmatch(r"Test[A-Za-z0-9_]*", name):
        return "incomplete"
    go_bin = str(getattr(runner, "go_bin", None) or "go")
    wt = _worktree(repo, sha)
    if wt is None:
        return "incomplete"
    home = Path(tempfile.mkdtemp(prefix="sentinel-upstream-home-"))
    try:
        labels = []
        for ver in (cand.old, cand.new):
            if _remaining(deadline) < 8:
                return "incomplete"
            filtered = Path(tempfile.mkdtemp(prefix="sentinel-upstream-goproxy-"))
            if not _filter_proxy(src, cand.package, ver, filtered):
                return "incomplete"
            cache = filtered / "cache"
            cache.mkdir()
            env = build_scrubbed_env(home=str(home), extra={
                "GOPROXY": filtered.as_uri(),
                "GOSUMDB": "off",
                "GOTOOLCHAIN": "local",
                "GO111MODULE": "on",
                "GOCACHE": str(cache),
                "GOMODCACHE": str(cache / "mod"),
                "GOPATH": str(cache / "path"),
            })
            (cache / "mod").mkdir()
            (cache / "path").mkdir()
            rel = "." if pkg == "." else pkg
            cmd = [go_bin, "test", "-json", "-count=1", "-timeout=20s", "-run", f"^{name}$", rel]
            ran = _run(cmd, cwd=wt, env=env, timeout=min(25.0, _remaining(deadline)))
            if ran is None:
                return "incomplete"
            label, _kind, _detail = classify_go_json(ran.stdout or "", ran.stderr or "", None, [name])
            labels.append(label)
            shutil.rmtree(filtered, ignore_errors=True)
        if labels == ["green", "red"]:
            return "proven"
        if len(labels) == 2 and set(labels) <= {"green", "red"}:
            return "disproven"
        return "incomplete"
    finally:
        shutil.rmtree(home, ignore_errors=True)
        _drop_worktree(repo, wt)
