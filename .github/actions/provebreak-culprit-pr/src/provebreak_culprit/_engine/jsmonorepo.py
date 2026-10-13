"""Filtered builds for JavaScript/TypeScript workspaces (pnpm, Yarn, npm, turbo).

Single-package repositories are not workspaces: ``plan_workspace_build`` returns
``None`` and the runner does not build. A workspace build runs only the failing
package and the workspace packages it depends on (turbo ``--filter=...pkg``,
otherwise one ``build`` script per package, dependencies first). A package that
is not in that closure is not built.

Build failures are the caller's problem to report as ``build_error`` (the bisect
then abstains with ``inconclusive_build``). This module never decides a culprit.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

# npm package names, including a scope. Rejects flags and shell metacharacters.
# ``...`` is legal in the character class (dots) but widens pnpm/turbo filters
# (``pkg...`` means "this package and its dependents"), so it is rejected too.
_SAFE_NAME = re.compile(r"^(@[A-Za-z0-9_][A-Za-z0-9._-]*\/)?[A-Za-z0-9_][A-Za-z0-9._-]*$")
_DISPLAY_TOKEN = re.compile(r"^[A-Za-z0-9_./:@+=,-]+$")
_PNPM_ITEM = re.compile(r"""^\s*-\s+['"]?([^'"#\s]+)['"]?\s*(?:#.*)?$""")
_DEP_FIELDS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
# Remote-cache credentials. The bisect job has none; leaving them unset is not
# enough if a previous step or turbo.json turns remote-only mode on.
_TURBO_REMOTE_EXACT = {
    "TURBO_TOKEN",
    "TURBO_TEAM",
    "TURBO_API",
    "TURBO_REMOTE_CACHE_SIGNATURE_KEY",
    "TURBO_REMOTE_CACHE_READ_ONLY",
}


@dataclass(frozen=True)
class WorkspacePackage:
    name: str
    rel: str  # posix path relative to the repo root, no leading ./
    deps: tuple[str, ...]
    has_build: bool


@dataclass(frozen=True)
class BuildStep:
    argv: tuple[str, ...]
    cwd_rel: str


@dataclass(frozen=True)
class BuildPlan:
    """``error`` set: do not run anything (caller reports build_error).

    Empty ``steps`` and no error: workspace, but nothing declares a build.
    """

    steps: tuple[BuildStep, ...] = ()
    error: str | None = None


def scrub_turbo_remote(env: dict[str, str]) -> dict[str, str]:
    """Drop turbo remote-cache credentials and force a local build.

    ``TURBO_REMOTE_ONLY=false`` matters: a repo or a leaked variable that sets it
    true makes turbo fail when the remote cache is unreachable, which would
    abstain on every commit. The local cache is not read either: the build
    plan passes ``--force`` and the runner deletes ``.turbo`` before each step,
    so a missing turbo input cannot replay another commit's outputs.
    """
    out = {
        k: v
        for k, v in env.items()
        if k.upper() not in _TURBO_REMOTE_EXACT and "TOKEN" not in k.upper()
    }
    out["TURBO_REMOTE_ONLY"] = "false"
    out["TURBO_DAEMON"] = "false"
    out["TURBO_TELEMETRY_DISABLED"] = "1"
    return out


def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace")[:500_000])
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _pnpm_globs(text: str) -> list[str]:
    globs: list[str] = []
    in_packages = False
    for ln in text.splitlines():
        if re.match(r"^packages:\s*$", ln):
            in_packages = True
            continue
        if not in_packages:
            continue
        if ln.strip() == "" or ln.strip().startswith("#"):
            continue
        if re.match(r"^\S", ln):
            break
        m = _PNPM_ITEM.match(ln)
        if not m:
            continue
        pat = m.group(1).strip()
        if pat.startswith("!") or pat.startswith("/") or ".." in pat.split("/"):
            continue
        globs.append(pat[2:] if pat.startswith("./") else pat)
    return globs


def _json_workspaces(data: dict) -> list[str] | None:
    w = data.get("workspaces")
    raw: list | None = None
    if isinstance(w, list):
        raw = w
    elif isinstance(w, dict) and isinstance(w.get("packages"), list):
        raw = w["packages"]
    if raw is None:
        return None
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            continue
        pat = item.strip()
        if not pat or pat.startswith("!") or pat.startswith("/") or ".." in pat.split("/"):
            continue
        out.append(pat[2:] if pat.startswith("./") else pat)
    return out


def workspace_globs(root: Path) -> list[str] | None:
    """Workspace patterns, or ``None`` when this checkout is not a workspace.

    An empty list means a workspace file is present but names no packages.
    ``turbo.json`` alone does not make a single-package repo a workspace.
    """
    found = False
    globs: list[str] = []
    for name in ("pnpm-workspace.yaml", "pnpm-workspace.yml"):
        path = root / name
        if not path.is_file():
            continue
        found = True
        try:
            globs.extend(_pnpm_globs(path.read_text(encoding="utf-8", errors="replace")[:200_000]))
        except OSError:
            continue
    data = _read_json(root / "package.json")
    if data is not None:
        listed = _json_workspaces(data)
        if listed is not None:
            found = True
            globs.extend(listed)
    if not found:
        return None
    deduped: list[str] = []
    for g in globs:
        if g not in deduped:
            deduped.append(g)
    return deduped


def _expand_globs(root: Path, patterns: list[str]) -> list[Path]:
    found: list[Path] = []
    seen: set[str] = set()
    for pat in patterns:
        # ``.`` is the workspace root. pathlib rejects that glob, and the root
        # package is resolved without a workspace entry.
        if not pat or pat == ".":
            continue
        try:
            matches = list(root.glob(pat))
        except (OSError, ValueError, IndexError):
            continue
        # ``packages/*`` does not match the directory itself; a pattern with no
        # wildcard that is itself a package directory does.
        direct = root / pat
        if direct.is_dir():
            matches.append(direct)
        for p in matches:
            try:
                if not p.is_dir():
                    continue
                rel = p.resolve().relative_to(root.resolve()).as_posix()
            except (OSError, ValueError):
                continue
            parts = rel.split("/")
            if not rel or rel == "." or "node_modules" in parts or ".git" in parts:
                continue
            if ".." in parts:
                continue
            if not (p / "package.json").is_file():
                continue
            if rel not in seen:
                seen.add(rel)
                found.append(p)
    return found


def package_name_ok(name: object) -> bool:
    """Workspace package names we will put in a pnpm/yarn/turbo filter."""
    return isinstance(name, str) and "..." not in name and bool(_SAFE_NAME.match(name))


def workspace_project_args(root: Path, pkg_rel: str, framework: str) -> list[str]:
    """``--project`` / ``--selectProjects`` for one workspace package.

    Empty for a single-package repo, the repo root, or a name we will not
    pass on an argv. The runner drops the flag and retries when the test
    file is not in that project's report.
    """
    if framework not in ("vitest", "jest"):
        return []
    rel = (pkg_rel or ".").strip().strip("/")
    if not rel or rel == "." or ".." in rel.split("/"):
        return []
    if workspace_globs(root) is None:
        return []
    name = _package_name_at(root, rel)
    if not package_name_ok(name):
        return []
    if framework == "vitest":
        return ["--project", name]
    return ["--selectProjects", name]


def _dep_names(data: dict, known: set[str], versions: dict[str, str]) -> tuple[str, ...]:
    """Workspace deps only: ``workspace:`` / ``file:`` / ``link:`` / ``*``, or a spec
    that equals that workspace package's version. A semver range is not enough:
    the package may resolve from the registry.
    """
    deps: list[str] = []
    for field in _DEP_FIELDS:
        block = data.get(field)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if name not in known or name in deps:
                continue
            spec_s = spec if isinstance(spec, str) else ""
            if spec_s.startswith(("workspace:", "file:", "link:")) or spec_s == "*":
                deps.append(name)
                continue
            ver = versions.get(name) or ""
            if ver and spec_s == ver:
                deps.append(name)
    return tuple(deps)


def discover_workspaces(root: Path) -> list[WorkspacePackage]:
    globs = workspace_globs(root)
    if not globs:
        return []
    drafts: list[tuple[str, str, dict]] = []
    for path in _expand_globs(root, globs):
        data = _read_json(path / "package.json") or {}
        name = data.get("name")
        if not package_name_ok(name):
            continue
        rel = path.resolve().relative_to(root.resolve()).as_posix()
        ver = data.get("version")
        ver_s = ver.strip() if isinstance(ver, str) else ""
        drafts.append((name, rel, data, ver_s))
    known = {name for name, _, _, _ in drafts}
    versions = {name: ver for name, _, _, ver in drafts if ver}
    # First name wins if two directories claim it.
    out: list[WorkspacePackage] = []
    seen: set[str] = set()
    for name, rel, data, _ver in drafts:
        if name in seen:
            continue
        seen.add(name)
        scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
        out.append(WorkspacePackage(
            name=name,
            rel=rel,
            deps=_dep_names(data, known, versions),
            has_build=isinstance(scripts.get("build"), str) and bool(scripts.get("build").strip()),
        ))
    return out


def locate_test_file(
    root: Path, rel_file: str, packages: list[WorkspacePackage],
    present=None,
) -> tuple[str, str] | None | str:
    """``(package dir, path inside it)``, ``None`` to use the single-package
    resolver, or ``'ambiguous'`` / ``'missing'``.
    """
    if not packages:
        return None
    if not rel_file or rel_file.startswith("/") or ".." in rel_file.split("/"):
        return "missing"

    def is_file(rel: str) -> bool:
        if present is not None:
            return bool(present(rel))
        return (root / rel).is_file()

    prefixed: list[tuple[int, str, str]] = []
    for pkg in packages:
        prefix = pkg.rel + "/"
        if rel_file.startswith(prefix):
            rest = rel_file[len(prefix):]
            if rest and is_file(prefix + rest):
                prefixed.append((len(pkg.rel), pkg.rel, rest))
    if prefixed:
        prefixed.sort(key=lambda t: -t[0])
        best = prefixed[0][0]
        top = [t for t in prefixed if t[0] == best]
        if len({t[1] for t in top}) > 1:
            return "ambiguous"
        return top[0][1], top[0][2]
    hits = [pkg for pkg in packages if is_file(pkg.rel + "/" + rel_file)]
    if len(hits) == 1:
        return hits[0].rel, rel_file
    if len(hits) > 1:
        return "ambiguous"
    if is_file(rel_file):
        return None
    return "missing"


def dependency_closure(packages: list[WorkspacePackage], name: str) -> list[WorkspacePackage]:
    """Dependencies first, then ``name``. Cycles are skipped rather than looped."""
    by = {p.name: p for p in packages}
    if name not in by:
        return []
    order: list[WorkspacePackage] = []
    done: set[str] = set()
    stack: set[str] = set()

    def visit(n: str) -> None:
        if n in done or n in stack or n not in by:
            return
        stack.add(n)
        for dep in by[n].deps:
            visit(dep)
        stack.remove(n)
        done.add(n)
        order.append(by[n])

    visit(name)
    return order


def _turbo_build_task(root: Path) -> str | None:
    data = _read_json(root / "turbo.json")
    if not data:
        return None
    tasks = data.get("tasks") if isinstance(data.get("tasks"), dict) else None
    if tasks is None and isinstance(data.get("pipeline"), dict):
        tasks = data["pipeline"]
    if isinstance(tasks, dict) and "build" in tasks:
        return "build"
    return None


def _root_scripts(root: Path) -> dict:
    data = _read_json(root / "package.json") or {}
    scripts = data.get("scripts")
    return scripts if isinstance(scripts, dict) else {}


def _root_fallback(root: Path, pm_argv: tuple[str, ...]) -> BuildPlan:
    scripts = _root_scripts(root)
    for script in ("build:all", "build"):
        body = scripts.get(script)
        if isinstance(body, str) and body.strip():
            return BuildPlan(steps=(BuildStep(pm_argv + ("run", script), "."),))
    return BuildPlan(steps=())


def plan_workspace_build(
    root: Path,
    pkg_rel: str,
    *,
    pm_argv: list[str] | tuple[str, ...],
    manager: str,
    turbo_bin: list[str] | None,
) -> BuildPlan | None:
    """Build steps for the workspace package at ``pkg_rel``, or ``None`` if
    ``root`` is not a workspace (single-package behaviour: do not build).
    """
    if workspace_globs(root) is None:
        return None
    packages = discover_workspaces(root)
    argv = tuple(pm_argv)
    if not packages:
        return _root_fallback(root, argv)
    pkg = next((p for p in packages if p.rel == pkg_rel), None)
    if pkg is None:
        raw = _package_name_at(root, pkg_rel)
        if raw and not package_name_ok(raw):
            # A name containing ``...`` would widen ``--filter``. Do not fall
            # through to a root ``build`` that runs every package.
            return BuildPlan(error="unsafe_workspace_package_name")
        # Test file lives outside a workspace package (repo root). Nothing to filter.
        return _root_fallback(root, argv)
    if not package_name_ok(pkg.name):
        return BuildPlan(error="unsafe_workspace_package_name")
    closure = dependency_closure(packages, pkg.name)
    if any(not package_name_ok(p.name) for p in closure):
        return BuildPlan(error="unsafe_workspace_package_name")
    task = _turbo_build_task(root)
    if task and turbo_bin and _turbo_lockfile_readable(root):
        # ``...pkg`` is turbo's "this package and its dependencies".
        # ``--force`` is ``--cache=local:w,remote:w``: never read a cache that
        # might have been filled by a different commit.
        return BuildPlan(steps=(BuildStep(
            tuple(turbo_bin) + ("run", task, f"--filter=...{pkg.name}", "--force"),
            ".",
        ),))
    buildable = [p for p in closure if p.has_build]
    if not buildable:
        # This package and its workspace dependencies declare no build script.
        # The root ``build`` script is a different command (Vue's is
        # ``node scripts/build.js``, a release bundle the unit job never runs).
        # Running it turns a test that CI runs after install into
        # ``inconclusive_build`` on every commit.
        return BuildPlan(steps=())
    if manager == "pnpm":
        # ``name...`` is pnpm's "this package and its dependencies". ``-r``
        # runs ``build`` in that set, dependencies first. A package outside
        # the set is not built.
        return BuildPlan(steps=(BuildStep(
            argv + ("--filter", f"{pkg.name}...", "-r", "run", "build"),
            ".",
        ),))
    steps: list[BuildStep] = []
    for p in buildable:
        if manager == "yarn":
            cmd = argv + ("workspace", p.name, "run", "build")
        else:
            cmd = argv + ("run", "build", "--workspace", p.name)
        steps.append(BuildStep(cmd, "."))
    return BuildPlan(steps=tuple(steps))


def _turbo_lockfile_readable(root: Path) -> bool:
    """Turbo 2.x cannot parse a multi-document pnpm lockfile (two ``---`` markers).

    When that happens ``--filter=...pkg`` is not the dependency closure: turbo
    reports every workspace it can see. Building that set fails unrelated
    packages and abstains on every commit. Per-package scripts are used instead.
    No pnpm lockfile (npm, Yarn) stays on the turbo path.
    """
    lock = root / "pnpm-lock.yaml"
    try:
        text = lock.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return True
    markers = 0
    for ln in text.splitlines():
        if ln.strip() == "---":
            markers += 1
            if markers >= 2:
                return False
    return True


def corepack_tool_shim_dir(cache: Path, tool: str) -> Path:
    """A ``pnpm`` or ``yarn`` on PATH that is ``corepack <tool>``.

    Turbo runs ``pnpm run build`` / ``yarn run build`` from PATH. A global
    package manager that is not the ``packageManager`` version fails the build
    on every commit (Yarn 1 vs yarn@4, or a pnpm 9 binary vs pnpm@12).
    """
    if tool not in ("pnpm", "yarn"):
        raise ValueError(tool)
    bindir = Path(cache) / "corepack-shims"
    bindir.mkdir(parents=True, exist_ok=True)
    shim = bindir / tool
    script = f"#!/bin/sh\nexec corepack {tool} \"$@\"\n"
    current = shim.read_text(encoding="utf-8") if shim.is_file() else ""
    if current != script:
        shim.write_text(script)
        shim.chmod(0o755)
    return bindir


def yarn_corepack_shim_dir(cache: Path) -> Path:
    """A ``yarn`` on PATH that is ``corepack yarn``."""
    return corepack_tool_shim_dir(cache, "yarn")


def find_turbo_bin(root: Path) -> list[str] | None:
    """Local turbo after install. Never ``npx`` (that would download)."""
    candidates = [root / "node_modules" / ".bin" / "turbo"]
    # pnpm may leave the bin only under the root virtual store's .bin, which
    # the path above already covers when the root package depends on turbo.
    for cand in candidates:
        if cand.exists() and not cand.is_dir():
            return [str(cand)]
    return None


def _package_name_at(root: Path, rel: str) -> str:
    path = root / "package.json" if not rel or rel == "." else root / rel / "package.json"
    data = _read_json(path) or {}
    name = data.get("name")
    return name if isinstance(name, str) else ""


def wipe_turbo_read_cache(root: Path) -> None:
    """Delete turbo's on-disk cache so a step cannot replay another commit.

    ``node_modules`` itself is kept (reinstalls follow the lockfile). ``--force``
    on the turbo argv is the other half, including a cache that lives outside
    these directories. A custom ``build_command`` does not get ``--force``, so
    the delete still runs.
    """
    for rel in (".turbo", "node_modules/.cache/turbo"):
        target = root / rel
        if target.is_dir():
            shutil.rmtree(target, ignore_errors=True)


def _pm_field(root: Path) -> str:
    data = _read_json(root / "package.json") or {}
    pm = data.get("packageManager")
    return pm.strip() if isinstance(pm, str) else ""


def _manager_of(root: Path) -> str:
    if (root / "pnpm-lock.yaml").is_file() or (root / "pnpm-workspace.yaml").is_file() or (root / "pnpm-workspace.yml").is_file():
        return "pnpm"
    if (root / "yarn.lock").is_file() or (root / ".yarnrc.yml").is_file():
        return "yarn"
    pm = _pm_field(root)
    if pm.startswith("pnpm@"):
        return "pnpm"
    if pm.startswith("yarn@"):
        return "yarn"
    return "npm"


def _yarn_berry(root: Path) -> bool:
    pm = _pm_field(root)
    m = re.match(r"^yarn@(\d+)", pm)
    if m:
        return int(m.group(1)) >= 2
    return (root / ".yarnrc.yml").is_file()


def _yarn_path(root: Path) -> str:
    path = root / ".yarnrc.yml"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")[:20_000]
    except OSError:
        return ""
    for ln in text.splitlines():
        m = re.match(r"^yarnPath:\s*[\"']?([^\"'#\s]+)", ln.strip())
        if not m:
            continue
        rel = m.group(1)
        if rel.startswith("./"):
            rel = rel[2:]
        if not rel or rel.startswith("/") or ".." in rel.split("/"):
            return ""
        if _DISPLAY_TOKEN.fullmatch(rel):
            return rel
    return ""


def _display(argv: list[str]) -> str:
    if not argv:
        return ""
    for token in argv:
        if not _DISPLAY_TOKEN.fullmatch(token) or ".." in token.split("/"):
            return ""
    return " ".join(argv)


def pnpm_build_allowlist(root: Path) -> bool:
    """True when the checkout names which dependency builds may run.

    pnpm 10+ ignores dependency scripts unless ``allowBuilds`` or
    ``onlyBuiltDependencies`` lists them. That list is the project's trust
    boundary. An install that also passes ``--ignore-scripts`` skips the
    approved builds (esbuild, swc) and the test cannot load.
    """
    for name in ("pnpm-workspace.yaml", "pnpm-workspace.yml"):
        path = root / name
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:200_000]
        except OSError:
            continue
        if re.search(
            r"(?m)^(allowBuilds|onlyBuiltDependencies|neverBuiltDependencies|ignoredBuiltDependencies)\s*:",
            text,
        ):
            return True
    data = _read_json(root / "package.json") or {}
    block = data.get("pnpm")
    if isinstance(block, dict) and any(
        k in block
        for k in (
            "onlyBuiltDependencies",
            "neverBuiltDependencies",
            "ignoredBuiltDependencies",
            "allowBuilds",
        )
    ):
        return True
    return False


# Newest pnpm 10 release with no prerelease tag, as of 2026-09-27.
# pnpm 10 and 11 both write lockfileVersion 9.0. A checkout with no
# packageManager pin and no ``pnpm@x.y.z`` line is pnpm 9, unless the
# workspace uses keys pnpm 9 does not understand. pnpm 11 is not inferred:
# an install that still fails stays an abstain.
_PNPM10_FALLBACK = "10.34.5"
_PNPM10_KEYS = re.compile(
    r"(?m)^(allowBuilds|minimumReleaseAge|minimumReleaseAgeExclude)\s*:"
)


def _pnpm10_workspace_keys(root: Path) -> bool:
    """True when the checkout uses pnpm 10 workspace keys and no version pin."""
    for name in ("pnpm-workspace.yaml", "pnpm-workspace.yml"):
        path = root / name
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:200_000]
        except OSError:
            continue
        if _PNPM10_KEYS.search(text):
            return True
    data = _read_json(root / "package.json") or {}
    block = data.get("pnpm")
    if isinstance(block, dict) and any(
        k in block for k in ("allowBuilds", "minimumReleaseAge", "minimumReleaseAgeExclude")
    ):
        return True
    return False


def pnpm_version_from_checkout(root: Path) -> str | None:
    """Pinned pnpm version, from ``packageManager`` or the lockfile.

    ``packageManager`` wins. A lockfile that names ``pnpm@x.y.z`` is next.
    Otherwise the lockfile major maps to the last release of that pnpm line
    (``9.0`` lockfiles are pnpm 9; pnpm 10 and 11 still write ``9.0`` and are
    distinguished by ``packageManager``). A ``9.0`` lockfile with
    ``allowBuilds``, ``minimumReleaseAge``, or ``minimumReleaseAgeExclude``
    and no pin is pnpm 10 (``10.34.5``). Those keys are what made frozen
    installs fail when the runner used pnpm 9.
    """
    pm = _pm_field(root)
    m = re.match(r"^pnpm@(\d+\.\d+\.\d+)", pm)
    if m:
        return m.group(1)
    lock = root / "pnpm-lock.yaml"
    try:
        text = lock.read_text(encoding="utf-8", errors="replace")[:8000]
    except OSError:
        return None
    named = re.search(r"(?m)^#?\s*pnpm@(\d+\.\d+\.\d+)\s*$", text)
    if named:
        return named.group(1)
    major = re.search(r"(?m)^lockfileVersion:\s*['\"]?(\d+)", text)
    if not major:
        return None
    mapped = {"5": "7.33.7", "6": "8.15.9", "9": "9.15.9"}.get(major.group(1))
    if mapped == "9.15.9" and _pnpm10_workspace_keys(root):
        return _PNPM10_FALLBACK
    return mapped


def pnpm_major(root: Path) -> int | None:
    ver = pnpm_version_from_checkout(root)
    if not ver:
        return None
    head = ver.split(".", 1)[0]
    return int(head) if head.isdigit() else None


_BUILD_OUTPUT_PARTS = frozenset({"dist", "build", "esm", "cjs", "lib"})
_BUILD_CACHE_SKIP = frozenset({"node_modules", ".git", ".turbo"})
_BUILD_CACHE_MAX_FILES = 4000


def save_build_cache(wt: Path, dest: Path) -> int:
    """Copy gitignored build outputs for this commit into ``dest``.

    ``node_modules`` is not copied (the install cache already has it). Returns
    the number of files stored. An empty result means there is nothing to restore.
    """
    try:
        listed = _git(
            wt, "status", "--ignored", "--porcelain", "-z", "-uall", timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 0
    if listed.returncode != 0:
        return 0
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    n = 0
    root = wt.resolve()
    for rel in listed.stdout.decode("utf-8", errors="replace").split("\0"):
        if not rel.startswith("!! "):
            continue
        rel = rel[3:]
        if not rel or rel.endswith("/"):
            continue
        parts = rel.split("/")
        if ".." in parts or any(p in _BUILD_CACHE_SKIP for p in parts):
            continue
        if not any(p in _BUILD_OUTPUT_PARTS for p in parts):
            continue
        src = (wt / rel)
        try:
            if not src.is_file():
                continue
            if not src.resolve().is_relative_to(root):
                continue
        except (OSError, ValueError):
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, target)
        except OSError:
            continue
        n += 1
        if n >= _BUILD_CACHE_MAX_FILES:
            break
    if n:
        (dest / ".sentinel-build-count").write_text(str(n) + "\n")
    return n


def restore_build_cache(dest: Path, wt: Path) -> bool:
    """Put a previous build for this same commit back. False if nothing was saved."""
    marker = dest / ".sentinel-build-count"
    if not marker.is_file():
        return False
    root = wt.resolve()
    restored = 0
    for path in dest.rglob("*"):
        if not path.is_file() or path.name == ".sentinel-build-count":
            continue
        try:
            rel = path.relative_to(dest).as_posix()
        except ValueError:
            continue
        parts = rel.split("/")
        if ".." in parts or any(p in _BUILD_CACHE_SKIP for p in parts):
            continue
        target = wt / rel
        try:
            if not target.resolve().is_relative_to(root):
                continue
        except (OSError, ValueError):
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(path, target)
        except OSError:
            continue
        restored += 1
    return restored > 0


def _install_display(root: Path, manager: str) -> str:
    """Frozen install a person can run. No cache paths."""
    pm = _pm_field(root)
    if manager == "pnpm":
        tool = ["corepack", "pnpm"] if pm.startswith("pnpm@") else ["pnpm"]
        cmd = tool + ["install", "--frozen-lockfile"]
        if not pnpm_build_allowlist(root):
            cmd.append("--ignore-scripts")
        return _display(cmd)
    if manager == "yarn" and _yarn_berry(root):
        rel = _yarn_path(root)
        head = ["node", rel] if rel else (["corepack", "yarn"] if pm.startswith("yarn@") else ["yarn"])
        return _display(head + ["install", "--immutable", "--mode=skip-build"])
    if manager == "yarn":
        tool = ["corepack", "yarn"] if pm.startswith("yarn@") else ["yarn"]
        return _display(tool + ["install", "--frozen-lockfile", "--ignore-scripts"])
    return _display(["npm", "ci", "--ignore-scripts"])


def _tool_argv(root: Path, manager: str) -> list[str]:
    pm = _pm_field(root)
    if manager == "yarn" and _yarn_berry(root):
        rel = _yarn_path(root)
        if rel:
            return ["node", rel]
        if pm.startswith("yarn@"):
            return ["corepack", "yarn"]
        return ["yarn"]
    if pm.startswith(manager + "@"):
        return ["corepack", manager]
    return [manager]


def workspace_reproduce_fields(root: Path, rel_file: str, present=None) -> dict | None:
    """Install + filtered build a monorepo card can show. ``None`` for a single package.

    Every token is generated here from a validated package name. Script bodies
    from the repo are never copied into the command.
    """
    if workspace_globs(root) is None:
        return None
    packages = discover_workspaces(root)
    if not packages:
        return None
    loc = locate_test_file(root, rel_file, packages, present=present)
    if not isinstance(loc, tuple):
        return None
    pkg_rel, _inner = loc
    manager = _manager_of(root)
    turbo = ["turbo"] if _turbo_build_task(root) and _turbo_lockfile_readable(root) else None
    plan = plan_workspace_build(
        root, pkg_rel, pm_argv=_tool_argv(root, manager), manager=manager, turbo_bin=turbo,
    )
    if plan is None or plan.error or not plan.steps:
        return None
    parts: list[str] = []
    for step in plan.steps:
        argv = list(step.argv)
        if argv and Path(argv[0]).name == "turbo":
            argv[0] = "turbo"
        piece = _display(argv)
        if not piece:
            return None
        parts.append(piece)
    install = _install_display(root, manager)
    if not install:
        return None
    return {
        "install": install,
        "build": " && ".join(parts),
        "test_dir": "" if pkg_rel in ("", ".") else pkg_rel,
    }


def _git(repo: Path, *args: str, timeout: float = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args],
        capture_output=True, timeout=timeout,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
    )


def _snapshot_manifests(repo: Path, sha: str, dest: Path) -> bool:
    """Copy workspace manifests at ``sha`` into ``dest``. Does not run scripts."""
    try:
        listed = _git(repo, "ls-tree", "-r", "--name-only", sha, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if listed.returncode != 0:
        return False
    names = {
        "package.json", "pnpm-workspace.yaml", "pnpm-workspace.yml", "turbo.json",
        "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "npm-shrinkwrap.json",
        ".yarnrc.yml",
    }
    n = 0
    for rel in listed.stdout.decode("utf-8", errors="replace").splitlines():
        if not rel or "node_modules" in rel.split("/") or rel.startswith(".git/"):
            continue
        if rel.rsplit("/", 1)[-1] not in names:
            continue
        if n >= 400:
            break
        try:
            blob = _git(repo, "show", f"{sha}:{rel}", timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if blob.returncode != 0 or len(blob.stdout) > 30_000_000:
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob.stdout)
        n += 1
    return (dest / "package.json").is_file() or (dest / "pnpm-workspace.yaml").is_file()


def attach_workspace_reproduce(card: dict, repo: str | None) -> None:
    """Record the monorepo install + build on the card (render has no checkout)."""
    if not repo:
        return
    ft = card.get("failing_tests") if isinstance(card.get("failing_tests"), dict) else {}
    if ft.get("runner") not in ("vitest", "jest", "mocha"):
        return
    ids = [t for t in (ft.get("ids") or []) if isinstance(t, str)]
    if not ids:
        return
    rel = ids[0].split(" > ", 1)[0].strip()
    if not rel or rel.startswith("/") or ".." in rel.split("/"):
        return
    root = Path(repo)
    rng = card.get("range") if isinstance(card.get("range"), dict) else {}
    head = str(rng.get("head_sha") or "")
    sha = head.lower() if re.fullmatch(r"[0-9a-fA-F]{40}", head) else ""
    hint = None
    if sha:
        try:
            exists = _git(root, "cat-file", "-e", sha + "^{commit}")
        except (OSError, subprocess.TimeoutExpired):
            exists = None
        if exists is not None and exists.returncode == 0:
            import tempfile
            with tempfile.TemporaryDirectory(prefix="sentinel-ws-") as tmp:
                dest = Path(tmp)
                if _snapshot_manifests(root, sha, dest):
                    def present(path: str, _sha=sha, _root=root) -> bool:
                        try:
                            r = _git(_root, "cat-file", "-e", f"{_sha}:{path}")
                        except (OSError, subprocess.TimeoutExpired):
                            return False
                        return r.returncode == 0
                    hint = workspace_reproduce_fields(dest, rel, present=present)
    if hint is None and root.is_dir():
        hint = workspace_reproduce_fields(root, rel)
    if hint:
        card["workspace_reproduce"] = hint


def remove_node_modules(root: Path) -> None:
    """Delete every ``node_modules`` directory under ``root`` (not the store)."""
    for dirpath, dirnames, _filenames in os.walk(root):
        if ".git" in dirnames:
            dirnames.remove(".git")
        if "node_modules" in dirnames:
            target = Path(dirpath) / "node_modules"
            dirnames.remove("node_modules")
            shutil.rmtree(target, ignore_errors=True)
