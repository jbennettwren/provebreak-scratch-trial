"""One browser spec, at the Playwright revision its package pins.

The spec id is relative to the nearest ``playwright.config.{ts,js,mjs,cjs}``.
That directory is where ``npx playwright test --config`` runs. A range or a
missing lock entry for that package is not a pin. The same relative path
under two configs is not one spec. Two runs that disagree are a flake, and a
flake is not a culprit. A failure whose error line is not the one from the
job log is not that failure.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

_BROWSER_LOG = re.compile(
    r"playwright|@vitest/browser|e2e-browser|\[chromium\]|\[firefox\]|\[webkit\]",
    re.I,
)
_PW_FAIL = re.compile(
    r"(?P<file>(?:[\w.+@-]+/)*[\w.+@-]+\.(?:spec|test)\.[cm]?[jt]sx?)"
    r"(?::\d+:\d+)?\s+›\s+(?P<title>.+?)\s*$"
)
# A passing row (✓) is not a failing spec. A numbered list row, a ✘, or a
# project tag is. The duration and the box-drawing rule are not part of the title.
_PW_FAIL_MARK = re.compile(
    r"(?:✘|×|(?:^|\s)\d+\)|\[(?:chromium|firefox|webkit)\])",
    re.I,
)
_PW_DURATION = re.compile(r"\s+\(\d+(?:\.\d+)?m?s\)\s*$")
_PW_RULE = re.compile(r"\s*[─]{3,}.*$")
_PW_FILE = re.compile(
    r"^(?:[\w.+@-]+/)*[\w.+@-]+\.(?:spec|test)\.[cm]?[jt]sx?$"
)
_BROWSER_MISSING = re.compile(
    r"Executable doesn't exist|browserType\.launch:\s*Executable|"
    r"Please run the following command to download new browsers|"
    r"error while loading shared libraries",
    re.I,
)
PLAYWRIGHT_INDEPENDENT_CAP = 5
_EXACT = re.compile(r"^\d+\.\d+\.\d+$")
_RANGE = re.compile(r"[\^~*xX]| - ")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_PW_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_PW_GH_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z ?")
_PW_WF = re.compile(r"^##\[[A-Za-z]+\]\s?")


def _plain(text: str) -> str:
    return _ANSI.sub("", text or "")


def _pw_line(raw: str) -> str:
    line = raw.lstrip("\ufeff")
    for _ in range(4):
        nxt = _PW_WF.sub("", _PW_GH_TS.sub("", _PW_ANSI.sub("", line)))
        if nxt == line:
            break
        line = nxt
    return line.rstrip("\r").strip().replace("\\", "/")


def looks_like_browser(log_text: str) -> bool:
    return bool(_BROWSER_LOG.search(log_text or ""))


def _clean_title(title: str) -> str:
    text = _PW_DURATION.sub("", (title or "").strip())
    text = _PW_RULE.sub("", text).strip()
    return text


def _failure_line(line: str) -> bool:
    """A Playwright result row for a failure, not a passing ✓ row."""
    if "✓" in line or "✔" in line:
        return False
    return bool(_PW_FAIL_MARK.search(line))


def playwright_specs(log_text: str) -> list[str]:
    """Failing ``file.spec.ts › title`` lines, in order, without duplicates.

    Windows job logs print ``test\\ui.spec.ts``. Those are the same spec as
    ``test/ui.spec.ts``. A passing ``✓`` row is not a failure. A trailing
    ``(1.2s)`` is not part of the title. ``*.e2e.ts`` is not this shape.
    """
    found: list[str] = []
    for line in (log_text or "").splitlines():
        raw = _pw_line(line)
        if not _failure_line(raw):
            continue
        match = _PW_FAIL.search(raw)
        if not match:
            continue
        title = _clean_title(match.group("title"))
        if not title:
            continue
        spec = f"{match.group('file')} › {title}"
        if spec not in found:
            found.append(spec)
    return found


def browser_launch_missing(output: str) -> bool:
    """The run did not start a browser. That is not a failing assertion."""
    return bool(_BROWSER_MISSING.search(output or ""))


def spec_needs_browser(source: str) -> bool:
    """The spec source names a browser fixture. A bare ``expect`` does not."""
    return bool(re.search(r"\b(?:page|browser|browserName|context)\b", source or ""))


def safe_spec_path(file: str) -> str:
    """A relative spec path, or '' when the path is not one we can open."""
    rel = (file or "").replace("\\", "/").strip()
    if rel.startswith("./"):
        rel = rel[2:]
    if not rel or rel.startswith("/") or ".." in rel.split("/"):
        return ""
    if not _PW_FILE.match(rel):
        return ""
    return rel


def classify_browser(log_text: str, tests: list[str]) -> tuple[str, str] | None:
    """``(runner, spec)`` for one browser spec, ``('many', '')`` when several, else None.

    ``runner`` is ``playwright`` or ``vitest``. A test id that merely contains
    ``e2e`` is not a browser spec unless the log shows a browser runner.
    """
    specs = playwright_specs(log_text)
    if len(specs) > 1:
        return ("many", "")
    if len(specs) == 1:
        return ("playwright", specs[0])
    if not looks_like_browser(log_text):
        return None
    ids = [str(item) for item in tests if item]
    if len(ids) == 1:
        return ("vitest", ids[0])
    if len(ids) > 1:
        return ("many", "")
    return None


def _exact_version(value: str) -> str:
    text = (value or "").strip()
    if _EXACT.match(text):
        return text
    return ""


# ``playwright@1.62.1:`` in a lock, not ``playwright-core`` and not a range key.
_LOCK_KEY = re.compile(
    r"""(?m)^[ \t]*['"]?(?P<name>@playwright/test|playwright)@(?P<ver>\d+\.\d+\.\d+)['"]?\s*:"""
)
# pnpm importer: ``playwright:`` then ``version: 1.62.1`` (the specifier line is a range).
_PNPM_RESOLVED = re.compile(
    r"""(?m)^[ \t]*['"]?(?P<name>@playwright/test|playwright)['"]?:\s*\n"""
    r"""(?:[ \t]+(?!version:)[^\n]*\n){0,8}?[ \t]+version:\s*['"]?(?P<ver>\d+\.\d+\.\d+)"""
)
_YARN_RESOLVED = re.compile(
    r"""(?m)^['"]?(?P<name>@playwright/test|playwright)@[^:\n]+:\s*\n"""
    r"""(?:[ \t]+[^\n]+\n)*?[ \t]+version\s+['"](?P<ver>\d+\.\d+\.\d+)['"]"""
)
_PIN_PACKAGES = ("@playwright/test", "playwright")


def _remember(versions: list[str], version: str) -> None:
    if version and version not in versions:
        versions.append(version)


def _versions_in(text: str) -> list[str]:
    """Resolved Playwright versions in a lockfile body. A range is not a version."""
    found: list[str] = []
    blob = text or ""
    for pattern in (_LOCK_KEY, _PNPM_RESOLVED, _YARN_RESOLVED):
        for match in pattern.finditer(blob):
            if match.group("name") not in _PIN_PACKAGES:
                continue
            _remember(found, match.group("ver"))
    return found


def playwright_pin_text(*blobs: str) -> str:
    """One exact Playwright version, or '' when the pin is missing, a range, or ambiguous.

    An exact ``package.json`` version is a pin. When that file only has a range,
    the single version a lockfile resolved (``playwright@1.62.1`` or the pnpm
    ``version:`` under ``playwright:``) is the pin. Two different resolved
    versions are not a pin.
    """
    versions: list[str] = []
    for blob in blobs:
        if not blob:
            continue
        try:
            data = json.loads(blob)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            packages = data.get("packages") if isinstance(data.get("packages"), dict) else {}
            for name in ("node_modules/@playwright/test", "node_modules/playwright"):
                entry = packages.get(name)
                if isinstance(entry, dict):
                    _remember(versions, _exact_version(str(entry.get("version") or "")))
            deps = data.get("dependencies") if isinstance(data.get("dependencies"), dict) else {}
            for name in _PIN_PACKAGES:
                locked = deps.get(name)
                if isinstance(locked, dict):
                    _remember(versions, _exact_version(str(locked.get("version") or "")))
            for key in ("dependencies", "devDependencies"):
                bucket = data.get(key) if isinstance(data.get(key), dict) else {}
                for name in _PIN_PACKAGES:
                    raw = bucket.get(name)
                    if not isinstance(raw, str) or _RANGE.search(raw):
                        continue
                    _remember(versions, _exact_version(raw))
        for version in _versions_in(blob):
            _remember(versions, version)
    if len(versions) == 1:
        return versions[0]
    return ""


def _git_show(repo: Path, sha: str, path: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), "show", f"{sha}:{path}"],
        capture_output=True, text=True, timeout=30,
    )
    if proc.returncode != 0:
        return ""
    return proc.stdout


def playwright_pin_at(repo: Path, sha: str) -> str:
    """The Playwright test-runner version pinned at ``sha``, or ''."""
    blobs = [
        _git_show(repo, sha, name)
        for name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "package.json")
    ]
    return playwright_pin_text(*blobs)


_CONFIG_NAMES = (
    "playwright.config.ts",
    "playwright.config.js",
    "playwright.config.mjs",
    "playwright.config.cjs",
)
_WALK_SKIP = frozenset({"node_modules", ".git"})
_LOCK_NAMES = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")


class PlaywrightLayout:
    """One spec, the directory of its nearest Playwright config, and that config."""

    def __init__(self, package_dir: Path, config: Path | None, spec_rel: str, repo_rel: str):
        self.package_dir = package_dir
        self.config = config
        self.spec_rel = spec_rel
        self.repo_rel = repo_rel


class PlaywrightLayoutError:
    def __init__(self, detail: str, kind: str):
        self.detail = detail
        self.kind = kind


def _read_text(path: Path, limit: int = 8_000_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(_read_text(path, 1_000_000))
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _walk_up(start: Path, root: Path):
    cur = start.resolve()
    root_r = root.resolve()
    while True:
        yield cur
        if cur == root_r:
            return
        parent = cur.parent
        if parent == cur:
            return
        cur = parent


def _configs_in(directory: Path) -> list[Path]:
    return [directory / name for name in _CONFIG_NAMES if (directory / name).is_file()]


def _nearest_config(start: Path, root: Path) -> Path | str | None:
    """The nearest config walking up, ``ambiguous`` when one directory has two, else None."""
    for directory in _walk_up(start, root):
        found = _configs_in(directory)
        if len(found) > 1:
            return "ambiguous"
        if len(found) == 1:
            return found[0]
    return None


def _spec_files(root: Path, rel: str) -> list[Path]:
    """Files whose repo-relative path is ``rel`` or ends with ``/rel``. Skip installed deps."""
    name = Path(rel).name
    root_r = root.resolve()
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [item for item in dirnames if item not in _WALK_SKIP]
        if name not in filenames:
            continue
        candidate = (Path(dirpath) / name).resolve()
        try:
            suffix = candidate.relative_to(root_r).as_posix()
        except ValueError:
            continue
        if suffix == rel or suffix.endswith("/" + rel):
            found.append(candidate)
    return found


def resolve_playwright_layout(root: Path, spec_file: str) -> PlaywrightLayout | PlaywrightLayoutError:
    """The package that owns this spec id, or an abstain.

    Playwright prints the path relative to the directory of the nearest
    ``playwright.config.{ts,js,mjs,cjs}``. A file at the repository root with
    no config is the old single-package layout. The same relative path under
    two configs is ``playwright_ambiguous_spec``. A missing file is
    ``playwright_unsupported_layout`` with kind ``not_found``.
    """
    rel = safe_spec_path(spec_file)
    if not rel:
        return PlaywrightLayoutError("playwright_unsupported_layout", "unknown")
    root_r = root.resolve()
    owners: list[PlaywrightLayout] = []
    seen: set[str] = set()
    for candidate in _spec_files(root, rel):
        repo_rel = candidate.relative_to(root_r).as_posix()
        if repo_rel in seen:
            continue
        seen.add(repo_rel)
        config = _nearest_config(candidate.parent, root)
        if config == "ambiguous":
            return PlaywrightLayoutError("playwright_ambiguous_spec", "unknown")
        if not isinstance(config, Path):
            continue
        spec_rel = candidate.relative_to(config.parent.resolve()).as_posix()
        # The log id is the path Playwright prints, relative to that config.
        if spec_rel != rel:
            continue
        owners.append(PlaywrightLayout(config.parent.resolve(), config, spec_rel, repo_rel))
    if len(owners) > 1:
        return PlaywrightLayoutError("playwright_ambiguous_spec", "unknown")
    if len(owners) == 1:
        return owners[0]
    direct = root_r / rel
    if direct.is_file():
        config = _nearest_config(direct.parent, root)
        if config == "ambiguous":
            return PlaywrightLayoutError("playwright_ambiguous_spec", "unknown")
        if isinstance(config, Path):
            spec_rel = direct.resolve().relative_to(config.parent.resolve()).as_posix()
            return PlaywrightLayout(
                config.parent.resolve(), config, spec_rel, direct.resolve().relative_to(root_r).as_posix(),
            )
        return PlaywrightLayout(root_r, None, rel, rel)
    return PlaywrightLayoutError("playwright_unsupported_layout", "not_found")


def _dep_shape(data: dict) -> tuple[list[str], bool]:
    """Exact Playwright versions declared by this package, and whether a range is declared."""
    exacts: list[str] = []
    ranged = False
    for key in ("dependencies", "devDependencies"):
        bucket = data.get(key) if isinstance(data.get(key), dict) else {}
        for name in _PIN_PACKAGES:
            raw = bucket.get(name)
            if not isinstance(raw, str):
                continue
            exact = _exact_version(raw)
            if exact:
                _remember(exacts, exact)
            else:
                ranged = True
    return exacts, ranged


def _npm_package_pin(lock_text: str, package_rel: str) -> str:
    """The version ``package-lock.json`` resolves for this package path, or ''."""
    try:
        data = json.loads(lock_text or "")
    except json.JSONDecodeError:
        return ""
    packages = data.get("packages") if isinstance(data.get("packages"), dict) else {}
    entry = packages.get(package_rel)
    if not isinstance(entry, dict):
        return ""
    declared = False
    for key in ("dependencies", "devDependencies"):
        bucket = entry.get(key) if isinstance(entry.get(key), dict) else {}
        if any(isinstance(bucket.get(name), str) for name in _PIN_PACKAGES):
            declared = True
    if not declared:
        return ""
    versions: list[str] = []
    if package_rel:
        nested = (
            f"{package_rel}/node_modules/@playwright/test",
            f"{package_rel}/node_modules/playwright",
        )
    else:
        nested = ("node_modules/@playwright/test", "node_modules/playwright")
    for key in nested:
        item = packages.get(key)
        if isinstance(item, dict):
            _remember(versions, _exact_version(str(item.get("version") or "")))
    if len(versions) == 1:
        return versions[0]
    if versions:
        return ""
    hoisted: list[str] = []
    for key in ("node_modules/@playwright/test", "node_modules/playwright"):
        item = packages.get(key)
        if isinstance(item, dict):
            _remember(hoisted, _exact_version(str(item.get("version") or "")))
    if len(hoisted) == 1:
        return hoisted[0]
    return ""


def _pnpm_importer_block(text: str, importer: str) -> str:
    lines = (text or "").splitlines()
    key = f"  {importer}:"
    in_importers = False
    start = None
    for index, line in enumerate(lines):
        if line == "importers:" or line.startswith("importers:"):
            in_importers = True
            continue
        if in_importers and line and not line.startswith(" "):
            break
        if in_importers and line == key:
            start = index + 1
            break
    if start is None:
        return ""
    block: list[str] = []
    for line in lines[start:]:
        if line.startswith("  ") and not line.startswith("   ") and line.endswith(":"):
            break
        block.append(line)
    return "\n".join(block)


def _pnpm_importer_pin(lock_text: str, package_rel: str) -> str:
    importer = "." if not package_rel else package_rel
    block = _pnpm_importer_block(lock_text, importer)
    if not block:
        return ""
    if not re.search(r"(?m)^[ \t]*['\"]?(?:@playwright/test|playwright)['\"]?:", block):
        return ""
    return playwright_pin_text(block)


def _lock_rel(lock_dir: Path, package_dir: Path) -> str:
    package = package_dir.resolve()
    base = lock_dir.resolve()
    if package == base:
        return ""
    return package.relative_to(base).as_posix()


def _scoped_lock_pin(root: Path, package_dir: Path) -> str:
    """One lockfile version recorded for this package, or ''."""
    versions: list[str] = []
    for directory in _walk_up(package_dir, root):
        present = [directory / name for name in _LOCK_NAMES if (directory / name).is_file()]
        if not present:
            continue
        rel = _lock_rel(directory, package_dir)
        for path in present:
            text = _read_text(path)
            if path.name == "package-lock.json":
                pin = _npm_package_pin(text, rel)
            elif path.name == "pnpm-lock.yaml":
                pin = _pnpm_importer_pin(text, rel)
            else:
                pin = playwright_pin_text(text)
            if pin:
                _remember(versions, pin)
        break
    if len(versions) == 1:
        return versions[0]
    return ""


def playwright_pin_in_tree(root: Path) -> str:
    """The root pin, using the same rules as ``playwright_pin_at`` on the checkout."""
    blobs = [_read_text(root / name) for name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "package.json")]
    return playwright_pin_text(*blobs)


def playwright_pin_for_package(root: Path, package_dir: Path) -> str:
    """The pin for the package that owns the spec.

    The repository root keeps the existing rule: an exact ``package.json``
    version, or one version in the root lockfile. A subpackage with an exact
    version uses that version. A subpackage range uses the lockfile resolution
    recorded for that package. A range with no single resolution is ''.
    """
    root_r = root.resolve()
    cur = package_dir.resolve()
    if cur == root_r:
        return playwright_pin_in_tree(root)
    while cur != root_r:
        data = _read_json(cur / "package.json")
        if data is not None:
            exacts, ranged = _dep_shape(data)
            if exacts or ranged:
                versions = list(exacts)
                lock_pin = _scoped_lock_pin(root, cur)
                if lock_pin:
                    _remember(versions, lock_pin)
                if len(versions) == 1:
                    return versions[0]
                return ""
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    return playwright_pin_in_tree(root)


def installed_playwright_version_from(start: Path, root: Path) -> str:
    """The Playwright version visible from ``start``, walking up to ``root``."""
    for directory in _walk_up(start, root):
        got = installed_playwright_version(directory)
        if got:
            return got
    return ""


def installed_playwright_version(root: Path) -> str:
    """The installed ``@playwright/test`` or ``playwright`` version, when there is one."""
    candidates = [
        root / "node_modules" / "@playwright" / "test" / "package.json",
        root / "node_modules" / "playwright" / "package.json",
    ]
    pnpm = root / "node_modules" / ".pnpm"
    if pnpm.is_dir():
        candidates.extend(sorted(pnpm.glob("@playwright+test@*/node_modules/@playwright/test/package.json"))[:4])
        candidates.extend(sorted(pnpm.glob("playwright@*/node_modules/playwright/package.json"))[:4])
    found: list[str] = []
    for path in candidates:
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        exact = _exact_version(str(data.get("version") or ""))
        if exact and exact not in found:
            found.append(exact)
    if len(found) == 1:
        return found[0]
    return ""


def _split_spec(spec: str) -> tuple[str, str]:
    text = (spec or "").strip()
    if " › " in text:
        file, title = text.split(" › ", 1)
        return file.strip(), title.strip()
    if " > " in text:
        file, title = text.split(" > ", 1)
        return file.strip(), title.strip()
    return text, ""


def browser_fault_line(log_text: str) -> str:
    """An ``Error:`` or ``Expected:`` line from a browser log, or ''."""
    for line in _plain(log_text).splitlines():
        clean = line.strip()
        low = clean.lower()
        if low.startswith("error:") or low.startswith("expected:"):
            return clean
    return ""


def spec_matches(spec: str, output: str, fault_text: str = "") -> bool:
    """The output fails this spec, and includes the captured error line when one was given."""
    file, title = _split_spec(spec)
    blob = _plain(output)
    if file and file not in blob:
        return False
    if title and title not in blob:
        return False
    message = ""
    for line in (fault_text or "").splitlines():
        clean = line.strip()
        if clean.lower().startswith("error:") or clean.lower().startswith("expected:"):
            message = clean
            break
    if message and message not in blob:
        return False
    return bool(file)


class PlaywrightSpecRunner:
    """Bisect one Playwright spec with the checkout's locked runner."""

    def __init__(self, repo: Path, *, per_run_timeout_sec: float, cache_dir: Path | None = None, fault_text: str = ""):
        from provebreak_culprit._engine.bisect import PytestGitRunner

        self.repo = Path(repo)
        self.per_run_timeout_sec = float(per_run_timeout_sec)
        self.cache_dir = Path(cache_dir) if cache_dir else Path("/tmp") / "sentinel-playwright-cache"
        self.fault_text = fault_text or ""
        self.fault_file = ""
        self.install_mode = ""
        self.launch = ()
        self._git = PytestGitRunner(repo=self.repo, per_run_timeout_sec=self.per_run_timeout_sec)

    def validate_ids(self, tests) -> tuple[list[str], str | None]:
        rows = [str(item) for item in tests if str(item).strip()]
        if len(rows) != 1:
            return [], "browser_spec_count"
        return rows, None

    def cleanup(self) -> None:
        self._git.cleanup()

    def evaluate(self, sha: str, tests, *, reruns: int, deadline: float | None = None):
        from provebreak_culprit._engine.bisect import EvalResult, build_scrubbed_env, git_clean_worktree, remaining_budget, run_capped

        clean, err = self.validate_ids(tests)
        if err:
            return EvalResult(label="error", detail=err, kind="unknown")
        spec = clean[0]
        self.install_mode = ""
        self.fault_file = _split_spec(spec)[0]
        wt = self._git._ensure_worktree(sha)
        if wt is None:
            return EvalResult(label="error", detail=f"checkout_failed:{sha[:12]}", kind="checkout")
        try:
            if wt.resolve() == self.repo.resolve():
                return EvalResult(label="error", detail="refuse_clean_primary_checkout", kind="checkout")
            git_clean_worktree(wt, timeout=min(30.0, max(0.5, remaining_budget(deadline))))
        except (OSError, subprocess.TimeoutExpired):
            return EvalResult(label="error", detail="checkout_failed", kind="checkout")
        layout = resolve_playwright_layout(wt, _split_spec(spec)[0])
        if isinstance(layout, PlaywrightLayoutError):
            # A missing file is not_found: the bisect treats that on the parent
            # as "the test was not here yet", and an error on the tip as an abstain.
            return EvalResult(label="error", detail=layout.detail, kind=layout.kind)
        self.fault_file = layout.repo_rel
        pin = playwright_pin_for_package(wt, layout.package_dir)
        if not pin:
            return EvalResult(label="error", detail="playwright_unpinned", kind="unknown")
        home = Path("/tmp") / f"sentinel-pw-home-{os.getpid()}"
        home.mkdir(parents=True, exist_ok=True)
        env = build_scrubbed_env(home=str(home))
        installed = self._ensure_modules(wt, env, deadline, pin)
        if installed is not None:
            return installed
        got = installed_playwright_version_from(layout.package_dir, wt)
        if got != pin:
            return EvalResult(
                label="error",
                detail=f"playwright_version_mismatch:{got or 'missing'}!={pin}",
                kind="unknown",
            )
        spec_path = layout.package_dir / layout.spec_rel
        try:
            source = spec_path.read_text(encoding="utf-8", errors="replace")[:200_000]
        except OSError:
            return EvalResult(label="error", detail="playwright_unsupported_layout", kind="unknown")
        if spec_needs_browser(source):
            from provebreak_culprit._engine.runners import ensure_playwright_browsers

            ensure_playwright_browsers(wt, self.cache_dir, env, deadline, pin=pin)
        launch = self._launch(wt, spec, layout)
        if launch is None:
            return EvalResult(label="error", detail="playwright_cli_missing", kind="unknown")
        cmd, cwd = launch
        run_env = self._path_for(layout, wt, env)
        labels = []
        runs = max(1, int(reruns))
        for _ in range(runs):
            if remaining_budget(deadline) < 0.05:
                labels.append(EvalResult(label="error", detail="budget_exhausted", kind="timeout"))
                break
            timeout = min(self.per_run_timeout_sec, remaining_budget(deadline))
            if timeout < 0.05:
                labels.append(EvalResult(label="error", detail="budget_exhausted", kind="timeout"))
                break
            try:
                rc, out, err_text = run_capped(cmd, cwd=cwd, env=run_env, timeout=timeout)
            except subprocess.TimeoutExpired:
                labels.append(EvalResult(label="error", detail="timeout", kind="timeout"))
                continue
            except (OSError, FileNotFoundError) as exc:
                labels.append(EvalResult(label="error", detail=type(exc).__name__, kind="os"))
                break
            blob = (out or "") + "\n" + (err_text or "")
            if rc == 0:
                labels.append(EvalResult(label="green", passes=1, runs=1, kind="pass"))
            elif browser_launch_missing(blob):
                labels.append(EvalResult(
                    label="error", detail="playwright_browser_missing", kind="env_setup",
                ))
            elif spec_matches(spec, blob, self.fault_text):
                labels.append(EvalResult(label="red", fails=1, runs=1, kind="fail", detail="spec_failed"))
            else:
                labels.append(EvalResult(
                    label="error", detail="unrelated_error", kind="unrelated_error",
                ))
        return _combine(labels)

    def _argv(self, wt: Path, spec: str) -> list[str] | None:
        """Root layout with no Playwright config. The installed CLI runs the spec."""
        launch = self._launch(wt, spec, PlaywrightLayout(wt, None, _split_spec(spec)[0], _split_spec(spec)[0]))
        if launch is None:
            return None
        return launch[0]

    def _launch(self, wt: Path, spec: str, layout: PlaywrightLayout) -> tuple[list[str], Path] | None:
        """``(argv, cwd)``. A config runs ``npx playwright test --config`` in that directory."""
        _file, title = _split_spec(spec)
        if layout.config is not None:
            npx = shutil.which("npx")
            if not npx:
                return None
            cmd = [
                npx, "--no-install", "playwright", "test", layout.spec_rel,
                "--config", layout.config.name,
                "--retries=0", "--workers=1",
            ]
            if title:
                cmd.extend(["-g", re.escape(title)])
            self.launch = (str(layout.package_dir), cmd)
            return cmd, layout.package_dir
        cli = wt / "node_modules" / "@playwright" / "test" / "cli.js"
        node = shutil.which("node")
        if not node or not cli.is_file():
            return None
        cmd = [node, str(cli), "test", layout.spec_rel, "--retries=0", "--workers=1"]
        if title:
            cmd.extend(["-g", re.escape(title)])
        self.launch = (str(wt), cmd)
        return cmd, wt

    def _path_for(self, layout: PlaywrightLayout, wt: Path, env: dict) -> dict:
        if layout.config is None:
            return env
        bins: list[str] = []
        for directory in _walk_up(layout.package_dir, wt):
            bindir = directory / "node_modules" / ".bin"
            if bindir.is_dir():
                bins.append(str(bindir))
        if not bins:
            return env
        child = dict(env)
        child["PATH"] = os.pathsep.join([*bins, child.get("PATH", "")])
        return child

    def _note_install_mode(self, wt: Path) -> None:
        marker = wt / "node_modules" / ".sentinel-lock-sha256"
        try:
            lines = marker.read_text().splitlines()
        except OSError:
            return
        if len(lines) > 2 and lines[2].strip() == "non_frozen":
            self.install_mode = "non_frozen"

    def _ensure_modules(self, wt: Path, env: dict, deadline, pin: str):
        """Install the checkout with the same fallbacks as a vitest bisect.

        A stripped copy of ``package.json`` plus the lockfile drops
        ``pnpm-workspace.yaml``, so a frozen pnpm install reports a catalogs
        mismatch that the real tree does not have. The install runs in the
        checkout.
        """
        from provebreak_culprit._engine.bisect import EvalResult, remaining_budget
        from provebreak_culprit._engine.runners import JsGitRunner

        if installed_playwright_version(wt) == pin:
            self._note_install_mode(wt)
            return None
        lock = ""
        for name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
            if (wt / name).is_file():
                lock = name
                break
        if not lock:
            return EvalResult(label="error", detail="playwright_unpinned", kind="unknown")
        timeout = min(180.0, remaining_budget(deadline))
        if timeout < 5:
            return EvalResult(label="error", detail="budget_exhausted", kind="timeout")
        child_env = dict(env)
        child_env.setdefault("CI", "true")
        helper = JsGitRunner(
            repo=self.repo, framework="vitest", cache_dir=self.cache_dir,
            install_timeout_sec=timeout, ignore_scripts=True, max_installs=3,
        )
        bad = helper._install(wt, child_env, deadline, ".")
        self.install_mode = helper.install_mode
        if bad is None:
            return None
        detail = bad.detail or ""
        if detail.startswith("install_unfaithful:") or detail.startswith("peer_deps_blocked:"):
            return bad
        if bad.kind in ("timeout", "install_budget"):
            return bad
        quoted = detail.replace("\n", " ")[-180:]
        return EvalResult(
            label="error", detail=f"playwright_install_failed:{quoted}", kind="unknown",
        )


def _combine(labels: list):
    from provebreak_culprit._engine.bisect import EvalResult

    if not labels:
        return EvalResult(label="error", detail="no_runs", kind="unknown")
    passes = sum(1 for item in labels if item.label == "green")
    fails = sum(1 for item in labels if item.label == "red")
    errors = [item for item in labels if item.label not in ("green", "red")]
    if errors:
        last = errors[-1]
        return EvalResult(
            label="error", passes=passes, fails=fails, runs=len(labels),
            detail=last.detail, kind=last.kind or "unknown",
        )
    if passes == len(labels):
        return EvalResult(label="green", passes=passes, runs=len(labels), kind="pass")
    if fails == len(labels):
        return EvalResult(label="red", fails=fails, runs=len(labels), kind="fail")
    return EvalResult(label="flaky", passes=passes, fails=fails, runs=len(labels), kind="mixed")


class PinnedVitestBrowser:
    """A vitest browser spec. Refuses a checkout that does not pin Playwright."""

    def __init__(self, inner, repo: Path):
        self.inner = inner
        self.repo = Path(repo)
        self.fault_file = ""

    def validate_ids(self, tests):
        validate = getattr(self.inner, "validate_ids", None)
        if callable(validate):
            return validate(tests)
        return list(tests), None

    def cleanup(self) -> None:
        cleanup = getattr(self.inner, "cleanup", None)
        if callable(cleanup):
            cleanup()

    def evaluate(self, sha: str, tests, *, reruns: int, deadline: float | None = None):
        from provebreak_culprit._engine.bisect import EvalResult

        if not playwright_pin_at(self.repo, sha):
            return EvalResult(label="error", detail="playwright_unpinned", kind="unknown")
        clean, err = self.validate_ids(tests)
        if not err and clean:
            self.fault_file = _split_spec(str(clean[0]))[0]
        return self.inner.evaluate(sha, tests, reruns=max(1, int(reruns)), deadline=deadline)


def action_bisect_playwright(
    repo: Path,
    tests: list[str],
    *,
    good_sha: str,
    bad_sha: str,
    fault_text: str = "",
    cache_dir: Path | None = None,
    time_budget_sec: float = 1200,
    step_budget: int = 16,
    flaky_reruns: int = 3,
    confirm_reruns: int | None = None,
    expected_commit_count: int | None = None,
    per_run_timeout_sec: float | None = None,
    base_cls: type | None = None,
):
    """Bisect each Playwright spec on its own, the way the local history tool does.

    A commit is named only when every spec included in the verdict proved that
    same commit. Two specs that prove different commits name nothing. Specs
    past the cap are not folded into a proof.
    """
    import time

    from provebreak_culprit._engine.bisect import BisectResult, confirm_culprit_safe, remaining_budget
    from provebreak_culprit._engine.runners import make_runner

    specs = [str(item) for item in tests if str(item).strip()]
    if not specs:
        return BisectResult(status="not_proven", reason="no_failing_tests_provided", failing_tests=[])
    cap = specs[:PLAYWRIGHT_INDEPENDENT_CAP]
    held = specs[PLAYWRIGHT_INDEPENDENT_CAP:]
    deadline = time.monotonic() + max(1.0, float(time_budget_sec))
    pairs: list[tuple[str, object]] = []
    for spec in cap:
        if remaining_budget(deadline) < 0.05:
            pairs.append((spec, BisectResult(
                status="budget_exhausted", reason="budget_exhausted", failing_tests=[spec],
            )))
            break
        runner = make_runner(
            "playwright", repo,
            per_run_timeout_sec=per_run_timeout_sec,
            cache_dir=cache_dir,
            fault_text=fault_text,
            base_cls=base_cls,
        )
        try:
            result = confirm_culprit_safe(
                repo=repo,
                good_sha=good_sha or "",
                bad_sha=bad_sha or "",
                failing_tests=[spec],
                runner=runner,
                time_budget_sec=time_budget_sec,
                step_budget=step_budget,
                flaky_reruns=flaky_reruns,
                confirm_reruns=confirm_reruns,
                expected_commit_count=expected_commit_count,
                deadline=deadline,
            )
        finally:
            cleanup = getattr(runner, "cleanup", None)
            if callable(cleanup):
                cleanup()
        pairs.append((spec, result))
    if len(pairs) == 1 and not held:
        return pairs[0][1]
    return _combine_playwright_bisects(pairs, held)


def _combine_playwright_bisects(pairs: list[tuple[str, object]], held: list[str]):
    """One verdict. Disagreeing proofs do not become one culprit."""
    from provebreak_culprit._engine.bisect import BisectResult

    proven = []
    for spec, result in pairs:
        status = str(getattr(result, "status", "") or "")
        sha = str(getattr(result, "culprit_sha", "") or "")
        if status == "proven" and sha:
            proven.append((spec, result))
    shas = {str(result.culprit_sha) for _spec, result in proven}
    parents = {str(getattr(result, "parent_sha", "") or "") for _spec, result in proven}
    steps = sum(int(getattr(result, "steps_used", 0) or 0) for _spec, result in pairs)
    elapsed = sum(float(getattr(result, "elapsed_sec", 0) or 0) for _spec, result in pairs)
    if len(shas) == 1 and len(parents) == 1 and "" not in parents:
        base = proven[0][1]
        tests: list[str] = []
        evaluations = list(getattr(base, "evaluations", None) or [])
        for spec, result in proven:
            for item in list(getattr(result, "failing_tests", None) or [spec]):
                if item not in tests:
                    tests.append(item)
            if result is not base:
                for row in list(getattr(result, "evaluations", None) or []):
                    if len(evaluations) >= 64:
                        break
                    evaluations.append(row)
        reason = str(getattr(base, "reason", "") or "")
        if held:
            reason = (reason + f"; {len(held)} spec(s) past the independent cap were not bisected").strip("; ")
        return BisectResult(
            status="proven",
            culprit_sha=str(base.culprit_sha),
            parent_sha=str(base.parent_sha),
            failing_tests=tests,
            reproductions=min(int(getattr(result, "reproductions", 0) or 0) for _s, result in proven),
            reproduction_attempts=min(int(getattr(result, "reproduction_attempts", 0) or 0) for _s, result in proven),
            steps_used=min(200, steps),
            elapsed_sec=elapsed,
            reason=reason[:300],
            evidence=str(getattr(base, "evidence", "") or "")[:400],
            evaluations=evaluations[:64],
            upstream=getattr(base, "upstream", None),
        )
    if len(shas) > 1:
        return BisectResult(
            status="not_proven",
            culprit_sha=None,
            parent_sha=None,
            failing_tests=[spec for spec, _result in proven],
            steps_used=min(200, steps),
            elapsed_sec=elapsed,
            reason="playwright specs proved different commits",
        )
    return _playwright_abstain(pairs, held, steps=steps, elapsed=elapsed)


def _playwright_abstain(pairs, held, *, steps: int, elapsed: float):
    """Keep the most specific abstain. Do not carry a candidate SHA forward."""
    from provebreak_culprit._engine.bisect import BisectResult

    if not pairs:
        reason = "no_failing_tests_provided"
        if held:
            reason = "playwright specs past the independent cap were not bisected"
        return BisectResult(status="not_proven", reason=reason, failing_tests=held[:5])

    def rank(result) -> int:
        text = f"{getattr(result, 'status', '')} {getattr(result, 'reason', '')}".lower()
        if "playwright_browser_missing" in text:
            return 0
        if "playwright_unsupported_layout" in text or "playwright_ambiguous_spec" in text:
            return 1
        if "unpinned" in text or "version_mismatch" in text:
            return 2
        if getattr(result, "status", "") == "inconclusive_flaky":
            return 3
        if getattr(result, "status", "") == "inconclusive_env":
            return 4
        if getattr(result, "status", "") == "budget_exhausted":
            return 5
        return 6

    chosen = min((result for _spec, result in pairs), key=rank)
    reason = str(getattr(chosen, "reason", "") or "not_proven")
    if held:
        reason = (reason + f"; {len(held)} spec(s) past the independent cap were not bisected").strip("; ")
    return BisectResult(
        status=str(getattr(chosen, "status", "") or "not_proven"),
        culprit_sha=None,
        parent_sha=None,
        failing_tests=list(getattr(chosen, "failing_tests", None) or []),
        steps_used=min(200, steps),
        elapsed_sec=elapsed,
        reason=reason[:300],
        evidence=str(getattr(chosen, "evidence", "") or "")[:400],
        evaluations=list(getattr(chosen, "evaluations", None) or [])[:64],
    )
