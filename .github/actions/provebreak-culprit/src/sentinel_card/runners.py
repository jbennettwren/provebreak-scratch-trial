"""Test runners and failing-test extraction for confirm-culprit bisect."""
from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path

from sentinel_card import cargo as cargo_support
from sentinel_card import cpp as cpp_support
from sentinel_card import jvm as jvm_support
from sentinel_card import phpunit as phpunit_support
from sentinel_card import ruby_test as ruby_support
from sentinel_card.bisect import _scrub_reason
from sentinel_card.bisect import apply_isolated_home
from sentinel_card.bisect import build_scrubbed_env
from sentinel_card.bisect import checkout_fidelity
from sentinel_card.bisect import CHECKOUT_FIDELITY_SEC
from sentinel_card.bisect import compiler_location
from sentinel_card.bisect import ensure_declared_services
from sentinel_card.bisect import EvalResult
from sentinel_card.bisect import extract_pytest_log
from sentinel_card.bisect import git_clean_worktree
from sentinel_card.bisect import make_isolated_home
from sentinel_card.bisect import PytestGitRunner
from sentinel_card.bisect import remaining_budget
from sentinel_card.bisect import run_capped
from sentinel_card.bisect import setup_error_quote
from sentinel_card.bisect import validate_node_ids
from sentinel_card.jsmonorepo import corepack_tool_shim_dir
from sentinel_card.jsmonorepo import discover_workspaces
from sentinel_card.jsmonorepo import find_turbo_bin
from sentinel_card.jsmonorepo import locate_test_file
from sentinel_card.jsmonorepo import plan_workspace_build
from sentinel_card.jsmonorepo import pnpm_build_allowlist
from sentinel_card.jsmonorepo import pnpm_major
from sentinel_card.jsmonorepo import pnpm_version_from_checkout
from sentinel_card.jsmonorepo import remove_node_modules
from sentinel_card.jsmonorepo import restore_build_cache
from sentinel_card.jsmonorepo import save_build_cache
from sentinel_card.jsmonorepo import scrub_turbo_remote
from sentinel_card.jsmonorepo import wipe_turbo_read_cache
from sentinel_card.jsmonorepo import workspace_project_args
from sentinel_card.jsmonorepo import yarn_corepack_shim_dir

RUNNERS = (
    "pytest", "go", "vitest", "jest", "mocha", "playwright", "junit", "dotnet",
    "cargo", "cpp", "minitest", "rspec", "phpunit",
)
JS_FRAMEWORKS = ("vitest", "jest", "mocha")
MAX_TEST_ID_LEN = 512

_GH_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z ?")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
# Test-id lines strip only SGR and erase-line. Any other ESC stays for the gate.
_SGR = re.compile(r"\x1b\[[0-9;]*m")
_EL = re.compile(r"\x1b\[[0-9]*K")
# Cursor show/hide only. A CSI class that ends on any letter is the r4 bug.
_CURSOR = re.compile(r"\x1b\[\?25[hl]")
# OSC 8 hyperlink: ESC ] 8 ; ; url ST. ST is ESC \ or BEL. The anchor stays.
_OSC8 = re.compile(r"\x1b\]8;;.*?(?:\x1b\\|\x07)")


# Test runners write these on every invocation. Hashing them made a healthy
# install look mutated and the old mtime wipe deleted it. A dependency edit
# is a file outside these directories.
_NM_HASH_SKIP_DIRS = frozenset({".cache", ".vite", ".turbo", ".parcel-cache"})


def _node_modules_content_hash(root: Path) -> str:
    """Hash of file bytes under an install tree. Mtimes are not part of it."""
    digest = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _NM_HASH_SKIP_DIRS and d != ".git")
        for name in sorted(filenames):
            if name == ".sentinel-lock-sha256":
                continue
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            digest.update(rel.encode())
            digest.update(b"\0")
            try:
                if path.is_symlink():
                    digest.update(b"L")
                    digest.update(os.readlink(path).encode())
                else:
                    digest.update(b"F")
                    digest.update(path.read_bytes())
            except OSError:
                digest.update(b"E")
            digest.update(b"\0")
    return digest.hexdigest()


def _is_content_hash(text: str) -> bool:
    return len(text) == 64 and all(c in "0123456789abcdef" for c in text)


def _discard_mutated_node_modules(root: Path) -> bool:
    """Drop an install tree whose bytes changed since the marker was written.

    ``git clean`` keeps ``node_modules`` so a lockfile hit can skip reinstall.
    A marker that only stored file count and newest mtime wiped healthy trees
    when a tool touched a file, so that wipe was left uncalled. This compares
    content. A legacy mtime marker is left in place. Returns True when a tree
    was removed.
    """
    removed = False
    for dirpath, dirnames, _filenames in os.walk(root):
        if "node_modules" not in dirnames:
            continue
        nm = Path(dirpath) / "node_modules"
        dirnames.remove("node_modules")
        marker = nm / ".sentinel-lock-sha256"
        if not marker.is_file():
            continue
        try:
            lines = marker.read_text().splitlines()
        except OSError:
            continue
        if len(lines) < 2 or not _is_content_hash(lines[1].strip()):
            continue
        if _node_modules_content_hash(nm) != lines[1].strip():
            shutil.rmtree(nm, ignore_errors=True)
            removed = True
    return removed


_WF_CMD = re.compile(r"^##\[[A-Za-z]+\]\s?")


def _clean_lines(log_text: str) -> list[str]:
    """Drop one leading GitHub timestamp, ANSI, and CR. Keep ``##[group]`` and ``##[error]``.

    History reports read those workflow commands from this cleaner. A timestamp
    hidden by ANSI, or a second timestamp on the same line, stays here, the
    same single pass as main. Test-id parsers strip those with
    ``_lines_for_test_ids``.
    """
    return [
        _ANSI.sub("", _GH_TS.sub("", ln.lstrip("\ufeff"))).rstrip("\r\n").rstrip()
        for ln in log_text.splitlines()
    ]


def _strip_test_id_esc(text: str) -> str:
    """SGR, erase-line, ``ESC[?25h`` / ``ESC[?25l``, and a full OSC 8 link.

    OSC 8 drops the URL and keeps the anchor. Any other ESC stays put.
    """
    return _OSC8.sub("", _CURSOR.sub("", _EL.sub("", _SGR.sub("", text))))


def _lines_for_test_ids(log_text: str) -> list[str]:
    """Drop a leading timestamp and workflow command. Strip a small ESC set.

    ``ESC[...m``, ``ESC[K`` / ``ESC[2K``, ``ESC[?25h`` / ``ESC[?25l``, and a
    full OSC 8 hyperlink come off. Any other ESC stays in the line so the
    summary gate can abstain. ``splitlines`` already breaks on CR, so two
    summaries joined by ``\\r`` stay two lines.
    """
    out = []
    for raw in (log_text or "").splitlines():
        line = _strip_test_id_esc(raw.lstrip("\ufeff"))
        line = _GH_TS.sub("", line).rstrip("\r\n").rstrip()
        for _ in range(4):
            nxt = _WF_CMD.sub("", _GH_TS.sub("", line))
            if nxt == line:
                break
            line = nxt
        out.append(line.rstrip())
    return out


def test_id_esc_error(log_text: str) -> str | None:
    """Abstain when a test-id log still has an ESC after the whitelist."""
    for raw in (log_text or "").splitlines() or [""]:
        if "\x1b" in _strip_test_id_esc(raw):
            return "test_ids_unparsed_entry"
    return None


# 5.2.0 (NS5): monorepo task runners prefix every line of a task's output:
#   turbo      "web:test: FAIL  src/a.test.ts > s > t"   ("<pkg>:<task>: ")
#   pnpm -r    "apps/web test: FAIL  src/a.test.ts > …"   ("<pkg> <script>: ")
# The task token must contain a letter (so "calc_test.go:9: msg" and
# "a.go:12:3: undefined" are never treated as prefixes). A prefix is only
# stripped when it repeats (>= 3 lines) and prefixed lines are >= 5 and >= 10%
# of non-empty lines, so a single "Runner name: x" line is never touched.
_TURBO_PREFIX = re.compile(r"^([\w@][\w@/.-]*:[\w:-]*[A-Za-z][\w:-]*): ?")
_PNPM_PREFIX = re.compile(r"^([\w@.][\w@/.-]* [\w-]*[A-Za-z][\w:-]*): ")


def _task_prefix(line: str) -> str | None:
    m = _TURBO_PREFIX.match(line) or _PNPM_PREFIX.match(line)
    return m.group(1) if m else None


def strip_task_prefixes(text: str) -> str:
    """Remove turbo / ``pnpm -r`` task prefixes (see above). Idempotent in practice."""
    if not text:
        return text or ""
    lines = text.split("\n")
    counts: dict[str, int] = {}
    nonempty = 0
    for ln in lines:
        if ln.strip():
            nonempty += 1
            p = _task_prefix(ln)
            if p:
                counts[p] = counts.get(p, 0) + 1
    keep = {p for p, n in counts.items() if n >= 3}
    total = sum(counts[p] for p in keep)
    if not keep or total < 5 or total < 0.10 * max(1, nonempty):
        return text
    out: list[str] = []
    for ln in lines:
        p = _task_prefix(ln)
        if p in keep:
            rest = ln[len(p):]
            if rest.startswith(": "):
                rest = rest[2:]
            elif rest.startswith(":"):
                rest = rest[1:]
            out.append(rest)
        else:
            out.append(ln)
    return "\n".join(out)


# =============================================================================
# Test ids
# =============================================================================
# Go:  "<package>::<TopLevelTest>"  package = import path or ./relative dir.
_GO_PKG = re.compile(r"^(?:\.|\./[A-Za-z0-9_.~+/-]+|[A-Za-z0-9_.~+-]+(?:/[A-Za-z0-9_.~+-]+)*)$")
_GO_TEST = re.compile(r"^(?:Test|Fuzz|Example)[A-Za-z0-9_]*$")
_GO_SEG = re.compile(r"^[A-Za-z0-9_-]+$")
_GO_MAX_DEPTH = 8
# JS:  "<file> > <suite> > ... > <test>"
_JS_FILE = re.compile(r"^[A-Za-z0-9_@.+~\-/\[\]()]+\.(?:[cm]?[jt]sx?)$")
JS_SEP = " > "


def go_test_path_ok(name: str) -> bool:
    """Top-level Go test, or TestX/Sub/Name. Each segment is [A-Za-z0-9_]."""
    parts = str(name or "").split("/")
    if not 1 <= len(parts) <= _GO_MAX_DEPTH:
        return False
    if not _GO_TEST.fullmatch(parts[0]):
        return False
    return all(_GO_SEG.fullmatch(p) and not p.startswith("-") for p in parts[1:])


def validate_go_ids(tests: Sequence[str]) -> tuple[list[str], str | None]:
    if not tests:
        return [], "no_failing_tests_provided"
    clean: list[str] = []
    for raw in tests:
        t = str(raw).strip()
        if not t:
            continue
        if len(t) > MAX_TEST_ID_LEN:
            return [], f"go_id_too_long:{t[:40]}"
        if t.startswith("-") or "::" not in t:
            return [], f"go_id_must_be_pkg::Test:{t[:40]}"
        pkg, _, name = t.rpartition("::")
        if not _GO_PKG.match(pkg) or ".." in pkg.split("/") or pkg.startswith("/"):
            return [], f"go_id_bad_package:{pkg[:40]}"
        if not go_test_path_ok(name):
            return [], f"go_id_bad_test_name:{name[:40]}"
        if t not in clean:
            clean.append(t)
    return (clean, None) if clean else ([], "no_failing_tests_provided")


def split_js_id(t: str) -> tuple[str, list[str]] | None:
    file, sep, rest = t.partition(JS_SEP)
    if not sep or not rest:
        return None
    return file, rest.split(JS_SEP)


def validate_js_ids(tests: Sequence[str]) -> tuple[list[str], str | None]:
    if not tests:
        return [], "no_failing_tests_provided"
    clean: list[str] = []
    for raw in tests:
        t = str(raw).strip("\r\n")
        if not t.strip():
            continue
        if len(t) > MAX_TEST_ID_LEN:
            return [], f"js_id_too_long:{t[:40]}"
        if any(ord(c) < 32 for c in t):
            return [], f"js_id_control_chars:{t[:40]}"
        parts = split_js_id(t)
        if not parts:
            return [], f"js_id_must_be_file > name:{t[:40]}"
        file, names = parts
        if file.startswith(("-", "/")) or ".." in file.split("/") or not _JS_FILE.match(file):
            return [], f"js_id_bad_file:{file[:40]}"
        if not names[-1].strip():
            return [], f"js_id_empty_test_name:{t[:40]}"
        if names[0].startswith("-") and len(names) == 1:
            return [], f"js_id_looks_like_option:{t[:40]}"
        if t not in clean:
            clean.append(t)
    return (clean, None) if clean else ([], "no_failing_tests_provided")


def validate_playwright_ids(tests: Sequence[str]) -> tuple[list[str], str | None]:
    """``file.spec.ts › title``. One spec per id. ``*.e2e.ts`` is not this shape."""
    from sentinel_card.browser_spec import _split_spec
    from sentinel_card.browser_spec import safe_spec_path

    if not tests:
        return [], "no_failing_tests_provided"
    clean: list[str] = []
    for raw in tests:
        text = str(raw).strip("\r\n").strip()
        if not text:
            continue
        if len(text) > MAX_TEST_ID_LEN:
            return [], f"playwright_id_too_long:{text[:40]}"
        if any(ord(c) < 32 for c in text):
            return [], f"playwright_id_control_chars:{text[:40]}"
        file, title = _split_spec(text)
        if not safe_spec_path(file) or not title.strip():
            return [], f"playwright_unsupported_layout:{text[:40]}"
        if text not in clean:
            clean.append(text)
    return (clean, None) if clean else ([], "no_failing_tests_provided")


# FullyQualifiedName: Namespace.Class.Method, optional nested '+' / generic '`',
# optional theory suffix "(...)". Filter metacharacters are refused so the value
# can be passed as one --filter argument without changing the expression.
_DOTNET_ID = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*"
    r"(?:\.[A-Za-z_][A-Za-z0-9_+`]*){2,}"
    r"(?:\((?:[^|&~=!\"'`\\)\r\n]){0,160}\))?$"
)
_DOTNET_FILTER_META = re.compile(r"[|&~=!]")


def validate_dotnet_ids(tests: Sequence[str]) -> tuple[list[str], str | None]:
    """xUnit / NUnit ids are the VSTest FullyQualifiedName, nothing else."""
    if not tests:
        return [], "no_failing_tests_provided"
    clean: list[str] = []
    for raw in tests:
        t = str(raw).strip()
        if not t:
            continue
        if len(t) > MAX_TEST_ID_LEN:
            return [], f"dotnet_id_too_long:{t[:40]}"
        if any(ord(c) < 32 for c in t):
            return [], f"dotnet_id_control_chars:{t[:40]}"
        if t.startswith("-") or ".." in t or "/" in t or "\\" in t or _DOTNET_FILTER_META.search(t):
            return [], f"dotnet_id_unsafe:{t[:40]}"
        if not _DOTNET_ID.fullmatch(t):
            return [], f"dotnet_id_must_be_fully_qualified_name:{t[:40]}"
        if t not in clean:
            clean.append(t)
    return (clean, None) if clean else ([], "no_failing_tests_provided")


def dotnet_filter(ids: Sequence[str]) -> str:
    """Exact FullyQualifiedName filter. Ids are already rejected if they contain ``|``."""
    return "|".join(f"FullyQualifiedName={i}" for i in ids)


def validate_ids(runner: str, tests: Sequence[str]) -> tuple[list[str], str | None]:
    if runner == "go":
        return validate_go_ids(tests)
    if runner == "junit":
        return jvm_support.validate_jvm_ids(tests)
    if runner == "cargo":
        return cargo_support.validate_cargo_ids(tests)
    if runner == "cpp":
        return cpp_support.validate_cpp_ids(tests)
    if runner == "minitest":
        return ruby_support.validate_minitest_ids(tests)
    if runner == "rspec":
        return ruby_support.validate_rspec_ids(tests)
    if runner == "phpunit":
        return phpunit_support.validate_phpunit_ids(tests)
    if runner in JS_FRAMEWORKS:
        return validate_js_ids(tests)
    if runner == "playwright":
        return validate_playwright_ids(tests)
    if runner == "dotnet":
        return validate_dotnet_ids(tests)
    return validate_node_ids(tests)


def runner_for_ids(tests: Sequence[str]) -> str | None:
    """Infer the runner family from id shape alone (None when mixed/unknown)."""
    kinds = set()
    for t in tests:
        go_ok = not validate_go_ids([t])[1]
        cargo_ok = not cargo_support.validate_cargo_ids([t])[1]
        if ".py::" in t and not validate_node_ids([t])[1]:
            kinds.add("pytest")
        elif not ruby_support.validate_minitest_ids([t])[1]:
            kinds.add("minitest")
        elif not ruby_support.validate_rspec_ids([t])[1]:
            kinds.add("rspec")
        elif not phpunit_support.validate_phpunit_ids([t])[1]:
            kinds.add("phpunit")
        elif go_ok and cargo_ok:
            # ``tests::TestAdds`` is a libtest path and a Go id. Shape alone
            # does not pick a runner. Repo files may.
            return None
        elif go_ok:
            kinds.add("go")
        elif cargo_ok and "::" in str(t):
            kinds.add("cargo")
        elif cargo_ok and cpp_support.is_ctest_id(str(t).strip()):
            # A bare name is both a libtest path and a CTest name.
            return None
        elif cargo_ok:
            kinds.add("cargo")
        elif not jvm_support.validate_jvm_ids([t])[1]:
            kinds.add("junit")
        elif not validate_js_ids([t])[1]:
            kinds.add("js")
        elif not validate_playwright_ids([t])[1]:
            kinds.add("playwright")
        elif not validate_dotnet_ids([t])[1]:
            kinds.add("dotnet")
        elif cpp_support.is_gtest_id(str(t).strip()):
            kinds.add("cpp")
        else:
            return None
    if len(kinds) != 1:
        return None
    k = kinds.pop()
    return None if k == "js" else k  # vitest vs jest vs mocha needs repo/log context


# =============================================================================
# Log extraction — Go
# =============================================================================
# "--- FAIL: TestX (0.01s)" possibly indented (subtests); names never contain spaces.
_GO_DASH_FAIL = re.compile(r"^\s*--- FAIL: (\S+) \((?:\d+(?:\.\d+)?s|unknown)\)\s*$")
_GO_DASH_PASS = re.compile(r"^\s*--- PASS: (\S+) \((?:\d+(?:\.\d+)?s|unknown)\)\s*$")
# Package result lines (go test / gotestsum standard-quiet).
_GO_PKG_OK = re.compile(r"^ok\s+(\S+)\s+(?:\(cached\)|[\d.]+s)")
_GO_PKG_FAIL = re.compile(r"^FAIL\s+(\S+)\s+(?:[\d.]+s|\[(?:build|setup) failed\]|\(cached\))")
_GO_PKG_NOTEST = re.compile(r"^\?\s+(\S+)\s+\[no test files\]")
# gotestsum summary: "=== FAIL: pkg/rel TestX/sub (0.01s)"; package-level failures have no test.
_GOTESTSUM_FAIL = re.compile(r"^=== FAIL: (\S+) (\S+) \((?:\d+(?:\.\d+)?s|unknown)\)\s*$")
_GOTESTSUM_DONE = re.compile(r"^DONE \d+ tests?")


def _go_json_events(lines: Iterable[str]) -> list[dict]:
    evs = []
    for ln in lines:
        s = ln.strip()
        if not (s.startswith("{") and '"Action"' in s):
            continue
        try:
            ev = json.loads(s)
        except ValueError:
            continue
        if isinstance(ev, dict):
            evs.append(ev)
    return evs


def go_was_retried(lines: list[str]) -> bool:
    """A name failed and later passed in the same log (text or ``-json``)."""
    failed: set[str] = set()
    for ln in lines:
        fail = _GO_DASH_FAIL.match(ln)
        if fail:
            failed.add(fail.group(1))
            continue
        ok = _GO_DASH_PASS.match(ln)
        if ok and ok.group(1) in failed:
            return True
    seen: set[tuple[str, str]] = set()
    for ev in _go_json_events(lines):
        action, test, pkg = ev.get("Action"), ev.get("Test"), ev.get("Package")
        if action not in ("fail", "pass") or not test or not pkg:
            continue
        key = (str(pkg), str(test))
        if action == "pass" and key in seen:
            return True
        if action == "fail":
            seen.add(key)
    return False


def _gated_ids(runner: str, log_text: str, ids: list[str]) -> list[str]:
    from sentinel_card.summary_gate import apply_gate

    kept, _err = apply_gate(runner, log_text, ids)
    return kept


def _go_ids(log_text: str, ids: list[str]) -> list[str]:
    return _gated_ids("go", log_text, ids)


def extract_go_failing_tests(log_text: str, *, limit: int = 20) -> list[str]:
    """Failing Go tests from ``go test -json`` events only.

    ``Action`` ``fail`` with ``Test`` set. ``Package`` is that event's package.
    A later ``pass`` drops the name. Package-level failures are not ids. Text
    logs, including gotestsum standard-verbose, return no ids.
    """
    if not log_text:
        return []
    from sentinel_card.summary_gate import _go_kind

    lines = _lines_for_test_ids(log_text)
    if _go_kind(lines) != "json":
        return []
    found: list[str] = []

    def add(pkg: str, name: str) -> bool:
        if not go_test_path_ok(name):
            # A subtest with spaces or other shell-unsafe characters falls back
            # to the parent so the failure is not dropped.
            top = name.split("/", 1)[0]
            if not go_test_path_ok(top):
                return False
            name = top
        pkg = pkg.strip()
        if pkg in ("", "."):
            pkg = "."
        tid = f"{pkg}::{name}"
        clean, err = validate_go_ids([tid])
        if err:
            return False
        tid = clean[0]
        drop = []
        for existing in found:
            ep, _, en = existing.rpartition("::")
            if ep != pkg:
                continue
            if name.startswith(en + "/"):
                drop.append(existing)
            elif en == name or en.startswith(name + "/"):
                return len(found) >= limit
        for old in drop:
            found.remove(old)
        if tid not in found:
            found.append(tid)
        return len(found) >= limit

    # 1) go test -json. A later pass for the same test drops the failure.
    evs = _go_json_events(lines)
    if evs:
        last: dict[tuple[str, str], str] = {}
        order: list[tuple[str, str]] = []
        for ev in evs:
            action, test, pkg = ev.get("Action"), ev.get("Test"), ev.get("Package")
            if action in ("fail", "pass") and test and pkg:
                key = (str(pkg), str(test))
                if key not in last:
                    order.append(key)
                last[key] = str(action)
        for pkg, name in order:
            if last[(pkg, name)] == "fail" and add(pkg, name):
                return _go_ids(log_text, found)
        if found or last:
            return _go_ids(log_text, found)
    return []


# =============================================================================
# Log extraction — vitest / jest / mocha
# =============================================================================
_VITEST_FAILED_HDR = re.compile(r"^[⎯\-]{2,}\s*Failed Tests? \d+\s*[⎯\-]{2,}$")
_VITEST_OTHER_HDR = re.compile(r"^[⎯\-]{2,}\s*(?:Failed Suites?|Unhandled Errors?|Failed Tests?)\b.*[⎯\-]{2,}$")
# A vitest ``--project`` badge may be several tokens, including ``name (browser)``.
_VITEST_FAIL = re.compile(
    r"^\s*FAIL\s+(?:(?!\S+\.[cm]?[jt]sx?(?:\s|>|$))\S+\s+)*(\S+\.[cm]?[jt]sx?)\s+>\s+(.+?)\s*$"
)
_VITEST_SUMMARY = re.compile(r"^\s*Test Files\s+\d+\s+(?:failed|passed)")
# optional jest ``displayName`` badge between the status and the file ("FAIL  api  src/a.test.ts")
_JEST_FILE = re.compile(r"^\s*(FAIL|PASS)\s+(?:(?!\S+\.[cm]?[jt]sx?\b)[\w@.:/-]{1,40}\s+)?(\S+\.[cm]?[jt]sx?)(?:\s+\([\d.]+ m?s\))?\s*$")
_JEST_BULLET = re.compile(r"^\s{0,4}● (.*)$")
_JEST_SUMMARY = re.compile(r"^\s*(?:Test Suites:|Tests:|Summary of all failing tests)")
_JEST_NOT_TESTS = {"Console", "Test suite failed to run"}
_PLAYWRIGHT = re.compile(r"(?:^|\s)(?:✘|\[chromium\]|\[firefox\]|\[webkit\])|Running \d+ tests? using \d+ workers?|npx playwright")


def _norm_file(f: str) -> str:
    return f[2:] if f.startswith("./") else f


def extract_vitest_failing_tests(log_text: str, *, limit: int = 20) -> list[str]:
    """vitest ids ``file > suite > test`` from the ``Failed Tests N`` section.

    Tree lines (``×``/``✓``) and ``Failed Suites`` (file/hook failures) never
    count. Retries repeat the same FAIL line; ids are de-duplicated. When the
    log has no Failed Tests / Failed Suites header, a ``FAIL file > name`` line
    from the basic reporter still counts.
    """
    if not log_text:
        return []
    found: list[str] = []
    loose: list[str] = []
    in_section = False
    saw_header = False

    def take(bucket: list[str], line: str) -> bool:
        m = _VITEST_FAIL.match(line)
        if not m:
            return False
        tid = f"{_norm_file(m.group(1))}{JS_SEP}{m.group(2)}"
        clean, err = validate_js_ids([tid])
        if err or clean[0] in bucket:
            return len(bucket) >= limit
        bucket.append(clean[0])
        return len(bucket) >= limit

    for ln in _lines_for_test_ids(log_text):
        s = ln.strip()
        if _VITEST_OTHER_HDR.match(s):
            saw_header = True
            in_section = bool(_VITEST_FAILED_HDR.match(s))
            continue
        if s.startswith(("stdout |", "stderr |")):
            in_section = False
            continue
        if _VITEST_SUMMARY.match(s):
            in_section = False
            continue
        if in_section:
            if take(found, ln):
                break
            continue
        # Basic reporter prints ``FAIL file > name`` with no Failed Tests header.
        # Tree lines (×/✓) and lines under a Failed Suites header stay out.
        if not saw_header and take(loose, ln):
            break
    if found or saw_header:
        return _gated_ids("vitest", log_text, found)
    return _gated_ids("vitest", log_text, loose[:limit])


def extract_jest_failing_tests(log_text: str, *, limit: int = 20) -> list[str]:
    """jest ids from ``● a › b`` headers inside a ``FAIL <file>`` block.

    ``● Test suite failed to run`` and ``● Console`` are not tests. Bullets
    outside a FAIL block (after PASS, after the summary) are ignored.
    """
    if not log_text:
        return []
    from sentinel_card.summary_gate import _mask

    lines, err = _mask("jest", _lines_for_test_ids(log_text))
    if err:
        return []
    found: list[str] = []
    current: str | None = None
    for ln in lines:
        m = _JEST_FILE.match(ln)
        # An indented FAIL inside ``● Console`` is printed output, not the suite.
        if m and not ln[:1].isspace():
            current = _norm_file(m.group(2)) if m.group(1) == "FAIL" else None
            continue
        if _JEST_SUMMARY.match(ln):
            current = None
            continue
        if current is None:
            continue
        b = _JEST_BULLET.match(ln)
        if not b:
            continue
        title = b.group(1).rstrip()
        if title.strip() in _JEST_NOT_TESTS or not title.strip():
            continue
        names = title.split(" › ")
        tid = current + JS_SEP + JS_SEP.join(names)
        clean, err = validate_js_ids([tid])
        if not err and clean[0] not in found:
            found.append(clean[0])
            if len(found) >= limit:
                break
    return _gated_ids("jest", log_text, found)


# Mocha's spec epilogue (mocha 6 one-line fullTitle, mocha 7+ indented titlePath).
# The progress tree also numbers failures, but those lines are indented further
# and they sit above the ``N failing`` summary. Only the epilogue is parsed.
_MOCHA_FAILING = re.compile(r"^\s*\d+\s+failing\s*$")
_MOCHA_ENTRY = re.compile(r"^  (\d+)\)\s+(\S.*)$")
_MOCHA_CONT = re.compile(r"^ {5,}(\S.*?)\s*$")
_MOCHA_HOOK = re.compile(
    r"""["'](?:before|after)(?: each| all)?["']\s+hook|\bhook for\b|\bhook in\b""",
    re.I,
)
_MOCHA_STACK = re.compile(
    r"\((?:file://)?([^()\s]+?\.(?:[cm]?[jt]sx?)):(\d+):(\d+)\)"
)
_MOCHA_CI_ROOT = re.compile(
    r"^(?:/home/runner/work/[^/]+/[^/]+/|/__w/[^/]+/[^/]+/|/home/circleci/(?:project|repo)/)"
)
_MOCHA_TEST_DIR = frozenset({"test", "tests", "src", "packages", "lib", "spec"})
_KARMA_MARK = re.compile(
    r"(?m)(?:\bKarma v\d|\bExecuted \d+ of \d+|\[launcher\]|^TOTAL:\s+\d+\s+(?:SUCCESS|FAILED))"
)


def looks_like_karma(log_text: str) -> bool:
    """Karma drives a browser. Its log is not a Mocha CLI run, even when the
    framework inside the browser is Mocha."""
    return bool(log_text) and bool(_KARMA_MARK.search(log_text))


def _mocha_rel_file(raw: str) -> str | None:
    path = str(raw or "").strip().replace("\\", "/")
    if path.startswith("file://"):
        path = path[7:]
    if path.startswith("./"):
        path = path[2:]
    path = path.split("?", 1)[0]
    if "node_modules" in path.split("/") or path.startswith("node:"):
        return None
    path = _MOCHA_CI_ROOT.sub("", path)
    if path.startswith("/"):
        parts = [p for p in path.split("/") if p]
        for i, part in enumerate(parts):
            if part in _MOCHA_TEST_DIR and i > 0:
                path = "/".join(parts[i:])
                break
        else:
            return None
    if path.startswith("/") or ".." in path.split("/") or not _JS_FILE.match(path):
        return None
    return path


def _mocha_file_from_block(lines: list[str]) -> str | None:
    at_file = re.compile(r"\bat ((?:[\w./-]+)\.(?:[cm]?[jt]sx?)):(\d+):(\d+)\b")
    for ln in lines:
        for m in _MOCHA_STACK.finditer(ln):
            rel = _mocha_rel_file(m.group(1))
            if rel:
                return rel
        at = at_file.search(ln)
        if at:
            rel = _mocha_rel_file(at.group(1))
            if rel:
                return rel
    return None


def _mocha_title_parts(first: str, following: list[str]) -> list[str] | None:
    """Suite/test parts from one epilogue entry. Hook failures are not tests."""
    first = first.strip()
    if first.endswith(":") and not following:
        parts = [first[:-1].strip()]
    else:
        parts = []
        if first.endswith(":"):
            parts = [first[:-1].strip()]
        else:
            parts = [first]
            closed = False
            for ln in following:
                m = _MOCHA_CONT.match(ln)
                if not m:
                    break
                piece = m.group(1).strip()
                if piece.endswith(":"):
                    piece = piece[:-1].strip()
                    if piece:
                        parts.append(piece)
                    closed = True
                    break
                if piece:
                    parts.append(piece)
                if len(parts) > 8:
                    return None
            if not closed and not (len(parts) == 1 and first.endswith(":")):
                return None
    parts = [p for p in parts if p]
    if not parts or not parts[-1]:
        return None
    return parts


def _mocha_ids_from_spec(log_text: str, *, limit: int) -> list[str]:
    lines = _lines_for_test_ids(log_text)
    start = None
    for i, ln in enumerate(lines):
        if _MOCHA_FAILING.match(ln.strip()):
            start = i + 1
    if start is None:
        return []
    found: list[str] = []
    i = start
    while i < len(lines):
        m = _MOCHA_ENTRY.match(lines[i])
        if not m:
            i += 1
            continue
        j = i + 1
        while j < len(lines) and not _MOCHA_ENTRY.match(lines[j]):
            j += 1
        block = lines[i:j]
        parts = _mocha_title_parts(m.group(2), block[1:])
        rel = _mocha_file_from_block(block)
        i = j
        if not parts or not rel:
            continue
        tid = rel + JS_SEP + JS_SEP.join(parts)
        clean, err = validate_js_ids([tid])
        if err or clean[0] in found:
            continue
        found.append(clean[0])
        if len(found) >= limit:
            break
    return found


def _mocha_report_from_text(text: str) -> dict | None:
    if not text or '"failures"' not in text or '"stats"' not in text:
        return None
    decoder = json.JSONDecoder()
    start = text.find("{")
    while start >= 0:
        try:
            data, _end = decoder.raw_decode(text[start:])
        except ValueError:
            start = text.find("{", start + 1)
            continue
        if isinstance(data, dict) and isinstance(data.get("stats"), dict) and "failures" in data:
            return data
        start = text.find("{", start + 1)
    return None


def _mocha_ids_from_json(log_text: str, *, limit: int) -> list[str]:
    data = _mocha_report_from_text(log_text)
    if not data:
        return []
    found: list[str] = []
    for item in data.get("failures") or []:
        if not isinstance(item, dict):
            continue
        full = str(item.get("fullTitle") or item.get("title") or "").strip()
        if not full or _MOCHA_HOOK.search(full):
            continue
        rel = _mocha_rel_file(str(item.get("file") or ""))
        if not rel:
            continue
        tid = rel + JS_SEP + full
        clean, err = validate_js_ids([tid])
        if err or clean[0] in found:
            continue
        found.append(clean[0])
        if len(found) >= limit:
            break
    return found


def extract_mocha_failing_tests(log_text: str, *, limit: int = 20) -> list[str]:
    """Mocha ids ``file > suite > test`` from the spec epilogue, else JSON.

    Passing lines and hook failures (``"before all" hook``) are not tests.
    A Karma log is not Mocha: this returns nothing so a browser run is not
    given a Mocha id. ``extract_failing_tests_any`` reports ``karma_unsupported``.
    """
    if not log_text or looks_like_karma(log_text):
        return []
    found = _mocha_ids_from_spec(log_text, limit=limit)
    if not found:
        found = _mocha_ids_from_json(log_text, limit=limit)
    return _gated_ids("mocha", log_text, found)


_NODE_NOT_OK = re.compile(r"^(\s*)not ok(?:\s+\d+)?(?:\s+-\s+|\s+)(\S.*?)\s*$")
_NODE_SUBTEST = re.compile(r"^(\s*)# Subtest:\s+(\S.*?)\s*$")
_NODE_LOCATION = re.compile(r"""location:\s+['\"]?(?:file://)?([^'\"\s]+)""")
_NODE_FAILTYPE = re.compile(r"""failureType:\s+['\"]?([A-Za-z]+)""")
_NODE_GATE = re.compile(r"node:test|TAP version|failureType:")
_NODE_SKIP_TYPE = frozenset({"subtestsFailed", "cancelledByParent", "hookFailed"})


_NODE_TEST_FILE = re.compile(r"(?:\.test\.|\.spec\.|_test\.)(?:c|m)?[jt]sx?$")


@dataclass
class NodeExtract:
    ids: list[str]
    error: str | None = None


def _node_file_is_test(rel: str) -> bool:
    """True when *rel* is a node:test file, not a helper module."""
    return bool(_NODE_TEST_FILE.search(rel.rsplit("/", 1)[-1]))


def extract_node_test_result(log_text: str, *, limit: int = 20) -> NodeExtract:
    """Node's test runner TAP, or a named abstain.

    Ids are ``file > suite > test``. The location file has to be that test's
    own file (``*.test.js`` / ``*.spec.js`` / ``*_test.js``). A helper location
    is ``test_ids_ambiguous_location``. A truncated title is
    ``test_ids_truncated``. A missing location, two locations, or a title that
    is not the ``# Subtest`` name is ``test_ids_ambiguous_location``. There is
    no runner that re-executes node:test, so a parsed id is not handed to
    vitest, jest, or mocha.
    """
    if not log_text or "not ok" not in log_text or not _NODE_GATE.search(log_text):
        return NodeExtract([])
    lines = _lines_for_test_ids(log_text)
    found: list[str] = []
    reason: str | None = None
    stack: list[tuple[int, str]] = []
    index = 0
    while index < len(lines):
        sub = _NODE_SUBTEST.match(lines[index])
        if sub:
            indent = len(sub.group(1).replace("\t", "    "))
            stack = [(n, title) for n, title in stack if n < indent]
            stack.append((indent, sub.group(2).strip()))
            index += 1
            continue
        failed = _NODE_NOT_OK.match(lines[index])
        if not failed:
            index += 1
            continue
        indent = len(failed.group(1).replace("\t", "    "))
        title = failed.group(2).strip()
        block: list[str] = []
        index += 1
        while index < len(lines):
            if lines[index].strip() == "..." or _NODE_NOT_OK.match(lines[index]) or _NODE_SUBTEST.match(lines[index]):
                break
            block.append(lines[index])
            index += 1
        if index < len(lines) and lines[index].strip() == "...":
            index += 1
        fail_type = ""
        locs: list[str] = []
        for line in block:
            kind = _NODE_FAILTYPE.search(line)
            if kind:
                fail_type = kind.group(1)
            loc = _NODE_LOCATION.search(line)
            if loc:
                locs.append(loc.group(1))
        if fail_type in _NODE_SKIP_TYPE:
            continue
        if "…" in title or title.endswith("...") or any("…" in loc or loc.endswith("...") for loc in locs):
            reason = "test_ids_truncated"
            continue
        if len(locs) != 1:
            reason = reason or "test_ids_ambiguous_location"
            continue
        path = re.sub(r":\d+:\d+$", "", locs[0])
        rel = _mocha_rel_file(path)
        if not rel or not _node_file_is_test(rel):
            reason = reason or "test_ids_ambiguous_location"
            continue
        kept = [(n, name) for n, name in stack if n <= indent]
        if kept and kept[-1][0] == indent:
            if kept[-1][1] != title:
                reason = reason or "test_ids_ambiguous_location"
                continue
            parts = [name for _, name in kept]
        elif not kept:
            parts = [title]
        else:
            reason = reason or "test_ids_ambiguous_location"
            continue
        if any("…" in part or part.endswith("...") for part in parts):
            reason = "test_ids_truncated"
            continue
        clean, err = validate_js_ids([rel + JS_SEP + JS_SEP.join(parts)])
        if err or not clean:
            reason = reason or "test_ids_ambiguous_location"
            continue
        if clean[0] not in found:
            found.append(clean[0])
    if reason:
        return NodeExtract([], reason)
    return NodeExtract(found[:limit])


def extract_node_test_failing_tests(log_text: str, *, limit: int = 20) -> list[str]:
    """Node TAP ids. ``extract_node_test_result`` carries the named abstain."""
    return extract_node_test_result(log_text, limit=limit).ids


def looks_like_playwright(log_text: str) -> bool:
    return bool(log_text) and bool(_PLAYWRIGHT.search(log_text))


def _playwright_extraction(text: str, *, limit: int) -> Extraction:
    """Playwright spec ids, or an abstain when the log is not that layout.

    ``*.e2e.ts``, a passing-only log, and a job that only names Playwright
    without a ``file.spec.ts › title`` failure are ``playwright_unsupported_layout``.
    A log that is not Playwright stays ``no_failing_tests_found``.
    """
    from sentinel_card.browser_spec import playwright_specs

    specs = playwright_specs(text)[:limit]
    if specs:
        return Extraction("playwright", specs)
    if looks_like_playwright(text):
        return Extraction(None, [], "playwright_unsupported_layout")
    return Extraction(None, [], "no_failing_tests_found")


# =============================================================================
# Detection
# =============================================================================
def detect_runner_from_repo(repo: str | Path | None) -> list[str]:
    """Runner families suggested by repo files at the checkout (read-only)."""
    out: list[str] = []
    if not repo:
        return out
    root = Path(repo)
    try:
        if (root / "go.mod").is_file() or (root / "go.work").is_file():
            out.append("go")
        pj = root / "package.json"
        if pj.is_file():
            txt = pj.read_text(encoding="utf-8", errors="replace")[:500_000]
            if re.search(r'"vitest"\s*:', txt) or any(root.glob("vitest.*config.*")):
                out.append("vitest")
            if re.search(r'"jest"\s*:', txt) or any(root.glob("jest.config.*")):
                out.append("jest")
            if re.search(r'"mocha"\s*:', txt) or any(root.glob(".mocharc.*")) or (root / "mocha.opts").is_file():
                out.append("mocha")
        if jvm_support.repo_suggests_junit(root):
            out.append("junit")
        if cargo_support.repo_suggests_cargo(root):
            out.append("cargo")
        if cpp_support.repo_suggests_cpp(root):
            out.append("cpp")
        if ruby_support.repo_suggests_ruby(root, "minitest"):
            out.append("minitest")
        if ruby_support.repo_suggests_ruby(root, "rspec"):
            out.append("rspec")
        if phpunit_support.repo_suggests_phpunit(root):
            out.append("phpunit")
        if any((root / n).is_file() for n in ("pytest.ini", "conftest.py", "setup.cfg", "tox.ini")) or (
            (root / "pyproject.toml").is_file()
        ):
            out.append("pytest")
        chosen, why = select_dotnet_project(discover_dotnet_projects(root))
        if chosen is not None and not why:
            out.append("dotnet")
    except OSError:
        pass
    return out


@dataclass
class Extraction:
    runner: str | None
    ids: list[str] = field(default_factory=list)
    error: str | None = None


# 5.2.0 (NS5): runner-family evidence lines. Detection is by majority evidence,
# never by a single line (a Go job that runs one helper printing "FAILED x.py::t"
# is still a Go job).
_EVIDENCE = {
    "pytest": re.compile(
        r"^(?:FAILED \S+\.py::|PASSED |ERROR \S+\.py::|\S+\.py::\S+ (?:PASSED|FAILED)\b|=+ (?:test session starts|short test summary info|FAILURES|ERRORS) =+"
        r"|collected \d+ items?|=+ .*\b\d+ (?:failed|passed)\b.* in [\d.]+s)"
    ),
    "go": re.compile(
        r"^(?:\s*--- (?:FAIL|PASS|SKIP): \S+ \(|=== (?:RUN|PAUSE|CONT|FAIL:|SKIP:)\s|ok\s+\S+\s+(?:\(cached\)|[\d.]+s)"
        r"|FAIL\s+\S+\s+(?:[\d.]+s|\[)|\?\s+\S+\s+\[no test files\]|panic: |DONE \d+ tests|\{\"Time\":.*\"Action\":)"
    ),
    "vitest": re.compile(
        r"^\s*(?:[✓×✗❯↓] \S+\.[cm]?[jt]sx?\b|Test Files\s+\d+|[⎯]{2,}.*Failed (?:Tests?|Suites?)|FAIL\s+(?:\S+\s+)?\S+\.[cm]?[jt]sx? > |RUN\s+v\d+\.|stderr \| \S+\.[cm]?[jt]sx?)"
    ),
    "jest": re.compile(
        r"^\s*(?:(?:PASS|FAIL)\s+\S+\.[cm]?[jt]sx?(?:\s+\([\d.]+ m?s\))?\s*$|● |Test Suites:\s+\d+|Tests:\s+\d+|Ran all test suites)"
    ),
    "mocha": re.compile(
        r"^(?:  \d+\)\s+\S|\s*\d+ passing \(|\s*\d+ failing$|\s*\d+ pending\b|[ \t]+✔ )"
    ),
    "junit": re.compile(
        r"^(?:\[(?:ERROR|WARNING)\]\s+\S+\s+--\s+Time elapsed:.*<<< (?:FAILURE|ERROR)!|\[INFO\]\s+T E S T S\s*$)"
    ),
    "dotnet": re.compile(
        r"^(?:\[xUnit\.net\b|NUnit Adapter\b|"
        r"\s*(?:\d+\)\s+)?Failed\s+[A-Za-z_][\w.+`]*\.[A-Za-z_][\w.+`]*\.[A-Za-z_]\S*\s+\[|"
        r"(?:Passed|Failed)!  - Failed:\s+\d+, Passed:)"
    ),
    "cargo": re.compile(
        r"^(?:running \d+ tests?\s*$|test \S+ \.\.\. (?:ok|FAILED|ignored)\b|test result: (?:ok|FAILED)\.)"
    ),
    "cpp": re.compile(
        r"^(?:\[\s+(?:OK|FAILED|SKIPPED|RUN)\s+\]\s+\S|"
        r"\d+/\d+\s+Test\s+#\d+:|The following tests FAILED:)"
    ),
    "minitest": re.compile(
        r"^(?:Run options: |# Running:|\d+ runs, \d+ assertions,|"
        r"[A-Za-z_][\w:]*#test_[A-Za-z0-9_]+ \[)"
    ),
    "rspec": re.compile(
        r"^(?:Failures:|Failed examples:|rspec \./\S+_spec\.rb:\d+ # )"
    ),
    "phpunit": re.compile(
        r"^(?:PHPUnit \d|There was \d+ (?:failure|error)|FAILURES!$|"
        r"\d+\)\s+[A-Za-z_\\].*::test)"
    ),
}


def runner_evidence(text: str) -> dict[str, int]:
    """Count evidence lines per runner family (cheap; capped at 200k lines)."""
    counts = {k: 0 for k in _EVIDENCE}
    for i, ln in enumerate(_clean_lines(text or "")):
        if i > 200_000:
            break
        for k, rx in _EVIDENCE.items():
            if rx.match(ln):
                counts[k] += 1
    return counts


def _junit_extraction(text: str, *, limit: int) -> Extraction:
    """Maven Surefire ids, or an abstain when the log is Gradle or not ``Class#method``."""
    got = jvm_support.extract_jvm(text, limit=limit)
    if got.error and not got.ids:
        return Extraction(None, [], got.error)
    return Extraction("junit", got.ids)


def _cargo_extraction(text: str, *, limit: int) -> Extraction:
    """Libtest ids, or an abstain when the log is nextest or not a path id."""
    got = cargo_support.extract_cargo(text, limit=limit)
    if got.error and not got.ids:
        return Extraction(None, [], got.error)
    return Extraction("cargo", got.ids)


def _ruby_extraction(text: str, *, framework: str, limit: int) -> Extraction:
    """Minitest or RSpec ids, or an abstain when the failure is not that shape."""
    if framework == "rspec":
        got = ruby_support.extract_rspec(text, limit=limit)
        error = got.error or "rspec_unsupported_id"
        runner = "rspec"
    else:
        got = ruby_support.extract_minitest(text, limit=limit)
        error = got.error or "minitest_unsupported_id"
        runner = "minitest"
    if got.error and not got.ids:
        return Extraction(None, [], error)
    return Extraction(runner, got.ids)


def _phpunit_extraction(text: str, *, limit: int) -> Extraction:
    """PHPUnit ids, or an abstain when the name is a data provider or not a method."""
    got = phpunit_support.extract_phpunit(text, limit=limit)
    if got.error and not got.ids:
        return Extraction(None, [], got.error)
    return Extraction("phpunit", got.ids)


def _cpp_extraction(text: str, *, limit: int) -> Extraction:
    """CTest or GoogleTest ids, or an abstain when the log is Catch2 or not a path id."""
    got = cpp_support.extract_cpp(text, limit=limit)
    if got.error and not got.ids:
        return Extraction(None, [], got.error)
    return Extraction("cpp", got.ids)


def _node_tap_abstain(text: str, *, limit: int) -> Extraction | None:
    """A node:test TAP log abstains. Vitest, jest, and mocha cannot re-run it."""
    got = extract_node_test_result(text, limit=limit)
    if got.error and not got.ids:
        return Extraction(None, [], got.error)
    if got.ids:
        return Extraction(None, [], "node_test_unsupported")
    return None


def _js_or_node(runner: str, text: str, *, limit: int) -> Extraction:
    """Framework ids. node:test TAP is not that framework's run."""
    from sentinel_card.summary_gate import apply_gate

    fn = {
        "vitest": extract_vitest_failing_tests,
        "jest": extract_jest_failing_tests,
        "mocha": extract_mocha_failing_tests,
    }[runner]
    ids = fn(text, limit=limit)
    gids, gerr = apply_gate(runner, text, ids)
    if gids:
        return Extraction(runner, gids)
    if gerr:
        return Extraction(None, [], gerr)
    node = _node_tap_abstain(text, limit=limit)
    if node:
        return node
    return Extraction(runner, [])


def extract_failing_tests_any(
    log_text: str, *, runner: str = "auto", repo: str | Path | None = None, limit: int = 20
) -> Extraction:
    """Extract failing ids, or a named abstain.

    Explicit ``runner`` uses that family. Auto mode abstains
    ``test_ids_runner_ambiguous`` when more than one family has a summary
    or ids. A pass summary counts.
    """
    runner = (runner or "auto").strip().lower()
    text = strip_task_prefixes(log_text or "")
    if test_id_esc_error(text):
        return Extraction(None, [], "test_ids_unparsed_entry")
    if runner == "karma" or (runner in ("auto", "mocha") and looks_like_karma(text)):
        return Extraction(None, [], "karma_unsupported")
    if runner not in ("auto",) + RUNNERS:
        return Extraction(None, [], f"unknown_runner:{runner[:20]}")
    if runner == "pytest":
        got = extract_pytest_log(text, limit=limit)
        if got.ids:
            return Extraction("pytest", got.ids)
        if got.error:
            return Extraction(None, [], got.error)
        return Extraction("pytest", [])
    if runner == "go":
        from sentinel_card.summary_gate import apply_gate

        ids = extract_go_failing_tests(text, limit=limit)
        gids, gerr = apply_gate("go", text, ids)
        if gerr and not gids:
            return Extraction(None, [], gerr)
        return Extraction("go" if gids else None, gids)
    if runner == "vitest":
        return _js_or_node("vitest", text, limit=limit)
    if runner == "jest":
        return _js_or_node("jest", text, limit=limit)
    if runner == "mocha":
        return _js_or_node("mocha", text, limit=limit)
    if runner == "playwright":
        return _playwright_extraction(text, limit=limit)
    if runner == "junit":
        return _junit_extraction(text, limit=limit)
    if runner == "dotnet":
        return _dotnet_extraction(text, limit=limit)
    if runner == "cargo":
        return _cargo_extraction(text, limit=limit)
    if runner == "cpp":
        return _cpp_extraction(text, limit=limit)
    if runner == "minitest":
        return _ruby_extraction(text, framework="minitest", limit=limit)
    if runner == "rspec":
        return _ruby_extraction(text, framework="rspec", limit=limit)
    if runner == "phpunit":
        return _phpunit_extraction(text, limit=limit)
    from sentinel_card.summary_gate import apply_gate
    from sentinel_card.summary_gate import counts_as_yield

    yielded: list[str] = []
    gated: dict[str, list[str]] = {}
    errors: list[tuple[str, str]] = []

    def note(name: str, ids: list[str], error: str | None) -> None:
        if ids:
            gated[name] = list(ids)
            yielded.append(name)
            return
        if counts_as_yield([], error):
            yielded.append(name)
        if error and error != "no_failing_tests_found":
            errors.append((name, error))

    py = extract_pytest_log(text, limit=limit)
    note("pytest", py.ids, py.error)
    for name, fn in (
        ("go", extract_go_failing_tests),
        ("vitest", extract_vitest_failing_tests),
        ("jest", extract_jest_failing_tests),
        ("mocha", extract_mocha_failing_tests),
    ):
        got = fn(text, limit=limit)
        gids, gerr = apply_gate(name, text, got)
        note(name, gids, gerr)
    junit = jvm_support.extract_jvm(text, limit=limit)
    note("junit", junit.ids, junit.error)
    dotnet_ex = _dotnet_extraction(text, limit=limit)
    note("dotnet", dotnet_ex.ids, dotnet_ex.error)
    cargo = cargo_support.extract_cargo(text, limit=limit)
    note("cargo", cargo.ids, cargo.error)
    cpp = cpp_support.extract_cpp(text, limit=limit)
    note("cpp", cpp.ids, cpp.error)
    for name, framework in (("minitest", "minitest"), ("rspec", "rspec"), ("phpunit", "phpunit")):
        extra = _ruby_extraction(text, framework=framework, limit=limit) if name != "phpunit" else _phpunit_extraction(text, limit=limit)
        note(name, extra.ids, extra.error)
    node_ids = extract_node_test_result(text, limit=limit)
    if node_ids.ids:
        yielded.append("node")
    if len(yielded) > 1:
        return Extraction(None, [], "test_ids_runner_ambiguous")
    if len(yielded) == 1:
        name = yielded[0]
        if name == "node":
            return Extraction(None, [], node_ids.error or "node_test_unsupported")
        if name in gated:
            return Extraction(name, gated[name])
        for runner_name, err in errors:
            if runner_name == name:
                return Extraction(None, [], err)
    soft = {
        "summary_reports_pass",
        "test_ids_no_summary",
        "test_ids_count_mismatch",
        "test_ids_result_disagreed",
        "flaky_retry",
    }
    specific = [err for _name, err in errors if err not in soft]
    if specific:
        return Extraction(None, [], specific[0])
    if node_ids.error and not node_ids.ids:
        return Extraction(None, [], node_ids.error)
    if errors:
        rank = (
            "flaky_retry",
            "test_ids_result_disagreed",
            "test_ids_count_mismatch",
            "test_ids_no_summary",
            "summary_reports_pass",
        )
        errors.sort(key=lambda item: rank.index(item[1]) if item[1] in rank else 99)
        return Extraction(None, [], errors[0][1])
    return _playwright_extraction(text, limit=limit)


def resolve_runner(
    explicit: str | None, card_runner: str | None, tests: Sequence[str], repo: str | Path | None
) -> str:
    """Runner for bisect: explicit input > card (log) > id shape > repo files > pytest."""
    e = (explicit or "auto").strip().lower()
    if e in RUNNERS:
        return e
    if card_runner in RUNNERS:
        return str(card_runner)
    shape = runner_for_ids(tests) if tests else None
    hints = detect_runner_from_repo(repo)
    if shape in ("pytest", "go", "playwright", "junit", "dotnet", "cargo", "cpp", "minitest", "rspec", "phpunit"):
        return shape
    if tests and all(cpp_support.is_gtest_id(str(t).strip()) for t in tests):
        return "cpp"
    bare = [str(t).strip() for t in tests]
    if bare and all(cpp_support.is_ctest_id(item) and "::" not in item for item in bare):
        others = [h for h in hints if h in ("pytest", "go", "junit", "dotnet", *JS_FRAMEWORKS)]
        if "cpp" in hints and "cargo" not in hints and not others:
            return "cpp"
        if "cargo" in hints and "cpp" not in hints and "go" not in hints:
            return "cargo"
    if tests and all(not cargo_support.validate_cargo_ids([t])[1] for t in tests):
        if "cargo" in hints and "go" not in hints and "cpp" not in hints:
            return "cargo"
    if tests and all(not validate_js_ids([t])[1] for t in tests):
        js = [h for h in hints if h in JS_FRAMEWORKS]
        if len(js) == 1:
            return js[0]
        if "vitest" in js:
            return "vitest"
        if "jest" in js:
            return "jest"
        return "mocha" if "mocha" in js else "vitest"
    return "pytest"


# =============================================================================
# Shared runner plumbing
# =============================================================================
def default_cache_dir() -> Path:
    base = os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()
    return Path(base) / "sentinel-bisect-cache"


_GO_ENV_PASS = ("GOFLAGS", "GOPROXY", "GONOSUMDB", "GONOSUMCHECK", "GOPRIVATE", "GONOPROXY",
                "GOSUMDB", "CGO_ENABLED", "GOEXPERIMENT", "GOARCH", "GOOS", "GOAMD64")
_NODE_ENV_PASS = ("NODE_OPTIONS", "NODE_ENV", "TZ")


def _passthrough(env: dict[str, str], keys: Iterable[str]) -> None:
    for k in keys:
        v = os.environ.get(k)
        if v is None:
            continue
        if "@" in v and "://" in v:  # URL with embedded credentials
            continue
        env[k] = v


class _WorktreeRunner(PytestGitRunner):
    """Reuses the pytest runner's worktree handling; subclasses implement ``_run_once``."""

    kind_name = "base"

    def _prepare(self, sha: str, deadline: float | None) -> tuple[Path | None, EvalResult | None]:
        if remaining_budget(deadline) < 0.05:
            return None, EvalResult(label="error", detail="budget_exhausted", kind="timeout")
        wt = self._ensure_worktree(sha)
        if wt is None:
            return None, EvalResult(label="error", detail=f"checkout_failed:{sha[:12]}", kind="checkout")
        try:
            if wt.resolve() == self.repo.resolve():
                return None, EvalResult(label="error", detail="refuse_clean_primary_checkout", kind="checkout")
            git_clean_worktree(wt, timeout=min(60.0, max(0.5, remaining_budget(deadline))))
            subprocess.run(
                ["git", "-C", str(wt), "reset", "--hard", "HEAD"],
                capture_output=True, timeout=min(60.0, max(0.5, remaining_budget(deadline))),
                env=build_scrubbed_env(),
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
        self._apply_file_overlay(wt)
        fidelity = checkout_fidelity(
            wt, timeout=min(CHECKOUT_FIDELITY_SEC, max(1.0, remaining_budget(deadline))),
        )
        if fidelity:
            return None, EvalResult(label="error", detail=fidelity, kind="checkout_incomplete")
        return wt, None

    @staticmethod
    def _aggregate(labels: list[EvalResult]) -> EvalResult:
        """Combine per-run results with the same rules as the pytest runner."""
        passes = sum(1 for r in labels if r.label == "green")
        fails = sum(1 for r in labels if r.label == "red")
        errs = [r for r in labels if r.label not in ("green", "red")]
        runs = len(labels)
        if runs == 0:
            return EvalResult(label="error", detail="no_runs", kind="unknown")
        if errs:
            last = errs[-1]
            return EvalResult(label="error", passes=passes, fails=fails, runs=runs,
                              detail=last.detail, kind=last.kind or "unknown")
        if passes == runs:
            return EvalResult(label="green", passes=passes, runs=runs, detail=labels[-1].detail, kind="pass")
        if fails == runs:
            shape = "assertion" if any(getattr(r, "failure", "") == "assertion" for r in labels) else ""
            return EvalResult(label="red", fails=fails, runs=runs, detail=labels[-1].detail, kind="fail", failure=shape)
        return EvalResult(label="flaky", passes=passes, fails=fails, runs=runs,
                          detail=labels[-1].detail, kind="mixed")


# =============================================================================
# Go runner
# =============================================================================
def go_run_regexes(names: Sequence[str]) -> list[str]:
    """``go test -run`` values.

    Top-level names share one anchored regexp. A subtest is its own regexp,
    ``^TestX$/^Sub$/^Name$``, so Go does not also run sibling subtests.
    Go splits ``-run`` on unbracketed ``/``; the parent function still runs.
    """
    tops = [n for n in names if "/" not in n]
    subs = [n for n in names if "/" in n]
    out: list[str] = []
    if len(tops) == 1:
        out.append(f"^{tops[0]}$")
    elif tops:
        out.append("^(?:" + "|".join(tops) + ")$")
    for name in subs:
        out.append("/".join(f"^{part}$" for part in name.split("/")))
    return out


def _go_json_regex(names: Sequence[str]) -> str:
    # names are validated identifiers ([A-Za-z0-9_]) — no regex metacharacters
    regs = go_run_regexes(names)
    return regs[0] if len(regs) == 1 else "^(" + "|".join(names) + ")$"


def _read_go_modules(wt: Path, limit: int = 300) -> list[tuple[str, str]]:
    """(module_path, rel_dir) for go.mod files tracked at this commit."""
    mods: list[tuple[str, str]] = []
    try:
        r = subprocess.run(["git", "-C", str(wt), "ls-files", "--", "go.mod", "*/go.mod"],
                           capture_output=True, text=True, timeout=30, env=build_scrubbed_env())
        paths = [p for p in r.stdout.splitlines() if p.endswith("go.mod")][:limit]
    except (OSError, subprocess.TimeoutExpired):
        paths = []
    for p in paths:
        try:
            txt = (wt / p).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = re.search(r"^\s*module\s+(\S+)", txt, re.M)
        if m:
            d = str(Path(p).parent)
            mods.append((m.group(1).strip('"'), "." if d in ("", ".") else d))
    return mods


def resolve_go_package(wt: Path, pkg: str) -> tuple[str, str] | None:
    """Map an id package to (module_dir, ./rel_pkg) inside the worktree."""
    if pkg == "." or pkg.startswith("./"):
        return ".", pkg
    best: tuple[int, str, str] | None = None
    for mod, d in _read_go_modules(wt):
        if pkg == mod or pkg.startswith(mod + "/"):
            rest = pkg[len(mod):].lstrip("/")
            cand = (len(mod), d, "./" + rest if rest else ".")
            if best is None or cand[0] > best[0]:
                best = cand
    if best is None:
        return None
    return best[1], best[2]


_TOOLCHAIN_DIRECTIVE = re.compile(r"(?m)^[ \t]*toolchain[ \t]+(go\d+\.\d+\.\d+)[ \t]*$")
_GO_DIRECTIVE = re.compile(r"(?m)^[ \t]*go[ \t]+(\d+\.\d+(?:\.\d+)?)[ \t]*$")
_GO_VERSION_LINE = re.compile(r"go(\d+)\.(\d+)(?:\.(\d+))?")


def parse_go_mod_toolchain(text: str) -> tuple[str, tuple[int, int, int], bool] | None:
    """(``go1.2.3``, (1, 2, 3), exact).

    ``exact`` is true when the module has a ``toolchain`` directive. A bare
    ``go 1.22`` line is the language version (patch 0, not exact).
    """
    m = _TOOLCHAIN_DIRECTIVE.search(text or "")
    if m:
        name = m.group(1)
        ver = _GO_VERSION_LINE.search(name)
        if not ver:
            return None
        return name, (int(ver.group(1)), int(ver.group(2)), int(ver.group(3) or 0)), True
    m = _GO_DIRECTIVE.search(text or "")
    if not m:
        return None
    parts = [int(p) for p in m.group(1).split(".")]
    while len(parts) < 3:
        parts.append(0)
    major, minor, patch = parts[:3]
    return f"go{major}.{minor}.{patch}", (major, minor, patch), False


def local_go_version(go_bin: str = "go") -> tuple[int, int, int] | None:
    try:
        r = subprocess.run([go_bin, "version"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = _GO_VERSION_LINE.search((r.stdout or "") + (r.stderr or ""))
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


# Final patch of each minor whose ``go1.N.0`` zip is not on the toolchain
# download service. Go 1.21 is the first minor that publishes ``go1.N.0``.
# A bare ``go 1.20`` line used to ask for ``go1.20.0`` and then abstain with
# "toolchain not available", even though ``go1.20.14`` downloads and runs.
_FINAL_GO_PATCH = {
    (1, 9): 7,
    (1, 10): 8,
    (1, 11): 13,
    (1, 12): 17,
    (1, 13): 15,
    (1, 14): 15,
    (1, 15): 15,
    (1, 16): 15,
    (1, 17): 13,
    (1, 18): 10,
    (1, 19): 13,
    (1, 20): 14,
}

# Toolchain zip publish day (YYYYMMDD) from proxy.golang.org ``.info`` Time.
# A floating ``go 1.N`` line picks the last patch on or before the commit.
_GO_PATCH_RELEASED_ROWS = (
    (20, 1, "20230213"), (20, 2, "20230303"), (20, 3, "20230329"), (20, 4, "20230426"),
    (20, 5, "20230601"), (20, 6, "20230706"), (20, 7, "20230726"), (20, 8, "20230831"),
    (20, 9, "20230928"), (20, 10, "20231009"), (20, 11, "20231101"), (20, 12, "20231129"),
    (20, 13, "20240104"), (20, 14, "20240202"),
    (21, 0, "20230804"), (21, 1, "20230831"), (21, 2, "20230928"), (21, 3, "20231009"),
    (21, 4, "20231101"), (21, 5, "20231129"), (21, 6, "20240104"), (21, 7, "20240202"),
    (21, 8, "20240229"), (21, 9, "20240329"), (21, 10, "20240501"), (21, 11, "20240530"),
    (21, 12, "20240627"), (21, 13, "20240731"),
    (22, 0, "20240202"), (22, 1, "20240229"), (22, 2, "20240329"), (22, 3, "20240501"),
    (22, 4, "20240530"), (22, 5, "20240627"), (22, 6, "20240731"), (22, 7, "20240829"),
    (22, 8, "20240928"), (22, 9, "20241106"), (22, 10, "20241127"), (22, 11, "20250110"),
    (22, 12, "20250131"),
    (23, 0, "20240807"), (23, 1, "20240829"), (23, 2, "20240928"), (23, 3, "20241106"),
    (23, 4, "20241127"), (23, 5, "20250110"), (23, 6, "20250131"), (23, 7, "20250227"),
    (23, 8, "20250326"), (23, 9, "20250430"), (23, 10, "20250529"), (23, 11, "20250702"),
    (23, 12, "20250801"),
    (24, 0, "20250210"), (24, 1, "20250227"), (24, 2, "20250326"), (24, 3, "20250430"),
    (24, 4, "20250529"), (24, 5, "20250702"), (24, 6, "20250801"), (24, 7, "20250827"),
    (24, 8, "20251002"), (24, 9, "20251013"), (24, 10, "20251031"), (24, 11, "20251126"),
    (24, 12, "20260108"), (24, 13, "20260203"),
    (25, 0, "20250808"), (25, 1, "20250827"), (25, 2, "20251002"), (25, 3, "20251013"),
    (25, 4, "20251031"), (25, 5, "20251126"), (25, 6, "20260108"), (25, 7, "20260203"),
    (25, 8, "20260305"), (25, 9, "20260327"), (25, 10, "20260504"), (25, 11, "20260529"),
    (25, 12, "20260701"), (25, 13, "20260811"), (25, 14, "20260818"),
    (26, 0, "20260210"), (26, 1, "20260305"), (26, 2, "20260327"), (26, 3, "20260504"),
    (26, 4, "20260529"), (26, 5, "20260701"), (26, 6, "20260811"), (26, 7, "20260818"),
    (26, 8, "20260828"),
)
_GO_PATCH_RELEASED: dict[tuple[int, int], list[tuple[int, str]]] = {}
for _minor, _patch, _day in _GO_PATCH_RELEASED_ROWS:
    _GO_PATCH_RELEASED.setdefault((1, _minor), []).append((_patch, _day))


def _apply_buildvcs_flag(env: dict[str, str]) -> None:
    """``-buildvcs`` exists only since Go 1.18.

    The runner adds it so a checkout with a dirty git dir does not fail the
    build. Go 1.13–1.17 reject the flag (``unknown flag -buildvcs``) and the
    commit is then reported as a build failure. Strip it for those toolchains.
    ``local`` and ``auto`` are the process Go, which is new enough.
    """
    parts = [p for p in (env.get("GOFLAGS") or "").split() if not p.startswith("-buildvcs")]
    tc = env.get("GOTOOLCHAIN") or ""
    old = False
    m = re.match(r"^go(\d+)\.(\d+)(?:\.(\d+))?$", tc)
    if m:
        old = (int(m.group(1)), int(m.group(2))) < (1, 18)
    if not old:
        parts.append("-buildvcs=false")
    env["GOFLAGS"] = " ".join(parts).strip()


def _downloadable_go_toolchain(name: str, ver: tuple[int, int, int], *, exact: bool) -> str:
    major, minor, patch = ver
    if exact or patch != 0 or (major, minor) >= (1, 21):
        return name
    last = _FINAL_GO_PATCH.get((major, minor))
    if not last:
        return name
    return f"go{major}.{minor}.{last}"


def _go_line_pins_patch(mod_text: str) -> bool:
    """True when the ``go`` line writes a patch (``go 1.22.5``), not ``go 1.22``."""
    match = _GO_DIRECTIVE.search(mod_text or "")
    if not match:
        return False
    return match.group(1).count(".") >= 2


def go_patch_current_on(major: int, minor: int, on_yyyymmdd: str) -> str | None:
    """Newest ``go1.N.P`` of that minor published on or before ``on_yyyymmdd``.

    Dates are the toolchain zip's module-proxy time. A minor that is not in
    the table is left alone (the caller keeps the go.mod version). A commit
    from before the first zip uses that first downloadable patch.
    """
    rows = _GO_PATCH_RELEASED.get((major, minor))
    if not rows or not re.fullmatch(r"20\d{6}", on_yyyymmdd or ""):
        return None
    eligible = [patch for patch, day in rows if day <= on_yyyymmdd]
    patch = eligible[-1] if eligible else rows[0][0]
    return f"go{major}.{minor}.{patch}"


def select_gotoolchain(
    mod_text: str,
    local: tuple[int, int, int] | None,
    *,
    on_date: str | None = None,
) -> str:
    """GOTOOLCHAIN value for this checkout's go.mod, not the job's HEAD toolchain.

    A ``toolchain`` line is used as written. An explicit ``go 1.N.P`` patch is
    that compiler. A floating ``go 1.N`` line, when ``on_date`` is the commit
    day (``YYYYMMDD``), uses the newest patch of ``1.N`` published on or
    before that day. Without a date, a bare ``go 1.N`` for N < 21 names the
    last published patch (``go1.N.0`` is not downloadable) and N >= 21 names
    ``go1.N.0``. ``local`` is returned only when the binary already on PATH
    is that exact version. A newer patch of the same minor is still HEAD's
    compiler, so it is not reused. Downloads land in GOMODCACHE.
    """
    parsed = parse_go_mod_toolchain(mod_text)
    if parsed is None:
        return "auto"
    name, ver, exact = parsed
    major, minor, patch = ver
    if on_date and not exact and not _go_line_pins_patch(mod_text):
        dated = go_patch_current_on(major, minor, on_date)
        if dated:
            name = dated
            ver = _go_version_tuple(dated) or ver
            major, minor, patch = ver
    name = _downloadable_go_toolchain(name, ver, exact=exact)
    if not exact and patch == 0 and name != f"go{major}.{minor}.{patch}":
        # The substituted patch is the one local-vs-download compares against.
        patch = int(name.rsplit(".", 1)[-1])
    # The job's ``setup-go`` reads HEAD's go.mod. A same-minor newer patch is
    # still HEAD's toolchain. Use this commit's version unless it is the same
    # tuple as the binary already on PATH (no download).
    want = _GO_VERSION_LINE.search(name)
    if want:
        major = int(want.group(1))
        minor = int(want.group(2))
        patch = int(want.group(3) or 0)
    if local is not None and local == (major, minor, patch):
        return "local"
    return name


def _commit_calendar_day(wt: Path) -> str | None:
    """Committer date of HEAD as ``YYYYMMDD``, or None when git cannot say."""
    try:
        result = subprocess.run(
            ["git", "-C", str(wt), "log", "-1", "--format=%cI"],
            capture_output=True, text=True, timeout=10, env=build_scrubbed_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.match(r"(\d{4})-(\d{2})-(\d{2})", (result.stdout or "").strip())
    if not match:
        return None
    return match.group(1) + match.group(2) + match.group(3)


def go_failure_shape(text: str) -> str:
    """``assertion`` for a failing test check, '' for panics and compile errors."""
    if re.search(r"\bpanic:", text or "", re.I):
        return ""
    if re.search(r"--- FAIL:|Error Trace:|Error:|Not equal|@@ ", text or ""):
        return "assertion"
    return ""


def classify_go_json(stdout: str, stderr: str, pkg_import: str | None, names: Sequence[str]) -> tuple[str, str, str]:
    """(label, kind, detail) for one ``go test -json`` invocation over one package."""
    evs = _go_json_events((stdout or "").splitlines())
    text = (stdout or "") + "\n" + (stderr or "")
    human = "".join(str(ev.get("Output") or "") for ev in evs if ev.get("Action") in ("output", "build-output"))
    human += "\n".join(ln for ln in (stdout or "").splitlines() if not ln.lstrip().startswith("{"))
    human += "\n" + (stderr or "")
    interesting = [ln.strip() for ln in human.splitlines()
                   if ln.strip() and not ln.startswith(("=== RUN", "=== PAUSE", "=== CONT"))]
    # Prefer the assertion or compiler line. A ``file.go:line`` debug log
    # (Coder's pubsub dial, for example) must not hide ``--- FAIL:``.
    prefer = [ln for ln in interesting if re.search(
        r"--- FAIL:|Error Trace:|Error:|Not equal|undefined:|panic:|does not exist|FATAL", ln)]
    key = prefer or [ln for ln in interesting if re.search(
        r"\berror\b|cannot|undefined|panic|FAIL|timed out", ln, re.I)]
    detail = _scrub_reason(" | ".join((key or interesting)[:3]), max_len=200)
    loc = compiler_location(human)
    if loc and loc not in detail:
        detail = _scrub_reason(f"{loc}: {detail}", max_len=200)
    if any(ev.get("Action") == "build-fail" for ev in evs) or re.search(r"\[(?:build|setup) failed\]", text):
        return "error", "build_error", detail or "build_failed"
    if not evs:
        if "test timed out" in text:
            return "error", "test_timeout", detail
        return "error", "build_error", detail or "no_json_output"
    final: dict[str, str] = {}
    pkg_final = None
    for ev in evs:
        a = ev.get("Action")
        if a not in ("pass", "fail", "skip"):
            continue
        t = ev.get("Test")
        if t:
            final[str(t)] = str(a)
        else:
            pkg_final = a
    if "panic: test timed out" in text:
        return "error", "test_timeout", detail
    statuses = [final.get(n) for n in names]
    if any(s is None for s in statuses):
        if pkg_final == "fail" and not any(s == "fail" for s in statuses):
            return "error", "package_fail", detail or "package_failed_without_target_result"
        return "error", "not_found", detail or "test_not_found"
    if any(s == "skip" for s in statuses):
        return "error", "skipped", detail or "test_skipped"
    if any(s == "fail" for s in statuses):
        return "red", "fail", detail or "fail"
    if pkg_final == "fail":
        return "error", "package_fail", detail or "package_failed_after_pass"
    return "green", "pass", detail or "pass"


def maybe_migrate_coder(wt: Path, env: dict, deadline, go_bin: str) -> str | None:
    """Apply Coder's migrations to ``CODER_PG_CONNECTION_URL`` when that variable is set.

    ``dbtestutil.NewDB`` migrates a private database only when the variable is
    unset. Install docs tell the job to set it, so the named database is empty
    unless this step runs ``migrations.Up`` against it. Returns a short error
    or None. The helper source is removed before tests run.
    """
    dsn = env.get("CODER_PG_CONNECTION_URL") or ""
    if not dsn.startswith("postgres"):
        return None
    if not (wt / "coderd" / "database" / "migrations").is_dir():
        return None
    try:
        mod = (wt / "go.mod").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "coder_migrate_no_gomod"
    m = re.search(r"(?m)^module\s+(\S+)", mod)
    if not m:
        return "coder_migrate_no_module"
    module = m.group(1).strip('"')
    if not re.fullmatch(r"[A-Za-z0-9_./~+-]+", module):
        return "coder_migrate_bad_module"
    dest = wt / "scripts" / "_sentinel_migrate"
    try:
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "main.go").write_text(
            "package main\n\nimport (\n\t\"database/sql\"\n\t\"os\"\n\n"
            f"\t\"{module}/coderd/database/migrations\"\n\n"
            "\t_ \"github.com/lib/pq\"\n)\n\nfunc main() {\n"
            "\tdb, err := sql.Open(\"postgres\", os.Getenv(\"CODER_PG_CONNECTION_URL\"))\n"
            "\tif err != nil {\n\t\tpanic(err)\n\t}\n\tdefer db.Close()\n"
            "\tif err = db.Ping(); err != nil {\n\t\tpanic(err)\n\t}\n"
            "\tif err = migrations.Up(db); err != nil {\n\t\tpanic(err)\n\t}\n}\n",
            encoding="utf-8",
        )
        rem = remaining_budget(deadline)
        if rem < 2:
            return "budget_exhausted"
        rc, out, errt = run_capped(
            [go_bin, "run", "./scripts/_sentinel_migrate"],
            cwd=wt, env=env, timeout=min(180.0, rem),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return type(exc).__name__
    finally:
        shutil.rmtree(dest, ignore_errors=True)
    if rc != 0:
        return setup_error_quote(out, errt) or _scrub_reason((errt or out)[-200:], max_len=120) or "coder_migrate_failed"
    return None


_DB_RESET_META = re.compile(r"[\x00-\x1f;&|`$<>]")


def allocate_fresh_db(cache: Path, sha: str) -> dict[str, str]:
    """A new empty sqlite file and a new database name for this commit.

    The previous commit's file is not reused. ``SENTINEL_DATABASE_URL`` and
    ``SENTINEL_DB_NAME`` are what a customer reset command should migrate.
    """
    safe = re.sub(r"[^0-9a-f]", "", (sha or "").lower())[:12] or "nosha"
    dest = Path(cache) / "fresh-db" / safe / f"{uuid.uuid4().hex}.sqlite"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(b"")
    return {
        "SENTINEL_DB_PATH": str(dest),
        "SENTINEL_DATABASE_URL": "sqlite:///" + str(dest),
        "SENTINEL_DB_NAME": f"s{safe}{dest.stem[:8]}",
    }


_HELM_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
_HELM_VERSION_OUT = re.compile(r"v?(\d+\.\d+\.\d+)")
_HELM_TARBALL_MAX = 40_000_000
_HELM_BINARY_MAX = 80_000_000
_TOOL_NAME = re.compile(r"^[A-Za-z0-9_-]+$")


def pinned_tool_version(root: Path, tool: str) -> str | None:
    """Exact ``X.Y.Z`` pin for ``tool`` in ``mise.toml`` or ``.tool-versions``.

    Coder's CI installs the tools in ``mise.toml`` before the job runs. A
    replay that uses a different release fails the parent and the culprit
    for the same reason.
    """
    if not _TOOL_NAME.fullmatch(tool or ""):
        return None
    mise_re = re.compile(
        rf"(?m)^{re.escape(tool)}\s*=\s*[\"'](\d+\.\d+\.\d+)[\"']\s*$"
    )
    file_re = re.compile(rf"(?m)^{re.escape(tool)}[ \t]+(\d+\.\d+\.\d+)[ \t]*$")
    for name in ("mise.toml", ".mise.toml"):
        try:
            text = (root / name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        match = mise_re.search(text)
        if match and _HELM_SEMVER.fullmatch(match.group(1)):
            return match.group(1)
    try:
        text = (root / ".tool-versions").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    match = file_re.search(text)
    if match and _HELM_SEMVER.fullmatch(match.group(1)):
        return match.group(1)
    return None


def pinned_helm_version(root: Path) -> str | None:
    """Helm release named by this checkout, or None."""
    return pinned_tool_version(root, "helm")


def _go_version_tuple(text: str | None) -> tuple[int, int, int] | None:
    match = re.fullmatch(r"(?:go)?(\d+)\.(\d+)\.(\d+)", (text or "").strip())
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def merge_mise_go(mod_text: str, selected: str, mise_go: str | None) -> str:
    """Use the checkout's mise Go pin when it is newer than ``go.mod``.

    Never lower the selection. A job stuck on Go 1.26.4 cannot parse a module
    that says ``go 1.26.5``; the mise pin must not put that older compiler
    back. An explicit ``toolchain`` directive is left as written. A mise pin
    with no ``go.mod`` line is the compiler to download.
    """
    pin = _go_version_tuple(mise_go)
    if pin is None:
        return selected
    parsed = parse_go_mod_toolchain(mod_text or "")
    if parsed is not None and parsed[2]:
        return selected
    floor = _go_version_tuple(selected)
    if floor is None and parsed is not None:
        floor = parsed[1]
    if floor is None:
        return f"go{pin[0]}.{pin[1]}.{pin[2]}"
    if pin > floor:
        return f"go{pin[0]}.{pin[1]}.{pin[2]}"
    return selected


def workflow_go_versions(root: Path) -> list[tuple[int, int, int]]:
    """Go versions named by this checkout's GitHub Actions workflows.

    A matrix ``go: [17, 22]`` next to ``go-version: 1.${{ matrix.go }}.x`` is
    1.17 and 1.22. An explicit ``go-version: 1.21`` is that version. Patch 0
    means "the minor"; ``select``'s download helper fills the last published
    patch when ``go1.N.0`` does not exist.
    """
    wf = root / ".github" / "workflows"
    if not wf.is_dir():
        return []
    found: list[tuple[int, int, int]] = []
    explicit = re.compile(
        r"""(?m)^[ \t]*go-version:[ \t]*['\"]?(?:\^|>=|v)?(\d+)\.(\d+)(?:\.(\d+)|(?:\.[xX]))?"""
    )
    for path in sorted(wf.glob("*.y*ml")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in explicit.finditer(text):
            found.append((int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)))
        if not re.search(r"go-version:.*matrix\.go", text):
            continue
        block = re.search(
            r"(?m)^[ \t]*go:[ \t]*\n((?:[ \t]+-[ \t]*['\"]?\d+(?:\.\d+){0,2}['\"]?[ \t]*\n)+)",
            text,
        )
        if not block:
            continue
        for raw in re.findall(r"(\d+(?:\.\d+){0,2})", block.group(1)):
            parts = [int(piece) for piece in raw.split(".")]
            if len(parts) == 1 and 10 <= parts[0] <= 30:
                found.append((1, parts[0], 0))
            elif len(parts) >= 2 and parts[0] == 1:
                while len(parts) < 3:
                    parts.append(0)
                found.append((parts[0], parts[1], parts[2]))
    return found


def merge_workflow_go(mod_text: str, selected: str, versions: list[tuple[int, int, int]]) -> str:
    """Prefer the oldest CI Go that is still at least the ``go`` directive.

    An explicit ``toolchain`` line is left as written. A workflow pin older
    than ``selected`` is ignored, so a lint job on an old Go cannot pull the
    compiler backwards.
    """
    parsed = parse_go_mod_toolchain(mod_text or "")
    if parsed is not None and parsed[2]:
        return selected
    if not versions:
        return selected
    floor = _go_version_tuple(selected)
    lang = parsed[1] if parsed is not None else (floor or (0, 0, 0))
    eligible = [ver for ver in versions if (ver[0], ver[1]) >= (lang[0], lang[1])]
    if not eligible:
        return selected
    pick = min(eligible)
    name = _downloadable_go_toolchain(
        f"go{pick[0]}.{pick[1]}.{pick[2]}",
        pick,
        exact=pick[2] != 0,
    )
    chosen = _go_version_tuple(name)
    if floor is not None and chosen is not None and chosen > floor:
        return name
    if floor is None:
        return name
    return selected


def _helm_target_arch() -> str | None:
    if sys.platform != "linux":
        return None
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    return None


def _http_bytes(url: str, limit: int, timeout: float = 60.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "sentinel-bisect"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - host is get.helm.sh, version is a semver
        chunks: list[bytes] = []
        total = 0
        while True:
            block = resp.read(64 * 1024)
            if not block:
                break
            total += len(block)
            if total > limit:
                raise ValueError("response_too_large")
            chunks.append(block)
    return b"".join(chunks)


def _extract_named_binary(blob: bytes, member_name: str, dest: Path) -> None:
    """Write one tar member to ``dest``. The member name is an exact path."""
    parts = member_name.split("/")
    if not member_name or member_name.startswith("/") or ".." in parts:
        raise ValueError("helm_member")
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
        try:
            member = archive.getmember(member_name)
        except KeyError as exc:
            raise ValueError("helm_member_missing") from exc
        if not member.isfile() or member.size <= 0 or member.size > _HELM_BINARY_MAX:
            raise ValueError("helm_member_size")
        src = archive.extractfile(member)
        if src is None:
            raise ValueError("helm_member_empty")
        data = src.read(member.size + 1)
        if len(data) != member.size:
            raise ValueError("helm_member_short")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".tmp")
    tmp.write_bytes(data)
    tmp.chmod(0o755)
    os.replace(tmp, dest)


def _install_helm_release(version: str, dest: Path) -> str | None:
    """Install one Helm release from get.helm.sh into ``dest``. Checksum checked."""
    if not _HELM_SEMVER.fullmatch(version):
        return "helm_install_failed:version"
    arch = _helm_target_arch()
    if arch is None:
        return "helm_install_failed:platform"
    url = f"https://get.helm.sh/helm-v{version}-linux-{arch}.tar.gz"
    try:
        blob = _http_bytes(url, _HELM_TARBALL_MAX)
        digest_text = _http_bytes(url + ".sha256", 256, timeout=30).decode("ascii", "replace")
    except Exception as exc:  # noqa: BLE001 - network and HTTP errors become env_setup
        return "helm_install_failed:" + type(exc).__name__
    digest = digest_text.strip().split()[0] if digest_text.strip() else ""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        return "helm_install_failed:checksum"
    if hashlib.sha256(blob).hexdigest().lower() != digest.lower():
        return "helm_install_failed:checksum"
    try:
        _extract_named_binary(blob, f"linux-{arch}/helm", dest / "helm")
    except (OSError, ValueError, tarfile.TarError):
        return "helm_install_failed:extract"
    return None


def _helm_binary_version(binary: str, env: dict[str, str]) -> str | None:
    if not binary or not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        return None
    try:
        rc, out, err = run_capped(
            [binary, "version", "--template", "{{.Version}}"],
            env=env, timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if rc != 0:
        return None
    match = _HELM_VERSION_OUT.search((out or err or "").strip())
    return match.group(1) if match else None


def _helm_on_path(env: dict[str, str]) -> str | None:
    found = shutil.which("helm", path=env.get("PATH"))
    if not found:
        return None
    return _helm_binary_version(found, env)


def ensure_pinned_helm(root: Path, cache: Path, env: dict[str, str]) -> str | None:
    """Put this checkout's pinned Helm first on ``PATH``.

    ``None`` means the pin is absent, or Helm is ready. A string is an
    environment error (the install failed). A binary already on ``PATH`` is
    kept only when it is that exact release. The directory is also stored in
    ``SENTINEL_TOOL_HELM`` so a private ``/tmp`` bind-mounts it back.
    """
    version = pinned_helm_version(root)
    if not version:
        return None
    if _helm_on_path(env) == version:
        return None
    dest = cache / "tools" / "helm" / version
    binary = dest / "helm"
    if _helm_binary_version(str(binary), env) != version:
        err = _install_helm_release(version, dest)
        if err:
            return err
        if _helm_binary_version(str(binary), env) != version:
            return "helm_install_failed:version"
    env["SENTINEL_TOOL_HELM"] = str(dest)
    env["PATH"] = str(dest) + os.pathsep + env.get("PATH", "/usr/bin:/bin")
    return None


def apply_db_reset(
    command: Sequence[str] | None,
    *,
    cwd: Path,
    env: dict[str, str],
    deadline: float | None,
    sha: str,
    cache: Path,
) -> str | None:
    """Run the customer reset-and-migrate argv against a fresh database.

    ``None`` means success, or that no command was configured. A failure is an
    environment error, never a red test. The fresh URL is copied onto ``env``
    only after the command exits 0, so the tests see the database it migrated.
    """
    if not command:
        return None
    for part in command:
        if not isinstance(part, str) or not part or _DB_RESET_META.search(part):
            return "db_reset_rejected"
    extra = allocate_fresh_db(cache, sha)
    run_env = dict(env)
    run_env.update(extra)
    rem = remaining_budget(deadline)
    if rem < 1:
        return "budget_exhausted"
    try:
        rc, out, errt = run_capped(list(command), cwd=cwd, env=run_env, timeout=min(180.0, rem))
    except subprocess.TimeoutExpired:
        return "db_reset_timeout"
    except OSError as exc:
        return f"db_reset_failed:{type(exc).__name__}"
    if rc != 0:
        quote = setup_error_quote(out, errt) or _scrub_reason((errt or out)[-160:], max_len=120)
        return "db_reset_failed:" + (quote or f"exit_{rc}")
    env.update(extra)
    return None


@dataclass
class GoGitRunner(_WorktreeRunner):
    """``go test -json -count=1 -run '^(TestA|TestB)$' ./pkg`` per package, per commit."""

    go_bin: str = "go"
    test_command: Sequence[str] | None = None  # argv prefix replacing ["go", "test"]
    db_reset_command: Sequence[str] | None = None
    cache_dir: Path | None = None
    per_run_timeout_sec: float = 300.0
    kind_name = "go"

    def validate_ids(self, tests: Sequence[str]) -> tuple[list[str], str | None]:
        return validate_go_ids(tests)

    def _child_env_go(self, home: Path) -> dict[str, str]:
        env = build_scrubbed_env(extra=dict(self.env or {}), home=str(home))
        apply_isolated_home(env, home)
        _passthrough(env, _GO_ENV_PASS)
        cache = Path(self.cache_dir or default_cache_dir())
        (cache / "gocache").mkdir(parents=True, exist_ok=True)
        (cache / "gomodcache").mkdir(parents=True, exist_ok=True)
        (cache / "gopath").mkdir(parents=True, exist_ok=True)
        env["GOCACHE"] = str(cache / "gocache")
        env["GOMODCACHE"] = str(cache / "gomodcache")
        env["GOPATH"] = str(cache / "gopath")
        # Replaced from this checkout's go.mod in ``_pin_toolchain``. A job-level
        # GOTOOLCHAIN (HEAD's setup-go) must not survive that pin.
        env["GOTOOLCHAIN"] = "auto"
        env["GOFLAGS"] = (env.get("GOFLAGS", "") + " -buildvcs=false").strip()
        env["GIT_TERMINAL_PROMPT"] = "0"
        return env

    def evaluate(self, sha: str, tests: Sequence[str], *, reruns: int, deadline: float | None = None) -> EvalResult:
        clean, err = validate_go_ids(tests)
        if err:
            return EvalResult(label="error", detail=err, kind="unknown")
        wt, early = self._prepare(sha, deadline)
        if early is not None:
            return early
        assert wt is not None
        # group by resolved package
        groups: dict[tuple[str, str], list[str]] = {}
        for t in clean:
            pkg, _, name = t.rpartition("::")
            res = resolve_go_package(wt, pkg)
            if res is None:
                return EvalResult(label="error", detail=f"package_not_in_any_module:{pkg[:60]}", kind="not_found")
            mod_dir, rel = res
            if not (wt / mod_dir / rel).is_dir():
                return EvalResult(label="error", detail=f"package_dir_missing:{rel[:60]}", kind="not_found")
            groups.setdefault((mod_dir, rel), []).append(name)
        home = make_isolated_home()
        try:
            env = self._child_env_go(home)
            ensure_declared_services(wt, env)
            first_mod = next(iter(groups))[0]
            self._pin_toolchain(wt, first_mod, env)
            cache = Path(self.cache_dir or default_cache_dir())
            helm_err = ensure_pinned_helm(wt, cache, env)
            if helm_err:
                return EvalResult(label="error", detail=helm_err, kind="env_setup")
            db_err = apply_db_reset(
                self.db_reset_command, cwd=wt, env=env, deadline=deadline, sha=sha,
                cache=cache,
            )
            if db_err:
                kind = "timeout" if "budget" in db_err or db_err == "db_reset_timeout" else "env_setup"
                return EvalResult(label="error", detail=db_err, kind=kind)
            self._migrate_note = maybe_migrate_coder(wt, env, deadline, self.go_bin)
            runs: list[EvalResult] = []
            for _ in range(max(1, reruns)):
                rem = remaining_budget(deadline)
                if rem < 0.05:
                    runs.append(EvalResult(label="error", detail="budget_exhausted", kind="timeout"))
                    break
                per = [self._run_group(wt, mod_dir, rel, names, env, deadline)
                       for (mod_dir, rel), names in groups.items()]
                runs.append(_combine_groups(per))
                if runs[-1].kind == "timeout" or runs[-1].kind == "build_error":
                    break  # a build error will not change on rerun; save budget
            return self._aggregate(runs)
        finally:
            shutil.rmtree(home, ignore_errors=True)

    def _pin_toolchain(self, wt: Path, mod_dir: str, env: dict) -> None:
        path = wt / mod_dir / "go.mod"
        if not path.is_file():
            path = wt / "go.mod"
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            mise = pinned_tool_version(wt, "go")
            env["GOTOOLCHAIN"] = f"go{mise}" if mise else "auto"
            return
        if not hasattr(self, "_local_go"):
            prefix = list(self.test_command)[:1] if self.test_command else [self.go_bin]
            self._local_go = local_go_version(prefix[0] if prefix else self.go_bin)
        selected = merge_mise_go(
            text,
            select_gotoolchain(text, self._local_go, on_date=_commit_calendar_day(wt)),
            pinned_tool_version(wt, "go"),
        )
        # ``go 1.15`` is the minimum language version. CI's setup-go is often
        # newer (the tests call ``io.ReadAll``). Use the oldest workflow
        # compiler that still satisfies that minimum.
        env["GOTOOLCHAIN"] = merge_workflow_go(text, selected, workflow_go_versions(wt))
        _apply_buildvcs_flag(env)

    def _run_group(self, wt: Path, mod_dir: str, rel: str, names: list[str], env: dict, deadline) -> EvalResult:
        env = dict(env)
        self._pin_toolchain(wt, mod_dir, env)
        rem = remaining_budget(deadline)
        t = min(float(self.per_run_timeout_sec), rem)
        if t < 0.05:
            return EvalResult(label="error", detail="budget_exhausted", kind="timeout")
        prefix = list(self.test_command) if self.test_command else [self.go_bin, "test"]
        groups = go_run_regexes(names)
        # Pair each regexp with the names it covers. Subtests are one name each.
        covered: list[tuple[str, list[str]]] = []
        tops = [n for n in names if "/" not in n]
        subs = [n for n in names if "/" in n]
        if tops:
            covered.append((groups[0], tops))
            rest = groups[1:]
        else:
            rest = groups
        for reg, name in zip(rest, subs, strict=False):
            covered.append((reg, [name]))
        per: list[EvalResult] = []
        for reg, group_names in covered:
            cmd = prefix + ["-json", "-count=1", f"-timeout={max(1, int(t))}s", "-run", reg, rel]
            try:
                rc, out, errt = run_capped(cmd, cwd=wt / mod_dir, env=env, timeout=t + 5)
            except subprocess.TimeoutExpired:
                return EvalResult(label="error", detail="timeout", kind="timeout")
            except OSError as e:
                return EvalResult(label="error", detail=f"os:{type(e).__name__}", kind="tool_missing")
            label, kind, detail = classify_go_json(out, errt, None, group_names)
            shape = go_failure_shape(out + "\n" + errt) if label == "red" else ""
            if self._migrate_note and label == "red" and not setup_error_quote(detail):
                detail = _scrub_reason(f"{detail} | migrate: {self._migrate_note}", max_len=200)
            per.append(EvalResult(label=label, detail=detail, kind=kind, failure=shape,
                                  passes=int(label == "green"), fails=int(label == "red"), runs=1))
        return _combine_groups(per)


def _combine_groups(per: list[EvalResult]) -> EvalResult:
    """One run over several packages: build_error > not_found > other error > red > green."""
    for k in ("build_error", "timeout", "not_found"):
        for r in per:
            if r.label == "error" and r.kind == k:
                return r
    for r in per:
        if r.label == "error":
            return r
    if any(r.label == "red" for r in per):
        return next(r for r in per if r.label == "red")
    return per[0] if per else EvalResult(label="error", kind="unknown", detail="no_groups")


# =============================================================================
# JS runner (vitest / jest)
# =============================================================================
def js_name_pattern(names: Sequence[str]) -> str:
    """Anchored JS regex matching the full test name whether the runner joins
    suite names with ' ' (vitest 1-3, jest) or ' > '."""
    def esc(s: str) -> str:
        return re.sub(r"([.*+?^${}()|\[\]\\/])", r"\\\1", s)
    return "^" + "(?: > | )".join(esc(n) for n in names) + "$"


_LOCKFILES = (("pnpm-lock.yaml", "pnpm"), ("package-lock.json", "npm"),
              ("npm-shrinkwrap.json", "npm"), ("yarn.lock", "yarn"))


def _package_manager_field(wt: Path) -> str:
    try:
        data = json.loads((wt / "package.json").read_text(encoding="utf-8", errors="replace")[:500_000])
    except (OSError, ValueError):
        return ""
    pm = data.get("packageManager") if isinstance(data, dict) else None
    return pm.strip() if isinstance(pm, str) else ""


def _yarn_berry_path(wt: Path) -> str:
    """``yarnPath`` from .yarnrc.yml when it points at a checked-in release inside the repo."""
    try:
        txt = (wt / ".yarnrc.yml").read_text(encoding="utf-8", errors="replace")[:100_000]
    except OSError:
        return ""
    m = re.search(r"^yarnPath:\s*[\"']?([^\s\"'#]+)", txt, re.M)
    if not m:
        return ""
    rel = m.group(1)
    target = (wt / rel)
    try:
        if target.is_file() and target.resolve().is_relative_to(wt.resolve()):
            return rel
    except (OSError, ValueError):
        return ""
    return ""


def is_yarn_berry(wt: Path) -> bool:
    pm = _package_manager_field(wt)
    m = re.match(r"^yarn@(\d+)", pm)
    if m:
        return int(m.group(1)) >= 2
    return (wt / ".yarnrc.yml").is_file() or (wt / ".yarn" / "releases").is_dir()


_PNPM_EXACT = re.compile(r"^\d+\.\d+\.\d+$")


def _corepack_pnpm_bin(home: Path, version: str) -> Path | None:
    """pnpm 9 publishes ``pnpm.mjs``. pnpm 10+ also publishes ``pnpm.cjs``."""
    base = home / "v1" / "pnpm" / version / "bin"
    for name in ("pnpm.mjs", "pnpm.cjs"):
        candidate = base / name
        if candidate.is_file():
            return candidate
    return None


def prepared_pnpm_argv(cache: Path, version: str) -> list[str] | None:
    """``node <corepack home>/pnpm.mjs`` (or ``pnpm.cjs``) for a lockfile pin.

    ``packageManager`` checkouts keep using ``corepack pnpm``, which reads that
    field. This path is for a lockfile that names a version and a package.json
    that does not. A failed download returns ``None`` so the caller can fall
    back; it is not a test failure.
    """
    if not _PNPM_EXACT.fullmatch(version or ""):
        return None
    home = Path(cache) / "corepack"
    binary = _corepack_pnpm_bin(home, version)
    if binary is None:
        home.mkdir(parents=True, exist_ok=True)
        env = build_scrubbed_env()
        env["COREPACK_HOME"] = str(home)
        env["COREPACK_ENABLE_DOWNLOAD_PROMPT"] = "0"
        try:
            rc, _out, _err = run_capped(
                ["corepack", "prepare", f"pnpm@{version}"],
                cwd=home, env=env, timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        binary = _corepack_pnpm_bin(home, version)
        if rc != 0 or binary is None:
            return None
    node = shutil.which("node")
    if not node:
        return None
    return [node, str(binary)]


def js_pm_argv(wt: Path, tool_name: str, *, which=shutil.which, cache: Path | None = None) -> list[str]:
    """How to invoke pnpm or yarn: checked-in Yarn Berry, else corepack when
    ``packageManager`` pins a version, else the pnpm release named by the
    lockfile, else the binary on PATH.
    """
    pm = _package_manager_field(wt)
    if tool_name == "yarn" and is_yarn_berry(wt):
        rel = _yarn_berry_path(wt)
        if rel and which("node"):
            return ["node", rel]
    if pm.startswith(tool_name + "@") and which("corepack"):
        return ["corepack", tool_name]
    if (
        tool_name == "pnpm"
        and not pm.startswith("pnpm@")
        and cache is not None
        and which("corepack")
    ):
        ver = pnpm_version_from_checkout(wt)
        if ver:
            prepared = prepared_pnpm_argv(cache, ver)
            if prepared:
                return prepared
    if which(tool_name):
        return [tool_name]
    return ["corepack", tool_name] if which("corepack") else [tool_name]


def js_install_command(wt: Path, mgr: str, cache: Path, *, ignore_scripts: bool,
                       which=shutil.which) -> tuple[list[str], dict[str, str]]:
    """(argv, extra env) for a frozen install with the repo's package manager.

    * npm: ``npm ci``.
    * pnpm: ``pnpm install --frozen-lockfile`` (``corepack pnpm`` when pnpm is not on PATH).
    * Yarn classic (v1): ``yarn install --frozen-lockfile``.
    * Yarn Berry (v2+; ``.yarnrc.yml`` / ``packageManager: yarn@N>=2`` / ``.yarn/releases``):
      ``yarn install --immutable`` via the checked-in ``yarnPath`` release, else corepack.
      ``--ignore-scripts`` does not exist in Berry: ``--mode=skip-build`` is its equivalent.
      ``nodeLinker`` is forced to ``node-modules`` so the test binary resolves.
    Corepack never prompts and caches under the ProveBreak cache dir. bun is unsupported.
    """
    extra = {"COREPACK_ENABLE_DOWNLOAD_PROMPT": "0", "COREPACK_HOME": str(cache / "corepack")}

    if mgr == "pnpm":
        cmd = js_pm_argv(wt, "pnpm", which=which, cache=cache) + [
            "install", "--frozen-lockfile", "--prefer-offline",
            "--store-dir", str(cache / "pnpm-store"),
        ]
        # An allowlist means the project already chose which dependency builds
        # run. ``--ignore-scripts`` would skip those too. pnpm 10+ also fails
        # the install when some other build was skipped (``strictDepBuilds``);
        # the allowlist is the decision, so that check is not a second veto.
        if ignore_scripts and not pnpm_build_allowlist(wt):
            cmd.append("--ignore-scripts")
        elif pnpm_build_allowlist(wt) and (pnpm_major(wt) or 0) >= 10:
            cmd.append("--config.strict-dep-builds=false")
        return cmd, extra
    if mgr == "yarn" and is_yarn_berry(wt):
        cmd = js_pm_argv(wt, "yarn", which=which) + ["install", "--immutable"]
        if ignore_scripts:
            cmd.append("--mode=skip-build")
        extra.update({"YARN_CACHE_FOLDER": str(cache / "yarn-berry-cache"), "YARN_ENABLE_GLOBAL_CACHE": "0",
                      "YARN_NODE_LINKER": "node-modules", "YARN_ENABLE_TELEMETRY": "0",
                      "YARN_ENABLE_INLINE_BUILDS": "0"})
        return cmd, extra
    if mgr == "yarn":
        cmd = js_pm_argv(wt, "yarn", which=which, cache=cache) + ["install", "--frozen-lockfile", "--prefer-offline",
                                                     "--cache-folder", str(cache / "yarn-cache")]
        if ignore_scripts:
            cmd.append("--ignore-scripts")
        return cmd, extra
    cmd = ["npm", "ci", "--no-audit", "--no-fund", "--prefer-offline", "--cache", str(cache / "npm-cache")]
    if ignore_scripts:
        cmd.append("--ignore-scripts")
    return cmd, extra


def catalog_lockfile_mismatch(text: str) -> bool:
    """pnpm refused a frozen install because catalogs config and the lockfile disagree.

    Other ``LOCKFILE_CONFIG_MISMATCH`` names (overrides, packageExtensions) are
    not this error. A non-frozen install is only considered after this one.
    """
    blob = text or ""
    return "LOCKFILE_CONFIG_MISMATCH" in blob and "catalogs" in blob.lower()


def npm_eresolve(text: str) -> bool:
    """``npm ci`` stopped on a peer-dependency conflict."""
    return "ERESOLVE" in (text or "")


_LEGACY_FLAG_LINE = re.compile(
    r"(?i)\b(?:npm|pnpm|yarn)\b.*--legacy-peer-deps\b|--legacy-peer-deps\b.*\b(?:npm|pnpm|yarn)\b"
)
_LEGACY_TRUE = re.compile(r"(?im)^\s*legacy-peer-deps\s*=\s*true\s*(?:#.*)?$")
_CI_REL_PATHS = (
    ".circleci/config.yml",
    ".gitlab-ci.yml",
    "azure-pipelines.yml",
)


def _path_inside(root: Path, path: Path) -> bool:
    try:
        resolved = path.resolve() if path.exists() else path
        return resolved.is_relative_to(root.resolve())
    except (OSError, ValueError):
        return False


def _read_capped(root: Path, path: Path, limit: int = 200_000) -> str:
    if not _path_inside(root, path):
        return ""
    try:
        if path.is_symlink() and not path.resolve().is_relative_to(root.resolve()):
            return ""
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except (OSError, ValueError):
        return ""


def _text_uses_legacy_peer_deps(text: str) -> bool:
    if _LEGACY_TRUE.search(text or ""):
        return True
    return any(_LEGACY_FLAG_LINE.search(line) for line in (text or "").splitlines())


def _ci_config_texts(root: Path) -> list[str]:
    """CI config files only. A script or a README is not CI."""
    chunks: list[str] = []
    workflows = root / ".github" / "workflows"
    if workflows.is_dir() and _path_inside(root, workflows):
        try:
            names = sorted(
                p.name for p in workflows.iterdir()
                if p.is_file() and p.suffix in {".yml", ".yaml"}
            )
        except OSError:
            names = []
        for name in names[:40]:
            chunks.append(_read_capped(root, workflows / name))
    for rel in _CI_REL_PATHS:
        chunks.append(_read_capped(root, root / rel))
    try:
        extras = sorted(
            p for p in root.glob("azure-pipelines*.yml") if p.is_file() and p.parent == root
        )[:5]
    except OSError:
        extras = []
    for path in extras:
        chunks.append(_read_capped(root, path))
    return chunks


def ci_uses_legacy_peer_deps(root: Path) -> bool:
    """True when a CI workflow at this commit passes ``--legacy-peer-deps``.

    Only CI config is read: GitHub workflows, CircleCI, GitLab CI, and Azure
    Pipelines. A script or a README that mentions the flag is not CI.
    """
    return _text_uses_legacy_peer_deps("\n".join(_ci_config_texts(root)))


def npmrc_uses_legacy_peer_deps(directory: Path) -> bool:
    """True when ``.npmrc`` in ``directory`` sets ``legacy-peer-deps=true``."""
    return _LEGACY_TRUE.search(_read_capped(directory, directory / ".npmrc")) is not None


def commit_allows_legacy_peer_deps(start: Path, top: Path) -> bool:
    """True when this commit's CI workflow or an ``.npmrc`` on the way up opts in.

    ``legacy-peer-deps=false`` does not opt in. A flag outside CI and ``.npmrc``
    does not opt in.
    """
    current = start.resolve()
    stop = top.resolve()
    for _ in range(8):
        if npmrc_uses_legacy_peer_deps(current):
            return True
        if current == stop:
            break
        if stop not in current.parents:
            break
        parent = current.parent
        if parent == current:
            break
        current = parent
    return ci_uses_legacy_peer_deps(top)


_PACKAGE_LOCK_ASSIGN = re.compile(
    r"(?im)^\s*package-lock\s*=\s*(true|false)\s*(?:#.*)?$"
)
_NPM_VERB = re.compile(r"(?i)^npm(?:\.cmd)?\s+(install|ci)\b(.*)$")
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=\S*\s+")
_CI_COMMAND_KEY = re.compile(r"(?i)^(?:run|command|script)\s*:\s*(.*)$")
_CI_OTHER_KEY = re.compile(r"(?i)^[A-Za-z0-9_.-]+\s*:")
_NPM_COSMETIC_FLAGS = frozenset({
    "--no-audit", "--no-fund", "--ignore-scripts", "--no-package-lock",
    "--no-progress", "--silent", "--quiet", "--no-color", "--color",
})
_NPM_VALUE_FLAGS = frozenset({"--loglevel", "--cache", "--progress", "--package-lock"})


def _strip_unquoted_comment(line: str) -> str:
    out: list[str] = []
    quote = ""
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            continue
        if ch == "#":
            break
        out.append(ch)
    return "".join(out).strip()


def _ci_command_body(line: str) -> str:
    text = re.sub(r"^-\s+", "", line.strip())
    keyed = _CI_COMMAND_KEY.match(text)
    if keyed:
        body = keyed.group(1).strip()
        if body in {"|", ">", "|-", ">-", "|+", ">+"}:
            return ""
        return body
    if _CI_OTHER_KEY.match(text):
        return ""
    return text


def npmrc_package_lock_value(directory: Path) -> str | None:
    """``true``, ``false``, or ``None`` when ``.npmrc`` does not set one value.

    Two different assignments in the same file are not a decision.
    """
    found = [item.lower() for item in _PACKAGE_LOCK_ASSIGN.findall(
        _read_capped(directory, directory / ".npmrc")
    )]
    if len(set(found)) == 1:
        return found[0]
    return None


def checkout_disables_package_lock(start: Path, top: Path) -> bool:
    """True when the nearest ``package-lock`` assignment on the way up is false.

    ``package-lock=true`` closer to the install directory wins. A comment is
    not an assignment.
    """
    current = start.resolve()
    stop = top.resolve()
    for _ in range(8):
        value = npmrc_package_lock_value(current)
        if value == "false":
            return True
        if value == "true":
            return False
        if current == stop or stop not in current.parents:
            break
        parent = current.parent
        if parent == current:
            break
        current = parent
    return False


def _classify_npm_segment(segment: str) -> str:
    """``npm_install``, ``npm_install_legacy``, ``npm_ci``, ``disqualified``, or empty."""
    text = segment.strip()
    while True:
        assigned = _ENV_ASSIGN.match(text)
        if not assigned:
            break
        text = text[assigned.end():]
    matched = _NPM_VERB.match(text)
    if not matched:
        return ""
    verb = matched.group(1).lower()
    if verb == "ci":
        return "npm_ci"
    tokens = matched.group(2).split()
    legacy = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in ("-g", "--global"):
            return ""
        if token == "--legacy-peer-deps":
            legacy = True
            index += 1
            continue
        if token in _NPM_COSMETIC_FLAGS or any(token.startswith(flag + "=") for flag in _NPM_VALUE_FLAGS):
            index += 1
            continue
        if token in _NPM_VALUE_FLAGS and index + 1 < len(tokens):
            index += 2
            continue
        return "disqualified"
    return "npm_install_legacy" if legacy else "npm_install"


def ci_npm_install_policy(root: Path) -> str:
    """How this commit's CI installs an npm tree that has no lockfile.

    ``npm_install`` or ``npm_install_legacy`` when every project install is
    ``npm install`` and none is ``npm ci``. ``ambiguous`` when those disagree
    or a flag would change the tree (``--production``, ``--omit``, ``--force``).
    ``absent`` when CI never installs the project that way. A global
    ``npm install -g``, a ``name:`` label, a comment, a script, and a README
    are not an install.
    """
    kinds: set[str] = set()
    for text in _ci_config_texts(root):
        for raw in text.splitlines():
            body = _ci_command_body(_strip_unquoted_comment(raw))
            if not body:
                continue
            for segment in re.split(r"\s*(?:&&|\|\||;)\s*", body):
                kind = _classify_npm_segment(segment)
                if kind:
                    kinds.add(kind)
    project = kinds & {"npm_install", "npm_install_legacy"}
    if "disqualified" in kinds or len(project) > 1 or (project and "npm_ci" in kinds):
        return "ambiguous"
    if "npm_ci" in kinds:
        return "npm_ci"
    if "npm_install_legacy" in kinds:
        return "npm_install_legacy"
    if "npm_install" in kinds:
        return "npm_install"
    return "absent"


def _package_json_object(directory: Path) -> dict | None:
    try:
        data = json.loads((directory / "package.json").read_text(encoding="utf-8", errors="replace")[:500_000])
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _declares_js_workspaces(directory: Path) -> bool:
    if (directory / "pnpm-workspace.yaml").is_file():
        return True
    if (directory / "lerna.json").is_file() or (directory / "nx.json").is_file():
        return True
    data = _package_json_object(directory)
    workspaces = data.get("workspaces") if data else None
    if isinstance(workspaces, list):
        return any(str(item).strip() for item in workspaces)
    if isinstance(workspaces, dict):
        packages = workspaces.get("packages")
        return isinstance(packages, list) and any(str(item).strip() for item in packages)
    return False


def npm_unlocked_policy(directory: Path, repo_root: Path) -> str:
    """``npm_install`` or ``npm_install_legacy`` when a lockfile-less npm install is the repo's own.

    Both signals are required: ``.npmrc`` sets ``package-lock=false``, and CI
    runs ``npm install`` without ``npm ci``. A workspace stays on the lockfile
    path. Empty means abstain.
    """
    if _package_json_object(directory) is None or _declares_js_workspaces(directory):
        return ""
    if not checkout_disables_package_lock(directory, repo_root):
        return ""
    policy = ci_npm_install_policy(repo_root)
    if policy in ("npm_install", "npm_install_legacy"):
        return policy
    return ""


def js_unlocked_npm_install_command(
    cache: Path, *, ignore_scripts: bool, legacy_peer_deps: bool,
) -> tuple[list[str], dict[str, str]]:
    """``npm install`` for a repo that commits no lockfile.

    ``--no-package-lock`` is the ``package-lock=false`` already in ``.npmrc``.
    ``--prefer-offline`` is omitted so the registry, not a warm cache, picks
    versions. Cosmetic flags do not change that set.
    """
    cmd = ["npm", "install", "--no-package-lock", "--no-audit", "--no-fund", "--cache", str(cache / "npm-cache")]
    if legacy_peer_deps:
        cmd.append("--legacy-peer-deps")
    if ignore_scripts:
        cmd.append("--ignore-scripts")
    extra = {"COREPACK_ENABLE_DOWNLOAD_PROMPT": "0", "COREPACK_HOME": str(cache / "corepack")}
    return cmd, extra


def _drop_generated_npm_lock(directory: Path) -> None:
    """Remove a lockfile ``npm install`` just wrote. The commit did not have one."""
    for name in ("package-lock.json", "npm-shrinkwrap.json"):
        path = directory / name
        try:
            if path.is_file() and not path.is_symlink():
                path.unlink()
        except OSError:
            pass


def pnpm_package_ids(text: str) -> tuple[str, ...]:
    """Package keys under the lockfile ``packages:`` section, sorted.

    The ``catalogs:`` block is not included. A non-frozen install that only
    rewrites that block keeps the same ids.
    """
    ids: list[str] = []
    in_packages = False
    for line in (text or "").splitlines():
        if not in_packages:
            if line == "packages:" or line.startswith("packages:"):
                in_packages = True
            continue
        if line and not line[0].isspace() and not line.startswith("#"):
            break
        match = re.match(r"^  ['\"]?(.+?)['\"]?:\s*$", line)
        if match and "@" in match.group(1):
            ids.append(match.group(1))
    return tuple(sorted(ids))


def pnpm_importer_versions(text: str) -> tuple[str, ...]:
    """Resolved ``version:`` lines under ``importers:``, not under ``catalogs:``."""
    versions: list[str] = []
    section = ""
    for line in (text or "").splitlines():
        if line and not line[0].isspace() and not line.startswith("#") and line.endswith(":"):
            section = line.split(":", 1)[0]
        if section == "importers" and re.match(r"^\s+version:\s+\S+", line):
            versions.append(line.strip())
    return tuple(sorted(versions))


def pnpm_lock_fingerprint(text: str) -> tuple[str, ...]:
    """Package ids plus importer resolutions. Catalog metadata is not part of it."""
    return pnpm_package_ids(text) + pnpm_importer_versions(text)


def _pm_prefix(cmd: list[str]) -> tuple[str, ...]:
    try:
        return tuple(cmd[:cmd.index("install")])
    except ValueError:
        return tuple(cmd)


def _swap_pm_prefix(cmd: list[str], tool: list[str]) -> list[str]:
    try:
        idx = cmd.index("install")
    except ValueError:
        return list(tool) + list(cmd)
    return list(tool) + cmd[idx:]


def _non_frozen_cmd(cmd: list[str]) -> list[str]:
    out = ["--no-frozen-lockfile" if tok == "--frozen-lockfile" else tok for tok in cmd]
    if "--no-frozen-lockfile" not in out:
        try:
            out.insert(out.index("install") + 1, "--no-frozen-lockfile")
        except ValueError:
            out.append("--no-frozen-lockfile")
    return out


def pinned_pnpm_tool(root: Path, cache: Path) -> list[str] | None:
    """Argv for the pnpm this checkout pins, via ``packageManager`` or the lockfile.

    ``corepack pnpm`` when ``packageManager`` names that version. Otherwise the
    corepack binary for the lockfile pin. ``None`` when that version cannot be run.
    """
    version = pnpm_version_from_checkout(root)
    if not version:
        return None
    pm = _package_manager_field(root)
    if pm.startswith("pnpm@" + version) and shutil.which("corepack"):
        return ["corepack", "pnpm"]
    prepared = prepared_pnpm_argv(cache, version)
    if prepared:
        return prepared
    return None


def js_missing_module(detail: str) -> bool:
    """The installed tree cannot resolve a package the test imported."""
    text = detail or ""
    return "ERR_MODULE_NOT_FOUND" in text or "Cannot find module" in text


def _cli_playwright_version(cli: Path) -> str:
    try:
        data = json.loads((cli.parent / "package.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    version = str(data.get("version") or "")
    return version if re.fullmatch(r"\d+\.\d+\.\d+", version) else ""


def ensure_playwright_browsers(
    wt: Path, cache: Path, env: dict[str, str], deadline, *,
    browsers: list[str] | None = None, pin: str = "",
) -> None:
    """Install the pinned Playwright's browsers into the bisect cache.

    The test HOME is deleted after each commit, and Playwright's default cache
    lives under that HOME. ``PLAYWRIGHT_BROWSERS_PATH`` points at the cache so
    the next commit still finds the browser. The CLI is the one whose package
    version equals the lockfile pin when that pin is known.     A failed download
    leaves the test as a build abstain. The Playwright runner calls this only
    when the spec source names a browser fixture. A missing browser after that
    is ``playwright_browser_missing``, not a red test.
    """
    from sentinel_card.browser_spec import playwright_pin_text

    dest = Path(cache) / "ms-playwright"
    env["PLAYWRIGHT_BROWSERS_PATH"] = str(dest)
    wanted = [name for name in (browsers or ["chromium"]) if name in {"chromium", "firefox", "webkit"}]
    if "chromium" not in wanted:
        wanted.insert(0, "chromium")
    if not pin:
        blobs = []
        for name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "package.json"):
            path = wt / name
            if not path.is_file():
                continue
            try:
                blobs.append(path.read_text(encoding="utf-8", errors="replace")[:500_000])
            except OSError:
                continue
        pin = playwright_pin_text(*blobs)
    clis: list[Path] = []
    rels = [
        "node_modules/playwright/cli.js",
        "node_modules/playwright-core/cli.js",
        "node_modules/@playwright/test/cli.js",
    ]
    pnpm = wt / "node_modules" / ".pnpm"
    if pnpm.is_dir():
        rels.extend(
            str(p.relative_to(wt))
            for p in list(pnpm.glob("playwright@*/node_modules/playwright/cli.js"))[:4]
        )
        rels.extend(
            str(p.relative_to(wt))
            for p in list(pnpm.glob("@playwright+test@*/node_modules/@playwright/test/cli.js"))[:4]
        )
    for rel in rels:
        candidate = wt / rel
        if candidate.is_file() and candidate not in clis:
            clis.append(candidate)
    cli = None
    if pin:
        for candidate in clis:
            if _cli_playwright_version(candidate) == pin:
                cli = candidate
                break
    if cli is None and clis:
        cli = clis[0]
    if cli is None:
        return
    node = shutil.which("node")
    if not node:
        return
    rem = remaining_budget(deadline)
    if rem < 5:
        return
    dest.mkdir(parents=True, exist_ok=True)
    # Headless CI uses the shell build. Older Playwright rejects ``--only-shell``.
    attempts = [
        [node, str(cli), "install", *wanted, "--only-shell"],
        [node, str(cli), "install", *wanted],
    ]
    for argv in attempts:
        try:
            rc, _out, _err = run_capped(argv, cwd=wt, env=env, timeout=min(180.0, rem))
        except (OSError, subprocess.TimeoutExpired):
            return
        if rc == 0:
            return
        rem = remaining_budget(deadline)
        if rem < 5:
            return


def _js_reported_path(reported: str) -> str:
    name = str(reported or "").replace("\\", "/").split("?", 1)[0]
    name = re.sub(r"^file://", "", name)
    if name.startswith("/@fs/"):
        name = name[5:]
    return name


def _js_paths_match(reported: str, rel_file: str) -> bool:
    name = _js_reported_path(reported)
    rel = str(rel_file or "").replace("\\", "/").lstrip("./")
    if not rel:
        return False
    return name == rel or name.endswith("/" + rel)


_JS_CONFIG_SUFFIXES = {".ts", ".js", ".mjs", ".cjs", ".mts", ".cts"}
_DEFAULT_VITEST_CONFIGS = {
    "vitest.config.ts", "vitest.config.mts", "vitest.config.cts",
    "vitest.config.js", "vitest.config.mjs", "vitest.config.cjs",
}
_DEFAULT_JEST_CONFIGS = {
    "jest.config.js", "jest.config.ts", "jest.config.cjs", "jest.config.mjs",
    "jest.config.cts", "jest.config.mts",
}
_DEFAULT_MOCHA_CONFIGS = {
    ".mocharc.js", ".mocharc.cjs", ".mocharc.json", ".mocharc.yml", ".mocharc.yaml", ".mocharc.jsonc",
}
_MOCHA_CONFIG_SUFFIXES = _JS_CONFIG_SUFFIXES | {".yml", ".yaml", ".json", ".jsonc"}


def _js_config_prefix(framework: str) -> str:
    if framework == "vitest":
        return "vitest.config"
    if framework == "jest":
        return "jest.config"
    return ".mocharc"


def _js_config_suffixes(framework: str) -> set[str]:
    return _MOCHA_CONFIG_SUFFIXES if framework == "mocha" else _JS_CONFIG_SUFFIXES


def _js_default_configs(framework: str) -> set[str]:
    if framework == "vitest":
        return _DEFAULT_VITEST_CONFIGS
    if framework == "jest":
        return _DEFAULT_JEST_CONFIGS
    return _DEFAULT_MOCHA_CONFIGS
_DIST_REF = re.compile(r"(packages/[A-Za-z0-9_.@-]+/dist/[A-Za-z0-9_./+-]+)")
_ENV_PREFIX = re.compile(r"^([A-Z][A-Z0-9_]{0,40})=([A-Za-z0-9_.:/-]{1,80})(?:\s|$)")


def _expand_braces(pattern: str, depth: int = 0) -> list[str]:
    """``*.{spec,test}.ts`` becomes the two concrete globs. One level of braces."""
    if depth > 8 or "{" not in pattern:
        return [pattern]
    match = re.search(r"\{([^{}]*)\}", pattern)
    if not match:
        return [pattern]
    out: list[str] = []
    for part in match.group(1).split(","):
        expanded = pattern[:match.start()] + part + pattern[match.end():]
        out.extend(_expand_braces(expanded, depth + 1))
    return out or [pattern]


def _glob_match(pattern: str, rel: str) -> bool:
    """Glob match for vitest ``include`` / ``exclude`` (``**``, ``*``, ``[abc]``, ``{a,b}``)."""
    if "{" in str(pattern or ""):
        return any(_glob_match_one(item, rel) for item in _expand_braces(pattern))
    return _glob_match_one(pattern, rel)


def _glob_match_one(pattern: str, rel: str) -> bool:
    pat = str(pattern or "").strip().replace("\\", "/")
    if pat.startswith("./"):
        pat = pat[2:]
    rel = str(rel or "").replace("\\", "/").lstrip("./")
    if not pat or not rel:
        return False
    out: list[str] = []
    i = 0
    while i < len(pat):
        c = pat[i]
        if c == "*" and i + 1 < len(pat) and pat[i + 1] == "*":
            out.append(".*")
            i += 2
            if i < len(pat) and pat[i] == "/":
                i += 1
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j = pat.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
                i += 1
            else:
                out.append(pat[i:j + 1])
                i = j + 1
        else:
            out.append(re.escape(c))
            i += 1
    try:
        return re.fullmatch("".join(out), rel) is not None
    except re.error:
        return False


def _config_globs(text: str, key: str) -> list[str]:
    """Every ``include`` / ``exclude`` string in a config, including later projects.

    A workspace config often excludes a file from one project and includes it
    in another. The first array is not the only one that matters.
    """
    found: list[str] = []
    for m in re.finditer(rf"(?m)\b{key}\s*:\s*\[([^\[\]]{{0,8000}})\]", text or ""):
        found.extend(re.findall(r"""['"]([^'"]+)['"]""", m.group(1)))
    if found:
        return found
    m = re.search(rf"""(?m)\b{key}\s*:\s*['"]([^'"]+)['"]""", text or "")
    return [m.group(1)] if m else []


def _alias_keys(text: str) -> set[str]:
    return set(re.findall(r"""['"](~[^'"]+|@[A-Za-z0-9_./-]+|#[A-Za-z0-9_./-]+)['"]\s*:""", text or ""))


def _import_specs(text: str) -> set[str]:
    specs: set[str] = set()
    for m in re.finditer(r"""(?:from|import|require\()\s*['"]([^'"]+)['"]""", text or ""):
        spec = m.group(1)
        if spec.startswith(("~", "@", "#")):
            specs.add(spec)
            specs.add(spec.split("/")[0])
            if spec.startswith("@") and "/" in spec:
                specs.add("/".join(spec.split("/")[:2]))
    return specs


def select_js_launch(wt: Path, pkg_root: str, rel_file: str, *, framework: str = "vitest") -> tuple[str, str | None, str]:
    """``(cwd relative to the repo, config file name or None, file arg relative to cwd)``.

    A config is used only when its ``include`` matches this file and it does not
    ``exclude`` it, or it defines an alias this file imports. Otherwise the
    package directory stays the working directory, so a checkout with no
    matching config behaves as before.
    """
    pkg = (pkg_root or ".").strip().strip("/") or "."
    file_abs = ((wt / pkg / rel_file) if pkg != "." else (wt / rel_file)).resolve()
    if not file_abs.is_file():
        alt = (wt / rel_file).resolve()
        if alt.is_file():
            file_abs = alt
    top = wt.resolve()
    try:
        file_abs.relative_to(top)
    except ValueError:
        return pkg, None, rel_file
    try:
        src = file_abs.read_text(encoding="utf-8", errors="replace")[:100_000] if file_abs.is_file() else ""
    except OSError:
        src = ""
    imports = _import_specs(src)
    prefix = _js_config_prefix(framework)
    suffixes = _js_config_suffixes(framework)
    dirs: list[Path] = []
    d = file_abs.parent if file_abs.is_file() else (wt / pkg if pkg != "." else wt)
    while True:
        dirs.append(d)
        if d.resolve() == top or top not in d.resolve().parents:
            break
        d = d.parent
    configs: list[Path] = []
    seen: set[Path] = set()
    for directory in dirs:
        if not directory.is_dir():
            continue
        try:
            names = sorted(directory.iterdir())
        except OSError:
            continue
        for p in names:
            if not p.is_file() or not p.name.startswith(prefix) or p.suffix not in suffixes:
                continue
            if p.resolve() in seen:
                continue
            seen.add(p.resolve())
            configs.append(p)
    best: tuple[tuple[int, int], Path] | None = None
    for cfg in configs:
        try:
            text = cfg.read_text(encoding="utf-8", errors="replace")[:200_000]
        except OSError:
            continue
        cfg_dir = cfg.parent.resolve()
        try:
            rel_from_cfg = file_abs.relative_to(cfg_dir).as_posix()
        except ValueError:
            continue
        excludes = _config_globs(text, "exclude")
        includes = _config_globs(text, "include")
        included = any(_glob_match(g, rel_from_cfg) for g in includes) if includes else False
        excluded = any(_glob_match(g, rel_from_cfg) for g in excludes) if excludes else False
        # One project can exclude a file that another project in the same
        # file includes. An explicit include keeps the config.
        if excluded and not included:
            continue
        aliases = _alias_keys(text)
        alias_hit = False
        for spec in imports:
            head = spec.split("/")[0]
            if spec.startswith("@") and "/" in spec:
                head = "/".join(spec.split("/")[:2])
            if spec in aliases or head in aliases:
                alias_hit = True
                break
        if framework == "mocha":
            # Mocha's rc sets require and timeout. It does not use a vitest include
            # list; the file argument is the test. An exclude that matches already
            # skipped this rc above.
            score = 1
        else:
            if not included and not alias_hit:
                continue
            score = (2 if alias_hit else 0) + (1 if included else 0)
        try:
            depth = len(cfg_dir.relative_to(top).parts)
        except ValueError:
            depth = 0
        key = (score, depth)
        if best is None or key > best[0]:
            best = (key, cfg)
    if best is None and framework == "jest" and file_abs.suffix in {".ts", ".tsx", ".mts", ".cts"}:
        # A root ``jest.config.js`` with ``preset: 'ts-jest'`` does not use
        # vitest ``include`` or an alias this file imports. Launching in the
        # package directory then parses the TypeScript file as JavaScript.
        # Use the nearest config that names ts-jest and does not exclude the file.
        for cfg in configs:
            try:
                text = cfg.read_text(encoding="utf-8", errors="replace")[:200_000]
            except OSError:
                continue
            if "ts-jest" not in text:
                continue
            cfg_dir = cfg.parent.resolve()
            try:
                rel_from_cfg = file_abs.relative_to(cfg_dir).as_posix()
            except ValueError:
                continue
            excludes = _config_globs(text, "exclude")
            includes = _config_globs(text, "include")
            included = any(_glob_match(g, rel_from_cfg) for g in includes) if includes else False
            excluded = any(_glob_match(g, rel_from_cfg) for g in excludes) if excludes else False
            if excluded and not included:
                continue
            best = ((0, 0), cfg)
            break
    if best is None:
        return pkg, None, rel_file
    cfg = best[1]
    cfg_dir = cfg.parent.resolve()
    cwd_rel = "." if cfg_dir == top else cfg_dir.relative_to(top).as_posix()
    file_arg = file_abs.relative_to(cfg_dir).as_posix()
    defaults = _js_default_configs(framework)
    # Vitest auto-loads ``vitest.config.mts`` when ``--config`` is omitted.
    # A sibling ``vitest.config.unit.mts`` that actually includes this file
    # has to be named, or the browser config starts and closes before the spec.
    siblings = 0
    try:
        siblings = sum(
            1 for p in cfg_dir.iterdir()
            if p.is_file() and p.name.startswith(prefix) and p.suffix in suffixes
        )
    except OSError:
        siblings = 1
    config_arg = None if cfg.name in defaults and siblings <= 1 else cfg.name
    return cwd_rel, config_arg, file_arg


def _js_failure_detail(*blobs: str) -> str:
    """The first real module or Error line, not a ``get_format`` stack frame.

    A missing ``packages/<name>/dist/`` file is named as a build step.
    """
    text = "\n".join(b or "" for b in blobs)
    if not text.strip():
        return ""
    dist = _DIST_REF.search(text)
    if dist and re.search(r"Cannot find module|ENOENT|MODULE_NOT_FOUND|not found", text, re.I):
        path = dist.group(1).rstrip(".,);\"'")
        return f"missing_build_output:{path}"[:160]
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("at ") or "get_format" in s:
            continue
        if "Cannot find module" in s or s.startswith("Error:") or s.startswith("Error [") or "MODULE_NOT_FOUND" in s:
            return _scrub_reason(s, max_len=160)
    if "get_format" in text:
        return "transform_error: module format could not be resolved"
    return ""


def referenced_missing_dist(wt: Path, texts: list[str]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for text in texts:
        for m in _DIST_REF.finditer(text or ""):
            rel = m.group(1).rstrip(".,);\"'")
            if rel in seen:
                continue
            seen.add(rel)
            if not (wt / rel).is_file():
                found.append(rel)
    return found


def browsers_requested(wt: Path, pkg_root: str, rel_file: str, *, framework: str = "vitest") -> list[str]:
    """Chromium, plus firefox or webkit when the selected config names that instance."""
    names = ["chromium"]
    cwd_rel, config_arg, _file = select_js_launch(wt, pkg_root, rel_file, framework=framework)
    cfg_dir = wt if cwd_rel == "." else wt / cwd_rel
    texts: list[str] = []
    candidates = []
    if config_arg:
        candidates.append(cfg_dir / config_arg)
    prefix = _js_config_prefix(framework)
    if cfg_dir.is_dir():
        try:
            for path in sorted(cfg_dir.iterdir()):
                if path.is_file() and (
                    path.name.startswith(prefix) or path.name in {"settings.ts", "settings.js"}
                ):
                    candidates.append(path)
        except OSError:
            pass
    seen: set[Path] = set()
    for path in candidates:
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        try:
            texts.append(path.read_text(encoding="utf-8", errors="replace")[:80_000])
        except OSError:
            continue
    blob = "\n".join(texts)
    for name in ("firefox", "webkit"):
        if re.search(rf"""browser\s*:\s*['"]{name}['"]""", blob) and name not in names:
            names.append(name)
    return names


def browser_provider_env(wt: Path, file_rel: str) -> dict[str, str]:
    """``PROVIDER=playwright`` when a root script sets it and this file is a browser test."""
    rel = str(file_rel or "").replace("\\", "/")
    if "browser" not in rel:
        return {}
    try:
        data = json.loads((wt / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
    for key in ("test:playwright", "test:browser"):
        body = scripts.get(key)
        if not isinstance(body, str):
            continue
        m = _ENV_PREFIX.match(body.strip())
        if m:
            return {m.group(1): m.group(2)}
    return {}


def classify_js_json(
    report: dict | None, rel_file: str, names: list[str], *, sole_file: bool = False,
) -> tuple[str, str, str]:
    if not isinstance(report, dict):
        return "error", "build_error", "no_json_report"
    results = report.get("testResults") or []
    file_res = None
    for r in results:
        name = str(r.get("name") or r.get("testFilePath") or r.get("filepath") or "")
        if _js_paths_match(name, rel_file):
            file_res = r
            break
    if file_res is None and sole_file and len(results) == 1 and isinstance(results[0], dict):
        # The invocation named one file. Vitest's filepath can differ by a project root prefix.
        file_res = results[0]
    if file_res is None:
        return "error", "build_error", "file_not_in_report"
    asserts = file_res.get("assertionResults") or []
    if not asserts and (file_res.get("status") == "failed" or file_res.get("message")):
        return "error", "build_error", _scrub_reason(str(file_res.get("message") or "suite_failed_to_load"), max_len=160)
    for a in asserts:
        path = list(a.get("ancestorTitles") or []) + [str(a.get("title") or "")]
        if path == names:
            st = str(a.get("status") or "")
            if st == "failed":
                return "red", "fail", "fail"
            if st == "passed":
                return "green", "pass", "pass"
            return "error", "skipped", f"test_{st or 'unknown'}"
    if file_res.get("status") == "failed" and file_res.get("message"):
        return "error", "build_error", _scrub_reason(str(file_res.get("message")), max_len=160)
    return "error", "not_found", "test_not_in_file"


def _mocha_title_matches(item: dict, names: list[str]) -> bool:
    full = str(item.get("fullTitle") or "").strip()
    title = str(item.get("title") or "").strip()
    pat = js_name_pattern(names)
    if full and re.fullmatch(pat, full):
        return True
    path = item.get("titlePath")
    if isinstance(path, list) and path:
        joined = [str(part) for part in path if str(part).strip()]
        if joined and (
            re.fullmatch(pat, " ".join(joined)) or re.fullmatch(pat, JS_SEP.join(joined))
        ):
            return True
    if len(names) == 1 and title and re.fullmatch(pat, title):
        return True
    return False


def _mocha_file_ok(item: dict, rel_file: str, pool: list[dict], *, sole_file: bool) -> bool:
    reported = str(item.get("file") or "")
    if reported and _js_paths_match(reported, rel_file):
        return True
    if not sole_file:
        return False
    files = {str(other.get("file") or "") for other in pool}
    files.discard("")
    if not reported:
        return len(files) <= 1
    return len(files) <= 1


def classify_mocha_json(
    report: dict | None, rel_file: str, names: list[str], *, sole_file: bool = False,
) -> tuple[str, str, str]:
    """One Mocha JSON report. Pending is not a pass. A hook-only report is a build error."""
    if not isinstance(report, dict) or not isinstance(report.get("stats"), dict) or "failures" not in report:
        return "error", "build_error", "no_json_report"
    failures = [x for x in (report.get("failures") or []) if isinstance(x, dict)]
    passes = [x for x in (report.get("passes") or []) if isinstance(x, dict)]
    pending = [x for x in (report.get("pending") or []) if isinstance(x, dict)]
    tests = [x for x in (report.get("tests") or []) if isinstance(x, dict)]
    pool = failures + passes + pending + tests
    for bucket, label, kind, detail in (
        (failures, "red", "fail", "fail"),
        (passes, "green", "pass", "pass"),
        (pending, "error", "skipped", "test_pending"),
    ):
        for item in bucket:
            if _mocha_file_ok(item, rel_file, pool, sole_file=sole_file) and _mocha_title_matches(item, names):
                return label, kind, detail
    if not pool:
        return "error", "build_error", "no_json_report"
    if passes or pending or tests:
        return "error", "not_found", "test_not_in_file"
    return "error", "build_error", "suite_failed_to_load"


_JS_OBSOLETE_SNAP = re.compile(r"snapshots?\s+obsolete|obsolete\s+snapshots?", re.I)
_JS_COVERAGE = re.compile(r"coverage threshold|does not meet global threshold|not meet (the )?threshold", re.I)
_JS_OPEN_HANDLES = re.compile(
    r"open handles?|failed to exit gracefully|force exited|did not exit one second|Force exiting Jest",
    re.I,
)


def _project_flag_rejected(res: EvalResult) -> bool:
    """The workspace ``--project`` / ``--selectProjects`` flag produced no tests."""
    detail = (res.detail or "").lower()
    if "no projects matched" in detail or "no project matched" in detail:
        return True
    return res.detail in ("file_not_in_report", "no_json_report")


def js_nonzero_exit_is_unrelated(report: dict | None, out: str, err: str) -> bool:
    """A passing target test, and the process exit is something else.

    Jest exits 1 when ``--ci`` sees obsolete snapshots from tests the name
    filter skipped, when a coverage threshold is missed, when a worker is
    force-exited for an open handle, or when a different test in the file
    failed. Those do not change the target assertion. An exit we cannot
    explain stays ambiguous: the caller keeps ``exit_N_with_target_passed``.
    """
    if not isinstance(report, dict):
        return False
    stats = report.get("stats") if isinstance(report.get("stats"), dict) else None
    if stats is not None and "failures" in stats:
        try:
            if int(stats.get("failures") or 0) > 0:
                return True
        except (TypeError, ValueError):
            pass
    text = f"{out or ''}\n{err or ''}"
    snap = report.get("snapshot") if isinstance(report.get("snapshot"), dict) else {}
    try:
        unchecked = int(snap.get("unchecked") or 0)
    except (TypeError, ValueError):
        unchecked = 0
    try:
        failed_tests = int(report.get("numFailedTests") or 0)
    except (TypeError, ValueError):
        failed_tests = 0
    # The caller already matched the target assertion as passed. A failed
    # count is some other test in this invocation.
    if failed_tests > 0:
        return True
    if unchecked > 0 or _JS_OBSOLETE_SNAP.search(text):
        return True
    if _JS_COVERAGE.search(text):
        return True
    if _JS_OPEN_HANDLES.search(text):
        return True
    if report.get("success") is True:
        return True
    return False


@dataclass
class JsGitRunner(_WorktreeRunner):
    """vitest / jest / mocha with a JSON report, per commit; lockfile-keyed install cache."""

    framework: str = "vitest"  # vitest | jest | mocha
    test_command: Sequence[str] | None = None  # argv prefix replacing the local binary
    install_command: Sequence[str] | None = None  # argv; default from the lockfile
    build_command: Sequence[str] | None = None  # argv; default: filtered workspace build
    db_reset_command: Sequence[str] | None = None
    test_workdir: str | None = None  # package dir holding the test files (monorepos)
    cache_dir: Path | None = None
    per_run_timeout_sec: float = 300.0
    install_timeout_sec: float = 600.0
    build_timeout_sec: float = 600.0
    max_installs: int = 6
    ignore_scripts: bool = True
    _faithful_install_retried: bool = False
    # ``non_frozen`` after a catalogs mismatch that kept lockfile package ids.
    # ``unlocked`` after ``npm install --no-package-lock`` for a repo whose
    # ``.npmrc`` and CI both say there is no lockfile. Empty means frozen.
    install_mode: str = ""
    node_bin: str = "node"
    _pkg_root: str | None = None
    _installs: int = 0
    kind_name = "js"

    def validate_ids(self, tests: Sequence[str]) -> tuple[list[str], str | None]:
        return validate_js_ids(tests)

    # --- env
    def _child_env_js(self, home: Path, wt: Path) -> dict[str, str]:
        env = build_scrubbed_env(extra=dict(self.env or {}), home=str(home))
        apply_isolated_home(env, home)
        _passthrough(env, _NODE_ENV_PASS)
        env["CI"] = "true"
        env["FORCE_COLOR"] = "0"
        env["NO_COLOR"] = "1"
        env.pop("NPM_CONFIG_USERCONFIG", None)
        cache = Path(self.cache_dir or default_cache_dir())
        env["COREPACK_ENABLE_DOWNLOAD_PROMPT"] = "0"
        env["COREPACK_HOME"] = str(cache / "corepack")
        # No turbo token in this job. Force a local build so a remote-only
        # setting cannot fail every commit (that would abstain, but a local
        # build is what proves the culprit).
        env = scrub_turbo_remote(env)
        # turbo runs ``pnpm``/``yarn`` from PATH. Pin those to corepack so a
        # global Yarn 1 or an older pnpm does not fail every commit.
        pm = _package_manager_field(wt)
        shim_dir = None
        if pm.startswith("pnpm@"):
            shim_dir = corepack_tool_shim_dir(cache, "pnpm")
        if is_yarn_berry(wt):
            env["YARN_CACHE_FOLDER"] = str(cache / "yarn-berry-cache")
            env["YARN_ENABLE_GLOBAL_CACHE"] = "0"
            env["YARN_NODE_LINKER"] = "node-modules"
            env["YARN_ENABLE_TELEMETRY"] = "0"
            shim_dir = yarn_corepack_shim_dir(cache)
        if shim_dir is not None:
            env["PATH"] = str(shim_dir) + os.pathsep + env.get("PATH", "")
        return env

    # --- package root
    def _resolve_pkg_root(self, wt: Path, rel_file: str) -> str | None:
        if self.test_workdir:
            d = self.test_workdir.strip().strip("/") or "."
            return None if ".." in d.split("/") else d
        if self._pkg_root is not None:
            return self._pkg_root
        try:
            r = subprocess.run(["git", "-C", str(wt), "ls-files"], capture_output=True, text=True,
                               timeout=60, env=build_scrubbed_env())
            files = r.stdout.splitlines()
        except (OSError, subprocess.TimeoutExpired):
            return None
        fs = set(files)
        roots = []
        if rel_file in fs:
            roots.append(".")
        suffix = "/" + rel_file
        for f in files:
            if f.endswith(suffix):
                root = f[: -len(suffix)]
                if f"{root}/package.json" in fs:
                    roots.append(root)
        roots = sorted(set(roots))
        if len(roots) == 1:
            self._pkg_root = roots[0]
            return roots[0]
        return None

    # --- install
    def _run_pm(self, cmd: list[str], cwd: Path, env: dict[str, str], deadline) -> tuple[int, str, str] | EvalResult:
        t = min(float(self.install_timeout_sec), remaining_budget(deadline))
        if t < 1:
            return EvalResult(label="error", detail="budget_exhausted", kind="timeout")
        try:
            rc, out, errt = run_capped(cmd, cwd=cwd, env=env, timeout=t)
        except subprocess.TimeoutExpired:
            return EvalResult(
                label="error", detail="install_timeout",
                kind="timeout" if remaining_budget(deadline) < 1 else "build_error",
            )
        except OSError as exc:
            return EvalResult(
                label="error", detail=f"install_tool_missing:{type(exc).__name__}", kind="tool_missing",
            )
        return rc, out or "", errt or ""

    def _install_failed(self, out: str, errt: str) -> EvalResult:
        return EvalResult(
            label="error",
            detail="install_failed: " + _scrub_reason((errt or out)[-300:], max_len=160),
            kind="build_error",
        )

    def _env_install(self, detail: str) -> EvalResult:
        self.install_mode = ""
        return EvalResult(label="error", detail=detail, kind="env_setup")

    def _write_install_marker(self, marker: Path, key: str) -> None:
        try:
            marker.parent.mkdir(parents=True, exist_ok=True)
            digest = _node_modules_content_hash(marker.parent)
            mode = self.install_mode if self.install_mode in ("non_frozen", "unlocked") else "frozen"
            marker.write_text(f"{key}\n{digest}\n{mode}\n")
        except OSError:
            pass

    def _recover_catalog_mismatch(
        self, wt: Path, idir: Path, lock: Path, cmd: list[str], env: dict[str, str],
        deadline, cache: Path,
    ) -> EvalResult | None:
        """Retry a catalogs mismatch with the pinned pnpm, then a recorded non-frozen install.

        ``None`` means the tree is installed. An ``EvalResult`` abstains or reports
        the install error. A non-frozen install that changes package ids is not used.
        """
        pinned = pinned_pnpm_tool(idir, cache)
        if pinned is None:
            return self._env_install(
                "install_unfaithful: pnpm catalogs mismatch and the pinned pnpm version could not be run"
            )
        pinned_cmd = _swap_pm_prefix(cmd, pinned)
        active = cmd
        if _pm_prefix(pinned_cmd) != _pm_prefix(cmd):
            remove_node_modules(wt)
            ran = self._run_pm(pinned_cmd, idir, env, deadline)
            if isinstance(ran, EvalResult):
                return ran
            rc, out, errt = ran
            if rc == 0:
                self.install_mode = ""
                return None
            if not catalog_lockfile_mismatch(out + "\n" + errt):
                return self._install_failed(out, errt)
            active = pinned_cmd
        original = lock.read_bytes()
        before = pnpm_lock_fingerprint(original.decode("utf-8", errors="replace"))
        remove_node_modules(wt)
        ran = self._run_pm(_non_frozen_cmd(active), idir, env, deadline)
        try:
            if isinstance(ran, EvalResult):
                return ran
            rc, out, errt = ran
            if rc != 0:
                return self._env_install(
                    "install_unfaithful: pnpm catalogs mismatch; pinned frozen install failed "
                    "and the non-frozen install failed too"
                )
            try:
                after = pnpm_lock_fingerprint(lock.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                after = ()
            if before != after:
                remove_node_modules(wt)
                return self._env_install(
                    "install_unfaithful: pnpm catalogs mismatch; non-frozen install changed "
                    "lockfile package versions, so it was not used"
                )
            self.install_mode = "non_frozen"
            return None
        finally:
            try:
                lock.write_bytes(original)
            except OSError:
                pass

    def _recover_npm_eresolve(
        self, wt: Path, idir: Path, cmd: list[str], env: dict[str, str], deadline,
    ) -> EvalResult | None:
        """Retry ``npm ci`` with ``--legacy-peer-deps`` only when this commit's CI or ``.npmrc`` uses it."""
        if not commit_allows_legacy_peer_deps(idir, wt):
            return self._env_install(
                "peer_deps_blocked: npm ci failed ERESOLVE and this commit's CI workflow "
                "and .npmrc do not use legacy-peer-deps"
            )
        if "--legacy-peer-deps" in cmd:
            return self._install_failed("ERESOLVE", "")
        remove_node_modules(wt)
        ran = self._run_pm(cmd + ["--legacy-peer-deps"], idir, env, deadline)
        if isinstance(ran, EvalResult):
            return ran
        rc, out, errt = ran
        if rc != 0:
            return self._install_failed(out, errt)
        return None

    def _install(self, wt: Path, env: dict[str, str], deadline, pkg_root: str = ".") -> EvalResult | None:
        self.install_mode = ""
        # 5.2.0: nearest lockfile from the package root up to the repo root (a JS package
        # in a subdirectory, or a workspace root lockfile); install runs in that directory.
        lock = None
        mgr = None
        top = wt.resolve()
        d = (wt / (pkg_root or ".")).resolve()
        if top != d and top not in d.parents:
            d = top
        while True:
            for name, m in _LOCKFILES:
                if (d / name).is_file():
                    lock, mgr = d / name, m
                    break
            if lock is not None or d == top:
                break
            d = d.parent
        idir = lock.parent if lock is not None else top
        # A previous test may have edited this tree. git clean will not.
        # Content that does not match the marker is removed before the lockfile hit.
        _discard_mutated_node_modules(wt)
        # packageManager is part of the key so a commit that only bumps pnpm/yarn
        # reinstalls with that commit's corepack version.
        pm_field = _package_manager_field(idir).encode()
        scripts_flag = b"scripts" if not self.ignore_scripts else b"noscripts"
        unlocked_policy = ""
        if self.install_command:
            key_src = b"custom:" + " ".join(self.install_command).encode() + b"\0" + pm_field + b"\0"
            key_src += lock.read_bytes() if lock else b""
        elif lock is None:
            # A lockfile still wins. This path is only a repo that commits none,
            # says so in .npmrc, and whose CI runs npm install rather than npm ci.
            unlocked_policy = npm_unlocked_policy(idir, top)
            if not unlocked_policy:
                if (wt / "node_modules").is_dir() or (idir / "node_modules").is_dir():
                    return None
                return EvalResult(label="error", detail="no_lockfile_for_install", kind="build_error")
            try:
                pkg_bytes = (idir / "package.json").read_bytes()
            except OSError:
                pkg_bytes = b""
            try:
                npmrc_bytes = (idir / ".npmrc").read_bytes()
            except OSError:
                npmrc_bytes = b""
            key_src = (
                b"npm-unlocked\0" + unlocked_policy.encode() + b"\0" + scripts_flag
                + b"\0" + pkg_bytes + b"\0" + npmrc_bytes
            )
        else:
            key_src = (mgr or "npm").encode() + b"\0" + pm_field + b"\0" + scripts_flag + b"\0" + lock.read_bytes()
        key = hashlib.sha256(key_src).hexdigest()
        marker = idir / "node_modules" / ".sentinel-lock-sha256"
        try:
            if marker.is_file():
                lines = marker.read_text().splitlines()
                if lines[:1] == [key]:
                    saved = lines[1].strip() if len(lines) > 1 else ""
                    if _is_content_hash(saved):
                        mode = lines[2].strip() if len(lines) > 2 else ""
                        self.install_mode = mode if mode in ("non_frozen", "unlocked") else ""
                        return None
                    # Old marker stored a file count and an mtime. Do not wipe on
                    # that; record a content hash so the next edit can be seen.
                    digest = _node_modules_content_hash(marker.parent)
                    marker.write_text(f"{key}\n{digest}\nfrozen\n")
                    return None
        except OSError:
            pass
        if self._installs >= self.max_installs:
            return EvalResult(label="error", detail="install_cap_reached", kind="install_budget")
        self._installs += 1
        cache = Path(self.cache_dir or default_cache_dir())
        cache.mkdir(parents=True, exist_ok=True)
        if self.install_command:
            cmd = list(self.install_command)
        elif unlocked_policy:
            cmd, extra = js_unlocked_npm_install_command(
                cache,
                ignore_scripts=bool(self.ignore_scripts),
                legacy_peer_deps=unlocked_policy == "npm_install_legacy",
            )
            env = {**env, **extra}
        else:
            cmd, extra = js_install_command(idir, mgr or "npm", cache, ignore_scripts=bool(self.ignore_scripts))
            env = {**env, **extra}
        # fresh node_modules for a new lockfile (stale deps must not leak across commits)
        remove_node_modules(wt)
        ran = self._run_pm(cmd, idir, env, deadline)
        if unlocked_policy:
            _drop_generated_npm_lock(idir)
        if isinstance(ran, EvalResult):
            return ran
        rc, out, errt = ran
        if rc != 0 and not self.install_command and lock is not None:
            blob = out + "\n" + errt
            if mgr == "pnpm" and catalog_lockfile_mismatch(blob):
                recovered = self._recover_catalog_mismatch(wt, idir, lock, cmd, env, deadline, cache)
                if recovered is not None:
                    return recovered
                self._write_install_marker(marker, key)
                return None
            if (mgr or "npm") == "npm" and npm_eresolve(blob):
                recovered = self._recover_npm_eresolve(wt, idir, cmd, env, deadline)
                if recovered is not None:
                    return recovered
                self._write_install_marker(marker, key)
                return None
        if rc != 0:
            return self._install_failed(out, errt)
        if unlocked_policy:
            self.install_mode = "unlocked"
        self._write_install_marker(marker, key)
        return None

    def _bin(self, wt: Path, pkg_root: str) -> list[str] | None:
        if self.test_command:
            return list(self.test_command)
        name = self.framework if self.framework in JS_FRAMEWORKS else "vitest"
        d = (wt / pkg_root).resolve()
        top = wt.resolve()
        while True:
            cand = d / "node_modules" / ".bin" / name
            if cand.exists():
                return [str(cand)]
            if d == top or top not in d.parents:
                break
            d = d.parent
        return None

    def _group_tests(self, wt: Path, parsed: list) -> tuple[dict[str, list[tuple[str, list[str]]]], EvalResult | None]:
        """Package directory -> [(file relative to that package, test name parts)]."""
        packages = [] if self.test_workdir else discover_workspaces(wt)
        groups: dict[str, list[tuple[str, list[str]]]] = {}
        for file, names in parsed:
            if not file:
                continue
            if self.test_workdir:
                d = self.test_workdir.strip().strip("/") or "."
                if ".." in d.split("/"):
                    return {}, EvalResult(label="error", detail="bad_test_workdir", kind="unknown")
                if not (wt / d / file).is_file():
                    return {}, EvalResult(label="error", detail=f"test_file_missing:{file[:60]}", kind="not_found")
                groups.setdefault(d, []).append((file, names))
                continue
            loc = locate_test_file(wt, file, packages)
            if loc == "ambiguous":
                return {}, EvalResult(
                    label="error",
                    detail="test_file_root_ambiguous_or_missing (set test_workdir)",
                    kind="ambiguous_test_file",
                )
            if loc == "missing":
                return {}, EvalResult(label="error", detail=f"test_file_missing:{file[:60]}", kind="not_found")
            if loc is None:
                root = self._resolve_pkg_root(wt, file)
                if root is None:
                    return {}, EvalResult(
                        label="error",
                        detail="test_file_root_ambiguous_or_missing (set test_workdir)",
                        kind="ambiguous_test_file",
                    )
                if not (wt / root / file).is_file():
                    return {}, EvalResult(label="error", detail=f"test_file_missing:{file[:60]}", kind="not_found")
                groups.setdefault(root, []).append((file, names))
            else:
                groups.setdefault(loc[0], []).append((loc[1], names))
        if not groups:
            return {}, EvalResult(label="error", detail="no_failing_tests_provided", kind="unknown")
        return groups, None

    def _build(self, wt: Path, env: dict[str, str], deadline, pkg_root: str,
               sha: str | None = None) -> EvalResult | None:
        """Build workspace dependencies of ``pkg_root``. ``None`` means nothing to build.

        Single-package checkouts (no workspace config) return ``None`` without
        running a build. A non-zero build is ``build_error``, never a test failure.
        A build that already succeeded for this same commit is restored from
        the cache instead of running again.
        """
        if self.build_command:
            steps = [(list(self.build_command), wt)]
        else:
            # Manager and tool argv follow the lockfile directory (the workspace root).
            mgr = "npm"
            tool_dir = wt
            top = wt.resolve()
            d = (wt / (pkg_root or ".")).resolve()
            if top != d and top not in d.parents:
                d = top
            lock_mgr = None
            while True:
                for _name, m in _LOCKFILES:
                    if (d / _name).is_file():
                        lock_mgr = m
                        break
                if lock_mgr is not None or d == top:
                    break
                d = d.parent
            if lock_mgr:
                mgr = lock_mgr
                tool_dir = d
            if mgr == "npm":
                pm_argv = ["npm"]
            else:
                pm_argv = js_pm_argv(
                    tool_dir, mgr, cache=Path(self.cache_dir or default_cache_dir()),
                )
            plan = plan_workspace_build(
                wt, pkg_root or ".", pm_argv=pm_argv, manager=mgr, turbo_bin=find_turbo_bin(wt),
            )
            if plan is None or (not plan.steps and not plan.error):
                return None
            if plan.error:
                return EvalResult(label="error", detail=plan.error, kind="build_error")
            steps = [(list(step.argv), wt / step.cwd_rel) for step in plan.steps]
        cached = None
        if sha and re.fullmatch(r"[0-9a-fA-F]{7,40}", sha):
            cached = Path(self.cache_dir or default_cache_dir()) / "js-build" / sha.lower()
            if restore_build_cache(cached, wt):
                return None
        env = scrub_turbo_remote(env)
        for cmd, cwd in steps:
            t = min(float(self.build_timeout_sec), remaining_budget(deadline))
            if t < 1:
                return EvalResult(label="error", detail="budget_exhausted", kind="timeout")
            try:
                rc, out, errt = run_capped(cmd, cwd=cwd, env=env, timeout=t)
            except subprocess.TimeoutExpired:
                return EvalResult(label="error", detail="build_timeout", kind="timeout"
                                  if remaining_budget(deadline) < 1 else "build_error")
            except OSError as e:
                return EvalResult(label="error", detail=f"build_tool_missing:{type(e).__name__}", kind="tool_missing")
            if rc != 0:
                return EvalResult(
                    label="error",
                    detail="build_failed: " + _scrub_reason((errt or out)[-300:], max_len=160),
                    kind="build_error",
                )
        if cached is not None:
            save_build_cache(wt, cached)
        return None

    def evaluate(self, sha: str, tests: Sequence[str], *, reruns: int, deadline: float | None = None) -> EvalResult:
        self.install_mode = ""
        clean, err = validate_js_ids(tests)
        if err:
            return EvalResult(label="error", detail=err, kind="unknown")
        wt, early = self._prepare(sha, deadline)
        if early is not None:
            return early
        assert wt is not None
        # A customer's turbo.json can omit an input. Keeping ``.turbo`` would
        # replay the previous commit's outputs and could prove the wrong SHA.
        wipe_turbo_read_cache(wt)
        parsed = [p for p in (split_js_id(t) for t in clean) if p]
        groups, bad_loc = self._group_tests(wt, parsed)
        if bad_loc is not None:
            return bad_loc
        home = make_isolated_home()
        try:
            env = self._child_env_js(home, wt)
            ensure_declared_services(wt, env)
            env["PLAYWRIGHT_BROWSERS_PATH"] = str(
                Path(self.cache_dir or default_cache_dir()) / "ms-playwright"
            )
            db_err = apply_db_reset(
                self.db_reset_command, cwd=wt, env=env, deadline=deadline, sha=sha,
                cache=Path(self.cache_dir or default_cache_dir()),
            )
            if db_err:
                kind = "timeout" if "budget" in db_err or db_err == "db_reset_timeout" else "env_setup"
                return EvalResult(label="error", detail=db_err, kind=kind)
            first_pkg = next(iter(groups))
            bad = self._install(wt, env, deadline, first_pkg)
            if bad is not None:
                return bad
            requested = ["chromium"]
            for pkg_root, files in groups.items():
                for file_rel, _names in files:
                    for name in browsers_requested(wt, pkg_root, file_rel, framework=self.framework):
                        if name not in requested:
                            requested.append(name)
            ensure_playwright_browsers(
                wt, Path(self.cache_dir or default_cache_dir()), env, deadline,
                browsers=requested,
            )
            for pkg_root in groups:
                built = self._build(wt, env, deadline, pkg_root, sha=sha)
                if built is not None:
                    return built
            for pkg_root, files in groups.items():
                seen_files = []
                for file_rel, _names in files:
                    if file_rel not in seen_files:
                        seen_files.append(file_rel)
                for file_rel in seen_files:
                    missing = self._ensure_referenced_dist(wt, env, deadline, pkg_root, file_rel)
                    if missing is not None:
                        return missing
            bins: dict[str, list[str]] = {}
            for pkg_root in groups:
                binv = self._bin(wt, pkg_root)
                if not binv:
                    return EvalResult(label="error", detail=f"{self.framework}_binary_not_found", kind="build_error")
                bins[pkg_root] = binv
            runs: list[EvalResult] = []
            for _ in range(max(1, reruns)):
                if remaining_budget(deadline) < 0.05:
                    runs.append(EvalResult(label="error", detail="budget_exhausted", kind="timeout"))
                    break
                per = []
                for pkg_root, files in groups.items():
                    # One invocation per file. Names for the same file are combined.
                    by_file: dict[str, list[list[str]]] = {}
                    for file_rel, names in files:
                        by_file.setdefault(file_rel, []).append(names)
                    for file_rel in sorted(by_file):
                        per.append(self._run_file(
                            wt, pkg_root, file_rel, by_file[file_rel], bins[pkg_root], env, deadline))
                runs.append(_combine_groups(per))
                if runs[-1].kind in ("timeout", "build_error"):
                    break
            result = self._aggregate(runs)
            if (
                self.ignore_scripts
                and not self._faithful_install_retried
                and result.kind == "build_error"
                and js_missing_module(result.detail or "")
                and remaining_budget(deadline) > 5
            ):
                # Frozen install skipped lifecycle scripts, and a package file
                # is missing. CI runs those scripts. One reinstall, then the
                # same abstain if the module is still gone.
                self._faithful_install_retried = True
                saved_ignore = self.ignore_scripts
                self.ignore_scripts = False
                try:
                    retried = self._install(wt, env, deadline, first_pkg)
                finally:
                    self.ignore_scripts = saved_ignore
                if retried is not None:
                    return retried
                ensure_playwright_browsers(
                    wt, Path(self.cache_dir or default_cache_dir()), env, deadline,
                    browsers=requested,
                )
                per = []
                for pkg_root, files in groups.items():
                    by_file: dict[str, list[list[str]]] = {}
                    for file_rel, names in files:
                        by_file.setdefault(file_rel, []).append(names)
                    for file_rel in sorted(by_file):
                        per.append(self._run_file(
                            wt, pkg_root, file_rel, by_file[file_rel], bins[pkg_root], env, deadline))
                return self._aggregate([_combine_groups(per)])
            return result
        finally:
            # The next commit reuses this worktree. Drop a tree the test edited
            # before that commit's install decides the lockfile is unchanged.
            _discard_mutated_node_modules(wt)
            shutil.rmtree(home, ignore_errors=True)

    def _ensure_referenced_dist(self, wt: Path, env: dict, deadline, pkg_root: str, rel_file: str) -> EvalResult | None:
        """Build a package whose ``dist/`` a test or its vitest config names, when that file is absent."""
        cwd_rel, config_name, _file_arg = select_js_launch(
            wt, pkg_root, rel_file, framework=self.framework,
        )
        texts: list[str] = []
        candidates = [wt / rel_file]
        if pkg_root not in ("", "."):
            candidates.insert(0, wt / pkg_root / rel_file)
        for candidate in candidates:
            try:
                if candidate.is_file():
                    texts.append(candidate.read_text(encoding="utf-8", errors="replace")[:80_000])
                    break
            except OSError:
                continue
        cfg_dir = wt if cwd_rel == "." else wt / cwd_rel
        if self.framework == "mocha":
            cfg_names = [config_name] if config_name else [
                ".mocharc.js", ".mocharc.cjs", ".mocharc.json", ".mocharc.yml",
            ]
        else:
            cfg_names = [config_name] if config_name else [
                "vitest.config.ts", "vitest.config.js", "vitest.config.mjs",
                "jest.config.ts", "jest.config.js",
            ]
        for name in cfg_names:
            if not name:
                continue
            path = cfg_dir / name
            if not path.is_file():
                continue
            try:
                texts.append(path.read_text(encoding="utf-8", errors="replace")[:80_000])
            except OSError:
                pass
            if config_name:
                break
        missing = referenced_missing_dist(wt, texts)
        if not missing:
            return None
        pkgs: list[str] = []
        for rel in missing:
            parts = rel.split("/")
            if len(parts) >= 3 and parts[0] == "packages":
                pkgs.append(f"packages/{parts[1]}")
        for prel in dict.fromkeys(pkgs):
            if all((wt / m).is_file() for m in missing if m.startswith(prel + "/")):
                continue
            self._build(wt, env, deadline, prel)
            still = [m for m in missing if m.startswith(prel + "/") and not (wt / m).is_file()]
            if still:
                return EvalResult(label="error", kind="build_error", detail=f"missing_build_output:{still[0]}")
        still = [m for m in missing if not (wt / m).is_file()]
        if still:
            return EvalResult(label="error", kind="build_error", detail=f"missing_build_output:{still[0]}")
        return None

    def _run_file(self, wt: Path, pkg_root: str, rel_file: str, name_lists: list[list[str]],
                  binv: list[str], env: dict, deadline) -> EvalResult:
        t = min(float(self.per_run_timeout_sec), remaining_budget(deadline))
        if t < 0.05:
            return EvalResult(label="error", detail="budget_exhausted", kind="timeout")
        cwd_rel, config_arg, file_arg = select_js_launch(
            wt, pkg_root, rel_file, framework=self.framework,
        )
        cwd = wt if cwd_rel == "." else wt / cwd_rel
        run_env = dict(env)
        repo_rel = rel_file if pkg_root in ("", ".") else f"{pkg_root}/{rel_file}"
        for key, value in browser_provider_env(wt, repo_rel).items():
            run_env.setdefault(key, value)
        pattern = "|".join("(?:" + js_name_pattern(n) + ")" for n in name_lists) if len(name_lists) > 1 \
            else js_name_pattern(name_lists[0])
        sole = len(name_lists) == 1
        project_args = workspace_project_args(wt, pkg_root, self.framework)

        def once(use_pattern: bool, *, use_project: bool = True) -> EvalResult:
            # The report has to live in the worktree. run_capped gives the test
            # a private /tmp, so a file created under the host /tmp would be invisible.
            out_dir = cwd / ".sentinel-js-report"
            if out_dir.exists():
                shutil.rmtree(out_dir, ignore_errors=True)
            out_dir.mkdir(parents=True, exist_ok=True)
            out_json = out_dir / "report.json"
            def mocha_cmd(use_output: bool, *, color: bool = True) -> list[str]:
                # Mocha 4 rejects ``--no-color`` (``unknown option``). A later
                # retry drops it. Mocha 6+ accepts the flag.
                cmd = list(binv)
                if color:
                    cmd.append("--no-color")
                cmd += ["--reporter", "json"]
                if use_output:
                    cmd += ["--reporter-option", f"output={out_json}"]
                if config_arg:
                    cmd += ["--config", config_arg]
                if use_pattern:
                    cmd += ["--grep", pattern]
                cmd.append(file_arg)
                return cmd

            if self.framework == "vitest":
                cmd = binv + (["run"] if not self.test_command else [])
                if config_arg:
                    cmd += ["--config", config_arg]
                if use_project and project_args:
                    cmd += project_args
                cmd += ["--reporter=json", f"--outputFile={out_json}"]
                if use_pattern:
                    cmd += ["--testNamePattern", pattern]
                cmd.append(file_arg)
            elif self.framework == "mocha":
                cmd = mocha_cmd(True)
            else:
                cmd = binv + ["--ci", "--json", f"--outputFile={out_json}", "--watchman=false"]
                if config_arg:
                    cmd += ["--config", config_arg]
                if use_project and project_args:
                    cmd += project_args
                if use_pattern:
                    cmd += ["--testNamePattern", pattern]
                cmd += ["--runTestsByPath", "--", file_arg]
            try:
                try:
                    rc, out, errt = run_capped(cmd, cwd=cwd, env=run_env, timeout=t)
                except subprocess.TimeoutExpired:
                    return EvalResult(label="error", detail="timeout", kind="timeout")
                except OSError as e:
                    return EvalResult(label="error", detail=f"os:{type(e).__name__}", kind="tool_missing")
                report = None
                try:
                    if out_json.is_file():
                        report = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
                except (OSError, ValueError):
                    report = None
                if report is None:
                    for blob in (out, errt):
                        start = (blob or "").find("{")
                        if start < 0:
                            continue
                        try:
                            report = json.loads(blob[start:])
                            break
                        except ValueError:
                            continue
                if (
                    self.framework == "mocha"
                    and not (isinstance(report, dict) and "failures" in report)
                ):
                    blob = f"{out or ''}\n{errt or ''}".lower()
                    if "reporter-option" in blob or "unknown option" in blob:
                        # ``--no-color`` is unknown on Mocha 4. Drop it, and drop
                        # ``--reporter-option`` in the same retry: that flag is
                        # what the first branch already decided to abandon.
                        drop_color = "no-color" in blob and "unknown option" in blob
                        try:
                            rc, out, errt = run_capped(
                                mocha_cmd(False, color=not drop_color),
                                cwd=cwd, env=run_env, timeout=t,
                            )
                        except subprocess.TimeoutExpired:
                            return EvalResult(label="error", detail="timeout", kind="timeout")
                        except OSError as e:
                            return EvalResult(label="error", detail=f"os:{type(e).__name__}", kind="tool_missing")
                        report = _mocha_report_from_text(out or "") or _mocha_report_from_text(errt or "")
                        if (
                            not drop_color
                            and not (isinstance(report, dict) and "failures" in report)
                        ):
                            again = f"{out or ''}\n{errt or ''}".lower()
                            if "no-color" in again and "unknown option" in again:
                                try:
                                    rc, out, errt = run_capped(
                                        mocha_cmd(False, color=False),
                                        cwd=cwd, env=run_env, timeout=t,
                                    )
                                except subprocess.TimeoutExpired:
                                    return EvalResult(label="error", detail="timeout", kind="timeout")
                                except OSError as e:
                                    return EvalResult(label="error", detail=f"os:{type(e).__name__}", kind="tool_missing")
                                report = _mocha_report_from_text(out or "") or _mocha_report_from_text(errt or "")
                if self.framework == "mocha":
                    per_test = []
                    for n in name_lists:
                        label, kind, detail = classify_mocha_json(report, file_arg, n, sole_file=sole)
                        if file_arg != rel_file and detail in ("test_not_in_file", "no_json_report"):
                            alt_label, alt_kind, alt_detail = classify_mocha_json(report, rel_file, n, sole_file=sole)
                            if alt_detail not in ("test_not_in_file", "no_json_report"):
                                label, kind, detail = alt_label, alt_kind, alt_detail
                        if detail == "no_json_report" and rc == 0:
                            label, kind, detail = "error", "not_found", "test_not_in_file"
                        per_test.append((label, kind, detail))
                else:
                    per_test = [classify_js_json(report, file_arg, n, sole_file=sole) for n in name_lists]
                    if file_arg != rel_file and any(d == "file_not_in_report" for _l, _k, d in per_test):
                        alt = [classify_js_json(report, rel_file, n, sole_file=sole) for n in name_lists]
                        if not any(d == "file_not_in_report" for _l, _k, d in alt):
                            per_test = alt
                results = [EvalResult(label=label, kind=kind, detail=detail, runs=1,
                                      passes=int(label == "green"), fails=int(label == "red"))
                           for label, kind, detail in per_test]
                res = _combine_groups(results)
                if res.kind == "build_error" or res.detail in ("no_json_report", "file_not_in_report"):
                    better = _js_failure_detail(out, errt, res.detail)
                    noisy = res.detail in ("file_not_in_report", "no_json_report", "suite_failed_to_load") or "get_format" in (res.detail or "")
                    if better and (noisy or better.startswith("missing_build_output:")):
                        res = EvalResult(label="error", kind="build_error", detail=better, runs=1)
                if res.label == "green" and rc != 0:
                    if js_nonzero_exit_is_unrelated(report if isinstance(report, dict) else None, out, errt):
                        return res
                    return EvalResult(label="error", detail=f"exit_{rc}_with_target_passed", kind="package_fail", runs=1)
                return res
            finally:
                shutil.rmtree(out_dir, ignore_errors=True)

        first = once(True)
        if first.kind == "timeout":
            return first
        # ``--project <package name>`` is the workspace package. Vitest's own
        # project names are often different (``unit``, ``unit-gc``). A filter
        # that matches nothing exits before any JSON report. Drop the flag
        # and run the file once more. An unexplained exit is still an error.
        if project_args and _project_flag_rejected(first):
            without = once(True, use_project=False)
            if without.kind == "timeout":
                return without
            first = without
        if first.kind == "timeout":
            return first
        if first.detail in ("file_not_in_report", "test_not_in_file"):
            second = once(False, use_project=not project_args)
            if second.detail not in ("file_not_in_report", "test_not_in_file"):
                return second
            return second
        return first


def _machine_preflight_stop(
    kind: str,
    repo: Path,
    *,
    dotnet_bin: str | None = None,
    runner_env: dict | None = None,
) -> EvalResult | None:
    """Abstain before a runner scrubs the host environment or starts a tool.

    ``dotnet`` and ``junit`` share one scanner. Other runners do not call it.
    ``dotnet_bin`` is that runner's binary, not whichever ``dotnet`` is on PATH.
    """
    if kind not in ("dotnet", "junit"):
        return None
    from sentinel_card.machine_preflight import preflight_reason

    hit = preflight_reason(kind, repo, dotnet_bin=dotnet_bin, runner_env=runner_env)
    if not hit:
        return None
    return EvalResult(label="error", detail=hit, kind="machine_preflight")


# =============================================================================
# Maven Surefire / JUnit 5
# =============================================================================
@dataclass
class JvmGitRunner(_WorktreeRunner):
    """``mvn -Dtest=Class#method test`` for one single-module ``pom.xml``.

    Red and green come from ``target/surefire-reports`` written by that run.
    Gradle, a reactor with modules, and a missing JDK or Maven abstain.
    """

    mvn_bin: str = "mvn"
    test_command: Sequence[str] | None = None
    db_reset_command: Sequence[str] | None = None
    cache_dir: Path | None = None
    per_run_timeout_sec: float = 300.0
    kind_name = "junit"

    def validate_ids(self, tests: Sequence[str]) -> tuple[list[str], str | None]:
        return jvm_support.validate_jvm_ids(tests)

    def _mvn(self) -> str:
        if self.test_command:
            return self.test_command[0]
        return self.mvn_bin

    def evaluate(self, sha: str, tests: Sequence[str], *, reruns: int, deadline: float | None = None) -> EvalResult:
        stopped = _machine_preflight_stop(self.kind_name, Path(self.repo), runner_env=self.env)
        if stopped is not None:
            return stopped
        clean, err = jvm_support.validate_jvm_ids(tests)
        if err:
            return EvalResult(label="error", detail=err, kind="unknown")
        why = jvm_support.toolchain_error(self._mvn())
        if why:
            return EvalResult(label="error", detail=why, kind="tool_missing")
        wt, early = self._prepare(sha, deadline)
        if early is not None:
            return early
        assert wt is not None
        layout, reason = jvm_support.jvm_layout(wt)
        if layout != "maven_single":
            return EvalResult(label="error", detail=reason or "jvm_no_build_file", kind="unsupported_layout")
        home = make_isolated_home()
        try:
            env = jvm_support.jvm_child_env(home, extra=dict(self.env or {}))
            cache = Path(self.cache_dir or default_cache_dir())
            repo_local = cache / "m2"
            repo_local.mkdir(parents=True, exist_ok=True)
            db_err = apply_db_reset(
                self.db_reset_command, cwd=wt, env=env, deadline=deadline, sha=sha, cache=cache,
            )
            if db_err:
                kind = "timeout" if "budget" in db_err or db_err == "db_reset_timeout" else "env_setup"
                return EvalResult(label="error", detail=db_err, kind=kind)
            runs: list[EvalResult] = []
            for _ in range(max(1, reruns)):
                rem = remaining_budget(deadline)
                if rem < 0.05:
                    runs.append(EvalResult(label="error", detail="budget_exhausted", kind="timeout"))
                    break
                runs.append(self._run_once(wt, clean, env, repo_local, deadline))
                if runs[-1].kind in ("timeout", "build_error", "tool_missing", "unsupported_layout"):
                    break
            return self._aggregate(runs)
        finally:
            shutil.rmtree(home, ignore_errors=True)

    def _run_once(self, wt: Path, tests: list[str], env: dict, repo_local: Path, deadline) -> EvalResult:
        rem = remaining_budget(deadline)
        timeout = min(float(self.per_run_timeout_sec), rem)
        if timeout < 0.05:
            return EvalResult(label="error", detail="budget_exhausted", kind="timeout")
        jvm_support.clear_surefire_reports(wt)
        prefix = list(self.test_command) if self.test_command else [self.mvn_bin]
        binary = prefix[0] if prefix else self.mvn_bin
        flags = prefix[1:]
        argv = jvm_support.maven_test_argv(binary, tests, repo_local)
        cmd = [argv[0], *flags, *argv[1:]]
        # A cache under /tmp is bind-mounted only when the path is an env value.
        env = dict(env)
        env["SENTINEL_M2_REPO"] = str(repo_local)
        try:
            rc, out, errt = run_capped(cmd, cwd=wt, env=env, timeout=timeout)
        except subprocess.TimeoutExpired:
            return EvalResult(label="error", detail="timeout", kind="timeout")
        except OSError as exc:
            return EvalResult(label="error", detail=f"os:{type(exc).__name__}", kind="tool_missing")
        label, kind, detail, shape = jvm_support.classify_surefire(
            wt, tests, returncode=rc, output=(out or "") + "\n" + (errt or ""),
        )
        return EvalResult(
            label=label, kind=kind, detail=detail, failure=shape, runs=1,
            passes=int(label == "green"), fails=int(label == "red"),
        )



# =============================================================================
# .NET runner (single-project xUnit or NUnit via `dotnet test`)
# =============================================================================
# Scaffolding. One test project, xUnit or NUnit, filtered by FullyQualifiedName.
# A missing SDK, two test projects, or any other adapter abstains. No accuracy
# figure is claimed from this path.

_XUNIT_REF = re.compile(
    r"""Include\s*=\s*["'](?:xunit|xunit\.v3|xunit\.runner\.visualstudio)["']""",
    re.I,
)
_NUNIT_REF = re.compile(
    r"""Include\s*=\s*["'](?:NUnit|NUnit3TestAdapter)["']""",
    re.I,
)
_MSTEST_REF = re.compile(
    r"""Include\s*=\s*["'](?:MSTest(?:\.TestFramework|\.TestAdapter)?)["']""",
    re.I,
)
_TEST_SDK_REF = re.compile(r"""Include\s*=\s*["']Microsoft\.NET\.Test\.Sdk["']""", re.I)
_IS_TEST_PROJECT = re.compile(r"<IsTestProject>\s*true\s*</IsTestProject>", re.I)
_DOTNET_FAIL_LINE = re.compile(
    r"^\s*(?:\d+\)\s+)?Failed\s+"
    r"(?P<id>[A-Za-z_][A-Za-z0-9_+`]*(?:\.[A-Za-z_][A-Za-z0-9_+`]*){2,}"
    r"(?:\([^)\r\n]{0,160}\))?)"
    r"\s+\[[^\]]+\]\s*$"
)
_XUNIT_FAIL_LINE = re.compile(
    r"^\s*\[xUnit\.net[^\]]*\]\s+"
    r"(?P<id>[A-Za-z_][A-Za-z0-9_+`]*(?:\.[A-Za-z_][A-Za-z0-9_+`]*){2,}"
    r"(?:\([^)\r\n]{0,160}\))?)"
    r"\s+\[FAIL\]\s*$"
)
_ANY_DOTNET_FAIL = re.compile(r"^\s*(?:\d+\)\s+)?Failed\s+\S+")
_MSTEST_LOG = re.compile(
    r"MSTest\.TestAdapter|Microsoft\.VisualStudio\.TestTools|Assert\.AreEqual failed|Assert\.IsTrue failed",
    re.I,
)
_XUNIT_LOG = re.compile(r"\[xUnit\.net|Xunit\.Sdk|Assert\.Equal\(\) Failure")
_NUNIT_LOG = re.compile(r"NUnit Adapter|NUnit\.Framework|Assert\.That\(")
_VSTEST_FAILED = re.compile(
    r"Failed!  - Failed:\s+([1-9]\d*), Passed:\s+\d+, Skipped:\s+\d+, Total:\s+\d+"
)
_DOTNET_NO_MATCH = re.compile(r"No test matches the given testcase filter", re.I)
_DOTNET_SDK_MISSING = re.compile(
    r"A compatible \.NET SDK was not found|"
    r"You must install or update \.NET to run this application|"
    r"The framework 'Microsoft\.NETCore\.App'|"
    r"Install the \.NET SDK",
    re.I,
)
_DOTNET_BUILD_FAIL = re.compile(r"Build FAILED\.|(?:^|\s)error (?:CS|NU|MSB)\d+", re.M)

_DOTNET_ABSTAIN = {
    "dotnet_sdk_missing": "dotnet_sdk_missing: the dotnet SDK is not on PATH",
    "dotnet_multi_project": "dotnet_multi_project: more than one test project; not guessing which one",
    "dotnet_unsupported_adapter": "dotnet_unsupported_adapter: not a single-project xUnit or NUnit test",
    "dotnet_ambiguous_adapter": "dotnet_ambiguous_adapter: xUnit and NUnit are both referenced",
    "dotnet_no_test_project": "dotnet_no_test_project: no xUnit or NUnit csproj",
    "dotnet_test_not_found": "dotnet_test_not_found: FullyQualifiedName matched no test",
    "dotnet_test_skipped": "dotnet_test_skipped: the test did not run",
    "dotnet_build_failed": "dotnet_build_failed: the project did not build",
    "dotnet_result_unparsed": "dotnet_result_unparsed: the dotnet test result did not name the requested test",
}


def dotnet_abstain_detail(code: str) -> str:
    return _DOTNET_ABSTAIN.get(code, code)


@dataclass(frozen=True)
class DotnetProject:
    rel: str
    adapter: str  # xunit | nunit | mstest | unknown | mixed


def adapter_from_csproj(text: str) -> str:
    """Adapter named by this project file, or ``""`` when it is not a test project."""
    xunit = bool(_XUNIT_REF.search(text or ""))
    nunit = bool(_NUNIT_REF.search(text or ""))
    mstest = bool(_MSTEST_REF.search(text or ""))
    kinds = [name for name, on in (("xunit", xunit), ("nunit", nunit), ("mstest", mstest)) if on]
    if len(kinds) > 1:
        return "mixed"
    if len(kinds) == 1:
        return kinds[0]
    if _TEST_SDK_REF.search(text or "") or _IS_TEST_PROJECT.search(text or ""):
        return "unknown"
    return ""


def discover_dotnet_projects(root: Path) -> list[DotnetProject]:
    """Test ``*.csproj`` files under ``root``, skipping ``bin`` / ``obj``."""
    found: list[DotnetProject] = []
    try:
        paths = sorted(root.rglob("*.csproj"))
    except OSError:
        return found
    for path in paths:
        try:
            rel_path = path.relative_to(root)
        except ValueError:
            continue
        if set(rel_path.parts) & {"bin", "obj", ".git"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:500_000]
        except OSError:
            continue
        adapter = adapter_from_csproj(text)
        if adapter:
            found.append(DotnetProject(rel_path.as_posix(), adapter))
    return found


def select_dotnet_project(projects: Sequence[DotnetProject]) -> tuple[DotnetProject | None, str | None]:
    """One xUnit or NUnit project, or an abstain code."""
    tests = [p for p in projects if p.adapter]
    if not tests:
        return None, "dotnet_no_test_project"
    if len(tests) > 1:
        return None, "dotnet_multi_project"
    one = tests[0]
    if one.adapter in ("mstest", "unknown"):
        return None, "dotnet_unsupported_adapter"
    if one.adapter == "mixed":
        return None, "dotnet_ambiguous_adapter"
    if one.adapter not in ("xunit", "nunit"):
        return None, "dotnet_unsupported_adapter"
    return one, None


def _dotnet_extraction(log_text: str, *, limit: int = 20) -> Extraction:
    """Failing FullyQualifiedName ids, or an abstain when the log is not that shape."""
    if not log_text:
        return Extraction(None, [], "no_failing_tests_found")
    text = strip_task_prefixes(log_text)
    mstest = bool(_MSTEST_LOG.search(text))
    xunit = bool(_XUNIT_LOG.search(text))
    nunit = bool(_NUNIT_LOG.search(text))
    if mstest and not xunit and not nunit:
        return Extraction(None, [], "dotnet_unsupported_adapter")
    if mstest and (xunit or nunit):
        return Extraction(None, [], "dotnet_ambiguous_adapter")
    from sentinel_card.summary_gate import _mask

    visible, mask_err = _mask("dotnet", _lines_for_test_ids(text))
    if mask_err:
        return Extraction(None, [], mask_err)
    found: list[str] = []
    unparsed = False
    for line in visible:
        match = _DOTNET_FAIL_LINE.match(line) or _XUNIT_FAIL_LINE.match(line)
        if match:
            clean, err = validate_dotnet_ids([match.group("id")])
            if err or not clean:
                unparsed = True
                continue
            if clean[0] not in found:
                found.append(clean[0])
            if len(found) >= limit:
                break
            continue
        if _ANY_DOTNET_FAIL.match(line):
            unparsed = True
    dotnet_log = bool(xunit or nunit or _VSTEST_FAILED.search(text) or re.search(r"Failed:\s*\d+", text))
    if unparsed and (found or dotnet_log):
        return Extraction(None, [], "test_ids_unparsed_entry")
    if found:
        from sentinel_card.summary_gate import apply_gate

        gids, gerr = apply_gate("dotnet", text, found)
        if gerr and not gids:
            return Extraction(None, [], gerr)
        return Extraction("dotnet", gids)
    if unparsed and (xunit or nunit or _VSTEST_FAILED.search(text)):
        return Extraction(None, [], "dotnet_unsupported_adapter")
    if _VSTEST_FAILED.search(text):
        return Extraction(None, [], "dotnet_unsupported_adapter")
    from sentinel_card.summary_gate import apply_gate

    _gids, gerr = apply_gate("dotnet", text, [])
    if gerr == "summary_reports_pass":
        return Extraction(None, [], gerr)
    return Extraction(None, [], "no_failing_tests_found")


def extract_dotnet_failing_tests(log_text: str, *, limit: int = 20) -> list[str]:
    """Failing xUnit / NUnit FullyQualifiedName values. MSTest yields nothing."""
    return _dotnet_extraction(log_text, limit=limit).ids


def _xml_local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_trx_results(xml_text: str) -> list[dict] | None:
    """Unit-test rows from a TRX file. ``None`` when the XML does not parse."""
    if not xml_text or "<TestRun" not in xml_text:
        return None
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    defs: dict[str, dict[str, str]] = {}
    for el in root.iter():
        if _xml_local(el.tag) != "UnitTest":
            continue
        uid = el.attrib.get("id") or ""
        info = {"name": el.attrib.get("name") or "", "class": "", "method": ""}
        for child in list(el):
            if _xml_local(child.tag) == "TestMethod":
                info["class"] = child.attrib.get("className") or ""
                info["method"] = child.attrib.get("name") or ""
        if uid:
            defs[uid] = info
    rows: list[dict] = []
    for el in root.iter():
        if _xml_local(el.tag) != "UnitTestResult":
            continue
        info = defs.get(el.attrib.get("testId") or "") or {}
        rows.append({
            "testName": el.attrib.get("testName") or "",
            "outcome": el.attrib.get("outcome") or "",
            "name": info.get("name") or "",
            "class": info.get("class") or "",
            "method": info.get("method") or "",
        })
    return rows


def _trx_matches(row: dict, fqn: str) -> bool:
    if row.get("testName") == fqn or row.get("name") == fqn:
        return True
    cls, method = row.get("class") or "", row.get("method") or ""
    return bool(cls and method and f"{cls}.{method}" == fqn)


def _console_outcome(blob: str, fqn: str) -> str | None:
    escaped = re.escape(fqn)
    if re.search(rf"(?m)^\s*(?:\d+\)\s+)?Failed\s+{escaped}\s+\[", blob):
        return "red"
    if re.search(rf"\[xUnit\.net[^\]]*\]\s+{escaped}\s+\[FAIL\]", blob):
        return "red"
    if re.search(rf"(?m)^\s*Passed\s+{escaped}\s+\[", blob):
        return "green"
    return None


def _outcome_label(outcome: str) -> str | None:
    name = (outcome or "").strip().lower()
    if name == "passed":
        return "green"
    if name == "failed":
        return "red"
    if name in ("notexecuted", "skipped", "inconclusive"):
        return "skipped"
    return None


def classify_dotnet_run(
    stdout: str,
    stderr: str,
    trx_xml: str | None,
    ids: Sequence[str],
) -> tuple[str, str, str]:
    """Map one ``dotnet test`` invocation to a label. Exit code is not enough.

    Green only when every requested id ran and passed. Red only when every
    requested id was seen and at least one failed. A build failure, a skipped
    test, or a filter that matched nothing is an error.
    """
    if not ids:
        return "error", "unknown", "no_failing_tests_provided"
    blob = f"{stdout or ''}\n{stderr or ''}"
    if _DOTNET_SDK_MISSING.search(blob):
        return "error", "tool_missing", dotnet_abstain_detail("dotnet_sdk_missing")
    rows = parse_trx_results(trx_xml or "")
    labels: list[str] = []
    for fqn in ids:
        label = None
        if rows is not None:
            matched = [_outcome_label(row.get("outcome") or "") for row in rows if _trx_matches(row, fqn)]
            matched = [item for item in matched if item]
            if "red" in matched:
                label = "red"
            elif matched and all(item == "green" for item in matched):
                label = "green"
            elif "skipped" in matched:
                label = "skipped"
        if label is None:
            label = _console_outcome(blob, fqn)
        labels.append(label or "missing")
    if labels and all(item == "green" for item in labels):
        return "green", "pass", "pass"
    if labels and "red" in labels and "missing" not in labels and "skipped" not in labels:
        return "red", "fail", "fail"
    if _DOTNET_BUILD_FAIL.search(blob) and "red" not in labels:
        return "error", "build_error", dotnet_abstain_detail("dotnet_build_failed")
    if any(item == "skipped" for item in labels) and "red" not in labels:
        return "error", "skipped", dotnet_abstain_detail("dotnet_test_skipped")
    if _DOTNET_NO_MATCH.search(blob) or any(item == "missing" for item in labels):
        if "red" not in labels:
            return "error", "not_found", dotnet_abstain_detail("dotnet_test_not_found")
    return "error", "unknown", dotnet_abstain_detail("dotnet_result_unparsed")


def _dotnet_ready(binary: str, env: dict[str, str]) -> bool:
    if os.path.isabs(binary):
        return os.path.isfile(binary) and os.access(binary, os.X_OK)
    return shutil.which(binary, path=env.get("PATH")) is not None


@dataclass
class DotnetGitRunner(_WorktreeRunner):
    """``dotnet test <csproj> --filter FullyQualifiedName=...`` for one project."""

    dotnet_bin: str = "dotnet"
    cache_dir: Path | None = None
    per_run_timeout_sec: float = 300.0
    kind_name = "dotnet"

    def validate_ids(self, tests: Sequence[str]) -> tuple[list[str], str | None]:
        return validate_dotnet_ids(tests)

    def _child_env_dotnet(self, home: Path) -> dict[str, str]:
        """Scrub allow-list, plus DOTNET_ROOT pass-through and the forced CLI flags.

        Host keys outside that set, including ``DISPLAY`` and ``PS1``, are not copied.
        A build-hook key in the bisect overlay is dropped here. Preflight abstains on it.
        """
        from sentinel_card.machine_preflight import scrub_runner_env

        env = build_scrubbed_env(extra=scrub_runner_env("dotnet", dict(self.env or {})), home=str(home))
        apply_isolated_home(env, home)
        _passthrough(env, ("DOTNET_ROOT", "DOTNET_ROOT_X64", "DOTNET_MULTILEVEL_LOOKUP"))
        cache = Path(self.cache_dir or default_cache_dir())
        (cache / "nuget").mkdir(parents=True, exist_ok=True)
        env["NUGET_PACKAGES"] = str(cache / "nuget")
        env["DOTNET_CLI_HOME"] = str(home)
        env["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
        env["DOTNET_NOLOGO"] = "1"
        env["DOTNET_SKIP_FIRST_TIME_EXPERIENCE"] = "1"
        env["NUGET_XMLDOC_MODE"] = "skip"
        env["GIT_TERMINAL_PROMPT"] = "0"
        return env

    def evaluate(self, sha: str, tests: Sequence[str], *, reruns: int, deadline: float | None = None) -> EvalResult:
        stopped = _machine_preflight_stop(
            self.kind_name, Path(self.repo), dotnet_bin=self.dotnet_bin, runner_env=self.env,
        )
        if stopped is not None:
            return stopped
        clean, err = validate_dotnet_ids(tests)
        if err:
            return EvalResult(label="error", detail=err, kind="unknown")
        home = make_isolated_home()
        try:
            env = self._child_env_dotnet(home)
            if not _dotnet_ready(self.dotnet_bin, env):
                return EvalResult(
                    label="error", detail=dotnet_abstain_detail("dotnet_sdk_missing"), kind="tool_missing",
                )
            wt, early = self._prepare(sha, deadline)
            if early is not None:
                return early
            assert wt is not None
            chosen, why = select_dotnet_project(discover_dotnet_projects(wt))
            if why:
                return EvalResult(label="error", detail=dotnet_abstain_detail(why), kind="unknown")
            assert chosen is not None
            runs: list[EvalResult] = []
            for _ in range(max(1, reruns)):
                rem = remaining_budget(deadline)
                if rem < 0.05:
                    runs.append(EvalResult(label="error", detail="budget_exhausted", kind="timeout"))
                    break
                runs.append(self._run_project(wt, chosen, clean, env, deadline))
                if runs[-1].kind in ("timeout", "build_error", "tool_missing"):
                    break
            return self._aggregate(runs)
        finally:
            shutil.rmtree(home, ignore_errors=True)

    def _run_project(
        self,
        wt: Path,
        project: DotnetProject,
        ids: Sequence[str],
        env: dict[str, str],
        deadline: float | None,
    ) -> EvalResult:
        rem = remaining_budget(deadline)
        timeout = min(float(self.per_run_timeout_sec), rem)
        if timeout < 0.05:
            return EvalResult(label="error", detail="budget_exhausted", kind="timeout")
        cache = Path(self.cache_dir or default_cache_dir())
        results = cache / "trx" / uuid.uuid4().hex
        results.mkdir(parents=True, exist_ok=True)
        cmd = [
            self.dotnet_bin, "test", project.rel,
            "--nologo",
            "--filter", dotnet_filter(ids),
            "--results-directory", str(results),
            "--logger", "trx;LogFileName=sentinel.trx",
            "--logger", "console;verbosity=detailed",
        ]
        try:
            _rc, out, errt = run_capped(cmd, cwd=wt, env=env, timeout=timeout + 5)
        except subprocess.TimeoutExpired:
            return EvalResult(label="error", detail="timeout", kind="timeout")
        except OSError as exc:
            return EvalResult(label="error", detail=f"os:{type(exc).__name__}", kind="tool_missing")
        trx = None
        try:
            trx_files = sorted(results.glob("*.trx"))
            if trx_files:
                trx = trx_files[0].read_text(encoding="utf-8", errors="replace")
        except OSError:
            trx = None
        finally:
            shutil.rmtree(results, ignore_errors=True)
        label, kind, detail = classify_dotnet_run(out, errt, trx, ids)
        failure = ""
        if label == "red" and re.search(r"Assert\.|Xunit\.Sdk|NUnit\.Framework", f"{out}\n{errt}"):
            failure = "assertion"
        return EvalResult(
            label=label, detail=detail, kind=kind, failure=failure,
            passes=int(label == "green"), fails=int(label == "red"), runs=1,
        )



# =============================================================================
# cargo test (single crate)
# =============================================================================
@dataclass
class CargoGitRunner(_WorktreeRunner):
    """``cargo test -- --exact <path>`` for one crate.

    Red and green come from that run's libtest lines. A workspace, more
    than one ``Cargo.toml``, and a missing ``rustc`` or ``cargo`` abstain.
    """

    cargo_bin: str = "cargo"
    test_command: Sequence[str] | None = None
    db_reset_command: Sequence[str] | None = None
    cache_dir: Path | None = None
    per_run_timeout_sec: float = 300.0
    kind_name = "cargo"

    def validate_ids(self, tests: Sequence[str]) -> tuple[list[str], str | None]:
        return cargo_support.validate_cargo_ids(tests)

    def _cargo(self) -> str:
        if self.test_command:
            return self.test_command[0]
        return self.cargo_bin

    def evaluate(self, sha: str, tests: Sequence[str], *, reruns: int, deadline: float | None = None) -> EvalResult:
        clean, err = cargo_support.validate_cargo_ids(tests)
        if err:
            return EvalResult(label="error", detail=err, kind="unknown")
        why = cargo_support.toolchain_error(self._cargo())
        if why:
            return EvalResult(label="error", detail=why, kind="tool_missing")
        wt, early = self._prepare(sha, deadline)
        if early is not None:
            return early
        assert wt is not None
        # Before cargo. A member or path-dep build script is not a culprit,
        # including when the layout itself would also abstain.
        script = cargo_support.cargo_script_gate(wt)
        layout, reason = cargo_support.cargo_layout(wt)
        if layout != "cargo_single":
            if script:
                return EvalResult(label="error", detail=script, kind="unknown")
            return EvalResult(label="error", detail=reason or "cargo_no_manifest", kind="unsupported_layout")
        manifest = cargo_support.cargo_manifest(wt)
        if manifest is None:
            return EvalResult(label="error", detail="cargo_no_manifest", kind="unsupported_layout")
        home = make_isolated_home()
        try:
            cache = Path(self.cache_dir or default_cache_dir())
            env = cargo_support.cargo_child_env(home, cache, extra=dict(self.env or {}))
            db_err = apply_db_reset(
                self.db_reset_command, cwd=wt, env=env, deadline=deadline, sha=sha, cache=cache,
            )
            if db_err:
                kind = "timeout" if "budget" in db_err or db_err == "db_reset_timeout" else "env_setup"
                return EvalResult(label="error", detail=db_err, kind=kind)
            runs: list[EvalResult] = []
            for _ in range(max(1, reruns)):
                rem = remaining_budget(deadline)
                if rem < 0.05:
                    runs.append(EvalResult(label="error", detail="budget_exhausted", kind="timeout"))
                    break
                runs.append(self._run_once(manifest.parent, clean, env, deadline))
                if runs[-1].kind in ("timeout", "build_error", "tool_missing", "unsupported_layout"):
                    break
            return self._aggregate(runs)
        finally:
            shutil.rmtree(home, ignore_errors=True)

    def _run_once(self, crate: Path, tests: list[str], env: dict, deadline) -> EvalResult:
        rem = remaining_budget(deadline)
        timeout = min(float(self.per_run_timeout_sec), rem)
        if timeout < 0.05:
            return EvalResult(label="error", detail="budget_exhausted", kind="timeout")
        # Before cargo. A harness=false binary, a target runner, a wrapper,
        # a build script, or ``--config`` on the action argv can print a FAILED block.
        why = cargo_support.cargo_test_command_abstain(self.test_command)
        if why:
            return EvalResult(label="error", detail=why, kind="unknown")
        why = cargo_support.cargo_target_abstain(crate, env)
        if why:
            return EvalResult(label="error", detail=why, kind="unknown")
        prefix = list(self.test_command) if self.test_command else [self.cargo_bin, "test"]
        locked = (crate / "Cargo.lock").is_file()
        flags = ["--color", "never"]
        if locked:
            flags.append("--locked")
        cmd = [*prefix, *flags, "--", "--exact", *tests]
        try:
            rc, out, errt = run_capped(cmd, cwd=crate, env=env, timeout=timeout)
        except subprocess.TimeoutExpired:
            return EvalResult(label="error", detail="timeout", kind="timeout")
        except OSError as exc:
            return EvalResult(label="error", detail=f"os:{type(exc).__name__}", kind="tool_missing")
        label, kind, detail, shape = cargo_support.classify_cargo(
            (out or "") + "\n" + (errt or ""), tests, returncode=rc,
        )
        return EvalResult(
            label=label, kind=kind, detail=detail, failure=shape, runs=1,
            passes=int(label == "green"), fails=int(label == "red"),
        )


# =============================================================================
# CTest / GoogleTest (one binary)
# =============================================================================
@dataclass
class CppGitRunner(_WorktreeRunner):
    """``ctest -R '^<id>$'`` for one C or C++ test executable.

    Red and green come from that run's CTest or GoogleTest lines. A
    workspace, a second executable, a toolchain file, and a missing
    compiler abstain.
    """

    cache_dir: Path | None = None
    per_run_timeout_sec: float = 300.0
    db_reset_command: Sequence[str] | None = None
    kind_name = "cpp"

    def validate_ids(self, tests: Sequence[str]) -> tuple[list[str], str | None]:
        return cpp_support.validate_cpp_ids(tests)

    def evaluate(self, sha: str, tests: Sequence[str], *, reruns: int, deadline: float | None = None) -> EvalResult:
        clean, err = cpp_support.validate_cpp_ids(tests)
        if err:
            return EvalResult(label="error", detail=err, kind="unknown")
        why = cpp_support.toolchain_error()
        if why:
            return EvalResult(label="error", detail=why, kind="tool_missing")
        wt, early = self._prepare(sha, deadline)
        if early is not None:
            return early
        assert wt is not None
        layout, reason = cpp_support.cpp_layout(wt)
        if layout not in {"ctest_single", "gtest_single"}:
            return EvalResult(label="error", detail=reason or "cpp_no_cmake", kind="unsupported_layout")
        home = make_isolated_home()
        try:
            cache = Path(self.cache_dir or default_cache_dir())
            env = cpp_support.cpp_child_env(home, extra=dict(self.env or {}))
            db_err = apply_db_reset(
                self.db_reset_command, cwd=wt, env=env, deadline=deadline, sha=sha, cache=cache,
            )
            if db_err:
                kind = "timeout" if "budget" in db_err or db_err == "db_reset_timeout" else "env_setup"
                return EvalResult(label="error", detail=db_err, kind=kind)
            runs: list[EvalResult] = []
            for _ in range(max(1, reruns)):
                rem = remaining_budget(deadline)
                if rem < 0.05:
                    runs.append(EvalResult(label="error", detail="budget_exhausted", kind="timeout"))
                    break
                runs.append(self._run_once(wt, sha, clean, env, deadline))
                if runs[-1].kind in ("timeout", "build_error", "tool_missing", "unsupported_layout"):
                    break
            return self._aggregate(runs)
        finally:
            shutil.rmtree(home, ignore_errors=True)

    def _run_once(self, wt: Path, sha: str, tests: list[str], env: dict, deadline) -> EvalResult:
        import time

        rem = remaining_budget(deadline)
        budget = min(float(self.per_run_timeout_sec), rem)
        if budget < 0.05:
            return EvalResult(label="error", detail="budget_exhausted", kind="timeout")
        compilers = cpp_support.pinned_compilers()
        if compilers is None:
            return EvalResult(label="error", detail="cpp_compiler_missing", kind="tool_missing")
        cache = Path(self.cache_dir or default_cache_dir())
        build = cache / "cpp" / sha
        shutil.rmtree(build, ignore_errors=True)
        build.mkdir(parents=True, exist_ok=True)
        started = time.monotonic()

        def left() -> float:
            return min(budget - (time.monotonic() - started), remaining_budget(deadline))

        configure = [
            "cmake", "-S", str(wt), "-B", str(build),
            "-G", "Unix Makefiles",
            "-DCMAKE_BUILD_TYPE=Debug",
            f"-DCMAKE_C_COMPILER={compilers[0]}",
            f"-DCMAKE_CXX_COMPILER={compilers[1]}",
            "-DCMAKE_COLOR_DIAGNOSTICS=OFF",
        ]
        try:
            rc, out, errt = run_capped(configure, cwd=wt, env=env, timeout=left())
        except subprocess.TimeoutExpired:
            return EvalResult(label="error", detail="timeout", kind="timeout")
        except OSError as exc:
            return EvalResult(label="error", detail=f"os:{type(exc).__name__}", kind="tool_missing")
        if rc != 0:
            label, kind, detail, shape = cpp_support.classify_cpp((out or "") + "\n" + (errt or ""), tests, returncode=rc)
            if kind != "build_error":
                kind, detail = "build_error", detail or "configure_failed"
            return EvalResult(label="error", kind=kind, detail=detail, failure=shape, runs=1)
        if left() < 0.05:
            return EvalResult(label="error", detail="budget_exhausted", kind="timeout")
        try:
            rc, out, errt = run_capped(
                ["cmake", "--build", str(build)], cwd=wt, env=env, timeout=left(),
            )
        except subprocess.TimeoutExpired:
            return EvalResult(label="error", detail="timeout", kind="timeout")
        except OSError as exc:
            return EvalResult(label="error", detail=f"os:{type(exc).__name__}", kind="tool_missing")
        if rc != 0:
            label, kind, detail, shape = cpp_support.classify_cpp((out or "") + "\n" + (errt or ""), tests, returncode=rc)
            if kind != "build_error":
                kind, detail = "build_error", detail or "build_failed"
            return EvalResult(label="error", kind=kind, detail=detail, failure=shape, runs=1)
        registered, reg_err = cpp_support._registered_tests(build)
        if reg_err:
            kind = "unsupported_layout" if reg_err == "cpp_multibinary_unsupported" else "not_found"
            if reg_err in {"cpp_tests_not_discovered", "cpp_ctest_command_unsupported"}:
                kind = "build_error" if reg_err == "cpp_tests_not_discovered" else "unsupported_layout"
            return EvalResult(label="error", detail=reg_err, kind=kind)
        missing = [name for name in tests if name not in registered]
        if missing:
            return EvalResult(label="error", detail="test_not_registered", kind="not_found")
        if left() < 0.05:
            return EvalResult(label="error", detail="budget_exhausted", kind="timeout")
        pattern = cpp_support.ctest_name_regex(tests)
        try:
            rc, out, errt = run_capped(
                ["ctest", "--test-dir", str(build), "--output-on-failure", "-R", pattern],
                cwd=wt, env=env, timeout=left(),
            )
        except subprocess.TimeoutExpired:
            return EvalResult(label="error", detail="timeout", kind="timeout")
        except OSError as exc:
            return EvalResult(label="error", detail=f"os:{type(exc).__name__}", kind="tool_missing")
        label, kind, detail, shape = cpp_support.classify_cpp(
            (out or "") + "\n" + (errt or ""), tests, returncode=rc,
        )
        return EvalResult(
            label=label, kind=kind, detail=detail, failure=shape, runs=1,
            passes=int(label == "green"), fails=int(label == "red"),
        )


# =============================================================================
# Ruby (minitest / RSpec) and PHPUnit
# =============================================================================
@dataclass
class RubyGitRunner(_WorktreeRunner):
    """``bundle exec`` for one Gemfile with a Gemfile.lock.

    Minitest re-runs ``ruby FILE -v -n /\\AClass#test_name\\z/``. RSpec
    re-runs ``rspec FILE --format json --example DESCRIPTION``. A missing
    lockfile does not run Bundler.
    """

    framework: str = "minitest"
    ruby_bin: str = "ruby"
    bundle_bin: str = "bundle"
    cache_dir: Path | None = None
    per_run_timeout_sec: float = 300.0
    kind_name = "minitest"

    def validate_ids(self, tests: Sequence[str]) -> tuple[list[str], str | None]:
        if self.framework == "rspec":
            return ruby_support.validate_rspec_ids(tests)
        return ruby_support.validate_minitest_ids(tests)

    def _validate(self, tests: Sequence[str]) -> tuple[list[str], str | None]:
        return self.validate_ids(tests)

    def evaluate(self, sha: str, tests: Sequence[str], *, reruns: int, deadline: float | None = None) -> EvalResult:
        clean, err = self._validate(tests)
        if err:
            return EvalResult(label="error", detail=err, kind="unknown")
        wt, early = self._prepare(sha, deadline)
        if early is not None:
            return early
        assert wt is not None
        layout, reason = ruby_support.ruby_layout(wt, self.framework)
        if layout != "bundler_single":
            return EvalResult(label="error", detail=reason or "ruby_no_gemfile", kind="unsupported_layout")
        why = ruby_support.toolchain_error(ruby_bin=self.ruby_bin, bundle_bin=self.bundle_bin)
        if why:
            return EvalResult(label="error", detail=why, kind="tool_missing")
        home = make_isolated_home()
        try:
            cache = Path(self.cache_dir or default_cache_dir())
            env = ruby_support.ruby_child_env(home, cache, extra=dict(self.env or {}))
            db_err = apply_db_reset(
                self.db_reset_command, cwd=wt, env=env, deadline=deadline, sha=sha, cache=cache,
            )
            if db_err:
                kind = "timeout" if "budget" in db_err or db_err == "db_reset_timeout" else "env_setup"
                return EvalResult(label="error", detail=db_err, kind=kind)
            runs: list[EvalResult] = []
            for _ in range(max(1, reruns)):
                rem = remaining_budget(deadline)
                if rem < 0.05:
                    runs.append(EvalResult(label="error", detail="budget_exhausted", kind="timeout"))
                    break
                runs.append(self._run_once(wt, clean, env, deadline))
                if runs[-1].kind in ("timeout", "build_error", "tool_missing", "unsupported_layout"):
                    break
            return self._aggregate(runs)
        finally:
            shutil.rmtree(home, ignore_errors=True)

    def _run_once(self, wt: Path, tests: list[str], env: dict, deadline) -> EvalResult:
        rem = remaining_budget(deadline)
        timeout = min(float(self.per_run_timeout_sec), rem)
        if timeout < 0.05:
            return EvalResult(label="error", detail="budget_exhausted", kind="timeout")
        install = [self.bundle_bin, "install", "--frozen", "--jobs", "1", "--retry", "1"]
        try:
            rc, out, errt = run_capped(install, cwd=wt, env=env, timeout=timeout)
        except subprocess.TimeoutExpired:
            return EvalResult(label="error", detail="timeout", kind="timeout")
        except OSError as exc:
            return EvalResult(label="error", detail=f"os:{type(exc).__name__}", kind="tool_missing")
        if rc != 0:
            detail = _scrub_reason(((errt or out or "bundle_install_failed").strip().splitlines() or ["bundle_install_failed"])[-1])
            return EvalResult(label="error", detail=detail or "bundle_install_failed", kind="build_error")
        if self.framework == "rspec":
            split = ruby_support.split_rspec_id(tests[0])
            if split is None or len(tests) != 1:
                return EvalResult(label="error", detail="rspec_unsupported_id", kind="unknown")
            cmd = ruby_support.rspec_argv(self.bundle_bin, split[0], split[1])
        else:
            if len(tests) != 1:
                return EvalResult(label="error", detail="minitest_unsupported_id", kind="unknown")
            split_m = ruby_support.split_minitest_id(tests[0])
            if split_m is None:
                return EvalResult(label="error", detail="minitest_unsupported_id", kind="unknown")
            cmd = ruby_support.minitest_argv(self.bundle_bin, *split_m)
        file = cmd[3]
        if not (wt / file).is_file():
            return EvalResult(label="error", detail="ruby_test_file_missing", kind="not_found")
        try:
            _rc, out, errt = run_capped(cmd, cwd=wt, env=env, timeout=timeout)
        except subprocess.TimeoutExpired:
            return EvalResult(label="error", detail="timeout", kind="timeout")
        except OSError as exc:
            return EvalResult(label="error", detail=f"os:{type(exc).__name__}", kind="tool_missing")
        blob = (out or "") + "\n" + (errt or "")
        if self.framework == "rspec":
            label, kind, detail, shape = ruby_support.classify_rspec(blob, tests)
        else:
            label, kind, detail, shape = ruby_support.classify_minitest(blob, tests)
        return EvalResult(
            label=label, kind=kind, detail=detail, failure=shape, runs=1,
            passes=int(label == "green"), fails=int(label == "red"),
        )


@dataclass
class PhpunitGitRunner(_WorktreeRunner):
    """``composer install`` then ``vendor/bin/phpunit --filter`` for one package.

    Red and green come from that run's JUnit XML. A missing composer.lock
    does not run Composer.
    """

    php_bin: str = "php"
    composer_bin: str = "composer"
    cache_dir: Path | None = None
    per_run_timeout_sec: float = 300.0
    kind_name = "phpunit"

    def validate_ids(self, tests: Sequence[str]) -> tuple[list[str], str | None]:
        return phpunit_support.validate_phpunit_ids(tests)

    def evaluate(self, sha: str, tests: Sequence[str], *, reruns: int, deadline: float | None = None) -> EvalResult:
        clean, err = phpunit_support.validate_phpunit_ids(tests)
        if err:
            return EvalResult(label="error", detail=err, kind="unknown")
        wt, early = self._prepare(sha, deadline)
        if early is not None:
            return early
        assert wt is not None
        layout, reason = phpunit_support.php_layout(wt)
        if layout != "composer_single":
            return EvalResult(label="error", detail=reason or "php_no_composer", kind="unsupported_layout")
        why = phpunit_support.toolchain_error(php_bin=self.php_bin, composer_bin=self.composer_bin)
        if why:
            return EvalResult(label="error", detail=why, kind="tool_missing")
        home = make_isolated_home()
        try:
            cache = Path(self.cache_dir or default_cache_dir())
            env = phpunit_support.php_child_env(home, cache, extra=dict(self.env or {}))
            db_err = apply_db_reset(
                self.db_reset_command, cwd=wt, env=env, deadline=deadline, sha=sha, cache=cache,
            )
            if db_err:
                kind = "timeout" if "budget" in db_err or db_err == "db_reset_timeout" else "env_setup"
                return EvalResult(label="error", detail=db_err, kind=kind)
            runs: list[EvalResult] = []
            for _ in range(max(1, reruns)):
                rem = remaining_budget(deadline)
                if rem < 0.05:
                    runs.append(EvalResult(label="error", detail="budget_exhausted", kind="timeout"))
                    break
                runs.append(self._run_once(wt, clean, env, cache, deadline))
                if runs[-1].kind in ("timeout", "build_error", "tool_missing", "unsupported_layout"):
                    break
            return self._aggregate(runs)
        finally:
            shutil.rmtree(home, ignore_errors=True)

    def _run_once(self, wt: Path, tests: list[str], env: dict, cache: Path, deadline) -> EvalResult:
        rem = remaining_budget(deadline)
        timeout = min(float(self.per_run_timeout_sec), rem)
        if timeout < 0.05:
            return EvalResult(label="error", detail="budget_exhausted", kind="timeout")
        try:
            rc, out, errt = run_capped(
                phpunit_support.composer_install_argv(self.composer_bin),
                cwd=wt, env=env, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return EvalResult(label="error", detail="timeout", kind="timeout")
        except OSError as exc:
            return EvalResult(label="error", detail=f"os:{type(exc).__name__}", kind="tool_missing")
        if rc != 0:
            detail = _scrub_reason(((errt or out or "composer_install_failed").strip().splitlines() or ["composer_install_failed"])[-1])
            return EvalResult(label="error", detail=detail or "composer_install_failed", kind="build_error")
        binary = wt / "vendor" / "bin" / "phpunit"
        if not binary.is_file():
            return EvalResult(label="error", detail="phpunit_not_installed", kind="tool_missing")
        junit_dir = cache / "phpunit-junit" / uuid.uuid4().hex
        junit_dir.mkdir(parents=True, exist_ok=True)
        junit_path = junit_dir / "sentinel-phpunit.xml"
        cmd = phpunit_support.phpunit_argv(str(binary), tests, junit_path)
        if not cmd:
            return EvalResult(label="error", detail="phpunit_unsupported_id", kind="unknown")
        for rel in cmd[cmd.index("--log-junit") + 2:]:
            if rel.startswith("-"):
                continue
            if not (wt / rel).is_file():
                return EvalResult(label="error", detail="phpunit_test_file_missing", kind="not_found")
        try:
            _rc, out, errt = run_capped(cmd, cwd=wt, env=env, timeout=timeout)
        except subprocess.TimeoutExpired:
            return EvalResult(label="error", detail="timeout", kind="timeout")
        except OSError as exc:
            return EvalResult(label="error", detail=f"os:{type(exc).__name__}", kind="tool_missing")
        xml = ""
        try:
            if junit_path.is_file():
                xml = junit_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            xml = ""
        finally:
            shutil.rmtree(junit_dir, ignore_errors=True)
        label, kind, detail, shape = phpunit_support.classify_phpunit(
            (out or "") + "\n" + (errt or ""), xml, tests,
        )
        return EvalResult(
            label=label, kind=kind, detail=detail, failure=shape, runs=1,
            passes=int(label == "green"), fails=int(label == "red"),
        )


# =============================================================================
# Factory
# =============================================================================
def make_runner(
    runner: str,
    repo: str | Path,
    *,
    python: str = "python3",
    test_command: str | None = None,
    install_command: str | None = None,
    build_command: str | None = None,
    db_reset_command: str | None = None,
    test_workdir: str | None = None,
    per_run_timeout_sec: float | None = None,
    cache_dir: str | Path | None = None,
    base_cls: type | None = None,
    env: dict[str, str] | None = None,
    fault_text: str | None = None,
):
    """Build a runner instance. ``base_cls`` lets callers wrap evaluate() (logging).

    ``env``: non-secret variables passed through to every test run (the ``bisect_env``
    input, resolved by ``bisect.parse_bisect_env``). Secret-looking names are still dropped
    by ``build_scrubbed_env``.
    """
    env = dict(env) if env else None
    tc = shlex.split(test_command) if test_command else None
    ic = shlex.split(install_command) if install_command else None
    bc = shlex.split(build_command) if build_command else None
    dc = shlex.split(db_reset_command) if db_reset_command else None
    if runner == "playwright":
        from sentinel_card.browser_spec import PlaywrightSpecRunner

        cls = _wrap(PlaywrightSpecRunner, base_cls)
        return cls(
            Path(repo),
            per_run_timeout_sec=float(per_run_timeout_sec or 300),
            cache_dir=Path(cache_dir) if cache_dir else None,
            fault_text=fault_text or "",
        )
    if runner == "go":
        cls = _wrap(GoGitRunner, base_cls)
        kw = dict(repo=Path(repo), test_command=tc, db_reset_command=dc,
                  cache_dir=Path(cache_dir) if cache_dir else None, env=env)
        if per_run_timeout_sec:
            kw["per_run_timeout_sec"] = float(per_run_timeout_sec)
        return cls(**kw)
    if runner == "junit":
        cls = _wrap(JvmGitRunner, base_cls)
        kw = dict(repo=Path(repo), test_command=tc, db_reset_command=dc,
                  cache_dir=Path(cache_dir) if cache_dir else None, env=env,
                  per_run_timeout_sec=float(per_run_timeout_sec or 300))
        return cls(**kw)
    if runner == "dotnet":
        cls = _wrap(DotnetGitRunner, base_cls)
        kw = dict(repo=Path(repo), cache_dir=Path(cache_dir) if cache_dir else None, env=env)
        if per_run_timeout_sec:
            kw["per_run_timeout_sec"] = float(per_run_timeout_sec)
        return cls(**kw)
    if runner == "cargo":
        cls = _wrap(CargoGitRunner, base_cls)
        kw = dict(repo=Path(repo), test_command=tc, db_reset_command=dc,
                  cache_dir=Path(cache_dir) if cache_dir else None, env=env,
                  per_run_timeout_sec=float(per_run_timeout_sec or 300))
        return cls(**kw)
    if runner == "cpp":
        cls = _wrap(CppGitRunner, base_cls)
        kw = dict(repo=Path(repo), db_reset_command=dc,
                  cache_dir=Path(cache_dir) if cache_dir else None, env=env,
                  per_run_timeout_sec=float(per_run_timeout_sec or 300))
        return cls(**kw)
    if runner in ("minitest", "rspec"):
        cls = _wrap(RubyGitRunner, base_cls)
        kw = dict(repo=Path(repo), framework=runner, db_reset_command=dc,
                  cache_dir=Path(cache_dir) if cache_dir else None, env=env,
                  per_run_timeout_sec=float(per_run_timeout_sec or 300))
        return cls(**kw)
    if runner == "phpunit":
        cls = _wrap(PhpunitGitRunner, base_cls)
        kw = dict(repo=Path(repo), db_reset_command=dc,
                  cache_dir=Path(cache_dir) if cache_dir else None, env=env,
                  per_run_timeout_sec=float(per_run_timeout_sec or 300))
        return cls(**kw)
    if runner in JS_FRAMEWORKS:
        cls = _wrap(JsGitRunner, base_cls)
        kw = dict(repo=Path(repo), framework=runner, test_command=tc, install_command=ic,
                  build_command=bc, db_reset_command=dc, test_workdir=test_workdir or None,
                  cache_dir=Path(cache_dir) if cache_dir else None, env=env)
        if per_run_timeout_sec:
            kw["per_run_timeout_sec"] = float(per_run_timeout_sec)
        return cls(**kw)
    cls = _wrap(PytestGitRunner, base_cls)
    kw = dict(repo=Path(repo), python=python, env=env, db_reset_command=dc,
              cache_dir=Path(cache_dir) if cache_dir else None)
    if per_run_timeout_sec:
        kw["per_run_timeout_sec"] = float(per_run_timeout_sec)
    return cls(**kw)


def _wrap(cls: type, mixin: type | None) -> type:
    if mixin is None:
        return cls
    return type(f"{mixin.__name__}{cls.__name__}", (mixin, cls), {})


def preflight(runner: str, *, python: str = "python3", test_command: str | None = None) -> tuple[bool, str]:
    """Can the toolchain start under the scrubbed env? (No repo code runs here.)"""
    if runner == "junit":
        if test_command:
            binary = shlex.split(test_command)[:1]
            why = jvm_support.toolchain_error(binary[0] if binary else "mvn")
            if why:
                return False, why
        return jvm_support.preflight_junit()
    if runner == "cargo":
        if test_command:
            binary = shlex.split(test_command)[:1]
            why = cargo_support.toolchain_error(binary[0] if binary else "cargo")
            if why:
                return False, why
        return cargo_support.preflight_cargo()
    if runner == "cpp":
        return cpp_support.preflight_cpp()
    if runner in ("minitest", "rspec"):
        why = ruby_support.toolchain_error()
        return (False, why) if why else (True, "")
    if runner == "phpunit":
        why = phpunit_support.toolchain_error()
        return (False, why) if why else (True, "")
    home = make_isolated_home()
    try:
        env = build_scrubbed_env(home=str(home))
        apply_isolated_home(env, home)
        if runner == "go":
            cmd = (shlex.split(test_command)[:1] if test_command else ["go"]) + ["version"]
        elif runner in JS_FRAMEWORKS or runner == "playwright":
            cmd = ["node", "--version"]
        elif runner == "dotnet":
            cmd = ["dotnet", "--version"]
        else:
            cmd = [python, "-c", "import pytest"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env, cwd=str(home))
        if r.returncode == 0:
            return True, ""
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-1:] or [f"exit {r.returncode}"]
        return False, _scrub_reason(tail[0], max_len=160)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, type(e).__name__
    finally:
        shutil.rmtree(home, ignore_errors=True)
