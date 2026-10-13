"""Minitest and RSpec ids for one Bundler project.

Experimental scaffolding. A minitest id is ``test/test_calc.rb::CalcTest#test_adds``.
An RSpec id is ``spec/calc_spec.rb::Calc adds two numbers``. Red and green
come only from that run's verbose minitest line or RSpec JSON example.
An exit code by itself is not a pass.

One ``Gemfile`` plus ``Gemfile.lock`` is the only layout this runner
installs. A missing lockfile, a second Gemfile, Rails, and both
frameworks in one Gemfile abstain. They are not a culprit.
"""
from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from sentinel_card.bisect import _scrub_reason
from sentinel_card.bisect import apply_isolated_home
from sentinel_card.bisect import build_scrubbed_env
from sentinel_card.toolchain_pin import BUNDLER_VERSION
from sentinel_card.toolchain_pin import RUBY_VERSION
from sentinel_card.toolchain_pin import version_mismatch

MAX_RUBY_ID_LEN = 512
_SKIP_DIRS = frozenset({".git", "vendor", "node_modules", ".bundle", "tmp", "log"})
_RB_FILE = re.compile(r"^[A-Za-z0-9_./-]+\.rb$")
_CLASS = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$")
_TEST_METHOD = re.compile(r"^test_[A-Za-z0-9_]+$")
_DESC = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.,:'+-]{0,180}$")
_GH_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z ?")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_WF_CMD = re.compile(r"^##\[[A-Za-z]+\]\s?")
_GEM = re.compile(r"""(?m)^\s*gem\s+['"]([^'"]+)['"]""")
_RAILS_GEM = frozenset({"rails", "rspec-rails"})
_RSPEC_GEMS = frozenset({"rspec", "rspec-core"})
_MINITEST_GEMS = frozenset({"minitest"})
_FAILURE_LOC = re.compile(
    r"^([A-Za-z_][\w:]*)#(test_[A-Za-z0-9_]+) \[([^\]]+\.rb):\d+\]:\s*$"
)
_VERBOSE = re.compile(
    r"^([A-Za-z_][\w:]*)#(test_[A-Za-z0-9_]+) = .* = ([.FES])\s*$"
)
_RSPEC_FAILED = re.compile(r"^rspec (\./)?(\S+_spec\.rb):\d+ # (.+)$")
_RSPEC_BLOCK = re.compile(r"^\s*\d+\)\s+(.+)$")
_RSPEC_FILE = re.compile(r"#\s+(?:\./)?(\S+_spec\.rb):\d+")
_MINITEST_TRACE = re.compile(
    r"((?:[A-Za-z0-9_./-]+)\.rb):\d+:in\s+[`']([^`']+)['`]"
)
_RSPEC_SHARED = re.compile(r"(?:^|/)(?:shared|support|helpers)/")
_LOAD_ERROR = re.compile(
    r"SyntaxError|LoadError|cannot load such file|Bundler::GemNotFound|"
    r"Could not find |bundle install"
)
_RAILS_APP = "config/application.rb"


@dataclass
class RubyLog:
    ids: list[str]
    error: str | None = None


def _lines(log_text: str) -> list[str]:
    out = []
    for raw in (log_text or "").splitlines():
        line = raw.lstrip("\ufeff")
        for _ in range(4):
            nxt = _WF_CMD.sub("", _GH_TS.sub("", _ANSI.sub("", line)))
            if nxt == line:
                break
            line = nxt
        out.append(line.rstrip("\r").rstrip())
    return out


def _safe_rb(path: str) -> bool:
    text = (path or "").strip()
    if text.startswith("./"):
        text = text[2:]
    if not text or text.startswith(("/", "-")) or ".." in text.split("/"):
        return False
    return bool(_RB_FILE.fullmatch(text))


def _rel_rb(path: str) -> str | None:
    text = (path or "").strip().replace("\\", "/")
    text = re.sub(r":\d+$", "", text)
    if text.startswith("./"):
        text = text[2:]
    if _safe_rb(text):
        return text
    if not text.startswith("/"):
        return None
    for marker in ("/test/", "/spec/", "/tests/"):
        idx = text.rfind(marker)
        if idx >= 0 and _safe_rb(text[idx + 1:]):
            return text[idx + 1:]
    return None


def _reject(prefix: str, text: str) -> str:
    return f"{prefix}:{text[:40]}"


def validate_minitest_ids(tests: list | tuple) -> tuple[list[str], str | None]:
    """``file.rb::Class#test_method``. Display names and flags are refused."""
    if not tests:
        return [], "no_failing_tests_provided"
    clean: list[str] = []
    for raw in tests:
        text = str(raw).strip()
        if not text:
            continue
        if len(text) > MAX_RUBY_ID_LEN:
            return [], _reject("minitest_id_too_long", text)
        if any(ord(c) < 32 for c in text) or text.startswith("-"):
            return [], _reject("minitest_unsupported_id", text)
        file, sep, name = text.partition("::")
        if not sep or "#" not in name:
            return [], _reject("minitest_unsupported_id", text)
        class_name, method = name.split("#", 1)
        rel = _rel_rb(file)
        if rel is None or not _CLASS.fullmatch(class_name) or not _TEST_METHOD.fullmatch(method):
            return [], _reject("minitest_unsupported_id", text)
        if not (rel.startswith("test/") or rel.startswith("tests/") or "/test/" in f"/{rel}"):
            if not (rel.split("/")[-1].startswith("test_") or rel.split("/")[-1].endswith("_test.rb")):
                return [], _reject("minitest_unsupported_id", text)
        tid = f"{rel}::{class_name}#{method}"
        if tid not in clean:
            clean.append(tid)
    return (clean, None) if clean else ([], "no_failing_tests_provided")


def validate_rspec_ids(tests: list | tuple) -> tuple[list[str], str | None]:
    """``spec/file_spec.rb::full description``. Example indexes are refused."""
    if not tests:
        return [], "no_failing_tests_provided"
    clean: list[str] = []
    for raw in tests:
        text = str(raw).strip()
        if not text:
            continue
        if len(text) > MAX_RUBY_ID_LEN:
            return [], _reject("rspec_id_too_long", text)
        if any(ord(c) < 32 for c in text) or text.startswith("-") or "'" in text or "`" in text:
            return [], _reject("rspec_unsupported_id", text)
        file, sep, desc = text.partition("::")
        if not sep or "#" in desc or "[" in desc:
            return [], _reject("rspec_unsupported_id", text)
        rel = _rel_rb(file)
        desc = desc.strip()
        if (
            rel is None
            or not rel.endswith("_spec.rb")
            or not _DESC.fullmatch(desc)
            or desc.startswith("-")
        ):
            return [], _reject("rspec_unsupported_id", text)
        tid = f"{rel}::{desc}"
        if tid not in clean:
            clean.append(tid)
    return (clean, None) if clean else ([], "no_failing_tests_provided")


def split_minitest_id(text: str) -> tuple[str, str, str] | None:
    clean, err = validate_minitest_ids([text])
    if err or not clean:
        return None
    file, name = clean[0].split("::", 1)
    class_name, method = name.split("#", 1)
    return file, class_name, method


def split_rspec_id(text: str) -> tuple[str, str] | None:
    clean, err = validate_rspec_ids([text])
    if err or not clean:
        return None
    file, desc = clean[0].split("::", 1)
    return file, desc


def _ruby_done(log_text: str, runner: str, ids: list[str], error: str | None = None) -> RubyLog:
    from sentinel_card.summary_gate import finish

    kept, err = finish(runner, log_text, ids, error)
    return RubyLog(kept, err)


def extract_minitest(log_text: str, *, limit: int = 20) -> RubyLog:
    """Failing minitest ids from a ``Class#test_name [file.rb:line]:`` block.

    A verbose pass line is not an id. A chopped name is
    ``test_ids_truncated``. A failure whose path or name is not that shape
    is ``minitest_unsupported_id`` when nothing safer was found.
    """
    if not log_text:
        return _ruby_done(log_text, "minitest", [])
    found: list[str] = []
    unsafe = False
    saw = False
    chopped = False
    lines = _lines(log_text)
    for line in lines:
        stripped = line.strip()
        if ("…" in stripped or "..." in stripped) and "#" in stripped and ".rb" in stripped:
            chopped = True
            continue
        matched = _FAILURE_LOC.match(stripped)
        if not matched:
            continue
        saw = True
        rel = _rel_rb(matched.group(3))
        if rel is None:
            unsafe = True
            continue
        tid = f"{rel}::{matched.group(1)}#{matched.group(2)}"
        clean, err = validate_minitest_ids([tid])
        if err or not clean:
            unsafe = True
            continue
        if clean[0] not in found:
            found.append(clean[0])
        if len(found) >= limit:
            break
    verbose, verbose_err = _minitest_verbose(lines, limit=limit)
    if found:
        if chopped or verbose_err or (verbose and set(verbose) != set(found)):
            return _ruby_done(log_text, "minitest", [], verbose_err or ("test_ids_truncated" if chopped else "minitest_unsupported_id"))
        return _ruby_done(log_text, "minitest", found)
    if verbose_err:
        return _ruby_done(log_text, "minitest", [], verbose_err)
    if verbose:
        return _ruby_done(log_text, "minitest", verbose)
    if chopped:
        return _ruby_done(log_text, "minitest", [], "test_ids_truncated")
    if saw or unsafe:
        return _ruby_done(log_text, "minitest", [], "minitest_unsupported_id")
    return _ruby_done(log_text, "minitest", [])


def extract_rspec(log_text: str, *, limit: int = 20) -> RubyLog:
    """Failing RSpec ids from ``rspec ./spec/file_spec.rb:N # description``.

    A passing example is not an id. An example id (``[1:1]``) or a
    description this runner cannot re-run is ``rspec_unsupported_id``.
    """
    if not log_text:
        return _ruby_done(log_text, "rspec", [])
    found: list[str] = []
    unsafe = False
    saw_rspec = False
    lines = _lines(log_text)
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("rspec "):
            saw_rspec = True
        matched = _RSPEC_FAILED.match(stripped)
        if not matched:
            if stripped.startswith("rspec ") and "_spec.rb" in stripped:
                unsafe = True
            continue
        rel = _rel_rb(matched.group(2))
        desc = matched.group(3).strip()
        if rel is None:
            unsafe = True
            continue
        tid = f"{rel}::{desc}"
        clean, err = validate_rspec_ids([tid])
        if err or not clean:
            unsafe = True
            continue
        if clean[0] not in found:
            found.append(clean[0])
        if len(found) >= limit:
            break
    block, block_err = _rspec_blocks(lines, limit=limit)
    if found:
        if block_err or (block and set(block) != set(found)):
            return _ruby_done(log_text, "rspec", [], "rspec_unsupported_id")
        return _ruby_done(log_text, "rspec", found)
    if block_err:
        return _ruby_done(log_text, "rspec", [], block_err)
    if block:
        return _ruby_done(log_text, "rspec", block)
    if unsafe or (saw_rspec and "Failed examples:" in (log_text or "")):
        return _ruby_done(log_text, "rspec", [], "rspec_unsupported_id")
    return _ruby_done(log_text, "rspec", [])


def _minitest_verbose(lines: list[str], *, limit: int) -> tuple[list[str], str | None]:
    """``Class#test = … = F`` plus the test method's own file.

    A frame counts only when ``in `method'`` is that test. A helper-only
    backtrace, or two files, is ``test_ids_ambiguous_location``. A chopped
    name is ``test_ids_truncated``.
    """
    found: list[str] = []
    reason: str | None = None
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if (
            ("…" in stripped or "..." in stripped)
            and "#" in stripped
            and re.search(r" = [FE]\s*$", stripped)
        ):
            reason = "test_ids_truncated"
            index += 1
            continue
        matched = _VERBOSE.match(stripped)
        if not matched or matched.group(3) not in "FE":
            index += 1
            continue
        method = matched.group(2)
        block: list[str] = []
        index += 1
        while index < len(lines):
            nxt = lines[index].strip()
            if _VERBOSE.match(nxt) or _FAILURE_LOC.match(nxt) or re.match(r"^\d+ runs,", nxt):
                break
            block.append(lines[index])
            index += 1
        files: list[str] = []
        own: list[str] = []
        for line in block:
            for trace in _MINITEST_TRACE.finditer(line):
                rel = _rel_rb(trace.group(1))
                if rel is None:
                    if trace.group(1).startswith("/"):
                        continue
                    reason = reason or "test_ids_ambiguous_location"
                    continue
                files.append(rel)
                if trace.group(2) == method:
                    own.append(rel)
        unique = list(dict.fromkeys(files))
        if len(unique) != 1 or not own or own[0] != unique[0]:
            reason = reason or "test_ids_ambiguous_location"
            continue
        tid = f"{unique[0]}::{matched.group(1)}#{method}"
        clean, err = validate_minitest_ids([tid])
        if err or not clean:
            reason = reason or "test_ids_ambiguous_location"
            continue
        if clean[0] not in found:
            found.append(clean[0])
    if reason:
        return [], reason
    return found[:limit], None


def _rspec_blocks(lines: list[str], *, limit: int) -> tuple[list[str], str | None]:
    """``N) description`` plus one example file.

    ``spec/shared/``, ``spec/support/``, and ``spec/helpers/`` are not the
    example's own file. Two files abstain ``test_ids_ambiguous_location``.
    A chopped description is ``test_ids_truncated``.
    """
    found: list[str] = []
    reason: str | None = None
    index = 0
    while index < len(lines):
        matched = _RSPEC_BLOCK.match(lines[index])
        if not matched:
            index += 1
            continue
        desc = matched.group(1).strip()
        block: list[str] = []
        index += 1
        while index < len(lines):
            if _RSPEC_BLOCK.match(lines[index]) or lines[index].startswith(("Failed examples", "Finished")):
                break
            block.append(lines[index])
            index += 1
        block_text = "\n".join(block)
        if "Failure/Error" not in block_text and not _RSPEC_FILE.search(block_text):
            continue
        if "…" in desc or desc.endswith("..."):
            reason = "test_ids_truncated"
            continue
        junk = False
        for line in block:
            text = line.strip()
            if not text:
                continue
            if text.startswith(("Failure/Error", "#", "expected", "Expected", "got:", "Diff:")):
                break
            junk = True
            break
        if junk:
            reason = reason or "test_ids_ambiguous_location"
            continue
        files: list[str] = []
        for line in block:
            for spec in _RSPEC_FILE.finditer(line):
                rel = _rel_rb(spec.group(1))
                if rel is None:
                    reason = reason or "test_ids_ambiguous_location"
                    continue
                files.append(rel)
        unique = list(dict.fromkeys(files))
        if len(unique) != 1 or _RSPEC_SHARED.search(unique[0] if unique else ""):
            reason = reason or "test_ids_ambiguous_location"
            continue
        clean, err = validate_rspec_ids([f"{unique[0]}::{desc}"])
        if err or not clean:
            reason = reason or "test_ids_ambiguous_location"
            continue
        if clean[0] not in found:
            found.append(clean[0])
    if reason:
        return [], reason
    return found[:limit], None


def _walk_named(root: Path, name: str) -> list[Path]:
    found: list[Path] = []
    if not root.is_dir():
        return found
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".sentinel")]
        try:
            depth = len(Path(dirpath).resolve().relative_to(root.resolve()).parts)
        except (OSError, ValueError):
            dirnames.clear()
            continue
        if depth > 6:
            dirnames.clear()
            continue
        if name in filenames:
            found.append(Path(dirpath) / name)
        if len(found) > 20:
            break
    return found


def _gems(text: str) -> set[str]:
    return {match.group(1) for match in _GEM.finditer(text or "")}


def _read(path: Path) -> str:
    try:
        if path.is_symlink() or path.stat().st_size > 500_000:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")[:500_000]
    except OSError:
        return ""


def ruby_layout(root: Path, framework: str) -> tuple[str, str | None]:
    """``('bundler_single', None)`` or ``('unsupported', reason)``.

    One Gemfile, its Gemfile.lock, and exactly the requested framework.
    ``bundle install`` is not run for any other layout.
    """
    gemfiles = _walk_named(Path(root), "Gemfile")
    if len(gemfiles) > 1:
        return "unsupported", "ruby_multi_gemfile"
    if not gemfiles:
        return "unsupported", "ruby_no_gemfile"
    gemfile = gemfiles[0]
    if not (gemfile.parent / "Gemfile.lock").is_file():
        return "unsupported", "gemfile_lock_missing"
    text = _read(gemfile)
    gems = _gems(text)
    if gems & _RAILS_GEM or (Path(root) / _RAILS_APP).is_file():
        return "unsupported", "ruby_rails_unsupported"
    wants_rspec = bool(gems & _RSPEC_GEMS)
    wants_minitest = bool(gems & _MINITEST_GEMS)
    if wants_rspec and wants_minitest:
        return "unsupported", "ruby_ambiguous_framework"
    if framework == "rspec" and not wants_rspec:
        return "unsupported", "ruby_framework_mismatch"
    if framework == "minitest" and not wants_minitest:
        return "unsupported", "ruby_framework_mismatch"
    if framework not in ("minitest", "rspec"):
        return "unsupported", "ruby_framework_mismatch"
    return "bundler_single", None


def repo_suggests_ruby(root: Path, framework: str) -> bool:
    layout, reason = ruby_layout(root, framework)
    if layout == "bundler_single":
        return True
    return reason in {
        "gemfile_lock_missing",
        "ruby_multi_gemfile",
        "ruby_rails_unsupported",
        "ruby_ambiguous_framework",
        "ruby_framework_mismatch",
    }


def _executable(name: str) -> bool:
    if not name or any(ord(c) < 32 for c in name):
        return False
    path = Path(name)
    if path.is_file() and os.access(path, os.X_OK):
        return True
    return shutil.which(name) is not None


def toolchain_error(*, ruby_bin: str = "ruby", bundle_bin: str = "bundle") -> str | None:
    """Missing binary, then the one-click pin. A wrong version is not a culprit."""
    if not _executable(ruby_bin):
        return "ruby_missing"
    if not _executable(bundle_bin):
        return "bundler_missing"
    why = version_mismatch([ruby_bin, "--version"], RUBY_VERSION, "ruby_version_mismatch")
    if why:
        return why
    return version_mismatch([bundle_bin, "--version"], BUNDLER_VERSION, "bundler_version_mismatch")


def ruby_child_env(home: Path, cache: Path, *, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Scrubbed env. Gems install under the bisect cache, not the job's home.

    ``BUNDLE_FROZEN`` stays on, so a checkout cannot drop the lockfile.
    Registry tokens are not copied. ``build_scrubbed_env`` drops names
    that contain ``TOKEN``.
    """
    bundle_path = Path(cache) / "bundle"
    bundle_path.mkdir(parents=True, exist_ok=True)
    overlay = {
        "BUNDLE_PATH": str(bundle_path),
        "BUNDLE_FROZEN": "true",
        "BUNDLE_JOBS": "1",
        "BUNDLE_RETRY": "1",
        "BUNDLE_DISABLE_SHARED_GEMS": "true",
        "BUNDLE_USER_HOME": str(home),
        "BUNDLE_USER_CONFIG": str(home / "bundle-config"),
        "GEM_HOME": str(bundle_path),
        "GIT_TERMINAL_PROMPT": "0",
    }
    if extra:
        for key, value in extra.items():
            if value is not None:
                overlay[key] = value
    env = build_scrubbed_env(extra=overlay, home=str(home))
    apply_isolated_home(env, home)
    env.update(overlay)
    env["HOME"] = str(home)
    return env


def minitest_argv(bundle: str, file: str, class_name: str, method: str) -> list[str]:
    pattern = f"/\\A{class_name}#{method}\\z/"
    return [bundle, "exec", "ruby", file, "-v", "-n", pattern]


def rspec_argv(bundle: str, file: str, description: str) -> list[str]:
    return [
        bundle, "exec", "rspec", file,
        "--format", "json", "--no-color", "--example", description,
    ]


def _minitest_marks(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    rank = {"pass": 1, "skip": 2, "fail": 3}
    for line in _lines(text):
        matched = _VERBOSE.match(line.strip())
        if matched:
            key = f"{matched.group(1)}#{matched.group(2)}"
            mark = {".": "pass", "F": "fail", "E": "fail", "S": "skip"}[matched.group(3)]
        else:
            located = _FAILURE_LOC.match(line.strip())
            if not located:
                continue
            key = f"{located.group(1)}#{located.group(2)}"
            mark = "fail"
        previous = found.get(key)
        if previous is None or rank[mark] > rank[previous]:
            found[key] = mark
    return found


def _rspec_examples(text: str) -> list[dict] | None:
    decoder = json.JSONDecoder()
    start = (text or "").find("{")
    while start >= 0:
        try:
            data, _end = decoder.raw_decode(text[start:])
        except ValueError:
            start = text.find("{", start + 1)
            continue
        if isinstance(data, dict) and isinstance(data.get("examples"), list):
            return [item for item in data["examples"] if isinstance(item, dict)]
        start = text.find("{", start + 1)
    return None


def _failure_detail(text: str) -> str:
    lines = []
    for raw in _lines(text):
        line = raw.strip()
        if not line:
            continue
        if line.startswith(("Expected:", "expected:", "Failure/Error:", "Actual:")) or "Expected:" in line:
            lines.append(line)
    if not lines:
        lines = [ln.strip() for ln in _lines(text) if ln.strip()][-3:]
    return " | ".join(lines[:3])


def classify_minitest(output: str, tests: list[str]) -> tuple[str, str, str, str]:
    """``(label, kind, detail, failure_shape)`` for the requested minitest ids.

    Exit 0 is not green. Green requires a verbose ``= .`` line for every
    requested id. Red requires ``= F``, ``= E``, or a failure block for
    that id. Another test's failure is not that id.
    """
    clean, err = validate_minitest_ids(tests)
    detail = _scrub_reason(_failure_detail(output or ""), max_len=200)
    if err or not clean:
        return "error", "unknown", detail or (err or "minitest_unsupported_id"), ""
    marks = _minitest_marks(output or "")
    statuses = []
    for tid in clean:
        split = split_minitest_id(tid)
        key = f"{split[1]}#{split[2]}" if split else ""
        statuses.append(marks.get(key, "missing"))
    if any(status == "fail" for status in statuses) and "missing" not in statuses:
        shape = "assertion" if re.search(r"Expected:|assert", output or "") else ""
        return "red", "fail", detail or "minitest_fail", shape
    if any(status == "missing" for status in statuses):
        if _LOAD_ERROR.search(output or ""):
            return "error", "build_error", detail or "ruby_load_failed", ""
        return "error", "not_found", detail or "test_not_in_output", ""
    if any(status == "skip" for status in statuses):
        return "error", "skipped", detail or "minitest_skipped", ""
    return "green", "pass", detail or "minitest_pass", ""


def classify_rspec(output: str, tests: list[str]) -> tuple[str, str, str, str]:
    """Green only when every requested example's JSON status is ``passed``."""
    clean, err = validate_rspec_ids(tests)
    detail = _scrub_reason(_failure_detail(output or ""), max_len=200)
    if err or not clean:
        return "error", "unknown", detail or (err or "rspec_unsupported_id"), ""
    examples = _rspec_examples(output or "")
    if examples is None:
        if _LOAD_ERROR.search(output or ""):
            return "error", "build_error", detail or "ruby_load_failed", ""
        return "error", "unknown", detail or "rspec_result_unparsed", ""
    statuses = []
    for tid in clean:
        split = split_rspec_id(tid)
        if split is None:
            statuses.append("missing")
            continue
        file, desc = split
        hits = []
        for item in examples:
            rel = _rel_rb(str(item.get("file_path") or ""))
            full = str(item.get("full_description") or "").strip()
            if rel == file and full == desc:
                hits.append(str(item.get("status") or ""))
        if not hits:
            statuses.append("missing")
        elif any(status == "failed" for status in hits):
            statuses.append("fail")
        elif all(status == "passed" for status in hits):
            statuses.append("pass")
        elif any(status == "pending" for status in hits):
            statuses.append("skip")
        else:
            statuses.append("missing")
    if any(status == "fail" for status in statuses) and "missing" not in statuses:
        return "red", "fail", detail or "rspec_fail", "assertion"
    if any(status == "missing" for status in statuses):
        if _LOAD_ERROR.search(output or ""):
            return "error", "build_error", detail or "ruby_load_failed", ""
        return "error", "not_found", detail or "example_not_in_report", ""
    if any(status == "skip" for status in statuses):
        return "error", "skipped", detail or "rspec_pending", ""
    return "green", "pass", detail or "rspec_pass", ""
