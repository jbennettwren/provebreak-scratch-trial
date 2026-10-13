"""``cargo test`` ids for one crate.

Experimental scaffolding. A test id is the libtest path, for example
``tests::adds_two_numbers``. Red and green come only from that run's
``test <id> ... FAILED`` or ``ok`` line. An exit code by itself is not a
pass. A cargo build failure (``failed to run custom build command``,
``could not compile``, or a build-script ``--- stdout`` / ``--- stderr``
section) is ``cargo_build_failed`` before any test line is read. Lines in
that section are not test evidence. A FAILED line counts only inside a
real harness: cargo's ``Running ...`` header, then that harness's
``running N tests``, then its ``test result:``. A second ``test result:``
in that same section is ``test_ids_multiple_summaries`` and is not red.
Red also requires a non-zero exit and one ``test result: FAILED`` summary
whose failed count matches those lines. Exit 0, or ``test result: ok``
with a FAILED line, is ``cargo_result_disagreed``. Classify is not red
when extract abstains. A pass summary and an empty doc-test beside one
real summary stay green or red. A signal or crash exit,
``cargo_signal_unsupported``, and a doc-test id abstain with that same
reason. ``harness = false``, ``[lib] test = false``, and a custom target
runner abstain before cargo runs (``cargo_harness_false``,
``cargo_test_false``, ``cargo_custom_runner``). A cargo config that is a
symlink, oversized, or not UTF-8 abstains, as do ``rustc-wrapper``,
``linker``, ``rustflags``, a directory source or source replacement, a
build script or ``links`` key, and a ``test_command`` that passes
``--config``. A symlinked, oversized, or non-UTF-8 ``Cargo.toml``, a git
dependency, and a manifest walk that stops with a dependency still unread
abstain the same way. A leading UTF-8 BOM is stripped before the manifest
is parsed so a ``build`` key is not missed. A Cargo workspace, more than
one ``Cargo.toml``, cargo-nextest, and a missing ``rustc`` or ``cargo``
abstain. They are not a culprit.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path

from provebreak_culprit._engine.bisect import _scrub_reason
from provebreak_culprit._engine.bisect import apply_isolated_home
from provebreak_culprit._engine.bisect import build_scrubbed_env
from provebreak_culprit._engine.bisect import make_isolated_home
from provebreak_culprit._engine.toolchain_pin import CARGO_VERSION
from provebreak_culprit._engine.toolchain_pin import RUSTC_VERSION
from provebreak_culprit._engine.toolchain_pin import version_mismatch

MAX_CARGO_ID_LEN = 512
_MAX_SEGMENTS = 16
_SEGMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_GH_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z ?")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_TEST_LINE = re.compile(r"^test (.+?) \.\.\. (ok|FAILED|ignored)\b")
_LIBTEST_RUNNING = re.compile(r"^Running\s+\S.*\(([^)]+)\)\s*$")
_NEXTEST = re.compile(r"(?m)(?:^|\s)(?:Nextest run ID|cargo nextest)\b|^\s*FAIL \[")
_NEXTEST_STATUS = re.compile(
    r"^\s*(FAIL|PASS|SKIP|IGNORED|LEAK)\s+\[[^\]]+\]\s+(\S+)\s+(\S+)\s*$"
)
_WF_CMD = re.compile(r"^##\[[A-Za-z]+\]\s?")
_BUILD = re.compile(
    r"(?m)^error(?:\[E\d+\])?: (?!test failed\b)|^error: could not compile |"
    r"^error: linking with |^error: failed to |^could not compile `"
)
_SKIP_DIRS = frozenset({".git", "target", "node_modules"})
_WORKSPACE = re.compile(
    r"(?m)^\s*\[\s*workspace(?:\s*\.\s*[A-Za-z0-9_.-]+)?\s*\]\s*$"
)
_PACKAGE = re.compile(r"(?m)^\s*\[package\]\s*$")
_TOOLCHAIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,78}$")
_DEFAULT_TOOLCHAIN = re.compile(
    r'(?m)^(?:default_toolchain|default)\s*=\s*"([^"]+)"\s*$'
)


@dataclass
class CargoLog:
    ids: list[str]
    error: str | None = None


def validate_cargo_ids(tests: list | tuple) -> tuple[list[str], str | None]:
    """Libtest path ``module::test``. Doc-test names and flags are refused."""
    if not tests:
        return [], "no_failing_tests_provided"
    clean: list[str] = []
    for raw in tests:
        text = str(raw).strip()
        if not text:
            continue
        if len(text) > MAX_CARGO_ID_LEN:
            return [], f"cargo_id_too_long:{text[:40]}"
        if any(ord(c) < 32 for c in text):
            return [], f"cargo_id_control_chars:{text[:40]}"
        if text.startswith("-") or " " in text or "/" in text or "#" in text:
            return [], f"cargo_unsupported_id:{text[:40]}"
        parts = text.split("::")
        if not 1 <= len(parts) <= _MAX_SEGMENTS or any(not _SEGMENT.fullmatch(part) for part in parts):
            return [], f"cargo_unsupported_id:{text[:40]}"
        if text not in clean:
            clean.append(text)
    return (clean, None) if clean else ([], "no_failing_tests_provided")


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


def _failure_names(lines: list[str]) -> list[str]:
    """Indented names under ``failures:``, not the ``---- stdout ----`` block."""
    names: list[str] = []
    i = 0
    while i < len(lines):
        if lines[i].strip() != "failures:":
            i += 1
            continue
        block: list[str] = []
        j = i + 1
        while j < len(lines):
            raw = lines[j]
            if not raw.strip():
                j += 1
                if block:
                    break
                continue
            if raw.startswith((" ", "\t")):
                name = raw.strip()
                if name.startswith(("----", "thread ")) or " " in name:
                    break
                block.append(name)
                j += 1
                continue
            break
        for name in block:
            clean, err = validate_cargo_ids([name])
            if not err and clean and clean[0] not in names:
                names.append(clean[0])
        i = j
    return names


def _cargo_done(log_text: str, ids: list[str], error: str | None = None) -> CargoLog:
    from provebreak_culprit._engine.summary_gate import finish

    kept, err = finish("cargo", log_text, ids, error)
    return CargoLog(kept, err)


def extract_cargo(log_text: str, *, limit: int = 20) -> CargoLog:
    """Failing libtest ids from a ``cargo test`` log.

    A passing ``ok`` line is not an id. A doc-test name (spaces, a source
    path) is ``cargo_unsupported_id`` when nothing safer was found. Any
    cargo-nextest log, including a JUnit report whose root or testsuite is
    named ``nextest-run``, abstains ``cargo_nextest_unsupported``. Libtest
    lines inside JUnit ``system-out`` or ``system-err`` are the test's own
    print and are not ids. A signal number (``signal: 6``, ``signal 7``),
    a ``SIG`` name, a nextest status word before ``[``, or
    ``process didn't exit successfully`` without one matching libtest
    ``test result:`` failed-count abstains ``cargo_signal_unsupported``.
    A libtest ``test result: FAILED`` with no ``test <id> ... FAILED``
    line cannot name the binary, so it abstains
    ``test_ids_duplicate_across_binaries``. The same test name under two
    ``Running`` binaries does too. Stack traces are not ids.
    """
    if not log_text:
        return _cargo_done(log_text, [])
    raw_lines = _lines(log_text)
    if _is_nextest_junit(log_text, raw_lines):
        return CargoLog([], "cargo_nextest_unsupported")
    # A bannered nextest log abstains as nextest even when it also names a
    # signal. Without the banner, SIGABRT [ / ABORT SIG 7 [ is a signal.
    if _NEXTEST_BANNER.search("\n".join(raw_lines)) or (
        _is_nextest(raw_lines) and not _status_word_bracket(raw_lines)
    ):
        return CargoLog([], "cargo_nextest_unsupported")
    if _has_signal(raw_lines):
        return CargoLog([], "cargo_signal_unsupported")
    if _is_nextest(raw_lines):
        return CargoLog([], "cargo_nextest_unsupported")
    from provebreak_culprit._engine.summary_gate import _mask

    lines, err = _mask("cargo", _lines(_strip_junit_captured(log_text)))
    if err:
        return _cargo_done(log_text, [], err)
    found: list[str] = []
    unsafe = False
    current_bin = ""
    lib_bins: dict[str, set[str]] = {}
    for line in lines:
        running = _LIBTEST_RUNNING.match(line.strip())
        if running:
            current_bin = running.group(1).strip()
            continue
        matched = _TEST_LINE.match(line.strip())
        if not matched:
            continue
        name = matched.group(1).strip()
        clean, err = validate_cargo_ids([name])
        if err or not clean:
            if matched.group(2) == "FAILED":
                unsafe = True
            continue
        lib_bins.setdefault(clean[0], set()).add(current_bin)
        if matched.group(2) != "FAILED":
            continue
        if clean[0] not in found and len(found) < limit:
            found.append(clean[0])
    if any(len(bins) > 1 for bins in lib_bins.values()):
        return _cargo_done(log_text, [], "test_ids_duplicate_across_binaries")
    listed = _failure_names(lines)
    if listed and found:
        kept = [name for name in found if name in listed]
        if kept:
            found = kept
    if found and not unsafe:
        return _cargo_done(log_text, found[:limit])
    if unsafe:
        return _cargo_done(log_text, [], "cargo_unsupported_id")
    if _libtest_failed_unbound(lines):
        return _cargo_done(log_text, [], "test_ids_duplicate_across_binaries")
    return _cargo_done(log_text, [])


_LIBTEST_FAILED = re.compile(r"^test result: FAILED\..*\b(\d+) failed;")


_JUNIT_TAG = re.compile(r"<(?:testsuites|testsuite|testcase)\b", re.IGNORECASE)
_NEXTEST_JUNIT_NAME = re.compile(
    r"""<(?:testsuites|testsuite)\b[^>]*\bname\s*=\s*["']nextest-run["']""",
    re.IGNORECASE,
)
_JUNIT_CAPTURED = re.compile(
    r"<(system-out|system-err)\b[^>]*>.*?</\1\s*>",
    re.IGNORECASE | re.DOTALL,
)
_JUNIT_CAPTURED_OPEN = re.compile(
    r"<(system-out|system-err)\b[^>]*>.*\Z",
    re.IGNORECASE | re.DOTALL,
)
_SIGNAL_NUM = re.compile(r"signal[: ]\s*\d+")
_SIG_NAME = re.compile(r"(?<![A-Z])SIG[A-Z]{3,}(?![A-Z])")
_NEXTEST_BANNER = re.compile(r"(?m)(?:^|\s)(?:Nextest run ID|cargo nextest)\b")
_STATUS_WORD_BRACKET = re.compile(
    r"\b(?:SIGABRT|SIGBUS|SIGSEGV|ABORT|LEAK|TIMEOUT)\b[^\n]*\["
)
_PROCESS_DIED = re.compile(r"process didn't exit successfully")
_TEST_RESULT_FAILED = re.compile(
    r"^test result: (?:ok|FAILED)\. \d+ passed; (\d+) failed;"
)
_TEST_RESULT = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed;"
)
_RUNNING_LINE = re.compile(r"^running (\d+) tests?\b")
_RUNNING_COUNT = re.compile(r"(?m)^running (\d+) tests?\b")
_NEXTEST_ZERO = re.compile(r"\b0 tests run\b")
_NEXTEST_SOME = re.compile(r"\b[1-9]\d* tests? run\b")
_NEXTEST_SUMMARY = re.compile(
    r"\b(\d+) tests? run:\s*(\d+) passed,\s*(\d+) failed\b"
)
_NEXTEST_RUN_COUNT = re.compile(r"\b(\d+) tests? run\b")
_BUILD_SCRIPT_SECTION = re.compile(r"(?m)^[ \t]*--- (?:stdout|stderr)[ \t]*$")
_CARGO_BUILD_FAIL = re.compile(r"failed to run custom build command|could not compile")


def _is_nextest(lines: list[str]) -> bool:
    """True for any cargo-nextest log, including one ``FAIL [time]`` line."""
    if _NEXTEST.search("\n".join(lines)):
        return True
    return any(_NEXTEST_STATUS.match(line.strip()) for line in lines)


def _is_nextest_junit(log_text: str, lines: list[str]) -> bool:
    """A JUnit document from nextest is not a libtest log.

    The root or a ``testsuite`` named ``nextest-run`` is enough. So is any
    other nextest marker carried in that document.
    """
    if not _JUNIT_TAG.search(log_text or ""):
        return False
    if _NEXTEST_JUNIT_NAME.search(log_text):
        return True
    return _is_nextest(lines)


def _status_word_bracket(lines: list[str]) -> bool:
    """A nextest status word and a later ``[`` on the same line.

    ``SIGABRT [``, ``ABORT SIG 7 [``, ``LEAK [``, and ``TIMEOUT [`` are
    this shape. ``FAIL [`` is not.
    """
    return any(_STATUS_WORD_BRACKET.search(line) for line in lines)


def _process_died_unmatched(lines: list[str]) -> bool:
    """``process didn't exit successfully`` with no single matching libtest count.

    One ``test result:`` line whose failed count equals the number of
    ``test <id> ... FAILED`` lines is a match. Any other shape abstains.
    """
    if not any(_PROCESS_DIED.search(line) for line in lines):
        return False
    failed_rows = 0
    counts: list[int] = []
    for line in lines:
        matched = _TEST_LINE.match(line.strip())
        if matched and matched.group(2) == "FAILED":
            failed_rows += 1
        result = _TEST_RESULT_FAILED.match(line.strip())
        if result:
            counts.append(int(result.group(1)))
    return not (len(counts) == 1 and counts[0] == failed_rows)


def _has_signal(lines: list[str]) -> bool:
    """Signal text the test can print next to a fake libtest block.

    ``signal: 6``, ``signal 7``, ``SIGABRT``, a nextest status word before
    ``[``, or a process-died line whose libtest count does not match.
    """
    text = "\n".join(lines)
    if _SIGNAL_NUM.search(text) or _SIG_NAME.search(text):
        return True
    if _status_word_bracket(lines):
        return True
    return _process_died_unmatched(lines)


def _cargo_build_failed(text: str) -> bool:
    """A cargo build failure, before any test line is evidence.

    ``failed to run custom build command``, ``could not compile``, or a
    build-script ``--- stdout`` / ``--- stderr`` section. The indented lines
    under that section are the script's own print, not a harness.
    """
    blob = text or ""
    if _CARGO_BUILD_FAIL.search(blob):
        return True
    return _BUILD_SCRIPT_SECTION.search(blob) is not None


def _crash_exit(returncode: int) -> bool:
    """A signal death. Cargo's own test failure is 101, which is not this."""
    if returncode < 0:
        return True
    return 128 < returncode < 256


def _real_harness_text(text: str) -> str:
    """Closed ``running N`` blocks, and only when cargo started a test binary.

    The runner concatenates stdout then stderr. Cargo prints the harness on
    stdout and ``Running unittests ... (path)`` on stderr, so the header can
    follow the block. A printed block with no ``Running`` header in the log
    is not a harness. Doc-tests have no ``Running ... (path)`` line of their
    own; they count only when a unit-test binary was started.
    """
    lines = _lines(text)
    if not any(_LIBTEST_RUNNING.match(line.strip()) for line in lines):
        return ""
    parts: list[str] = []
    for block in _harness_blocks(text):
        if block["summary"] is None:
            continue
        word = "test" if block["n"] == 1 else "tests"
        parts.append(f"running {block['n']} {word}")
        parts.extend(block["lines"])
    return "\n".join(parts)


def _nextest_fail_line(text: str) -> bool:
    for line in _lines(text):
        matched = _NEXTEST_STATUS.match(line.strip())
        if matched and matched.group(1) == "FAIL":
            return True
    return False


def _harness_blocks(text: str) -> list[dict]:
    """Libtest harness blocks. A block starts at ``running N``.

    It stays open through every later ``test result:`` until the next
    ``running M``. The first summary is ``summary``. A planted summary
    must not close the block and drop libtest's own summary. A printed
    ``running N`` with no summary stays an open block. An empty doc-test
    harness is its own block (``running 0`` plus ``0 passed; 0 failed``).
    """
    blocks: list[dict] = []
    current: dict | None = None
    for line in _lines(text):
        stripped = line.strip()
        running = _RUNNING_LINE.match(stripped)
        if running:
            if current is not None:
                blocks.append(current)
            current = {"n": int(running.group(1)), "lines": [], "summary": None, "summaries": 0}
            continue
        if current is None:
            continue
        current["lines"].append(stripped)
        summary = _TEST_RESULT.match(stripped)
        if summary is None:
            continue
        current["summaries"] += 1
        if current["summary"] is None:
            current["summary"] = (
                summary.group(1),
                int(summary.group(2)),
                int(summary.group(3)),
            )
    if current is not None:
        blocks.append(current)
    return blocks


def _duplicate_summary_in_running_section(text: str) -> bool:
    """One ``Running`` harness section contains two ``test result:`` lines."""
    lines = _lines(text)
    if not any(_LIBTEST_RUNNING.match(line.strip()) for line in lines):
        return False
    return any(int(block.get("summaries") or 0) > 1 for block in _harness_blocks(text))


def _benign_empty_extra(text: str) -> bool:
    """One real summary, and every other closed block is an empty doc-test.

    ``cargo test -- --exact`` on a passing crate prints ``running 0`` and
    ``0 passed; 0 failed`` for doc-tests. That second summary is not a
    planted close of the unit-test harness.
    """
    closed = [block for block in _harness_blocks(text) if block["summary"] is not None]
    if not closed:
        return False
    real = []
    for block in closed:
        if int(block.get("summaries") or 0) != 1:
            return False
        status, passed, failed = block["summary"]
        if block["n"] == 0 and status == "ok" and passed == 0 and failed == 0:
            continue
        real.append(block)
    if len(real) != 1:
        return False
    _status, passed, failed = real[0]["summary"]
    return passed + failed > 0


def _extract_blocks_red(error: str | None, text: str) -> bool:
    """True when extract abstained and that abstain must not stay red.

    A pass summary does not block green, and it is not consulted here.
    An empty doc-test beside one real summary is still that real result.
    """
    if not error or error == "summary_reports_pass":
        return False
    if error == "test_ids_multiple_summaries" and _benign_empty_extra(text):
        return False
    return True


def selected_no_tests(text: str) -> bool:
    """The exact filter ran nothing.

    Any ``0 tests run`` counts, even next to another ``N tests run``.
    A harness ``running 0 tests`` counts even next to a printed ``running N``
    that has no ``test result:``. A closed harness that actually ran tests
    (passed + failed > 0) is not this case: that is the empty doc-test
    harness beside a real ``running 1`` block.
    """
    if _NEXTEST_ZERO.search(text or ""):
        return True
    blocks = _harness_blocks(text)
    if not any(block["n"] == 0 for block in blocks):
        return False
    for block in blocks:
        summary = block["summary"]
        if block["n"] > 0 and summary is not None and summary[1] + summary[2] > 0:
            return False
    return True


def _conflicting_run_counts(text: str) -> bool:
    """Two different positive ``running N`` or ``N tests run`` counts."""
    running = {int(n) for n in _RUNNING_COUNT.findall(text or "") if int(n) > 0}
    if len(running) > 1:
        return True
    nextest = {int(n) for n in _NEXTEST_RUN_COUNT.findall(text or "") if int(n) > 0}
    return len(nextest) > 1


def _libtest_summaries(text: str) -> list[tuple[str, int, int]]:
    found = []
    for line in _lines(text):
        matched = _TEST_RESULT.match(line.strip())
        if matched:
            found.append((matched.group(1), int(matched.group(2)), int(matched.group(3))))
    return found


def _line_outcomes(text: str) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for line in _lines(text):
        matched = _TEST_LINE.match(line.strip())
        if not matched:
            continue
        clean, err = validate_cargo_ids([matched.group(1).strip()])
        if err or not clean:
            continue
        found.setdefault(clean[0], set()).add(matched.group(2))
    return found


def _failure_marker(text: str) -> bool:
    """A libtest ``FAILED`` line or a nextest ``FAIL [`` line."""
    for line in _lines(text):
        stripped = line.strip()
        matched = _TEST_LINE.match(stripped)
        if matched and matched.group(2) == "FAILED":
            return True
        nxt = _NEXTEST_STATUS.match(stripped)
        if nxt and nxt.group(1) == "FAIL":
            return True
    return False


def _nextest_says_nothing_failed(text: str) -> bool:
    for _ran, _passed, failed in _NEXTEST_SUMMARY.findall(text or ""):
        if int(failed) < 1:
            return True
    return False


def _consistent_libtest_red(text: str, ids: list[str]) -> bool:
    """One ``test result: FAILED`` whose failed count matches the FAILED lines.

    An empty doc-test ``test result: ok`` (0 passed, 0 failed) may sit beside
    that summary. A summary that passed the selected id, or a second FAILED
    summary, is not consistent. The selected id must be FAILED and not also ok.
    """
    summaries = _libtest_summaries(text)
    failed_summaries = [row for row in summaries if row[0] == "FAILED"]
    if len(failed_summaries) != 1:
        return False
    _status, _passed, failed_n = failed_summaries[0]
    if failed_n < 1:
        return False
    for status, passed, failed in summaries:
        if status == "ok" and not (passed == 0 and failed == 0):
            return False
    if _nextest_says_nothing_failed(text):
        return False
    seen = _line_outcomes(text)
    failed_ids = [name for name, kinds in seen.items() if kinds == {"FAILED"}]
    if len(failed_ids) != failed_n:
        return False
    return all(name in failed_ids for name in ids)


def _strip_junit_captured(log_text: str) -> str:
    """Drop JUnit ``system-out`` and ``system-err``. That text is untrusted."""
    if not _JUNIT_TAG.search(log_text or ""):
        return log_text

    def _empty(matched: re.Match[str]) -> str:
        tag = matched.group(1)
        return f"<{tag}></{tag}>"

    stripped = _JUNIT_CAPTURED.sub(_empty, log_text)
    return _JUNIT_CAPTURED_OPEN.sub(_empty, stripped)


def _libtest_failed_unbound(lines: list[str]) -> bool:
    """A libtest summary counted failures, but no ``test <id> ... FAILED`` id was kept.

    The ``failures:`` list and ``--test <binary>`` hint do not say which
    binary owns a bare name such as ``it_works``. That is
    ``test_ids_duplicate_across_binaries``, including when two binaries
    share the name.
    """
    for line in lines:
        matched = _LIBTEST_FAILED.match(line.strip())
        if matched and int(matched.group(1)) > 0:
            return True
    return False


def _manifests(root: Path) -> list[tuple[Path, str]]:
    found: list[tuple[Path, str]] = []
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
        if "Cargo.toml" not in filenames:
            continue
        path = Path(dirpath) / "Cargo.toml"
        try:
            if path.is_symlink() or path.stat().st_size > 500_000:
                continue
            text = path.read_text(encoding="utf-8-sig", errors="replace")[:500_000]
        except OSError:
            continue
        found.append((path, text))
        if len(found) > 20:
            break
    return found


def cargo_layout(root: Path) -> tuple[str, str | None]:
    """``('cargo_single', None)`` or ``('unsupported', reason)``.

    One ``[package]`` manifest and no ``[workspace]`` table is the only
    layout this runner executes.
    """
    rows = _manifests(Path(root))
    if not rows:
        return "unsupported", "cargo_no_manifest"
    if any(_WORKSPACE.search(text) for _path, text in rows):
        return "unsupported", "cargo_workspace_unsupported"
    packages = [path for path, text in rows if _PACKAGE.search(text)]
    if len(packages) == 1 and len(rows) == 1:
        return "cargo_single", None
    if len(rows) > 1 or len(packages) > 1:
        return "unsupported", "cargo_multicrate_ambiguous"
    return "unsupported", "cargo_no_manifest"


def cargo_manifest(root: Path) -> Path | None:
    layout, _reason = cargo_layout(root)
    if layout != "cargo_single":
        return None
    packages = [path for path, text in _manifests(Path(root)) if _PACKAGE.search(text)]
    return packages[0] if len(packages) == 1 else None


_RUNNER_ENV = re.compile(r"^CARGO_TARGET_[A-Z0-9_]+_RUNNER$")
_TOML_COMMENT = re.compile(r"(?m)#.*$")
_CONFIG_REASONS = (
    ("runner", "cargo_custom_runner"),
    ("rustc-workspace-wrapper", "cargo_rustc_wrapper"),
    ("rustc-wrapper", "cargo_rustc_wrapper"),
    ("rustc", "cargo_rustc_wrapper"),
    ("linker", "cargo_custom_linker"),
    ("rustflags", "cargo_rustflags"),
    ("directory", "cargo_directory_source"),
    ("local-registry", "cargo_source_replacement"),
    ("replace-with", "cargo_source_replacement"),
)
_CONFIG_BYTE_CAP = 500_000


def _read_capped(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _CONFIG_BYTE_CAP:
            return None
        return path.read_text(encoding="utf-8-sig", errors="replace")[:_CONFIG_BYTE_CAP]
    except OSError:
        return None


def _value_set(value: object) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return len(value) > 0
    return value not in (None, False)


def _has_key(node: object, key: str) -> bool:
    if isinstance(node, dict):
        if key in node and _value_set(node.get(key)):
            return True
        return any(_has_key(child, key) for child in node.values())
    if isinstance(node, list):
        return any(_has_key(child, key) for child in node)
    return False


def _reason_in_config_text(text: str) -> str | None:
    """A runner, wrapper, linker, rustflags, or source-replacement key."""
    if text.startswith("\ufeff"):
        text = text[1:]
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        stripped = _TOML_COMMENT.sub("", text)
        for key, reason in _CONFIG_REASONS:
            if re.search(rf"(?m)^\s*{re.escape(key)}\s*=", stripped):
                return reason
        return None
    if not isinstance(data, dict):
        return None
    for key, reason in _CONFIG_REASONS:
        if _has_key(data, key):
            return reason
    return None


def _config_file_reason(path: Path) -> str | None:
    """Abstain when cargo would read a config this process must not trust.

    A symlink, a file over 500000 bytes, and bytes that are not UTF-8 are
    not inspected. Cargo follows the link and reads the large file.
    """
    try:
        if path.is_symlink():
            return "cargo_config_symlink"
        if not path.is_file():
            return None
        if path.stat().st_size > _CONFIG_BYTE_CAP:
            return "cargo_config_oversize"
        raw = path.read_bytes()
    except OSError:
        return "cargo_config_unreadable"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return "cargo_config_unreadable"
    return _reason_in_config_text(text)


def _config_paths(crate: Path, env: dict[str, str]) -> list[Path]:
    """Project config cargo would read, then the child's ``CARGO_HOME``."""
    found: list[Path] = []
    current = Path(crate)
    try:
        current = current.resolve()
    except OSError:
        return found
    for _ in range(12):
        found.append(current / ".cargo" / "config.toml")
        found.append(current / ".cargo" / "config")
        if current.parent == current:
            break
        current = current.parent
    cargo_home = (env.get("CARGO_HOME") or "").strip()
    if cargo_home and "\n" not in cargo_home and "\r" not in cargo_home:
        home = Path(cargo_home)
        found.append(home / "config.toml")
        found.append(home / "config")
    return found


def _config_abstain(crate: Path, env: dict[str, str]) -> str | None:
    for key, value in env.items():
        if _RUNNER_ENV.fullmatch(key) and str(value).strip():
            return "cargo_custom_runner"
    for path in _config_paths(crate, env):
        reason = _config_file_reason(path)
        if reason:
            return reason
    return None


_SCRIPT_CAP = 64
_DEP_KEYS = ("dependencies", "dev-dependencies", "build-dependencies")


def _load_manifest(path: Path) -> dict | None:
    text = _read_capped(path)
    if not text:
        return None
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _expand_member(base: Path, pattern: str) -> tuple[list[Path], bool]:
    """One workspace member path. ``*`` is a single directory level.

    The bool is true when the expansion hit ``_SCRIPT_CAP`` and dropped
    the rest. Those dropped directories are not a clean walk.
    """
    text = pattern.strip().replace("\\", "/").rstrip("/")
    if not text or text.startswith("/") or "\x00" in text:
        return [], False
    dirs = [base]
    truncated = False
    for part in text.split("/"):
        nxt: list[Path] = []
        for directory in dirs:
            if part == "*":
                try:
                    kids = list(directory.iterdir())
                except OSError:
                    continue
                for kid in kids:
                    try:
                        if kid.is_dir():
                            nxt.append(kid)
                    except OSError:
                        continue
            elif part and part != ".":
                nxt.append(directory / part)
        dirs = nxt
        if len(dirs) > _SCRIPT_CAP:
            del dirs[_SCRIPT_CAP:]
            truncated = True
            break
    return dirs, truncated


def _path_dep_dirs(base: Path, table: object) -> list[Path]:
    if not isinstance(table, dict):
        return []
    found: list[Path] = []
    for value in table.values():
        if not isinstance(value, dict):
            continue
        raw = value.get("path")
        if not isinstance(raw, str):
            continue
        raw = raw.strip()
        if raw and "\n" not in raw and "\r" not in raw and "\x00" not in raw:
            found.append(base / raw)
    return found


def _dep_tables(data: dict) -> list[object]:
    tables: list[object] = [data.get(key) for key in _DEP_KEYS]
    target = data.get("target")
    if isinstance(target, dict):
        for node in target.values():
            if isinstance(node, dict):
                tables.extend(node.get(key) for key in _DEP_KEYS)
    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        tables.append(workspace.get("dependencies"))
    patch = data.get("patch")
    if isinstance(patch, dict):
        tables.extend(node for node in patch.values() if isinstance(node, dict))
    return tables


def _enqueue_manifest(found: list[Path], child: Path) -> None:
    try:
        if child.is_symlink() or child.is_file():
            found.append(child)
    except OSError:
        return


def _member_manifests(manifest: Path, data: dict) -> tuple[list[Path], bool]:
    workspace = data.get("workspace")
    if not isinstance(workspace, dict):
        return [], False
    base = manifest.parent
    members = workspace.get("members")
    exclude = workspace.get("exclude")
    if not isinstance(members, list):
        members = []
    if not isinstance(exclude, list):
        exclude = []
    truncated = False
    excluded: set[str] = set()
    for item in exclude:
        if not isinstance(item, str):
            continue
        directories, hit = _expand_member(base, item)
        truncated = truncated or hit
        for directory in directories:
            try:
                excluded.add(str(directory.resolve()))
            except OSError:
                excluded.add(str(directory))
    found: list[Path] = []
    for item in members:
        if not isinstance(item, str):
            continue
        directories, hit = _expand_member(base, item)
        truncated = truncated or hit
        for directory in directories:
            try:
                key = str(directory.resolve())
            except OSError:
                key = str(directory)
            if key in excluded:
                continue
            _enqueue_manifest(found, directory / "Cargo.toml")
    return found, truncated


def _child_manifests(manifest: Path, data: dict) -> tuple[list[Path], bool]:
    base = manifest.parent
    found, truncated = _member_manifests(manifest, data)
    for table in _dep_tables(data):
        for directory in _path_dep_dirs(base, table):
            _enqueue_manifest(found, directory / "Cargo.toml")
    return found, truncated


def _build_script_here(manifest: Path, package: object) -> bool:
    """``build.rs`` beside the manifest, or ``build`` set to something other than false."""
    try:
        if (manifest.parent / "build.rs").is_file():
            return True
    except OSError:
        pass
    if not isinstance(package, dict) or "build" not in package:
        return False
    return package.get("build") is not False


def _links_here(package: object) -> bool:
    if not isinstance(package, dict) or "links" not in package:
        return False
    return package.get("links") is not False


def _has_git_dep(data: dict) -> bool:
    for table in _dep_tables(data):
        if not isinstance(table, dict):
            continue
        for value in table.values():
            if isinstance(value, dict) and _value_set(value.get("git")):
                return True
    return False


def _manifest_access_reason(path: Path) -> str | None:
    """Symlink, oversize, and non-UTF-8 manifests are not parsed.

    Cargo follows the link and reads the large file. Skipping either one
    misses a ``build`` key. A leading UTF-8 BOM is not a reason: it is
    stripped so the key can be read.
    """
    try:
        if path.is_symlink():
            return "cargo_manifest_symlink"
        if not path.is_file():
            return None
        if path.stat().st_size > _CONFIG_BYTE_CAP:
            return "cargo_manifest_oversize"
        raw = path.read_bytes()
    except OSError:
        return "cargo_manifest_unreadable"
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return "cargo_manifest_unreadable"
    return None


def _pending_unseen(pending: list[Path], seen: set[str]) -> bool:
    for manifest in pending:
        try:
            key = str(manifest.resolve())
        except OSError:
            key = str(manifest)
        if key not in seen:
            return True
    return False


def cargo_script_gate(root: Path) -> str | None:
    """Build script, ``links``, or a manifest this process must not trust.

    Script text is not read. ``cargo_build_script_present`` wins when a
    build script is in the closure. A git dependency is
    ``cargo_git_dependency`` when the walk finishes without a build script.
    Stopping at ``_SCRIPT_CAP`` with a manifest still unread, or a member
    glob that dropped directories, is ``cargo_script_cap``.
    ``cargo_links_present`` is only when that walk finished and found links.
    """
    start = Path(root) / "Cargo.toml"
    try:
        if not start.is_symlink() and not start.is_file():
            return None
    except OSError:
        return "cargo_manifest_unreadable"
    pending = [start]
    seen: set[str] = set()
    links = False
    git_dep = False
    capped = False
    while pending and len(seen) < _SCRIPT_CAP:
        manifest = pending.pop(0)
        try:
            key = str(manifest.resolve())
        except OSError:
            key = str(manifest)
        if key in seen:
            continue
        seen.add(key)
        reason = _manifest_access_reason(manifest)
        if reason:
            return reason
        data = _load_manifest(manifest)
        package = data.get("package") if isinstance(data, dict) else None
        if _build_script_here(manifest, package):
            return "cargo_build_script_present"
        if _links_here(package):
            links = True
        if isinstance(data, dict):
            if _has_git_dep(data):
                git_dep = True
            children, truncated = _child_manifests(manifest, data)
            capped = capped or truncated
            pending.extend(children)
    if capped or _pending_unseen(pending, seen):
        return "cargo_script_cap"
    if git_dep:
        return "cargo_git_dependency"
    if links:
        return "cargo_links_present"
    return None


def cargo_test_command_abstain(command: object) -> str | None:
    """``--config`` on the action's cargo argv is not a test result."""
    if not command:
        return None
    try:
        args = list(command)
    except TypeError:
        return None
    for arg in args:
        text = str(arg)
        if text == "--config" or text.startswith("--config="):
            return "cargo_test_command_config"
    return None


def _has_harness_false(node: object) -> bool:
    if isinstance(node, dict):
        if node.get("harness") is False:
            return True
        return any(_has_harness_false(child) for child in node.values())
    if isinstance(node, list):
        return any(_has_harness_false(child) for child in node)
    return False


def cargo_target_abstain(crate: Path, env: dict[str, str] | None = None) -> str | None:
    """A custom runner, wrapper, linker, rustflags, build script, or links key.

    Checked on the checkout before cargo runs. A symlinked, oversized, or
    non-UTF-8 config abstains without being parsed, as does a directory
    source or ``replace-with``. A build script is ``build.rs`` beside a
    manifest, or ``build`` other than false, including on a workspace member
    or path dependency. A symlinked, oversized, or non-UTF-8 manifest, a
    git dependency, and an unfinished manifest walk abstain. A leading BOM
    is stripped before the ``build`` key is read. ``[[bin]] test = false``
    is not ``cargo_test_false``. ``CARGO_TARGET_DIR`` is not a runner.
    ``harness = false`` and ``[lib] test = false`` still abstain.
    """
    child = dict(env or {})
    root = Path(crate)
    config = _config_abstain(root, child)
    if config:
        return config
    script = cargo_script_gate(root)
    if script:
        return script
    text = _read_capped(root / "Cargo.toml")
    if text is None:
        return None
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    if _has_harness_false(data):
        return "cargo_harness_false"
    lib = data.get("lib")
    if isinstance(lib, dict) and lib.get("test") is False:
        return "cargo_test_false"
    return None


def repo_suggests_cargo(root: Path) -> bool:
    layout, reason = cargo_layout(root)
    if layout == "cargo_single":
        return True
    return reason in {"cargo_workspace_unsupported", "cargo_multicrate_ambiguous"}


def _executable(name: str) -> bool:
    if not name or any(ord(c) < 32 for c in name):
        return False
    path = Path(name)
    if path.is_file() and os.access(path, os.X_OK):
        return True
    return shutil.which(name) is not None


def toolchain_error(cargo_bin: str = "cargo") -> str | None:
    """Missing binary, then the one-click pin. A wrong version is not a culprit."""
    if not _executable(cargo_bin):
        return "cargo_missing"
    if not _executable("rustc"):
        return "rustc_missing"
    why = version_mismatch([cargo_bin, "--version"], CARGO_VERSION, "cargo_version_mismatch")
    if why:
        return why
    return version_mismatch(["rustc", "--version"], RUSTC_VERSION, "rustc_version_mismatch")


def _rustup_home() -> str:
    """The job's rustup directory, when cargo is a rustup proxy.

    An isolated ``HOME`` would hide it, and ``cargo`` would then abstain
    with ``rustup could not choose a version``. A checkout's
    ``rust-toolchain`` file is not this directory.
    """
    raw = os.environ.get("RUSTUP_HOME") or ""
    if raw and "\n" not in raw and "\r" not in raw and Path(raw).is_dir():
        return raw
    for candidate in (Path.home() / ".rustup", Path("/usr/local/rustup")):
        if candidate.is_dir():
            return str(candidate)
    return ""


def _default_toolchain(rustup_home: str) -> str:
    explicit = os.environ.get("RUSTUP_TOOLCHAIN") or ""
    if _TOOLCHAIN.fullmatch(explicit):
        return explicit
    path = Path(rustup_home) / "settings.toml"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")[:20_000]
    except OSError:
        return ""
    matched = _DEFAULT_TOOLCHAIN.search(text)
    if matched and _TOOLCHAIN.fullmatch(matched.group(1)):
        return matched.group(1)
    return ""


def cargo_child_env(home: Path, cache: Path, *, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Scrubbed env. ``CARGO_HOME`` is the bisect cache, not the job's home.

    Registry tokens stay out: ``build_scrubbed_env`` drops names that contain
    ``TOKEN``. ``RUSTUP_HOME`` and ``RUSTUP_TOOLCHAIN`` stay on the runner's
    compiler so a ``rust-toolchain`` file in the checkout cannot select one.
    This does not vendor crates and does not read a credential file.
    """
    cargo_home = Path(cache) / "cargo-home"
    cargo_home.mkdir(parents=True, exist_ok=True)
    overlay: dict[str, str] = {
        "CARGO_HOME": str(cargo_home),
        "CARGO_TERM_COLOR": "never",
        "GIT_TERMINAL_PROMPT": "0",
    }
    rustup_home = _rustup_home()
    if rustup_home:
        overlay["RUSTUP_HOME"] = rustup_home
        toolchain = _default_toolchain(rustup_home)
        if toolchain:
            overlay["RUSTUP_TOOLCHAIN"] = toolchain
    if extra:
        for key, value in extra.items():
            if value is not None:
                overlay[key] = value
    env = build_scrubbed_env(extra=overlay, home=str(home))
    apply_isolated_home(env, home)
    env["CARGO_HOME"] = str(cargo_home)
    env["CARGO_TERM_COLOR"] = "never"
    if rustup_home:
        env["RUSTUP_HOME"] = rustup_home
        toolchain = _default_toolchain(rustup_home)
        if toolchain:
            env["RUSTUP_TOOLCHAIN"] = toolchain
    return env


def cargo_test_argv(cargo: str, tests: list[str], *, locked: bool) -> list[str]:
    cmd = [cargo, "test", "--color", "never"]
    if locked:
        cmd.append("--locked")
    cmd.extend(["--", "--exact", *tests])
    return cmd


def _outcomes(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    rank = {"pass": 1, "skip": 2, "fail": 3}
    for line in _lines(text):
        matched = _TEST_LINE.match(line.strip())
        if not matched:
            continue
        name = matched.group(1).strip()
        clean, err = validate_cargo_ids([name])
        if err or not clean:
            continue
        label = {"ok": "pass", "FAILED": "fail", "ignored": "skip"}[matched.group(2)]
        previous = found.get(clean[0])
        if previous is None or rank[label] > rank[previous]:
            found[clean[0]] = label
    return found


def _failure_detail(text: str) -> str:
    lines = []
    for raw in _lines(text):
        line = raw.strip()
        if not line:
            continue
        if "panicked at" in line or line.startswith("assertion ") or line.startswith("assert"):
            lines.append(line)
    if not lines:
        lines = [ln.strip() for ln in _lines(text) if ln.strip()][-3:]
    return " | ".join(lines[:3])


def classify_cargo(
    output: str,
    tests: list[str],
    *,
    returncode: int,
) -> tuple[str, str, str, str]:
    """``(label, kind, detail, failure_shape)`` for the requested ids.

    Exit 0 is not green. Green requires every requested id to have a
    ``test <id> ... ok`` line from this run. A build failure is
    ``cargo_build_failed`` before any of that. Red requires a non-zero
    exit that is not a signal, one ``Running`` harness, and one
    ``test result: FAILED`` summary in that harness whose failed count
    matches the FAILED lines inside it. A second summary in that same
    section is ``test_ids_multiple_summaries``. Anything outside that
    harness is not a failure. Exit 0, or ``test result: ok`` / 0 failed,
    plus a FAILED line inside the harness is ``cargo_result_disagreed``.
    A nextest ``FAIL [`` line uses that same gate and is never red on its
    own. When extract abstains, this is not red. A pass summary, and an
    empty doc-test beside one real summary, keep the result they already
    had. A signal exit, or a log extract that abstains as
    ``cargo_signal_unsupported`` or ``cargo_unsupported_id``, abstains
    here with that reason.
    """
    clean, err = validate_cargo_ids(tests)
    text = output or ""
    detail = _scrub_reason(_failure_detail(text), max_len=200)
    if err or not clean:
        return "error", "unknown", detail or (err or "cargo_unsupported_id"), ""
    # Before any test line. A build script can print a whole harness.
    if _cargo_build_failed(text):
        return "error", "unknown", "cargo_build_failed", ""
    extracted = extract_cargo(text)
    if extracted.error in {"cargo_signal_unsupported", "cargo_unsupported_id"}:
        return "error", "unknown", extracted.error, ""
    if _crash_exit(returncode):
        return "error", "unknown", "cargo_signal_unsupported", ""
    # Before any FAILED line. A printed ``running 1 test`` does not cancel
    # a harness ``running 0 tests`` / ``0 tests run``.
    if selected_no_tests(text):
        return "error", "not_found", "filter_selected_no_tests", ""
    if _conflicting_run_counts(text):
        return "error", "unknown", "cargo_inconsistent_run", ""
    # A planted ``test result:`` must not close the block and hide libtest's.
    if _duplicate_summary_in_running_section(text):
        return "error", "unknown", "test_ids_multiple_summaries", ""
    harness = _real_harness_text(text)
    if _failure_marker(harness) or _nextest_fail_line(text):
        # Red only when the process exit and one harness summary agree.
        # A nextest FAIL line is a failure marker, so exit 0 is disagreed
        # and a summary outside the Running harness cannot be red.
        # Extract abstains are not red. An empty doc-test summary is.
        if returncode != 0 and _failure_marker(harness) and _consistent_libtest_red(harness, clean):
            if _extract_blocks_red(extracted.error, text):
                return "error", "unknown", extracted.error, ""
            shape = "assertion" if re.search(r"assertion|assert_eq|assert!", text) else ""
            return "red", "fail", detail or "cargo_fail", shape
        return "error", "unknown", "cargo_result_disagreed", ""
    outcomes = _outcomes(text)
    statuses = [outcomes.get(name, "missing") for name in clean]
    if any(status == "missing" for status in statuses):
        if _BUILD.search(text) or (returncode != 0 and "test result:" not in text):
            return "error", "build_error", detail or "build_failed", ""
        return "error", "not_found", detail or "test_not_in_output", ""
    if any(status == "skip" for status in statuses):
        return "error", "skipped", detail or "test_ignored", ""
    if returncode != 0:
        return "error", "package_fail", detail or f"exit_{returncode}_with_target_passed", ""
    return "green", "pass", detail or "cargo_pass", ""


def preflight_cargo() -> tuple[bool, str]:
    why = toolchain_error()
    if why:
        return False, why
    home = make_isolated_home()
    try:
        env = cargo_child_env(home, home / "cache")
        for cmd, reason in ((["cargo", "--version"], "cargo_missing"), (["rustc", "--version"], "rustc_missing")):
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=60, env=env, cwd=str(home),
                )
            except (OSError, subprocess.TimeoutExpired):
                return False, reason
            if result.returncode != 0:
                return False, reason
        return True, ""
    finally:
        shutil.rmtree(home, ignore_errors=True)
