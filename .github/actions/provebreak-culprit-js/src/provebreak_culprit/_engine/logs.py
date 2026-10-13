"""Extract failure, runner, and dependency facts from CI logs.

Pytest node ids prefer the security-reviewed bisect helper when that module
is installed (confirm-culprit). This module does not implement bisect.
"""
from __future__ import annotations

import re
from typing import Any

_GH_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\s?")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Node id may carry a parametrize id with spaces, e.g. test_x[plain notepad].
_FAILED = re.compile(r"^FAILED\s+(\S+?\.py::[^\s\[]+(?:\[[^\]\n]*\])?|\S+)")
_PASSED = re.compile(r"^PASSED\s+(\S+)")
_PASSED_SUFFIX = re.compile(r"^(\S+\.py::\S+)\s+PASSED\b")
# Only pytest failure section headers ("_____ tests/x.py::t _____"). A bare
# "tests/x.py::t PASSED [ 0%]" verbose line must never count as a failure.
_TESTS_NODE = re.compile(r"^_{3,}\s+(?:ERROR at \w+ of )?(tests/\S+\.py::\S+)\s+_{3,}\s*$")

_PYTEST_E = re.compile(
    r"^E\s+([A-Za-z_][\w.]*(?:Error|Exception|Interrupt|Exit))\b\s*:?\s*(.*)$"
)
_GENERIC_EXC = re.compile(
    r"^([A-Za-z_][\w.]*(?:Error|Exception))\s*:\s*(.+)$"
)
_FRAME = re.compile(r'File "([^"]+)", line (\d+), in (\S+)')
_PY_LOC = re.compile(r"^(\S+\.py):(\d+):\s+([A-Za-z_][\w.]*(?:Error|Exception))", re.MULTILINE)

_NPM_FAIL = re.compile(r"^FAIL\s+(\S+)")
_JEST_TEST = re.compile(r"^\s*●\s+(.+)$")
_NPM_ERR = re.compile(r"^npm ERR!\s+(?!code\b)(?!peer\b)(.+)$")

_INSTALL = re.compile(
    r"(ModuleNotFoundError|ImportError|Could not find a version|"
    r"No matching distribution|ResolutionImpossible|ERESOLVE|"
    r"npm ERR!|SolverProblemError|No solution found|"
    r"ERROR:\s*Cannot install|Couldn't find package|"
    r"failed to select a version|Cannot find module)",
    re.IGNORECASE,
)
_NO_MODULE = re.compile(r"No module named ['\"]([^'\"]+)['\"]")
_NO_JS_MODULE = re.compile(r"Cannot find module ['\"]([^'\"]+)['\"]")
_PIP_DIST = re.compile(
    r"(?:No matching distribution found for|Could not find a version that satisfies the requirement)\s+([A-Za-z0-9_.\-]+)",
    re.IGNORECASE,
)

_PIP_OK = re.compile(r"^Successfully installed (.+)$")
_PIP_REQ = re.compile(
    r"^Requirement already satisfied:\s+([A-Za-z0-9_.\-]+)==([0-9][^\s;]*)",
    re.IGNORECASE,
)
_UV_PIN = re.compile(r"^\s*[+~-]\s+([A-Za-z0-9_.\-]+)==([0-9][^\s]*)")
_POETRY = re.compile(r"Installing\s+([A-Za-z0-9_.\-]+)\s+\(([0-9][^)\s]*)\)")
_NPM_EXACT = re.compile(
    r"(?:^|[\s├└─])(@?[A-Za-z0-9._/-]+)@(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?)"
)
_PNPM = re.compile(r"^\s*\+\s+(@?[A-Za-z0-9._/-]+)\s+(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?)\s*$")
_PIP_TOKEN = re.compile(r"^(.+)-(\d+\.\d+\S*)$")

_STDLIB = frozenset(
    {
        "sys",
        "os",
        "re",
        "json",
        "typing",
        "pathlib",
        "collections",
        "itertools",
        "functools",
        "abc",
        "builtins",
        "importlib",
        "unittest",
        "pkgutil",
    }
)

_NODE_ID_PATH = re.compile(r"^[\w./\-]+\.py$")


def strip_log_prefixes(text: str) -> str:
    """Drop GitHub log timestamps and ANSI codes so anchors match real lines."""
    if not text:
        return ""
    out: list[str] = []
    for line in text.splitlines():
        line = _ANSI.sub("", line.lstrip("\ufeff"))
        line = _GH_TS.sub("", line)
        out.append(line)
    return "\n".join(out)


# v5 dedupe: one reviewed node-id validator and one failing-test extractor, both in
# bisect.py (security-reviewed; PASSED lines are never failures). The intel copies
# (_node_id_ok / _extract_failing_tests_from_log) were removed.
from provebreak_culprit._engine.bisect import _LOG_ANSI as _ANSI  # noqa: E402,F811
from provebreak_culprit._engine.bisect import _LOG_GH_TS as _GH_TS  # noqa: E402,F811
from provebreak_culprit._engine.bisect import (
    extract_failing_tests_from_log as _reviewed_extract,  # noqa: E402
)
from provebreak_culprit._engine.bisect import validate_node_ids as _validate_node_ids  # noqa: E402


def _node_id_ok(nid: str) -> bool:
    """One id through the reviewed bisect validator."""
    clean, err = _validate_node_ids([str(nid)])
    return not err and len(clean) == 1 and clean[0] == str(nid).strip()


def extract_pytest_node_ids(log_text: str, *, limit: int = 20) -> list[str]:
    """Failing pytest node ids (reviewed bisect extractor; never PASSED lines)."""
    text = strip_log_prefixes(log_text or "")
    try:
        ids = _reviewed_extract(text, limit=limit)
    except Exception:  # noqa: BLE001
        ids = []
    out: list[str] = []
    seen: set[str] = set()
    for nid in ids or []:
        s = str(nid).strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
        if len(out) >= limit:
            break
    return out


def _collect_node_ids(log_text: str, pattern: re.Pattern[str], *, limit: int = 40) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for line in log_text.splitlines():
        m = pattern.match(line.strip())
        if not m:
            continue
        nid = m.group(1).strip()
        if not _node_id_ok(nid) or nid in seen:
            continue
        seen.add(nid)
        found.append(nid)
        if len(found) >= limit:
            break
    return found


def _basename(path: str) -> str:
    path = path.replace("\\", "/").split("?", 1)[0]
    return path.rstrip("/").split("/")[-1] or path


def _relevant_frame(path: str) -> bool:
    p = path.replace("\\", "/")
    bad = ("site-packages", "dist-packages", "/usr/lib", "lib/python", "<frozen", "/pytest/")
    return not any(b in p for b in bad)


_SUMMARY_REASON = re.compile(r"^(?:FAILED|ERROR)\s+\S+?\.py::\S+?(?:\[[^\]\n]*\])?\s+-\s+(.+)$")
_REASON_TYPE = re.compile(r"^([A-Za-z_][\w.]*)\s*:\s*(.*)$")


def first_failed_reason(log_text: str) -> tuple[str, str]:
    """(type, message) from the FIRST pytest short-summary ``FAILED id - reason`` line.

    v5: used only for the display headline (experimental, off by default). The
    fingerprint keeps using _first_exception so validated seen-before matches do
    not change. Handles Warnings and ``Failed:`` that _PYTEST_E skips.
    """
    for line in (log_text or "").splitlines():
        m = _SUMMARY_REASON.match(line.strip())
        if not m:
            continue
        reason = m.group(1).strip()
        t = _REASON_TYPE.match(reason)
        if t and " " not in t.group(1):
            return t.group(1), t.group(2).strip()
        return "", reason
    return "", ""


def _first_exception(log_text: str) -> tuple[str, str]:
    for line in log_text.splitlines():
        m = _PYTEST_E.match(line.strip())
        if m:
            return m.group(1), (m.group(2) or "").strip()
    for line in log_text.splitlines():
        raw = line.strip()
        if raw.startswith("npm ERR!") or raw.startswith("ERROR:"):
            continue
        m = _GENERIC_EXC.match(raw)
        if m and not raw.startswith("E "):
            return m.group(1), m.group(2).strip()
    return "", ""


def _top_frame(log_text: str) -> str:
    chosen = ""
    for m in _FRAME.finditer(log_text):
        path, _line, func = m.group(1), m.group(2), m.group(3)
        if _relevant_frame(path):
            chosen = f"{_basename(path)} in {func}"
    if chosen:
        return chosen
    m = _PY_LOC.search(log_text)
    if m and _relevant_frame(m.group(1)):
        return _basename(m.group(1))
    return ""


def _top_frame_loc(log_text: str) -> str:
    """Display-only ``path:line in func`` (``top_frame`` stays as-is: it is fingerprinted)."""
    chosen = ""
    for m in _FRAME.finditer(log_text):
        path, line, func = m.group(1), m.group(2), m.group(3)
        if _relevant_frame(path):
            chosen = f"{path.replace(chr(92), '/')}:{line} in {func}"
    if chosen:
        return chosen
    m = _PY_LOC.search(log_text)
    if m and _relevant_frame(m.group(1)):
        return f"{m.group(1)}:{m.group(2)}"
    return ""


# ---------------------------------------------------------------- 5.2.0 NB4 anchors
# Runner-aware failure anchors. The excerpt must show the real failure, never the
# runner banner ("Current runner version", "Runner Image", GITHUB_TOKEN perms).
_BANNER = re.compile(
    r"^(?:Current runner version:|Runner name:|Runner group name:|Machine name:|##\[group\]|##\[endgroup\]"
    r"|Hosted Compute Agent|Operating System|Runner Image|GITHUB_TOKEN Permissions|Secret source:|Prepare workflow directory"
    r"|Prepare all required actions|Getting action download info|Download action repository|Complete job name:)"
)
_GO_GOTESTSUM_FAIL = re.compile(r"^=== FAIL: \S+ \S+ \((?:\d+(?:\.\d+)?s|unknown)\)\s*$")
_GO_DASH = re.compile(r"^(\s*)--- FAIL: (\S+) \((?:\d+(?:\.\d+)?s|unknown)\)\s*$")
_GO_RUN = re.compile(r"^=== RUN\s+(\S+)\s*$")
_GO_PANIC = re.compile(r"^panic: ")
_GO_PKG_FAIL_LINE = re.compile(r"^FAIL\s+\S+\s+(?:[\d.]+s|\[(?:build|setup) failed\])")
_GO_ASSERT = re.compile(r"^\s+(?:\S+_test\.go:\d+:.*|Error:\s+.+|Messages:\s+.+)$")
_GO_LOC = re.compile(r"(\S+_test\.go):(\d+)")
_VITEST_FAILED_TESTS = re.compile(r"^[⎯\-]{2,}\s*Failed Tests? \d+\s*[⎯\-]{2,}$")
_VITEST_FAILED_ANY = re.compile(r"^[⎯\-]{2,}\s*(?:Failed Suites?|Failed Tests?|Unhandled Errors?)\b.*[⎯\-]{2,}$")
_VITEST_X = re.compile(r"^\s*[×✗] \S")
_JEST_FAIL_FILE = re.compile(r"^\s*FAIL\s+(?:(?!\S+\.[cm]?[jt]sx?\b)[\w@.:/-]{1,40}\s+)?\S+\.[cm]?[jt]sx?(?:\s+\([\d.]+ m?s\))?\s*$")
_JEST_BUL = re.compile(r"^\s{0,4}● (.*)$")
_EXCERPT_MAX = 20


def _clip(lines: list[str], start: int, end: int) -> str:
    out: list[str] = []
    for line in lines[max(0, start):min(len(lines), end)]:
        if _RUNNER_TRAILER.match(line.strip()):
            break
        out.append(line)
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out[:_EXCERPT_MAX])


def _go_anchor(lines: list[str]) -> str:
    """Earliest Go test failure: gotestsum ``=== FAIL:`` or ``--- FAIL:`` block, then panic, then pkg FAIL."""
    for i, line in enumerate(lines):
        if _GO_GOTESTSUM_FAIL.match(line):
            end = i + 1
            while end < len(lines) and end - i < 18:
                nxt = lines[end]
                if not nxt.strip() or nxt.startswith("=== "):
                    break
                end += 1
            return _clip(lines, i, end)
        m = _GO_DASH.match(line)
        if m:
            name = m.group(2)
            # walk back to "=== RUN   <name>" keeping only indented (test output) lines
            before: list[str] = []
            k = i - 1
            while k >= 0 and i - k <= 60:
                r = _GO_RUN.match(lines[k])
                if r and r.group(1) == name:
                    break
                if lines[k][:1] in (" ", "\t") and lines[k].strip():
                    before.append(lines[k])
                k -= 1
            before = list(reversed(before))[-12:]
            after: list[str] = []
            k = i + 1
            while k < len(lines) and len(after) < 6:
                nxt = lines[k]
                if nxt[:1] in (" ", "\t") and nxt.strip() and not _GO_DASH.match(nxt):
                    after.append(nxt)
                    k += 1
                    continue
                break
            block = before + [line] + after
            return "\n".join(block[:_EXCERPT_MAX])
    for i, line in enumerate(lines):
        if _GO_PANIC.match(line):
            return _clip(lines, i, i + 18)
    for i, line in enumerate(lines):
        if _GO_PKG_FAIL_LINE.match(line.strip()):
            return _clip(lines, i - 8, i + 2)
    return ""


def _vitest_anchor(lines: list[str]) -> str:
    for i, line in enumerate(lines):
        if _VITEST_FAILED_TESTS.match(line.strip()):
            return _clip(lines, i, i + 18)
    for i, line in enumerate(lines):
        if _VITEST_FAILED_ANY.match(line.strip()):
            return _clip(lines, i, i + 18)
    for i, line in enumerate(lines):
        if _VITEST_X.match(line):
            return _clip(lines, i, i + 18)
    return ""


def _cpp_anchor(lines: list[str]) -> str:
    for i, line in enumerate(lines):
        stripped = line.strip()
        if re.search(r"^\[\s+FAILED\s+\]\s+\S", stripped):
            # GoogleTest prints the assertion above the FAILED summary line.
            return _clip(lines, max(0, i - 12), i + 6)
        if "***Failed" in stripped or stripped.startswith("The following tests FAILED:"):
            return _clip(lines, max(0, i - 4), i + 8)
    return ""


def _dotnet_anchor(lines: list[str]) -> str:
    for i, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"(?:\d+\)\s+)?Failed\s+\S+\s+\[", stripped) or stripped.startswith("[xUnit.net"):
            return _clip(lines, max(0, i - 1), i + 14)
    return ""


def _mocha_anchor(lines: list[str]) -> str:
    for i, line in enumerate(lines):
        if re.match(r"^\s*\d+\s+failing\s*$", line.strip()):
            return _clip(lines, i, i + 18)
    return ""


def _minitest_anchor(lines: list[str]) -> str:
    for i, line in enumerate(lines):
        if re.search(r"#test_[A-Za-z0-9_]+ \[", line):
            return _clip(lines, max(0, i - 2), i + 8)
    return ""


def _rspec_anchor(lines: list[str]) -> str:
    for i, line in enumerate(lines):
        if line.strip() == "Failed examples:" or line.strip().startswith("Failure/Error:"):
            return _clip(lines, max(0, i - 6), i + 8)
    return ""


def _phpunit_anchor(lines: list[str]) -> str:
    for i, line in enumerate(lines):
        if line.strip() == "FAILURES!" or re.match(r"^\d+\)\s+\S+::test", line.strip()):
            return _clip(lines, max(0, i - 2), i + 10)
    return ""


def _junit_anchor(lines: list[str]) -> str:
    for i, line in enumerate(lines):
        if "<<< FAILURE!" in line or "<<< ERROR!" in line:
            return _clip(lines, i, i + 12)
    return ""


def _cargo_anchor(lines: list[str]) -> str:
    for i, line in enumerate(lines):
        if re.search(r"^test .+ \.\.\. FAILED\s*$", line.strip()):
            return _clip(lines, i, i + 14)
    return ""


def _jest_anchor(lines: list[str]) -> str:
    current = None
    for i, line in enumerate(lines):
        if _JEST_FAIL_FILE.match(line):
            current = i
            continue
        if current is not None:
            b = _JEST_BUL.match(line)
            if b and b.group(1).strip() not in ("Console", ""):
                body = _clip(lines, i, i + 17)
                return lines[current].strip() + "\n" + body
    return ""


def _looks_like_job_log(lines: list[str]) -> bool:
    return any(_BANNER.match(line.strip()) for line in lines[:200])


def _excerpt_around(log_text: str, runner: str | None = None) -> str:
    lines = log_text.splitlines()
    order = {
        "go": (_go_anchor,),
        "vitest": (_vitest_anchor,),
        "jest": (_jest_anchor,),
        "mocha": (_mocha_anchor,),
        "junit": (_junit_anchor,),
        "dotnet": (_dotnet_anchor,),
        "cargo": (_cargo_anchor,),
        "cpp": (_cpp_anchor,),
        "minitest": (_minitest_anchor,),
        "rspec": (_rspec_anchor,),
        "phpunit": (_phpunit_anchor,),
    }.get(runner or "", ())
    for fn in order:
        got = fn(lines)
        if got.strip():
            return got
    idx = None
    for i, line in enumerate(lines):
        s = line.strip()
        if _BANNER.match(s):
            continue
        if s.startswith("FAILED ") or s.startswith("E ") or s.startswith("ERROR:") or s.startswith("npm ERR! code"):
            idx = i
            break
        if s.startswith("FAIL ") or _GENERIC_EXC.match(s):
            idx = i
            break
    if idx is None:
        for fn in (_go_anchor, _vitest_anchor, _jest_anchor, _mocha_anchor):
            if fn in order:
                continue
            got = fn(lines)
            if got.strip():
                return got
        if _looks_like_job_log(lines):
            return ""  # a runner banner is not failure evidence
        return "\n".join(lines[:20])
    start = max(0, idx - 2)
    end = min(len(lines), idx + 18)
    out: list[str] = []
    for line in lines[start:end]:
        if _RUNNER_TRAILER.match(line.strip()):
            break  # runner cleanup (post-job git, "Process completed") is not failure evidence
        out.append(line)
    return "\n".join(out)


_GO_ERRLINE = re.compile(r"^\s*Error:\s+(.+)$")
_GO_MSGLINE = re.compile(r"^\s*(\S+\.go):\d+:\s*(.*)$")
_GO_TRACE = re.compile(r"^\s*Error Trace:\s+(\S+\.go):\d+")


def _go_failure_facts(text: str) -> tuple[str, str]:
    """(message, top_frame) from the Go failure excerpt: testify ``Error:`` line, else
    the first ``file.go:N: msg`` line with text; frame = first ``*_test.go`` location
    (else the first Go file named in the output). Line numbers are not part of either.
    """
    err = loc_msg = ""
    test_file = any_file = ""
    for line in text.splitlines():
        m = _GO_ERRLINE.match(line)
        if m and not err:
            err = "Error: " + m.group(1).strip()
        m = _GO_MSGLINE.match(line)
        if m:
            f = _basename(m.group(1))
            if m.group(2).strip() and not loc_msg:
                loc_msg = f + ": " + m.group(2).strip()
            any_file = any_file or f
            if f.endswith("_test.go") and not test_file:
                test_file = f
        for loc in _GO_LOC.finditer(line):
            test_file = test_file or _basename(loc.group(1))
        m = _GO_TRACE.match(line)
        if m:
            any_file = any_file or _basename(m.group(1))
    msgs = ""
    for line in text.splitlines():
        m = re.match(r"^\s*Messages:\s+(.+)$", line)
        if m:
            msgs = "Messages: " + m.group(1).strip()
            break
    msg = err or msgs or loc_msg
    if not msg:
        # e.g. "x_test.go:12:" followed by testify expected/actual lines
        parts: list[str] = []
        for line in text.splitlines():
            st = line.strip()
            if not st or st.startswith(("Error Trace:", "Test:", "--- FAIL", "=== FAIL")) or _GO_MSGLINE.match(line):
                continue
            parts.append(re.sub(r"\s+", " ", st))
            if len(parts) >= 3:
                break
        msg = " | ".join(parts)
    return msg[:400], (test_file or any_file)[:200]


_RUNNER_TRAILER = re.compile(
    r"^(?:##\[error\]Process completed with exit code|Post job cleanup\.?$|\[command\]|##\[(?:group|endgroup)\])"
)


def parse_runner_image(log_text: str) -> dict[str, str]:
    """Runner image name and version from the GitHub-hosted log header."""
    text = strip_log_prefixes(log_text or "")
    idx = text.find("Runner Image")
    window = text[idx : idx + 900] if idx >= 0 else ""
    if not window:
        return {}
    image_m = re.search(r"Image:\s*(\S+)", window)
    ver_m = re.search(r"Version:\s*(\S+)", window)
    url_m = re.search(r"Included Software:\s*(\S+)", window)
    image = image_m.group(1).strip() if image_m else ""
    version = ver_m.group(1).strip() if ver_m else ""
    url = ""
    if url_m:
        raw = url_m.group(1).strip()
        if raw.startswith("https://github.com/actions/runner-images/"):
            url = raw[:300]
    if not image and not version:
        return {}
    return {"image": image, "version": version, "software_url": url}


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _add_dep(deps: list[dict[str, str]], seen: set[tuple[str, str]], ecosystem: str, name: str, version: str) -> None:
    name = name.strip().strip("'\"")
    version = version.strip().rstrip(",")
    if not name or not version or version.startswith("^") or "*" in version:
        return
    if ecosystem == "pypi":
        name = _pep503(name)
    key = (ecosystem, name)
    if key in seen:
        return
    seen.add(key)
    deps.append({"ecosystem": ecosystem, "name": name, "version": version})
    if len(deps) > 200:
        deps.pop()
        seen.discard(key)


def parse_dependencies(log_text: str) -> list[dict[str, str]]:
    """Resolved versions from pip, uv, poetry, npm, yarn, and pnpm log lines."""
    text = strip_log_prefixes(log_text or "")
    deps: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in text.splitlines():
        raw = line.strip()
        m = _PIP_OK.match(raw)
        if m:
            for token in m.group(1).split():
                tm = _PIP_TOKEN.match(token.strip())
                if tm:
                    _add_dep(deps, seen, "pypi", tm.group(1), tm.group(2))
            continue
        m = _PIP_REQ.match(raw)
        if m:
            _add_dep(deps, seen, "pypi", m.group(1), m.group(2))
            continue
        m = _UV_PIN.match(raw)
        if m and "==" in raw:
            _add_dep(deps, seen, "pypi", m.group(1), m.group(2))
            continue
        m = _POETRY.search(raw)
        if m:
            _add_dep(deps, seen, "pypi", m.group(1), m.group(2))
            continue
        m = _PNPM.match(raw)
        if m:
            _add_dep(deps, seen, "npm", m.group(1), m.group(2))
            continue
        if raw.startswith(("├", "└", "info ", "+ ")) or "@" in raw and "npm" not in raw[:4]:
            for em in _NPM_EXACT.finditer(raw):
                if "^" in raw or "~" in raw:
                    continue
                _add_dep(deps, seen, "npm", em.group(1), em.group(2))
    return deps


def error_packages(log_text: str) -> list[dict[str, str]]:
    """Package names named by an import or install error. No versions invented."""
    text = strip_log_prefixes(log_text or "")
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(ecosystem: str, name: str) -> None:
        name = name.strip().strip("'\"")
        if not name or name.startswith(".") or "/" in name or name.startswith("-"):
            return
        top = name.split(".")[0]
        if ecosystem == "pypi":
            if top in _STDLIB:
                return
            name = _pep503(top)
        key = (ecosystem, name)
        if key in seen:
            return
        seen.add(key)
        out.append({"ecosystem": ecosystem, "name": name})

    for m in _NO_MODULE.finditer(text):
        add("pypi", m.group(1))
    for m in _NO_JS_MODULE.finditer(text):
        add("npm", m.group(1))
    for m in _PIP_DIST.finditer(text):
        add("pypi", m.group(1).split("==")[0].split(">=")[0].split("[")[0])
    return out[:12]


def _js_test_ids(log_text: str) -> list[str]:
    ids: list[str] = []
    pending_file = ""
    for line in log_text.splitlines():
        m = _NPM_FAIL.match(line.strip())
        if m:
            pending_file = m.group(1)
            continue
        m = _JEST_TEST.match(line)
        if m and pending_file:
            title = re.sub(r"\s+", " ", m.group(1)).strip()
            ids.append(f"{pending_file}::{title}"[:240])
            if len(ids) >= 20:
                break
    return ids


def node_id_from_junit(file: str, classname: str, name: str) -> str:
    """Rebuild a pytest node id from one JUnit ``testcase``.

    Pytest writes ``classname`` with dots (``tests.test_foo.TestBar``) and
    ``name`` as the function plus parameters. The file attribute, when
    present, is the path. The node id is ``tests/test_foo.py::TestBar::test``.
    A classname without a file is split at the first CamelCase segment.
    """
    name = (name or "").strip()
    if not name or any(c in name for c in "\n\r\x00"):
        return ""
    file = (file or "").replace("\\", "/").strip()
    while file.startswith("./"):
        file = file[2:]
    classname = (classname or "").strip()
    if ".." in file.split("/"):
        return ""
    if file.endswith(".py"):
        mod = file[:-3].replace("/", ".")
        stem = file.rsplit("/", 1)[-1][:-3]
        rest = ""
        if classname in (mod, stem, ""):
            rest = ""
        elif classname.startswith(mod + "."):
            rest = classname[len(mod) + 1:]
        elif classname.startswith(stem + "."):
            rest = classname[len(stem) + 1:]
        elif classname[:1].isupper():
            rest = classname
        classes = [p for p in rest.split(".") if p]
        return "::".join([file, *classes, name])[:300]
    parts = [p for p in classname.split(".") if p]
    if not parts:
        return ""
    split = len(parts)
    for i, part in enumerate(parts):
        if part[:1].isupper():
            split = i
            break
    mod_parts = parts[:split]
    class_parts = parts[split:]
    if not mod_parts or any(p in ("", ".", "..") for p in mod_parts):
        return ""
    path = "/".join(mod_parts) + ".py"
    return "::".join([path, *class_parts, name])[:300]


def parse_junit(xml_text: str) -> dict[str, str]:
    """Map pytest node id → pass|fail|error|skip. Empty dict if the XML is unusable.

    Ids are rebuilt from ``file``, ``classname``, and ``name``. A class in the
    classname is part of the node id (``file.py::Class::test``), not dropped.
    """
    if not xml_text or len(xml_text) > 2_000_000:
        return {}
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}
    out: dict[str, str] = {}
    for tc in root.iter("testcase"):
        file_ = (tc.get("file") or "").replace("\\", "/")
        name = tc.get("name") or ""
        tid = node_id_from_junit(file_, tc.get("classname") or "", name)
        if not tid:
            continue
        if tc.find("failure") is not None or tc.find("error") is not None:
            status = "fail"
        elif tc.find("skipped") is not None:
            status = "skip"
        else:
            status = "pass"
        out[tid[:300]] = status
        if len(out) >= 500:
            break
    return out


_GENERIC_EXIT = re.compile(r"^Process completed with exit code \d+\.?$", re.IGNORECASE)


def is_generic_runner_exit(text: str) -> bool:
    """True when the only text is GitHub's 'Process completed with exit code N' line."""
    msgs: list[str] = []
    for line in (text or "").splitlines():
        raw = line.strip()
        if not raw:
            continue
        msgs.append(raw.split(": ", 1)[-1].strip())
    return bool(msgs) and all(_GENERIC_EXIT.match(m) for m in msgs)


def annotations_to_text(annotations: list | None) -> str:
    lines: list[str] = []
    for ann in annotations or []:
        if not isinstance(ann, dict):
            continue
        msg = str(ann.get("message") or "").strip()
        if not msg:
            continue
        path = str(ann.get("path") or "").strip()
        line_no = ann.get("start_line") or ""
        if path:
            lines.append(f"{path}:{line_no}: {msg}")
        else:
            lines.append(msg)
        if len(lines) >= 40:
            break
    return "\n".join(lines)


def extract_failure(log_text: str) -> dict[str, Any]:
    """First-error facts from one log blob (possibly several jobs concatenated)."""
    text = strip_log_prefixes(log_text or "")
    failed = extract_pytest_node_ids(text)
    # Also keep non-pytest ids the bisect helper would skip (header lines).
    if not failed:
        failed = []
        for line in text.splitlines():
            m = _FAILED.match(line.strip()) or _TESTS_NODE.match(line.strip())
            if m and _node_id_ok(m.group(1)):
                nid = m.group(1)
                if nid not in failed:
                    failed.append(nid)
    passed = _collect_node_ids(text, _PASSED)
    for line in text.splitlines():
        m = _PASSED_SUFFIX.match(line.strip())
        if m and _node_id_ok(m.group(1)) and m.group(1) not in passed:
            passed.append(m.group(1))
    js_ids = _js_test_ids(text)
    exc_type, message = _first_exception(text)
    head_type, head_msg = first_failed_reason(text)
    if not exc_type:
        for line in text.splitlines():
            if line.strip().startswith("npm ERR! code"):
                exc_type = "npm ERR"
                message = line.strip()
                break
            if line.strip().startswith("ERROR:"):
                exc_type = "pip ERROR"
                message = line.strip()
                break
    frame = _top_frame(text)
    runner_name = None
    if not failed:
        # 5.2.0 (NB4): Go / vitest / jest ids from the reviewed runner extractors, so
        # the fingerprint and excerpt are built on the real failure, not the banner.
        try:
            from provebreak_culprit._engine.runners import extract_failing_tests_any
            from provebreak_culprit._engine.runners import strip_task_prefixes

            text = strip_task_prefixes(text)
            ex = extract_failing_tests_any(text)
            # Go text is not a bisect id. The excerpt still anchors on the failure block.
            if ex.error == "go_text_output_unverifiable":
                runner_name = "go"
            else:
                runner_name = ex.runner if ex.runner in (
                    "go", "vitest", "jest", "mocha", "junit", "dotnet",
                    "cargo", "cpp", "minitest", "rspec", "phpunit",
                ) else None
                if runner_name and not js_ids:
                    js_ids = list(ex.ids)
        except Exception:  # noqa: BLE001
            runner_name = None
    excerpt = _excerpt_around(text, runner_name)
    if runner_name in ("vitest", "jest", "mocha") and excerpt:
        # NIT 7: the exception comes from the anchored failure block, not from an
        # earlier "stderr | other test" block.
        e_type, e_msg = _first_exception(excerpt)
        if e_type:
            exc_type, message = e_type, e_msg
    if runner_name == "cpp" and excerpt:
        for line in excerpt.splitlines():
            stripped = line.strip()
            if "Failure" in stripped or stripped.startswith("Expected ") or "***Failed" in stripped:
                exc_type, message = "cpp test failure", stripped[:200]
                break
    if runner_name == "junit" and excerpt:
        for line in excerpt.splitlines():
            if "<<< FAILURE!" in line or "<<< ERROR!" in line or "Assertion" in line:
                exc_type, message = "junit", line.strip()[:200]
                break
    if runner_name == "minitest" and excerpt:
        for line in excerpt.splitlines():
            if "Expected:" in line or line.strip().startswith("Failure:"):
                exc_type, message = "minitest failure", line.strip()[:200]
                break
    if runner_name == "rspec" and excerpt:
        for line in excerpt.splitlines():
            if line.strip().startswith("expected:") or "Failure/Error:" in line:
                exc_type, message = "rspec failure", line.strip()[:200]
                break
    if runner_name == "phpunit" and excerpt:
        for line in excerpt.splitlines():
            if line.strip().startswith("Failed asserting"):
                exc_type, message = "phpunit failure", line.strip()[:200]
                break
    if runner_name == "cargo" and excerpt:
        for line in excerpt.splitlines():
            if "panicked at" in line or line.strip().startswith("assertion"):
                exc_type, message = "cargo test failure", line.strip()[:200]
                break
    if runner_name == "go":
        # Go output never has a Python exception; any "X: y" line the generic scan
        # picked up (e.g. log noise) is replaced by the real failure content.
        g_msg, g_frame = _go_failure_facts(excerpt)
        if g_msg:
            exc_type, message = "go test failure", g_msg
        if g_frame and not frame:
            frame = g_frame
    packages = error_packages(text)
    kind = "unknown"
    if _INSTALL.search(text) or packages:
        kind = "import_or_install"
    elif failed or js_ids:
        kind = "test_failure"
    elif exc_type:
        kind = "test_failure" if exc_type not in {"pip ERROR", "npm ERR"} else "import_or_install"
    return {
        "test_ids": (failed + js_ids)[:20],
        "failed_test_ids": (failed + js_ids)[:20],
        "passed_test_ids": passed[:40],
        "exception_type": exc_type[:120],
        "message": message[:400],
        # display-only (not fingerprinted): first FAILED short-summary reason
        "headline_type": head_type[:120],
        "headline_message": head_msg[:400],
        "top_frame": frame[:200],
        "top_frame_loc": _top_frame_loc(text)[:200],
        "excerpt": excerpt[:2000],
        "kind": kind,
        "runner": parse_runner_image(text),
        "deps": parse_dependencies(text),
        "error_packages": packages,
    }


def parse_requirements_text(text: str) -> list[dict[str, str]]:
    deps: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in (text or "").splitlines():
        raw = line.split("#", 1)[0].strip()
        if not raw or raw.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([0-9][^\s;\\]*)", raw)
        if m:
            _add_dep(deps, seen, "pypi", m.group(1), m.group(2))
    return deps


def parse_lock_name_versions(text: str, ecosystem: str) -> list[dict[str, str]]:
    """poetry.lock / uv.lock style name+version pairs. Best-effort, no TOML lib."""
    deps: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    name = ""
    for line in (text or "").splitlines():
        if line.startswith("[[package"):
            name = ""
            continue
        m = re.match(r'\s*name\s*=\s*"([^"]+)"', line)
        if m:
            name = m.group(1)
            continue
        m = re.match(r'\s*version\s*=\s*"([^"]+)"', line)
        if m and name:
            _add_dep(deps, seen, ecosystem, name, m.group(1))
            name = ""
    return deps


def parse_package_lock(text: str) -> list[dict[str, str]]:
    import json

    deps: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return []
    root = packages.get("") if isinstance(packages.get(""), dict) else {}
    direct = set()
    for section in ("dependencies", "devDependencies"):
        block = root.get(section) or {}
        if isinstance(block, dict):
            direct.update(block.keys())
    if not direct:
        direct = set(packages.keys())
    for path, meta in packages.items():
        if not isinstance(meta, dict) or not str(path).startswith("node_modules/"):
            continue
        name = str(path).split("node_modules/")[-1]
        if direct and name not in direct and not any(name == d or name.endswith("/" + d) for d in direct):
            # keep direct deps only; nested paths end with the package name
            base = name.split("node_modules/")[-1]
            if base not in direct:
                continue
            name = base
        ver = str(meta.get("version") or "")
        if ver:
            _add_dep(deps, seen, "npm", name, ver)
    return deps
