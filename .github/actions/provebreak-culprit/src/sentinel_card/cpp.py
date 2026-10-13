"""CTest or GoogleTest ids for one C or C++ binary. Exit 0 is never red."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from sentinel_card.bisect import _scrub_reason
from sentinel_card.bisect import apply_isolated_home
from sentinel_card.bisect import build_scrubbed_env
from sentinel_card.bisect import make_isolated_home
from sentinel_card.toolchain_pin import CMAKE_VERSION
from sentinel_card.toolchain_pin import CTEST_VERSION
from sentinel_card.toolchain_pin import GCC_MAJOR
from sentinel_card.toolchain_pin import gnu_major
from sentinel_card.toolchain_pin import tool_version_text
from sentinel_card.toolchain_pin import version_mismatch

MAX_CPP_ID_LEN = 512
_SKIP_DIRS = frozenset({
    ".git", "build", "CMakeFiles", "_deps", "node_modules", ".sentinel-cpp-build",
})
_SEGMENT = r"[A-Za-z_][A-Za-z0-9_]*"
_GTEST_ID = re.compile(rf"^{_SEGMENT}\.{_SEGMENT}$")
_CTEST_ID = re.compile(rf"^{_SEGMENT}$")
_GH_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z ?")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_WF_CMD = re.compile(r"^##\[[A-Za-z]+\]\s?")
_GTEST_OUT = re.compile(r"^\[\s+(OK|FAILED|SKIPPED)\s+\]\s+(\S+)")
_GTEST_PASSED_SUMMARY = re.compile(r"^\[\s+PASSED\s+\]\s+\d+\s+tests?\.?\s*$")
_GTEST_FAILED_SUMMARY = re.compile(
    r"^(?:\[\s+FAILED\s+\]\s+\d+\s+tests?,\s+listed below:|\d+\s+FAILED\s+TESTS?)\s*$"
)
_GTEST_RAN = re.compile(
    r"^\[=+\]\s+(\d+)\s+tests?\s+from\s+\d+\s+test\s+suites?\s+ran\b"
)
_GTEST_PASSED_N = re.compile(r"^\[\s+PASSED\s+\]\s+(\d+)\s+tests?\.?\s*$")
_GTEST_LISTED = re.compile(r"^\[\s+FAILED\s+\]\s+(\d+)\s+tests?,\s+listed below:\s*$")
_GTEST_BARE_FAIL = re.compile(r"^\[\s+FAILED\s+\]\s+(\S+)\s*$")
_GTEST_MARKER = re.compile(
    r"^\[=+\]|^\[\s+RUN\s+\]|^\[\s+(?:OK|FAILED|PASSED|SKIPPED)\s+\]"
)
_CTEST_FAILED_OUT = re.compile(r"\b(\d+)\s+tests?\s+failed out of\b")
_GH_COMMAND = re.compile(r"^##\[[A-Za-z]+\]")
_CTEST_OUT = re.compile(
    r"^\d+/\d+\s+Test\s+#\d+:\s+(.+?)\s+\.+(\*+)?\s*(Passed|Failed|Not Run)\b"
)
_CTEST_SUMMARY = re.compile(r"^\s*\d+\s+-\s+(.+?)\s+\((Failed|Not Run)\)\s*$")
_CATCH_LOG = re.compile(r"(?i)(?:\bis a Catch v\d|Catch2 v\d|CATCH_CONFIG_MAIN)")
_ADD_EXE = re.compile(rf"(?m)^\s*add_executable\s*\(\s*({_SEGMENT})\b")
_ADD_TEST = re.compile(rf"(?m)^\s*add_test\s*\(\s*(?:NAME\s+)?({_SEGMENT})\b")
_DISCOVER = re.compile(rf"(?m)^\s*gtest_discover_tests\s*\(\s*({_SEGMENT})\b")
_ENABLE = re.compile(r"(?m)^\s*(?:enable_testing\s*\(|include\s*\(\s*CTest\b)")
_SUBDIR = re.compile(r"(?m)^\s*add_subdirectory\s*\(")
_GTEST_CMAKE = re.compile(r"\b(?:GTest::|find_package\s*\(\s*GTest|gtest_discover_tests|GoogleTest)\b")
_CATCH_CMAKE = re.compile(
    r"\b(?:Catch2::|find_package\s*\(\s*Catch2|catch_discover_tests)\b|"
    r"#\s*include\s*[<\"]catch2?/catch"
)
_GTEST_INCLUDE = re.compile(r"#\s*include\s*[<\"]gtest/gtest\.h[\">]")
_TOOLCHAIN_SET = re.compile(r"CMAKE_TOOLCHAIN_FILE")
_BUILD_FAIL = re.compile(
    r"(?m)^CMake Error|:\s+error:|^undefined reference|fatal error:|collect2: error:"
)
_NO_TESTS = re.compile(r"No tests were found")
_ADD_TEST_GEN = re.compile(
    r"^add_test\((?:\[=+\[)?([^\]\s]+)(?:\]=+\])?\s+(\S+)"
)
_INCLUDE_GEN = re.compile(r'^include\("([^"]+)"\)\s*$')
_SOURCE_SUFFIX = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}


@dataclass
class CppLog:
    ids: list[str]
    error: str | None = None


def ctest_name_regex(tests: list[str]) -> str:
    """A CMake regular expression that matches these ids and no others.

    CTest does not compile Python's ``(?:...)``. A ``.`` in a GoogleTest
    id is escaped so it is not "any character".
    """
    parts = [name.replace("\\", "\\\\").replace(".", r"\.") for name in tests]
    if len(parts) == 1:
        return "^" + parts[0] + "$"
    return "^(" + "|".join(parts) + ")$"


def is_gtest_id(text: str) -> bool:
    return bool(_GTEST_ID.fullmatch(text))


def is_ctest_id(text: str) -> bool:
    return bool(_CTEST_ID.fullmatch(text))


def validate_cpp_ids(tests: list | tuple) -> tuple[list[str], str | None]:
    """CTest name or GoogleTest ``Suite.Case``. Flags, spaces, and ``/`` are refused."""
    if not tests:
        return [], "no_failing_tests_provided"
    clean: list[str] = []
    for raw in tests:
        text = str(raw).strip()
        if not text:
            continue
        if len(text) > MAX_CPP_ID_LEN:
            return [], f"cpp_id_too_long:{text[:40]}"
        if any(ord(c) < 32 for c in text):
            return [], f"cpp_id_control_chars:{text[:40]}"
        if text.startswith("-") or any(ch in text for ch in "#\\"):
            return [], f"cpp_unsupported_id:{text[:40]}"
        if "/" in text:
            return [], f"cpp_unsupported_id:{text[:40]}"
        if " " in text:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?: [A-Za-z0-9_]+)+", text):
                return [], f"cpp_unsupported_id:{text[:40]}"
        elif not (is_gtest_id(text) or is_ctest_id(text)):
            return [], f"cpp_unsupported_id:{text[:40]}"
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


def cpp_summary_gate(lines: list[str], ids: list[str]) -> tuple[list[str], str | None]:
    from sentinel_card.summary_gate import _pick

    g_pass: list[int] = []
    g_fail: list[tuple[int, int]] = []
    c_out: list[int] = []
    c_list = 0
    for index, ln in enumerate(lines):
        text = ln.strip()
        if _GTEST_PASSED_SUMMARY.match(text):
            g_pass.append(index)
        failed_n = re.match(r"^(\d+)\s+FAILED\s+TESTS?$", text)
        if failed_n:
            g_fail.append((index, int(failed_n.group(1))))
        out = _CTEST_FAILED_OUT.search(text)
        if out:
            c_out.append(int(out.group(1)))
        matched = _CTEST_SUMMARY.match(text)
        if matched and matched.group(2) == "Failed":
            c_list += 1
    if len(g_pass) > 1 or len(g_fail) > 1 or len(c_out) > 1:
        return [], "test_ids_multiple_summaries"
    if g_pass and g_fail and g_pass[-1] > g_fail[-1][0]:
        return [], "test_ids_multiple_summaries"
    if (g_pass and not g_fail) or (len(c_out) == 1 and c_out[0] == 0 and not g_fail):
        return [], "summary_reports_pass"
    if g_fail:
        return _pick(g_fail[0][1], [], ids)
    if c_out:
        return _pick(c_out[0], [], ids)
    if c_list:
        return _pick(c_list, [], ids)
    if ids:
        return [], "test_ids_no_summary"
    return [], None


def _cpp_done(log_text: str, ids: list[str], error: str | None = None) -> CppLog:
    from sentinel_card.summary_gate import finish

    kept, err = finish("cpp", log_text, ids, error)
    return CppLog(kept, err)


def _gtest_shaped(lines: list[str]) -> bool:
    return any(_GTEST_MARKER.match(line.strip()) for line in lines)


def _gtest_final_block(lines: list[str]) -> tuple[str, list[str]] | None:
    """The GoogleTest final block, or None when this log is not GoogleTest.

    Ids are named only from ``[  FAILED  ] F tests, listed below:`` when
    ``[==========] N tests ... ran`` and ``[  PASSED  ] k`` are present,
    exactly F bare ids follow, and ``N = k + F``. Anything else is
    ``cpp_incomplete_run``. A ``/`` in a failed id stays
    ``cpp_unsupported_id``.
    """
    if not _gtest_shaped(lines):
        return None
    for line in lines:
        matched = _GTEST_OUT.match(line.strip())
        if matched and matched.group(1) == "FAILED" and "/" in matched.group(2):
            return ("cpp_unsupported_id", [])
    ran = [(index, int(matched.group(1))) for index, line in enumerate(lines) if (matched := _GTEST_RAN.match(line.strip()))]
    if len(ran) != 1:
        return ("cpp_incomplete_run", [])
    index, total = ran[0]
    passed: int | None = None
    failed_n: int | None = None
    listed: list[str] = []
    phase = "passed"
    for line in lines[index + 1:]:
        text = line.strip()
        if not text:
            continue
        if phase == "passed":
            matched = _GTEST_PASSED_N.match(text)
            if not matched:
                return ("cpp_incomplete_run", [])
            passed = int(matched.group(1))
            phase = "failed"
            continue
        if phase == "failed":
            matched = _GTEST_LISTED.match(text)
            if not matched:
                break
            failed_n = int(matched.group(1))
            phase = "ids"
            continue
        matched = _GTEST_BARE_FAIL.match(text)
        if not matched:
            break
        listed.append(matched.group(1))
    if phase == "failed" and passed == total:
        return ("ids", [])
    if failed_n is None or passed is None or len(listed) != failed_n or total != passed + failed_n:
        return ("cpp_incomplete_run", [])
    clean: list[str] = []
    for name in listed:
        ok, err = validate_cpp_ids([name])
        if err or not ok:
            return ("cpp_unsupported_id", [])
        if ok[0] not in clean:
            clean.append(ok[0])
    return ("ids", clean)


def selected_no_tests(text: str) -> bool:
    """The exact filter ran nothing: GoogleTest ``0 tests`` or CTest ``No tests were found``."""
    if _NO_TESTS.search(text or ""):
        return True
    if re.search(r"Running 0 tests\b", text or ""):
        return True
    return re.search(r"(?m)^\[=+\]\s+0 tests from \d+ test suites? ran\b", text or "") is not None


def extract_cpp(log_text: str, *, limit: int = 20) -> CppLog:
    """Failing CTest or GoogleTest ids.

    A passing line is not an id. GoogleTest ids come only from a complete
    final block whose counts agree (``cpp_incomplete_run`` otherwise). A
    Catch2 banner with no CTest or GoogleTest id is
    ``cpp_catch2_unsupported``.
    """
    if not log_text:
        return _cpp_done(log_text, [])
    lines = _lines(log_text)
    from sentinel_card.summary_gate import _mask

    lines, err = _mask("cpp", lines)
    if err:
        return _cpp_done(log_text, [], err)
    final = _gtest_final_block(lines)
    listed_ids: list[str] | None = None
    if final is not None:
        if final[0] != "ids":
            return _cpp_done(log_text, [], final[0])
        listed_ids = final[1]
    found: list[str] = []
    unsafe = False
    unparsed = False
    slash = False
    g_fail = False
    c_failed: list[str] = []
    c_passed: list[str] = []
    c_list: list[str] = []

    def take(name: str) -> None:
        nonlocal unsafe
        clean, err = validate_cpp_ids([name])
        if err or not clean:
            unsafe = True
            return
        if clean[0] not in found:
            found.append(clean[0])

    if listed_ids:
        g_fail = True
        for name in listed_ids:
            take(name)
    for line in lines:
        text = line.strip()
        if listed_ids is not None and (
            _GTEST_FAILED_SUMMARY.match(text) or (_GTEST_OUT.match(text) and _GTEST_OUT.match(text).group(1) == "FAILED")
        ):
            continue
        if _GTEST_FAILED_SUMMARY.match(text):
            g_fail = True
            continue
        matched = _GTEST_OUT.match(text)
        if matched and matched.group(1) == "FAILED":
            name = matched.group(2)
            if "/" in name:
                slash = True
                unsafe = True
            else:
                clean, err = validate_cpp_ids([name])
                if err or not clean:
                    unparsed = True
                else:
                    take(name)
        if "Test #" in text and "***Failed" in text and not _CTEST_OUT.match(text):
            unparsed = True
        summary = _CTEST_SUMMARY.match(line)
        if summary and summary.group(2) == "Failed" and summary.group(1) not in c_list:
            c_list.append(summary.group(1))
            take(summary.group(1))
        ctest = _CTEST_OUT.match(text)
        if ctest:
            (c_failed if ctest.group(3) == "Failed" else c_passed).append(ctest.group(1))
            if ctest.group(3) == "Failed":
                take(ctest.group(1))
        if len(found) >= limit:
            break
    if (c_list and c_passed and not c_failed) or (c_list and c_failed and set(c_list) != set(c_failed)):
        return _cpp_done(log_text, [], "test_ids_result_disagreed")
    if g_fail and c_passed and not c_failed:
        return _cpp_done(log_text, [], "test_ids_result_disagreed")
    if slash:
        return _cpp_done(log_text, [], "cpp_unsupported_id")
    if unparsed:
        return _cpp_done(log_text, [], "test_ids_unparsed_entry")
    if found:
        return _cpp_done(log_text, found[:limit])
    text = "\n".join(lines)
    if _CATCH_LOG.search(text):
        return _cpp_done(log_text, [], "cpp_catch2_unsupported")
    if unsafe:
        return _cpp_done(log_text, [], "cpp_unsupported_id")
    return _cpp_done(log_text, [])


def _strip_cmake_comments(text: str) -> str:
    out = []
    for line in text.splitlines():
        buf: list[str] = []
        quote = ""
        for ch in line:
            if quote:
                buf.append(ch)
                if ch == quote:
                    quote = ""
                continue
            if ch in "\"'":
                quote = ch
                buf.append(ch)
                continue
            if ch == "#":
                break
            buf.append(ch)
        out.append("".join(buf))
    return "\n".join(out)


def _read_text(path: Path, limit: int = 500_000) -> str:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def _walk(root: Path):
    if not root.is_dir():
        return
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
        yield Path(dirpath), filenames


def _named_files(root: Path, pred) -> list[Path]:
    found: list[Path] = []
    for directory, filenames in _walk(root):
        for name in filenames:
            path = directory / name
            if pred(path):
                found.append(path)
                if len(found) > 40:
                    return found
    return found


def _toolchain_file(path: Path) -> bool:
    name = path.name.lower()
    return name in {"cmakepresets.json", "cmakeuserpresets.json"} or (
        name.endswith(".cmake") and "toolchain" in name
    )


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def cpp_layout(root: Path) -> tuple[str, str | None]:
    """``('ctest_single'|'gtest_single', None)`` or ``('unsupported', reason)``.

    One root ``CMakeLists.txt``, testing enabled, and one ``add_executable``
    is the only layout this runner builds. GoogleTest may register many
    cases from that one binary. A second binary does not.
    """
    root = Path(root)
    lists = _named_files(root, lambda p: p.name == "CMakeLists.txt")
    meson = (root / "meson.build").is_file()
    bazel = any((root / name).is_file() for name in ("BUILD.bazel", "WORKSPACE", "WORKSPACE.bazel", "MODULE.bazel"))
    autotools = (root / "configure.ac").is_file() or (root / "Makefile.am").is_file()
    makefile = (root / "Makefile").is_file() or (root / "makefile").is_file()
    if not lists:
        if meson:
            return "unsupported", "cpp_meson_unsupported"
        if bazel:
            return "unsupported", "cpp_bazel_unsupported"
        if autotools:
            return "unsupported", "cpp_autotools_unsupported"
        if makefile:
            return "unsupported", "cpp_make_unsupported"
        return "unsupported", "cpp_no_cmake"
    if meson or bazel or autotools:
        return "unsupported", "cpp_mixed_build_unsupported"
    if len(lists) != 1:
        return "unsupported", "cpp_workspace_unsupported"
    cmake_path = lists[0]
    try:
        if cmake_path.parent.resolve() != root.resolve():
            return "unsupported", "cpp_workspace_unsupported"
    except OSError:
        return "unsupported", "cpp_workspace_unsupported"
    if _named_files(root, _toolchain_file):
        return "unsupported", "cpp_toolchain_file_unsupported"
    text = _strip_cmake_comments(_read_text(cmake_path))
    if not text:
        return "unsupported", "cpp_no_cmake"
    if _TOOLCHAIN_SET.search(text):
        return "unsupported", "cpp_toolchain_file_unsupported"
    if _SUBDIR.search(text):
        return "unsupported", "cpp_workspace_unsupported"
    if not _ENABLE.search(text):
        return "unsupported", "cpp_ctest_not_enabled"
    catch = bool(_CATCH_CMAKE.search(text))
    gtest = bool(_GTEST_CMAKE.search(text))
    if not gtest:
        for directory, filenames in _walk(root):
            for name in filenames:
                path = directory / name
                if path.suffix.lower() not in _SOURCE_SUFFIX:
                    continue
                if _GTEST_INCLUDE.search(_read_text(path, 200_000)):
                    gtest = True
                    break
            if gtest:
                break
    if catch and gtest:
        return "unsupported", "cpp_ambiguous_framework"
    if catch:
        return "unsupported", "cpp_catch2_unsupported"
    executables = _ADD_EXE.findall(text)
    tests = _ADD_TEST.findall(text)
    discovers = _DISCOVER.findall(text)
    if "add_executable" in text and not executables:
        return "unsupported", "cpp_layout_unparsed"
    if len(executables) != 1:
        return "unsupported", "cpp_multibinary_unsupported" if executables else "cpp_no_test_binary"
    if discovers and tests:
        return "unsupported", "cpp_layout_ambiguous"
    if len(discovers) > 1 or len(tests) > 1:
        return "unsupported", "cpp_multibinary_unsupported"
    if gtest and (discovers or tests):
        return "gtest_single", None
    if gtest:
        return "unsupported", "cpp_no_ctest_test"
    if len(tests) == 1 and is_ctest_id(tests[0]):
        return "ctest_single", None
    if tests:
        return "unsupported", "cpp_layout_unparsed"
    return "unsupported", "cpp_no_ctest_test"


def repo_suggests_cpp(root: Path) -> bool:
    layout, reason = cpp_layout(root)
    if layout in {"ctest_single", "gtest_single"}:
        return True
    return reason in {
        "cpp_workspace_unsupported",
        "cpp_multibinary_unsupported",
        "cpp_toolchain_file_unsupported",
        "cpp_catch2_unsupported",
        "cpp_mixed_build_unsupported",
        "cpp_meson_unsupported",
        "cpp_bazel_unsupported",
        "cpp_autotools_unsupported",
        "cpp_make_unsupported",
        "cpp_ambiguous_framework",
        "cpp_layout_ambiguous",
        "cpp_no_test_binary",
        "cpp_no_ctest_test",
        "cpp_ctest_not_enabled",
        "cpp_layout_unparsed",
    }


def _executable(name: str) -> str:
    if not name or any(ord(c) < 32 or c in ";|&$`" for c in name):
        return ""
    found = shutil.which(name)
    if not found:
        return ""
    path = Path(found)
    if path.is_file() and os.access(path, os.X_OK):
        return str(path)
    return ""


def pinned_compilers() -> tuple[str, str] | None:
    """The job compiler pair. A checkout toolchain file is not consulted.

    GNU is used when both ``gcc`` and ``g++`` are on PATH. A Clang pair is
    returned only so the pin check can abstain ``cpp_compiler_version_mismatch``.
    The one-click pin is GCC 13.
    """
    gcc, gxx = _executable("gcc"), _executable("g++")
    if gcc and gxx:
        return gcc, gxx
    clang, clangxx = _executable("clang"), _executable("clang++")
    if clang and clangxx:
        return clang, clangxx
    return None


def _compiler_pin(compilers: tuple[str, str]) -> str | None:
    """GCC 13 is the pin. Clang, or another GNU major, is not that compiler."""
    for binary in compilers:
        name = Path(binary).name
        if name not in {"gcc", "g++", "gcc-13", "g++-13"}:
            return "cpp_compiler_version_mismatch"
        if gnu_major(tool_version_text([binary, "--version"])) != GCC_MAJOR:
            return "cpp_compiler_version_mismatch"
    return None


def toolchain_error() -> str | None:
    """Missing binary, then the one-click pin. A wrong version is not a culprit."""
    if not _executable("cmake"):
        return "cmake_missing"
    if not _executable("ctest"):
        return "ctest_missing"
    compilers = pinned_compilers()
    if compilers is None:
        return "cpp_compiler_missing"
    why = version_mismatch(["cmake", "--version"], CMAKE_VERSION, "cmake_version_mismatch")
    if why:
        return why
    why = version_mismatch(["ctest", "--version"], CTEST_VERSION, "ctest_version_mismatch")
    if why:
        return why
    return _compiler_pin(compilers)


def cpp_child_env(home: Path, *, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Scrubbed env. ``CC`` and ``CXX`` are the pinned job compilers.

    ``CMAKE_TOOLCHAIN_FILE`` from the job or the overlay is dropped. A
    checkout that names one abstains before configure.
    """
    compilers = pinned_compilers()
    overlay: dict[str, str] = {
        "CMAKE_COLOR_DIAGNOSTICS": "OFF",
        "CMAKE_EXPORT_COMPILE_COMMANDS": "OFF",
        "CTEST_OUTPUT_ON_FAILURE": "1",
    }
    if compilers:
        overlay["CC"] = compilers[0]
        overlay["CXX"] = compilers[1]
    if extra:
        for key, value in extra.items():
            if value is None or key in {"CC", "CXX", "CMAKE_TOOLCHAIN_FILE"}:
                continue
            overlay[key] = value
    env = build_scrubbed_env(extra=overlay, home=str(home))
    apply_isolated_home(env, home)
    env.pop("CMAKE_TOOLCHAIN_FILE", None)
    env["CMAKE_COLOR_DIAGNOSTICS"] = "OFF"
    if compilers:
        env["CC"] = compilers[0]
        env["CXX"] = compilers[1]
    return env


def _registered_tests(build: Path) -> tuple[dict[str, Path], str | None]:
    """Map CTest name to its executable, following includes inside ``build``."""
    root_file = build / "CTestTestfile.cmake"
    if not root_file.is_file():
        return {}, "cpp_no_ctest_test"
    pending = [root_file]
    seen: set[Path] = set()
    found: dict[str, Path] = {}
    while pending and len(seen) < 20:
        path = pending.pop(0)
        try:
            resolved = path.resolve()
        except OSError:
            return {}, "cpp_ctest_command_unsupported"
        if resolved in seen or not _inside(resolved, build):
            continue
        seen.add(resolved)
        text = _read_text(resolved)
        for line in text.splitlines():
            included = _INCLUDE_GEN.match(line.strip())
            if included:
                pending.append(Path(included.group(1)))
                continue
            matched = _ADD_TEST_GEN.match(line.strip())
            if not matched:
                continue
            name = matched.group(1)
            if name.endswith("_NOT_BUILT"):
                continue
            raw_exe = matched.group(2).strip("\"'")
            exe = Path(raw_exe)
            if not exe.is_absolute():
                exe = build / exe
            try:
                exe_resolved = exe.resolve()
            except OSError:
                return {}, "cpp_ctest_command_unsupported"
            if not _inside(exe_resolved, build):
                return {}, "cpp_ctest_command_unsupported"
            previous = found.get(name)
            if previous is not None and previous != exe_resolved:
                return {}, "cpp_multibinary_unsupported"
            found[name] = exe_resolved
            if len(found) > 200:
                return {}, "cpp_multibinary_unsupported"
    if not found:
        return {}, "cpp_tests_not_discovered"
    executables = set(found.values())
    if len(executables) > 1:
        return {}, "cpp_multibinary_unsupported"
    return found, None


def _outcomes(text: str) -> tuple[dict[str, str], bool]:
    """Map id to pass/fail/skip. The bool is true when two sources disagree."""
    found: dict[str, str] = {}
    sources: dict[str, str] = {}
    rank = {"pass": 1, "skip": 2, "fail": 3}
    conflict = False

    def put(name: str, label: str, source: str) -> None:
        nonlocal conflict
        clean, err = validate_cpp_ids([name])
        if err or not clean:
            return
        key = clean[0]
        previous = found.get(key)
        if previous is not None and sources.get(key) not in (None, source) and previous != label:
            conflict = True
        if previous is None or rank[label] > rank[previous]:
            found[key] = label
            sources[key] = source

    for line in _lines(text):
        stripped = line.strip()
        gtest = _GTEST_OUT.match(stripped)
        if gtest:
            put(gtest.group(2), {"OK": "pass", "FAILED": "fail", "SKIPPED": "skip"}[gtest.group(1)], "gtest")
        ctest = _CTEST_OUT.match(stripped)
        if ctest:
            put(ctest.group(1), {"Passed": "pass", "Failed": "fail", "Not Run": "skip"}[ctest.group(3)], "ctest")
        summary = _CTEST_SUMMARY.match(line)
        if summary:
            put(summary.group(1), {"Failed": "fail", "Not Run": "skip"}[summary.group(2)], "ctest")
    return found, conflict


def _workflow_command(line: str) -> bool:
    """GitHub ``##[warning]`` (and the other ``##[command]``) lines are not results."""
    return bool(_GH_COMMAND.match(line.strip()))


def _gtest_summary_passed(text: str) -> bool:
    """True when ``[  PASSED  ] N tests`` is present and no failure summary is."""
    passed = False
    failed_summary = False
    for line in _lines(text):
        stripped = line.strip()
        if _workflow_command(stripped):
            continue
        if _GTEST_PASSED_SUMMARY.match(stripped):
            passed = True
        elif _GTEST_FAILED_SUMMARY.match(stripped):
            failed_summary = True
    return passed and not failed_summary


def _ctest_result_failed(text: str, ids: set[str]) -> bool:
    """True when CTest itself reports a failure for this run or a requested id."""
    for line in _lines(text):
        stripped = line.strip()
        if _workflow_command(stripped):
            continue
        failed_out = _CTEST_FAILED_OUT.search(stripped)
        if failed_out and int(failed_out.group(1)) > 0:
            return True
        ctest = _CTEST_OUT.match(stripped)
        if ctest and ctest.group(1) in ids and ctest.group(3) != "Passed":
            return True
        summary = _CTEST_SUMMARY.match(line)
        if summary and summary.group(1) in ids:
            return True
    return False


def _gtest_failed_line(text: str, ids: set[str]) -> bool:
    """A ``[  FAILED  ] <id>`` line for a requested id. Workflow commands do not count."""
    for line in _lines(text):
        stripped = line.strip()
        if _workflow_command(stripped):
            continue
        matched = _GTEST_OUT.match(stripped)
        if matched and matched.group(1) == "FAILED" and matched.group(2) in ids:
            return True
    return False


def _passed_run_has_failed_line(text: str, ids: list[str], returncode: int) -> bool:
    """Exit 0 and a passing GoogleTest summary disagree with a FAILED line.

    CTest, when it reports a result, has to agree the run passed. A
    ``##[warning]`` line is not that result.
    """
    if returncode != 0:
        return False
    wanted = set(ids)
    if not _gtest_summary_passed(text):
        return False
    if _ctest_result_failed(text, wanted):
        return False
    return _gtest_failed_line(text, wanted)


def _failure_detail(text: str) -> str:
    lines = []
    for raw in _lines(text):
        line = raw.strip()
        if not line:
            continue
        if "Failure" in line or line.startswith("Expected ") or "CMake Error" in line or ": error:" in line:
            lines.append(line)
    if not lines:
        lines = [ln.strip() for ln in _lines(text) if ln.strip()][-3:]
    return " | ".join(lines[:3])


def classify_cpp(
    output: str,
    tests: list[str],
    *,
    returncode: int,
) -> tuple[str, str, str, str]:
    """``(label, kind, detail, failure_shape)`` for the requested ids.

    Exit 0 is not green. Green requires a Passed or ``[       OK ]`` line
    for every requested id from this run. Red requires a failure line for
    a requested id. Another test's failure is not that id. Exit 0 and a
    passing GoogleTest summary (``[  PASSED  ] N tests`` with no
    ``N FAILED TEST`` footer) disagree with a ``[  FAILED  ]`` line for a
    requested id: that is ``cpp_result_disagreed``, not red. A
    ``##[warning]`` line is not a GoogleTest result. A non-zero exit with
    a matching FAILED summary is still red.
    """
    clean, err = validate_cpp_ids(tests)
    text = output or ""
    detail = _scrub_reason(_failure_detail(text), max_len=200)
    if err or not clean:
        return "error", "unknown", detail or (err or "cpp_unsupported_id"), ""
    # Before any FAILED line. ``Running 0 tests`` / ``No tests were found``
    # means the filter selected nothing, even if the log prints a failure.
    if selected_no_tests(text):
        return "error", "not_found", "filter_selected_no_tests", ""
    outcomes, conflict = _outcomes(text)
    if conflict or _passed_run_has_failed_line(text, clean, returncode):
        return "error", "unknown", "cpp_result_disagreed", ""
    statuses = [outcomes.get(name, "missing") for name in clean]
    if any(status == "fail" for status in statuses):
        if returncode == 0:
            return "error", "unknown", "cpp_result_disagreed", ""
        shape = "assertion" if re.search(r"Failure|Expected equality|Expected:", text) else ""
        return "red", "fail", detail or "cpp_fail", shape
    if any(status == "missing" for status in statuses):
        if _BUILD_FAIL.search(text):
            return "error", "build_error", detail or "build_failed", ""
        if _NO_TESTS.search(text):
            return "error", "not_found", detail or "test_not_registered", ""
        if returncode != 0 and not outcomes:
            return "error", "build_error", detail or "build_failed", ""
        return "error", "not_found", detail or "test_not_in_output", ""
    if any(status == "skip" for status in statuses):
        return "error", "skipped", detail or "test_skipped", ""
    if returncode != 0:
        return "error", "package_fail", detail or f"exit_{returncode}_with_target_passed", ""
    return "green", "pass", detail or "cpp_pass", ""


def preflight_cpp() -> tuple[bool, str]:
    why = toolchain_error()
    if why:
        return False, why
    home = make_isolated_home()
    try:
        env = cpp_child_env(home)
        compilers = pinned_compilers() or ("", "")
        checks = (
            (["cmake", "--version"], "cmake_missing"),
            (["ctest", "--version"], "ctest_missing"),
            ([compilers[1] or "c++", "--version"], "cpp_compiler_missing"),
        )
        for cmd, reason in checks:
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
