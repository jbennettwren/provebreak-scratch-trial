"""Maven Surefire / JUnit 5 ids for a single-module build.

Experimental scaffolding. A test id is ``com.example.CalcTest#method``.
Red and green come only from a Surefire XML ``<testcase>`` for that id.
A compile error, a missing JDK or Maven, Gradle, a multi-module reactor,
and a parameterized id are abstains. They are not a culprit.

Kotlin uses this path when Maven already compiles the test to a JUnit 5
class. The id is the JVM class and method.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from sentinel_card.bisect import _scrub_reason
from sentinel_card.bisect import apply_isolated_home
from sentinel_card.bisect import build_scrubbed_env
from sentinel_card.bisect import make_isolated_home

MAX_JVM_ID_LEN = 512
_CLASS = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\$[A-Za-z_][A-Za-z0-9_]*)*$"
)
_METHOD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_GH_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z ?")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
# Surefire 3: "[ERROR] lab.calc.CalcTest$Inner.addsInside -- Time elapsed: 0.001 s <<< FAILURE!"
_SUREFIRE_FAIL = re.compile(
    r"^\[(?:ERROR|WARNING)\]\s+"
    r"((?:[A-Za-z_][\w$]*\.)*[A-Za-z_][\w$]*)"
    r"\.([A-Za-z_]\w*)(?:\([^)\n]*\))?\s+--\s+Time elapsed:.*<<< (?:FAILURE|ERROR)!\s*$"
)
# Surefire 2: "[ERROR] addsTwoNumbers(lab.calc.CalcTest)  Time elapsed: 0.003 s  <<< FAILURE!"
_SUREFIRE_OLD = re.compile(
    r"^\[(?:ERROR|WARNING)\]\s+([A-Za-z_]\w*)"
    r"\(((?:[A-Za-z_][\w$]*\.)*[A-Za-z_][\w$]*)\)"
    r"\s+Time elapsed:.*<<< (?:FAILURE|ERROR)!"
)
_SUREFIRE_MARK = re.compile(r"<<< (?:FAILURE|ERROR)!")
_GRADLE_MARK = re.compile(
    r"(?m)(?:^> Task\s|FAILURE: Build failed with an exception|^\* What went wrong:|^BUILD FAILED\s*$)"
)
_COMPILE = re.compile(
    r"COMPILATION ERROR|Compilation failure|maven-compiler-plugin:|"
    r"kotlin-maven-plugin:.*[Cc]ompilation|Unresolved reference|"
    r"Could not resolve dependencies|Non-resolvable parent POM|"
    r"Could not transfer artifact|Failed to execute goal"
)
_SKIP_DIRS = frozenset({".git", "target", "node_modules", ".gradle"})
_GRADLE_NAMES = frozenset({
    "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
})
_XML_COMMENT = re.compile(r"<!--.*?-->", re.S)
_POM_MODULES = re.compile(r"<modules\b[^>]*>\s*<module\b", re.S)


@dataclass
class JvmLog:
    ids: list[str]
    error: str | None = None


def validate_jvm_ids(tests: list | tuple) -> tuple[list[str], str | None]:
    """``classname#method``. Parameterized names and display names are refused."""
    if not tests:
        return [], "no_failing_tests_provided"
    clean: list[str] = []
    for raw in tests:
        text = str(raw).strip()
        if not text:
            continue
        if len(text) > MAX_JVM_ID_LEN:
            return [], f"junit_id_too_long:{text[:40]}"
        if any(ord(c) < 32 for c in text):
            return [], f"junit_id_control_chars:{text[:40]}"
        if text.startswith("-") or text.count("#") != 1:
            return [], f"junit_id_must_be_class#method:{text[:40]}"
        classname, method = text.split("#", 1)
        if not _CLASS.fullmatch(classname) or not _METHOD.fullmatch(method):
            return [], f"junit_unsupported_id:{text[:40]}"
        if text not in clean:
            clean.append(text)
    return (clean, None) if clean else ([], "no_failing_tests_provided")


def split_jvm_id(text: str) -> tuple[str, str] | None:
    clean, err = validate_jvm_ids([text])
    if err or not clean:
        return None
    classname, method = clean[0].split("#", 1)
    return classname, method


def _lines(log_text: str) -> list[str]:
    out = []
    for raw in (log_text or "").splitlines():
        line = _ANSI.sub("", _GH_TS.sub("", raw.lstrip("\ufeff"))).rstrip()
        out.append(line)
    return out


def _take(found: list[str], classname: str, method: str, limit: int) -> bool:
    tid = f"{classname}#{method}"
    clean, err = validate_jvm_ids([tid])
    if err or not clean:
        return False
    if clean[0] not in found:
        found.append(clean[0])
    return len(found) >= limit


def _jvm_done(log_text: str, ids: list[str], error: str | None = None) -> JvmLog:
    from sentinel_card.summary_gate import finish

    kept, err = finish("junit", log_text, ids, error)
    return JvmLog(kept, err)


def extract_jvm(log_text: str, *, limit: int = 20) -> JvmLog:
    """Failing JUnit ids from a Maven Surefire console log.

    A Gradle log is ``gradle_unsupported``. A failure line whose name is not
    ``Class#method`` (a parameter list, a display name) is
    ``junit_unsupported_id`` when nothing safer was found. Stack traces are
    not ids. A passing summary is not an id.
    """
    if not log_text:
        return _jvm_done(log_text, [])
    from sentinel_card.summary_gate import _mask

    lines, err = _mask("junit", _lines(log_text))
    if err:
        return _jvm_done(log_text, [], err)
    found: list[str] = []
    unsafe = False
    saw_surefire = False
    for line in lines:
        if _SUREFIRE_MARK.search(line):
            saw_surefire = True
        matched = False
        modern = _SUREFIRE_FAIL.match(line.strip())
        if modern:
            matched = True
            if _take(found, modern.group(1), modern.group(2), limit):
                return _jvm_done(log_text, found)
        old = _SUREFIRE_OLD.match(line.strip())
        if old:
            matched = True
            if _take(found, old.group(2), old.group(1), limit):
                return _jvm_done(log_text, found)
        if (
            _SUREFIRE_MARK.search(line)
            and not matched
            and line.strip().startswith("[")
            and "Tests run:" not in line
        ):
            unsafe = True
    if unsafe:
        return _jvm_done(log_text, [], "test_ids_unparsed_entry")
    if found:
        return _jvm_done(log_text, found)
    gradle = bool(_GRADLE_MARK.search(log_text))
    if gradle and not saw_surefire:
        return _jvm_done(log_text, [], "gradle_unsupported")
    if unsafe:
        return _jvm_done(log_text, [], "junit_unsupported_id")
    return _jvm_done(log_text, [])


def _interesting(root: Path) -> tuple[list[Path], list[Path]]:
    poms: list[Path] = []
    gradles: list[Path] = []
    if not root.is_dir():
        return poms, gradles
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
        for name in filenames:
            path = Path(dirpath) / name
            if name == "pom.xml":
                poms.append(path)
            elif name in _GRADLE_NAMES:
                gradles.append(path)
        if len(poms) + len(gradles) > 20:
            break
    return poms, gradles


def _pom_has_modules(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")[:500_000]
    except OSError:
        return False
    return bool(_POM_MODULES.search(_XML_COMMENT.sub("", text)))


def jvm_layout(root: Path) -> tuple[str, str | None]:
    """``('maven_single', None)`` or ``('unsupported', reason)``.

    One ``pom.xml`` and no Gradle file is the only layout this runner executes.
    """
    poms, gradles = _interesting(Path(root))
    if gradles and poms:
        return "unsupported", "jvm_mixed_build_unsupported"
    if gradles:
        return "unsupported", "gradle_unsupported"
    if len(poms) > 1:
        return "unsupported", "jvm_multimodule_ambiguous"
    if len(poms) == 1:
        if _pom_has_modules(poms[0]):
            return "unsupported", "jvm_multimodule_ambiguous"
        return "maven_single", None
    return "unsupported", "jvm_no_build_file"


def repo_suggests_junit(root: Path) -> bool:
    layout, reason = jvm_layout(root)
    if layout == "maven_single":
        return True
    return reason in {
        "gradle_unsupported",
        "jvm_multimodule_ambiguous",
        "jvm_mixed_build_unsupported",
    }


def clear_surefire_reports(root: Path) -> None:
    """Drop the previous run's XML so a stale ``<failure>`` cannot be red."""
    directory = Path(root) / "target" / "surefire-reports"
    if directory.is_dir():
        shutil.rmtree(directory, ignore_errors=True)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _method_name(raw: str) -> str | None:
    name = (raw or "").strip()
    if name.endswith("()"):
        name = name[:-2]
    if _METHOD.fullmatch(name):
        return name
    return None


def _case_rows(path: Path) -> list[tuple[str, str, str, str]]:
    try:
        if path.is_symlink() or path.stat().st_size > 2_000_000:
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    rows = []
    for node in root.iter():
        if _local(node.tag) != "testcase":
            continue
        classname = node.get("classname") or ""
        method = _method_name(node.get("name") or "")
        if not classname or not method:
            continue
        children = [_local(child.tag) for child in list(node)]
        if "failure" in children or "error" in children:
            status = "fail"
        elif "skipped" in children:
            status = "skip"
        else:
            status = "pass"
        detail = ""
        for child in list(node):
            if _local(child.tag) in ("failure", "error"):
                parts = [child.get("type") or "", child.get("message") or ""]
                detail = " ".join(part for part in parts if part)[:300] or status
                break
        rows.append((classname, method, status, detail))
        if len(rows) >= 500:
            break
    return rows


def _reports(root: Path) -> list[Path]:
    directory = Path(root) / "target" / "surefire-reports"
    if not directory.is_dir():
        return []
    found = []
    for path in sorted(directory.glob("TEST-*.xml")):
        if path.is_file():
            found.append(path)
        if len(found) >= 40:
            break
    return found


def classify_surefire(
    root: Path,
    tests: list[str],
    *,
    returncode: int,
    output: str,
) -> tuple[str, str, str, str]:
    """``(label, kind, detail, failure_shape)`` for the requested ids.

    Exit 0 is not green. Green requires every requested ``<testcase>`` to be
    present and passed in the XML written by this run. Red requires a
    ``<failure>`` or ``<error>`` on a requested testcase. Another testcase's
    failure is ignored.
    """
    wanted = []
    for raw in tests:
        parts = split_jvm_id(raw)
        if parts:
            wanted.append(parts)
    text = output or ""
    detail = _scrub_reason(_maven_detail(text), max_len=200)
    if not wanted:
        return "error", "unknown", detail or "junit_unsupported_id", ""
    by_id: dict[tuple[str, str], tuple[str, str]] = {}
    for path in _reports(root):
        for classname, method, status, message in _case_rows(path):
            key = (classname, method)
            previous = by_id.get(key)
            if previous is None or status == "fail" or (status == "skip" and previous[0] == "pass"):
                by_id[key] = (status, message)
    statuses = []
    messages = []
    for key in wanted:
        hit = by_id.get(key)
        if hit is None:
            statuses.append("missing")
        else:
            statuses.append(hit[0])
            if hit[1]:
                messages.append(hit[1])
    if any(status == "fail" for status in statuses):
        shape = "assertion" if re.search(r"Assert", " ".join(messages)) else ""
        fail_detail = _scrub_reason(messages[0] if messages else "junit_fail", max_len=200)
        return "red", "fail", fail_detail or "junit_fail", shape
    if any(status == "missing" for status in statuses):
        if _COMPILE.search(text) or (returncode != 0 and not by_id):
            return "error", "build_error", detail or "build_failed", ""
        return "error", "not_found", detail or "test_not_in_report", ""
    if any(status == "skip" for status in statuses):
        return "error", "skipped", detail or "test_skipped", ""
    if returncode != 0:
        return "error", "package_fail", detail or f"exit_{returncode}_with_target_passed", ""
    return "green", "pass", detail or "junit_pass", ""


def _maven_detail(text: str) -> str:
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or "cwiki.apache.org" in line or "re-run Maven" in line:
            continue
        if line.startswith("[ERROR] [Help") or line == "[ERROR]":
            continue
        if re.search(r"COMPILATION ERROR|ERROR\]|error:|Unresolved reference|Could not resolve|BUILD FAILURE|There are test failures", line):
            lines.append(line)
    if not lines:
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()][-3:]
    return " | ".join(lines[:3])


def _executable(name: str) -> bool:
    if not name or any(ord(c) < 32 for c in name):
        return False
    path = Path(name)
    if path.is_file() and os.access(path, os.X_OK):
        return True
    return shutil.which(name) is not None


def java_home() -> str:
    raw = os.environ.get("JAVA_HOME") or ""
    if raw and "\n" not in raw and "\r" not in raw and Path(raw, "bin", "java").is_file():
        return raw
    java = shutil.which("java")
    if not java:
        return ""
    resolved = Path(java).resolve()
    if resolved.parent.name == "bin" and (resolved.parent.parent / "bin" / "java").is_file():
        return str(resolved.parent.parent)
    return ""


def toolchain_error(mvn_bin: str = "mvn") -> str | None:
    if not _executable("java") and not java_home():
        return "jdk_missing"
    if not _executable(mvn_bin):
        return "maven_missing"
    return None


def jvm_child_env(home: Path, *, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Child env is the scrub allow-list, plus JAVA_HOME and the headless Maven flag.

    setup-java exports ``MAVEN_ARGS=-ntp``. That flag is already on the argv, so
    the child keeps that exact value. Any other host key (``DISPLAY``, ``PS1``,
    ``_JAVA_OPTIONS``) stays out of this dict.
    """
    overlay: dict[str, str] = {"MAVEN_OPTS": "-Djava.awt.headless=true", "GIT_TERMINAL_PROMPT": "0"}
    home_java = java_home()
    if home_java:
        overlay["JAVA_HOME"] = home_java
    if os.environ.get("MAVEN_ARGS") == "-ntp":
        overlay["MAVEN_ARGS"] = "-ntp"
    from sentinel_card.machine_preflight import scrub_runner_env

    overlay.update(scrub_runner_env("junit", extra))
    env = build_scrubbed_env(extra=overlay, home=str(home))
    apply_isolated_home(env, home)
    if home_java:
        bin_dir = str(Path(home_java) / "bin")
        path = env.get("PATH") or ""
        if bin_dir not in path.split(":"):
            env["PATH"] = bin_dir + (":" + path if path else "")
    return env


def maven_test_argv(mvn: str, tests: list[str], repo_local: Path) -> list[str]:
    selector = ",".join(tests)
    return [
        mvn,
        "-B",
        "--no-transfer-progress",
        f"-Dmaven.repo.local={repo_local}",
        "-DtrimStackTrace=false",
        "-Dsurefire.failIfNoSpecifiedTests=true",
        f"-Dtest={selector}",
        "test",
    ]


def preflight_junit() -> tuple[bool, str]:
    why = toolchain_error()
    if why:
        return False, why
    home = make_isolated_home()
    try:
        env = jvm_child_env(home)
        for cmd, reason in ((["java", "-version"], "jdk_missing"), (["mvn", "-version"], "maven_missing")):
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=60, env=env, cwd=str(home),
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                return False, type(exc).__name__ if reason == "jdk_missing" else reason
            if result.returncode != 0:
                return False, reason
        return True, ""
    finally:
        shutil.rmtree(home, ignore_errors=True)
