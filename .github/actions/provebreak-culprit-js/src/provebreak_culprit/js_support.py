"""JavaScript (vitest / jest) support for the Action wrapper.

Wrapper-only: detects the framework and turns a JUnit XML or JSON reporter file into
engine ids of the form ``file > describe > test`` (the engine's JS_SEP). The engine's
existing JsGitRunner does the per-commit runs. Anything ambiguous returns an error
string so the CLI abstains instead of guessing.
"""
from __future__ import annotations
import json
import os
import xml.etree.ElementTree as ET
from pathlib import Path

from provebreak_culprit._engine.runners import JS_SEP, detect_runner_from_repo, validate_js_ids

JS_RUNNERS = ("vitest", "jest")
_FILE_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts")


def detect_framework(repo: str | Path) -> tuple[str | None, str | None]:
    """(framework, error). Exactly one of vitest/jest found → that one; else an abstain reason.
    A repo with no JS framework but pytest-ish files returns ("pytest", None)."""
    found = [r for r in detect_runner_from_repo(repo) if r in JS_RUNNERS]
    if len(found) == 1:
        return found[0], None
    if len(found) > 1:
        return None, "js_framework_ambiguous:" + "+".join(found)
    return "pytest", None


def _rel(path: str, repo: Path) -> str | None:
    p = path.replace("\\", "/")
    if os.path.isabs(p):
        try:
            p = Path(p).resolve().relative_to(repo.resolve()).as_posix()
        except ValueError:
            return None
    while p.startswith("./"):
        p = p[2:]
    return p if p.endswith(_FILE_EXT) else None


def _ids_from_json(d: dict, repo: Path) -> tuple[list[str], str | None]:
    if not isinstance(d, dict) or not isinstance(d.get("testResults"), list):
        return [], "js_report_not_vitest_or_jest_json"
    ids: list[str] = []
    for tr in d["testResults"]:
        f = _rel(str(tr.get("name", "")), repo)
        fails = [a for a in tr.get("assertionResults") or [] if a.get("status") == "failed"]
        if not fails:
            if tr.get("status") == "failed":
                return [], "js_suite_failed_without_test_ids"  # load error: nothing to bisect by id
            continue
        if f is None:
            return [], "js_report_file_outside_repo"
        for a in fails:
            parts = [*map(str, a.get("ancestorTitles") or []), str(a.get("title", ""))]
            ids.append(JS_SEP.join([f, *parts]))
    return ids, None


def _ids_from_junit(root: ET.Element, repo: Path, framework: str) -> tuple[list[str], str | None]:
    ids: list[str] = []
    for suite in root.iter("testsuite"):
        for tc in suite.iter("testcase"):
            if tc.find("failure") is None and tc.find("error") is None:
                continue
            name = tc.get("name", "")
            if framework == "vitest":
                f = _rel(tc.get("file") or tc.get("classname") or suite.get("name", ""), repo)
            else:  # jest-junit: needs addFileAttribute and a " > " separated title
                f = _rel(tc.get("file") or "", repo)
                if f and JS_SEP not in name and name.strip().count(" ") > 0:
                    return [], "jest_junit_ambiguous_titles:use --json or ancestorSeparator ' > '"
                name = name.strip()
            if f is None:
                return [], "junit_testcase_without_js_file"
            ids.append(f + JS_SEP + name)
    return ids, None


def extract_js_ids(report: str | Path, repo: str | Path, framework: str) -> tuple[list[str], str | None]:
    """Failing ids from a vitest/jest JSON or JUnit XML report, validated by the engine."""
    repo = Path(repo)
    try:
        text = Path(report).read_text(errors="replace")
    except OSError:
        return [], "js_report_unreadable"
    s = text.lstrip()
    try:
        if s.startswith("{"):
            ids, err = _ids_from_json(json.loads(s), repo)
        elif s.startswith("<"):
            ids, err = _ids_from_junit(ET.fromstring(s), repo, framework)
        else:
            return [], "js_report_unknown_format"
    except (ValueError, ET.ParseError):
        return [], "js_report_parse_error"
    if err:
        return [], err
    if not ids:
        return [], "no_failing_tests_in_report"
    seen: list[str] = []
    for i in ids:
        if i not in seen:
            seen.append(i)
    return validate_js_ids(seen[:20])
