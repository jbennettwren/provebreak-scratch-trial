"""Summary and structural gate. Runs after each failing-test parser.

No imports from ``bisect`` or ``runners`` at module scope (those import this
module). A pass summary yields no ids (``summary_reports_pass``). No summary
yields ``test_ids_no_summary``. A count or list disagreement abstains.
"""
from __future__ import annotations

import re

_YIELD = frozenset({
    "test_ids_no_summary",
    "test_ids_count_mismatch",
    "test_ids_result_disagreed",
    "test_ids_multiple_summaries",
    "test_ids_unparsed_entry",
    "flaky_retry",
    "summary_reports_pass",
    "go_result_disagreed",
    "go_text_output_unverifiable",
})


def counts_as_yield(ids: list, error: str | None) -> bool:
    """True when this runner has ids or a summary, including a pass summary."""
    return bool(ids) or error in _YIELD


def finish(runner: str, log: str, ids: list, error: str | None) -> tuple[list, str | None]:
    """Keep a named abstain. A pass summary still wins over a disagreement."""
    if error and not ids:
        _gids, gerr = apply_gate(runner, log, [])
        if gerr == "summary_reports_pass":
            return [], gerr
        return [], error
    return apply_gate(runner, log, ids)


def apply_gate(runner: str, log: str, ids: list) -> tuple[list, str | None]:
    fn = _HANDLERS.get(runner or "")
    if fn is None:
        return list(ids), None
    from sentinel_card.runners import test_id_esc_error

    esc = test_id_esc_error(log or "")
    if esc:
        return [], esc
    lines = _clean(log or "")
    if (runner or "") == "go":
        kind = _go_kind(lines)
        if kind == "mixed":
            return [], "test_ids_result_disagreed"
        if kind == "text":
            return [], "go_text_output_unverifiable"
    lines, err = _mask(runner or "", lines)
    gids, gerr = fn(lines, list(ids)) if fn else (list(ids), None)
    if err == "test_ids_multiple_summaries" or gerr == "test_ids_multiple_summaries":
        return [], "test_ids_multiple_summaries"
    if err:
        return [], err
    return list(gids), gerr


def _clean(log: str) -> list[str]:
    from sentinel_card.runners import _lines_for_test_ids

    return _lines_for_test_ids(log)


def _pytest(lines: list[str], ids: list) -> tuple[list, str | None]:
    from sentinel_card.bisect import pytest_summary_gate

    return pytest_summary_gate(lines, ids)


def _hits(lines: list[str], pred) -> list[tuple[int, int]]:
    found = []
    for index, line in enumerate(lines):
        count = pred(line)
        if count is not None:
            found.append((index, count))
    return found


def _one(hits: list[tuple[int, int]], lines: list[str], ids: list, after) -> tuple[list, str | None]:
    """Exactly one summary, and it is the last runner-shaped line."""
    if len(hits) > 1:
        return [], "test_ids_multiple_summaries"
    if not hits:
        return ([], "test_ids_no_summary") if ids else ([], None)
    index, count = hits[0]
    if count == 0:
        return [], "summary_reports_pass"
    if any(after(line) for line in lines[index + 1:]):
        return [], "test_ids_multiple_summaries"
    return _pick(count, [], ids)


def _go_kind(lines: list[str]) -> str:
    """``json`` events, raw Go text, both, or neither.

    A ``--- FAIL`` inside a JSON ``Output`` string is not a text line.
    """
    json_log = False
    text = False
    for ln in lines:
        s = ln.strip()
        if s.startswith("{") and '"Action"' in s:
            json_log = True
            continue
        if (
            s.startswith("=== RUN")
            or s.startswith("--- FAIL:")
            or s.startswith("--- PASS:")
            or s.startswith("=== FAIL:")
            or s in ("=== Failed", "=== Errors")
            or s.startswith("DONE ")
            or ("\t" in s and re.match(r"^(?:FAIL|ok)\s+\S+", s))
        ):
            text = True
    if json_log and text:
        return "mixed"
    if text:
        return "text"
    if json_log:
        return "json"
    return "none"


def _pytest_log(lines: list[str]) -> bool:
    for ln in lines:
        s = ln.strip()
        if s.startswith("FAILED ") and "::" in s:
            return True
        if "short test summary" in s or "test session starts" in s:
            return True
        if re.match(r"=+ .* in [\d.]+s =+", s):
            return True
    return False


def _jest_log(lines: list[str]) -> bool:
    for ln in lines:
        s = ln.strip()
        if s.startswith("● Console") or s.startswith(("Test Suites:", "Tests:")):
            return True
        if re.match(r"^(?:FAIL|PASS)\s+\S+\.[cm]?[jt]sx?\b", s):
            return True
    return False


def _vitest_log(lines: list[str]) -> bool:
    for ln in lines:
        s = ln.strip()
        if s.startswith(("stdout |", "stderr |", "Tests", "Test Files")):
            return True
        if s.startswith("FAIL ") and " > " in s:
            return True
        if re.match(r"^[⎯\-]{2,}\s*Failed Tests\b", s):
            return True
    return False


def _cargo_log(lines: list[str]) -> bool:
    """Cargo's own lines. A pytest ``---- Captured stdout`` banner is not one."""
    for ln in lines:
        s = ln.strip()
        if s.startswith("test result:") or s.startswith("Summary ["):
            return True
        if re.match(r"^running \d+ tests?\b", s):
            return True
        if re.match(r"^test \S+ \.\.\. (?:ok|FAILED|ignored)\b", s):
            return True
        if re.match(r"^(?:FAIL|PASS|SLOW) \[[^\]]+\] ", s):
            return True
    return False


def _owns_log(runner: str, lines: list[str]) -> bool:
    """True when this log is that runner's, so its captured-region mask may run."""
    if runner == "pytest":
        return _pytest_log(lines)
    if runner == "jest":
        return _jest_log(lines)
    if runner == "vitest":
        return _vitest_log(lines)
    if runner == "cargo":
        return _cargo_log(lines)
    if runner == "cpp":
        return any(_gtest_run(ln) or _gtest_done(ln) for ln in lines)
    if runner == "dotnet":
        return any(
            _dotnet_out(ln) or ln.strip().startswith(("Passed!", "Failed!")) or "Failed:" in ln
            for ln in lines
        )
    if runner == "junit":
        return any(_junit_out(ln) or "Tests run:" in ln for ln in lines)
    if runner == "go":
        # Text abstains before the mask. JSON events are not a captured region.
        return False
    return False


def _mask(runner: str, lines: list[str]) -> tuple[list[str], str | None]:
    """Captured-region masks run only on that runner's own log."""
    if not _owns_log(runner, lines):
        return lines, None
    if runner == "pytest":
        return _skip_region(lines, _py_cap, _py_cap_end, keep_end=True, eof_ok=False)
    if runner == "jest":
        return _skip_region(lines, _jest_console, _jest_console_end, keep_end=True, eof_ok=False)
    if runner == "vitest":
        return _mask_vitest(lines)
    if runner == "cargo":
        return _skip_region(lines, _cargo_stdio, _cargo_stdio_end, keep_end=True, eof_ok=False)
    if runner == "go":
        return _mask_go(lines)
    if runner == "cpp":
        return _skip_region(lines, _gtest_run, _gtest_done, keep_end=True, eof_ok=False)
    if runner == "dotnet":
        return _skip_region(lines, _dotnet_out, _dotnet_out_end, keep_end=True, eof_ok=False)
    if runner == "junit":
        return _skip_region(lines, _junit_out, _junit_out_end, keep_end=True, eof_ok=False)
    return lines, None


def _skip_region(lines, start, end, *, keep_end: bool, eof_ok: bool, keep_start: bool = False) -> tuple[list[str], str | None]:
    out: list[str] = []
    index = 0
    total = len(lines)
    while index < total:
        if start(lines[index]):
            nxt = index + 1
            while nxt < total and not end(lines[nxt]):
                nxt += 1
            if nxt >= total:
                if not eof_ok:
                    return [], "test_ids_unparsed_entry"
                return out, None
            if keep_start:
                out.append(lines[index])
            if keep_end:
                out.append(lines[nxt])
            index = nxt + 1
            continue
        out.append(lines[index])
        index += 1
    return out, None


def _py_cap(line: str) -> bool:
    text = line.strip()
    return "Captured stdout" in text or "Captured stderr" in text or "Captured log" in text


def _py_cap_end(line: str) -> bool:
    text = line.strip()
    return text.startswith("====") or (text.startswith("----") and "Captured " not in text)


def _jest_console(line: str) -> bool:
    return line.lstrip().startswith("● Console")


def _jest_console_end(line: str) -> bool:
    text = line.lstrip()
    if text.startswith("● ") and not text.startswith("● Console"):
        return True
    return not line[:1].isspace() and (
        line.startswith(("FAIL ", "PASS ", "Tests:", "Test Suites:"))
    )


def _vitest_stdio(line: str) -> bool:
    return line.strip().startswith(("stdout |", "stderr |"))


def _vitest_stdio_end(line: str) -> bool:
    text = line.strip()
    if text.startswith(("stdout |", "stderr |", "Tests", "Test Files")):
        return True
    if re.match(r"^[⎯\-]{2,}\s*(?:Failed Suites?|Unhandled Errors?|Failed Tests?)\b", text):
        return True
    return bool(re.match(r"^\s*×\s+\S", line))


def _mask_vitest(lines: list[str]) -> tuple[list[str], str | None]:
    """Drop stdout/stderr bodies. A column-0 FAIL there is unparsed, not an id."""
    out: list[str] = []
    index = 0
    total = len(lines)
    flagged = False
    while index < total:
        if _vitest_stdio(lines[index]):
            index += 1
            while index < total and not _vitest_stdio_end(lines[index]):
                body = lines[index]
                if not body[:1].isspace() and body.strip().startswith("FAIL ") and " > " in body:
                    flagged = True
                index += 1
            if index >= total:
                return [], "test_ids_unparsed_entry"
            continue
        out.append(lines[index])
        index += 1
    if flagged:
        return out, "test_ids_unparsed_entry"
    return out, None


def _cargo_stdio(line: str) -> bool:
    """Cargo ``---- name stdout ----``. Pytest's ``Captured stdout`` banner is not this."""
    text = line.strip()
    return (
        text.startswith("----")
        and text.endswith("----")
        and "stdout" in text
        and "Captured " not in text
    )


def _cargo_stdio_end(line: str) -> bool:
    text = line.strip()
    return text.startswith(("test result:", "test ")) or text == "failures:"


def _go_run(line: str) -> bool:
    return line.strip().startswith("=== RUN")


def _go_done(line: str) -> bool:
    return line.strip().startswith("--- ")


def _mask_go(lines: list[str]) -> tuple[list[str], str | None]:
    """Drop test-body lines. Keep every ``=== RUN`` and ``---`` marker.

    A nested ``=== RUN`` sits between the parent run and the first ``---``.
    It has to stay, so a verbose id can be checked against its own run.
    An unclosed run is unparsed.
    """
    out: list[str] = []
    in_body = False
    for line in lines:
        text = line.strip()
        if _go_run(line):
            out.append(line)
            in_body = True
            continue
        if _go_done(line):
            out.append(line)
            in_body = False
            continue
        if in_body:
            continue
        out.append(line)
    if in_body:
        return [], "test_ids_unparsed_entry"
    return out, None


def _gtest_run(line: str) -> bool:
    return bool(re.match(r"^\[\s+RUN\s+\]", line.strip()))


def _gtest_done(line: str) -> bool:
    return bool(re.match(r"^\[\s+(?:OK|FAILED|SKIPPED)\s+\]", line.strip()))


def _dotnet_out(line: str) -> bool:
    return line.strip() == "Standard Output Messages:"


def _dotnet_out_end(line: str) -> bool:
    return line.startswith(("Passed!", "Failed!"))


def _junit_out(line: str) -> bool:
    return line.strip() in {"Standard Out:", "Standard Error:"}


def _junit_out_end(line: str) -> bool:
    return line.startswith(("[INFO]", "[ERROR]", "[WARNING]"))


def _pick(count: int | None, structural: list[str], ids: list) -> tuple[list, str | None]:
    if count == 0:
        return [], "summary_reports_pass"
    if count is None:
        return ([], "test_ids_no_summary") if (structural or ids) else ([], None)
    if structural and len(structural) == count:
        return structural, None
    if len(ids) == count:
        return list(ids), None
    return [], "test_ids_count_mismatch"


def _jest_n(line: str) -> int | None:
    text = line.strip()
    if not text.startswith("Tests:"):
        return None
    failed = re.search(r"(\d+)\s+failed", text)
    if failed:
        return int(failed.group(1))
    if "passed" in text:
        return 0
    return None


def _jest(lines: list[str], ids: list) -> tuple[list, str | None]:
    hits = _hits(lines, _jest_n)
    if not hits and not ids and any(
        (ln.startswith("FAIL ") and " > " not in ln) or (ln[:1].isspace() and ln.lstrip().startswith("● "))
        for ln in lines
    ):
        return [], "test_ids_no_summary"
    return _one(hits, lines, ids, lambda ln: ln.startswith(("FAIL ", "PASS ")) or ln.lstrip().startswith("● "))


def _vitest_n(line: str) -> int | None:
    text = line.strip()
    failed = re.match(r"Tests\s+(\d+)\s+failed\b", text)
    if failed:
        return int(failed.group(1))
    passed = re.match(r"Tests\s+(\d+)\s+passed\b", text)
    if passed and "failed" not in text:
        return 0
    return None


def _vitest_fail_id(line: str) -> str | None:
    from sentinel_card.runners import _VITEST_FAIL, validate_js_ids

    matched = _VITEST_FAIL.match(line)
    if not matched:
        return None
    tid = f"{matched.group(1)} > {matched.group(2)}"
    clean, err = validate_js_ids([tid])
    if err or not clean:
        return None
    return clean[0]


def _vitest_tree_id(line: str) -> str | None:
    from sentinel_card.runners import validate_js_ids

    matched = re.match(
        r"^\s*×\s+(\S+\.[cm]?[jt]sx?)\s+>\s+(.+?)(?:\s+\d+(?:\.\d+)?m?s)?\s*$",
        line,
    )
    if not matched:
        return None
    tid = f"{matched.group(1)} > {matched.group(2)}"
    clean, err = validate_js_ids([tid])
    if err or not clean:
        return None
    return clean[0]


def _vitest(lines: list[str], ids: list) -> tuple[list, str | None]:
    """Before-summary ids and Failed Tests ids must be the same set as the count."""
    from sentinel_card.runners import _VITEST_FAILED_HDR, _VITEST_OTHER_HDR

    hits = _hits(lines, _vitest_n)
    if not hits:
        hits = _hits(lines, lambda ln: _file_n(ln.strip()))
    shaped = any(
        (ln.strip().startswith("FAIL ") and " > " in ln) or _vitest_tree_id(ln)
        for ln in lines
    )
    if len(hits) > 1:
        return [], "test_ids_multiple_summaries"
    if not hits:
        if ids or shaped:
            return [], "test_ids_no_summary"
        return [], None
    index, count = hits[0]
    if count == 0:
        return [], "summary_reports_pass"
    before: list[str] = []
    under: list[str] = []
    section = False
    failed_tests = False
    for at, ln in enumerate(lines):
        text = ln.strip()
        if _VITEST_OTHER_HDR.match(text):
            failed_tests = bool(_VITEST_FAILED_HDR.match(text))
            section = True
            continue
        if text.startswith(("Tests", "Test Files")):
            section = False
            failed_tests = False
        if at > index and not section and (_vitest_fail_id(ln) or _vitest_tree_id(ln)):
            return [], "test_ids_multiple_summaries"
        tid = _vitest_fail_id(ln) or _vitest_tree_id(ln)
        if not tid:
            continue
        bucket = under if failed_tests else before
        if at < index or failed_tests:
            if tid not in bucket:
                bucket.append(tid)
    if before and under and set(before) != set(under):
        return [], "test_ids_result_disagreed"
    chosen = before or under
    if before and under and len(set(chosen)) != count:
        return [], "test_ids_result_disagreed"
    return _pick(count, chosen, chosen)


def _file_n(text: str) -> int | None:
    failed = re.match(r"Test Files\s+(\d+)\s+failed\b", text)
    if failed:
        return int(failed.group(1))
    if text.startswith("Test Files") and re.search(r"\d+\s+passed\b", text) and "failed" not in text:
        return 0
    return None


def _mocha(lines: list[str], ids: list) -> tuple[list, str | None]:
    from sentinel_card.runners import _MOCHA_FAILING

    hits = _hits(lines, lambda ln: int(ln.strip().split()[0]) if _MOCHA_FAILING.match(ln) else None)
    if len(hits) > 1:
        return [], "test_ids_multiple_summaries"
    if len(hits) == 1:
        entries = [ln for ln in lines if re.match(r"^  \d+\)\s+\S", ln)]
        got = _one(hits, lines, ids, lambda _ln: False)
        if got[1] is None and entries and len(entries) != len(got[0]):
            return [], "test_ids_unparsed_entry"
        return got
    stats = re.search(r'"stats"\s*:\s*\{[^}]*"failures"\s*:\s*(\d+)', "\n".join(lines))
    if stats:
        return _pick(int(stats.group(1)), [], ids)
    if ids:
        return [], "test_ids_no_summary"
    return [], None



def _go(lines: list[str], ids: list) -> tuple[list, str | None]:
    """Ids only from ``go test -json`` events already parsed by the extractor.

    Any raw Go text log abstains. JSON mixed with that text abstains too.
    """
    kind = _go_kind(lines)
    if kind == "mixed":
        return [], "test_ids_result_disagreed"
    if kind == "text":
        return [], "go_text_output_unverifiable"
    if kind == "json":
        return list(ids), None
    if ids:
        return [], "test_ids_no_summary"
    return [], None



def _cargo_n(line: str) -> int | None:
    matched = re.match(r"^test result: (?:ok|FAILED)\. \d+ passed; (\d+) failed;", line.strip())
    if matched:
        return int(matched.group(1))
    return None


def _cargo(lines: list[str], ids: list) -> tuple[list, str | None]:
    hits = _hits(lines, _cargo_n)
    if hits:
        return _one(hits, lines, ids, lambda ln: bool(re.match(r"^test \S+ \.\.\. FAILED$", ln.strip())))
    nextest = list(re.finditer(r"Summary\s+\[[^\]]+\]\s+\d+\s+tests?\s+run:.*?(\d+)\s+failed", "\n".join(lines)))
    if len(nextest) > 1:
        return [], "test_ids_multiple_summaries"
    if nextest:
        return _pick(int(nextest[0].group(1)), [], ids)
    if ids:
        return [], "test_ids_no_summary"
    return [], None


def _count_pair(lines: list[str], pattern: str, ids: list, *, total=lambda row: int(row[-1]), after=lambda _ln: False) -> tuple[list, str | None]:
    hits: list[tuple[int, int]] = []
    regex = re.compile(pattern)
    for index, line in enumerate(lines):
        matched = regex.search(line)
        if matched:
            hits.append((index, total(matched.groups())))
    return _one(hits, lines, ids, after)


def _rspec(lines: list[str], ids: list) -> tuple[list, str | None]:
    return _count_pair(
        lines, r"(\d+) examples?, (\d+) failures?", ids,
        after=lambda ln: ln.strip().startswith("rspec "),
    )


def _minitest(lines: list[str], ids: list) -> tuple[list, str | None]:
    return _count_pair(
        lines,
        r"(\d+) failures?, (\d+) errors?",
        ids,
        total=lambda row: int(row[0]) + int(row[1]),
        after=lambda ln: bool(re.match(r"^\S+#test\S* \[", ln.strip())),
    )


def _phpunit(lines: list[str], ids: list) -> tuple[list, str | None]:
    from sentinel_card.phpunit import phpunit_summary_gate

    return phpunit_summary_gate(lines, ids)


def _junit(lines: list[str], ids: list) -> tuple[list, str | None]:
    # A per-class ``Tests run: … -- in Class`` line is not a second module run.
    text = "\n".join(lines)
    footers: list[tuple[int, int]] = []
    for index, ln in enumerate(lines):
        if "-- in " in ln:
            continue
        matched = re.search(r"Tests run:\s*\d+,\s*Failures:\s*(\d+),\s*Errors:\s*(\d+)", ln)
        if matched:
            footers.append((index, int(matched.group(1)) + int(matched.group(2))))
    success = "BUILD SUCCESS" in text
    marks = [
        ln for ln in lines
        if ("<<< FAILURE" in ln or "<<< ERROR" in ln) and "Tests run:" not in ln
    ]
    if len(footers) > 1:
        return [], "test_ids_multiple_summaries"
    if not footers:
        if success and not ids:
            return [], "summary_reports_pass"
        return ([], "test_ids_no_summary") if ids else ([], None)
    index, count = footers[0]
    if count == 0:
        return [], "summary_reports_pass"
    if any(("<<< FAILURE" in ln or "<<< ERROR" in ln) and "Tests run:" not in ln for ln in lines[index + 1:]):
        return [], "test_ids_multiple_summaries"
    if success:
        return [], "test_ids_result_disagreed"
    if marks and len(marks) != len(ids):
        return [], "test_ids_unparsed_entry"
    return _pick(count, [], ids)


def _cpp(lines: list[str], ids: list) -> tuple[list, str | None]:
    from sentinel_card.cpp import cpp_summary_gate

    return cpp_summary_gate(lines, ids)


def _dotnet(lines: list[str], ids: list) -> tuple[list, str | None]:
    return _one(
        _hits(lines, lambda ln: int(m.group(1)) if (m := re.search(r"Failed:\s*(\d+)", ln)) else None),
        lines,
        ids,
        lambda ln: ln.strip().startswith("Failed ") and not re.search(r"Failed:\s*\d+", ln),
    )


_HANDLERS = {
    "pytest": _pytest,
    "jest": _jest,
    "vitest": _vitest,
    "mocha": _mocha,
    "go": _go,
    "cargo": _cargo,
    "rspec": _rspec,
    "minitest": _minitest,
    "phpunit": _phpunit,
    "junit": _junit,
    "cpp": _cpp,
    "dotnet": _dotnet,
}
