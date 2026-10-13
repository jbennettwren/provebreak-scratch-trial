"""PHPUnit ids for one Composer project.

Experimental scaffolding. A test id is
``tests/CalcTest.php::Lab\\Tests\\CalcTest::testAdds``. Red and green come
only from that run's JUnit ``<testcase>``. An exit code by itself is not
a pass.

One ``composer.json`` plus ``composer.lock`` that locks
``phpunit/phpunit`` is the only layout this runner installs. A missing
lockfile, a second Composer project, and a data-provider name abstain.
They are not a culprit.
"""
from __future__ import annotations

import os
import re
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from provebreak_culprit._engine.bisect import _scrub_reason
from provebreak_culprit._engine.bisect import apply_isolated_home
from provebreak_culprit._engine.bisect import build_scrubbed_env
from provebreak_culprit._engine.toolchain_pin import COMPOSER_VERSION
from provebreak_culprit._engine.toolchain_pin import PHP_VERSION
from provebreak_culprit._engine.toolchain_pin import version_mismatch

MAX_PHP_ID_LEN = 512
_SKIP_DIRS = frozenset({".git", "vendor", "node_modules", "tmp"})
_PHP_FILE = re.compile(r"^[A-Za-z0-9_./-]+\.php$")
_CLASS = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\\[A-Za-z_][A-Za-z0-9_]*)*$")
_METHOD = re.compile(r"^test[A-Za-z0-9_]+$")
_GH_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z ?")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_WF_CMD = re.compile(r"^##\[[A-Za-z]+\]\s?")
_FAIL_LINE = re.compile(
    r"^\d+\)\s+([A-Za-z_][A-Za-z0-9_\\]*)::(test[A-Za-z0-9_]+)\s*$"
)
_PEST_FAIL = re.compile(
    r"^(?:FAILED|FAIL|[⨯✗×])\s+([A-Za-z_][A-Za-z0-9_\\]*)::(test[A-Za-z0-9_]+)\s*$"
)
_UNSAFE_FAIL = re.compile(r"^\d+\)\s+\S")
_PHPUNIT_MARK = re.compile(r"(?m)^(?:PHPUnit \d|There was \d+ (?:failure|error)|FAILURES!|OK \()")
_BUILD = re.compile(
    r"Parse error|syntax error|Could not open input file|Class .* not found|"
    r"Failed opening required|Your requirements could not be resolved|"
    r"composer\.lock"
)
_LOCK_NAME = re.compile(r'"name"\s*:\s*"phpunit/phpunit"')


@dataclass
class PhpunitLog:
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


def _safe_php(path: str) -> bool:
    text = (path or "").strip()
    if text.startswith("./"):
        text = text[2:]
    if not text or text.startswith(("/", "-")) or ".." in text.split("/"):
        return False
    return bool(_PHP_FILE.fullmatch(text))


def _rel_php(path: str) -> str | None:
    text = (path or "").strip().replace("\\", "/")
    text = re.sub(r":\d+$", "", text)
    if text.startswith("./"):
        text = text[2:]
    if _safe_php(text):
        return text
    if not text.startswith("/"):
        return None
    for marker in ("/tests/", "/test/"):
        idx = text.rfind(marker)
        if idx >= 0 and _safe_php(text[idx + 1:]):
            return text[idx + 1:]
    name = text.rsplit("/", 1)[-1]
    if _safe_php(name):
        return name
    return None


def validate_phpunit_ids(tests: list | tuple) -> tuple[list[str], str | None]:
    """``file.php::Namespace\\Class::testMethod``. Data providers are refused."""
    if not tests:
        return [], "no_failing_tests_provided"
    clean: list[str] = []
    for raw in tests:
        text = str(raw).strip()
        if not text:
            continue
        if len(text) > MAX_PHP_ID_LEN:
            return [], f"phpunit_id_too_long:{text[:40]}"
        if any(ord(c) < 32 for c in text) or text.startswith("-") or " " in text or "#" in text:
            return [], f"phpunit_unsupported_id:{text[:40]}"
        file, sep, rest = text.partition("::")
        if not sep or "::" not in rest:
            return [], f"phpunit_unsupported_id:{text[:40]}"
        class_name, method = rest.rsplit("::", 1)
        rel = _rel_php(file)
        if rel is None or not _CLASS.fullmatch(class_name) or not _METHOD.fullmatch(method):
            return [], f"phpunit_unsupported_id:{text[:40]}"
        tid = f"{rel}::{class_name}::{method}"
        if tid not in clean:
            clean.append(tid)
    return (clean, None) if clean else ([], "no_failing_tests_provided")


def split_phpunit_id(text: str) -> tuple[str, str, str] | None:
    clean, err = validate_phpunit_ids([text])
    if err or not clean:
        return None
    file, rest = clean[0].split("::", 1)
    class_name, method = rest.rsplit("::", 1)
    return file, class_name, method


def phpunit_filter(class_name: str, method: str) -> str:
    """Anchored regex. ``re.escape`` keeps a namespace separator literal."""
    return "^" + re.escape(f"{class_name}::{method}") + "$"


def phpunit_summary_gate(lines: list[str], ids: list[str]) -> tuple[list[str], str | None]:
    from provebreak_culprit._engine.summary_gate import _pick

    text = "\n".join(lines)
    # Surefire also prints ``Failures: N``. Only a PHPUnit/Pest log counts.
    if not ids and not re.search(r"(?m)PHPUnit|^FAILURES!|Assertions:|^OK(?:[ \t]*\(|[ \t]*$)", text):
        return [], None
    oks = re.findall(r"(?m)^OK(?:[ \t]*\(|[ \t]*$)", text)
    banners = re.findall(r"(?m)^FAILURES![ \t]*$", text)
    fails = [int(n) for n in re.findall(r"Failures:[ \t]*(\d+)", text)]
    errs = [int(n) for n in re.findall(r"Errors:[ \t]*(\d+)", text)]
    if len(oks) > 1 or len(banners) > 1 or len(fails) > 1 or len(errs) > 1:
        return [], "test_ids_multiple_summaries"
    if oks and (banners or fails or errs):
        return [], "test_ids_multiple_summaries"
    if oks:
        return [], "summary_reports_pass"
    if not fails and not errs:
        return ([], "test_ids_no_summary") if ids else ([], None)
    return _pick((fails[0] if fails else 0) + (errs[0] if errs else 0), [], ids)


def _php_done(log_text: str, ids: list[str], error: str | None = None) -> PhpunitLog:
    from provebreak_culprit._engine.summary_gate import finish

    kept, err = finish("phpunit", log_text, ids, error)
    return PhpunitLog(kept, err)


def extract_phpunit(log_text: str, *, limit: int = 20) -> PhpunitLog:
    """Failing PHPUnit ids from ``N) Namespace\\Class::testMethod`` plus a path.

    A data-provider name (``with data set``) is ``phpunit_unsupported_id``
    when nothing safer was found. An ``OK`` summary is not an id.
    """
    if not log_text:
        return _php_done(log_text, [])
    lines = _lines(log_text)
    found: list[str] = []
    unsafe = False
    unparsed = False
    saw = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        data = re.match(
            r"^\d+\)\s+([A-Za-z_][A-Za-z0-9_\\]*)::(test[A-Za-z0-9_]+)\s+with data set\b",
            stripped,
        )
        if data or "with data set" in stripped:
            saw = True
            matched_data = data
            rel = None
            if matched_data:
                for follow in lines[index + 1:index + 8]:
                    rel = _rel_php(follow.strip())
                    if rel:
                        break
            if not matched_data or rel is None:
                unparsed = True
                continue
            tid = f"{rel}::{matched_data.group(1)}::{matched_data.group(2)}"
            clean, err = validate_phpunit_ids([tid])
            if err or not clean:
                unparsed = True
                continue
            if clean[0] not in found:
                found.append(clean[0])
            continue
        matched = _FAIL_LINE.match(stripped)
        if not matched:
            if _UNSAFE_FAIL.match(stripped) and "::" in stripped and _PHPUNIT_MARK.search(log_text):
                unsafe = True
                saw = True
            continue
        saw = True
        rel = None
        for follow in lines[index + 1:index + 8]:
            candidate = follow.strip()
            if not candidate or candidate.startswith("Failed asserting"):
                continue
            rel = _rel_php(candidate)
            if rel:
                break
        if rel is None:
            unsafe = True
            continue
        tid = f"{rel}::{matched.group(1)}::{matched.group(2)}"
        clean, err = validate_phpunit_ids([tid])
        if err or not clean:
            unsafe = True
            continue
        if clean[0] not in found:
            found.append(clean[0])
        if len(found) >= limit:
            break
    pest, pest_err = _pest_ids(lines, limit=limit)
    if unparsed:
        return _php_done(log_text, [], "test_ids_unparsed_entry")
    if found:
        if pest_err or (pest and set(pest) != set(found)):
            return _php_done(log_text, [], "phpunit_unsupported_id")
        return _php_done(log_text, found)
    if pest_err:
        return _php_done(log_text, [], pest_err)
    if pest:
        return _php_done(log_text, pest)
    if unsafe or (saw and _PHPUNIT_MARK.search(log_text or "")):
        return _php_done(log_text, [], "phpunit_unsupported_id")
    return _php_done(log_text, [])


def _pest_ids(lines: list[str], *, limit: int) -> tuple[list[str], str | None]:
    """``FAILED`` or ``⨯`` plus ``Class::testMethod`` and one test file.

    A path under ``vendor/`` is not the test's own file. Two paths inside the
    next eight lines, including the next failure's path, are
    ``test_ids_ambiguous_location``. A chopped name is ``test_ids_truncated``.
    """
    found: list[str] = []
    reason: str | None = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if "with data set" in stripped:
            continue
        matched = _PEST_FAIL.match(stripped)
        if not matched:
            failish = re.match(r"^(?:FAILED|FAIL|[⨯✗×])\s+\S", stripped)
            if failish and ("…" in stripped or "..." in stripped):
                reason = "test_ids_truncated"
                continue
            if re.match(r"^[⨯✗×]\s+\S", stripped) or (
                re.match(r"^(?:FAILED|FAIL)\s+\S", stripped) and "::" in stripped
            ):
                reason = reason or "test_ids_ambiguous_location"
            continue
        if "…" in stripped or "..." in matched.group(2):
            reason = "test_ids_truncated"
            continue
        paths: list[str] = []
        for follow in lines[index + 1:index + 8]:
            candidate = follow.strip()
            if not candidate or candidate.startswith(("Failed asserting", "Failed ", "⨯", "✗", "×")):
                continue
            rel = _rel_php(candidate.split()[-1] if candidate.lower().startswith("at ") else candidate)
            if rel and rel not in paths:
                paths.append(rel)
        own = [path for path in paths if "vendor" not in path.split("/")]
        if len(paths) != 1 or len(own) != 1:
            reason = reason or "test_ids_ambiguous_location"
            continue
        tid = f"{own[0]}::{matched.group(1)}::{matched.group(2)}"
        clean, err = validate_phpunit_ids([tid])
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


def php_layout(root: Path) -> tuple[str, str | None]:
    """``('composer_single', None)`` or ``('unsupported', reason)``.

    Composer is not run unless one project locks ``phpunit/phpunit``.
    """
    manifests = _walk_named(Path(root), "composer.json")
    if len(manifests) > 1:
        return "unsupported", "php_multi_package"
    if not manifests:
        return "unsupported", "php_no_composer"
    manifest = manifests[0]
    lock = manifest.parent / "composer.lock"
    if not lock.is_file():
        return "unsupported", "composer_lock_missing"
    try:
        if lock.is_symlink() or lock.stat().st_size > 2_000_000:
            return "unsupported", "phpunit_not_locked"
        text = lock.read_text(encoding="utf-8", errors="replace")[:2_000_000]
    except OSError:
        return "unsupported", "phpunit_not_locked"
    if not _LOCK_NAME.search(text):
        return "unsupported", "phpunit_not_locked"
    return "composer_single", None


def repo_suggests_phpunit(root: Path) -> bool:
    layout, reason = php_layout(root)
    if layout == "composer_single":
        return True
    return reason in {"composer_lock_missing", "php_multi_package", "phpunit_not_locked"}


def _executable(name: str) -> bool:
    if not name or any(ord(c) < 32 for c in name):
        return False
    path = Path(name)
    if path.is_file() and os.access(path, os.X_OK):
        return True
    return shutil.which(name) is not None


def toolchain_error(*, php_bin: str = "php", composer_bin: str = "composer") -> str | None:
    """Missing binary, then the one-click pin. A wrong version is not a culprit."""
    if not _executable(php_bin):
        return "php_missing"
    if not _executable(composer_bin):
        return "composer_missing"
    why = version_mismatch([php_bin, "--version"], PHP_VERSION, "php_version_mismatch")
    if why:
        return why
    return version_mismatch([composer_bin, "--version"], COMPOSER_VERSION, "composer_version_mismatch")


def php_child_env(home: Path, cache: Path, *, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Scrubbed env. Composer cache stays in the bisect cache.

    No auth env is copied. ``build_scrubbed_env`` drops names that contain
    ``TOKEN``. Install uses ``--no-scripts`` so a checkout hook does not run.
    """
    composer_home = Path(cache) / "composer-home"
    composer_cache = Path(cache) / "composer-cache"
    composer_home.mkdir(parents=True, exist_ok=True)
    composer_cache.mkdir(parents=True, exist_ok=True)
    overlay = {
        "COMPOSER_HOME": str(composer_home),
        "COMPOSER_CACHE_DIR": str(composer_cache),
        "COMPOSER_DISABLE_XDEBUG_WARN": "1",
        "COMPOSER_NO_INTERACTION": "1",
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


def composer_install_argv(composer: str) -> list[str]:
    """Dev dependencies stay installed: PHPUnit is a require-dev package.

    ``--no-scripts`` skips checkout hooks. ``--no-plugins`` skips Composer
    plugins. The lockfile still selects the versions.
    """
    return [
        composer, "install",
        "--no-interaction", "--no-progress", "--prefer-dist",
        "--no-scripts", "--no-plugins",
    ]


def phpunit_argv(binary: str, tests: list[str], junit_path: Path) -> list[str] | None:
    files = []
    filters = []
    for tid in tests:
        split = split_phpunit_id(tid)
        if split is None:
            return None
        file, class_name, method = split
        if file not in files:
            files.append(file)
        filters.append(phpunit_filter(class_name, method))
    if len(filters) != 1:
        pattern = "(?:" + "|".join(filters) + ")"
    else:
        pattern = filters[0]
    return [
        binary, "--do-not-cache-result", "--colors=never",
        "--filter", pattern, "--log-junit", str(junit_path),
        *files,
    ]


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_phpunit_junit(xml_text: str) -> list[dict] | None:
    """One row per ``<testcase>``. ``None`` when the XML does not parse."""
    if not xml_text or "<testcase" not in xml_text or len(xml_text) > 2_000_000:
        return None
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    rows = []
    for el in root.iter():
        if _local(el.tag) != "testcase":
            continue
        kids = {_local(child.tag) for child in list(el)}
        if "failure" in kids or "error" in kids:
            outcome = "failed"
        elif "skipped" in kids:
            outcome = "skipped"
        else:
            outcome = "passed"
        rows.append({
            "name": el.attrib.get("name") or "",
            "class": el.attrib.get("class") or "",
            "file": el.attrib.get("file") or "",
            "outcome": outcome,
        })
    return rows


def _failure_detail(text: str) -> str:
    lines = []
    for raw in _lines(text):
        line = raw.strip()
        if line.startswith("Failed asserting") or line.startswith("1) "):
            lines.append(line)
    if not lines:
        lines = [ln.strip() for ln in _lines(text) if ln.strip()][-3:]
    return " | ".join(lines[:3])


def classify_phpunit(
    output: str,
    junit_xml: str | None,
    tests: list[str],
) -> tuple[str, str, str, str]:
    """``(label, kind, detail, failure_shape)``.

    Green requires one JUnit ``<testcase>`` for each requested id and no
    failure child. A data-provider row is not that id. Exit 0 is not green.
    """
    clean, err = validate_phpunit_ids(tests)
    detail = _scrub_reason(_failure_detail(output or ""), max_len=200)
    if err or not clean:
        return "error", "unknown", detail or (err or "phpunit_unsupported_id"), ""
    rows = parse_phpunit_junit(junit_xml or "")
    if rows is None:
        if _BUILD.search(output or ""):
            return "error", "build_error", detail or "php_build_failed", ""
        return "error", "unknown", detail or "phpunit_result_unparsed", ""
    statuses = []
    for tid in clean:
        split = split_phpunit_id(tid)
        if split is None:
            statuses.append("missing")
            continue
        file, class_name, method = split
        hits = []
        for row in rows:
            if row.get("class") != class_name or row.get("name") != method:
                continue
            rel = _rel_php(str(row.get("file") or ""))
            if rel and rel != file and not rel.endswith("/" + file) and file not in rel:
                continue
            hits.append(row.get("outcome") or "")
        if len(hits) != 1:
            statuses.append("missing" if not hits else "ambiguous")
        else:
            statuses.append({"failed": "fail", "passed": "pass", "skipped": "skip"}.get(hits[0], "missing"))
    if any(status == "fail" for status in statuses) and "missing" not in statuses and "ambiguous" not in statuses:
        shape = "assertion" if "Failed asserting" in (output or "") or "Failed asserting" in (junit_xml or "") else ""
        return "red", "fail", detail or "phpunit_fail", shape
    if any(status in ("missing", "ambiguous") for status in statuses):
        if _BUILD.search(output or "") and "fail" not in statuses:
            return "error", "build_error", detail or "php_build_failed", ""
        return "error", "not_found" if "ambiguous" not in statuses else "unknown", detail or "phpunit_result_unparsed", ""
    if any(status == "skip" for status in statuses):
        return "error", "skipped", detail or "phpunit_skipped", ""
    return "green", "pass", detail or "phpunit_pass", ""
