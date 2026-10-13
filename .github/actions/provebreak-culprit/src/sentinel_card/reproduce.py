"""One-line local reproduce command. Omitted unless the parse is unambiguous."""

from __future__ import annotations

import re

from sentinel_card.urls import valid_sha

# Known workflow-command names. A test id must not become one of these.
_WF_CMDS = frozenset(
    {
        "add-mask",
        "add-path",
        "debug",
        "echo",
        "endgroup",
        "error",
        "group",
        "notice",
        "save-state",
        "set-env",
        "set-output",
        "stop-commands",
        "warning",
    }
)
_TOKEN = re.compile(r"^[A-Za-z0-9_./:-]{1,300}$")
_PYTEST_FAIL = re.compile(
    r"(?m)^(?:FAILED|ERROR)\s+([A-Za-z0-9_./-]+\.py(?:::[A-Za-z0-9_]+){1,4})\b"
)
_JEST_FILE = re.compile(
    r"(?m)^FAIL\s+([A-Za-z0-9_./-]+\.(?:test|spec)\.[cm]?[jt]sx?)\b"
)
_JEST_NAME = re.compile(r"(?m)^[ \t]*●[ \t]+([^\n]{1,160})$")
_VITEST_FAIL = re.compile(
    r"(?m)^[ \t]*FAIL[ \t]+([A-Za-z0-9_./-]+\.(?:test|spec)\.[cm]?[jt]sx?)[ \t]+>[ \t]+([^\n]{1,160})$"
)
_GO_FAIL = re.compile(r"(?m)^--- FAIL: (Test[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)?)\b")
_GO_PKG = re.compile(r"(?m)^FAIL\t([A-Za-z0-9_./-]+)\t")
_MAX_TESTS = 10


def allow_test_token(token: str | None) -> str:
    """Pytest node id or similar. Rejects workflow-command segments and path escape."""
    if not token or not isinstance(token, str):
        return ""
    s = token.strip()
    if not _TOKEN.match(s):
        return ""
    if ".." in s.split("/"):
        return ""
    parts = s.split("::")
    if any(not part or part.lower() in _WF_CMDS for part in parts):
        return ""
    return s


def _unique(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _safe_name(name: str) -> str:
    """Jest/vitest/go display name safe to place inside single quotes."""
    s = name.strip()
    if not s or len(s) > 160:
        return ""
    if any(c in s for c in ("'", "`", "\n", "\r", "\\", "$", "<", ">", "|", "&")):
        return ""
    if "::" in s:
        return ""
    if s.lower() in _WF_CMDS:
        return ""
    return s


def _safe_path(path: str) -> str:
    s = path.strip()
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", s):
        return ""
    if ".." in s.split("/") or s.startswith("/"):
        return ""
    return s


def parse_log(log_text: str | None) -> dict | None:
    """Return {runner, tests, files, package} or None. Never raises."""
    if not log_text or not isinstance(log_text, str):
        return None
    text = log_text[:1_000_000]
    found: list[dict] = []

    pytest_ids = _unique([m.group(1) for m in _PYTEST_FAIL.finditer(text)])
    pytest_ids = [i for i in pytest_ids if allow_test_token(i)]
    if pytest_ids:
        if len(pytest_ids) > _MAX_TESTS:
            return None
        found.append(
            {"runner": "pytest", "tests": pytest_ids, "files": [], "package": ""}
        )

    jest_signal = "Test Suites:" in text or "●" in text
    vitest_signal = "vitest" in text.lower() or "Test Files" in text
    # Both families at once is ambiguous — ignore JS runners, keep pytest if present.
    if jest_signal and vitest_signal:
        jest_signal = False
        vitest_signal = False

    if jest_signal and not vitest_signal:
        files = _unique([_safe_path(m.group(1)) for m in _JEST_FILE.finditer(text)])
        files = [f for f in files if f]
        names = _unique([_safe_name(m.group(1)) for m in _JEST_NAME.finditer(text)])
        names = [n for n in names if n]
        if files and names:
            if len(files) > _MAX_TESTS or len(names) > _MAX_TESTS:
                return None
            found.append(
                {"runner": "jest", "tests": names, "files": files, "package": ""}
            )

    if not (jest_signal and vitest_signal):
        from sentinel_card.runners import extract_mocha_failing_tests
        from sentinel_card.runners import looks_like_karma

        if not looks_like_karma(text):
            mocha_ids = extract_mocha_failing_tests(text)
            if mocha_ids and len(mocha_ids) <= _MAX_TESTS:
                files = []
                names = []
                for tid in mocha_ids:
                    file, sep, rest = tid.partition(" > ")
                    path = _safe_path(file) if sep else ""
                    name = _safe_name(" ".join(part.strip() for part in rest.split(" > "))) if sep else ""
                    if path and name:
                        files.append(path)
                        names.append(name)
                files = _unique(files)
                names = _unique(names)
                if files and names:
                    found.append({"runner": "mocha", "tests": names, "files": files, "package": ""})

    if vitest_signal and not jest_signal:
        files: list[str] = []
        names: list[str] = []
        for m in _VITEST_FAIL.finditer(text):
            path = _safe_path(m.group(1))
            name = _safe_name(m.group(2))
            if path and name:
                files.append(path)
                names.append(name)
        files = _unique(files)
        names = _unique(names)
        if files and names and len(files) <= _MAX_TESTS and len(names) <= _MAX_TESTS:
            found.append(
                {"runner": "vitest", "tests": names, "files": files, "package": ""}
            )

    go_names = _unique([m.group(1) for m in _GO_FAIL.finditer(text)])
    go_names = [n for n in go_names if _safe_go(n)]
    if go_names:
        if len(go_names) > _MAX_TESTS:
            return None
        pkgs = _unique([_safe_path(m.group(1)) for m in _GO_PKG.finditer(text)])
        pkgs = [p for p in pkgs if p and ".." not in p]
        package = pkgs[0] if len(pkgs) == 1 else ""
        if len(pkgs) > 1:
            package = "./..."
        found.append(
            {
                "runner": "go",
                "tests": go_names,
                "files": [],
                "package": package or "./...",
            }
        )

    runners = {item["runner"] for item in found}
    if len(runners) != 1:
        return None
    return found[0]


def _safe_go(name: str) -> bool:
    from sentinel_card.runners import go_test_path_ok

    return go_test_path_ok(name)


def _ids_from_list(values: list | None) -> list[str]:
    out: list[str] = []
    for value in values or []:
        if isinstance(value, str):
            kept = allow_test_token(value)
            if kept and ".py::" in kept:
                out.append(kept)
    return _unique(out)[: _MAX_TESTS + 1]


def parse_annotations(annotations: list | None) -> dict | None:
    ids: list[str] = []
    for ann in annotations or []:
        if not isinstance(ann, dict):
            continue
        for key in ("node_ids", "failing_tests"):
            ids.extend(
                _ids_from_list(ann.get(key) if isinstance(ann.get(key), list) else [])
            )
        for key in ("message", "title"):
            raw = ann.get(key)
            if isinstance(raw, str):
                ids.extend(_ids_from_list(_PYTEST_FAIL.findall(raw) or _loose_ids(raw)))
    ids = _unique([i for i in ids if allow_test_token(i)])
    if not ids or len(ids) > _MAX_TESTS:
        return None
    return {"runner": "pytest", "tests": ids, "files": [], "package": ""}


def _loose_ids(text: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9_./-]+\.py(?:::[A-Za-z0-9_]+){1,4}", text)


def _same(a: dict | None, b: dict | None) -> bool:
    if not a or not b:
        return False
    if a["runner"] != b["runner"]:
        return False
    return set(a["tests"]) == set(b["tests"]) and set(a.get("files") or []) == set(
        b.get("files") or []
    )


def _choose(*sources: dict | None) -> dict | None:
    present = [s for s in sources if s and s.get("tests")]
    if not present:
        return None
    if len(present) == 1:
        item = present[0]
        return None if len(item["tests"]) > _MAX_TESTS else item
    head = present[0]
    if all(_same(head, other) for other in present[1:]):
        return head
    return None


def _shell_pattern(names: list[str]) -> str:
    # Names are single-quote safe. Escape regex metacharacters for -t / -run.
    escaped = []
    for name in names:
        escaped.append(re.sub(r"([.\\+*?^$()\[\]{}|])", r"\\\1", name))
    if len(escaped) == 1:
        return escaped[0]
    # Group the alternation so ^ and $ apply to every name, not just the ends.
    return "(?:" + "|".join(escaped) + ")"


def _playwright_from_ids(ids: list[str]) -> dict | None:
    """One spec becomes one ``playwright test`` command. Several specs do not."""
    from sentinel_card.browser_spec import _split_spec
    from sentinel_card.browser_spec import safe_spec_path

    if len(ids) != 1:
        return None
    file, title = _split_spec(ids[0])
    rel = safe_spec_path(file)
    title = title.strip()
    if not rel or not title or "'" in rel or "'" in title:
        return None
    return {"runner": "playwright", "tests": [title], "files": [rel], "package": ""}


def _js_test(runner: str, files: list[str], tests: list[str]) -> str:
    pattern = _shell_pattern(tests)
    joined = " ".join(files)
    if runner == "jest":
        return f"npx jest {joined} -t '{pattern}'"
    if runner == "mocha":
        return f"npx mocha {joined} --grep '{pattern}'"
    return f"npx vitest run {joined} -t '{pattern}'"


def _command(parsed: dict, sha: str, workspace: dict | None = None) -> str:
    runner = parsed["runner"]
    if runner == "pytest":
        joined = " ".join(parsed["tests"])
        return f"git checkout {sha} && pytest {joined}"
    if runner == "playwright":
        file = parsed["files"][0]
        title = parsed["tests"][0]
        return (
            f"git checkout {sha} && npx playwright test '{file}' -g '{title}' "
            "--retries=0 --workers=1"
        )
    if runner in ("jest", "vitest", "mocha"):
        files = list(parsed["files"])
        body = _js_test(runner, files, parsed["tests"])
        if workspace:
            td = workspace.get("test_dir") or ""
            if td:
                prefix = td + "/"
                files = [f[len(prefix):] if f.startswith(prefix) else f for f in files]
                body = f"cd {td} && {_js_test(runner, files, parsed['tests'])}"
            return f"git checkout {sha} && {workspace['install']} && {workspace['build']} && {body}"
        return f"git checkout {sha} && {body}"
    if runner == "go":
        from sentinel_card.runners import go_run_regexes

        pkg = parsed.get("package") or "./..."
        cmds = [f"go test -count=1 -run '{reg}' {pkg}" for reg in go_run_regexes(parsed["tests"])]
        return f"git checkout {sha} && " + " && ".join(cmds)
    if runner == "junit":
        joined = ",".join(parsed["tests"])
        if "'" in joined or "`" in joined:
            return ""
        return (
            f"git checkout {sha} && mvn -B -Dsurefire.failIfNoSpecifiedTests=true "
            f"'-Dtest={joined}' test"
        )
    if runner == "cargo":
        joined = " ".join(parsed["tests"])
        if "'" in joined or "`" in joined:
            return ""
        return f"git checkout {sha} && cargo test --color never -- --exact {joined}"
    if runner == "cpp":
        from sentinel_card.cpp import ctest_name_regex

        pattern = ctest_name_regex(parsed["tests"])
        if "'" in pattern or "`" in pattern:
            return ""
        return (
            f"git checkout {sha} && cmake -S . -B build -G 'Unix Makefiles' "
            f"-DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ && cmake --build build && "
            f"ctest --test-dir build --output-on-failure -R '{pattern}'"
        )
    if runner == "minitest":
        file = parsed["files"][0]
        name = parsed["tests"][0]
        if "'" in file or "'" in name:
            return ""
        return f"git checkout {sha} && bundle exec ruby {file} -v -n '/\\A{name}\\z/'"
    if runner == "rspec":
        file = parsed["files"][0]
        name = parsed["tests"][0]
        if "'" in file or "'" in name or "`" in name:
            return ""
        return f"git checkout {sha} && bundle exec rspec {file} --format documentation --example '{name}'"
    if runner == "phpunit":
        file = parsed["files"][0]
        name = parsed["tests"][0]
        if "'" in file or "'" in name or "`" in name:
            return ""
        return (
            f"git checkout {sha} && vendor/bin/phpunit --do-not-cache-result --colors=never "
            f"--filter '{name}' {file}"
        )
    return ""


def _command_safe(command: str) -> bool:
    """Allow the separators we insert; reject everything else that can escape a shell."""
    if not command or len(command) > 1000:
        return False
    outside_quotes = re.sub(r"'[^']*'", "", command)
    if any(c in outside_quotes for c in ("\n", "\r", "`", "$", ";", ">", "<", "|")):
        return False
    if "&" in command.replace(" && ", ""):
        return False
    return True


_JS_SEP = " > "


def _from_card_ids(card: dict, cc: dict) -> dict | None:
    """5.2.1: Go / vitest / jest / mocha reproduce from the validated v5 ids.

    Go ids are ``<import path>::TestName``; JS ids are ``<file> > describe > name``. Every
    id must share one runner and parse cleanly, else no command is shown.
    """
    ft = card.get("failing_tests") if isinstance(card.get("failing_tests"), dict) else {}
    runner = str(ft.get("runner") or "")
    if runner not in ("go", "vitest", "jest", "mocha", "junit", "cargo", "cpp", "minitest", "rspec", "phpunit"):
        return None
    ids = [t for t in (cc.get("failing_tests") if cc else None) or ft.get("ids") or [] if isinstance(t, str)]
    ids = _unique(ids)
    if not ids or len(ids) > _MAX_TESTS:
        return None
    if runner == "cargo":
        from sentinel_card.cargo import validate_cargo_ids

        clean, err = validate_cargo_ids(ids)
        if err or len(clean) != len(ids):
            return None
        return {"runner": "cargo", "tests": clean, "files": [], "package": ""}
    if runner == "junit":
        from sentinel_card.jvm import validate_jvm_ids

        clean, err = validate_jvm_ids(ids)
        if err or len(clean) != len(ids):
            return None
        return {"runner": "junit", "tests": clean, "files": [], "package": ""}
    if runner == "cpp":
        from sentinel_card.cpp import validate_cpp_ids

        clean, err = validate_cpp_ids(ids)
        if err or len(clean) != len(ids):
            return None
        return {"runner": "cpp", "tests": clean, "files": [], "package": ""}
    if runner == "minitest":
        from sentinel_card.ruby_test import split_minitest_id
        from sentinel_card.ruby_test import validate_minitest_ids

        clean, err = validate_minitest_ids(ids)
        if err or len(clean) != 1:
            return None
        split = split_minitest_id(clean[0])
        if split is None:
            return None
        file, class_name, method = split
        return {"runner": "minitest", "tests": [f"{class_name}#{method}"], "files": [file], "package": ""}
    if runner == "rspec":
        from sentinel_card.ruby_test import split_rspec_id
        from sentinel_card.ruby_test import validate_rspec_ids

        clean, err = validate_rspec_ids(ids)
        if err or len(clean) != 1:
            return None
        split = split_rspec_id(clean[0])
        if split is None:
            return None
        return {"runner": "rspec", "tests": [split[1]], "files": [split[0]], "package": ""}
    if runner == "phpunit":
        from sentinel_card.phpunit import phpunit_filter
        from sentinel_card.phpunit import split_phpunit_id
        from sentinel_card.phpunit import validate_phpunit_ids

        clean, err = validate_phpunit_ids(ids)
        if err or len(clean) != 1:
            return None
        split = split_phpunit_id(clean[0])
        if split is None:
            return None
        file, class_name, method = split
        return {
            "runner": "phpunit",
            "tests": [phpunit_filter(class_name, method)],
            "files": [file],
            "package": "",
        }
    if runner == "go":
        pkgs: list[str] = []
        names: list[str] = []
        for t in ids:
            pkg, sep, name = t.rpartition("::")
            if not sep or not _safe_path(pkg) or not _safe_go(name):
                return None
            pkgs.append(pkg)
            names.append(name)
        pkgs = _unique(pkgs)
        return {"runner": "go", "tests": _unique(names), "files": [],
                "package": " ".join(pkgs) if len(pkgs) <= 3 else "./..."}
    files: list[str] = []
    names = []
    for t in ids:
        file, sep, rest = t.partition(_JS_SEP)
        if not sep or not _safe_path(file):
            return None
        name = _safe_name(" ".join(part.strip() for part in rest.split(_JS_SEP)))
        if not name:
            return None
        files.append(file)
        names.append(name)
    return {"runner": runner, "tests": _unique(names), "files": _unique(files), "package": ""}


_NOTES = {
    "go": "Run from the directory that holds go.mod.",
    "vitest": "Run from the package root (the directory that holds package.json), after installing dependencies.",
    "jest": "Run from the package root (the directory that holds package.json), after installing dependencies.",
    "mocha": "Run from the package root (the directory that holds package.json), after installing dependencies.",
    "playwright": "Run from the repository root after installing the lockfile's Playwright. This does not download a browser.",
    "junit": "Run from the directory that holds pom.xml, with a JDK and Maven on PATH. This is single-module Maven Surefire only.",
    "cargo": "Run from the directory that holds Cargo.toml, with rustc and cargo on PATH. This is one crate, not a Cargo workspace. A Cargo.lock in that directory is passed --locked.",
    "cpp": "Run from the directory that holds the root CMakeLists.txt, with cmake, ctest, and gcc/g++ on PATH. This is one test executable, not a workspace and not a second binary. A toolchain file is not selected.",
    "minitest": "Run from the directory that holds Gemfile and Gemfile.lock, with ruby and bundle on PATH. bundle install --frozen first. Rails and a missing lockfile abstain.",
    "rspec": "Run from the directory that holds Gemfile and Gemfile.lock, with ruby and bundle on PATH. bundle install --frozen first. Rails and a missing lockfile abstain.",
    "phpunit": "Run from the directory that holds composer.json and composer.lock, with php and composer on PATH. composer install --no-scripts first. A missing lockfile abstains.",
}
_PIECE = re.compile(r"^[A-Za-z0-9_./:@+=,-]+$")


def _piece_ok(piece: str) -> bool:
    if not piece or len(piece) > 500:
        return False
    for token in piece.split(" "):
        if not token or not _PIECE.fullmatch(token) or ".." in token.split("/"):
            return False
    return True


def _chain_ok(chain: str) -> bool:
    parts = chain.split(" && ")
    return bool(parts) and all(_piece_ok(part) for part in parts)


def _workspace_from_card(card: dict) -> dict | None:
    """Install + filtered build recorded while a checkout existed. Reject anything else."""
    raw = card.get("workspace_reproduce")
    if not isinstance(raw, dict):
        return None
    install, build = raw.get("install"), raw.get("build")
    test_dir = raw.get("test_dir") or ""
    if not isinstance(install, str) or not isinstance(build, str) or not isinstance(test_dir, str):
        return None
    if not _chain_ok(install) or not _chain_ok(build):
        return None
    if test_dir and not _safe_path(test_dir):
        return None
    return {"install": install, "build": build, "test_dir": test_dir}


def build_reproduce(
    card: dict, *, sha: str, log_text: str | None = None
) -> dict | None:
    """A copy-paste command, or None when we are not confident."""
    sha = valid_sha(sha)
    if not sha:
        return None
    cc = (
        card.get("confirm_culprit")
        if isinstance(card.get("confirm_culprit"), dict)
        else {}
    )
    from_bisect = None
    bisect_ids = _ids_from_list(cc.get("failing_tests") if cc else None)
    ft = card.get("failing_tests") if isinstance(card.get("failing_tests"), dict) else {}
    id_runner = str(ft.get("runner") or cc.get("runner") or "")
    if id_runner == "playwright":
        # _ids_from_list keeps pytest node ids only. Playwright ids use ›.
        raw = cc.get("failing_tests") if isinstance(cc.get("failing_tests"), list) else []
        specs = [item.strip() for item in raw if isinstance(item, str) and item.strip()]
        from_bisect = _playwright_from_ids(specs)
        if from_bisect is None:
            return None
    elif bisect_ids and len(bisect_ids) <= _MAX_TESTS:
        from_bisect = {
            "runner": "pytest",
            "tests": bisect_ids,
            "files": [],
            "package": "",
        }
    elif bisect_ids:
        return None
    from_ids = None if from_bisect else _from_card_ids(card, cc)
    if from_ids:
        chosen = from_ids
    else:
        from_log = parse_log(log_text)
        from_ann = parse_annotations(card.get("annotations"))
        chosen = _choose(from_bisect, from_log, from_ann)
    if not chosen:
        return None
    workspace = _workspace_from_card(card) if chosen["runner"] in ("vitest", "jest", "mocha") else None
    command = _command(chosen, sha, workspace)
    if workspace and not _command_safe(command):
        workspace = None
        command = _command(chosen, sha)
    if not _command_safe(command):
        return None
    if workspace:
        where = workspace["test_dir"] or "the package directory"
        note = (
            "Run from the repository root. The install uses a frozen lockfile and skips install scripts. "
            "The build runs this repository's scripts, including prebuild and postbuild hooks. "
            f"The test then runs in {where}."
        )
    else:
        note = _NOTES.get(chosen["runner"], "")
    return {
        "command": command,
        "note": note,
        "runner": chosen["runner"],
        "tests": list(chosen["tests"]),
        "sha": sha,
    }
