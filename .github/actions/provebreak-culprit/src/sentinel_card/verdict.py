"""Typed abstain cards. Status codes are unchanged.

A result names a culprit only when the status is ``proven``. These four
kinds rephrase every other finished bisect: what was found, the evidence
that is already on the card, and one next step. Free text from the bisect
job is not copied onto the card. Links open existing GitHub pages; nothing
is created or re-run from here.
"""

from __future__ import annotations

import re
from urllib.parse import quote
from urllib.parse import urlencode

from sentinel_card.flaky_tip import earlier_runs_line
from sentinel_card.flaky_tip import head_sha_of
from sentinel_card.flaky_tip import rerun_evidence
from sentinel_card.urls import commit_url
from sentinel_card.urls import job_url
from sentinel_card.urls import run_url
from sentinel_card.urls import safe_github_url
from sentinel_card.urls import valid_branch
from sentinel_card.urls import valid_sha

_SHA = re.compile(r"^[0-9a-f]{40}$")
_KIND = re.compile(r"[a-z_]{0,40}")
_LABELS = frozenset({"green", "red", "flaky", "error"})
_PROVED = frozenset({"proven", "introduced_failing_test"})
_CODES = (
    "last_green_also_fails",
    "empty_commit_range",
    "shallow_clone",
    "commit_range_exceeds_max",
    "missing_good_or_bad_sha",
    "time_budget_before_start",
    "insufficient_wall_clock_budget",
    "stopped with range",
    "budget before",
    "budget during",
    "budget confirming",
    "hit wall-clock",
    "toolchain_unusable",
    "test_python_unusable",
    "bad_input",
    "bisect_result_rejected",
    "first failing commit is in",
    "could not build",
    "missing_build_output",
    "setup_error",
    "ci_node_id_did_not_resolve",
    "failure_does_not_reproduce_at_head",
    "not evaluable",
    "confirmation disagreed",
    "non-monotonic",
    "candidate ",
    "eval error",
)

# Anchors in the installed INSTALL.md (partner/INSTALL.md before install).
ANCHOR_BUDGET = "bisect-time-budget"
ANCHOR_TOOLS = "extra-tools"
ANCHOR_SERVICES = "database-and-services"
ANCHOR_HISTORY = "full-git-history"
ANCHOR_BUILD = "build-command"


def reason_code(reason: str | None) -> str:
    """A fixed prefix our bisect writes, or ''. The rest of the string is dropped."""
    text = str(reason or "").strip().lower()
    if text.startswith("shallow_clone;"):
        return "shallow_clone"
    for code in _CODES:
        if text.startswith(code):
            return code
    return ""


def _count(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    if value < 0 or value > 100:
        return 0
    return value


def _evs(cc: dict) -> list[dict]:
    out = []
    for ev in cc.get("evaluations") or []:
        if not isinstance(ev, dict):
            continue
        label = str(ev.get("label") or "")
        if label not in _LABELS:
            continue
        kind = str(ev.get("kind") or "")
        if not _KIND.fullmatch(kind):
            kind = ""
        out.append(
            {
                "sha": str(ev.get("sha") or "").strip().lower(),
                "label": label,
                "kind": kind,
                "passes": _count(ev.get("passes")),
                "fails": _count(ev.get("fails")),
                "runs": _count(ev.get("runs")),
            }
        )
    return out


def _by_sha(evs: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for ev in evs:
        if _SHA.fullmatch(ev["sha"]):
            grouped.setdefault(ev["sha"], []).append(ev)
    return grouped


NOT_YOUR_COMMIT = "This failure is likely not caused by this commit"
# The phrase is withheld until the flipping commit has this many runs.
# That matches the default confirmation count. Fewer runs stay an abstain
# and do not use this sentence.
MIN_NOT_YOUR_COMMIT_RUNS = 3
OUTSIDE_CHANGED = "Something outside the repo changed"
LAST_GREEN_FAILS = "The last green commit fails in this job too"


def _fmt_counts(passes: int, fails: int, runs: int) -> str:
    def word(n: int, one: str, many: str) -> str:
        return f"{n} {one if n == 1 else many}"

    if runs < 1:
        runs = passes + fails
    return (
        f"{word(passes, 'pass', 'passes')} / {word(fails, 'fail', 'fails')} "
        f"({word(runs, 'run', 'runs')})"
    )


def _buckets(evs: list[dict]) -> dict[str, tuple[int, int, int, bool]]:
    """Per SHA: passes, fails, runs, and whether those re-runs disagreed."""
    grouped: dict[str, list[dict]] = {}
    for ev in evs:
        grouped.setdefault(ev["sha"] or "?", []).append(ev)
    out: dict[str, tuple[int, int, int, bool]] = {}
    for sha, group in grouped.items():
        passes = sum(ev["passes"] for ev in group)
        fails = sum(ev["fails"] for ev in group)
        runs = sum(ev["runs"] for ev in group)
        labels = {ev["label"] for ev in group}
        if runs < 1:
            runs = passes + fails
        # A "flaky" label with every run on one side is a stable result.
        # Only a real pass and a real fail, on that commit, is intermittent.
        nondet = (passes > 0 and fails > 0) or ({"green", "red"} <= labels)
        out[sha] = (passes, fails, runs, nondet)
    return out


def _stable_side(item: tuple[int, int, int, bool], side: str) -> bool:
    """True when every run on this commit went the same way."""
    passes, fails, runs, nondet = item
    if nondet or runs < 1:
        return False
    if side == "red":
        return passes == 0 and fails > 0
    return fails == 0 and passes > 0


def _parent_and_head(cc: dict, card: dict | None, evs: list[dict], buckets: dict) -> tuple[str, str]:
    parent = str(cc.get("parent_sha") or "").strip().lower()
    rng = card.get("range") if isinstance(card, dict) and isinstance(card.get("range"), dict) else {}
    base = str(rng.get("base_sha") or "").strip().lower()
    if parent not in buckets and base in buckets:
        parent = base
    head = head_sha_of(card) if isinstance(card, dict) else ""
    if not head:
        for ev in evs:
            if ev["sha"] and ev["sha"] != parent:
                head = ev["sha"]
                break
        if not head:
            for ev in evs:
                if ev["sha"]:
                    head = ev["sha"]
                    break
    return parent, head


def parent_or_head_disagrees(cc: dict | None, card: dict | None) -> bool:
    """The parent or the commit under test both passed and failed.

    A ``flaky`` label whose runs all went one way does not count. Another SHA
    in the search does not count. A stable green parent and a stable red head
    is a real culprit, not a disagreement.
    """
    if not isinstance(cc, dict):
        return False
    evs = _evs(cc)
    if deterministic_regression(cc, card, evs):
        return False
    buckets = _buckets(evs)
    parent, head = _parent_and_head(cc, card, evs, buckets)
    # Without the card, the first evaluated SHA is not the commit under test
    # when the search also probed a neighbor. A stored culprit is that commit.
    if not isinstance(card, dict):
        culprit = str(cc.get("culprit_sha") or "").strip().lower()
        if _SHA.fullmatch(culprit):
            head = culprit
    seen: list[str] = []
    if parent:
        seen.append(parent)
    if head and head not in seen:
        seen.append(head)
    for sha in seen:
        item = buckets.get(sha)
        if not item:
            continue
        _passes, _fails, runs, nondet = item
        if nondet and runs >= 1:
            return True
    return False


def deterministic_regression(cc: dict, card: dict | None, evs: list[dict]) -> bool:
    """The PR commit failed every run and its parent passed every run.

    That shape is a real culprit. It is never the flaky-test verdict, even
    when a label says ``flaky`` or the status is ``inconclusive_flaky``.
    """
    buckets = _buckets(evs)
    parent, head = _parent_and_head(cc, card, evs, buckets)
    if not head or not parent or head == parent:
        return False
    if head not in buckets or parent not in buckets:
        return False
    return _stable_side(buckets[head], "red") and _stable_side(buckets[parent], "green")


def not_your_commit_line(cc: dict, card: dict | None, evs: list[dict]) -> str:
    """Re-run counts when one commit flipped across enough runs.

    Empty when every evaluated commit was stable, and empty when the flip was
    seen on fewer than ``MIN_NOT_YOUR_COMMIT_RUNS`` runs. A stable green parent
    and a stable red commit is a real culprit, not this line.
    """
    buckets = _buckets(evs)
    parent, head = _parent_and_head(cc, card, evs, buckets)
    if (
        head in buckets
        and parent in buckets
        and head != parent
        and _stable_side(buckets[head], "red")
        and _stable_side(buckets[parent], "green")
    ):
        return ""
    if not any(item[3] and item[2] >= MIN_NOT_YOUR_COMMIT_RUNS for item in buckets.values()):
        return ""
    parts: list[str] = []
    if parent in buckets:
        passes, fails, runs, _nondet = buckets[parent]
        parts.append(f"parent {_fmt_counts(passes, fails, runs)}")
    if head and head in buckets and head != parent:
        passes, fails, runs, _nondet = buckets[head]
        parts.append(f"the commit under test {_fmt_counts(passes, fails, runs)}")
    if not parts:
        passes = fails = runs = 0
        for item in buckets.values():
            if not item[3]:
                continue
            passes += item[0]
            fails += item[1]
            runs += item[2]
        if runs < 1 and passes + fails < 1:
            return ""
        parts.append(_fmt_counts(passes, fails, runs))
    return "Re-runs: " + "; ".join(parts) + "."


def _flipped(evs: list[dict]) -> tuple[int, int] | None:
    """Failing observations / total runs on one SHA that both passed and failed."""
    best: tuple[int, int] | None = None
    for group in _by_sha(evs).values():
        passes = sum(ev["passes"] for ev in group)
        fails = sum(ev["fails"] for ev in group)
        runs = sum(ev["runs"] for ev in group)
        labels = {ev["label"] for ev in group}
        mixed = (passes > 0 and fails > 0) or ({"green", "red"} <= labels)
        if not mixed:
            continue
        if runs < 1:
            runs = passes + fails
        if fails < 1:
            fails = 1
        if runs < fails:
            runs = fails
        pair = (min(fails, 10000), min(runs, 10000))
        if best is None or pair[1] > best[1]:
            best = pair
    return best


def _ordered_range(card: dict | None) -> list[str]:
    """``range_shas`` is ``git rev-list`` order: newest first. Return oldest first."""
    if not isinstance(card, dict):
        return []
    raw = []
    for sha in card.get("range_shas") or []:
        sha = str(sha).lower()
        if _SHA.fullmatch(sha) and sha not in raw:
            raw.append(sha)
    raw.reverse()
    return raw


def _label(grouped: dict[str, list[dict]], sha: str) -> str:
    group = grouped.get(sha)
    return group[-1]["label"] if group else ""


def _kind(grouped: dict[str, list[dict]], sha: str) -> str:
    group = grouped.get(sha)
    return group[-1]["kind"] if group else ""


def candidate_shas(cc: dict, card: dict | None) -> list[str]:
    """Commits in the unresolved window. Empty unless at least two could not be separated."""
    evs = _evs(cc)
    grouped = _by_sha(evs)
    ordered = _ordered_range(card)
    if not ordered:
        blocked = [
            sha
            for sha, group in grouped.items()
            if any(ev["kind"] == "build_error" for ev in group)
        ]
        return blocked if len(blocked) >= 2 else []

    rng = card.get("range") if isinstance(card, dict) and isinstance(card.get("range"), dict) else {}
    base = str(rng.get("base_sha") or "").lower()
    last_green = -1 if _SHA.fullmatch(base) and _label(grouped, base) == "green" else None
    for index, sha in enumerate(ordered):
        if _label(grouped, sha) == "green":
            last_green = index
    if last_green is None:
        return []
    end = len(ordered)
    for index in range(last_green + 1, len(ordered)):
        if _label(grouped, ordered[index]) == "red":
            end = index + 1
            break
    window = [sha for sha in ordered[last_green + 1 : end] if _label(grouped, sha) != "green"]
    blocked = [
        sha
        for sha in window
        if _label(grouped, sha) in ("", "error") or _kind(grouped, sha) == "build_error"
    ]
    if len(window) >= 2 and blocked:
        return window
    return []


def _tests(cc: dict, card: dict | None) -> list[str]:
    tests = [t for t in (cc.get("failing_tests") or []) if isinstance(t, str) and t.strip()]
    if tests or not isinstance(card, dict):
        return tests[:5]
    ft = card.get("failing_tests") if isinstance(card.get("failing_tests"), dict) else {}
    return [t for t in (ft.get("ids") or []) if isinstance(t, str) and t.strip()][:5]


def _repo(card: dict | None) -> tuple[str, str, str]:
    repo = card.get("repo") if isinstance(card, dict) and isinstance(card.get("repo"), dict) else {}
    server = str(repo.get("server_url") or "https://github.com").rstrip("/")
    return server, str(repo.get("owner") or ""), str(repo.get("name") or "")


def _last_green_counts(cc: dict, card: dict | None, evs: list[dict]) -> tuple[int, int, int]:
    """Pass, fail, and run totals on the last green SHA, when this job evaluated it."""
    buckets = _buckets(evs)
    parent = str(cc.get("parent_sha") or "").strip().lower()
    rng = card.get("range") if isinstance(card, dict) and isinstance(card.get("range"), dict) else {}
    base = str(rng.get("base_sha") or "").strip().lower()
    for sha in (parent, base):
        if sha in buckets:
            item = buckets[sha]
            return item[0], item[1], item[2]
    passes = fails = runs = 0
    for item in buckets.values():
        if item[1] > 0:
            passes += item[0]
            fails += item[1]
            runs += item[2]
    return passes, fails, runs


def _outside(cc: dict, card: dict | None, evs: list[dict]) -> bool:
    status = str(cc.get("status") or "")
    code = reason_code(cc.get("reason"))
    if status in ("inconclusive_env", "outside_cause") or code in (
        "last_green_also_fails",
        "empty_commit_range",
    ):
        return True
    rng = card.get("range") if isinstance(card, dict) and isinstance(card.get("range"), dict) else {}
    base = str(rng.get("base_sha") or "").lower()
    if not _SHA.fullmatch(base):
        return False
    return any(ev["sha"] == base and ev["label"] == "red" for ev in evs)


def _unrepro(status: str, code: str, evs: list[dict], reason: str = "") -> tuple[str, str, str]:
    """Sentence, next step, docs anchor."""
    kinds = {ev["kind"] for ev in evs}
    timeout = (
        status == "budget_exhausted"
        or "timeout" in kinds
        or code
        in {
            "time_budget_before_start",
            "insufficient_wall_clock_budget",
            "stopped with range",
            "budget before",
            "budget during",
            "budget confirming",
            "hit wall-clock",
            "candidate ",
        }
    )
    if timeout:
        return (
            "The bisect hit its time budget before the test could be isolated.",
            "Raise timeout-minutes on the bisect job, and bisect_budget_sec if the suite is slow.",
            ANCHOR_BUDGET,
        )
    if status == "inconclusive_git" or code == "shallow_clone":
        return (
            "The commit history was not in this clone, so the test could not be isolated.",
            "Check the card job out with fetch-depth: 0 so the bisect can see the range.",
            ANCHOR_HISTORY,
        )
    if code in ("toolchain_unusable", "test_python_unusable") or "tool_missing" in kinds:
        return (
            "A tool or interpreter the tests need did not start.",
            "Add an extra-tools step (for example helm or terraform), or set the toolchain the tests expect.",
            ANCHOR_TOOLS,
        )
    if "missing_build_output:" in reason or code == "missing_build_output":
        return (
            "A package dist/ directory is missing, so the test could not start.",
            "Set build_command to the package build CI runs before these tests.",
            ANCHOR_BUILD,
        )
    if status == "inconclusive_build" or "build_error" in kinds or code in (
        "could not build",
        "first failing commit is in",
    ):
        from sentinel_card.bisect import compiler_location

        loc = compiler_location(reason)
        sentence = "The test could not be isolated because a commit did not build."
        if loc:
            sentence = f"{sentence} The compiler stopped at {loc}."
        return (
            sentence,
            "Set build_command to the command CI runs before the tests.",
            ANCHOR_BUILD,
        )
    if code == "commit_range_exceeds_max":
        return (
            "The commit range is larger than the safety cap, so the test could not be isolated.",
            "Bisect a shorter stretch, or raise the commit cap only if you accept a longer job.",
            ANCHOR_BUDGET,
        )
    if status == "skipped":
        return (
            "The bisect did not run.",
            "Bisect runs on a push to the default branch. Pull-request runs stay on the card only.",
            ANCHOR_BUDGET,
        )
    if code == "failure_does_not_reproduce_at_head":
        return (
            "The failing test passes at HEAD, so this job did not reproduce the CI failure.",
            "Re-run the failed job, or add the service and env this test needs, before bisecting.",
            ANCHOR_SERVICES,
        )
    if code == "missing_good_or_bad_sha":
        return (
            "There was no last-green commit to compare, so the test could not be isolated.",
            "Wait for a green run on the default branch, then re-run the failed jobs.",
            ANCHOR_HISTORY,
        )
    return (
        "The failure could not be reproduced in this job.",
        "Check the bisect job log, then raise the timeout or add the missing tool or service.",
        ANCHOR_BUDGET,
    )


def _annotate_detail(detail: str, cc: dict, card: dict | None) -> str:
    """Append a safe setup quote and, when every failed CI job is another OS, that fact.

    The quote is a regex extract. The Coder sentence is the fixed string the bisect writes.
    """
    from sentinel_card.bisect import other_os_sentence, setup_error_quote

    raw = str(cc.get("reason") or "")
    quote = setup_error_quote(raw)
    if quote and quote not in detail:
        detail = f"{detail} Setup error: {quote}."
    coder = (
        "Coder tests migrate a private database only when CODER_PG_CONNECTION_URL is unset;"
        " this job set it."
    )
    if "CODER_PG_CONNECTION_URL is unset" in raw and coder not in detail:
        detail = f"{detail} {coder}"
    line = other_os_sentence(card)
    if line and line not in detail:
        detail = f"{detail} {line}"
    return detail


def classify(cc: dict | None, card: dict | None = None) -> dict | None:
    """One verdict, or None when this result is a proof (or empty)."""
    if not isinstance(cc, dict):
        return None
    status = str(cc.get("status") or "")
    # An empty status is not a verdict. A stored "proven" status does not
    # outrank re-runs that passed and failed on the parent or the PR commit.
    disagrees = parent_or_head_disagrees(cc, card)
    if not status or (status in _PROVED and not disagrees):
        return None
    raw_reason = str(cc.get("reason") or "")
    if raw_reason.startswith("machine_preflight_"):
        from sentinel_card.machine_preflight import CUSTOMER_LINE

        return {
            "kind": "unreproducible",
            "headline": CUSTOMER_LINE,
            "tests": _tests(cc, card),
            "passes": 0,
            "fails": 0,
            "runs": 0,
            "flip": None,
            "detail": raw_reason,
            "next": (
                "What to do next: remove the machine or user build setting this job "
                "does not share with the command on your machine, then re-run."
            ),
            "candidates": [],
            "fix_anchor": ANCHOR_TOOLS,
            "earlier": "",
        }
    evs = _evs(cc)
    head = head_sha_of(card) if isinstance(card, dict) else ""
    if not head:
        for ev in evs:
            if _SHA.fullmatch(ev["sha"]):
                head = ev["sha"]
                break
    # A deterministic red PR commit with a green parent is not a flake.
    # Skip both the plain sentence and the generic "not caused by any commit" line.
    regression = deterministic_regression(cc, card, evs)
    counts = "" if regression else not_your_commit_line(cc, card, evs)
    if counts:
        passes = fails = runs = 0
        for item in _buckets(evs).values():
            if not item[3]:
                continue
            passes += item[0]
            fails += item[1]
            runs += item[2]
        return {
            "kind": "flaky",
            "headline": f"{NOT_YOUR_COMMIT}. {counts}",
            "tests": _tests(cc, card),
            "passes": passes,
            "fails": fails,
            "runs": runs,
            "flip": None,
            "detail": "No commit is named.",
            "next": (
                "What to do next: quarantine this test, or retry it in CI. "
                "This result does not name a culprit."
            ),
            "candidates": [],
            "fix_anchor": "",
            "earlier": earlier_runs_line(card) if isinstance(card, dict) else "",
            "not_your_commit": True,
        }
    tip = rerun_evidence(cc, head) if head else None
    flip = None
    if tip:
        flip = (1 + tip["fails"], 1 + tip["runs"])
    else:
        flip = _flipped(evs)
    flaky = (not regression) and (
        status == "inconclusive_flaky" or tip is not None or flip is not None or disagrees
    )
    if flaky:
        passes = fails = runs = 0
        if tip:
            passes, fails, runs = tip["passes"], tip["fails"], tip["runs"]
        elif flip:
            fails, runs = flip
            passes = max(0, runs - fails)
        if runs > 0 or passes + fails > 0:
            counts = _fmt_counts(passes, fails, runs)
        else:
            counts = "pass and fail counts not counted on this run"
        return {
            "kind": "flaky",
            "headline": (
                "Not caused by any commit. This test passes and fails on the same code "
                f"({counts}). Safe to re-run."
            ),
            "tests": _tests(cc, card),
            "passes": passes,
            "fails": fails,
            "runs": runs,
            "flip": flip,
            "detail": "The same code produced both results. No commit is named.",
            "next": (
                "What to do next: quarantine this test, or retry it in CI. "
                "This result does not name a culprit."
            ),
            "candidates": [],
            "fix_anchor": "",
            "earlier": earlier_runs_line(card) if isinstance(card, dict) else "",
        }
    if _outside(cc, card, evs):
        code = reason_code(cc.get("reason"))
        passes = fails = runs = 0
        if status == "outside_cause" or code == "empty_commit_range":
            detail = "There is no commit between the last green run and this one."
            headline = (
                f"{OUTSIDE_CHANGED}. No commit changed between the last green run and this one."
            )
        elif any(ev["label"] == "red" and ev["kind"] in ("checkout", "os") for ev in evs):
            detail = "An evaluation failed while checking out or starting the runner, before the test assertion."
            headline = (
                "Not in the tested code: this failure is in infrastructure, the runner, "
                "the network, a dependency, or setup."
            )
        else:
            raw_reason = str(cc.get("reason") or "")
            if raw_reason.lower().startswith("setup_error"):
                passes = fails = runs = 0
                detail = "The tests did not start in this job."
                headline = (
                    "Not in the tested code: this failure is in infrastructure, the runner, "
                    "the network, a dependency, or setup."
                )
            else:
                passes, fails, runs = _last_green_counts(cc, card, evs)
                if runs > 0:
                    headline = f"{LAST_GREEN_FAILS}: {_fmt_counts(passes, fails, runs)}."
                else:
                    passes = fails = runs = 0
                    headline = f"{LAST_GREEN_FAILS}."
                detail = (
                    "It fails at the last green commit too, in this job. "
                    "The commits under test are not the cause."
                )
                from sentinel_card.upstream import headline_for

                up_line = headline_for(cc.get("upstream") if isinstance(cc.get("upstream"), dict) else None)
                if up_line:
                    headline = up_line
        detail = _annotate_detail(detail, cc, card)
        return {
            "kind": "outside",
            "headline": headline,
            "tests": _tests(cc, card),
            "passes": passes,
            "fails": fails,
            "runs": runs,
            "flip": None,
            "detail": detail,
            "next": (
                "What to do next: compare this job's setup with the last green run. "
                "Pass the variable the tests read in bisect_env, and publish services on 127.0.0.1."
            ),
            "candidates": [],
            "fix_anchor": ANCHOR_SERVICES,
            "earlier": "",
        }
    candidates = candidate_shas(cc, card)
    if len(candidates) >= 2 and status in (
        "inconclusive_build",
        "budget_exhausted",
        "not_proven",
        "error",
    ):
        kinds = {_kind(_by_sha(evs), sha) for sha in candidates}
        if "build_error" in kinds or any(
            _label(_by_sha(evs), sha) == "error" and _kind(_by_sha(evs), sha) == "build_error"
            for sha in candidates
        ):
            detail = "Skipped because they don't build."
        elif status == "budget_exhausted" or reason_code(cc.get("reason")) in {
            "stopped with range",
            "insufficient_wall_clock_budget",
        }:
            detail = "The search stopped before each commit was tested."
        else:
            detail = "They could not be tested separately on this runner."
        n = len(candidates)
        return {
            "kind": "narrowed",
            "headline": (
                f"It's one of these {n} commits, but they couldn't be tested separately."
            ),
            "tests": _tests(cc, card),
            "passes": 0,
            "fails": 0,
            "runs": 0,
            "flip": None,
            "detail": detail + " This list is not a culprit.",
            "next": "What to do next: open the compare link and inspect those commits. Do not revert one of them from this card.",
            "candidates": candidates,
            "fix_anchor": ANCHOR_BUILD,
            "earlier": "",
        }
    sentence, step, anchor = _unrepro(status, reason_code(cc.get("reason")), evs, str(cc.get("reason") or ""))
    return {
        "kind": "unreproducible",
        "headline": f"Couldn't reproduce: {sentence}",
        "tests": _tests(cc, card),
        "passes": 0,
        "fails": 0,
        "runs": 0,
        "flip": None,
        "detail": _annotate_detail(sentence, cc, card),
        "next": f"What to do next: {step}",
        "candidates": [],
        "fix_anchor": anchor,
        "earlier": "",
    }


def action_links(card: dict | None, verdict: dict) -> list[tuple[str, str]]:
    """(label, url) pairs. Every URL is an existing GitHub page. None of them POST."""
    if not isinstance(card, dict) or not isinstance(verdict, dict):
        return []
    server, owner, name = _repo(card)
    if not owner or not name or "/" in owner or "/" in name:
        return []
    kind = verdict.get("kind")
    links: list[tuple[str, str]] = []
    wr = card.get("workflow_run") if isinstance(card.get("workflow_run"), dict) else {}
    run_id = wr.get("id")
    if kind == "flaky":
        if isinstance(run_id, int) and not isinstance(run_id, bool) and run_id > 0:
            url = run_url(server, owner, name, run_id)
            if url:
                links.append(("Re-run failed jobs", url))
        test = ""
        tests = verdict.get("tests") or []
        if tests and isinstance(tests[0], str):
            test = tests[0][:180]
        title = f"Quarantine flaky test {test}".strip()[:120]
        body = (
            "This test passed and failed on the same code. "
            "Quarantine it or retry it in CI. ProveBreak did not name a culprit."
        )
        href = f"{server}/{owner}/{name}/issues/new?{urlencode({'title': title, 'body': body})}"
        if safe_github_url(href, server=server):
            links.append(("Open a quarantine issue", href))
        return links
    if kind == "narrowed":
        shas = [s for s in (verdict.get("candidates") or []) if _SHA.fullmatch(str(s))]
        if len(shas) >= 2:
            href = f"{server}/{owner}/{name}/compare/{shas[0]}...{shas[-1]}"
            if safe_github_url(href, server=server):
                links.append(("Compare these commits", href))
        for sha in shas[:9]:
            href = commit_url(server, owner, name, sha)
            if href:
                links.append((sha[:7], href))
        return links
    if kind == "outside":
        jobs = [j for j in (card.get("failed_jobs") or []) if isinstance(j, dict)]
        if jobs:
            href = safe_github_url(str(jobs[0].get("html_url") or ""), server=server)
            if not href and isinstance(run_id, int) and isinstance(jobs[0].get("id"), int):
                href = job_url(server, owner, name, run_id, jobs[0]["id"])
            if href:
                links.append(("Failing step log", href))
        return links
    if kind == "unreproducible":
        anchor = str(verdict.get("fix_anchor") or "")
        if not re.fullmatch(r"[a-z0-9-]{1,40}", anchor):
            return links
        repo = card.get("repo") if isinstance(card.get("repo"), dict) else {}
        ref = valid_branch(str(repo.get("default_branch") or ""))
        if not ref or "/" in ref:
            ref = valid_sha(head_sha_of(card))
        if not ref:
            return links
        href = (
            f"{server}/{owner}/{name}/blob/{quote(ref, safe='')}"
            f"/.github/actions/sentinel/INSTALL.md#{anchor}"
        )
        if safe_github_url(href, server=server):
            links.append(("Docs for this fix", href))
    return links


def gh_rerun_command(card: dict | None) -> str:
    if not isinstance(card, dict):
        return ""
    wr = card.get("workflow_run") if isinstance(card.get("workflow_run"), dict) else {}
    run_id = wr.get("id")
    if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
        return ""
    return f"gh run rerun {run_id} --failed"
