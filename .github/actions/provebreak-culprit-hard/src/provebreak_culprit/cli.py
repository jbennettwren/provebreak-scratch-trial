"""provebreak-culprit CLI: name the commit that broke a test, or abstain. Never raises; exit 0 unless --fail-on-error."""
from __future__ import annotations
import argparse, json, os, re, subprocess, sys, tempfile, time
from pathlib import Path
from provebreak_culprit._engine.bisect import confirm_culprit_safe, PytestGitRunner, sha_in_repo, is_shallow_repo, BisectResult
from provebreak_culprit._engine.runners import make_runner
from provebreak_culprit.js_support import JS_RUNNERS, detect_framework, extract_js_ids

ABSTAIN = ("ProveBreak did not name a culprit. This is an abstain, not a verdict: "
           "nothing here means any commit or person is at fault.")

NOT_SURE = "Not sure: no single commit stands out"
ERROR_LINE = ("ProveBreak hit an internal error and could not finish (outcome `error`). No culprit named; "
              "this says nothing about any commit or person.")


def verdict(status: str) -> str:
    """Plain verdict for the `verdict` output: proven -> 'culprit named', error -> 'error', every abstain -> 'not sure'."""
    return "culprit named" if status == "proven" else "error" if status == "error" else "not sure"
# Engine headlines/reasons that overclaim ("likely not caused by this commit", "not your commit") never reach the summary.
_OVERCLAIM = re.compile(r"caused by|not your commit|your commit", re.I)


def _rerun_counts(res: BisectResult) -> tuple[int, int]:
    """failed, attempted for the abstain summary.

    Proven paths fill reproductions / reproduction_attempts. Flaky and env
    abstains leave those at 0; the tip's rerun totals live in evaluations
    (engine probes tip first). Do not sum base — Detail cites tip.
    """
    n = int(res.reproduction_attempts or 0)
    k = int(res.reproductions or 0)
    if n > 0:
        return k, n
    tip = None
    fails = runs = 0
    for ev in res.evaluations or []:
        if not isinstance(ev, dict):
            continue
        sha = str(ev.get("sha") or "")
        if tip is None:
            tip = sha
        if not tip or sha != tip:
            continue
        fails += int(ev.get("fails") or 0)
        runs += int(ev.get("runs") or 0)
    return fails, runs

def _safe_detail(reason) -> str:
    r = str(reason or "").strip()
    return r[:200] if r and not _OVERCLAIM.search(r) else "unknown"

def _abstain_lines(res: BisectResult) -> list[str]:
    k, n = _rerun_counts(res)
    lines = [f"**{NOT_SURE}.**", "", ABSTAIN, "", f"Status: `{res.status}` · reruns: {k} failed of {n} attempted"]
    reason = str(res.reason or "").strip()
    if reason and not _OVERCLAIM.search(reason):
        lines.append(f"Detail: {reason[:200]}")
    return lines

BASE_RED = ("The failing test(s) also fail on the base branch commit this pull request targets, "
            "so the break is not searched for inside the pull request's commits.")


def _merge_base(repo: Path, a: str, b: str) -> str | None:
    """Wrapper-only PR helper: merge-base of base and head, or None. Read-only git."""
    try:
        r = subprocess.run(["git", "-C", str(repo), "merge-base", a, b], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = r.stdout.strip()
    return out if r.returncode == 0 and re.fullmatch(r"[0-9a-f]{40,64}", out) else None


def _pr_fork_point(repo: Path, base: str, head: str, limit: int) -> str | None:
    """First commit on head's first-parent chain that is already in base: the PR's own fork point.
    Equals merge-base(base, head) for a plain PR. After 'Update branch' (base merged into the PR)
    merge-base sits on the base side, off the first-parent chain the engine walks, so use this instead."""
    try:
        r = subprocess.run(["git", "-C", str(repo), "rev-list", "--first-parent", f"--max-count={limit + 2}", head],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return None
        for sha in r.stdout.split():
            a = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", sha, base], capture_output=True, timeout=30)
            if a.returncode == 0:
                return sha
    except (OSError, subprocess.TimeoutExpired):
        return None
    return None


def _is_merge(repo: Path, sha: str) -> bool:
    try:
        r = subprocess.run(["git", "-C", str(repo), "rev-list", "--parents", "-n", "1", sha], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return True  # unknown: never name it
    return r.returncode != 0 or len(r.stdout.split()) > 2


MERGE_NOT_NAMED = ("break first appears at a merge commit inside the PR (e.g. 'Update branch' merging the base in); "
                   "a merge commit is never named")


def pr_base_check(runner, base_sha: str, tests: list[str], reruns: int, deadline: float) -> BisectResult | None:
    """Run the failing tests on the PR's base commit first. Red on every run -> base_already_red;
    mixed -> inconclusive_flaky; green or not runnable (e.g. the PR adds the test) -> None (continue)."""
    er = runner.evaluate(base_sha, tests, reruns=reruns, deadline=deadline)
    ev = [{"sha": base_sha, "outcome": er.label, "fails": er.fails, "runs": er.runs}]
    if er.label == "red":
        return BisectResult(status="base_already_red", reason="failing tests also fail on the PR base commit",
                            evaluations=ev, reproductions=er.fails, reproduction_attempts=er.runs)
    if er.label == "flaky":
        return BisectResult(status="inconclusive_flaky", reason="results flipped between reruns on the PR base commit",
                            evaluations=ev)
    return None


def render(res: BisectResult, good: str, bad: str, base: str | None = None) -> str:
    lines = ["## ProveBreak culprit (observe-only)", ""]
    if res.status == "base_already_red":
        lines += [f"**{NOT_SURE}.**", "", BASE_RED, "", ABSTAIN, "",
                  f"Status: `base_already_red` · reruns on base: {res.reproductions} failed of {res.reproduction_attempts} attempted"]
        lines += ["", f"Base checked: `{(base or good)[:12]}` · PR head `{bad[:12]}` · {res.elapsed_sec:.1f}s"]
        return "\n".join(lines) + "\n"
    if res.status == "proven":
        lines += [f"**{res.card_line()}**", "",
                  "Named because the failing test(s) passed on the parent and failed on this commit, reproduced on rerun. "
                  "This identifies a change, not a person."]
    elif res.status == "introduced_failing_test":
        lines += ["**Not sure (no culprit named): the failing test is new in this commit, so there is no earlier passing run to compare.**", "", res.card_line()]
    elif res.status == "error":
        lines += [f"**{ERROR_LINE}**", "", f"Status: `error` · detail: {_safe_detail(res.reason)}",
                  "The Action's step stays green unless `fail-on-error: true`."]
    else:
        lines += _abstain_lines(res)
    if base is not None:
        lines += ["", f"Pull request mode: base `{base[:12]}` was not red on the base check (green, or the test does not exist there); searched the PR's own commits (fork point..head)."]
    lines += ["", f"Range checked: `{good[:12]}..{bad[:12]}` · steps {res.steps_used} · {res.elapsed_sec:.1f}s"]
    return "\n".join(lines) + "\n"

def _provenance_str() -> str:
    from provebreak_culprit import provenance
    return provenance()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="provebreak-culprit")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--good", required=True); ap.add_argument("--bad", required=True)
    ap.add_argument("--tests", default="", help="comma-separated ids (pytest node ids or JS 'file > describe > test')")
    ap.add_argument("--runner", default="pytest", choices=["auto", "pytest", "vitest", "jest"],
                    help="pytest (default, v1.0 behaviour), vitest, jest, or auto (detect from package.json/config)")
    ap.add_argument("--report", default="", help="vitest/jest JSON or JUnit XML report; failing ids are read from it")
    ap.add_argument("--budget-sec", type=float, default=180); ap.add_argument("--step-budget", type=int, default=16)
    ap.add_argument("--max-commits", type=int, default=200); ap.add_argument("--confirm-reruns", type=int, default=3)
    ap.add_argument("--per-run-timeout", type=float, default=60); ap.add_argument("--out", default=os.path.join(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir(), "provebreak-culprit.json"))
    ap.add_argument("--fail-on-error", action="store_true")
    ap.add_argument("--pr", action="store_true",
                    help="pull_request mode: --good is the PR base sha, --bad the PR head sha. Checks base first "
                         "(red -> base_already_red), then searches merge-base(base, head)..head")
    ap.add_argument("--version", action="version", version=_provenance_str())
    a = ap.parse_args(argv)
    t0 = time.monotonic()
    try:
        repo = Path(a.repo).resolve()
        tests = [t.strip() for t in a.tests.split(",") if t.strip()]
        kind, kerr = a.runner, None
        if kind == "auto":
            kind, kerr = detect_framework(repo)
        if kind in JS_RUNNERS and a.report and not kerr:
            ids, rerr = extract_js_ids(a.report, repo, kind)
            tests, kerr = (ids, None) if not rerr else ([], rerr)
        if kerr:
            res = BisectResult(status="not_proven", reason=kerr)
        elif not tests:
            res = BisectResult(status="not_proven", reason="no_failing_tests_provided")
        elif is_shallow_repo(repo):
            res = BisectResult(status="inconclusive_git", reason="shallow clone; use actions/checkout fetch-depth: 0")
        elif not (sha_in_repo(repo, a.good) and sha_in_repo(repo, a.bad)):
            res = BisectResult(status="inconclusive_git", reason="good or bad sha not in clone")
        else:
            def mk():
                if kind in JS_RUNNERS:
                    return make_runner(kind, repo, per_run_timeout_sec=a.per_run_timeout)
                return PytestGitRunner(repo=repo, per_run_timeout_sec=a.per_run_timeout)
            res, good = None, a.good
            if a.pr:
                mb = _merge_base(repo, a.good, a.bad) and _pr_fork_point(repo, a.good, a.bad, a.max_commits)
                if mb is None:
                    res = BisectResult(status="inconclusive_git", reason="no merge-base between PR base and head in clone")
                else:
                    pre = mk()
                    try:
                        res = pr_base_check(pre, a.good, tests, max(3, a.confirm_reruns), time.monotonic() + a.budget_sec)
                    finally:
                        getattr(pre, "cleanup", lambda: None)()
                    good = mb
                    base_green = res is None
            if res is None:
                runner = mk()
                left = max(1.0, a.budget_sec - (time.monotonic() - t0))
                res = confirm_culprit_safe(repo=repo, good_sha=good, bad_sha=a.bad, failing_tests=tests, runner=runner,
                                       time_budget_sec=left, step_budget=a.step_budget,
                                       confirm_reruns=a.confirm_reruns, max_commits=a.max_commits)
                if a.pr and res.status in ("proven", "introduced_failing_test") and res.culprit_sha and _is_merge(repo, res.culprit_sha):
                    res = BisectResult(status="not_proven", reason=MERGE_NOT_NAMED, evaluations=res.evaluations,
                                       steps_used=res.steps_used, elapsed_sec=res.elapsed_sec,
                                       reproductions=res.reproductions, reproduction_attempts=res.reproduction_attempts)
    except Exception as e:  # noqa: BLE001 fail-soft
        res = BisectResult(status="error", reason=f"internal {type(e).__name__} in the culprit search", elapsed_sec=time.monotonic() - t0)
    if not res.elapsed_sec:
        res.elapsed_sec = time.monotonic() - t0
    good = locals().get("good") or a.good
    d = res.to_dict(); d["good_sha"], d["bad_sha"] = good, a.bad
    if a.pr:
        d["pr_mode"], d["pr_base_sha"] = True, a.good
    d["runner"] = locals().get("kind", a.runner); d["failing_tests"] = locals().get("tests", [])
    d["named_culprit"] = res.culprit_sha if res.status == "proven" else None
    d["verdict"] = verdict(res.status)
    d["provenance"] = _provenance_str()
    md = render(res, good, a.bad, base=a.good if a.pr and (res.status == "base_already_red" or locals().get("base_green")) else None)
    print(md)
    try:  # fail-soft: an I/O error writing outputs must not crash the step
        Path(a.out).write_text(json.dumps(d, indent=2))
        summ = os.environ.get("GITHUB_STEP_SUMMARY")
        if summ:
            with open(summ, "a") as f: f.write(md)
        out = os.environ.get("GITHUB_OUTPUT")
        if out:
            with open(out, "a") as f:
                f.write(f"status={res.status}\nculprit_sha={d['named_culprit'] or ''}\nverdict={verdict(res.status)}\nresult_json={a.out}\n")
    except OSError as e:
        print(f"::warning title=ProveBreak culprit::could not write outputs ({type(e).__name__})")
        if a.fail_on_error:
            return 1
    if a.fail_on_error and res.status == "error":
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
