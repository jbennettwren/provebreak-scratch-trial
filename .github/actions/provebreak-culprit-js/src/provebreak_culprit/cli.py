"""provebreak-culprit CLI: name the commit that broke a test, or abstain. Never raises; exit 0 unless --fail-on-error."""
from __future__ import annotations
import argparse, json, os, re, sys, tempfile, time
from pathlib import Path
from provebreak_culprit._engine.bisect import confirm_culprit_safe, PytestGitRunner, sha_in_repo, is_shallow_repo, BisectResult
from provebreak_culprit._engine.runners import make_runner
from provebreak_culprit.js_support import JS_RUNNERS, detect_framework, extract_js_ids

ABSTAIN = ("ProveBreak did not name a culprit. This is an abstain, not a verdict: "
           "nothing here means any commit or person is at fault.")

NOT_SURE = "Not sure: no single commit stands out"
# Engine headlines/reasons that overclaim ("likely not caused by this commit", "not your commit") never reach the summary.
_OVERCLAIM = re.compile(r"caused by|not your commit|your commit", re.I)

def _abstain_lines(res: BisectResult) -> list[str]:
    n = res.reproduction_attempts or 0
    lines = [f"**{NOT_SURE}.**", "", ABSTAIN, "", f"Status: `{res.status}` · reruns: {res.reproductions} failed of {n} attempted"]
    reason = str(res.reason or "").strip()
    if reason and not _OVERCLAIM.search(reason):
        lines.append(f"Detail: {reason[:200]}")
    return lines

def render(res: BisectResult, good: str, bad: str) -> str:
    lines = ["## ProveBreak culprit (observe-only)", ""]
    if res.status == "proven":
        lines += [f"**{res.card_line()}**", "",
                  "Named because the failing test(s) passed on the parent and failed on this commit, reproduced on rerun. "
                  "This identifies a change, not a person."]
    elif res.status == "introduced_failing_test":
        lines.append(res.card_line())
    else:
        lines += _abstain_lines(res)
    lines += ["", f"Range checked: `{good[:12]}..{bad[:12]}` · steps {res.steps_used} · {res.elapsed_sec:.1f}s"]
    return "\n".join(lines) + "\n"

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
            if kind in JS_RUNNERS:
                runner = make_runner(kind, repo, per_run_timeout_sec=a.per_run_timeout)
            else:
                runner = PytestGitRunner(repo=repo, per_run_timeout_sec=a.per_run_timeout)
            res = confirm_culprit_safe(repo=repo, good_sha=a.good, bad_sha=a.bad, failing_tests=tests, runner=runner,
                                       time_budget_sec=a.budget_sec, step_budget=a.step_budget,
                                       confirm_reruns=a.confirm_reruns, max_commits=a.max_commits)
    except Exception as e:  # noqa: BLE001 fail-soft
        res = BisectResult(status="error", reason=type(e).__name__, elapsed_sec=time.monotonic() - t0)
    d = res.to_dict(); d["good_sha"], d["bad_sha"] = a.good, a.bad
    d["runner"] = locals().get("kind", a.runner); d["failing_tests"] = locals().get("tests", [])
    d["named_culprit"] = res.culprit_sha if res.status == "proven" else None
    md = render(res, a.good, a.bad)
    print(md)
    try:  # fail-soft: an I/O error writing outputs must not crash the step
        Path(a.out).write_text(json.dumps(d, indent=2))
        summ = os.environ.get("GITHUB_STEP_SUMMARY")
        if summ:
            with open(summ, "a") as f: f.write(md)
        out = os.environ.get("GITHUB_OUTPUT")
        if out:
            with open(out, "a") as f:
                f.write(f"status={res.status}\nculprit_sha={d['named_culprit'] or ''}\nresult_json={a.out}\n")
    except OSError as e:
        print(f"::warning title=ProveBreak culprit::could not write outputs ({type(e).__name__})")
        if a.fail_on_error:
            return 1
    if a.fail_on_error and res.status == "error":
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
