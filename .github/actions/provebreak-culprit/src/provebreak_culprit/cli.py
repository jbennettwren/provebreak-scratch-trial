"""provebreak-culprit CLI: name the commit that broke a test, or abstain. Never raises; exit 0 unless --fail-on-error."""
from __future__ import annotations
import argparse, json, os, sys, time
from pathlib import Path
from sentinel_card.bisect import confirm_culprit_safe, PytestGitRunner, sha_in_repo, is_shallow_repo, BisectResult

ABSTAIN = ("ProveBreak did not name a culprit. This is an abstain, not a verdict: "
           "nothing here means any commit or person is at fault.")

def render(res: BisectResult, good: str, bad: str) -> str:
    lines = ["## ProveBreak culprit (prototype, observe-only)", ""]
    if res.status == "proven":
        lines.append(f"**{res.card_line()}**")
    elif res.status == "introduced_failing_test":
        lines.append(res.card_line())
    else:
        lines += [ABSTAIN, "", f"Reason: {res.card_line()}"]
    lines += ["", f"Range checked: `{good[:12]}..{bad[:12]}` · steps {res.steps_used} · {res.elapsed_sec:.1f}s"]
    return "\n".join(lines) + "\n"

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="provebreak-culprit")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--good", required=True); ap.add_argument("--bad", required=True)
    ap.add_argument("--tests", required=True, help="comma-separated pytest node ids")
    ap.add_argument("--budget-sec", type=float, default=180); ap.add_argument("--step-budget", type=int, default=16)
    ap.add_argument("--max-commits", type=int, default=200); ap.add_argument("--confirm-reruns", type=int, default=3)
    ap.add_argument("--per-run-timeout", type=float, default=60); ap.add_argument("--out", default="provebreak-culprit.json")
    ap.add_argument("--fail-on-error", action="store_true")
    a = ap.parse_args(argv)
    t0 = time.monotonic()
    try:
        repo = Path(a.repo).resolve()
        tests = [t.strip() for t in a.tests.split(",") if t.strip()]
        if is_shallow_repo(repo):
            res = BisectResult(status="inconclusive_git", reason="shallow clone; use actions/checkout fetch-depth: 0")
        elif not (sha_in_repo(repo, a.good) and sha_in_repo(repo, a.bad)):
            res = BisectResult(status="inconclusive_git", reason="good or bad sha not in clone")
        else:
            runner = PytestGitRunner(repo=repo, per_run_timeout_sec=a.per_run_timeout)
            res = confirm_culprit_safe(repo=repo, good_sha=a.good, bad_sha=a.bad, failing_tests=tests, runner=runner,
                                       time_budget_sec=a.budget_sec, step_budget=a.step_budget,
                                       confirm_reruns=a.confirm_reruns, max_commits=a.max_commits)
    except Exception as e:  # noqa: BLE001 fail-soft
        res = BisectResult(status="error", reason=type(e).__name__, elapsed_sec=time.monotonic() - t0)
    d = res.to_dict(); d["good_sha"], d["bad_sha"] = a.good, a.bad
    d["named_culprit"] = res.culprit_sha if res.status == "proven" else None
    Path(a.out).write_text(json.dumps(d, indent=2))
    md = render(res, a.good, a.bad)
    summ = os.environ.get("GITHUB_STEP_SUMMARY")
    if summ:
        with open(summ, "a") as f: f.write(md)
    print(md)
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as f:
            f.write(f"status={res.status}\nculprit_sha={d['named_culprit'] or ''}\nresult_json={a.out}\n")
    if a.fail_on_error and res.status == "error":
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
