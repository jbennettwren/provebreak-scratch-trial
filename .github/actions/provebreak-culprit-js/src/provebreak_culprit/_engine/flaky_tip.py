"""The failing commit passed when the same tests were re-run.

That is an abstain. It is not a culprit, and the card must not name one.
The signal is the structured evaluation (green, zero fails) of the card's
own head SHA, not the bisect job's free-text reason.
"""

from __future__ import annotations

import re

_SHA = re.compile(r"^[0-9a-f]{40}$")
_SHORT = re.compile(r"^[0-9a-f]{7,39}$")

NOT_THIS_COMMIT_HEADLINE = (
    "Not caused by this commit: the failing test passed when re-run "
    "on the same commit (likely flaky)"
)
NEXT_STEP = (
    "Next step: quarantine this test, or retry it in CI. This result does not name a culprit."
)


def _count(value) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0 or value > 100:
        return None
    return value


def _matches(ev_sha: str, head: str) -> bool:
    ev = str(ev_sha or "").strip().lower()
    if ev == head:
        return True
    return bool(_SHORT.fullmatch(ev) and head.startswith(ev))


def rerun_evidence(cc: dict, head_sha: str) -> dict | None:
    """Pass/fail/run counts when every evaluation of ``head_sha`` is a clean pass."""
    if not isinstance(cc, dict) or cc.get("status") != "inconclusive_flaky":
        return None
    head = str(head_sha or "").strip().lower()
    if not _SHA.fullmatch(head):
        return None
    evs = cc.get("evaluations")
    if not isinstance(evs, list) or not evs:
        return None
    matched = []
    for ev in evs:
        if not isinstance(ev, dict):
            return None
        if _matches(str(ev.get("sha") or ""), head):
            matched.append(ev)
    if not matched:
        return None
    passes = fails = runs = 0
    for ev in matched:
        if ev.get("label") != "green":
            return None
        p, f, r = _count(ev.get("passes")), _count(ev.get("fails")), _count(ev.get("runs"))
        if p is None or f is None or r is None or f != 0 or p < 1 or r < 1:
            return None
        passes += p
        fails += f
        runs += r
    if passes > 100 or runs > 100:
        return None
    return {"passes": passes, "fails": fails, "runs": runs}


def tip_passed_rerun(cc: dict, head_sha: str) -> dict | None:
    """Same as ``rerun_evidence``, but None when a culprit SHA is already set.

    A named candidate is a different abstain. Callers that must not name a
    culprit strip the SHA first, then use this.
    """
    if isinstance(cc, dict) and cc.get("culprit_sha"):
        return None
    return rerun_evidence(cc, head_sha)


def head_sha_of(card: dict) -> str:
    rng = card.get("range") if isinstance(card.get("range"), dict) else {}
    head = str(rng.get("head_sha") or "").strip().lower()
    if _SHA.fullmatch(head):
        return head
    wr = card.get("workflow_run") if isinstance(card.get("workflow_run"), dict) else {}
    head = str(wr.get("head_sha") or "").strip().lower()
    return head if _SHA.fullmatch(head) else ""


def earlier_runs_line(card: dict) -> str:
    """How many earlier runs shared this fingerprint, if the card already has that count.

    This does not fetch logs. ``seen_before.same_count`` is prior matches only.
    """
    seen = card.get("seen_before")
    if not isinstance(seen, dict) or seen.get("enabled") is False or seen.get("skipped"):
        return ""
    n = seen.get("same_count")
    checked = seen.get("runs_checked")
    if isinstance(n, bool) or not isinstance(n, int) or not 0 <= n <= 10000:
        return ""
    times = "run" if n == 1 else "runs"
    if isinstance(checked, int) and not isinstance(checked, bool) and 0 <= checked <= 10000:
        return (
            f"The same failure fingerprint was seen on {n} other recent {times} "
            f"({checked} runs already fingerprinted on this card)."
        )
    return (
        f"The same failure fingerprint was seen on {n} other recent {times} "
        "(from data already on this card)."
    )
