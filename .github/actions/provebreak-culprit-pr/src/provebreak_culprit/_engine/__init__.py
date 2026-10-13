"""ProveBreak red-build triage card — factual CI triage plus opt-in evidence.

IP boundary: this package must NOT contain owner-prediction scorers,
weights, or blend signals. A future server-side "likely fixer" add-on
may attach via the marked extension point in triage.py.

Module boundaries for sibling features (do not collide):
- confirm_culprit / bisect.py — confirm-the-culprit bisect (separate)
- failure / seen_before / outside_break / flaky — this package (intel.py)
- verified_fix — separate
"""
__version__ = "5.3.0"
