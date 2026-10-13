#!/usr/bin/env bash
# Hardening pattern copied from action_hardening_20261012/action_steps.sh: env-only inputs, kill switch, timeout, fail-soft.
set -uo pipefail
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"; OUTPUT="${GITHUB_OUTPUT:-/dev/null}"
soft_fail() {
  echo "::warning title=ProveBreak culprit ($1)::$2"
  echo "- ⚠️ ProveBreak culprit $1: $2. Abstained; no culprit named (CI not affected)" >> "$SUMMARY"
  [[ "${PB_FAIL_ON_ERROR:-false}" == "true" ]] && { echo "::error::fail-on-error=true"; exit 1; }
  exit 0
}
run_limited() { local m="${PB_TIMEOUT_MINUTES:-10}"; [[ "$m" =~ ^[0-9]+$ ]] || m=10; timeout --kill-after=10s "${m}m" "$@"; }
case "${1:-}" in
  gate)
    if [[ "${PB_ENABLED:-true}" != "true" || "${PROVEBREAK_DISABLED:-}" == "1" ]]; then
      echo "::notice title=ProveBreak::disabled by kill switch; skipping"; echo "- ProveBreak culprit skipped: kill switch on" >> "$SUMMARY"
      echo "run=false" >> "$OUTPUT"
    elif [[ -z "${PB_TESTS:-}" ]]; then
      echo "- ProveBreak culprit: no failing test ids given. Abstained; no culprit named" >> "$SUMMARY"; echo "run=false" >> "$OUTPUT"
    elif [[ -z "${PB_GOOD:-}" || "${PB_GOOD}" =~ ^0+$ ]]; then
      echo "- ProveBreak culprit: no previous commit (new branch / first push). Abstained; no culprit named" >> "$SUMMARY"; echo "run=false" >> "$OUTPUT"
    else echo "run=true" >> "$OUTPUT"; fi
    exit 0 ;;
  install) run_limited pip install -q "${PB_ACTION_PATH:?}" || soft_fail install "pip install failed"; exit 0 ;;
  find)
    FOE=(); [[ "${PB_FAIL_ON_ERROR:-false}" == "true" ]] && FOE=(--fail-on-error)
    run_limited provebreak-culprit --repo . --good "$PB_GOOD" --bad "$PB_BAD" --tests "$PB_TESTS" \
      --budget-sec "${PB_BUDGET_SEC:-180}" --step-budget "${PB_STEP_BUDGET:-16}" --max-commits "${PB_MAX_COMMITS:-200}" "${FOE[@]}" \
      || soft_fail find "culprit search failed or timed out (exit $?)"
    exit 0 ;;
  *) soft_fail unknown "unknown stage" ;;
esac
