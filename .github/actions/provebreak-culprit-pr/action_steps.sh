#!/usr/bin/env bash
# Hardening pattern copied from action_hardening_20261012/action_steps.sh: env-only inputs, kill switch, timeout, fail-soft.
set -uo pipefail
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"; OUTPUT="${GITHUB_OUTPUT:-/dev/null}"
soft_fail() {
  echo "::warning title=ProveBreak culprit ($1)::$2"
  if [[ "${PB_FAIL_ON_ERROR:-false}" == "true" ]]; then
    echo "- ❌ ProveBreak culprit $1: $2. Abstained; no culprit named. Step failed because fail-on-error=true" >> "$SUMMARY"
    echo "::error::ProveBreak culprit $1 failed (fail-on-error=true)"; exit 1
  fi
  echo "- ⚠️ ProveBreak culprit $1: $2. Abstained; no culprit named (this step stays green; fail-on-error=false)" >> "$SUMMARY"
  exit 0
}
run_limited() { local m="${PB_TIMEOUT_MINUTES:-10}"; [[ "$m" =~ ^[0-9]+$ ]] || m=10; timeout --kill-after=10s "${m}m" "$@"; }
case "${1:-}" in
  gate)
    dis="$(printf '%s' "${PROVEBREAK_DISABLED:-}" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
    if [[ "${PB_ENABLED:-true}" != "true" || "$dis" == "1" || "$dis" == "true" || "$dis" == "yes" ]]; then
      echo "::notice title=ProveBreak::disabled by kill switch; skipping"; echo "- ProveBreak culprit skipped: kill switch on" >> "$SUMMARY"
      echo "run=false" >> "$OUTPUT"
    elif [[ -z "${PB_TESTS:-}" && -z "${PB_REPORT:-}" ]]; then
      echo "- ProveBreak culprit: no failing test ids given. Abstained; no culprit named" >> "$SUMMARY"; echo "run=false" >> "$OUTPUT"
    elif ! [[ "${PB_CONFIRM_RERUNS:-3}" =~ ^([3-9]|10)$ ]]; then
      echo "::warning title=ProveBreak culprit (confirm_reruns)::confirm_reruns must be an integer from 3 to 10 (got '${PB_CONFIRM_RERUNS:-}')"
      echo "- ProveBreak culprit: invalid confirm_reruns '${PB_CONFIRM_RERUNS:-}' (allowed 3-10). Abstained; no culprit named" >> "$SUMMARY"; echo "run=false" >> "$OUTPUT"
    elif [[ -z "${PB_GOOD:-}" || "${PB_GOOD}" =~ ^0+$ ]]; then
      echo "- ProveBreak culprit: no previous commit (new branch / first push). Abstained; no culprit named" >> "$SUMMARY"; echo "run=false" >> "$OUTPUT"
    else echo "run=true" >> "$OUTPUT"; fi
    exit 0 ;;
  install) run_limited python3 -m pip install -q --no-deps --disable-pip-version-check "${PB_ACTION_PATH:?}" || soft_fail install "pip install failed"; exit 0 ;;
  find)
    [[ "${PB_CONFIRM_RERUNS:-3}" =~ ^([3-9]|10)$ ]] || soft_fail confirm_reruns "invalid confirm_reruns '${PB_CONFIRM_RERUNS:-}' (allowed 3-10)"
    FOE=(); [[ "${PB_FAIL_ON_ERROR:-false}" == "true" ]] && FOE=(--fail-on-error)
    [[ "${PB_PR_MODE:-false}" == "true" ]] && FOE+=(--pr)
    run_limited provebreak-culprit --repo . --good "$PB_GOOD" --bad "$PB_BAD" --tests "$PB_TESTS" \
      --runner "${PB_RUNNER:-pytest}" --report "${PB_REPORT:-}" \
      --budget-sec "${PB_BUDGET_SEC:-180}" --step-budget "${PB_STEP_BUDGET:-16}" --max-commits "${PB_MAX_COMMITS:-200}" --confirm-reruns "${PB_CONFIRM_RERUNS:-3}" "${FOE[@]}" \
      || soft_fail find "culprit search failed or timed out (exit $?)"
    exit 0 ;;
  *) soft_fail unknown "unknown stage" ;;
esac
