#!/usr/bin/env bash
# Hardening: env-only inputs, silent kill switch, one overall deadline shared by install+find, fail-soft (status=error).
set -uo pipefail
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"; OUTPUT="${GITHUB_OUTPUT:-/dev/null}"
DEFAULT_TIMEOUT_MIN=15
soft_fail() {  # $1 stage, $2 reason. Always records status=error; exits 0 unless fail-on-error=true.
  echo "status=error" >> "$OUTPUT"; echo "culprit_sha=" >> "$OUTPUT"; echo "verdict=error" >> "$OUTPUT"
  echo "::warning title=ProveBreak culprit (error in $1)::$2"
  if [[ "${PB_FAIL_ON_ERROR:-false}" == "true" ]]; then
    echo "- ❌ ProveBreak culprit: outcome \`error\` ($1: $2). No culprit named. Step failed because fail-on-error=true" >> "$SUMMARY"
    echo "::error::ProveBreak culprit $1 failed (fail-on-error=true)"; exit 1
  fi
  echo "- ⚠️ ProveBreak culprit: outcome \`error\` ($1: $2). No culprit named. Abstained; this step stays green (fail-on-error=false)" >> "$SUMMARY"
  exit 0
}
timeout_min() { local m="${PB_TIMEOUT_MINUTES:-$DEFAULT_TIMEOUT_MIN}"; [[ "$m" =~ ^[0-9]+$ ]] && (( m >= 1 && m <= 360 )) || m=$DEFAULT_TIMEOUT_MIN; echo "$m"; }
remaining() {  # seconds left before the overall deadline set by gate (falls back to the full timeout)
  local d="${PB_DEADLINE:-}" now; now=$(date +%s)
  [[ "$d" =~ ^[0-9]+$ ]] || d=$(( now + $(timeout_min) * 60 ))
  echo $(( d - now ))
}
run_limited() {  # $1 stage; rest = command. Kills the whole command at the overall deadline.
  local stage="$1"; shift; local left; left=$(remaining)
  (( left > 5 )) || soft_fail "$stage" "overall timeout ($(timeout_min) min) reached before this stage started"
  command -v timeout >/dev/null || soft_fail "$stage" "GNU timeout not found on this runner (Linux runners only)"
  timeout --kill-after=10s "${left}s" "$@"; local rc=$?
  if (( rc == 124 || rc == 137 )); then soft_fail "$stage" "timed out (overall timeout-minutes=$(timeout_min))"; fi
  return $rc
}
case "${1:-}" in
  gate)
    en="$(printf '%s' "${PB_ENABLED:-true}" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
    dis="$(printf '%s' "${PROVEBREAK_DISABLED:-}" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
    if [[ "$en" != "true" || "$dis" == "1" || "$dis" == "true" || "$dis" == "yes" ]]; then
      echo "run=false" >> "$OUTPUT"; exit 0   # kill switch: silent (no summary, no annotation, no outputs set)
    fi
    m="${PB_TIMEOUT_MINUTES:-$DEFAULT_TIMEOUT_MIN}"
    [[ "$m" =~ ^[0-9]+$ ]] && (( m >= 1 && m <= 360 )) || echo "::warning title=ProveBreak culprit (timeout-minutes)::invalid timeout-minutes '$m' (allowed 1-360); using $DEFAULT_TIMEOUT_MIN"
    echo "deadline=$(( $(date +%s) + $(timeout_min) * 60 ))" >> "$OUTPUT"
    if [[ -z "${PB_TESTS:-}" && -z "${PB_REPORT:-}" ]]; then
      echo "- ProveBreak culprit: Not sure. No failing test ids given. Abstained; no culprit named" >> "$SUMMARY"; echo "run=false" >> "$OUTPUT"
    elif ! [[ "${PB_CONFIRM_RERUNS:-3}" =~ ^([3-9]|10)$ ]]; then
      echo "::warning title=ProveBreak culprit (confirm_reruns)::confirm_reruns must be an integer from 3 to 10 (got '${PB_CONFIRM_RERUNS:-}')"
      echo "- ProveBreak culprit: invalid confirm_reruns '${PB_CONFIRM_RERUNS:-}' (allowed 3-10). Abstained; no culprit named" >> "$SUMMARY"; echo "run=false" >> "$OUTPUT"
    elif [[ -z "${PB_GOOD:-}" || "${PB_GOOD}" =~ ^0+$ ]]; then
      echo "- ProveBreak culprit: Not sure. No previous commit (new branch / first push). Abstained; no culprit named" >> "$SUMMARY"; echo "run=false" >> "$OUTPUT"
    else echo "run=true" >> "$OUTPUT"; fi
    exit 0 ;;
  install)
    command -v python3 >/dev/null || soft_fail install "python3 not found (run your tests with Python in this job first)"
    run_limited install python3 -m pip install -q --no-deps --disable-pip-version-check "${PB_ACTION_PATH:?}" || soft_fail install "pip install failed (exit $?)"
    echo "ok=true" >> "$OUTPUT"; exit 0 ;;
  find)
    [[ "${PB_CONFIRM_RERUNS:-3}" =~ ^([3-9]|10)$ ]] || soft_fail confirm_reruns "invalid confirm_reruns '${PB_CONFIRM_RERUNS:-}' (allowed 3-10)"
    for v in "PB_BUDGET_SEC:${PB_BUDGET_SEC:-180}" "PB_STEP_BUDGET:${PB_STEP_BUDGET:-16}" "PB_MAX_COMMITS:${PB_MAX_COMMITS:-200}"; do
      [[ "${v#*:}" =~ ^[1-9][0-9]{0,5}$ ]] || soft_fail inputs "invalid ${v%%:*} '${v#*:}' (positive whole number expected)"
    done
    command -v provebreak-culprit >/dev/null || soft_fail find "provebreak-culprit not installed"
    # Engine budget must end before the hard kill, so it can report budget_exhausted instead of being killed.
    left=$(remaining); budget="${PB_BUDGET_SEC:-180}"; cap=$(( left - 60 )); (( cap < 30 )) && cap=30
    (( budget > cap )) && budget=$cap
    FOE=(); [[ "${PB_FAIL_ON_ERROR:-false}" == "true" ]] && FOE=(--fail-on-error)
    [[ "${PB_PR_MODE:-false}" == "true" ]] && FOE+=(--pr)
    run_limited find provebreak-culprit --repo . --good "$PB_GOOD" --bad "$PB_BAD" --tests "$PB_TESTS" \
      --runner "${PB_RUNNER:-pytest}" --report "${PB_REPORT:-}" \
      --budget-sec "$budget" --step-budget "${PB_STEP_BUDGET:-16}" --max-commits "${PB_MAX_COMMITS:-200}" --confirm-reruns "${PB_CONFIRM_RERUNS:-3}" "${FOE[@]}" \
      || soft_fail find "culprit search failed (exit $?)"
    exit 0 ;;
  *) soft_fail unknown "unknown stage" ;;
esac
