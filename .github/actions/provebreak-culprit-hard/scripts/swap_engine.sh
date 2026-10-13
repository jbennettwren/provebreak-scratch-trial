#!/usr/bin/env bash
# Re-vendor the culprit engine from a sentinel-lab commit, refresh ENGINE_LOCK.json + ENGINE_PROVENANCE.md, rerun tests.
# Usage: scripts/swap_engine.sh <sentinel-lab commit sha (40 hex)> [--source-repo URL|PATH] [--no-tests]
# Read-only against upstream (fetch only). Rolls back the vendored engine if vendoring or tests fail.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SHA="${1:-}"; shift || true
SRC_REPO="${SENTINEL_LAB_URL:-https://github.com/jbennettwren/sentinel-lab.git}"; RUN_TESTS=1
UPATH="${SENTINEL_ENGINE_PATH:-.github/actions/sentinel/src/sentinel_card}"
while [[ $# -gt 0 ]]; do case "$1" in
  --source-repo) SRC_REPO="$2"; shift 2 ;; --no-tests) RUN_TESTS=0; shift ;;
  *) echo "unknown arg $1" >&2; exit 2 ;; esac; done
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "need a full 40-hex commit sha (got '$SHA')" >&2; exit 2; }
WORK="$(mktemp -d)"; BAK="$(mktemp -d)"; trap 'rm -rf "$WORK" "$BAK"' EXIT
cp -a "$HERE/src/provebreak_culprit/_engine" "$BAK/_engine"; cp -a "$HERE/ENGINE_LOCK.json" "$HERE/ENGINE_PROVENANCE.md" "$HERE/src/provebreak_culprit/_provenance.py" "$BAK/"
rollback() { echo "swap FAILED: $1; restoring previous engine" >&2
  rm -rf "$HERE/src/provebreak_culprit/_engine"; cp -a "$BAK/_engine" "$HERE/src/provebreak_culprit/_engine"
  cp -a "$BAK/ENGINE_LOCK.json" "$BAK/ENGINE_PROVENANCE.md" "$HERE/"
  cp -a "$BAK/_provenance.py" "$HERE/src/provebreak_culprit/_provenance.py"; exit 1; }
git -C "$WORK" init -q up
git -C "$WORK/up" fetch -q --depth 1 "$SRC_REPO" "$SHA" || rollback "fetch of $SHA failed"
GOT="$(git -C "$WORK/up" rev-parse FETCH_HEAD)"; [[ "$GOT" == "$SHA" ]] || rollback "fetched $GOT != $SHA"
git -C "$WORK/up" -c advice.detachedHead=false checkout -q FETCH_HEAD
[[ -f "$WORK/up/$UPATH/bisect.py" ]] || rollback "no $UPATH/bisect.py at $SHA"
python3 "$HERE/scripts/vendor_engine.py" vendor --source-dir "$WORK/up/$UPATH" --commit "$SHA" --upstream-path "$UPATH" \
  --repo "$SRC_REPO" || rollback "vendoring"
# cross-check upstream blob shas against git's own tree
python3 - "$HERE/ENGINE_LOCK.json" "$WORK/up" "$UPATH" <<'PY' || rollback "blob sha mismatch vs upstream tree"
import json, subprocess, sys
lock, up, p = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3]
for f, e in lock["files"].items():
    t = subprocess.run(["git", "-C", up, "rev-parse", f"HEAD:{p}/{f}"], capture_output=True, text=True, check=True).stdout.strip()
    assert t == e["upstream_blob_sha"], (f, t)
PY
python3 "$HERE/scripts/vendor_engine.py" verify || rollback "verify"
python3 "$HERE/scripts/render_provenance.py" || rollback "provenance render"
if [[ $RUN_TESTS == 1 ]]; then
  (cd "$HERE" && python3 -m pytest -q -p no:cacheprovider tests) || rollback "tests failed on engine $SHA"
fi
echo "engine swapped to $SHA (review ENGINE_PROVENANCE.md; nothing pushed)"
