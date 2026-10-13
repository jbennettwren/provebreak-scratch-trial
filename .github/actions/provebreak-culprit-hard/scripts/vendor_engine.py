#!/usr/bin/env python3
"""Vendor the sentinel-lab culprit engine into src/provebreak_culprit/_engine/ as a swappable, hash-pinned unit.

The only transformation is a mechanical import rename on import lines:
    `sentinel_card`  ->  `provebreak_culprit._engine`
(so the vendored engine cannot clash with any other installed `sentinel_card`). Everything else is byte-identical.
ENGINE_LOCK.json records, per file, the upstream git blob sha + sha256 and the vendored sha256.

  vendor_engine.py vendor --source-dir <upstream sentinel_card dir> --commit <sha> [--upstream-path P] [--repo R]
  vendor_engine.py verify      # exit 1 if vendored files drift from ENGINE_LOCK.json
"""
from __future__ import annotations
import argparse, hashlib, json, re, shutil, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "src" / "provebreak_culprit" / "_engine"
LOCK = ROOT / "ENGINE_LOCK.json"
OLD, NEW = "sentinel_card", "provebreak_culprit._engine"
IMPORT_LINE = re.compile(r"^(\s*)(from|import)\s+sentinel_card\b")
DEP = re.compile(r"^\s*(?:from|import)\s+sentinel_card\.(\w+)", re.M)
ENTRY = "bisect.py"

def blob_sha(b: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(b) + b).hexdigest()

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def rewrite(src: str) -> str:
    out = []
    for line in src.splitlines(keepends=True):
        if IMPORT_LINE.match(line):
            line = line.replace(OLD, NEW, 1)
        out.append(line)
    res = "".join(out)
    leftover = [l for l in res.splitlines() if re.search(r"\bsentinel_card\b", l)]
    if leftover:
        raise SystemExit(f"non-import reference to sentinel_card, refusing to vendor: {leftover[:3]}")
    return res

def closure(src_dir: Path) -> list[str]:
    need, seen = [ENTRY, "__init__.py"], set()
    while need:
        f = need.pop()
        if f in seen: continue
        p = src_dir / f
        if not p.exists(): raise SystemExit(f"missing upstream module {f}")
        seen.add(f)
        need += [m + ".py" for m in DEP.findall(p.read_text())]
    return sorted(seen)

def vendor(a) -> None:
    src_dir = Path(a.source_dir)
    files = closure(src_dir)
    tmp = DEST.with_name("_engine.new")
    shutil.rmtree(tmp, ignore_errors=True); tmp.mkdir(parents=True)
    entries = {}
    for f in files:
        up = (src_dir / f).read_bytes()
        v = rewrite(up.decode("utf-8")).encode("utf-8")
        (tmp / f).write_bytes(v)
        entries[f] = {"upstream_blob_sha": blob_sha(up), "upstream_sha256": sha256(up), "vendored_sha256": sha256(v)}
    shutil.rmtree(DEST, ignore_errors=True); tmp.rename(DEST)
    lock = {"source_repo": a.repo, "commit": a.commit, "upstream_path": a.upstream_path,
            "transform": f"import-line rename {OLD} -> {NEW}; otherwise byte-identical",
            "entry": ENTRY, "files": entries}
    LOCK.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
    print(f"vendored {len(files)} files from {a.commit}")

def verify(_a=None) -> int:
    lock = json.loads(LOCK.read_text())
    have = {p.name for p in DEST.glob("*.py")}
    bad = sorted(have ^ set(lock["files"]))
    for f, e in lock["files"].items():
        p = DEST / f
        if p.exists() and sha256(p.read_bytes()) != e["vendored_sha256"]: bad.append(f)
    if bad:
        print("ENGINE DRIFT:", bad); return 1
    print(f"engine OK: {len(lock['files'])} files pinned to {lock['commit']}"); return 0

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); sp = ap.add_subparsers(dest="cmd", required=True)
    v = sp.add_parser("vendor"); v.add_argument("--source-dir", required=True); v.add_argument("--commit", required=True)
    v.add_argument("--repo", default="jbennettwren/sentinel-lab")
    v.add_argument("--upstream-path", default=".github/actions/sentinel/src/sentinel_card")
    sp.add_parser("verify")
    a = ap.parse_args()
    sys.exit(vendor(a) or 0 if a.cmd == "vendor" else verify(a))
