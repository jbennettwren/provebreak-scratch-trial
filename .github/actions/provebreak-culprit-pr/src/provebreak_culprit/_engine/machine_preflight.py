"""Shared machine preflight for the dotnet and junit runners.

One scan, called before either runner names a commit. The host environment
is copied before any scrub. A hit abstains and names no culprit. The probe
does not decide that an unknown file is harmless.

A dotnet or JVM prove requires the resolved install tree to match one stock
manifest: one root hash per install, not a file list. Anything else abstains.
"""

from __future__ import annotations

import base64
import errno
import gzip
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

# kind, version, sha256 of the sorted JSON records for that install.
# Each record is ``[kind, relpath, value]`` with kind in file, dir, symlink, dangling.
# Only installs we can name and reproduce. The comment on each row is its source.
_STOCK_MANIFESTS = (
    # actions/setup-dotnet@67a3573c, dotnet-version 8.0.x, SDK 8.0.425 (~/.dotnet).
    # Hosted plant-dotnet is blocked on billing, so this JSON-record hash is the
    # local tree that action installs, not a new hosted job log.
    ("dotnet", "8.0.425", "a600c7499c451bd630bddff45b471abdda5ffeace98da3f7003dd0cf5c025288"),
    # actions/setup-java@b6effb05, distribution temurin, java-version 21, resolved 21.0.12+101.
    # JSON-record hash of the local jdk-21.0.12.1+1 tarball. Includes internal legal/*
    # symlinks (link text, resolved path, and target bytes). The runner's Temurin
    # tree is the separate 21.0.12.1+1-LTS row.
    ("jdk", "21.0.12+101", "423083ba5ecc15b3771765171bc428a39ddecc16ac820172e7ae587c4a8d5999"),
    # Run 37135518095, job plant-jvm 111239145456, runner sentinel-box-1.
    # Temurin tree that job hashed, version token 21.0.12.1+1-LTS.
    ("jdk", "21.0.12.1+1-LTS", "d27c9a6539892fff0b62027688b54b78af11c855d9eeeefa025c6b35f0558719"),
    # Run 37135518048, unit job 111239145379, runner sentinel-box-1, debian maven 3.9.9-1.
    # plant-jvm job 111239145456 logged the same hash through 01e11f3bafba0d67957dc74 before the cut.
    # The two optional dangling links maven-resolver-transport-http.jar and
    # plexus-xml.jar are part of the stock package.
    ("mvn", "3.9.9", "01e11f3bafba0d67957dc7476328dab0ad1f620c5c5dd22b23c98df2b51807fe"),
)
# Bisect overlay names the dotnet/JVM child may receive. Every other overlay name is dropped.
_OVERLAY_ALLOW = frozenset({
    "PATH", "HOME", "TMPDIR", "LANG",
    "DOTNET_CLI_TELEMETRY_OPTOUT", "DOTNET_NOLOGO", "JAVA_HOME",
})
_GRADLE_DIST_HOSTS = frozenset({
    "services.gradle.org", "downloads.gradle.org", "repo.gradle.org", "plugins.gradle.org",
})


def _digest_known(digest: str | None) -> bool:
    return bool(digest) and any(item[2] == digest for item in _STOCK_MANIFESTS)


def _sha_file(path: Path, prefix: bytes = b"") -> str:
    digest = hashlib.sha256()
    if prefix:
        digest.update(prefix)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _errno_name(err: OSError) -> str:
    code = err.errno
    if code is None:
        return "EIO"
    return errno.errorcode.get(code, f"E{code}")


def _token_path(path: Path | str) -> str:
    """One reason token. Spaces would split the tool/version/hash groups."""
    return str(path).replace(" ", "%20").replace("\n", "%0A").replace("\t", "%09")


def _unreadable(kind: str, display: Path | str) -> str:
    return f"unreadable:{kind}:{_token_path(display)}"


def _has_control(text: str) -> bool:
    """True when ``text`` contains U+0000–U+001F or U+007F."""
    return any(char < " " or char == "\x7f" for char in text)


def _entry(kind: str, relpath: str, value: str) -> str:
    """One fingerprint record. Raw path and readlink bytes never reach the joiner."""
    return json.dumps([kind, relpath, value], ensure_ascii=True, separators=(",", ":"))


def _tree_digest(root: Path) -> str | None:
    """Root hash of one install tree.

    A regular file contributes its bytes. A symlink whose target exists contributes
    its link text, its resolved path, and, for a file, the target bytes. A symlink
    to a directory is followed, including links inside that target. A plain dangling
    symlink is a ``dangling`` record whose value is the raw ``os.readlink`` text,
    and that link is not followed. Each record is one JSON array
    ``[kind, relpath, value]`` with kind in ``file``, ``dir``, ``symlink``, or
    ``dangling``. A control character in a relative path or readlink, a cycle, a
    permission error, or a special file makes the digest ``None`` (abstain). The
    root hash is the sha256 of those records sorted. Each call walks the tree
    again. A hash from an earlier call is never reused, so a tree that changes
    after it was first hashed does not still match.
    """
    digest, _why = _tree_digest_result(root)
    return digest


def _tree_digest_result(root: Path) -> tuple[str | None, str]:
    """Return ``(digest, "")`` or ``(None, unreadable detail)``.

    A missing symlink target is fingerprinted, not an offender. A relative path
    or readlink containing a control character is ``unreadable:control_char``.
    A symlink target that is not UTF-8 is ``unreadable:non_utf8``.
    Otherwise the detail names the first cycle, permission error, or special
    file in sorted directory order: ``unreadable:cycle:<link>-><target>``,
    ``unreadable:permission:<errno>:<path>``, or ``unreadable:special:<path>``.
    """
    try:
        base = Path(os.path.realpath(root))
    except OSError as err:
        return None, _unreadable(f"permission:{_errno_name(err)}", root)
    lines: list[str] = []
    stack: set[str] = set()
    failure: list[str] = []

    def note(kind: str, display: Path | str) -> bool:
        if not failure:
            if kind in {"control_char", "non_utf8"}:
                failure.append(f"unreadable:{kind}")
            else:
                failure.append(_unreadable(kind, display))
        return False

    def walk(directory: Path, prefix: str) -> bool:
        try:
            real = os.path.realpath(directory)
        except OSError as err:
            return note(f"permission:{_errno_name(err)}", directory)
        if real in stack:
            return note("cycle", directory)
        stack.add(real)
        try:
            try:
                names = sorted(os.listdir(directory))
            except OSError as err:
                return note(f"permission:{_errno_name(err)}", directory)
            for name in names:
                child = directory / name
                rel = f"{prefix}/{name}" if prefix else name
                if _has_control(rel):
                    return note("control_char", rel)
                try:
                    is_link = child.is_symlink()
                except OSError as err:
                    return note(f"permission:{_errno_name(err)}", child)
                if is_link:
                    try:
                        link = os.readlink(child)
                    except OSError as err:
                        return note(f"permission:{_errno_name(err)}", child)
                    if _has_control(link):
                        return note("control_char", child)
                    try:
                        os.stat(child)
                    except FileNotFoundError:
                        lines.append(_entry("dangling", rel, link))
                        continue
                    except OSError as err:
                        shown = f"{child}->{link}"
                        if err.errno == errno.ELOOP:
                            return note("cycle", shown)
                        return note(f"permission:{_errno_name(err)}", shown)
                    try:
                        resolved = Path(os.path.realpath(child))
                    except OSError as err:
                        return note(f"permission:{_errno_name(err)}", child)
                    shown = f"{child}->{resolved}"
                    try:
                        is_dir = resolved.is_dir()
                        is_file = resolved.is_file()
                    except OSError as err:
                        return note(f"permission:{_errno_name(err)}", shown)
                    if is_dir:
                        try:
                            target_real = os.path.realpath(resolved)
                        except OSError as err:
                            return note(f"permission:{_errno_name(err)}", shown)
                        if target_real in stack:
                            return note("cycle", shown)
                        try:
                            lines.append(_entry("dir", rel, _link_digest(b"linkdir", link, resolved)))
                        except UnicodeEncodeError:
                            return note("non_utf8", shown)
                        if not walk(resolved, rel):
                            return False
                        continue
                    if is_file:
                        try:
                            file_prefix = b"linkfile\0" + link.encode() + b"\0" + str(resolved).encode() + b"\0"
                            digest = _sha_file(resolved, file_prefix)
                        except UnicodeEncodeError:
                            return note("non_utf8", shown)
                        except OSError as err:
                            return note(f"permission:{_errno_name(err)}", shown)
                        lines.append(_entry("symlink", rel, digest))
                        continue
                    return note("special", shown)
                try:
                    is_dir = child.is_dir()
                    is_file = child.is_file()
                except OSError as err:
                    return note(f"permission:{_errno_name(err)}", child)
                if is_dir:
                    if not walk(child, rel):
                        return False
                    continue
                if is_file:
                    try:
                        lines.append(_entry("file", rel, _sha_file(child)))
                    except OSError as err:
                        return note(f"permission:{_errno_name(err)}", child)
                    continue
                return note("special", child)
            return True
        finally:
            stack.discard(real)

    if not walk(base, ""):
        return None, (failure[0] if failure else _unreadable("permission:EIO", base))
    lines.sort()
    return hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest(), ""


def _link_digest(kind: bytes, link: str, resolved: Path, payload: bytes = b"") -> str:
    blob = kind + b"\0" + link.encode() + b"\0" + str(resolved).encode() + b"\0" + payload
    return hashlib.sha256(blob).hexdigest()




# MSBuild property names are case-insensitive, including when they arrive as env vars.
_MSBUILD_EXACT = frozenset({
    "ALTERNATECOMMONPROPS",
    "RESTORECONFIGFILE",
    "RESTOREPACKAGESPATH",
    "RUNSETTINGSFILEPATH",
})
TOOLCHAIN_UNVERIFIED = "machine_preflight_toolchain_unverified"
VCURRENT = "machine_preflight_msbuild_vcurrent"
RSP = "machine_preflight_msbuild_rsp"
_VCURRENT_FILES = (
    "vCurrent/Custom.Before.Microsoft.CSharp.targets",
    "vCurrent/Custom.After.Microsoft.CSharp.targets",
    "vCurrent/Custom.Before.Microsoft.Common.targets",
    "vCurrent/Custom.After.Microsoft.Common.targets",
    "vCurrent/Custom.Before.Microsoft.Common.props",
    "vCurrent/Custom.After.Microsoft.Common.props",
)
_VCURRENT_DIRS = ("vCurrent/ImportBefore", "vCurrent/ImportAfter")
_RSP_NAMES = ("Directory.Build.rsp", "MSBuild.rsp")

# A host key the child will not see is silent, unless it can still change the
# build the host command runs. The reason names the key and not the value.
ENV_UNSCRUBBED = "machine_preflight_env_unscrubbed"
_DOTNET_PASS = ("DOTNET_ROOT", "DOTNET_ROOT_X64", "DOTNET_MULTILEVEL_LOOKUP")
_STOCK_MAVEN_ARGS = "-ntp"
# Install locations. The GRADLE_* / MAVEN_* hook patterns do not apply to these.
_LOCATION_KEYS = frozenset({"GRADLE_HOME", "MAVEN_HOME", "M2_HOME"})
# The sandbox rewrites these on purpose. A different value is not a disagreement.
_REWRITTEN = frozenset({
    "HOME", "PATH", "PYTHONNOUSERSITE", "PYTHONSAFEPATH", "PYTHONDONTWRITEBYTECODE",
})
_NUGET_ORG = "https://api.nuget.org/v3/index.json"
_MAVEN_BAD = frozenset({
    "localrepository", "mirror", "repository", "pluginrepository", "proxy", "server",
    "profile", "activeprofile", "offline", "plugin", "extensions",
})
_CACHE_CAP = 24
_CACHE_MAX_BYTES = 20_000_000
_ENV_PLACEHOLDER = re.compile(r"^\$\{env\.[A-Za-z_][A-Za-z0-9_]*\}$")

_CSHARP_DIRS = (
    "Microsoft.CSharp.targets/ImportBefore",
    "Current/Microsoft.CSharp.targets/ImportBefore",
    "Microsoft.CSharp.targets/ImportAfter",
    "Current/Microsoft.CSharp.targets/ImportAfter",
)
_COMMON_TARGETS_BEFORE = (
    "Microsoft.Common.targets/ImportBefore",
    "Current/Microsoft.Common.targets/ImportBefore",
)
_COMMON_TARGETS_AFTER = (
    "Microsoft.Common.targets/ImportAfter",
    "Current/Microsoft.Common.targets/ImportAfter",
)
_COMMON_PROPS_BEFORE = (
    "Current/Imports/Microsoft.Common.props/ImportBefore",
)
_COMMON_PROPS_AFTER = (
    "Current/Imports/Microsoft.Common.props/ImportAfter",
)
_CROSS_BEFORE = (
    "Current/Microsoft.Common.CrossTargeting.targets/ImportBefore",
)
_CROSS_AFTER = (
    "Current/Microsoft.Common.CrossTargeting.targets/ImportAfter",
)

_GRADLE_DIST_SCRIPT = (".gradle", ".gradle.kts")

CUSTOMER_LINE = (
    "we did not name a commit, because a machine or user build setting "
    "can make this job disagree with the command on your machine."
)


def host_environ() -> dict[str, str]:
    """The process environment, before a runner replaces HOME or drops keys."""
    return {key: value for key, value in os.environ.items() if value is not None}


def _passwd_home() -> Path | None:
    try:
        return Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (KeyError, OSError):
        return None


def _key_token(key: str) -> bool:
    if not key or len(key) > 128:
        return False
    if not (key[0].isalpha() or key[0] == "_"):
        return False
    return key.replace("_", "A").isalnum()


def _java_home_passed(env: dict[str, str]) -> bool:
    raw = env.get("JAVA_HOME") or ""
    if not raw or "\n" in raw or "\r" in raw:
        return False
    return (Path(raw) / "bin" / "java").is_file()


def _msbuild_env_hook(key: str) -> bool:
    """An MSBuild hook name. Compared case-insensitively, as MSBuild compares properties."""
    folded = key.upper()
    if folded.startswith(("MSBUILD", "DIRECTORYBUILD")):
        return True
    if folded.startswith("CUSTOM") and folded.endswith(("TARGETS", "PROPS")):
        return True
    return folded in _MSBUILD_EXACT


def _build_hook(family: str, key: str) -> bool:
    """A host key that can change the build even when the child drops it."""
    if family == "junit":
        if key in _LOCATION_KEYS:
            return False
        if key.endswith("_JAVA_OPTIONS") or key in {"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "JAVA_OPTS"}:
            return True
        if key.startswith(("MAVEN_", "GRADLE_", "ORG_GRADLE_PROJECT_")):
            return True
        return False
    if family != "dotnet":
        return False
    if key.startswith(("NUGET_", "DOTNET_")):
        return True
    return _msbuild_env_hook(key)


def _rewritten_key(key: str) -> bool:
    if key in _REWRITTEN or key.startswith("XDG_") or key.startswith("GIT_CONFIG"):
        return True
    return False


def scrub_runner_env(family: str, extra: dict[str, str] | None) -> dict[str, str]:
    """Keep the dotnet/JVM overlay to a tiny allow-list. There is no name denylist."""
    if not extra:
        return {}
    if family not in {"dotnet", "junit"}:
        return {key: value for key, value in extra.items() if value is not None and not _build_hook(family, key)}
    return {key: value for key, value in extra.items() if value is not None and key in _OVERLAY_ALLOW}


def _child_view(family: str, env: dict[str, str], runner_env: dict[str, str] | None) -> dict[str, str]:
    """Host keys as the sandboxed child will see them. A missing key was dropped."""
    from provebreak_culprit._engine.bisect import build_scrubbed_env

    extra: dict[str, str] = {}
    if family == "junit":
        extra["MAVEN_OPTS"] = "-Djava.awt.headless=true"
        extra["GIT_TERMINAL_PROMPT"] = "0"
        if _java_home_passed(env):
            extra["JAVA_HOME"] = env["JAVA_HOME"]
        if env.get("MAVEN_ARGS") == _STOCK_MAVEN_ARGS:
            extra["MAVEN_ARGS"] = _STOCK_MAVEN_ARGS
    extra.update(scrub_runner_env(family, runner_env))
    child = build_scrubbed_env(base=env, extra=extra or None, home="/tmp/sentinel-preflight-home")
    if family == "dotnet":
        for key in _DOTNET_PASS:
            if env.get(key):
                child[key] = env[key]
        child["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
        child["DOTNET_NOLOGO"] = "1"
        child["DOTNET_SKIP_FIRST_TIME_EXPERIENCE"] = "1"
        child["NUGET_XMLDOC_MODE"] = "skip"
        child["GIT_TERMINAL_PROMPT"] = "0"
        if env.get("NUGET_PACKAGES"):
            child["NUGET_PACKAGES"] = "/tmp/sentinel-nuget-cache"
        if env.get("DOTNET_CLI_HOME"):
            child["DOTNET_CLI_HOME"] = "/tmp/sentinel-preflight-home"
    if family == "junit" and _java_home_passed(env):
        bin_dir = str(Path(env["JAVA_HOME"]) / "bin")
        path = child.get("PATH") or ""
        if bin_dir not in path.split(":"):
            child["PATH"] = bin_dir + (":" + path if path else "")
    return child


def _unscrubbed_key(family: str, env: dict[str, str], runner_env: dict[str, str] | None) -> str | None:
    """A build hook the child drops, or an allow-listed key whose value changes."""
    from provebreak_culprit._engine.bisect import build_scrubbed_env

    child = _child_view(family, env, runner_env)
    kept = build_scrubbed_env(base=env, home="/tmp/sentinel-preflight-home")
    bad: list[str] = []
    for key, value in env.items():
        if child.get(key) == value:
            continue
        if _build_hook(family, key):
            bad.append(key)
            continue
        if _rewritten_key(key):
            continue
        if kept.get(key) == value and child.get(key) != value:
            bad.append(key)
    if runner_env:
        for key, value in runner_env.items():
            if value is None:
                continue
            if key not in _OVERLAY_ALLOW:
                bad.append(key)
                continue
            if key in {"PATH", "HOME", "TMPDIR", "LANG", "JAVA_HOME"}:
                continue
            if value != "1":
                bad.append(key)
    if not bad:
        return None
    key = sorted(set(bad))[0]
    if not _key_token(key):
        return ENV_UNSCRUBBED
    return f"{ENV_UNSCRUBBED} {key}"


@dataclass
class ScanRoots:
    """Filesystem locations the scan reads. Tests pass a private tree."""

    passwd_home: Path | None = None
    env_home: Path | None = None
    xdg_data_home: Path | None = None
    appdata: Path | None = None
    localappdata: Path | None = None
    gradle_dist: Path | None = None
    sdk_dirs: tuple[Path, ...] = ()
    mavenrc_system: Path = Path("/etc/mavenrc")
    mavenrc_usr_local: Path = Path("/usr/local/etc/mavenrc")
    nuget_machine_dir: Path = Path("/etc/opt/NuGet/Config")
    program_files_nuget: tuple[Path, ...] = ()


def discover_roots(family: str, env: dict[str, str], *, dotnet_bin: str | None = None) -> ScanRoots:
    """Resolve homes and tool installs from the host snapshot."""
    passwd = _passwd_home()
    raw_home = (env.get("HOME") or "").strip()
    env_home = Path(raw_home) if raw_home else None
    if passwd is not None and env_home is not None and passwd == env_home:
        env_home = None
    xdg = (env.get("XDG_DATA_HOME") or "").strip()
    appdata = (env.get("APPDATA") or "").strip()
    local = (env.get("LOCALAPPDATA") or "").strip()
    program_files = []
    for key in ("ProgramFiles(x86)", "ProgramFiles", "ProgramW6432"):
        raw = (env.get(key) or "").strip()
        if raw:
            program_files.append(Path(raw) / "NuGet" / "Config")
    return ScanRoots(
        passwd_home=passwd,
        env_home=env_home,
        xdg_data_home=Path(xdg) if xdg else None,
        appdata=Path(appdata) if appdata else None,
        localappdata=Path(local) if local else None,
        gradle_dist=_gradle_dist(env) if family == "junit" else None,
        sdk_dirs=tuple(_sdk_dirs(env, dotnet_bin)) if family == "dotnet" else (),
        program_files_nuget=tuple(program_files),
    )


def _gradle_dist(env: dict[str, str]) -> Path | None:
    raw = (env.get("GRADLE_HOME") or "").strip()
    if raw:
        path = Path(raw)
        return path if path.is_dir() else None
    gradle = shutil.which("gradle", path=env.get("PATH"))
    if not gradle:
        return None
    try:
        resolved = Path(gradle).resolve()
    except OSError:
        return None
    if resolved.parent.name == "bin":
        return resolved.parent.parent
    return resolved.parent


def _sdk_dirs(env: dict[str, str], dotnet_bin: str | None = None) -> list[Path]:
    listed = _sdk_dirs_from_dotnet(env, dotnet_bin)
    if listed:
        return listed
    if dotnet_bin and os.path.isabs(dotnet_bin):
        return []
    return _sdk_dirs_from_disk(env)


def _sdk_dirs_from_dotnet(env: dict[str, str], dotnet_bin: str | None = None) -> list[Path]:
    if dotnet_bin and os.path.isabs(dotnet_bin):
        dotnet = dotnet_bin if os.path.isfile(dotnet_bin) and os.access(dotnet_bin, os.X_OK) else ""
    else:
        dotnet = shutil.which(dotnet_bin or "dotnet", path=env.get("PATH")) or ""
    if not dotnet:
        return []
    child = {
        "PATH": env.get("PATH", ""),
        "LANG": env.get("LANG", "C.UTF-8"),
        "HOME": str(_passwd_home() or "/tmp"),
    }
    for key in ("DOTNET_ROOT", "DOTNET_ROOT_X64"):
        if env.get(key):
            child[key] = env[key]
    try:
        proc = subprocess.run(
            [dotnet, "--list-sdks"],
            capture_output=True,
            text=True,
            timeout=30,
            env=child,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    found: list[Path] = []
    for line in (proc.stdout or "").splitlines():
        text = line.strip()
        if "[" not in text or not text.endswith("]"):
            continue
        base = text[text.rfind("[") + 1:-1].strip()
        version = text.split("[", 1)[0].strip()
        if not base or not version:
            continue
        path = Path(base) / version
        if path.is_dir() and path not in found:
            found.append(path)
    return found


def _sdk_dirs_from_disk(env: dict[str, str]) -> list[Path]:
    roots: list[Path] = []
    for key in ("DOTNET_ROOT", "DOTNET_ROOT_X64"):
        raw = (env.get(key) or "").strip()
        if raw:
            roots.append(Path(raw))
    roots.extend((Path("/usr/share/dotnet"), Path("/usr/lib/dotnet")))
    home = _passwd_home()
    if home is not None:
        roots.append(home / ".dotnet")
    found: list[Path] = []
    for root in roots:
        sdk = root / "sdk"
        try:
            children = list(sdk.iterdir()) if sdk.is_dir() else []
        except OSError:
            continue
        for child in children:
            if child.name[:1].isdigit() and child.is_dir() and not child.is_symlink():
                if child not in found:
                    found.append(child)
    return found


def preflight_reason(
    family: str,
    repo: Path,
    *,
    env: dict[str, str] | None = None,
    roots: ScanRoots | None = None,
    dotnet_bin: str | None = None,
    runner_env: dict[str, str] | None = None,
) -> str | None:
    """Return a reason code when the host can disagree with the probe.

    ``env`` defaults to the live process environment, read here, before the
    caller scrubs it. ``roots`` defaults to locations resolved from that snapshot.
    ``dotnet_bin`` is the runner's binary. ``runner_env`` is the bisect overlay
    the child actually receives.
    """
    host = host_environ() if env is None else dict(env)
    resolved = roots if roots is not None else discover_roots(family, host, dotnet_bin=dotnet_bin)
    if family == "dotnet":
        return _scan_dotnet(Path(repo), host, resolved, runner_env, dotnet_bin)
    if family == "junit":
        return _scan_jvm(Path(repo), host, resolved, runner_env)
    return None


def _homes(roots: ScanRoots) -> list[Path]:
    found: list[Path] = []
    for path in (roots.passwd_home, roots.env_home):
        if path is not None and path not in found:
            found.append(path)
    return found


def _user_msbuild_roots(roots: ScanRoots) -> list[Path]:
    """Host XDG_DATA_HOME when set, otherwise the passwd-home default.

    A distinct HOME is scanned too. Windows uses LOCALAPPDATA.
    """
    found: list[Path] = []
    if roots.xdg_data_home is not None:
        found.append(roots.xdg_data_home / "Microsoft" / "MSBuild")
    elif roots.passwd_home is not None:
        found.append(roots.passwd_home / ".local" / "share" / "Microsoft" / "MSBuild")
    if roots.env_home is not None:
        extra = roots.env_home / ".local" / "share" / "Microsoft" / "MSBuild"
        if extra not in found:
            found.append(extra)
    if roots.localappdata is not None:
        win = roots.localappdata / "Microsoft" / "MSBuild"
        if win not in found:
            found.append(win)
    return found


def _dir_has_extra(path: Path, *, sdk_root: Path | None) -> bool:
    try:
        if path.is_symlink():
            return True
        if not path.is_dir():
            return path.exists()
        for child in path.iterdir():
            if not (child.is_symlink() or child.is_file()):
                continue
            if sdk_root is not None and _is_stock_sdk_file(sdk_root, child):
                continue
            return True
    except OSError:
        return True
    return False


def _is_stock_sdk_file(sdk_root: Path, path: Path) -> bool:
    """True when ``path`` sits in an install whose whole-tree root hash is stock."""
    roots = [sdk_root]
    if sdk_root.parent.name == "sdk":
        roots.append(sdk_root.parent.parent)
    for root in roots:
        if not _digest_known(_tree_digest(root)):
            continue
        try:
            path.absolute().relative_to(root.resolve())
        except (OSError, ValueError):
            continue
        return True
    return False


def _import_hit(bases: list[Path], relatives: tuple[str, ...], *, sdk_root: Path | None) -> bool:
    for base in bases:
        for rel in relatives:
            if _dir_has_extra(base.joinpath(*rel.split("/")), sdk_root=sdk_root):
                return True
    return False


def _scan_import_pair(
    roots: ScanRoots,
    relatives: tuple[str, ...],
    code: str,
) -> str | None:
    if _import_hit(_user_msbuild_roots(roots), relatives, sdk_root=None):
        return code
    for sdk in roots.sdk_dirs:
        if _import_hit([sdk], relatives, sdk_root=sdk):
            return code
    return None


def _tool_path(family: str, env: dict[str, str], runner_env: dict[str, str] | None) -> str:
    """PATH the child will search. An unset PATH is not the process default."""
    if "PATH" not in env and not (runner_env and "PATH" in runner_env):
        if not (family == "junit" and _java_home_passed(env)):
            return ""
    return _child_view(family, env, runner_env).get("PATH") or ""


def _which(name: str, path: str) -> Path | None:
    if not path:
        return None
    found = shutil.which(name, path=path)
    return Path(found) if found else None


def _resolve_dotnet(dotnet_bin: str | None, path: str) -> Path | None:
    if dotnet_bin and os.path.isabs(dotnet_bin):
        binary = Path(dotnet_bin)
        if binary.is_file() and os.access(binary, os.X_OK):
            return binary
        return None
    return _which(dotnet_bin or "dotnet", path)


def _vcurrent_bases(roots: ScanRoots) -> list[Path]:
    found: list[Path] = list(roots.sdk_dirs)
    for home in _homes(roots):
        base = home / ".dotnet"
        if base not in found:
            found.append(base)
        sdk_root = base / "sdk"
        try:
            children = list(sdk_root.iterdir()) if sdk_root.is_dir() and not sdk_root.is_symlink() else []
        except OSError:
            continue
        for child in children:
            if child.name[:1].isdigit() and child.is_dir() and not child.is_symlink() and child not in found:
                found.append(child)
    return found


def _scan_vcurrent(roots: ScanRoots) -> str | None:
    for base in _vcurrent_bases(roots):
        sdk = base if base in roots.sdk_dirs else None
        for rel in _VCURRENT_FILES:
            path = base.joinpath(*rel.split("/"))
            if _exists_file(path) and not (sdk is not None and _is_stock_sdk_file(sdk, path)):
                return VCURRENT
        for rel in _VCURRENT_DIRS:
            if _dir_has_extra(base.joinpath(*rel.split("/")), sdk_root=sdk):
                return VCURRENT
    return None


def _rsp_named(repo: Path) -> bool:
    try:
        base = repo.resolve()
    except OSError:
        base = repo
    if base.is_dir():
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            current = Path(dirpath)
            dirnames[:] = [name for name in dirnames if name != ".git" and not (current / name).is_symlink()]
            for name in filenames:
                if name in _RSP_NAMES and _exists_file(current / name):
                    return True
    for parent in _ancestors(repo):
        for name in _RSP_NAMES:
            if _exists_file(parent / name):
                return True
    return False


def _rsp_beside(env: dict[str, str], roots: ScanRoots, runner_env: dict[str, str] | None, dotnet_bin: str | None) -> bool:
    spots: list[Path] = []
    binary = _resolve_dotnet(dotnet_bin, _tool_path("dotnet", env, runner_env))
    if binary is not None:
        spots.append(binary.parent)
    spots.extend(roots.sdk_dirs)
    for spot in spots:
        try:
            if spot.is_symlink() or not spot.is_dir():
                continue
            for child in spot.iterdir():
                if child.suffix.lower() == ".rsp" and _exists_file(child):
                    return True
        except OSError:
            return True
    return False


def _path_inside(root: Path, binary: Path) -> bool:
    try:
        binary.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def _parent_install(binary: Path) -> Path | None:
    try:
        resolved = binary.resolve()
    except OSError:
        return None
    if resolved.parent.name == "bin":
        return resolved.parent.parent
    return resolved.parent


def _pinned_home(env: dict[str, str], keys: tuple[str, ...]) -> Path | None:
    for key in keys:
        raw = (env.get(key) or "").strip()
        if raw:
            return Path(raw)
    return None


def _declared_install(env: dict[str, str], keys: tuple[str, ...], binary: Path) -> Path | None:
    """The declared home when the binary lives inside it, otherwise None.

    A set home that does not contain the binary is None. Callers that see a
    pinned home must abstain on None instead of accepting the binary's parent.
    """
    pinned = _pinned_home(env, keys)
    if pinned is not None:
        if _path_inside(pinned, binary):
            return pinned
        return None
    return _parent_install(binary)


def _version_token(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9.+_~-]", "_", (text or "").strip())[:80]
    return cleaned or "-"


def _release_version(root: Path) -> str:
    path = root / "release"
    try:
        if path.is_symlink() or not path.is_file():
            return ""
        text = path.read_text(encoding="utf-8", errors="replace")[:20_000]
    except OSError:
        return ""
    for key in ("JAVA_RUNTIME_VERSION", "JAVA_VERSION"):
        prefix = key + "="
        for line in text.splitlines():
            if line.startswith(prefix):
                return line.split("=", 1)[1].strip().strip('"')
    return ""


def _debian_pkg_version(package: str, upstream: str) -> str:
    """Package revision from the distro changelog, when it matches ``upstream``."""
    changelog = Path(f"/usr/share/doc/{package}/changelog.Debian.gz")
    try:
        if not changelog.is_file():
            return ""
        line = gzip.open(changelog, "rt", errors="replace").readline()
    except OSError:
        return ""
    match = re.match(rf"{re.escape(package)} \(([^)]+)\)", line)
    if not match:
        return ""
    deb = match.group(1).strip()
    if deb == upstream or deb.startswith(upstream + "-") or deb.startswith(upstream + "+"):
        return deb
    return ""


def _maven_core_version(root: Path) -> str:
    lib = root / "lib"
    try:
        if not lib.is_dir():
            return ""
        names = list(lib.iterdir())
    except OSError:
        return ""
    candidates = [path for path in names if "maven-core" in path.name]
    for path in candidates:
        try:
            real = Path(os.path.realpath(path))
            if not real.is_file():
                continue
            with zipfile.ZipFile(real) as archive:
                props = [
                    name for name in archive.namelist()
                    if name.endswith("org.apache.maven/maven-core/pom.properties")
                ]
                if not props:
                    continue
                text = archive.read(props[0]).decode("utf-8", "replace")
        except (OSError, zipfile.BadZipFile):
            continue
        upstream = ""
        for line in text.splitlines():
            if line.startswith("version="):
                upstream = line.split("=", 1)[1].strip()
                break
        if not upstream:
            continue
        try:
            rooted = os.path.realpath(root) == "/usr/share/maven" or str(real).startswith("/usr/share/java/")
        except OSError:
            rooted = False
        if rooted:
            deb = _debian_pkg_version("maven", upstream)
            if deb:
                return deb
        return upstream
    return ""


def _dotnet_version(root: Path) -> str:
    sdk = root / "sdk"
    try:
        if not sdk.is_dir():
            return ""
        children = sorted(sdk.iterdir(), key=lambda item: item.name)
    except OSError:
        return ""
    for child in children:
        version_file = child / ".version"
        try:
            if version_file.is_symlink() or not version_file.is_file():
                if child.name[:1].isdigit():
                    return child.name
                continue
            parts = version_file.read_text(encoding="utf-8", errors="replace").split()
        except OSError:
            continue
        if len(parts) >= 2:
            return parts[1]
        if child.name[:1].isdigit():
            return child.name
    return ""


def _tool_version(tool: str, root: Path | None) -> str:
    if root is None:
        return ""
    try:
        if not root.is_dir():
            return ""
    except OSError:
        return ""
    if tool in {"java", "javac"}:
        return _release_version(root)
    if tool == "mvn":
        return _maven_core_version(root)
    if tool == "dotnet":
        return _dotnet_version(root)
    return ""


def _unverified_part(tool: str, root: Path | None) -> str | None:
    """``tool version hash`` when ``root`` is not a seeded manifest, else None."""
    if root is not None:
        try:
            is_dir = root.is_dir()
        except OSError:
            is_dir = False
        if is_dir:
            digest, why = _tree_digest_result(root)
            if _digest_known(digest):
                return None
            version = _version_token(_tool_version(tool, root))
            hx = digest or why or "unreadable"
            return f"{tool} {version} {hx}"
    return f"{tool} - -"


def _format_unverified(parts: list[str]) -> str | None:
    if not parts:
        return None
    return TOOLCHAIN_UNVERIFIED + " " + " ".join(parts)


def _scan_toolchain_dotnet(
    env: dict[str, str], _roots: ScanRoots, runner_env: dict[str, str] | None, dotnet_bin: str | None,
) -> str | None:
    """Abstain unless the resolved ``dotnet`` file lives in a stock install tree.

    ``--list-sdks`` is not proof. A wrapper that execs the stock muxer resolves
    outside that tree, and a copied tree's root hash does not match.
    """
    binary = _resolve_dotnet(dotnet_bin, _tool_path("dotnet", env, runner_env))
    if binary is None:
        return None
    keys = ("DOTNET_ROOT", "DOTNET_ROOT_X64")
    pinned = _pinned_home(env, keys)
    root = _declared_install(env, keys, binary)
    if pinned is not None and root is None:
        parent = _parent_install(binary)
        parts: list[str] = []
        pin_part = _unverified_part("dotnet", pinned)
        parent_part = _unverified_part("dotnet", parent)
        if pin_part:
            parts.append(pin_part)
        if parent_part:
            parts.append(parent_part)
        if not parts:
            parts.append("dotnet outside -")
        return _format_unverified(parts)
    return _format_unverified([part] if (part := _unverified_part("dotnet", root)) else [])


def _scan_toolchain_jvm(env: dict[str, str], runner_env: dict[str, str] | None) -> str | None:
    path = _tool_path("junit", env, runner_env)
    child = _child_view("junit", env, runner_env)
    java_home = (child.get("JAVA_HOME") or "").strip()
    seen: list[tuple[str, Path]] = []
    if java_home:
        for name in ("java", "javac"):
            candidate = Path(java_home) / "bin" / name
            if candidate.is_file():
                seen.append((name, candidate))
    for name in ("java", "javac", "mvn", "gradle"):
        binary = _which(name, path)
        if binary is not None:
            seen.append((name, binary))
    homes = {
        "java": ("JAVA_HOME",),
        "javac": ("JAVA_HOME",),
        "mvn": ("MAVEN_HOME", "M2_HOME"),
        "gradle": ("GRADLE_HOME",),
    }
    parts: list[str] = []
    seen_roots: set[str] = set()

    def record(tool: str, root: Path | None) -> None:
        try:
            key = os.path.realpath(root) if root is not None else f"none:{tool}"
        except OSError:
            key = f"err:{tool}"
        if key in seen_roots:
            return
        part = _unverified_part(tool, root)
        seen_roots.add(key)
        if part:
            parts.append(part)

    for name, binary in seen:
        keys = homes[name]
        # The child home wins. A binary outside that tree is a wrapper even
        # when the binary's own parent is some other stock install.
        source = child if _pinned_home(child, keys) is not None else env
        pinned = _pinned_home(source, keys)
        if pinned is not None and not _path_inside(pinned, binary):
            parent = _parent_install(binary)
            pin_part = _unverified_part(name, pinned)
            parent_part = _unverified_part(name, parent)
            if pin_part:
                record(name, pinned)
            if parent_part:
                record(name, parent)
            if not pin_part and not parent_part:
                parts.append(f"{name} outside -")
            continue
        record(name, pinned if pinned is not None else _parent_install(binary))
    for key in ("MAVEN_HOME", "M2_HOME"):
        raw = (child.get(key) or env.get(key) or "").strip()
        if raw and Path(raw).is_dir():
            record("mvn", Path(raw))
    if java_home:
        home_path = Path(java_home)
        try:
            is_dir = home_path.is_dir()
        except OSError:
            is_dir = False
        if is_dir:
            record("java", home_path)
    return _format_unverified(parts)


def _scan_dotnet(
    repo: Path,
    env: dict[str, str],
    roots: ScanRoots,
    runner_env: dict[str, str] | None = None,
    dotnet_bin: str | None = None,
) -> str | None:
    hit = _unscrubbed_key("dotnet", env, runner_env)
    if hit:
        return hit
    hit = _scan_vcurrent(roots)
    if hit:
        return hit
    pairs = (
        (_CSHARP_DIRS[:2], "machine_preflight_msbuild_csharp_import_before"),
        (_CSHARP_DIRS[2:], "machine_preflight_msbuild_csharp_import_after"),
        (_COMMON_TARGETS_BEFORE, "machine_preflight_msbuild_common_import_before"),
        (_COMMON_TARGETS_AFTER, "machine_preflight_msbuild_common_import_after"),
        (_COMMON_PROPS_BEFORE, "machine_preflight_msbuild_common_props_import_before"),
        (_COMMON_PROPS_AFTER, "machine_preflight_msbuild_common_props_import_after"),
        (_CROSS_BEFORE, "machine_preflight_msbuild_cross_import_before"),
        (_CROSS_AFTER, "machine_preflight_msbuild_cross_import_after"),
    )
    for relatives, code in pairs:
        hit = _scan_import_pair(roots, relatives, code)
        if hit:
            return hit
    if _nuget_config_differs(roots):
        return "machine_preflight_nuget_config"
    if _repo_global_packages(repo):
        return "machine_preflight_nuget_relative_packages"
    if _parent_directory_build(repo):
        return "machine_preflight_directory_build"
    if _rsp_named(repo) or _rsp_beside(env, roots, runner_env, dotnet_bin):
        return RSP
    if _hashed_cache_tampered(_nuget_package_roots(roots), ".nupkg", ".sha512", _sha512_matches, ".nupkg.metadata"):
        return "machine_preflight_nuget_cache_tampered"
    return _scan_toolchain_dotnet(env, roots, runner_env, dotnet_bin)


def _tag(elem: ET.Element) -> str:
    return elem.tag.split("}")[-1].lower()


def _xml_root(path: Path) -> ET.Element | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        blob = path.read_bytes()[:1_000_000]
    except OSError:
        return None
    if blob.startswith(b"\xef\xbb\xbf"):
        blob = blob[3:]
    try:
        return ET.fromstring(blob)
    except ET.ParseError:
        return None


def _nuget_tree_differs(elem: ET.Element, parent: str) -> bool:
    tag = _tag(elem)
    if tag == "add" and parent == "packagesources":
        key = (elem.attrib.get("key") or "").strip().lower()
        value = (elem.attrib.get("value") or "").strip().rstrip("/")
        return key != "nuget.org" or value != _NUGET_ORG
    if tag in ("configuration", "packagesources"):
        return any(_nuget_tree_differs(child, tag) for child in list(elem))
    if tag in ("config", "disabledpackagesources", "activesource"):
        return bool(list(elem)) or bool((elem.text or "").strip())
    return True


def _nuget_file_differs(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        if not path.is_file():
            return False
    except OSError:
        return True
    root = _xml_root(path)
    if root is None or _tag(root) != "configuration":
        return True
    return _nuget_tree_differs(root, "")


def _nuget_dir_differs(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        if path.is_file():
            return _nuget_file_differs(path)
        if not path.is_dir():
            return False
        for child in path.iterdir():
            if child.is_symlink() or (child.is_file() and child.suffix.lower() == ".config" and _nuget_file_differs(child)):
                if child.is_symlink() or child.suffix.lower() == ".config":
                    return True
    except OSError:
        return True
    return False


def _nuget_config_differs(roots: ScanRoots) -> bool:
    names = ("NuGet.Config", "nuget.config")
    for home in _homes(roots):
        base = home / ".nuget" / "NuGet"
        for name in names:
            if _nuget_file_differs(base / name):
                return True
        config_dir = base / "config"
        try:
            children = list(config_dir.iterdir()) if config_dir.is_dir() and not config_dir.is_symlink() else []
        except OSError:
            return True
        for child in children:
            if child.suffix.lower() == ".config" and _nuget_file_differs(child):
                return True
    if roots.appdata is not None:
        for name in names:
            if _nuget_file_differs(roots.appdata / "NuGet" / name):
                return True
    if _nuget_dir_differs(roots.nuget_machine_dir):
        return True
    return any(_nuget_dir_differs(folder) for folder in roots.program_files_nuget)


def _exists_file(path: Path) -> bool:
    try:
        return path.is_symlink() or path.is_file()
    except OSError:
        return True


def _dir_has_any_file(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        if path.is_file():
            return True
        if not path.is_dir():
            return False
        return any(child.is_symlink() or child.is_file() for child in path.iterdir())
    except OSError:
        return True


def _repo_global_packages(repo: Path) -> bool:
    if not repo.is_dir():
        return False
    try:
        base = repo.resolve()
    except OSError:
        base = repo
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        current = Path(dirpath)
        dirnames[:] = [
            name for name in dirnames
            if name != ".git" and not (current / name).is_symlink()
        ]
        for name in filenames:
            if name.lower() != "nuget.config":
                continue
            path = current / name
            if path.is_symlink():
                continue
            if _config_sets_global_packages(path):
                return True
    return False


def _config_sets_global_packages(path: Path) -> bool:
    try:
        if path.stat().st_size > 1_000_000:
            blob = path.read_bytes()[:1_000_000]
        else:
            blob = path.read_bytes()
    except OSError:
        return False
    try:
        root = ET.fromstring(blob)
    except ET.ParseError:
        return False
    for elem in root.iter():
        tag = elem.tag.split("}")[-1].lower()
        if tag == "globalpackagesfolder":
            return True
        if tag == "add" and (elem.attrib.get("key") or "").lower() == "globalpackagesfolder":
            return True
    return False


def _parent_directory_build(repo: Path) -> bool:
    names = ("Directory.Build.props", "Directory.Build.targets")
    for parent in _ancestors(repo):
        for name in names:
            if _exists_file(parent / name):
                return True
    return False


def _ancestors(repo: Path) -> list[Path]:
    try:
        current = repo.resolve().parent
    except OSError:
        current = repo.parent
    found: list[Path] = []
    while True:
        found.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    return found


def _scan_jvm(
    repo: Path, env: dict[str, str], roots: ScanRoots, runner_env: dict[str, str] | None = None,
) -> str | None:
    hit = _unscrubbed_key("junit", env, runner_env)
    if hit:
        return hit
    if _gradle_user_init_dir(roots):
        return "machine_preflight_gradle_user_init"
    if _gradle_user_init_script(roots):
        return "machine_preflight_gradle_user_init_script"
    if roots.gradle_dist is not None and _gradle_dist_script(roots.gradle_dist / "init.d"):
        return "machine_preflight_gradle_dist_init"
    parent = _parent_settings(repo)
    if parent is not None:
        return parent
    if _exists_file(roots.mavenrc_system):
        return "machine_preflight_mavenrc_system"
    if _exists_file(roots.mavenrc_usr_local):
        return "machine_preflight_mavenrc_usr_local"
    if _user_mavenrc(roots):
        return "machine_preflight_mavenrc_user"
    if _user_maven_settings_differs(roots):
        return "machine_preflight_maven_user_settings"
    if _user_maven_toolchains_differs(roots, env):
        return "machine_preflight_maven_user_toolchains"
    if _user_gradle_properties(roots):
        return "machine_preflight_gradle_user_properties"
    if _maven_extensions(roots):
        return "machine_preflight_maven_extensions"
    if _mvn_dir(repo):
        return "machine_preflight_maven_mvn_dir"
    if _gradle_wrapper_untrusted(repo):
        return "machine_preflight_gradle_wrapper_url"
    if _hashed_cache_tampered(_maven_repo_roots(roots), ".jar", ".sha1", _sha1_matches, None):
        return "machine_preflight_maven_cache_tampered"
    return _scan_toolchain_jvm(env, runner_env)


def _maven_extensions(roots: ScanRoots) -> bool:
    for home in _homes(roots):
        if _exists_file(home / ".m2" / "extensions.xml"):
            return True
    return False


def _mvn_dir(repo: Path) -> bool:
    spots = [repo, *_ancestors(repo)]
    for spot in spots:
        path = spot / ".mvn"
        try:
            if path.is_symlink() or path.is_dir():
                return True
        except OSError:
            return True
    return False


def _wrapper_files(repo: Path) -> list[Path]:
    found: list[Path] = []
    try:
        base = repo.resolve()
    except OSError:
        base = repo
    if base.is_dir():
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            current = Path(dirpath)
            dirnames[:] = [name for name in dirnames if name != ".git" and not (current / name).is_symlink()]
            if "gradle-wrapper.properties" in filenames and _exists_file(current / "gradle-wrapper.properties"):
                found.append(current / "gradle-wrapper.properties")
    for parent in _ancestors(repo):
        candidate = parent / "gradle" / "wrapper" / "gradle-wrapper.properties"
        if _exists_file(candidate):
            found.append(candidate)
    return found


def _distribution_host(path: Path) -> str:
    try:
        if path.is_symlink() or not path.is_file():
            return ""
        text = path.read_text(encoding="utf-8", errors="replace")[:100_000]
    except OSError:
        return ""
    for line in text.splitlines():
        if not line.startswith("distributionUrl="):
            continue
        raw = line.split("=", 1)[1].strip().replace("\\:", ":").replace("\\\\", "\\")
        host = urlparse(raw).hostname or ""
        return host.lower()
    return ""


def _gradle_wrapper_untrusted(repo: Path) -> bool:
    for path in _wrapper_files(repo):
        if _distribution_host(path) not in _GRADLE_DIST_HOSTS:
            return True
    return False


def _gradle_homes(roots: ScanRoots) -> list[Path]:
    return [home / ".gradle" for home in _homes(roots)]


def _gradle_user_init_dir(roots: ScanRoots) -> bool:
    for home in _gradle_homes(roots):
        if _dir_has_any_file(home / "init.d"):
            return True
    return False


def _gradle_user_init_script(roots: ScanRoots) -> bool:
    for home in _gradle_homes(roots):
        for name in ("init.gradle", "init.gradle.kts"):
            if _exists_file(home / name):
                return True
    return False


def _gradle_dist_script(directory: Path) -> bool:
    """A distribution script is a hit. A stock readme.txt is not.

    A symlink directory is followed. A symlink whose name is a Gradle script
    is a hit. A symlink named readme.txt is not.
    """
    try:
        if not directory.exists() or not directory.is_dir():
            return False
        for child in directory.iterdir():
            if not (child.is_symlink() or child.is_file()):
                continue
            if child.name.lower().endswith(_GRADLE_DIST_SCRIPT):
                return True
    except OSError:
        return True
    return False


def _parent_settings(repo: Path) -> str | None:
    for parent in _ancestors(repo):
        for name in ("settings.gradle", "settings.gradle.kts"):
            path = parent / name
            if not _exists_file(path):
                continue
            detail = "machine_preflight_gradle_parent_settings"
            if _assigns_project_dir(path):
                return detail + " rootProject.projectDir"
            return detail
    return None


def _assigns_project_dir(path: Path) -> bool:
    try:
        if path.is_symlink() or not path.is_file():
            return False
        text = path.read_text(encoding="utf-8", errors="replace")[:200_000]
    except OSError:
        return False
    return "rootProject.projectDir" in text


def _user_mavenrc(roots: ScanRoots) -> bool:
    for home in _homes(roots):
        if _exists_file(home / ".mavenrc"):
            return True
    return False


def _stock_http_blocker(elem: ET.Element) -> bool:
    """Maven 3.8's global settings already block external HTTP with this mirror.

    A user file that only repeats it does not change the sandboxed run.
    """
    if _tag(elem) != "mirror":
        return False
    fields = {_tag(child): (child.text or "").strip() for child in list(elem)}
    return (
        fields.get("id") == "maven-default-http-blocker"
        and fields.get("mirrorof") == "external:http:*"
        and fields.get("url") == "http://0.0.0.0/"
        and fields.get("blocked", "").lower() == "true"
    )


def _setup_java_server(elem: ET.Element) -> bool:
    """The server block ``actions/setup-java`` writes. It does not select a repository.

    The username and password are ``${env.NAME}`` placeholders. A literal
    password, another server id, or an extra child is a different build.
    """
    if _tag(elem) != "server":
        return False
    fields: dict[str, str] = {}
    for child in list(elem):
        fields.setdefault(_tag(child), (child.text or "").strip())
    server_id = fields.get("id", "")
    if server_id == "github" and set(fields) <= {"id", "username", "password"}:
        return bool(_ENV_PLACEHOLDER.match(fields.get("username", ""))) and bool(
            _ENV_PLACEHOLDER.match(fields.get("password", ""))
        )
    if server_id == "gpg.passphrase" and set(fields) <= {"id", "passphrase"}:
        return bool(_ENV_PLACEHOLDER.match(fields.get("passphrase", "")))
    return False


def _job_jdk_toolchain(elem: ET.Element, java_home: str) -> bool:
    """A toolchain whose ``jdkHome`` is the job ``JAVA_HOME`` the sandbox already uses."""
    if _tag(elem) != "toolchain" or not java_home:
        return False
    kind = ""
    jdk_home = ""
    for child in list(elem):
        if _tag(child) == "type":
            kind = (child.text or "").strip().lower()
        elif _tag(child) == "configuration":
            for item in list(child):
                if _tag(item) == "jdkhome":
                    jdk_home = (item.text or "").strip()
    if kind not in ("", "jdk") or not jdk_home:
        return False
    try:
        return Path(jdk_home).resolve() == Path(java_home).resolve()
    except OSError:
        return False


def _user_maven_settings_differs(roots: ScanRoots) -> bool:
    return any(_settings_file_differs(home / ".m2" / "settings.xml") for home in _homes(roots))


def _settings_file_differs(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        if not path.is_file():
            return False
    except OSError:
        return True
    root = _xml_root(path)
    if root is None:
        return True
    return any(
        _tag(elem) in _MAVEN_BAD and not _stock_http_blocker(elem) and not _setup_java_server(elem)
        for elem in root.iter()
    )


def _user_maven_toolchains_differs(roots: ScanRoots, env: dict[str, str]) -> bool:
    java_home = env.get("JAVA_HOME") or ""
    return any(
        _toolchains_file_differs(home / ".m2" / "toolchains.xml", java_home) for home in _homes(roots)
    )


def _toolchains_file_differs(path: Path, java_home: str) -> bool:
    try:
        if path.is_symlink():
            return True
        if not path.is_file():
            return False
    except OSError:
        return True
    root = _xml_root(path)
    if root is None:
        return True
    return any(
        _tag(elem) == "toolchain" and not _job_jdk_toolchain(elem, java_home) for elem in root.iter()
    )


def _sha512_matches(path: Path, sig: Path) -> bool:
    try:
        raw = sig.read_text(encoding="utf-8", errors="replace").strip()
        digest = base64.b64encode(hashlib.sha512(path.read_bytes()).digest()).decode()
    except OSError:
        return False
    return raw == digest


def _sha1_matches(path: Path, sig: Path) -> bool:
    try:
        parts = sig.read_text(encoding="utf-8", errors="replace").strip().split()
        if not parts or len(parts[0]) != 40:
            return False
        digest = hashlib.sha1(path.read_bytes()).hexdigest()
    except OSError:
        return False
    return digest == parts[0].lower()


def _newer_than(directory: Path, marker: Path) -> bool:
    try:
        stamp = marker.stat().st_mtime
    except OSError:
        return False
    try:
        for child in directory.rglob("*"):
            if child.is_symlink() or not child.is_file():
                continue
            if child.stat().st_mtime > stamp + 2.0:
                return True
    except OSError:
        return True
    return False


def _hashed_cache_tampered(roots: list[Path], suffix: str, sig_ext: str, matches, marker: str | None) -> bool:
    """Hash up to ``_CACHE_CAP`` packages. A larger cache is not fully checked."""
    seen = 0
    for root in roots:
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            current = Path(dirpath)
            dirnames[:] = [name for name in dirnames if not (current / name).is_symlink()]
            for name in filenames:
                if not name.endswith(suffix):
                    continue
                path = current / name
                sig = current / (name + sig_ext)
                if not sig.is_file():
                    continue
                seen += 1
                if seen > _CACHE_CAP:
                    return False
                try:
                    if path.is_symlink():
                        return True
                    if path.stat().st_size > _CACHE_MAX_BYTES:
                        continue
                except OSError:
                    return True
                if not matches(path, sig):
                    return True
                if marker is not None:
                    mark = current / marker
                    if mark.is_file() and _newer_than(current, mark):
                        return True
    return False


def _nuget_package_roots(roots: ScanRoots) -> list[Path]:
    return [home / ".nuget" / "packages" for home in _homes(roots)]


def _maven_repo_roots(roots: ScanRoots) -> list[Path]:
    return [home / ".m2" / "repository" for home in _homes(roots)]


def _user_gradle_properties(roots: ScanRoots) -> bool:
    for home in _gradle_homes(roots):
        if _exists_file(home / "gradle.properties"):
            return True
    return False


# Kept so a future caller can see the addition list next to the scanner.
ADDITION_CODES = (
    "machine_preflight_msbuild_cross_import_before",
    "machine_preflight_msbuild_cross_import_after",
    "machine_preflight_directory_build",
    "machine_preflight_nuget_cache_tampered",
    "machine_preflight_maven_user_settings",
    "machine_preflight_maven_user_toolchains",
    "machine_preflight_gradle_user_properties",
    "machine_preflight_maven_cache_tampered",
    ENV_UNSCRUBBED,
    VCURRENT,
    RSP,
    TOOLCHAIN_UNVERIFIED,
    "machine_preflight_maven_extensions",
    "machine_preflight_maven_mvn_dir",
    "machine_preflight_gradle_wrapper_url",
)
