"""GitHub URL helpers. GHES-safe: honor GITHUB_SERVER_URL and GITHUB_API_URL."""

from __future__ import annotations

import os
import re
from urllib.parse import urlparse

_SHA = re.compile(r"^[0-9a-fA-F]{7,40}$")
_BRANCH = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")


def server_url() -> str:
    raw = (os.environ.get("GITHUB_SERVER_URL") or "https://github.com").strip()
    return raw.rstrip("/") or "https://github.com"


def api_url() -> str:
    raw = (os.environ.get("GITHUB_API_URL") or "https://api.github.com").strip()
    return raw.rstrip("/") or "https://api.github.com"


def server_host(url: str | None = None) -> str:
    return (urlparse(url or server_url()).hostname or "").lower()


def safe_github_url(url: str | None, *, server: str | None = None) -> str:
    """Keep https links whose host is this GitHub server (or github.com)."""
    if not url or not isinstance(url, str):
        return ""
    if any(c in url for c in (" ", "\n", "\r", "\t", "(", ")", "<", ">", "`")):
        return ""
    try:
        parsed = urlparse(url)
    except Exception:
        return ""
    base = server or server_url()
    base_parsed = urlparse(base)
    host = (parsed.hostname or "").lower()
    allowed = {server_host(base), "github.com", "www.github.com"}
    allowed.discard("")
    if parsed.username or parsed.password or host not in allowed:
        return ""
    if parsed.scheme == "https":
        pass
    elif (
        parsed.scheme == "http"
        and host == server_host(base)
        and base_parsed.scheme == "http"
    ):
        pass
    else:
        return ""
    if parsed.port not in (None, 443):
        return ""
    return url


def valid_sha(sha: str | None) -> str:
    if not sha or not isinstance(sha, str):
        return ""
    s = sha.strip()
    return s if _SHA.match(s) else ""


def valid_branch(name: str | None) -> str:
    if not name or not isinstance(name, str):
        return ""
    s = name.strip()
    if not _BRANCH.match(s) or ".." in s.split("/"):
        return ""
    return s


def commit_url(server: str, owner: str, repo: str, sha: str) -> str:
    sha = valid_sha(sha)
    if not sha or not owner or not repo:
        return ""
    return f"{server}/{owner}/{repo}/commit/{sha}"


def pr_url(server: str, owner: str, repo: str, number: int) -> str:
    if not owner or not repo or not isinstance(number, int) or number <= 0:
        return ""
    return f"{server}/{owner}/{repo}/pull/{number}"


def run_url(server: str, owner: str, repo: str, run_id: int) -> str:
    if not owner or not repo or not isinstance(run_id, int) or run_id <= 0:
        return ""
    return f"{server}/{owner}/{repo}/actions/runs/{run_id}"


def job_url(server: str, owner: str, repo: str, run_id: int, job_id: int) -> str:
    base = run_url(server, owner, repo, run_id)
    if not base or not isinstance(job_id, int) or job_id <= 0:
        return ""
    return f"{base}/job/{job_id}"


def blob_url(server: str, owner: str, repo: str, sha: str, path: str, line: int) -> str:
    sha = valid_sha(sha)
    if not sha or not path or not isinstance(line, int) or line < 1 or line > 100_000:
        return ""
    if path.startswith("/") or ".." in path.split("/"):
        return ""
    return f"{server}/{owner}/{repo}/blob/{sha}/{path}#L{line}"
