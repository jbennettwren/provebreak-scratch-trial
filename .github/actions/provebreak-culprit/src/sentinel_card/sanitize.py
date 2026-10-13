"""Input sanitization for untrusted repo / API content."""

from __future__ import annotations

import re
from pathlib import Path
from pathlib import PurePosixPath
from urllib.parse import urlparse

from sentinel_card.redact import redact_secrets

# Strip ALL controls including \t \n \r (workflow-command / GITHUB_ENV injection)
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_WORKFLOW_CMD = re.compile(r"::[\w-]+(?:=[^:\n]*)?::?")
_MIDWORD_COLONS = re.compile(r"(?<=[\w\])]): :(?=[\w\[])")
_HTML_TAG = re.compile(r"(?i)</?[a-z][^>\n]{0,200}>?")
_SLACK_PATH = re.compile(r"^/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+$")
_MAX_PATH = 512
_MAX_MSG = 500
_MAX_NAME = 128
_MAX_FILES = 500
_MAX_CODEOWNERS_BYTES = 256_000
_MAX_CODEOWNERS_LINES = 2_000
_MAX_COMMITS = 50
_SLACK_HOSTS = frozenset({"hooks.slack.com"})


def scrub_text(
    text: str | bytes | None, *, max_len: int = _MAX_MSG, flatten_colons: bool = True
) -> str:
    if not text:
        return ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    # Redact secret VALUES first, while newlines still delimit PEM blocks.
    s = redact_secrets(str(text))
    s = _CTRL.sub("", s)
    s = _WORKFLOW_CMD.sub("[CMD]", s)
    if flatten_colons:
        s = s.replace("::", ": :")
    # Keep a path arrow readable. Every other angle bracket is still removed.
    arrow = s.replace("->", "\ue000")
    s = _HTML_TAG.sub("", arrow)
    s = s.replace("<", "").replace(">", "")
    s = s.replace("\ue000", "->")
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return s


def sanitize_path(path: str | None) -> str | None:
    if path is None:
        return None
    raw = _CTRL.sub("", str(path)).strip().replace("\\", "/")
    if not raw or len(raw) > _MAX_PATH:
        return None
    if raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw):
        return None
    if "://" in raw or raw.startswith("~"):
        return None
    parts = PurePosixPath(raw).parts
    if ".." in parts:
        return None
    clean = str(PurePosixPath(*[p for p in parts if p not in ("", ".")]))
    if not clean or clean.startswith("../"):
        return None
    return clean


def sanitize_paths(paths: list[str] | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for p in paths or []:
        c = sanitize_path(p)
        if c and c not in seen:
            seen.add(c)
            out.append(c)
        if len(out) >= _MAX_FILES:
            break
    return out


def sanitize_login(name: str | None) -> str:
    """GitHub login / display name for plain (non-mention) display."""
    s = scrub_text(name, max_len=_MAX_NAME).strip()
    s = re.sub(r"[<>\"`]", "", s)
    s = s.lstrip("@").strip()
    return s[:_MAX_NAME] if s else "unknown"


def sanitize_commit_message(msg: str | None) -> str:
    return scrub_text(msg, max_len=_MAX_MSG)


def plain(text: str | None, *, max_len: int = _MAX_MSG) -> str:
    """Untrusted text safe to place in GitHub markdown (no mentions, no HTML).

    v5: this is the single, strictest markdown neutralizer. escape_markdown_cell /
    escape_markdown_text (intel) and the v4 renderer all route through it.
    """
    s = scrub_text(text, max_len=max_len)
    # Workflow commands only fire at the start of a line, and scrub_text already turned
    # "::cmd::" forms into [CMD]. Put back "::" when it's inside a token (test ids like
    # tests/x.py::test_y) so the card doesn't show "x.py: :test_y".
    s = _MIDWORD_COLONS.sub("::", s)
    s = s.replace("|", "/").replace("[", "(").replace("]", ")")
    s = s.replace("@", "(at)")
    s = s.replace("`", "'").replace("*", "")
    s = s.replace("_", "\\_")
    # 5.2.0 (NB3): GFM autolinks ("https://x", "www.x") are links too: make them inert.
    s = _SCHEME.sub(lambda m: m.group(1) + _WJ, s)
    if s.startswith("#"):
        s = "\\" + s
    return s


def escape_markdown_cell(text: str | None, *, max_len: int = _MAX_NAME) -> str:
    """Neutralize markdown / HTML / @mention injection in Job Summary cells."""
    return plain(text, max_len=max_len)


def escape_markdown_text(text: str | None, *, max_len: int = _MAX_MSG) -> str:
    """Same neutralization as a table cell, for longer single-line card text."""
    return plain(text, max_len=max_len)


def code_text(text: str | None, *, max_len: int = _MAX_MSG) -> str:
    """Sanitized text for a markdown code span.

    Allowlisted test ids and paths keep ``::`` and underscores. Anything else
    is scrubbed, and backticks cannot break out of the span. Underscores are
    not backslash-escaped: inside a code span that escape would show up.
    """
    if not text:
        return ""
    raw = str(text).strip()
    from sentinel_card.reproduce import allow_test_token

    token = allow_test_token(raw)
    if token:
        return token[:max_len]
    s = scrub_text(raw, max_len=max_len)
    return s.replace("`", "'").replace("|", "/")


# ----------------------------------------------------------------------------- code spans
# NB3 (5.2.0): the ONE helper for every test id and every attacker-controlled string that is
# shown as code on the card, in the PR comment (same markdown) and in Slack.
_WJ = "\u2060"  # WORD JOINER: invisible, breaks @mention / link / image / autolink syntax
_MENTION = re.compile(r"@(?=[A-Za-z0-9_-])")
_SCHEME = re.compile(r"(?i)\b(https?|ftp|mailto|javascript|data|file|www)(?=[:.])")


def _defang(s: str) -> str:
    """Make @mentions, links, images and autolinks inert even outside a code span."""
    s = _MENTION.sub("@" + _WJ, s)
    s = s.replace("](", "]" + _WJ + "(").replace("![", "!" + _WJ + "[").replace("<", "<" + _WJ)
    s = _SCHEME.sub(lambda m: m.group(1) + _WJ, s)
    return s


def code_span(text: str | None, *, max_len: int = 300, in_table: bool = False, defang: bool = True) -> str:
    """Return a COMPLETE, safe inline code span (delimiters included) for GitHub markdown.

    * secret values are redacted, control characters (incl. newlines) become spaces;
    * the backtick fence is one longer than the longest backtick run inside, so the
      content can never close the span (CommonMark 6.1); content that starts or ends
      with a backtick is padded with one space;
    * ``@mention``, ``[link](…)``, ``![image](…)``, raw ``<tag>`` and URL schemes get an
      invisible WORD JOINER so they stay inert even if a renderer ignores the span
      (``defang=False`` only for copy-paste commands built from allowlisted tokens);
    * ``>``, ``::``, ``_`` and ``*`` stay literal (no escaping inside code);
    * ``in_table=True`` escapes ``|`` (a GFM table splits cells even inside code).

    Empty input gives an empty string (callers decide on a placeholder).
    """
    if text is None:
        return ""
    s = redact_secrets(str(text))
    s = _CTRL.sub(" ", s).strip()
    if not s:
        return ""
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    if defang:
        s = _defang(s)
    if in_table:
        s = s.replace("|", "\\|")
    runs = [len(m.group(0)) for m in re.finditer(r"`+", s)]
    fence = "`" * ((max(runs) + 1) if runs else 1)
    pad = " " if (s.startswith("`") or s.endswith("`")) else ""
    return f"{fence}{pad}{s}{pad}{fence}"


def slack_code_span(text: str | None, *, max_len: int = 300) -> str:
    """Slack mrkdwn has no fence-length rule: drop backticks, escape &<>, defang mentions."""
    if text is None:
        return ""
    s = redact_secrets(str(text))
    s = _CTRL.sub(" ", s).strip().replace("`", "\u02cb")
    if not s:
        return ""
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = _MENTION.sub("@" + _WJ, s)
    s = _SCHEME.sub(lambda m: m.group(1) + _WJ, s)
    return f"`{s}`"


_INLINE_CMD = re.compile(r"(?<![\w\])])::[A-Za-z][\w-]*(?:\s[^:\n]*)?::")
_CODE_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def stored_log_tail(text: str | bytes | None, *, max_len: int = 200_000) -> str:
    """Log text stored on the card artifact for the reproduce line and a Playwright error match.

    The bisect job downloads that artifact and then runs repository code, so a
    token in the failed job log must not be sitting in the file. Secret values
    are redacted first, then the tail is kept. Pytest node ids keep ``::``.
    A workflow command is replaced. This is not the rendered excerpt.
    """
    if not text:
        return ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    body = redact_secrets(str(text).replace("\r\n", "\n").replace("\r", "\n"))
    if len(body) > max_len:
        body = body[-max_len:]
    lines: list[str] = []
    for raw in body.split("\n"):
        s = _CODE_CTRL.sub("", raw.replace("\t", "    "))
        s = re.sub(r"^(\s*)::", r"\1[CMD]", s)
        s = _INLINE_CMD.sub("[CMD]", s)
        lines.append(s)
    return "\n".join(lines)


def scrub_block(text: str | bytes | None, *, max_len: int = 2000, max_lines: int = 20) -> str:
    """Scrub a multi-line excerpt for display INSIDE a code fence.

    Secret values are redacted (block-aware, so PEM bodies go too), control
    characters are dropped and a workflow command at the start of a line is
    neutralized. No markdown escaping: the renderer puts the result in a fence
    whose length the content cannot match (``code_fence``), where ``_``, ``*``,
    ``@`` and HTML are inert.
    """
    if not text:
        return ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    body = redact_secrets(str(text).replace("\r\n", "\n").replace("\r", "\n"))
    lines: list[str] = []
    total = 0
    for raw in body.split("\n"):
        s = _CODE_CTRL.sub("", raw.replace("\t", "    ")).rstrip()
        s = re.sub(r"^(\s*)::", r"\1[CMD]", s)
        s = _INLINE_CMD.sub("[CMD]", s)  # "::name::" not glued to a word (test ids keep "::")
        if not s.strip():
            continue
        if len(s) > 240:
            s = s[:239] + "…"
        lines.append(s)
        total += len(s)
        if len(lines) >= max_lines or total >= max_len:
            break
    return "\n".join(lines)


def code_fence(text: str, *, info: str = "text") -> list[str]:
    """Fence ``text`` with a backtick run longer than any run inside it.

    A fence can only be closed by a backtick run at least as long as the opener,
    so the content cannot break out, whatever it contains.
    """
    runs = [len(m.group(0)) for m in re.finditer(r"`+", text or "")]
    fence = "`" * max(3, (max(runs) + 1) if runs else 3)
    return [fence + info, *(text or "").split("\n"), fence]


def safe_slack_webhook(url: str | None) -> str | None:
    """Allow only canonical Slack incoming-webhook URLs.

    Rejects other hosts, userinfo, non-443 ports, queries, fragments, and
    any path that is not ``/services/T…/B…/SECRET``. Returns a rebuilt URL
    so odd encodings are not forwarded.
    """
    if not url or not isinstance(url, str):
        return None
    if url != url.strip() or any(ch.isspace() or ord(ch) < 32 for ch in url):
        return None
    try:
        parsed = urlparse(url)
    except Exception:
        return None
    if parsed.scheme != "https":
        return None
    if parsed.username or parsed.password:
        return None
    host = (parsed.hostname or "").lower()
    if host not in _SLACK_HOSTS:
        return None
    if parsed.port not in (None, 443):
        return None
    if parsed.query or parsed.fragment:
        return None
    if not _SLACK_PATH.match(parsed.path or ""):
        return None
    return f"https://hooks.slack.com{parsed.path}"


def redact_email(email: str | None) -> str:
    if not email:
        return ""
    s = scrub_text(email, max_len=200)
    if "@" not in s:
        return ""
    _, _, domain = s.partition("@")
    return f"redacted@{domain}" if domain else ""


def safe_repo_path(repo: Path | str | None) -> Path | None:
    if repo is None:
        return None
    try:
        p = Path(repo).resolve()
    except (OSError, RuntimeError):
        return None
    if not p.exists() or not p.is_dir():
        return None
    return p


def clamp_int(n: int | str | None, *, default: int, lo: int, hi: int) -> int:
    try:
        v = int(n) if n is not None else default
    except (TypeError, ValueError):
        v = default
    return max(lo, min(hi, v))
