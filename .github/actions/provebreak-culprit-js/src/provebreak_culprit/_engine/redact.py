"""Value-based secret redaction for untrusted log text. Pure stdlib."""

from __future__ import annotations

import math
import os
import re
from collections.abc import Mapping

MARK = "[REDACTED]"
PEM_MARK = "[REDACTED PRIVATE KEY]"

# ---------------------------------------------------------------- known token formats
_TOKEN_FORMATS = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    r"gh[pousr]_[A-Za-z0-9]{6,}"                      # ghp_/gho_/ghs_/ghu_/ghr_, including short
    r"|github_pat_[A-Za-z0-9_]{6,}"                   # GitHub fine-grained PAT
    r"|xox[a-z]-[A-Za-z0-9-]{8,}"                      # Slack xox* tokens
    r"|xapp-\d-[A-Za-z0-9-]{10,}"                      # Slack app-level token
    r"|(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|APKA)[0-9A-Z]{16}"  # AWS key ids
    r"|sk-ant-[A-Za-z0-9_-]{16,}"                      # Anthropic
    r"|sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"  # OpenAI
    r"|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,}"        # Stripe secret / restricted, including short
    r"|whsec_[A-Za-z0-9]{8,}"                          # Stripe webhook secret
    r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"  # JWT
    r"|AIza[0-9A-Za-z_-]{35}"                          # Google API key
    r"|npm_[A-Za-z0-9]{16,}"                           # npm classic and shorter granular tokens
    r"|glpat-[A-Za-z0-9_-]{20,}"                       # GitLab PAT
    r")"
)
_SLACK_HOOK = re.compile(r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]+")
# 5.2.0: Discord webhooks, signed-URL signatures, 40-char AWS-style secret keys.
_DISCORD_HOOK = re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+")
_URL_SIG = re.compile(
    r"(?i)([?&](?:sig|signature|x-amz-signature|x-amz-security-token|x-amz-credential|x-goog-signature|x-goog-credential)=)([^&\s\"'#<>]+)"
)
_AWS_SECRET = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])")

# ---------------------------------------------------------------- URL userinfo
# password may contain "/" (5.2.0) but "host:8080/path@x" (a port) is not userinfo
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^@\s/]+|(?!\d+/)[^@\s]{1,200}?)@")

# ---------------------------------------------------------------- headers / bearer
_AUTH_HEADER = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])((?:proxy-)?authorization|cookie|set-cookie|x-api-key|x-auth-token)"
    r"(\s*[:=]\s*)([^\n]+)"
)
_BEARER = re.compile(r"(?i)\b(bearer|basic|token)(\s+)([A-Za-z0-9._~+/=-]{12,})")

# ---------------------------------------------------------------- PEM
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
_PEM_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
_PEM_INLINE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)",
    re.S,
)
_B64_LINE = re.compile(r"^(?:\d{4}-\d{2}-\d{2}T[\d:.]+Z ?)?\s*(?:E\s+)?(?:[A-Za-z0-9+/=]{4,}|(?:Proc-Type|DEK-Info|Comment|Version):\s.*)\s*$")

# ---------------------------------------------------------------- KEY=value
_KV = re.compile(
    r"(?<![A-Za-z0-9_.\-])"
    r"(?P<q>[\"']?)(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,80})(?P=q)"
    r"(?P<sep>[ \t]*(?:=(?!=)|:=(?!=)|:(?![:=]))[ \t]*)"  # 5.2.1: Go ":=" too
    r"(?P<val>\$\{\{[^}\n]*\}\}|\"[^\"\n]*\"|'[^'\n]*'|[^\s,;'\"})\]]+)"
)
# 5.2.0: "--password=hunter2", "-p=x"; "curl -u user:pass" / "--user user:pass"
_CLI_EQ = re.compile(r"(?<![A-Za-z0-9_])(--?(?P<key>[A-Za-z][A-Za-z0-9_-]{1,40}))=(?P<val>[^\s]+)")
_CURL_USER = re.compile(
    r"(?<![A-Za-z0-9_-])(-u|--user|--proxy-user)(\s+|=)(?P<q>['\"]?)(?P<user>[^\s:'\"]+):(?P<pw>[^\s'\"]+)(?P=q)"
)
_SAY_SECRET = re.compile(r"(?i)(?<![A-Za-z])(password|passwd|passphrase|secret|token|api[_-]?key)(\s+)(\"[^\"\n]{3,}\"|'[^'\n]{3,}')")
_CLI_FLAG = re.compile(r"(?<![A-Za-z0-9_])(--?(?P<key>[A-Za-z][A-Za-z0-9_-]{1,40}))([ \t]+)(?P<val>[^\s-][^\s]*)")

_SECRET_LAST = frozenset({
    "secret", "secrets", "token", "password", "passwd", "passphrase", "apikey", "apitoken",
    "accesstoken", "authtoken", "refreshtoken", "idtoken", "secretkey", "privatekey",
    "accesskey", "credential", "credentials", "creds", "auth", "authorization", "cookie",
    "webhook", "pat", "dsn",
})
_BIGRAMS = frozenset({
    ("api", "key"), ("access", "key"), ("secret", "key"), ("private", "key"), ("signing", "key"),
    ("encryption", "key"), ("master", "key"), ("account", "key"), ("session", "id"),
    ("session", "key"), ("session", "token"), ("client", "secret"), ("webhook", "url"),
    ("api", "secret"), ("app", "secret"), ("app", "key"), ("license", "key"),
})
_PASSWORD_WORDS = frozenset({"password", "passwd", "passphrase", "pwd"})
_PASSWORD_SUFFIXES = ("password", "passwd", "passphrase")
_VALUE_SUFFIX = frozenset({"value", "val", "str", "string", "b64", "base64", "hex", "raw",
                           "enc", "encoded", "plain", "plaintext", "literal", "env"})
_BENIGN_VALUES = frozenset({"none", "null", "nil", "true", "false", "undefined", "yes", "no",
                            "on", "off", "redacted", "***", "xxx", "xxxx", "...", "…", "-", "_"})


def _components(key: str) -> list[str]:
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", key)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    return [p for p in re.split(r"[_.\-\s]+", s.lower()) if p]


def secret_key_name(key: str) -> bool:
    """True when a key NAME looks like it holds a secret (value should be hidden)."""
    comps = _components(key or "")
    while len(comps) > 1 and comps[-1] in _VALUE_SUFFIX:
        comps.pop()
    if not comps:
        return False
    if comps == ["key"]:
        return True  # a bare KEY=... env name; primary_key and KeyError stay out
    if comps[-1] in _SECRET_LAST:
        return True
    if comps[-1].endswith(_PASSWORD_SUFFIXES):
        return True  # 5.2.1: PGPASSWORD, MYSQLPWD-style glued names (…password / …passwd)
    return len(comps) >= 2 and (comps[-2], comps[-1]) in _BIGRAMS


_TYPE_NAMES = frozenset({"str", "string", "int", "bytes", "bool", "float", "any", "object", "optional",
                         "secretstr", "secret", "text", "varchar", "char", "number", "boolean"})


def _benign_value(raw: str, strict: bool = False) -> bool:
    v = raw.strip()
    quoted = len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'"
    inner = v[1:-1].strip() if quoted else v
    low = inner.lower()
    if not inner or low in _BENIGN_VALUES or inner.startswith("[REDACTED"):
        return True
    if set(inner) <= set("*xX•.-_ ") or inner.startswith("<") and inner.endswith(">"):
        return True
    if re.fullmatch(r"\$\{\{.*\}\}|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%\(\w+\)s|\{\w*\}", inner):
        return True  # placeholders / env references
    if re.fullmatch(r"\d{1,6}", inner):
        return True
    if quoted:
        return False
    # unquoted code: attribute paths, calls, subscripts, plain lowercase identifiers
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+(?:\(.*)?", inner):
        return True
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*[\(\[].*", inner):
        return True
    if inner.lower() in _TYPE_NAMES:
        return True  # "password: str" type annotations
    if not strict and re.fullmatch(r"[a-z_]+", inner):
        return True  # "config.password = hunter" in code: an identifier, not a value
    return False


def _strict_kv(key: str, sep: str) -> bool:
    """Shell/env/YAML-style assignments: a bare lowercase word is still a value.

    ``DB_PASSWORD=letmein`` (UPPERCASE key), ``password=letmein`` (``=`` without
    spaces), ``client_secret: hunter`` (``:``) -> strict. ``config.password = hunter``
    (spaced ``=``, lowercase key: code) -> identifier rule applies.
    """
    letters = [c for c in key if c.isalpha()]
    if letters and all(c.isupper() for c in letters):
        return True
    st = sep.strip()
    if st == ":":
        return True
    return st == "=" and sep == "="


def _password_assignment(key: str, sep: str, val: str) -> bool:
    """5.2.1: ``config.password = hunter`` / ``x.password = letmein``: a plain assignment of a
    bare word of 6+ letters to a *password*-named attribute is treated as a value, unless the
    word itself names a password variable (``self.password = password``)."""
    comps = _components(key)
    if not comps or not (comps[-1] in _PASSWORD_WORDS or comps[-1].endswith(_PASSWORD_SUFFIXES)):
        return False
    if sep.strip() not in ("=", ":="):
        return False
    v = val.strip()
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{5,}", v):
        return False
    low = v.lower()
    return not any(w in low for w in ("pass", "pwd", "secret", "cred"))


def _kv_sub(m: re.Match) -> str:
    key, val = m.group("key"), m.group("val")
    strict = _strict_kv(key, m.group("sep")) or _password_assignment(key, m.group("sep"), val)
    if strict and m.group("sep") == "=" and not key.isupper():
        prev = m.string[max(0, m.start() - 2): m.start()].rstrip(" ")
        if prev.endswith(("(", ",")):
            strict = False  # f(token=token, password=None): keyword arguments in code
    if not secret_key_name(key) or _benign_value(val, strict=strict):
        return m.group(0)
    q = val[0] if val[:1] in ("'", '"') and val[-1:] == val[:1] and len(val) >= 2 else ""
    return f"{m.group('q')}{key}{m.group('q')}{m.group('sep')}{q}{MARK}{q}"


def _cli_eq_sub(m: re.Match) -> str:
    if not secret_key_name(m.group("key")) or _benign_value(m.group("val"), strict=True):
        return m.group(0)
    return f"{m.group(1)}={MARK}"


def _curl_user_sub(m: re.Match) -> str:
    pw = m.group("pw")
    if pw.startswith("[REDACTED") or re.fullmatch(r"\d+", pw) or pw.startswith("$"):
        return m.group(0)  # "-u 1000:1000" (docker uid:gid), "$PASS" references
    q = m.group("q")
    return f"{m.group(1)}{m.group(2)}{q}{m.group('user')}:{MARK}{q}"


def _apply_aws_secret(text: str) -> str:
    """40-character AWS secret access keys, including single-case and letter-only.

    A 40-hex string is a commit SHA and is kept. A CamelCase ``Test...`` name of
    40 letters is kept, and so is any token inside a test id or a file path.
    """
    spans = _protected_spans(text)

    def sub(m: re.Match) -> str:
        tok = m.group(0)
        if re.fullmatch(r"[0-9a-fA-F]{40}", tok):
            return tok
        if _inside(m.start(), m.end(), spans):
            return tok
        if re.fullmatch(r"Test[A-Z][A-Za-z0-9_]*", tok):
            return tok
        if len(set(tok)) < 8 or _entropy(tok) < 3.5:
            return tok
        return MARK

    return _AWS_SECRET.sub(sub, text)


def _cli_sub(m: re.Match) -> str:
    if not secret_key_name(m.group("key")) or _benign_value(m.group("val")):
        return m.group(0)
    return f"{m.group(1)}{m.group(3)}{MARK}"


def _header_sub(m: re.Match) -> str:
    if _benign_value(m.group(3)):
        return m.group(0)
    return f"{m.group(1)}{m.group(2)}{MARK}"


# ---------------------------------------------------------------- entropy near names
_NEAR_WORD = re.compile(
    r"(?i)(?<![a-z])(secret|token|password|passwd|passphrase|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|credentials?|auth|bearer)(?![a-z])"
)
_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/=_\-])[A-Za-z0-9+/=_\-]{20,}(?![A-Za-z0-9+/=_\-])")


def _entropy(s: str) -> float:
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(s))
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def high_entropy(s: str) -> bool:
    classes = sum(bool(re.search(p, s)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
    if classes < 2 or len(set(s)) < 10:
        return False
    return _entropy(s) >= 3.5


# Standalone high-entropy tokens. A digit and both letter cases are required.
# Hex SHAs, test ids (including a top-level Go TestName), and file paths are
# kept. A letter-only string is not a standalone secret.
_SHA_SPAN = re.compile(
    r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40})(?![0-9a-fA-F])"
)
_TEST_ID_SPAN = re.compile(
    r"(?<![\w./\\:-])(?:"
    r"[\w.\\/-]+\.py(?:::[\w.\[\]-]+)+"
    r"|[\w.\\/-]+\.(?:spec|test)\.[cm]?[jt]sx?(?:[ \t]*[›>][ \t]*[^\n]+)?"
    r"|\bTest[A-Z][A-Za-z0-9_]*(?:/[A-Za-z0-9_]+)*"
    r")"
)
_PATH_SPAN = re.compile(
    r"(?<![\w./\\-])(?:"
    r"(?:\.{0,2}/|/)(?:[\w.-]+/)*[\w.-]+\.[A-Za-z0-9]{1,8}"
    r"|(?:[\w.-]+/){1,}[\w.-]+\.[A-Za-z0-9]{1,8}"
    r")"
)
_ENTROPY_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_=-]{20,}(?![A-Za-z0-9+/_=-])")


def _protected_spans(line: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for pattern in (_SHA_SPAN, _TEST_ID_SPAN, _PATH_SPAN):
        spans.extend((match.start(), match.end()) for match in pattern.finditer(line))
    return spans


def _inside(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(span_start <= start and end <= span_end for span_start, span_end in spans)


def standalone_secret(token: str) -> bool:
    """True for a high-entropy secret that has a digit and is not a hex SHA.

    A letter-only string is not a standalone secret. That keeps a long
    CamelCase name such as ``TestCompactionFailsBoundaryCheck``.
    """
    if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", token or ""):
        return False
    if len(token) < 20:
        return False
    has_lower = bool(re.search(r"[a-z]", token))
    has_upper = bool(re.search(r"[A-Z]", token))
    has_digit = bool(re.search(r"\d", token))
    if not (has_lower and has_upper and has_digit):
        return False
    if len(set(token)) < 8 or _entropy(token) < 3.5:
        return False
    return True


def _standalone_entropy_line(line: str) -> str:
    spans = _protected_spans(line)
    out: list[str] = []
    last = 0
    for match in _ENTROPY_CANDIDATE.finditer(line):
        token = match.group(0)
        if _inside(match.start(), match.end(), spans) or not standalone_secret(token):
            continue
        out.append(line[last: match.start()])
        out.append(MARK)
        last = match.end()
    out.append(line[last:])
    return "".join(out)


def _entropy_line(line: str) -> str:
    if not _NEAR_WORD.search(line):
        return line
    spans = _protected_spans(line)
    out: list[str] = []
    last = 0
    for m in _CANDIDATE.finditer(line):
        tok = m.group(0)
        if _inside(m.start(), m.end(), spans):
            continue
        if MARK in line[max(0, m.start() - 1): m.end() + 1] or not high_entropy(tok):
            continue
        window = line[max(0, m.start() - 40): m.start()]
        if not _NEAR_WORD.search(window):
            continue
        out.append(line[last: m.start()])
        out.append(MARK)
        last = m.end()
    out.append(line[last:])
    return "".join(out)


# ---------------------------------------------------------------- PEM (line based)
def _redact_pem(text: str) -> str:
    if "PRIVATE KEY" not in text:
        return text
    if "\n" not in text:
        return _PEM_INLINE.sub(PEM_MARK, text)
    out: list[str] = []
    in_pem = False
    for line in text.split("\n"):
        if in_pem:
            if _PEM_END.search(line):
                in_pem = False
                rest = line[_PEM_END.search(line).end():]
                if rest.strip():
                    out.append(rest)
                continue
            if _B64_LINE.match(line):
                continue  # key material (or PEM headers) without an END line yet
            tail = re.search(r"[A-Za-z0-9+/=]{16,}\s*$", line)
            if tail:
                out.append(line[: tail.start()] + MARK)  # "label: <key material>"
                continue
            in_pem = False
        m = _PEM_BEGIN.search(line)
        if m:
            end = _PEM_END.search(line, m.end())
            if end:
                out.append(line[: m.start()] + PEM_MARK + line[end.end():])
            else:
                out.append(line[: m.start()] + PEM_MARK)
                in_pem = True
            continue
        out.append(line)
    return "\n".join(out)


# ANSI CSI / OSC sequences. A colored secret is still the secret once these are gone.
_ANSI = re.compile(
    r"\x1b\[[0-9;]*[A-Za-z]"
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|\x1b[@-Z\\-_]"
)
_TS = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z[ \t]*"
_LOG_BREAK = re.compile(rf"\n(?:{_TS})?(?:E[ \t]+)?")
_WRAPS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]*$"),
    re.compile(r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]*$"),
    re.compile(r"(?<![A-Za-z0-9_])npm_[A-Za-z0-9]*$"),
    re.compile(r"(?<![A-Za-z0-9_])whsec_[A-Za-z0-9]*$"),
    re.compile(r"(?<![A-Za-z0-9_])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]*$"),
    re.compile(r"(?<![A-Za-z0-9_])xox[a-z]-[A-Za-z0-9-]*$"),
    re.compile(r"(?<![A-Za-z0-9_])xapp-\d-[A-Za-z0-9-]*$"),
    re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]*$"),
)
_ENV_KEYWORDS = frozenset({"password", "secret", "token", "key", "passwd", "apikey"})
_SHA_LINE = re.compile(r"[0-9a-fA-F]{7,12}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")


def _strip_ansi(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return _ANSI.sub("", text)


def _payload(line: str) -> str:
    line = re.sub(rf"^{_TS}", "", line)
    return re.sub(r"^E[ \t]+", "", line)


_STARTS_PREFIX = re.compile(
    r"^(?:github_pat_|gh[pousr]_|npm_|whsec_|(?:sk|rk)_(?:live|test)_|xox[a-z]-|xapp-\d-|AKIA|ASIA)"
)


def _continuation_ok(prefix: str, nxt: str) -> bool:
    if _SHA_LINE.fullmatch(nxt) or nxt.startswith("Test") or _STARTS_PREFIX.match(nxt):
        return False  # a wrapped commit SHA, test name, or a new token is not a continuation
    if prefix.startswith(("AKIA", "ASIA")):
        alphabet = r"[0-9A-Z]"
    elif prefix.startswith(("xox", "xapp-")):
        alphabet = r"[A-Za-z0-9-]"
    elif prefix.startswith("github_pat_"):
        alphabet = r"[A-Za-z0-9_]"
    else:
        alphabet = r"[A-Za-z0-9]"
    return re.fullmatch(alphabet + r"{6,}", nxt) is not None


def _stitch_prefixed_wraps(text: str) -> str:
    """Join a known prefix with a continuation line that is only the rest of the token."""
    lines = text.split("\n")
    if len(lines) < 2:
        return text
    out = [lines[0]]
    for nxt in lines[1:]:
        prev = out[-1]
        prev_payload = _payload(prev).rstrip()
        nxt_payload = _payload(nxt).strip()
        joined = False
        for cre in _WRAPS:
            match = cre.search(prev_payload)
            if match and _continuation_ok(match.group(0), nxt_payload):
                out[-1] = prev.rstrip() + nxt_payload
                joined = True
                break
        if not joined:
            out.append(nxt)
    return "\n".join(out)


def _usable_env_secret(value: str) -> bool:
    if not value or len(value) < 6 or len(value) > 4096:
        return False
    if any(ch.isspace() for ch in value):
        return False
    if len(set(value)) < 4:
        return False
    low = value.lower()
    if low in _BENIGN_VALUES or low in _ENV_KEYWORDS:
        return False
    if value.startswith("[REDACTED") or value in MARK or value in PEM_MARK:
        return False
    return True


def secret_env_values(environ: Mapping[str, str] | None = None) -> list[str]:
    """Exact values of secret-named variables, longest first.

    ``environ`` defaults to the process environment (the runner). Pass a mapping
    to test a fixed set. A value shorter than 6 characters, or with fewer than
    4 distinct characters, is skipped: those collide with ordinary log text.
    """
    env = os.environ if environ is None else environ
    found: list[str] = []
    seen: set[str] = set()
    for name, value in env.items():
        if not secret_key_name(str(name)) or not _usable_env_secret(str(value)):
            continue
        if value in seen:
            continue
        seen.add(value)
        found.append(value)
    found.sort(key=len, reverse=True)
    return found


def _replace_bounded(text: str, value: str) -> str:
    pattern = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(value) + r"(?![A-Za-z0-9_])")
    return pattern.sub(MARK, text)


def _replace_split_value(text: str, value: str) -> str:
    """Remove ``value`` when one log line-break sits inside it."""
    if len(value) < 8:
        return text
    break_pat = rf"\n(?:{_TS})?(?:E[ \t]+)?"
    for cut in range(4, len(value) - 3):
        left, right = value[:cut], value[cut:]
        pattern = re.compile(
            r"(?<![A-Za-z0-9_])"
            + re.escape(left)
            + break_pat
            + re.escape(right)
            + r"(?![A-Za-z0-9_])"
        )
        text = pattern.sub(MARK, text)
    return text


def _redact_env_values(text: str, values: list[str]) -> str:
    for value in values:
        text = _replace_bounded(text, value)
        text = _replace_split_value(text, value)
    return text


def redact_secrets(text: str | None, environ: Mapping[str, str] | None = None) -> str:
    """Return ``text`` with secret values replaced. Idempotent.

    ``environ`` defaults to :data:`os.environ`. Secret-named variables in that
    mapping have their exact values removed from the text.
    """
    if not text:
        return ""
    s = _strip_ansi(str(text))
    s = _stitch_prefixed_wraps(s)
    s = _redact_env_values(s, secret_env_values(environ))
    s = _redact_pem(s)
    s = _SLACK_HOOK.sub(MARK, s)
    s = _DISCORD_HOOK.sub(MARK, s)
    s = _URL_SIG.sub(lambda m: m.group(0) if m.group(2).startswith("[REDACTED") else f"{m.group(1)}{MARK}", s)
    s = _TOKEN_FORMATS.sub(MARK, s)
    s = _URL_USERINFO.sub(lambda m: f"{m.group(1)}{m.group(2)}:{MARK}@", s)
    s = _AUTH_HEADER.sub(_header_sub, s)
    s = _BEARER.sub(lambda m: m.group(0) if m.group(3).startswith("[REDACTED") else f"{m.group(1)}{m.group(2)}{MARK}", s)
    s = _CURL_USER.sub(_curl_user_sub, s)
    s = _CLI_EQ.sub(_cli_eq_sub, s)
    s = _KV.sub(_kv_sub, s)
    s = _CLI_FLAG.sub(_cli_sub, s)
    s = _SAY_SECRET.sub(lambda m: m.group(0) if "[REDACTED" in m.group(3) else f"{m.group(1)}{m.group(2)}{m.group(3)[0]}{MARK}{m.group(3)[0]}", s)
    s = _apply_aws_secret(s)
    s = "\n".join(_standalone_entropy_line(_entropy_line(line)) for line in s.split("\n"))
    return s
