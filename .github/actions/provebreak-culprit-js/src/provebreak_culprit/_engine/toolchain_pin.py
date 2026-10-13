"""Pinned toolchain versions the one-click workflow installs.

A missing binary stays a ``*_missing`` reason. A binary whose version is
not this pin is ``<tool>_version_mismatch`` and is not a culprit. The
proof step in the customer workflow also skips itself when the install
step's outcome is failure, so an image toolchain cannot be used in its
place.
"""
from __future__ import annotations

import re
import subprocess
import tempfile

RUSTC_VERSION = "1.83.0"
CARGO_VERSION = "1.83.0"
CMAKE_VERSION = "3.28.3"
CTEST_VERSION = "3.28.3"
GCC_MAJOR = "13"
RUBY_VERSION = "3.2.3"
BUNDLER_VERSION = "2.4.20"
PHP_VERSION = "8.3.6"
COMPOSER_VERSION = "2.7.1"

# A trailing pre-release or distro suffix is not the pin. ``1.83.0-nightly``
# and ``13.3.0-6ubuntu2`` do not match. The compiler's own version is the
# token that ends the ``gcc --version`` line.
_SEMVER = re.compile(r"(?<![0-9.])(\d+)\.(\d+)\.(\d+)(?![0-9A-Za-z.-])")


def tool_version_text(argv: list[str]) -> str | None:
    """stdout and stderr of ``argv``, or None when the command does not succeed.

    The working directory is the temp dir so a checkout ``rust-toolchain``
    file is not what this read measures.
    """
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=tempfile.gettempdir(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return ((result.stdout or "") + "\n" + (result.stderr or ""))[:4000]


def semver(text: str | None) -> str | None:
    if not text:
        return None
    matched = _SEMVER.search(text)
    if not matched:
        return None
    return f"{int(matched.group(1))}.{int(matched.group(2))}.{int(matched.group(3))}"


def version_mismatch(argv: list[str], expected: str, reason: str) -> str | None:
    """``reason`` when ``argv --version`` is not ``expected``. Never a success on silence."""
    if semver(tool_version_text(argv)) != expected:
        return reason
    return None


def gnu_major(text: str | None) -> str | None:
    """Major version of a GNU compiler line. Clang is not that pin.

    ``gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`` carries the distro
    version inside the parentheses. The compiler version is the token
    after that closing parenthesis.
    """
    if not text:
        return None
    first = text.splitlines()[0]
    low = first.lower()
    if "clang" in low:
        return None
    if "gcc" not in low and "g++" not in low:
        return None
    tail = first.rsplit(")", 1)[-1] if ")" in first else first
    got = semver(tail)
    if got is None:
        return None
    return got.split(".", 1)[0]
