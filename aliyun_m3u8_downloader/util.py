"""Small shared helpers (port of the relevant parts of ``pkg/tool/util.go``)."""

from __future__ import annotations

import posixpath
import sys
from urllib.parse import urlsplit


def resolve_url(base: str, ref: str) -> str:
    """Resolve a (possibly relative) URI against the base M3U8 URL."""
    if ref.startswith(("http://", "https://")):
        return ref
    parts = urlsplit(base)
    if ref.startswith("/"):
        prefix = f"{parts.scheme}://{parts.netloc}"
    else:
        prefix = base[: base.rfind("/")]
    return prefix + posixpath.normpath(posixpath.join("/", ref))


def draw_progress_bar(prefix: str, proportion: float, width: int = 40) -> None:
    pos = int(proportion * width)
    bar = "■" * pos + " " * (width - pos)
    sys.stdout.write(f"\r[{prefix}] {bar} {proportion * 100:6.2f}%")
    sys.stdout.flush()
