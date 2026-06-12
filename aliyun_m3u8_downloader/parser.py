"""Fetch + parse an M3U8 into a resolved result (port of ``pkg/parse/parser.go``)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

import requests

from . import m3u8 as m3u8_mod
from .m3u8 import CRYPT_AES, CRYPT_NONE, M3u8
from .util import resolve_url

# load_key_func(m3u8_url, key_url) -> key string
LoadKeyFunc = Callable[[str, str], str]


@dataclass
class Result:
    url: str
    m3u8: M3u8


def default_load_key(_m3u8_url: str, key_url: str) -> str:
    """Download a standard HLS key (raw 16 bytes) as a latin-1 string."""
    resp = requests.get(key_url, timeout=30)
    resp.raise_for_status()
    return resp.content.decode("latin-1")


def _http_get(session: Optional[requests.Session], url: str) -> requests.Response:
    resp = (session or requests).get(url, timeout=30)
    resp.raise_for_status()
    return resp


def _resolve_keys(result: Result, m3u8_url: str, load_key: LoadKeyFunc) -> None:
    cache: dict[str, str] = {}
    for info in result.m3u8.keys.values():
        if not info.method or info.method == CRYPT_NONE:
            continue
        if info.method != CRYPT_AES:
            raise ValueError(f"unknown or unsupported cryption method: {info.method}")
        if info.uri not in cache:
            key_url = resolve_url(result.url, info.uri) if result.url else info.uri
            cache[info.uri] = load_key(m3u8_url, key_url)
        info.key = cache[info.uri]


def from_m3u8_url(
    m3u8_url: str,
    load_key: Optional[LoadKeyFunc] = None,
    session: Optional[requests.Session] = None,
) -> Result:
    """Build a :class:`Result` from a remote M3U8 URL (following master playlists)."""
    load_key = load_key or default_load_key
    resp = _http_get(session, m3u8_url)
    parsed = m3u8_mod.parse(resp.text)
    if parsed.master_playlist:
        variant = parsed.master_playlist[0]
        return from_m3u8_url(resolve_url(m3u8_url, variant.uri), load_key, session)
    if not parsed.segments:
        raise ValueError("can not found any TS file description")
    result = Result(url=m3u8_url, m3u8=parsed)
    _resolve_keys(result, m3u8_url, load_key)
    return result


def from_m3u8_content(
    m3u8_url: str, content: str, load_key: Optional[LoadKeyFunc] = None
) -> Result:
    """Build a :class:`Result` from already-fetched M3U8 text."""
    load_key = load_key or default_load_key
    parsed = m3u8_mod.parse(content)
    if not parsed.segments:
        raise ValueError("can not found any TS file description")
    result = Result(url=m3u8_url, m3u8=parsed)
    _resolve_keys(result, m3u8_url, load_key)
    return result
