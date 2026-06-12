"""M3U8 playlist parsing (port of ``pkg/parse/m3u8.go``)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

CRYPT_AES = "AES-128"
CRYPT_NONE = "NONE"

_LINE_PARAM = re.compile(r'([a-zA-Z-]+)=("[^"]+"|[^",]+)')


@dataclass
class Segment:
    uri: str = ""
    key_index: int = 0
    title: str = ""
    duration: float = 0.0
    length: int = 0
    offset: int = 0


@dataclass
class MasterPlaylist:
    uri: str = ""
    bandwidth: int = 0
    resolution: str = ""
    codecs: str = ""
    program_id: int = 0


@dataclass
class KeyInfo:
    method: str = ""
    uri: str = ""
    key: str = ""
    iv: str = ""
    aliyun_vod_encryption: bool = False


@dataclass
class M3u8:
    version: int = 0
    media_sequence: int = 0
    segments: list[Segment] = field(default_factory=list)
    master_playlist: list[MasterPlaylist] = field(default_factory=list)
    keys: dict[int, KeyInfo] = field(default_factory=dict)
    end_list: bool = False
    playlist_type: str = ""
    target_duration: float = 0.0


def _parse_params(line: str) -> dict[str, str]:
    return {m[0]: m[1].strip('"') for m in _LINE_PARAM.findall(line)}


def _parse_master(line: str) -> MasterPlaylist:
    params = _parse_params(line)
    if not params:
        raise ValueError("empty parameter")
    mp = MasterPlaylist()
    if "BANDWIDTH" in params:
        mp.bandwidth = int(params["BANDWIDTH"])
    if "RESOLUTION" in params:
        mp.resolution = params["RESOLUTION"]
    if "PROGRAM-ID" in params:
        mp.program_id = int(params["PROGRAM-ID"])
    if "CODECS" in params:
        mp.codecs = params["CODECS"]
    return mp


def parse(text: str) -> M3u8:
    """Parse M3U8 text into an :class:`M3u8` structure."""
    lines = text.splitlines()
    m3u8 = M3u8()
    key_index = 0
    seg: Segment | None = None
    ext_inf = ext_byte = False

    for i, raw in enumerate(lines):
        line = raw.strip()
        if i == 0:
            if line != "#EXTM3U":
                raise ValueError("invalid m3u8, missing #EXTM3U in line 1")
            continue
        if line == "":
            continue
        if line.startswith("#EXT-X-PLAYLIST-TYPE:"):
            m3u8.playlist_type = line.split(":", 1)[1]
        elif line.startswith("#EXT-X-TARGETDURATION:"):
            m3u8.target_duration = float(line.split(":", 1)[1])
        elif line.startswith("#EXT-X-MEDIA-SEQUENCE:"):
            m3u8.media_sequence = int(line.split(":", 1)[1])
        elif line.startswith("#EXT-X-VERSION:"):
            m3u8.version = int(line.split(":", 1)[1])
        elif line.startswith("#EXT-X-STREAM-INF:"):
            mp = _parse_master(line)
            mp.uri = lines[i + 1] if i + 1 < len(lines) else ""
            if not mp.uri or mp.uri.startswith("#"):
                raise ValueError(f"invalid EXT-X-STREAM-INF URI, line: {i + 2}")
            m3u8.master_playlist.append(mp)
        elif line.startswith("#EXTINF:"):
            if ext_inf:
                raise ValueError(f"duplicate EXTINF: {line}, line: {i + 1}")
            seg = seg or Segment()
            value = line.split(":", 1)[1].strip()
            if "," in value:
                dur, title = value.split(",", 1)
                seg.title = title
                value = dur
            seg.duration = float(value)
            seg.key_index = key_index
            ext_inf = True
        elif line.startswith("#EXT-X-BYTERANGE:"):
            if ext_byte:
                raise ValueError(f"duplicate EXT-X-BYTERANGE: {line}, line: {i + 1}")
            seg = seg or Segment()
            value = line.split(":", 1)[1].strip()
            if "@" in value:
                length, offset = value.split("@", 1)
                seg.offset = int(offset)
                value = length
            seg.length = int(value)
            ext_byte = True
        elif line.startswith("#EXT-X-KEY"):
            key_index += 1
            m3u8.keys[key_index] = _parse_key(line, i)
        elif line == "#EndList":
            m3u8.end_list = True
        elif not line.startswith("#"):
            if ext_inf and seg is not None:
                seg.uri = line
                m3u8.segments.append(seg)
                seg = None
                ext_inf = ext_byte = False

    return m3u8


def _parse_key(line: str, i: int) -> KeyInfo:
    params = _parse_params(line)
    if not params:
        raise ValueError(f"invalid EXT-X-KEY: {line}, line: {i + 1}")
    key = KeyInfo()
    method = params.get("METHOD", "")
    # Aliyun private encryption uses the (misspelled) "MEATHOD" attribute.
    if params.get("MEATHOD") == CRYPT_AES:
        method = CRYPT_AES
        key.aliyun_vod_encryption = True
    if method and method not in (CRYPT_AES, CRYPT_NONE):
        raise ValueError(f"invalid EXT-X-KEY method: {method}, line: {i + 1}")
    key.method = method
    key.uri = params.get("URI", "")
    iv = params.get("IV", "")
    if iv.startswith("0x"):
        raw = bytearray.fromhex(iv[2:])
        # Baidu cloud reverses each 4-byte group of the IV.
        if params.get("KEYFORMAT") in ("media-drm-token", "media-drm-player-binding"):
            for k in range(0, len(raw), 4):
                raw[k : k + 4] = raw[k : k + 4][::-1]
        iv = raw.decode("latin-1")
    key.iv = iv
    return key
