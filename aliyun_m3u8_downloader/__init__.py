"""Aliyun M3U8 Downloader (Python port).

A concise, multi-threaded M3U8 / TS downloader that supports:

* plain M3U8 / standard AES-128 (CBC) encrypted streams (``normal`` command)
* Aliyun VoD private-encrypted M3U8 streams (``aliyun`` command)

Ported from the Go project ``github.com/lbbniu/aliyun-m3u8-downloader``.
"""

from .downloader import Downloader
from .parser import from_m3u8_url, from_m3u8_content

__all__ = ["Downloader", "from_m3u8_url", "from_m3u8_content"]
__version__ = "1.0.0"
