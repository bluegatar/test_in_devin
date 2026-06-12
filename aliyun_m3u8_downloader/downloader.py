"""Multi-threaded downloader + merger (port of ``pkg/download/dowloader.go``)."""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from posixpath import basename
from typing import Optional

import requests

from . import ts_parser
from .crypto import aes128_cbc_decrypt
from .m3u8 import CRYPT_NONE
from .parser import Result, default_load_key, from_m3u8_content, from_m3u8_url
from .util import draw_progress_bar, resolve_url

DEFAULT_CONCURRENCY = 3
SYNC_BYTE = 0x47


class Downloader:
    """Download and merge a (possibly encrypted) M3U8 stream into a single file."""

    def __init__(
        self,
        url: str = "",
        output: str = "",
        filename: str = "",
        key: str = "",
        m3u8_content: str = "",
        mp4: bool = False,
        headers: Optional[dict] = None,
        verify: bool = True,
        max_retries: int = 5,
    ) -> None:
        self.url = url
        self.filename = filename
        self.mp4 = mp4
        self.max_retries = max_retries

        self.session = requests.Session()
        if headers:
            self.session.headers.update(headers)
        self.session.verify = verify

        self.folder = output or os.getcwd()
        os.makedirs(self.folder, exist_ok=True)

        base = filename or self._base_name(url)
        self.merge_filename = (base[:-4] if base.endswith(".mp4") else base) or "output"

        if not url and not m3u8_content:
            raise ValueError("either url or m3u8_content is required")

        self._finish = 0
        self._lock = threading.Lock()
        self.result: Optional[Result] = None

        if not mp4:
            self.ts_folder = os.path.join(self.folder, "ts")
            os.makedirs(self.ts_folder, exist_ok=True)
            load_key = (lambda *_: key) if key else default_load_key
            if m3u8_content:
                self.result = from_m3u8_content(url, m3u8_content, load_key)
            else:
                self.result = from_m3u8_url(url, load_key, self.session)

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _base_name(url: str) -> str:
        return basename(url.split("?", 1)[0])

    def _ts_url(self, idx: int) -> str:
        return resolve_url(self.result.url, self.result.m3u8.segments[idx].uri)

    def _ts_filename(self, idx: int, ts_url: str) -> str:
        return f"{idx}-{self._base_name(ts_url)}"

    # -- public API ------------------------------------------------------
    def start(self, concurrency: int = DEFAULT_CONCURRENCY) -> str:
        """Download everything and return the path of the merged output file."""
        if concurrency <= 0:
            raise ValueError("concurrency must be greater than 0")
        if self.mp4:
            return self._download_mp4()

        seg_len = len(self.result.m3u8.segments)
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {pool.submit(self._download_segment, i): i for i in range(seg_len)}
            for future in as_completed(futures):
                future.result()  # re-raise the first fatal error
        print()
        return self._merge(seg_len)

    # -- downloading -----------------------------------------------------
    def _download_mp4(self) -> str:
        path = os.path.join(self.folder, self.merge_filename + ".mp4")
        with self.session.get(self.url, stream=True, timeout=60) as resp:
            resp.raise_for_status()
            with open(path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=1 << 16):
                    f.write(chunk)
        print(f"[output] {path}")
        return path

    def _download_segment(self, idx: int) -> None:
        ts_url = self._ts_url(idx)
        path = os.path.join(self.ts_folder, self._ts_filename(idx, ts_url))
        if os.path.exists(path):
            self._advance(idx, len(self.result.m3u8.segments))
            return

        last_err: Optional[Exception] = None
        for _ in range(self.max_retries):
            try:
                data = self._fetch_and_decrypt(idx, ts_url, path)
                tmp = path + "_tmp"
                with open(tmp, "wb") as f:
                    f.write(data)
                os.replace(tmp, path)
                self._advance(idx, len(self.result.m3u8.segments))
                return
            except Exception as err:  # retry on any transient failure
                last_err = err
        raise RuntimeError(f"download failed for segment {idx} ({ts_url}): {last_err}")

    def _fetch_and_decrypt(self, idx: int, ts_url: str, path: str) -> bytes:
        resp = self.session.get(ts_url, timeout=60)
        resp.raise_for_status()
        data = resp.content
        seg = self.result.m3u8.segments[idx]
        info = self.result.m3u8.keys.get(seg.key_index)
        if info and info.method and info.method != CRYPT_NONE:
            if info.aliyun_vod_encryption:
                data = ts_parser.decrypt(data, info.key)
            elif info.key:
                data = aes128_cbc_decrypt(
                    data, info.key.encode("latin-1"), info.iv.encode("latin-1")
                )
        return self._trim_sync_byte(data)

    @staticmethod
    def _trim_sync_byte(data: bytes) -> bytes:
        # Some TS files have junk before the 0x47 sync byte; strip it so the
        # merged stream is playable.
        pos = data.find(SYNC_BYTE)
        return data[pos:] if pos > 0 else data

    def _advance(self, idx: int, seg_len: int) -> None:
        with self._lock:
            self._finish += 1
            done = self._finish
        draw_progress_bar(f"downloading {done}/{seg_len}", done / seg_len)

    # -- merging ---------------------------------------------------------
    def _merge(self, seg_len: int) -> str:
        ts_path = os.path.join(self.folder, self.merge_filename + ".ts")
        merged = 0
        with open(ts_path, "wb") as out:
            for idx in range(seg_len):
                part = os.path.join(self.ts_folder, self._ts_filename(idx, self._ts_url(idx)))
                if not os.path.exists(part):
                    continue
                with open(part, "rb") as f:
                    shutil.copyfileobj(f, out)
                merged += 1
        shutil.rmtree(self.ts_folder, ignore_errors=True)
        if merged != seg_len:
            print(f"[warning] {seg_len - merged} files merge failed")

        final = self._remux_to_mp4(ts_path)
        print(f"[output] {final}")
        return final

    @staticmethod
    def _remux_to_mp4(ts_path: str) -> str:
        """Remux the concatenated TS into MP4 via ffmpeg if it is available."""
        if not shutil.which("ffmpeg"):
            return ts_path
        mp4_path = ts_path[:-3] + ".mp4"
        try:
            subprocess.run(
                ["ffmpeg", "-y", "-i", ts_path, "-c", "copy", mp4_path],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            return ts_path
        os.remove(ts_path)
        return mp4_path
