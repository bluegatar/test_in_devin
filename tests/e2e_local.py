"""Manual end-to-end check: serve a local AES-128 encrypted m3u8 and download it."""

import http.server
import os
import tempfile
import threading

from Crypto.Cipher import AES

from aliyun_m3u8_downloader import downloader as dl_mod
from aliyun_m3u8_downloader.downloader import Downloader

# Force raw .ts output (skip ffmpeg) so we can byte-compare the merged result.
dl_mod.shutil.which = lambda _name: None  # type: ignore[assignment]

KEY = b"0123456789abcdef"
IV = b"abcdef0123456789"


def _pad(d):
    p = 16 - len(d) % 16
    return d + bytes([p]) * p


def main():
    work = tempfile.mkdtemp()
    # Three fake "TS" segments, AES-128-CBC encrypted, each starting with 0x47.
    plains = [b"\x47" + os.urandom(200) for _ in range(3)]
    for i, p in enumerate(plains):
        enc = AES.new(KEY, AES.MODE_CBC, IV).encrypt(_pad(p))
        open(os.path.join(work, f"seg{i}.ts"), "wb").write(enc)
    open(os.path.join(work, "key.key"), "wb").write(KEY)
    open(os.path.join(work, "index.m3u8"), "w").write(
        "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:1\n"
        '#EXT-X-KEY:METHOD=AES-128,URI="key.key",IV=0x'
        + IV.hex()
        + "\n"
        + "".join(f"#EXTINF:1.0,\nseg{i}.ts\n" for i in range(3))
        + "#EndList\n"
    )

    os.chdir(work)
    handler = http.server.SimpleHTTPRequestHandler
    httpd = http.server.HTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    out = tempfile.mkdtemp()
    path = Downloader(
        url=f"http://127.0.0.1:{port}/index.m3u8", output=out, filename="video"
    ).start()  # default 3 threads

    merged = open(path, "rb").read()
    expected = b"".join(plains)  # decrypted, sync-byte already 0x47
    assert merged == expected, f"mismatch: {len(merged)} vs {len(expected)}"
    print(f"\nE2E OK: downloaded+decrypted+merged {len(merged)} bytes -> {path}")
    httpd.shutdown()


if __name__ == "__main__":
    main()
