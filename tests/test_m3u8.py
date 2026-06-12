from aliyun_m3u8_downloader import m3u8 as m
from aliyun_m3u8_downloader.util import resolve_url


def test_parse_basic_with_key():
    text = "\n".join(
        [
            "#EXTM3U",
            "#EXT-X-VERSION:3",
            "#EXT-X-TARGETDURATION:10",
            '#EXT-X-KEY:METHOD=AES-128,URI="key.key",IV=0x0123456789abcdef0123456789abcdef',
            "#EXTINF:9.009,title-a",
            "seg0.ts",
            "#EXTINF:9.009,",
            "seg1.ts",
            "#EndList",
        ]
    )
    result = m.parse(text)
    assert result.version == 3
    assert result.target_duration == 10
    assert len(result.segments) == 2
    assert result.segments[0].uri == "seg0.ts"
    assert result.segments[0].title == "title-a"
    assert result.segments[0].key_index == 1
    key = result.keys[1]
    assert key.method == m.CRYPT_AES
    assert key.uri == "key.key"
    assert len(key.iv) == 16  # 16 raw bytes from the 32 hex chars


def test_parse_master_playlist():
    text = "\n".join(
        [
            "#EXTM3U",
            "#EXT-X-STREAM-INF:PROGRAM-ID=1,BANDWIDTH=240000,RESOLUTION=416x234",
            "variant.m3u8",
        ]
    )
    result = m.parse(text)
    assert len(result.master_playlist) == 1
    mp = result.master_playlist[0]
    assert mp.uri == "variant.m3u8"
    assert mp.bandwidth == 240000
    assert mp.resolution == "416x234"


def test_aliyun_meathod_flag():
    text = "\n".join(
        ["#EXTM3U", "#EXT-X-KEY:MEATHOD=AES-128", "#EXTINF:1.0,", "s.ts"]
    )
    result = m.parse(text)
    assert result.keys[1].aliyun_vod_encryption is True
    assert result.keys[1].method == m.CRYPT_AES


def test_resolve_url():
    base = "https://h.example.com/a/b/index.m3u8"
    assert resolve_url(base, "http://x/y.ts") == "http://x/y.ts"
    assert resolve_url(base, "seg.ts") == "https://h.example.com/a/b/seg.ts"
    assert resolve_url(base, "/r/seg.ts") == "https://h.example.com/r/seg.ts"
    assert resolve_url(base, "../seg.ts") == "https://h.example.com/a/b/seg.ts"
