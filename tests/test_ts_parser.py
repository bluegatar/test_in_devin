import os

from Crypto.Cipher import AES

from aliyun_m3u8_downloader import ts_parser

KEY = bytes(range(16))


def _build_video_packet(payload_start: bool, payload: bytes) -> tuple[bytes, int]:
    """Build a single 188-byte video (PID 0x100) TS packet, payload-only."""
    buf = bytearray(188)
    buf[0] = 0x47
    buf[1] = 0x01 | (0x40 if payload_start else 0)  # pid high bits + start flag
    buf[2] = 0x00  # pid low bits -> pid = 0x100
    buf[3] = 0x10  # payload only, no adaptation field
    if payload_start:
        buf[12] = 0  # PES extension header length -> pes_header_length = 9
        rel = 13
    else:
        rel = 4
    assert len(payload) == 188 - rel
    buf[rel:188] = payload
    return bytes(buf), rel


def test_decrypt_recovers_payloads():
    # One video PES made of 3 packets (1 start + 2 continuation).
    rels = [13, 4, 4]
    plain_parts = [os.urandom(188 - rel) for rel in rels]
    joined_plain = b"".join(plain_parts)

    # Encrypt the multiple-of-16 prefix with ECB, leave the tail in clear.
    n = len(joined_plain) - len(joined_plain) % 16
    enc_joined = AES.new(KEY, AES.MODE_ECB).encrypt(joined_plain[:n]) + joined_plain[n:]

    # Slice the encrypted stream back into the per-packet payload regions.
    enc_parts, pos = [], 0
    for rel in rels:
        length = 188 - rel
        enc_parts.append(enc_joined[pos : pos + length])
        pos += length

    data = b"".join(
        _build_video_packet(i == 0, enc_parts[i])[0] for i in range(len(rels))
    )

    out = ts_parser.decrypt(data, KEY.hex())

    # Re-extract the payloads and confirm they match the original plaintext.
    recovered = b"".join(out[i * 188 + rels[i] : (i + 1) * 188] for i in range(len(rels)))
    assert recovered == joined_plain


def test_invalid_length_raises():
    try:
        ts_parser.decrypt(b"\x47" * 100, KEY.hex())
    except ValueError:
        return
    raise AssertionError("expected ValueError for non-188-multiple length")
