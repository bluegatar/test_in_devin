"""Aliyun VoD private-encryption TS parser (port of ``pkg/parse/aliyun/tsparser.go``).

Aliyun encrypts only the PES payloads of the video (PID 0x100) and audio
(PID 0x101) elementary streams with AES-128-ECB. This module walks the 188-byte
TS packets, groups payloads into PES fragments and decrypts them in place.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import aes128_ecb_decrypt

PACKET_LENGTH = 188
SYNC_BYTE = 0x47
PAYLOAD_START_MASK = 0x40
ATF_MASK = 0x30
ATF_FIELD_ONLY = 0x02
ATF_FIELD_FOLLOW_PAYLOAD = 0x03


@dataclass
class _Packet:
    pid: int = 0
    is_payload_start: bool = False
    payload_start_offset: int = 0
    payload_length: int = 0
    payload: bytes = b""


@dataclass
class _Pes:
    packets: list[_Packet] = field(default_factory=list)


def _parse_packet(buf: bytes, offset: int) -> _Packet:
    if buf[0] != SYNC_BYTE:
        raise ValueError(f"invalid ts package at offset {offset}")
    pkt = _Packet()
    pkt.pid = (buf[1] & 0x1F) << 8 | (buf[2] & 0xFF)
    pkt.is_payload_start = bool(buf[1] & PAYLOAD_START_MASK)
    atf = (buf[3] & ATF_MASK) >> 4
    header_length = 4
    atf_length = 0
    if atf in (ATF_FIELD_ONLY, ATF_FIELD_FOLLOW_PAYLOAD):
        header_length += 1
        atf_length = buf[4] & 0xFF
    pes_header_length = 0
    if pkt.is_payload_start:
        # 6 bytes PES header + 3 bytes extension + declared extension length
        pes_header_length = 6 + 3 + (buf[header_length + atf_length + 8] & 0xFF)
    rel = header_length + atf_length + pes_header_length
    pkt.payload_start_offset = offset + rel
    pkt.payload_length = PACKET_LENGTH - rel
    if pkt.payload_length > 0:
        pkt.payload = buf[rel:PACKET_LENGTH]
    return pkt


def decrypt(data: bytes, hex_key: str) -> bytes:
    """Return ``data`` with its video/audio PES payloads decrypted."""
    if len(data) % PACKET_LENGTH != 0:
        raise ValueError("not a ts package")
    key = bytes.fromhex(hex_key)
    out = bytearray(data)

    videos: list[_Pes] = []
    audios: list[_Pes] = []
    current: dict[int, _Pes] = {}
    streams = {0x100: videos, 0x101: audios}

    for no in range(len(data) // PACKET_LENGTH):
        start = no * PACKET_LENGTH
        pkt = _parse_packet(data[start : start + PACKET_LENGTH], start)
        bucket = streams.get(pkt.pid)
        if bucket is None:
            continue
        if pkt.is_payload_start or pkt.pid not in current:
            current[pkt.pid] = _Pes()
            bucket.append(current[pkt.pid])
        current[pkt.pid].packets.append(pkt)

    for fragments in (videos, audios):
        for pes in fragments:
            joined = b"".join(p.payload for p in pes.packets)
            n = len(joined) - len(joined) % 16
            decrypted = aes128_ecb_decrypt(joined[:n], key) + joined[n:]
            pos = 0
            for p in pes.packets:
                end = pos + p.payload_length
                out[p.payload_start_offset : p.payload_start_offset + p.payload_length] = (
                    decrypted[pos:end]
                )
                pos = end

    return bytes(out)
