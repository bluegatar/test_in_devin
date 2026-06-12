"""Aliyun VoD play-info API (port of ``pkg/request/aliyun``).

Decodes the (optionally obfuscated) ``PlayAuth`` token, builds the signed
``GetPlayInfo`` request and returns the parsed JSON response.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote_plus

import requests

from .crypto import encrypt_rand

# Obfuscation signatures embedded in the original client.
_SIGN1 = [52, 58, 53, 121, 116, 102]
_SIGN2 = [90, 91]

_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36"
    ),
}


@dataclass
class PlayInfoOption:
    video_id: str = ""
    region: str = "cn-shanghai"
    stream_type: str = "video"
    formats: str = ""


def _sign_str(sign: list[int]) -> str:
    return "".join(chr(b - i) for i, b in enumerate(sign))


def _is_signed_play_auth(play_auth: str) -> bool:
    pos1 = datetime.now().year // 100
    s1, s2 = _sign_str(_SIGN1), _sign_str(_SIGN2)
    return (
        play_auth[pos1 : pos1 + len(s1)] == s1
        and play_auth[len(play_auth) - 2 :] == s2
    )


def _decode_signed_play_auth(play_auth: str) -> str:
    s1, s2 = _sign_str(_SIGN1), _sign_str(_SIGN2)
    play_auth = play_auth.replace(s1, "", 1)[: -len(s2)]
    factor = datetime.now().year // 100
    z = factor // 10
    out = bytearray(play_auth.encode("latin-1"))
    for i, code in enumerate(out):
        if code // factor != z:
            out[i] = code - 1
    return out.decode("latin-1")


def decode_play_auth(play_auth: str) -> str:
    if _is_signed_play_auth(play_auth):
        play_auth = _decode_signed_play_auth(play_auth)
    try:
        return base64.b64decode(play_auth).decode("utf-8")
    except (binascii.Error, ValueError):
        return ""


def _hmac_sha1(secret: str, string_to_sign: str) -> str:
    mac = hmac.new((secret + "&").encode(), string_to_sign.encode(), hashlib.sha1)
    return base64.b64encode(mac.digest()).decode()


def build_play_info_url(rand: str, play_auth: str, opt: PlayInfoOption) -> str:
    """Build the signed ``GetPlayInfo`` request URL."""
    auth = json.loads(decode_play_auth(play_auth))
    if not opt.video_id:
        opt.video_id = auth.get("VideoMeta", {}).get("VideoId", "") or ""
    region = auth.get("Region")
    if region:
        opt.region = region

    params = {
        "AccessKeyId": auth.get("AccessKeyId", ""),
        "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "SignatureMethod": "HMAC-SHA1",
        "SignatureVersion": "1.0",
        "SignatureNonce": str(uuid.uuid4()),
        "Format": "JSON",
        "Channel": "HTML5",
        "StreamType": opt.stream_type,
        "Formats": opt.formats,
        "Version": "2017-03-21",
        "Action": "GetPlayInfo",
        "AuthInfo": auth.get("AuthInfo", ""),
        "AuthTimeout": "7200",
        "Definition": "240",
        "PlayConfig": "{}",
        "PlayerVersion": "2.9.0",
        "ReAuthInfo": "{}",
        "SecurityToken": auth.get("SecurityToken", ""),
        "VideoId": opt.video_id,
    }
    if rand:
        params["Rand"] = rand

    cqs = "&".join(
        sorted(f"{quote_plus(k)}={quote_plus(v)}" for k, v in params.items())
    )
    string_to_sign = "GET&" + quote_plus("/") + "&" + quote_plus(cqs)
    signature = _hmac_sha1(auth.get("AccessKeySecret", ""), string_to_sign)
    query = cqs + "&Signature=" + quote_plus(signature)
    return f"https://vod.{opt.region}.aliyuncs.com/?{query}"


def get_vod_player_info(
    rand: str, play_auth: str, opt: Optional[PlayInfoOption] = None
) -> dict:
    """Encrypt the client random, query the VoD API and return the JSON dict."""
    opt = opt or PlayInfoOption()
    url = build_play_info_url(encrypt_rand(rand.encode()), play_auth, opt)
    resp = requests.get(url, headers=_HEADERS, timeout=30, verify=False)
    resp.raise_for_status()
    return resp.json()
