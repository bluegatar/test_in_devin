"""High-level Aliyun VoD download flow (port of ``pkg/download/aliyun.go``)."""

from __future__ import annotations

import uuid

from .aliyun_api import PlayInfoOption, _HEADERS, get_vod_player_info
from .crypto import decrypt_key
from .downloader import DEFAULT_CONCURRENCY, Downloader

ALIYUN_VOD_ENCRYPTION = "AliyunVoDEncryption"


def download_aliyun(
    play_auth: str,
    output: str = "",
    filename: str = "",
    concurrency: int = DEFAULT_CONCURRENCY,
    video_id: str = "",
    region: str = "",
) -> str:
    """Resolve an Aliyun ``PlayAuth`` into a playable file and download it."""
    client_rand = str(uuid.uuid4())
    opt = PlayInfoOption()
    if video_id:
        opt.video_id = video_id
    if region:
        opt.region = region

    info = get_vod_player_info(client_rand, play_auth, opt)
    play_info_list = info.get("PlayInfoList", {}).get("PlayInfo")
    if not play_info_list:
        raise RuntimeError(f"failed to get PlayInfo: {info}")
    play_info = play_info_list[-1]

    if not filename:
        filename = info.get("VideoBase", {}).get("Title", "") or ""

    play_url = play_info.get("PlayURL", "")
    key = ""
    if play_info.get("EncryptType") == ALIYUN_VOD_ENCRYPTION:
        key = decrypt_key(client_rand, play_info.get("Rand", ""), play_info.get("Plaintext", ""))

    downloader = Downloader(
        url=play_url,
        output=output,
        filename=filename,
        key=key,
        mp4=play_info.get("Format") == "mp4",
        headers=_HEADERS,
        verify=False,
    )
    return downloader.start(concurrency)
