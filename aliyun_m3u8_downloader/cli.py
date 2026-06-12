"""Command line interface (port of the ``cmd`` package)."""

from __future__ import annotations

import argparse
import sys

import urllib3

from .aliyun_download import download_aliyun
from .downloader import DEFAULT_CONCURRENCY, Downloader

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("-o", "--output", default="", help="下载保存目录")
    p.add_argument("-f", "--filename", default="", help="保存文件名")
    p.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help="下载并发数 (默认 3)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aliyun-m3u8-downloader",
        description="阿里云 M3U8 视频下载工具 (Python 版, 默认 3 线程)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    normal = sub.add_parser("normal", help="普通 m3u8 或标准 AES-128 加密下载")
    normal.add_argument("-u", "--url", required=True, help="m3u8 地址")
    _add_common(normal)

    aliyun = sub.add_parser("aliyun", help="阿里云私有加密 m3u8 下载")
    aliyun.add_argument("-p", "--play-auth", required=True, help="web 播放鉴权信息 PlayAuth")
    aliyun.add_argument("-v", "--video-id", default="", help="视频 id")
    aliyun.add_argument("-g", "--region", default="", help="地域, 默认 cn-shanghai")
    _add_common(aliyun)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "normal":
            Downloader(
                url=args.url, output=args.output, filename=args.filename
            ).start(args.concurrency)
        elif args.command == "aliyun":
            download_aliyun(
                play_auth=args.play_auth,
                output=args.output,
                filename=args.filename,
                concurrency=args.concurrency,
                video_id=args.video_id,
                region=args.region,
            )
    except Exception as err:  # noqa: BLE001 - top-level CLI guard
        print(f"error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
