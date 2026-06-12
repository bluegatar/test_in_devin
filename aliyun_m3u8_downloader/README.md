# aliyun-m3u8-downloader (Python)

`aliyun_m3u8_downloader` 是 Go 项目
[`github.com/lbbniu/aliyun-m3u8-downloader`](https://github.com/lbbniu/aliyun-m3u8-downloader)
的 Python 重写版本：一个简洁、高效、**默认 3 线程**的 M3U8 / TS 下载器。

> 本工具仅供学习研究使用，如有侵权请联系删除。

## 功能

- 下载并解析 M3U8（含 Master Playlist 自动选流）
- 标准 AES-128 (CBC) 加密解密
- 阿里云私有加密 (AliyunVoDEncryption) 解密：RSA + AES 密钥交换 + TS PES 负载 ECB 解密
- 多线程并发下载（默认 3 线程）+ 失败自动重试
- 去除 TS 同步字节 (0x47) 前的脏数据
- 合并 TS 分片，若系统安装了 `ffmpeg` 则自动 remux 为 MP4，否则输出 `.ts`

## 安装

```bash
pip install -r requirements.txt
# 或可安装为命令行工具
pip install -e .
```

依赖：`requests`、`pycryptodome`。可选：`ffmpeg`（用于输出 mp4）。

## 命令行用法

```bash
# 普通 m3u8 / 标准 AES-128 加密
python -m aliyun_m3u8_downloader normal -u https://example.com/index.m3u8 -o ./out -c 3

# 阿里云私有加密 m3u8
python -m aliyun_m3u8_downloader aliyun -p "<PlayAuth>" -v <videoId> -o ./out -c 3
```

安装后亦可直接使用 `aliyun-m3u8-downloader` 命令。

参数：

| 参数 | 说明 |
| --- | --- |
| `-u, --url` | m3u8 地址（normal 子命令） |
| `-p, --play-auth` | 阿里云 PlayAuth 鉴权信息（aliyun 子命令） |
| `-v, --video-id` | 视频 id（可选，aliyun） |
| `-g, --region` | 地域，默认 `cn-shanghai`（aliyun） |
| `-o, --output` | 保存目录 |
| `-f, --filename` | 保存文件名 |
| `-c, --concurrency` | 下载并发线程数，默认 `3` |

## 作为库使用

```python
from aliyun_m3u8_downloader import Downloader

# 普通 m3u8，默认 3 线程
Downloader(url="https://example.com/index.m3u8", output="./out").start()

# 指定并发数
Downloader(url="https://example.com/index.m3u8", output="./out").start(concurrency=5)
```

```python
from aliyun_m3u8_downloader.aliyun_download import download_aliyun

download_aliyun(play_auth="<PlayAuth>", output="./out", concurrency=3)
```

## 模块结构

| 模块 | 对应 Go 文件 | 说明 |
| --- | --- | --- |
| `crypto.py` | `pkg/tool/crypto.go`, `aliyun_aes.go` | AES-128 CBC/ECB、RSA 加密、阿里云密钥推导 |
| `m3u8.py` | `pkg/parse/m3u8.go` | M3U8 文本解析 |
| `parser.py` | `pkg/parse/parser.go` | 拉取 / 解析 M3U8、加载密钥 |
| `ts_parser.py` | `pkg/parse/aliyun/tsparser.go` | 阿里云私有加密 TS 解密 |
| `aliyun_api.py` | `pkg/request/aliyun/*` | PlayAuth 解码、签名请求 GetPlayInfo |
| `aliyun_download.py` | `pkg/download/aliyun.go` | 阿里云下载编排 |
| `downloader.py` | `pkg/download/dowloader.go` | 并发下载与合并 |
| `cli.py` | `cmd/*` | 命令行入口 |
