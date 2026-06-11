#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
咪咕视频 PlayUrl factor 请求协议（由 Frida v17 在 NetworkManager 层实测确认）
-----------------------------------------------------------------------------
实测来源:
  - 请求层: com.cmvideo.capability.network.NetworkManager.get(
                urlPath, headersMap, paramsMap, cachePolicy, retryCfg, request, ...)
  - 回调:   onSuccess(OkhttpNetworkSession{requestUrl=..., method=GET, queryParam={}}, ResponseData)
  - 落库:   PlayUrlFactorManager.savePlayUrlFactorBeanToLocal(PlayUrlFactorBean(sv, factor, tid, updateTime))

请求协议
  Method : GET
  Host   : https://v1-sc.miguvideo.com         （App 内实际用的; 你测过的 program-sc.miguvideo.com 是同一 staticcache CDN 的别名, 同样可用）
  Path   : /app-management/videox/staticcache/v2/factor/miguvideo/android   (普通播放 PlayUrl, 返回 sv=10001)
           /app-management/videox/staticcache/v2/factor/miguvideo/ajsb      (JS 播放,      返回 sv=10031)
  Query  : 无
  Headers: 业务层只塞 appCode(+userId); NetworkManager 在 okhttp 拦截器里追加全局公共头。
           ecapture(text 模式) 抓到的**完整上线请求头**(android/ajsb 相同, 仅 path 不同):
             l_t / timeStamp  = 请求毫秒时间戳(两者相同)
             l_c / clientId   = 客户端ID(两者相同, 设备级)
             l_s              = 请求签名(疑似对其它头/时间戳的 MD5, 公开 staticcache 接口实测不强校验)
             APP-VERSION-CODE = 260585013      appVersion = 2600058500   appVersionName = 6.5.85
             appCode = miguvideo_default_android  appId = miguvideo   terminalId = android
             osInfo = AD   networkInfo = WIFI   Support-Pendant = 1
             User-Agent = Dalvik/2.1.0 (Linux; U; Android 13; <model> Build/...)
             Phone-Info = <brand>|<model>|<sdk>   imei = unkonw(原文如此)
             SDKCEId = <uuid>   X-UP-CLIENT-CHANNEL-ID = 2600058500-99000-200300220100002
             Cache-Control = no-cache   Accept-Encoding = gzip   Host = v1-sc.miguvideo.com
           注意: 实测此接口为公开配置接口, **仅带 appCode 即可命中 CDN 返回**;
                 其余全局头不是必须的(签名 l_s 也不强校验)。下面 build_headers 给两档:
                 minimal(够用) 与 full(贴近真机, 需自行填设备相关值)。

响应 (staticcache 标准包装, body 即 factor bean):
  {"factor":"E8KmOzDHdgb0EGGi9uBJRw==","sv":"10001","tid":"android","updateTime":...}
  android -> sv=10001  factor=E8KmOzDHdgb0EGGi9uBJRw==
  ajsb    -> sv=10031  factor=70BM7OPJN41nv5REvL3qEg==
  factor 字段是 base64(AES) 密文, 客户端 native(libufs.so) 再 base64解码+AES解密 得到
  形如 "3,6,7,2,7" 的 5 个逗号分隔数字, 用于推 seed。
"""

import json
import time
import uuid

import requests

HOSTS = [
    "https://v1-sc.miguvideo.com",        # App 内实测 host
    "https://program-sc.miguvideo.com",   # 你测过可用的别名
]
PATHS = {
    "android": "/app-management/videox/staticcache/v2/factor/miguvideo/android",
    "ajsb":    "/app-management/videox/staticcache/v2/factor/miguvideo/ajsb",
}

def build_headers(user_id: str = "1768975581", full: bool = False,
                  client_id: str = "305ce4bb90adb65cf269c6ba3a39b953") -> dict:
    """minimal(默认)够用; full=True 复刻 ecapture 抓到的真机完整公共头。"""
    if not full:
        return {
            "appCode": "miguvideo_default_android",
            "userId": user_id,
        }
    now_ms = str(int(time.time() * 1000))
    return {
        "l_t": now_ms,
        "timeStamp": now_ms,
        "l_c": client_id,
        "clientId": client_id,
        # l_s 是请求签名(算法未确认); 公开 staticcache 接口实测不强校验, 故省略。
        "APP-VERSION-CODE": "260585013",
        "appVersion": "2600058500",
        "appVersionName": "6.5.85",
        "appCode": "miguvideo_default_android",
        "appId": "miguvideo",
        "terminalId": "android",
        "osInfo": "AD",
        "networkInfo": "WIFI",
        "Support-Pendant": "1",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; 23076RA4BC Build/TKQ1.221114.001)",
        "Phone-Info": "Redmi|23076RA4BC|13",
        "imei": "unkonw",
        "SDKCEId": str(uuid.uuid4()),
        "X-UP-CLIENT-CHANNEL-ID": "2600058500-99000-200300220100002",
        "Cache-Control": "no-cache",
        "Accept-Encoding": "gzip",
        "userId": user_id,
    }

def fetch_factor(tid: str = "android", user_id: str = "1768975581", host: str = HOSTS[0]) -> dict:
    url = host + PATHS[tid]
    r = requests.get(url, headers=build_headers(user_id), timeout=10)
    r.raise_for_status()
    print(f"GET {url} -> {r.status_code}")
    print("resp headers:", dict(r.headers))
    print("resp body   :", r.text)
    try:
        return r.json()
    except Exception:
        return {"raw": r.text}

# ---------------------------------------------------------------------------
# factor 解密 (libufs.so 里硬编码 AES-256)。注意: 以下 key/IV 直取自 .so 字符串,
# 但离线用「ASCII key + 常见 IV」尚未复现出 "3,6,7,2,7", 说明 key 可能还需一次派生
# (例如对该 32 字符再 MD5 / 取 hex 字节等)。请把它当作待确认的解密骨架。
# ---------------------------------------------------------------------------
def decrypt_factor(factor_b64: str, key: bytes = b"1ed7f236e8eedfe1c90ccad475b3ba19",
                   iv: bytes = b"\x00" * 16) -> bytes:
    import base64
    from Crypto.Cipher import AES  # pip install pycryptodome
    ct = base64.b64decode(factor_b64)
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    pad = pt[-1]
    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
        pt = pt[:-pad]
    return pt

if __name__ == "__main__":
    for tid in ("android", "ajsb"):
        data = fetch_factor(tid)
        print(tid, "=>", json.dumps(data, ensure_ascii=False))
        print("-" * 60)
