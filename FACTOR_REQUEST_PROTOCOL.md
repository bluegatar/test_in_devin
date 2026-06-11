# 咪咕视频 PlayUrl `factor` 请求协议（逆向结论）

本文记录通过 **静态 DEX 分析 + 动态 Frida 插桩** 还原出的 PlayUrl 加密因子
`factor` 的网络来源协议。请求层结论已由 Frida 在 `NetworkManager` 层 + 回调层
**实测确认**。

## 1. 请求协议

| 项 | 值 |
|----|----|
| Method | `GET` |
| Host | `https://v1-sc.miguvideo.com`（App 内实际使用）<br>`https://program-sc.miguvideo.com`（同一 staticcache CDN 的别名，亦可用）|
| Path（普通播放）| `/app-management/videox/staticcache/v2/factor/miguvideo/android` → `sv=10001` |
| Path（JS 播放）| `/app-management/videox/staticcache/v2/factor/miguvideo/ajsb` → `sv=10031` |
| Query | 无（`queryParam={}`）|
| Header `appCode` | `miguvideo_default_android` |
| Header `userId` | 用户 ID（实测 `1768975581`，仅用于灰度/分流，可选）|

> `NetworkManager` 在 okhttp 拦截器中还会追加一批全局公共头。但
> `staticcache/factor` 属公开配置接口，实测**仅带 `appCode` 即可命中 CDN 返回**。

### 完整上线请求头（ecapture text 模式实测，android/ajsb 仅 path 不同）

业务层只塞 `appCode`(+`userId`)，`NetworkManager` 在 okhttp 拦截器追加其余全局公共头。
线缆上的完整头：

```
GET /app-management/videox/staticcache/v2/factor/miguvideo/ajsb HTTP/1.1
l_t: 1781199012851                 # 请求毫秒时间戳（== timeStamp）
l_s: 263ffa22005132eea7082e295a9b2985   # 请求签名（疑似 MD5；公开接口实测不强校验）
l_c: 305ce4bb90adb65cf269c6ba3a39b953   # 客户端ID（== clientId）
clientId: 305ce4bb90adb65cf269c6ba3a39b953
timeStamp: 1781199012851
APP-VERSION-CODE: 260585013
appVersion: 2600058500
appVersionName: 6.5.85
appCode: miguvideo_default_android
appId: miguvideo
terminalId: android
osInfo: AD
networkInfo: WIFI
Support-Pendant: 1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; 23076RA4BC Build/TKQ1.221114.001)
Phone-Info: Redmi|23076RA4BC|13
imei: unkonw
SDKCEId: 27fb3129-5a54-45bc-8af1-7dc8f1155501
X-UP-CLIENT-CHANNEL-ID: 2600058500-99000-200300220100002
Cache-Control: no-cache
Accept-Encoding: gzip
Host: v1-sc.miguvideo.com
Connection: Keep-Alive
```

> 注意：wire 头里没有 `userId`（业务 map 里的 `userId` 未直接上线），设备标识是
> `clientId`/`l_c`。其余全局头非必须；签名 `l_s` 对该公开接口不强校验。

### 抓包方法对比（实践经验）

- **ecapture text 模式**（`./ecapture tls -l cap.log`，`probe=OpenSSL`）：uprobe 挂
  `SSL_write/SSL_read`，拿解密后明文，**与网卡无关，最稳**，能直接看到上面整段头。
- **ecapture pcap 模式**（`-m pcap`）：tc-eBPF 在 `-i <网卡>` 抓加密帧 + 把密钥写进
  pcapng(DSB)。强依赖 `-i` 指对真实出口网卡，否则 pcapng 为空；输出必须用 `.pcapng`
  （`.pcap` 会丢密钥导致 Wireshark 无法解密）。
- **VPN 抓包 App + SSL pinning**：见 `frida_bypass_full_v2.js`（信任链全绕过 + VPN 检测
  绕过）；另需把抓包 App 的 CA 装进**系统证书库**、并让其解密非 443 端口（如登录
  `passport.migu.cn:8443`）。

## 2. 响应

staticcache 标准包装，body 即 factor bean：

```json
{"factor":"E8KmOzDHdgb0EGGi9uBJRw==","sv":"10001","tid":"android","updateTime":1781193859122}
```

| tid | sv | factor（base64+AES 密文）|
|-----|----|--------------------------|
| android | 10001 | `E8KmOzDHdgb0EGGi9uBJRw==` |
| ajsb | 10031 | `70BM7OPJN41nv5REvL3qEg==` |

## 3. 完整来源链（从网络到使用）

```
GET https://v1-sc.miguvideo.com/app-management/videox/staticcache/v2/factor/miguvideo/android
    headers: appCode=miguvideo_default_android, userId=...
  → 响应 {"factor":"E8Km..==","sv":"10001","tid":"android","updateTime":..}
  → PlayUrlFactorManager.initPlayUrlFactorBean
       → savePlayUrlFactorBeanToLocal  (MMKV: mmapID=SPHelperEncrypt,
                                         key=key_play_url_factor_bean_PlayUrl)
  → 每次播放 getPlayUrlFactorBeanFromLocal 读本地 → PlayerConfigPool.getPlayUrlFactor()
  → PlayUrlEncryptionUtil → native(libufs.so) base64解码 + AES 解密 → "3,6,7,2,7" → seed
```

关键类 / 存储：

- 请求类：`com.cmvideo.datacenter.baseapi.api.appmanagement.staticcache.v2.factor.PlayUrlFactorRequest`
- 管理器：`com.cmvideo.capability.mguniformmpbusiness.playerconfig.PlayUrlFactorManager`
- 网络层：`com.cmvideo.capability.network.NetworkManager`（okhttp，门户网关）
- 服务定位：`ServiceCenterKt.getService(IPlayerConfig.class)` → 活的 `PlayerConfigPool`
- 本地缓存：MMKV 文件 `/data/user/0/com.cmcc.cmvideo/files/mmkv/SPHelperEncrypt`，
  key `key_play_url_factor_bean_PlayUrl`（JS 版 `..._JSUrl`），
  存的是**处理后的 bean JSON**（不含原始请求头）。

## 4. 复现脚本

- `factor_request.py`：直接 GET 两个接口，打印响应（解密骨架另附，待确认）。
- `frida_factor_trace_v17.js`：attach 后自动 `forceFactor()`，在 `NetworkManager.get`
  打印 **url + 完整 headers(Map) + params**，并在回调 `onSuccess` 打印响应、
  在 `savePlayUrlFactorBeanToLocal` 打印落库 bean。

## 5. 逆向过程中的关键经验

- **腾讯 legu 加固反调试**有两个杀进程触发点：① 冷启动注入（`frida -f` spawn / spawn-gating）；
  ② **堆扫描**（`Java.choose` / 全堆 `enumerateMethods`）。
  对策：**App 完全启动后再 attach + 只用类级方法 hook，不做任何堆扫描**。
- factor 走本地 MMKV 缓存，平时不发网络；`updateTime` 每次启动都会变 → 说明每次冷启动会重新拉取。
  要在 warm 进程中强制重拉：经 `ServiceCenterKt.getService(IPlayerConfig)` 拿到 `PlayerConfigPool`
  （**无需堆扫描**），临时让 `getPlayUrlFactorBeanFromLocal` 返回 null，再调
  `initPlayUrlFactorBean()` / `init()`。
- factor 的请求**不经 okhttp3 的 `Request$Builder.url()`**（那层只能看到 m3u8 等），
  而是经 `NetworkManager.get(urlPath, headersMap, paramsMap, cachePolicy, retryCfg, request)`，
  host 由网络层按环境拼接。
