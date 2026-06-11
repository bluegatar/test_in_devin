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

> `NetworkManager` 在 okhttp 拦截器中还会追加一批全局公共头（`sourceId` /
> `APP-VERSION-CODE` / `userInfo`(URL 编码 JSON) / `terminalId` 等）。但
> `staticcache/factor` 属公开配置接口，实测仅带 `appCode` 即可命中 CDN 返回。

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
