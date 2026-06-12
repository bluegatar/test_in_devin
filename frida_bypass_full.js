/*
 * frida_bypass_full.js  ——  SSL Pinning + VPN 检测 双绕过 (咪咕/通用 Android)
 * ---------------------------------------------------------------------------
 * 适用场景: 用「VPN 模式抓包 App(HttpCanary/Reqable/Stream...) + 系统CA」时,
 *   App 因 ① 证书校验失败(pinning) 或 ② 检测到 tun0/VPN 而对敏感接口断网。
 *   本脚本同时绕过这两类, 让抓包 App 能拿到明文。
 *
 * 用法(App 完全起来后再 attach, 不要 spawn, 避开 legu 冷启动反调试):
 *   frida -H 127.0.0.1:14725 -F -l frida_bypass_full.js
 * 然后在抓包 App 里开 VPN 抓包, 再操作咪咕(登录/播放)。
 *
 * 说明:
 *   - 全程只做「类方法 hook」, 不做 Java.choose / 堆扫描, 避免 legu 查杀。
 *   - 每个 hook 独立 try/catch, 某个类不存在不影响其它。
 *   - 部分类(okhttp/自定义TM)可能晚加载或被混淆, 用轮询重试安装。
 *   - ENUM_TM 默认 false; 置 true 会枚举已加载类找自定义 X509TrustManager
 *     (枚举的是「已加载类列表」, 非堆对象, 一般不触发 legu; 仍有风险, 按需开)。
 * ---------------------------------------------------------------------------
 */
'use strict';

var ENUM_TM = false;          // true: 额外枚举自定义 TrustManager 并绕过
var LOG_HEADERS = true;       // true: 尝试打印 okhttp Request 的完整请求头
var HEADER_URL = /staticcache\/v2\/factor|miguvideo/i;  // 只打印命中此正则的请求头

function ts() { return new Date().toISOString().substr(11, 12); }
function log(t, m) { console.log('[' + ts() + '][' + t + '] ' + m); }

/* 轮询安装: 类可能晚加载, 反复试直到拿到 */
function onClass(name, cb, tries) {
    tries = tries === undefined ? 40 : tries;
    Java.perform(function () {
        var k = null;
        try { k = Java.use(name); } catch (e) { k = null; }
        if (k !== null) { try { cb(k); } catch (e2) { log('ERR', name + ' cb: ' + e2); } return; }
        if (tries > 0) setTimeout(function () { onClass(name, cb, tries - 1); }, 500);
    });
}

/* ========================= 一、SSL Pinning 绕过 ========================= */

/* 1) 全信任 TrustManager 注入到 SSLContext.init */
function hookSSLContext() {
    onClass('javax.net.ssl.SSLContext', function (SSLContext) {
        try {
            var X509TM = Java.registerClass({
                name: 'com.devin.AllTrustTM' + Math.floor(Math.random() * 1e6),
                implements: [Java.use('javax.net.ssl.X509TrustManager')],
                methods: {
                    checkClientTrusted: function () {},
                    checkServerTrusted: function () {},
                    getAcceptedIssuers: function () { return Java.array('java.security.cert.X509Certificate', []); }
                }
            });
            var TMs = [X509TM.$new()];
            SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
            ).implementation = function (km, tm, sr) {
                log('SSL', 'SSLContext.init -> 注入全信任 TrustManager');
                this.init(km, TMs, sr);
            };
            log('HOOK', 'SSLContext.init (全信任 TM)');
        } catch (e) { log('ERR', 'SSLContext: ' + e); }
    });
}

/* 2) Conscrypt TrustManagerImpl: checkServerTrusted / verifyChain / checkTrustedRecursive */
function hookConscryptTMImpl() {
    onClass('com.android.org.conscrypt.TrustManagerImpl', function (TMImpl) {
        try {
            var List = Java.use('java.util.ArrayList');
            // verifyChain(...) 返回原链(全部信任)
            if (TMImpl.verifyChain) {
                TMImpl.verifyChain.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        log('SSL', 'TrustManagerImpl.verifyChain -> bypass');
                        return arguments[0]; // 第一个参数即 untrustedChain
                    };
                });
                log('HOOK', 'TrustManagerImpl.verifyChain');
            }
            // checkTrustedRecursive(...) 返回空 list
            if (TMImpl.checkTrustedRecursive) {
                TMImpl.checkTrustedRecursive.overloads.forEach(function (ov) {
                    ov.implementation = function () { return List.$new(); };
                });
                log('HOOK', 'TrustManagerImpl.checkTrustedRecursive');
            }
            // checkServerTrusted(...) 直接放过(返回空 list 或 void)
            if (TMImpl.checkServerTrusted) {
                TMImpl.checkServerTrusted.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        try { return List.$new(); } catch (e) { return; }
                    };
                });
                log('HOOK', 'TrustManagerImpl.checkServerTrusted');
            }
        } catch (e) { log('ERR', 'TMImpl: ' + e); }
    });
}

/* 3) okhttp3 CertificatePinner.check / check$okhttp -> no-op (含常见混淆名) */
function hookOkHttpPinner() {
    ['okhttp3.CertificatePinner'].forEach(function (cn) {
        onClass(cn, function (CP) {
            try {
                ['check', 'check$okhttp'].forEach(function (mn) {
                    if (!CP[mn]) return;
                    CP[mn].overloads.forEach(function (ov) {
                        ov.implementation = function () {
                            log('SSL', cn + '.' + mn + ' -> bypass');
                            return;
                        };
                    });
                    log('HOOK', cn + '.' + mn);
                });
            } catch (e) { log('ERR', cn + ': ' + e); }
        });
    });
}

/* 4) HostnameVerifier 全放过 */
function hookHostnameVerifier() {
    onClass('okhttp3.internal.tls.OkHostnameVerifier', function (V) {
        try {
            V.verify.overloads.forEach(function (ov) {
                ov.implementation = function () { return true; };
            });
            log('HOOK', 'OkHostnameVerifier.verify -> true');
        } catch (e) { log('ERR', 'OkHostnameVerifier: ' + e); }
    });
    onClass('javax.net.ssl.HttpsURLConnection', function (H) {
        try {
            H.setDefaultHostnameVerifier.implementation = function (v) {
                log('SSL', 'HttpsURLConnection.setDefaultHostnameVerifier -> 忽略(全放过)');
            };
        } catch (e) {}
    });
}

/* 5) (可选) 枚举已加载类, 绕过自定义 X509TrustManager */
function hookCustomTrustManagers() {
    if (!ENUM_TM) return;
    Java.perform(function () {
        try {
            var List = Java.use('java.util.ArrayList');
            Java.enumerateLoadedClasses({
                onMatch: function (name) {
                    if (name.indexOf('TrustManager') === -1 && name.indexOf('X509') === -1) return;
                    try {
                        var k = Java.use(name);
                        if (k.checkServerTrusted) {
                            k.checkServerTrusted.overloads.forEach(function (ov) {
                                ov.implementation = function () { try { return List.$new(); } catch (e) { return; } };
                            });
                            log('HOOK', '自定义 TM: ' + name + '.checkServerTrusted');
                        }
                    } catch (e) {}
                },
                onComplete: function () { log('SSL', '自定义 TrustManager 枚举完成'); }
            });
        } catch (e) { log('ERR', 'enumTM: ' + e); }
    });
}

/* ========================= 二、VPN 检测 绕过 ========================= */
/*
 * 常见检测手段:
 *   a) NetworkInterface.getNetworkInterfaces() 里出现 tun0/ppp0/tap0
 *   b) NetworkCapabilities.hasTransport(TRANSPORT_VPN=4) == true
 *   c) NetworkCapabilities.hasCapability(NET_CAPABILITY_NOT_VPN=15) == false
 *   d) ConnectivityManager.getNetworkInfo(TYPE_VPN=17) != null
 *   e) System.getProperty("http.proxyHost") 探测代理
 */
function hookVpnDetection() {
    // a) 网卡名: tun0/ppp0/tap -> 改名隐藏
    onClass('java.net.NetworkInterface', function (NI) {
        try {
            NI.getName.implementation = function () {
                var n = this.getName.call(this);
                if (n && /^(tun|ppp|tap)\d*/i.test(n)) {
                    log('VPN', 'NetworkInterface.getName ' + n + ' -> dummy0(隐藏)');
                    return 'dummy0';
                }
                return n;
            };
            log('HOOK', 'NetworkInterface.getName (隐藏 tun/ppp/tap)');
        } catch (e) { log('ERR', 'NetworkInterface: ' + e); }
    });

    // b)+c) NetworkCapabilities
    onClass('android.net.NetworkCapabilities', function (NC) {
        try {
            NC.hasTransport.implementation = function (t) {
                if (t === 4) { log('VPN', 'NetworkCapabilities.hasTransport(VPN=4) -> false'); return false; }
                return this.hasTransport(t);
            };
            log('HOOK', 'NetworkCapabilities.hasTransport(VPN) -> false');
        } catch (e) {}
        try {
            NC.hasCapability.implementation = function (c) {
                if (c === 15) { log('VPN', 'NetworkCapabilities.hasCapability(NOT_VPN=15) -> true'); return true; }
                return this.hasCapability(c);
            };
            log('HOOK', 'NetworkCapabilities.hasCapability(NOT_VPN) -> true');
        } catch (e) {}
    });

    // d) ConnectivityManager.getNetworkInfo(TYPE_VPN=17) -> null
    onClass('android.net.ConnectivityManager', function (CM) {
        try {
            if (CM.getNetworkInfo) {
                CM.getNetworkInfo.overload('int').implementation = function (t) {
                    if (t === 17) { log('VPN', 'ConnectivityManager.getNetworkInfo(VPN=17) -> null'); return null; }
                    return this.getNetworkInfo(t);
                };
                log('HOOK', 'ConnectivityManager.getNetworkInfo(VPN) -> null');
            }
        } catch (e) {}
    });

    // e) 代理探测: System.getProperty("http(s).proxyHost/Port") -> null
    onClass('java.lang.System', function (S) {
        try {
            S.getProperty.overload('java.lang.String').implementation = function (k) {
                if (k && /proxy(Host|Port)/i.test(k)) { return null; }
                return this.getProperty(k);
            };
            log('HOOK', 'System.getProperty(proxy*) -> null');
        } catch (e) {}
    });
}

/* ========================= 三、(可选) 打印完整请求头 ========================= */
/* okhttp3.Request 构建完成时读 headers(); 只打印命中 HEADER_URL 的请求 */
function hookHeaderDump() {
    if (!LOG_HEADERS) return;
    onClass('okhttp3.Request', function (Req) {
        try {
            Req.toString.implementation = function () {
                var s = this.toString.call(this);
                try {
                    var url = '' + this.url();
                    if (HEADER_URL.test(url)) {
                        log('HDRS', 'okhttp Request url=' + url);
                        var h = this.headers();
                        var n = h.size();
                        for (var i = 0; i < n; i++) {
                            console.log('      ' + h.name(i) + ': ' + h.value(i));
                        }
                        log('HDRS', 'method=' + this.method());
                    }
                } catch (e) {}
                return s;
            };
            log('HOOK', 'okhttp3.Request (命中 URL 打印完整 headers)');
        } catch (e) { log('ERR', 'Request: ' + e); }
    }, 60);
}

/* ========================= 安装 ========================= */
Java.perform(function () {
    log('READY', 'frida_bypass_full.js 安装中 (SSL pinning + VPN 检测)...');
    hookSSLContext();
    hookConscryptTMImpl();
    hookOkHttpPinner();
    hookHostnameVerifier();
    hookCustomTrustManagers();
    hookVpnDetection();
    hookHeaderDump();
    log('READY', '已安装。现在去抓包 App 开 VPN 抓包, 再操作咪咕(登录/播放)。');
});
