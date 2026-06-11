/*
 * frida_bypass_full_v2.js  ——  SSL Pinning + VPN 检测 双绕过 (加强版)
 * ---------------------------------------------------------------------------
 * v1 现象: hook 都生效了(CertificatePinner.check 被绕过, VPN 也返 false), 但
 *   登录请求 passport.migu.cn:8443 仍报 "网络不给力 YJ102226", 去掉 VPN 就正常。
 *
 * 关键诊断: 登录失败但**没有任何 [SSL] TrustManagerImpl 日志** → 说明 MITM 证书的
 *   信任校验**没走 TrustManagerImpl**, 或登录用的 OkHttpClient 在我们 attach 之前
 *   就建好了(自带 TrustManager/pinning)。光绕 CertificatePinner 不够, 还要把
 *   **握手期的信任链校验**整条放过。本版加:
 *     - TrustManagerImpl 全部 overload + 打日志(确认是否被调用)
 *     - X509TrustManagerExtensions.checkServerTrusted
 *     - Conscrypt Platform.checkServerTrusted / checkClientTrusted
 *     - okhttp3 CertificateChainCleaner.clean -> 原样返回
 *     - Certificate Transparency(appmattus) 放过(若存在)
 *     - ENUM_TM 默认 true: 枚举已加载的自定义 X509TrustManager 并绕过
 *   VPN 日志改为节流, 避免刷屏。
 *
 * 用法(App 起来后 attach):
 *   frida -H 127.0.0.1:14725 -F -l frida_bypass_full_v2.js
 *
 * !!! 同时务必确认两件抓包 App 侧的事(很可能才是真因) !!!
 *   1) 抓包 App 的 CA 必须装进**系统证书库**(root 机), 不能只在「用户证书」。
 *      Android 7+ 默认不信任用户 CA, 应用层会拒绝 MITM 证书。
 *   2) 抓包 App 必须**解密 8443 端口**。多数抓包 App 默认只解 443,
 *      passport.migu.cn 走的是 :8443, 要把 8443 加进 HTTPS/SSL 解密端口列表
 *      (HttpCanary: 设置→SSL端口; Reqable: HTTPS 解密端口里加 8443)。
 * ---------------------------------------------------------------------------
 */
'use strict';

var ENUM_TM = true;           // 枚举自定义 X509TrustManager 并绕过
var LOG_HEADERS = true;
var HEADER_URL = /passport\.migu|staticcache\/v2\/factor|miguvideo/i;

function ts() { return new Date().toISOString().substr(11, 12); }
function log(t, m) { console.log('[' + ts() + '][' + t + '] ' + m); }

var _lastVpn = {};
function vlog(key, m) { var n = Date.now(); if (!_lastVpn[key] || n - _lastVpn[key] > 3000) { _lastVpn[key] = n; log('VPN', m); } }

function onClass(name, cb, tries) {
    tries = tries === undefined ? 40 : tries;
    Java.perform(function () {
        var k = null;
        try { k = Java.use(name); } catch (e) { k = null; }
        if (k !== null) { try { cb(k); } catch (e2) { log('ERR', name + ' cb: ' + e2); } return; }
        if (tries > 0) setTimeout(function () { onClass(name, cb, tries - 1); }, 500);
    });
}

/* ========================= 一、SSL / 信任链 全绕过 ========================= */

function hookSSLContext() {
    onClass('javax.net.ssl.SSLContext', function (SSLContext) {
        try {
            var TM = Java.registerClass({
                name: 'com.devin.AllTrustTM' + Math.floor(Math.random() * 1e6),
                implements: [Java.use('javax.net.ssl.X509TrustManager')],
                methods: {
                    checkClientTrusted: function () {},
                    checkServerTrusted: function () {},
                    getAcceptedIssuers: function () { return Java.array('java.security.cert.X509Certificate', []); }
                }
            });
            var TMs = [TM.$new()];
            SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
                .implementation = function (km, tm, sr) { log('SSL', 'SSLContext.init -> 注入全信任 TM'); this.init(km, TMs, sr); };
            log('HOOK', 'SSLContext.init');
        } catch (e) { log('ERR', 'SSLContext: ' + e); }
    });
}

function hookConscryptTMImpl() {
    onClass('com.android.org.conscrypt.TrustManagerImpl', function (T) {
        var List = Java.use('java.util.ArrayList');
        try {
            T.verifyChain.overloads.forEach(function (ov) {
                ov.implementation = function () { log('SSL', 'TrustManagerImpl.verifyChain -> bypass'); return arguments[0]; };
            });
            log('HOOK', 'TrustManagerImpl.verifyChain (' + T.verifyChain.overloads.length + ')');
        } catch (e) {}
        try {
            T.checkTrustedRecursive.overloads.forEach(function (ov) {
                ov.implementation = function () { log('SSL', 'TrustManagerImpl.checkTrustedRecursive -> []'); return List.$new(); };
            });
            log('HOOK', 'TrustManagerImpl.checkTrustedRecursive');
        } catch (e) {}
        try {
            T.checkServerTrusted.overloads.forEach(function (ov) {
                ov.implementation = function () { log('SSL', 'TrustManagerImpl.checkServerTrusted -> []'); try { return List.$new(); } catch (e) { return; } };
            });
            log('HOOK', 'TrustManagerImpl.checkServerTrusted (' + T.checkServerTrusted.overloads.length + ')');
        } catch (e) {}
    });
}

function hookX509Extensions() {
    onClass('android.net.http.X509TrustManagerExtensions', function (X) {
        try {
            var List = Java.use('java.util.ArrayList');
            X.checkServerTrusted.implementation = function () { log('SSL', 'X509TrustManagerExtensions.checkServerTrusted -> []'); return List.$new(); };
            log('HOOK', 'X509TrustManagerExtensions.checkServerTrusted');
        } catch (e) { log('ERR', 'X509Ext: ' + e); }
    });
}

function hookConscryptPlatform() {
    onClass('com.android.org.conscrypt.Platform', function (P) {
        ['checkServerTrusted', 'checkClientTrusted'].forEach(function (mn) {
            try {
                if (!P[mn]) return;
                P[mn].overloads.forEach(function (ov) { ov.implementation = function () { log('SSL', 'Conscrypt.Platform.' + mn + ' -> bypass'); }; });
                log('HOOK', 'Conscrypt.Platform.' + mn);
            } catch (e) {}
        });
    });
}

function hookOkHttp() {
    onClass('okhttp3.CertificatePinner', function (CP) {
        ['check', 'check$okhttp'].forEach(function (mn) {
            try {
                if (!CP[mn]) return;
                CP[mn].overloads.forEach(function (ov) { ov.implementation = function () { log('SSL', 'CertificatePinner.' + mn + ' -> bypass'); }; });
                log('HOOK', 'CertificatePinner.' + mn);
            } catch (e) {}
        });
    });
    // CertificateChainCleaner.clean(chain, host) -> 原样返回, 防止它对 MITM 链抛异常
    onClass('okhttp3.internal.tls.CertificateChainCleaner', function (C) {
        try {
            C.clean.overloads.forEach(function (ov) {
                ov.implementation = function () { log('SSL', 'CertificateChainCleaner.clean -> 原样返回'); return arguments[0]; };
            });
            log('HOOK', 'CertificateChainCleaner.clean');
        } catch (e) {}
    });
    onClass('okhttp3.internal.tls.OkHostnameVerifier', function (V) {
        try { V.verify.overloads.forEach(function (ov) { ov.implementation = function () { return true; }; }); log('HOOK', 'OkHostnameVerifier.verify -> true'); } catch (e) {}
    });
}

// Certificate Transparency (appmattus 库, 很多 App 用它做 CT 校验)
function hookCT() {
    onClass('com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor', function (CT) {
        try { CT.intercept.implementation = function (chain) { log('SSL', 'CT Interceptor -> 放过'); return chain.proceed(chain.request()); }; log('HOOK', 'appmattus CT Interceptor'); } catch (e) {}
    }, 60);
}

function hookCustomTrustManagers() {
    if (!ENUM_TM) return;
    Java.perform(function () {
        try {
            var List = Java.use('java.util.ArrayList');
            Java.enumerateLoadedClasses({
                onMatch: function (name) {
                    if (name.indexOf('TrustManager') === -1 && name.indexOf('X509') === -1) return;
                    if (name.indexOf('com.android.org.conscrypt.TrustManagerImpl') !== -1) return; // 已单独处理
                    try {
                        var k = Java.use(name);
                        if (k.checkServerTrusted) {
                            k.checkServerTrusted.overloads.forEach(function (ov) {
                                ov.implementation = function () { log('SSL', '自定义TM ' + name + '.checkServerTrusted -> bypass'); try { return List.$new(); } catch (e) { return; } };
                            });
                            log('HOOK', '自定义TM: ' + name);
                        }
                    } catch (e) {}
                },
                onComplete: function () { log('SSL', '自定义 TrustManager 枚举完成'); }
            });
        } catch (e) { log('ERR', 'enumTM: ' + e); }
    });
}

/* ========================= 二、VPN 检测 绕过(节流日志) ========================= */
function hookVpnDetection() {
    onClass('java.net.NetworkInterface', function (NI) {
        try {
            NI.getName.implementation = function () {
                var n = this.getName.call(this);
                if (n && /^(tun|ppp|tap)\d*/i.test(n)) { vlog('ni', 'NetworkInterface.getName ' + n + ' -> dummy0'); return 'dummy0'; }
                return n;
            };
            log('HOOK', 'NetworkInterface.getName');
        } catch (e) {}
    });
    onClass('android.net.NetworkCapabilities', function (NC) {
        try { NC.hasTransport.implementation = function (t) { if (t === 4) { vlog('htv', 'hasTransport(VPN=4) -> false'); return false; } return this.hasTransport(t); }; log('HOOK', 'NetworkCapabilities.hasTransport(VPN)'); } catch (e) {}
        try { NC.hasCapability.implementation = function (c) { if (c === 15) { vlog('hcv', 'hasCapability(NOT_VPN=15) -> true'); return true; } return this.hasCapability(c); }; log('HOOK', 'NetworkCapabilities.hasCapability(NOT_VPN)'); } catch (e) {}
    });
    onClass('android.net.ConnectivityManager', function (CM) {
        try { if (CM.getNetworkInfo) { CM.getNetworkInfo.overload('int').implementation = function (t) { if (t === 17) { vlog('gni', 'getNetworkInfo(VPN=17) -> null'); return null; } return this.getNetworkInfo(t); }; log('HOOK', 'ConnectivityManager.getNetworkInfo(VPN)'); } } catch (e) {}
    });
    onClass('java.lang.System', function (S) {
        try { S.getProperty.overload('java.lang.String').implementation = function (k) { if (k && /proxy(Host|Port)/i.test(k)) return null; return this.getProperty(k); }; log('HOOK', 'System.getProperty(proxy*)'); } catch (e) {}
    });
}

/* ========================= 三、命中 URL 打印完整请求头 ========================= */
function hookHeaderDump() {
    if (!LOG_HEADERS) return;
    onClass('okhttp3.Request', function (Req) {
        try {
            Req.toString.implementation = function () {
                var s = this.toString.call(this);
                try {
                    var url = '' + this.url();
                    if (HEADER_URL.test(url)) {
                        log('HDRS', 'okhttp ' + this.method() + ' ' + url);
                        var h = this.headers(), n = h.size();
                        for (var i = 0; i < n; i++) console.log('      ' + h.name(i) + ': ' + h.value(i));
                    }
                } catch (e) {}
                return s;
            };
            log('HOOK', 'okhttp3.Request headers dump');
        } catch (e) {}
    }, 60);
}

/* ========================= 安装 ========================= */
Java.perform(function () {
    log('READY', 'v2 安装中 (信任链全绕过 + VPN + CT + 自定义TM)...');
    hookSSLContext();
    hookConscryptTMImpl();
    hookX509Extensions();
    hookConscryptPlatform();
    hookOkHttp();
    hookCT();
    hookVpnDetection();
    hookHeaderDump();
    // 枚举自定义 TM 放最后, 给类加载留时间
    setTimeout(hookCustomTrustManagers, 1500);
    log('READY', '已安装。务必同时确认: ①抓包App的CA在系统证书库 ②抓包App已解密8443端口。');
});
