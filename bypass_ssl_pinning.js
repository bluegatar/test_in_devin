/*
 * SSL Pinning Bypass — fixed native callback
 * Usage: frida -H 127.0.0.1:18999 -f com.janlent.ytb -l bypass_ssl_pinning.js
 */
"use strict";

// ==================== NATIVE ====================
(function () {
    var hooked = {};

    // Create a native callback that always returns ssl_verify_ok (0)
    // Signature: enum ssl_verify_result_t callback(SSL *ssl, uint8_t *out_alert)
    var alwaysOkCallback = new NativeCallback(function (ssl, out_alert) {
        return 0; // ssl_verify_ok
    }, "int", ["pointer", "pointer"]);

    var poll = setInterval(function () {
        ["libssl.so", "libjavacrypto.so"].forEach(function (lib) {
            if (hooked[lib]) return;
            if (!Process.findModuleByName(lib)) return;
            hooked[lib] = true;
            console.log("[+] " + lib);

            // SSL_set_custom_verify — replace callback with always-ok, keep mode as-is
            var scv = Module.findExportByName(lib, "SSL_set_custom_verify");
            if (scv) {
                Interceptor.attach(scv, {
                    onEnter: function (args) {
                        args[2] = alwaysOkCallback; // replace verify callback
                        console.log("[N] SSL_set_custom_verify → always ok");
                    }
                });
            }

            // SSL_CTX_set_custom_verify — same
            var ccv = Module.findExportByName(lib, "SSL_CTX_set_custom_verify");
            if (ccv) {
                Interceptor.attach(ccv, {
                    onEnter: function (args) {
                        args[2] = alwaysOkCallback;
                    }
                });
            }

            // SSL_get_verify_result — return 0 if it would fail
            var gvr = Module.findExportByName(lib, "SSL_get_verify_result");
            if (gvr) {
                Interceptor.attach(gvr, {
                    onLeave: function (r) {
                        if (r.toInt32() !== 0) {
                            console.log("[N] SSL_get_verify_result " + r + " → 0");
                            r.replace(ptr(0));
                        }
                    }
                });
            }
        });
        if (Object.keys(hooked).length >= 1) clearInterval(poll);
    }, 500);
})();

// ==================== JAVA ====================
Java.perform(function () {
    console.log("[*] Java hooks...");

    // 1. verifyChain — try-catch
    try {
        Java.use("com.android.org.conscrypt.TrustManagerImpl")
            .verifyChain.overloads.forEach(function (m) {
                m.implementation = function () {
                    try { return m.apply(this, arguments); }
                    catch (e) {
                        console.log("[J] verifyChain BLOCKED → bypass");
                        return Java.use("java.util.Arrays").asList(arguments[0]);
                    }
                };
            });
        console.log("[+] verifyChain");
    } catch (e) {}

    // 2. NSTM
    try {
        Java.use("android.security.net.config.NetworkSecurityTrustManager")
            .checkServerTrusted.overloads.forEach(function (m) {
                m.implementation = function () {
                    try { return m.apply(this, arguments); }
                    catch (e) {
                        console.log("[J] NSTM BLOCKED → bypass");
                        if (arguments.length >= 3) return Java.use("java.util.ArrayList").$new();
                    }
                };
            });
        console.log("[+] NSTM");
    } catch (e) {}

    // 3. OkHostnameVerifier
    try {
        Java.use("com.android.okhttp.internal.tls.OkHostnameVerifier")
            .verify.overloads.forEach(function (m) {
                m.implementation = function () {
                    var r = m.apply(this, arguments);
                    if (!r) { console.log("[J] OkHostnameVerifier → true"); return true; }
                    return r;
                };
            });
        console.log("[+] OkHostnameVerifier");
    } catch (e) {}

    // 4. CertificatePinner
    try {
        Java.use("com.android.okhttp.CertificatePinner").check.overloads.forEach(function (m) {
            m.implementation = function () {
                try { return m.apply(this, arguments); }
                catch (e) { console.log("[J] CertPinner → skip"); }
            };
        });
        console.log("[+] CertPinner");
    } catch (e) {}

    try {
        Java.use("okhttp3.CertificatePinner").check.overloads.forEach(function (m) {
            m.implementation = function () {
                try { return m.apply(this, arguments); }
                catch (e) {}
            };
        });
        console.log("[+] okhttp3");
    } catch (e) {}

    console.log("[*] Done (base hooks)");

    // ==================== TXVod: poll until class is loaded ====================
    var txHooked = false;
    var txPoll = setInterval(function () {
        if (txHooked) { clearInterval(txPoll); return; }
        Java.perform(function () {
            try {
                var found = false;
                Java.enumerateLoadedClasses({
                    onMatch: function (name) {
                        if (name === "com.tencent.rtmp.TXVodPlayer") found = true;
                    },
                    onComplete: function () {}
                });
                if (!found) return;

                var TXVodPlayer = Java.use("com.tencent.rtmp.TXVodPlayer");
                var TXVodPlayConfig = Java.use("com.tencent.rtmp.TXVodPlayConfig");

                TXVodPlayer.startPlay.overload("com.tencent.rtmp.TXPlayerAuthBuilder").implementation = function (builder) {
                    try { builder.setHttps(true); } catch (e) {}
                    try {
                        console.log("[TX] startPlay(auth) appId=" + builder.getAppId()
                            + " fileId=" + builder.getFileId()
                            + " timeout=" + builder.getTimeout()
                            + " us=" + builder.getUs()
                            + " exper=" + builder.getExper()
                            + " https=" + builder.isHttps());
                        console.log("[TX] sign=" + builder.getSign());
                    } catch (e) {
                        console.log("[TX] startPlay(auth) log err: " + e);
                    }
                    return this.startPlay.overload("com.tencent.rtmp.TXPlayerAuthBuilder").call(this, builder);
                };

                TXVodPlayer.startPlay.overload("java.lang.String").implementation = function (url) {
                    console.log("[TX] startPlay(url)=" + url);
                    return this.startPlay.overload("java.lang.String").call(this, url);
                };

                TXVodPlayer.setToken.overload("java.lang.String").implementation = function (token) {
                    console.log("[TX] setToken=" + token);
                    return this.setToken.overload("java.lang.String").call(this, token);
                };

                TXVodPlayConfig.setHeaders.overload("java.util.Map").implementation = function (headers) {
                    console.log("[TX] setHeaders=" + headers);
                    return this.setHeaders.overload("java.util.Map").call(this, headers);
                };

                TXVodPlayConfig.setExtInfo.overload("java.util.Map").implementation = function (info) {
                    console.log("[TX] setExtInfo=" + info);
                    return this.setExtInfo.overload("java.util.Map").call(this, info);
                };

                txHooked = true;
                clearInterval(txPoll);
                console.log("[+] TXVod hooks installed (delayed)");
            } catch (e) {
                console.log("[-] TXVod poll err: " + e);
            }
        });
    }, 2000);
});
