/*
 * frida_factor_trace_v15.js  —— 打印 factor 在 mmkv.default 里的「完整缓存条目」
 * -------------------------------------------------------------------------
 * v14 已确认:
 *   - factor 值缓存: MMKV 文件 SPHelperEncrypt, key=key_play_url_factor_bean_PlayUrl
 *       => /data/user/0/com.cmcc.cmvideo/files/mmkv/SPHelperEncrypt
 *   - mmkv.default 里有一堆 {"headers":{...}} 的「静态缓存(staticcache)请求/响应缓存」,
 *     按 MD5(url) 为 key, 但 v14 里被截断了, 看不全。
 *
 * v15: 把含 factor 特征(E8Km.. 或 "sv":"10001" 或 staticcache/v2/factor) 的
 *      mmkv.default 条目**完整、不截断**打印出来(分块打印, 避免单行过长丢失),
 *      从而拿到 factor 请求**真实的完整 headers + 响应 body**。
 *
 * 全程不用 Java.choose。
 * 用法: frida -H 127.0.0.1:14725 -F -l frida_factor_trace_v15.js
 *   连上后进一次播放页 → 看 [FULL]
 * -------------------------------------------------------------------------
 */
'use strict';

var SIG = /E8KmOzDHdgb0EGGi9uBJRw|"sv"\s*:\s*"10001"|staticcache\/v2\/factor|videox\/staticcache\/v2\/factor/;
var FACTOR_KEY = /play_url_factor|factor_bean/i;

function ts() { return new Date().toISOString().substr(11, 12); }
function log(t, m) { console.log('[' + ts() + '][' + t + '] ' + m); }
function mmapId(o) { try { return o.mmapID(); } catch (e) { return '?'; } }
function keyOf(a) { if (a.length >= 2 && typeof a[1] === 'string') return a[1]; if (a.length >= 1 && typeof a[0] === 'string') return a[0]; return null; }

function printFull(tag, header, s) {
    log(tag, header + '  (总长=' + s.length + ')');
    var CH = 1800;
    for (var i = 0; i < s.length; i += CH) console.log('    ' + s.substring(i, i + CH));
}

var printed = {}; // 去重: 同一条只打一次

Java.perform(function () {
    var MMKV;
    try { MMKV = Java.use('com.tencent.mmkv.MMKV'); }
    catch (e) { log('SKIP', 'MMKV 不存在 ' + e); return; }

    ['decodeString', 'getString'].forEach(function (mn) {
        try {
            if (!MMKV[mn]) return;
            MMKV[mn].overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var a = arguments, r = ov.apply(this, a);
                    try {
                        var fv = (r === null || r === undefined) ? '' : ('' + r);
                        var k = keyOf(a);
                        var id = mmapId(this);
                        // factor 值缓存
                        if (k && FACTOR_KEY.test(k)) log('FACTORVAL', id + ' / ' + k + ' = ' + fv);
                        // staticcache 请求缓存(含 headers + body)
                        if (fv && SIG.test(fv)) {
                            var dk = id + '|' + (k || '');
                            if (!printed[dk]) { printed[dk] = 1; printFull('FULL', '[' + mn + '] mmapID=' + id + '  key=' + (k || '<空>'), fv); }
                        }
                    } catch (e) {}
                    return r;
                };
            });
            log('HOOK', 'MMKV.' + mn + ' (' + MMKV[mn].overloads.length + ')');
        } catch (e) { log('SKIP', 'MMKV.' + mn + ' ' + e); }
    });
    log('READY', 'v15 已安装。进一次播放页, 看 [FULL](factor 请求的完整 headers+body) 与 [FACTORVAL]');
});
