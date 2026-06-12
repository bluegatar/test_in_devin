/*
 * frida_factor_trace_v14.js  —— 确认 factor 存在哪个 MMKV 文件
 * -------------------------------------------------------------------------
 * v13 发现: getPlayUrlFactorBeanFromLocal 窗口内**没有 FileInputStream** →
 *           它是用 MMKV(内存映射, 不走 FileInputStream)读的; 而 MMKV 类确实存在
 *           (v13 报 encodeString 签名是 (long,String,String))。v13 的 MMKV 钩子
 *           绑错了重载没生效。v14 用「遍历所有重载」的方式正确钩 MMKV, 抓出:
 *             - 读/写 factor 用的 key
 *             - 对应 MMKV 的 mmapID(=磁盘文件名)
 *             - MMKV 的 rootDir(自定义根目录, 很可能就是 .mla)
 *
 * 全程不用 Java.choose, 防崩。
 * 用法: frida -H 127.0.0.1:14725 -F -l frida_factor_trace_v14.js
 *   连上后进一次播放页 → 看 [MMKV]/[OPEN]/[ROOT]
 *   [MMKV] 里 key 命中 play_url_factor 的那条会同时打印 mmapID → 文件就是
 *          <rootDir>/<mmapID> (默认 rootDir = /data/user/0/<pkg>/files/mmkv)
 * -------------------------------------------------------------------------
 */
'use strict';

var MGR = 'com.cmvideo.capability.mguniformmpbusiness.playerconfig.PlayUrlFactorManager';
var KEYHINT = /play_url_factor|playUrlFactor|factor_bean/i;

function ts() { return new Date().toISOString().substr(11, 12); }
function log(t, m) { console.log('[' + ts() + '][' + t + '] ' + m); }
function asStr(v, max) { max = max || 500; if (v === null || v === undefined) return 'null'; var s; try { s = '' + v; } catch (e) { s = '<' + e + '>'; } if (s.length > max) s = s.substring(0, max) + '...(len=' + s.length + ')'; return s; }
function mmapId(o) { try { return o.mmapID(); } catch (e) { try { return o.mmapID.call(o); } catch (e2) { return '?'; } } }

var inIO = null;

Java.perform(function () {
    // 包裹 manager 本地读写, 标记窗口
    var t = 0, tm = setInterval(function () {
        t++;
        try {
            var M = Java.use(MGR);
            clearInterval(tm);
            Java.perform(function () {
                ['getPlayUrlFactorBeanFromLocal', 'savePlayUrlFactorBeanToLocal'].forEach(function (name) {
                    try {
                        if (!M[name]) return;
                        M[name].overloads.forEach(function (ov) {
                            ov.implementation = function () { var p = inIO; inIO = name; try { return ov.apply(this, arguments); } finally { inIO = p; } };
                        });
                        log('HOOK', 'MGR.' + name);
                    } catch (e) { log('SKIP', 'MGR.' + name + ' ' + e); }
                });
                log('READY', 'v14: 进一次播放页, 看 [MMKV]/[OPEN]/[ROOT]');
            });
        } catch (e) { if (t % 25 === 0) log('WAIT', 'MGR 未加载(' + t + ')'); if (t > 1500) clearInterval(tm); }
    }, 200);

    var MMKV;
    try { MMKV = Java.use('com.tencent.mmkv.MMKV'); }
    catch (e) { log('SKIP', 'MMKV 类不存在: ' + e); return; }

    function firstString(args) { for (var i = 0; i < args.length; i++) { try { if (typeof args[i] === 'string') return args[i]; var s = '' + args[i]; if (s && s.length < 200 && /[a-zA-Z_]/.test(s) && (typeof args[i] !== 'number')) { /*best effort*/ } } catch (e) {} } return null; }
    function keyOf(args) {
        // (long handle, String key, String val) → args[1]; (String key, ...) → args[0]
        if (args.length >= 2 && typeof args[1] === 'string') return args[1];
        if (args.length >= 1 && typeof args[0] === 'string') return args[0];
        return null;
    }

    ['decodeString', 'encodeString', 'getString', 'putString'].forEach(function (mn) {
        try {
            if (!MMKV[mn]) return;
            MMKV[mn].overloads.forEach(function (ov, idx) {
                ov.implementation = function () {
                    var a = arguments, r;
                    var k = null; try { k = keyOf(a); } catch (e) {}
                    var fire = false; try { fire = (inIO !== null) || (k && KEYHINT.test(k)); } catch (e) {}
                    r = ov.apply(this, a);
                    if (fire) {
                        try {
                            var val = (mn.indexOf('decode') === 0 || mn.indexOf('get') === 0) ? r : (a.length >= 3 ? a[2] : (a.length >= 2 ? a[1] : null));
                            log('MMKV', mn + '  mmapID=' + mmapId(this) + '  key=' + asStr(k, 120) + '  val=' + asStr(val, 400) + (inIO ? '  (在' + inIO + ')' : ''));
                        } catch (e) {}
                    }
                    return r;
                };
            });
            log('HOOK', 'MMKV.' + mn + ' (' + MMKV[mn].overloads.length + '个重载)');
        } catch (e) { log('SKIP', 'MMKV.' + mn + ' ' + e); }
    });

    // 哪些 MMKV 被打开(mmapID), 以及自定义根目录
    ['mmkvWithID', 'getMMKVWithID'].forEach(function (mn) {
        try {
            if (!MMKV[mn]) return;
            MMKV[mn].overloads.forEach(function (ov) {
                ov.implementation = function () { var r = ov.apply(this, arguments); try { log('OPEN', mn + '(' + asStr(arguments[0], 120) + ') -> mmapID=' + mmapId(r)); } catch (e) {} return r; };
            });
            log('HOOK', 'MMKV.' + mn);
        } catch (e) {}
    });
    ['initialize', 'initializeWithRoot'].forEach(function (mn) {
        try {
            if (!MMKV[mn]) return;
            MMKV[mn].overloads.forEach(function (ov) {
                ov.implementation = function () { try { log('ROOT', mn + '(' + asStr(arguments[0], 200) + ')'); } catch (e) {} return ov.apply(this, arguments); };
            });
        } catch (e) {}
    });
    try { log('ROOT', '当前 rootDir = ' + MMKV.getRootDir()); } catch (e) {}
});
