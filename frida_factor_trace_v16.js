/*
 * frida_factor_trace_v16.js  —— 在 App 内直接抓 factor 请求(headers)+响应, 并能强制触发
 * -------------------------------------------------------------------------
 * 为什么不靠 ecapture / 读缓存:
 *  - factor 自己的缓存(MMKV SPHelperEncrypt / key_play_url_factor_bean_PlayUrl)只存
 *    «处理后的结果» {"factor":..,"sv":"10001","tid":"android","updateTime":..}，**不含 headers**。
 *  - mmkv.default 里那些 {"headers":{...}} 是**别的** staticcache 接口的缓存，不是 factor。
 *  - ecapture 默认 uprobe libssl，对 Conscrypt(BoringSSL 静态链接)/QUIC 抓不到。
 *  - updateTime 每次启动都在变 → factor 是**每次启动重新拉的**，所以一定有网络请求，
 *    在 App 内 NetworkManager 层 + 回调层抓最稳(不受 SSL 库/pinning/QUIC 影响)。
 *
 * v16 做:
 *  [REQ]  钩 NetworkManager.get/post/postBody/put/del，命中 factor/staticcache/app-management
 *         打印 **完整参数(url + headers Map + params)** + 调用栈
 *  [RESP] 钩回调 PlayUrlFactorManager$initPlayUrlFactorBean$1 的 onSuccess/onFail，打印响应
 *  [SAVE] 钩 PlayUrlFactorManager.savePlayUrlFactorBeanToLocal，证明刚拉到新数据
 *  forceFactor():  不堆扫。经 ServiceCenterKt.getService(IPlayerConfig) 拿到活的
 *         PlayerConfigPool → 反射读 playUrlFactorManager → 临时让本地缓存返回 null →
 *         调 pool.init() / manager.initPlayUrlFactorBean() 逼它真正走网络。
 *
 * 用法: frida -H 127.0.0.1:14725 -F -l frida_factor_trace_v16.js
 *   连上后 REPL 手敲: forceFactor()   → 看 [REQ]/[RESP]/[SAVE]
 * -------------------------------------------------------------------------
 */
'use strict';

var NM   = 'com.cmvideo.capability.network.NetworkManager';
var POOL = 'com.cmvideo.capability.mguniformmpbusiness.playerconfig.PlayerConfigPool';
var MGR  = 'com.cmvideo.capability.mguniformmpbusiness.playerconfig.PlayUrlFactorManager';
var OBS  = 'com.cmvideo.capability.mguniformmpbusiness.playerconfig.PlayUrlFactorManager$initPlayUrlFactorBean$1';
var SC   = 'com.cmvideo.output.service.ioc.ServiceCenterKt';
var IPC  = 'com.cmvideo.output.service.biz.player.IPlayerConfig';
var HINT = /factor|staticcache|app-management|appmanagement/i;
var FACTOR_KEY = /play_url_factor|factor_bean/i;

function ts() { return new Date().toISOString().substr(11, 12); }
function log(t, m) { console.log('[' + ts() + '][' + t + '] ' + m); }
function jstack() { try { var E = Java.use('java.lang.Exception'); var L = Java.use('android.util.Log'); return L.getStackTraceString(E.$new()); } catch (e) { return '<' + e + '>'; } }
function asStr(v, max) { max = max || 3000; if (v === null || v === undefined) return 'null'; var s; try { s = '' + v; } catch (e) { s = '<' + e + '>'; } if (s.length > max) s = s.substring(0, max) + '...(len=' + s.length + ')'; return s; }
function readField(obj, name) { try { var c = obj.getClass(), g = 0; while (c !== null && g++ < 8) { var fs = c.getDeclaredFields(); for (var i = 0; i < fs.length; i++) if (fs[i].getName() === name) { fs[i].setAccessible(true); return fs[i].get(obj); } c = c.getSuperclass(); } } catch (e) {} return null; }

var armNull = false;

Java.perform(function () {
    // 让 factor 本地读取在 force 时返回 null (类级, 不堆扫)
    waitAndDo(MGR, function (M) {
        try { M.getPlayUrlFactorBeanFromLocal.overloads.forEach(function (ov) { ov.implementation = function () { if (armNull) { log('FORCE', 'getPlayUrlFactorBeanFromLocal -> null'); return null; } return ov.apply(this, arguments); }; }); log('HOOK', 'MGR.getPlayUrlFactorBeanFromLocal'); } catch (e) {}
        try { M.savePlayUrlFactorBeanToLocal.overloads.forEach(function (ov) { ov.implementation = function () { var a = arguments, d = []; for (var i = 0; i < a.length; i++) d.push(asStr(a[i], 1200)); log('SAVE', 'savePlayUrlFactorBeanToLocal(' + d.join(' || ') + ')'); log('SAVE', jstack()); return ov.apply(this, a); }; }); log('HOOK', 'MGR.savePlayUrlFactorBeanToLocal'); } catch (e) {}
    });

    // 回调 onSuccess/onFail
    waitAndDo(OBS, function (O) {
        ['onSuccess', 'onFail', 'onSuccessAsync', 'onError'].forEach(function (mn) {
            try { if (!O[mn]) return; O[mn].overloads.forEach(function (ov) { ov.implementation = function () { var a = arguments, d = []; for (var i = 0; i < a.length; i++) d.push(asStr(a[i], 4000)); log('RESP', mn + '(' + d.join(' || ') + ')'); log('RESP', jstack()); return ov.apply(this, a); }; }); log('HOOK', 'OBS.' + mn); } catch (e) {}
        });
    });

    // NetworkManager 请求层
    waitAndDo(NM, function (N) {
        ['get', 'post', 'postBody', 'put', 'del'].forEach(function (mn) {
            try {
                if (!N[mn]) return;
                N[mn].overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        var a = arguments;
                        try { var p = a.length ? ('' + a[0]) : ''; if (HINT.test(p)) { log('REQ', '>>> NetworkManager.' + mn + '()'); for (var i = 0; i < a.length; i++) log('REQ', '   arg[' + i + '] = ' + asStr(a[i], 4000)); log('REQ', jstack()); } } catch (e) {}
                        return ov.apply(this, a);
                    };
                });
                log('HOOK', 'NM.' + mn + ' (' + N[mn].overloads.length + ')');
            } catch (e) {}
        });
        log('READY', 'v16 已安装。REPL 手敲: forceFactor()');
    });
});

global.forceFactor = function () {
    Java.perform(function () {
        armNull = true;
        log('FORCE', '经 ServiceCenter 拿 PlayerConfigPool 并强制重拉 factor...');
        try {
            var SCu = Java.use(SC), IPCu = Java.use(IPC);
            var svc = null;
            try { svc = SCu.getService(IPCu.class); } catch (e) { log('FORCE', 'getService(IPlayerConfig.class) 失败: ' + e); }
            if (svc !== null) {
                log('FORCE', 'IPlayerConfig 实例 = ' + svc);
                try {
                    var Pool = Java.use(POOL);
                    var pool = Java.cast(svc, Pool);
                    // 先反射读 manager 并直接 init
                    var mgr = readField(pool, 'playUrlFactorManager');
                    var jsmgr = readField(pool, 'jsPlayUrlFactorManager');
                    log('FORCE', 'playUrlFactorManager = ' + mgr);
                    try { if (mgr !== null) { var Mu = Java.use(MGR); var m = Java.cast(mgr, Mu); m.initPlayUrlFactorBean.overloads.forEach(function (ov) { if (ov.argumentTypes.length === 0) { log('FORCE', 'manager.initPlayUrlFactorBean()'); ov.call(m); } }); } } catch (e) { log('FORCE', 'mgr.init ' + e); }
                    try { pool.init.overloads.forEach(function (ov) { if (ov.argumentTypes.length === 0) { log('FORCE', 'pool.init()'); ov.call(pool); } }); } catch (e) { log('FORCE', 'pool.init ' + e); }
                } catch (e) { log('FORCE', 'cast/await ' + e); }
            } else {
                log('FORCE', 'svc 为 null —— 改用其它方式');
            }
        } catch (e) { log('FORCE', e); }
        setTimeout(function () { armNull = false; log('FORCE', '已恢复本地读取正常'); }, 8000);
        log('FORCE', '完成, 观察 [REQ]/[RESP]/[SAVE]');
    });
    return 'forceFactor dispatched';
};

function waitAndDo(cls, fn) {
    var t = 0, timer = setInterval(function () {
        t++;
        try { var C = Java.use(cls); clearInterval(timer); Java.perform(function () { try { fn(C); } catch (e) { log('ERR', cls + ' ' + e); } }); }
        catch (e) { if (t % 50 === 0) log('WAIT', cls.split('.').pop() + ' 未加载(' + t + ')'); if (t > 2000) clearInterval(timer); }
    }, 200);
}
