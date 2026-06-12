/*
 * frida_factor_trace_v17.js  —— 正确打印 headers Map + 自动强制触发 factor 请求
 * -------------------------------------------------------------------------
 * v16 已证实: NetworkManager.get(url, headersMap, params, int, retryCfg, Observer)
 *   启动时有一大批 app-management/staticcache 请求; 但 arg[1](headers Map)被错误地
 *   打成 "[object Object]"。v17 修复: 把 Java Map 用 entrySet 逐项打印。
 * 另: factor 请求平时走本地缓存不发, 需要 forceFactor() 强制; v17 在装好钩子后
 *   **自动**调用一次 forceFactor()(也保留 REPL 手敲), 以防进程被 legu 周期性查杀。
 *
 * 输出:
 *   [REQ]  仅打印 factor 那条(/staticcache/v2/factor) 的 url + **完整 headers** + params + 栈
 *   [HDRS] 顺带把**第一条** staticcache 请求的 headers 打一次(它的全局公共头与 factor 相同)
 *   [RESP] 回调 onSuccess/onError 的响应
 *   [SAVE] savePlayUrlFactorBeanToLocal(刚拉到新数据)
 * -------------------------------------------------------------------------
 */
'use strict';

var NM   = 'com.cmvideo.capability.network.NetworkManager';
var POOL = 'com.cmvideo.capability.mguniformmpbusiness.playerconfig.PlayerConfigPool';
var MGR  = 'com.cmvideo.capability.mguniformmpbusiness.playerconfig.PlayUrlFactorManager';
var OBS  = 'com.cmvideo.capability.mguniformmpbusiness.playerconfig.PlayUrlFactorManager$initPlayUrlFactorBean$1';
var SC   = 'com.cmvideo.output.service.ioc.ServiceCenterKt';
var IPC  = 'com.cmvideo.output.service.biz.player.IPlayerConfig';
var FACTOR_URL = /staticcache\/v2\/factor/i;
var STATIC = /staticcache|app-management/i;
var FACTOR_KEY = /play_url_factor|factor_bean/i;

function ts() { return new Date().toISOString().substr(11, 12); }
function log(t, m) { console.log('[' + ts() + '][' + t + '] ' + m); }
function jstack() { try { var E = Java.use('java.lang.Exception'); var L = Java.use('android.util.Log'); return L.getStackTraceString(E.$new()); } catch (e) { return '<' + e + '>'; } }

function jstr(v, max) {
    max = max || 4000;
    if (v === null || v === undefined) return 'null';
    var s;
    try { s = v.toString(); } catch (e) { try { s = '' + v; } catch (e2) { s = '<' + e2 + '>'; } }
    if (s === '[object Object]') { try { s = Java.use('java.lang.String').valueOf(v); } catch (e) {} }
    if (s && s.length > max) s = s.substring(0, max) + '...(len=' + s.length + ')';
    return s;
}

// 把任意对象当 Map 逐项打印; 失败则退回 jstr
function dumpMap(tag, label, obj) {
    if (obj === null || obj === undefined) { log(tag, label + ' = null'); return; }
    try {
        var Map = Java.use('java.util.Map');
        var m = Java.cast(obj, Map);
        var it = m.entrySet().iterator();
        var lines = [];
        while (it.hasNext()) { var e = it.next(); var Entry = Java.use('java.util.Map$Entry'); var en = Java.cast(e, Entry); lines.push('      ' + jstr(en.getKey(), 200) + ' : ' + jstr(en.getValue(), 1500)); }
        log(tag, label + ' (Map, ' + lines.length + ' 项):');
        lines.forEach(function (l) { console.log(l); });
    } catch (e) { log(tag, label + ' = ' + jstr(obj, 4000) + '  (非Map: ' + e + ')'); }
}

function readField(obj, name) { try { var c = obj.getClass(), g = 0; while (c !== null && g++ < 8) { var fs = c.getDeclaredFields(); for (var i = 0; i < fs.length; i++) if (fs[i].getName() === name) { fs[i].setAccessible(true); return fs[i].get(obj); } c = c.getSuperclass(); } } catch (e) {} return null; }

var armNull = false, sampled = false;

Java.perform(function () {
    waitAndDo(MGR, function (M) {
        try { M.getPlayUrlFactorBeanFromLocal.overloads.forEach(function (ov) { ov.implementation = function () { if (armNull) { log('FORCE', 'getPlayUrlFactorBeanFromLocal -> null'); return null; } return ov.apply(this, arguments); }; }); log('HOOK', 'MGR.getPlayUrlFactorBeanFromLocal'); } catch (e) {}
        try { M.savePlayUrlFactorBeanToLocal.overloads.forEach(function (ov) { ov.implementation = function () { var a = arguments, d = []; for (var i = 0; i < a.length; i++) d.push(jstr(a[i], 1500)); log('SAVE', 'savePlayUrlFactorBeanToLocal(' + d.join(' || ') + ')'); return ov.apply(this, a); }; }); log('HOOK', 'MGR.savePlayUrlFactorBeanToLocal'); } catch (e) {}
    });

    waitAndDo(OBS, function (O) {
        ['onSuccess', 'onFail', 'onError'].forEach(function (mn) {
            try { if (!O[mn]) return; O[mn].overloads.forEach(function (ov) { ov.implementation = function () { var a = arguments, d = []; for (var i = 0; i < a.length; i++) d.push(jstr(a[i], 4000)); log('RESP', mn + '(' + d.join(' || ') + ')'); return ov.apply(this, a); }; }); log('HOOK', 'OBS.' + mn); } catch (e) {}
        });
    });

    waitAndDo(NM, function (N) {
        ['get', 'post', 'postBody'].forEach(function (mn) {
            try {
                if (!N[mn]) return;
                N[mn].overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        var a = arguments;
                        try {
                            var p = a.length ? ('' + a[0]) : '';
                            if (FACTOR_URL.test(p)) {
                                log('REQ', '############ FACTOR 请求命中 ############');
                                log('REQ', 'NetworkManager.' + mn + '  url=' + p);
                                for (var i = 1; i < a.length; i++) {
                                    if (i === 1) dumpMap('REQ', '  arg[1] headers', a[1]);
                                    else if (i === 2) dumpMap('REQ', '  arg[2] params', a[2]);
                                    else log('REQ', '  arg[' + i + '] = ' + jstr(a[i], 800));
                                }
                                log('REQ', jstack());
                            } else if (!sampled && STATIC.test(p)) {
                                sampled = true;
                                log('HDRS', '(样本)首条 staticcache 请求, 其全局公共头与 factor 相同:');
                                log('HDRS', 'url=' + p);
                                dumpMap('HDRS', '  headers', a.length > 1 ? a[1] : null);
                            }
                        } catch (e) {}
                        return ov.apply(this, a);
                    };
                });
                log('HOOK', 'NM.' + mn + ' (' + N[mn].overloads.length + ')');
            } catch (e) {}
        });
        log('READY', 'v17 已安装。3 秒后自动 forceFactor(); 也可 REPL 手敲 forceFactor()');
        setTimeout(function () { try { global.forceFactor(); } catch (e) { log('FORCE', 'auto ' + e); } }, 3000);
    });
});

global.forceFactor = function () {
    Java.perform(function () {
        armNull = true;
        log('FORCE', '经 ServiceCenter 取 PlayerConfigPool, 强制重拉 factor...');
        try {
            var SCu = Java.use(SC), IPCu = Java.use(IPC), svc = null;
            try { svc = SCu.getService(IPCu.class); } catch (e) { log('FORCE', 'getService 失败: ' + e); }
            if (svc !== null) {
                var Pool = Java.use(POOL), pool = Java.cast(svc, Pool);
                var mgr = readField(pool, 'playUrlFactorManager');
                try { if (mgr !== null) { var Mu = Java.use(MGR), m = Java.cast(mgr, Mu); m.initPlayUrlFactorBean.overloads.forEach(function (ov) { if (ov.argumentTypes.length === 0) { log('FORCE', 'manager.initPlayUrlFactorBean()'); ov.call(m); } }); } } catch (e) { log('FORCE', 'mgr.init ' + e); }
                try { pool.init.overloads.forEach(function (ov) { if (ov.argumentTypes.length === 0) { log('FORCE', 'pool.init()'); ov.call(pool); } }); } catch (e) { log('FORCE', 'pool.init ' + e); }
            } else { log('FORCE', 'svc=null'); }
        } catch (e) { log('FORCE', e); }
        setTimeout(function () { armNull = false; }, 8000);
        log('FORCE', '完成, 看 [REQ]/[RESP]/[SAVE]');
    });
    return 'forceFactor dispatched';
};

function waitAndDo(cls, fn) { var t = 0, timer = setInterval(function () { t++; try { var C = Java.use(cls); clearInterval(timer); Java.perform(function () { try { fn(C); } catch (e) { log('ERR', cls + ' ' + e); } }); } catch (e) { if (t % 50 === 0) log('WAIT', cls.split('.').pop() + '(' + t + ')'); if (t > 2000) clearInterval(timer); } }, 200); }
