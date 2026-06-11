/*
 * frida_factor_trace_v13.js  —— 定位 factor 本地缓存「到底存在哪个文件」
 * -------------------------------------------------------------------------
 * 目标: 找到承载 key_play_url_factor_bean_PlayUrl 的**持久化文件**，删掉它，
 *       force-stop 后冷启动(ecapture 抓包, 不用 frida → 不触发 legu 反调试)，
 *       就能抓到 https://program-sc.miguvideo.com/app-management/videox/
 *       staticcache/v2/factor/miguvideo/android 这条真实请求。
 *
 * 手法(全程 **不用 Java.choose**, 防崩):
 *   - 钩 PlayUrlFactorManager.getPlayUrlFactorBeanFromLocal / savePlayUrlFactorBeanToLocal
 *     进入时把 inIO=该方法名, 退出清空 → 在这个窗口内, 该方法内部走的所有
 *     文件/KV 操作都打印路径/键值, 从而锁定真正的存储文件                        [STORE]
 *   - 窗口内被动捕获:
 *       FileInputStream/FileOutputStream/RandomAccessFile(File 或 String 路径)  → 文件路径
 *       MMKV.decodeString/encodeString / getString/putString                  → mmapID + key
 *       SharedPreferences.getString / Editor.putString                        → SP 名 + key
 *   - 另外**无条件**打印任何 key 含 play_url_factor 的 SP/MMKV 读写(兜底)         [KV]
 *
 * 用法: frida -H 127.0.0.1:14725 -F -l frida_factor_trace_v13.js
 *   连上后进一次播放页(触发 getPlayUrlFactorBeanFromLocal) → 看 [STORE]/[KV]
 *   [STORE] 里那条 open(File)=... 就是要删的缓存文件路径。
 * -------------------------------------------------------------------------
 */
'use strict';

var MGR = 'com.cmvideo.capability.mguniformmpbusiness.playerconfig.PlayUrlFactorManager';
var KEYHINT = /play_url_factor|playUrlFactor|factor_bean/i;

function ts() { return new Date().toISOString().substr(11, 12); }
function log(t, m) { console.log('[' + ts() + '][' + t + '] ' + m); }
function jstack() { try { var E = Java.use('java.lang.Exception'); var L = Java.use('android.util.Log'); return L.getStackTraceString(E.$new()); } catch (e) { return '<' + e + '>'; } }
function asStr(v, max) { max = max || 600; if (v === null || v === undefined) return 'null'; var s; try { s = '' + v; } catch (e) { s = '<' + e + '>'; } if (s.length > max) s = s.substring(0, max) + '...(len=' + s.length + ')'; return s; }

var inIO = null; // 当前处于哪个 manager IO 方法窗口

function wrapIO(M, name) {
    try {
        if (!M[name]) { log('SKIP', 'MGR.' + name + ' 不存在'); return; }
        M[name].overloads.forEach(function (ov) {
            ov.implementation = function () {
                var prev = inIO; inIO = name;
                log('STORE', '>>> 进入 ' + name + '() —— 窗口内的文件/KV 操作即为它的存储位置');
                try { return ov.apply(this, arguments); }
                finally { var r; try { r = '' + arguments; } catch (e) {} inIO = prev; log('STORE', '<<< 离开 ' + name + '()'); }
            };
        });
        log('HOOK', 'MGR.' + name + ' (' + M[name].overloads.length + ')');
    } catch (e) { log('SKIP', 'MGR.' + name + ' ' + e); }
}

function hookFileCtor(clsName) {
    try {
        var C = Java.use(clsName);
        C.$init.overload('java.io.File').implementation = function (f) { try { if (inIO) log('STORE', '  [' + inIO + '] ' + clsName.split('.').pop() + '(File) = ' + f.getAbsolutePath()); } catch (e) {} return this.$init(f); };
    } catch (e) {}
    try {
        var C2 = Java.use(clsName);
        C2.$init.overload('java.lang.String').implementation = function (p) { try { if (inIO) log('STORE', '  [' + inIO + '] ' + clsName.split('.').pop() + '(String) = ' + p); } catch (e) {} return this.$init(p); };
    } catch (e) {}
}

Java.perform(function () {
    // File IO 构造(只在 IO 窗口内打印)
    hookFileCtor('java.io.FileInputStream');
    hookFileCtor('java.io.FileOutputStream');
    hookFileCtor('java.io.RandomAccessFile');
    log('HOOK', 'File IO ctors (scoped)');

    // SharedPreferences
    try {
        var SPImpl = Java.use('android.app.SharedPreferencesImpl');
        SPImpl.getString.implementation = function (k, d) {
            var v = this.getString(k, d);
            try { if (inIO || KEYHINT.test('' + k)) log('KV', 'SP.getString  key=' + k + '  val=' + asStr(v, 400) + (inIO ? '  (在' + inIO + '窗口)' : '')); } catch (e) {}
            return v;
        };
        log('HOOK', 'SharedPreferencesImpl.getString');
    } catch (e) { log('SKIP', 'SPImpl ' + e); }
    try {
        var Ed = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        Ed.putString.implementation = function (k, v) {
            try { if (inIO || KEYHINT.test('' + k)) log('KV', 'SP.Editor.putString  key=' + k + '  val=' + asStr(v, 400) + (inIO ? '  (在' + inIO + '窗口)' : '')); } catch (e) {}
            return this.putString(k, v);
        };
        log('HOOK', 'SP Editor.putString');
    } catch (e) { log('SKIP', 'SP Editor ' + e); }

    // MMKV(腾讯) —— 很多咪咕缓存走它
    try {
        var MMKV = Java.use('com.tencent.mmkv.MMKV');
        try {
            MMKV.decodeString.overload('java.lang.String').implementation = function (k) { var v = this.decodeString(k); try { if (inIO || KEYHINT.test('' + k)) log('KV', 'MMKV.decodeString  mmapID=' + tryMmapId(this) + '  key=' + k + '  val=' + asStr(v, 400) + (inIO ? '  (在' + inIO + '窗口)' : '')); } catch (e) {} return v; };
        } catch (e) {}
        try {
            MMKV.decodeString.overload('java.lang.String', 'java.lang.String').implementation = function (k, d) { var v = this.decodeString(k, d); try { if (inIO || KEYHINT.test('' + k)) log('KV', 'MMKV.decodeString  mmapID=' + tryMmapId(this) + '  key=' + k + '  val=' + asStr(v, 400) + (inIO ? '  (在' + inIO + '窗口)' : '')); } catch (e) {} return v; };
        } catch (e) {}
        MMKV.encodeString.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) { try { if (inIO || KEYHINT.test('' + k)) log('KV', 'MMKV.encodeString  mmapID=' + tryMmapId(this) + '  key=' + k + '  val=' + asStr(v, 400) + (inIO ? '  (在' + inIO + '窗口)' : '')); } catch (e) {} return this.encodeString(k, v); };
        log('HOOK', 'MMKV decode/encodeString');
    } catch (e) { log('SKIP', 'MMKV(未用或类名不同) ' + e); }

    // 等 MGR 加载后包裹其本地读写方法
    var t = 0, timer = setInterval(function () {
        t++;
        try {
            var M = Java.use(MGR);
            clearInterval(timer);
            Java.perform(function () {
                wrapIO(M, 'getPlayUrlFactorBeanFromLocal');
                wrapIO(M, 'savePlayUrlFactorBeanToLocal');
                // 有些版本叫法不同, 兜底再试几个
                ['getPlayUrlFactorBean', 'savePlayUrlFactorBean', 'readLocal', 'saveLocal'].forEach(function (n) { if (M[n]) wrapIO(M, n); });
                log('READY', 'v13 已安装(无 Java.choose)。进一次播放页, 看 [STORE]/[KV] 锁定缓存文件路径。');
            });
        } catch (e) { if (t % 25 === 0) log('WAIT', '仍未加载 MGR(' + t + ')'); if (t > 1500) clearInterval(timer); }
    }, 200);
});

function tryMmapId(mmkv) { try { return mmkv.mmapID(); } catch (e) { return '?'; } }
