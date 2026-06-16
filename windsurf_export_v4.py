#!/usr/bin/env python3
"""
Windsurf Cascade 对话记录导出工具 v4
通过本地 LanguageServerService JSON API 导出 Windsurf 对话为 Markdown 和 HTML

更新特性 (v4):
  - 自动使用 ctypes 扫描读取 WINDSURF_CSRF_TOKEN，无需依赖 get_token.exe。
  - --list 命令增强：显示首次用户提问作为标题和项目路径。
  - --id 命令后进入二级菜单，支持本地 SQLite (bak.db) 增量更新同步和从 DB 导出 HTML。
  - HTML 导出自动解析和渲染 Markdown 表格语法。

用法:
  python windsurf_export_v4.py --list
  python windsurf_export_v4.py --id CASCADE_ID
  python windsurf_export_v4.py --all

示例:
  python windsurf_export_v4.py --list
"""

import warnings
warnings.filterwarnings('ignore')

import os, sys, json, re, datetime, subprocess, argparse, sqlite3
import urllib.request as _ur
from html import escape as html_escape
import ctypes
from string import Template

# 修复 Windows GBK 终端编码问题
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

# ============================================================
# API 客户端 与 Token 自动获取 (ctypes)
# ============================================================

def get_csrf_token_auto():
    """用 Python ctypes 替代 get_token.exe，直接读取进程内存的环境变量"""
    # 1. 尝试从环境变量获取 (当前进程)
    for key, val in os.environ.items():
        if 'csrf' in key.lower() or 'codeium' in key.lower():
            if val and len(val) > 10 and '-' in val:
                return val

    # 2. 从其它进程中获取 (仅限 Windows 64-bit)
    if sys.platform != 'win32' or ctypes.sizeof(ctypes.c_void_p) != 8:
        return None

    print("尝试通过 Windows API 自动获取 Token...")
    try:
        from ctypes import wintypes

        # 使用 powershell 找出 windsurf 或 language_server 进程的 PID
        res = subprocess.run(['powershell', '-Command',
            'Get-CimInstance Win32_Process | Where-Object { $_.Name -match "windsurf" -or $_.Name -match "language_server" } | Select-Object -ExpandProperty ProcessId'],
            capture_output=True, text=True, timeout=10)
        pids = [int(p) for p in res.stdout.split() if p.isdigit()]
        if not pids:
            print("  未找到 Windsurf 相关进程")
            return None

        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010

        class PROCESS_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("Reserved1", ctypes.c_void_p),
                ("PebBaseAddress", ctypes.c_void_p),
                ("Reserved2", ctypes.c_void_p * 2),
                ("UniqueProcessId", ctypes.c_void_p),
                ("Reserved3", ctypes.c_void_p)
            ]

        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

        # 设置 argtypes/restype 避免指针溢出
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE

        kernel32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        ]
        kernel32.ReadProcessMemory.restype = wintypes.BOOL

        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        ntdll.NtQueryInformationProcess.argtypes = [
            wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p,
            ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)
        ]
        ntdll.NtQueryInformationProcess.restype = ctypes.c_long

        found_tokens = []
        for pid in pids:
            try:
                hProcess = kernel32.OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
                if not hProcess:
                    continue

                pbi = PROCESS_BASIC_INFORMATION()
                retLen = ctypes.c_ulong()
                status = ntdll.NtQueryInformationProcess(
                    hProcess, 0, ctypes.byref(pbi),
                    ctypes.sizeof(pbi), ctypes.byref(retLen))

                if status != 0 or not pbi.PebBaseAddress:
                    kernel32.CloseHandle(hProcess)
                    continue

                pProcessParams = ctypes.c_void_p()
                bytesRead = ctypes.c_size_t()

                # 64-bit PEB offset 0x20 -> ProcessParameters
                addr_pp = ctypes.c_void_p(pbi.PebBaseAddress + 0x20)
                ok = kernel32.ReadProcessMemory(
                    hProcess, addr_pp,
                    ctypes.byref(pProcessParams), 8, ctypes.byref(bytesRead))
                if not ok or not pProcessParams.value:
                    kernel32.CloseHandle(hProcess)
                    continue

                # 64-bit RTL_USER_PROCESS_PARAMETERS offset 0x80 -> Environment
                pEnvironment = ctypes.c_void_p()
                addr_env = ctypes.c_void_p(pProcessParams.value + 0x80)
                ok = kernel32.ReadProcessMemory(
                    hProcess, addr_env,
                    ctypes.byref(pEnvironment), 8, ctypes.byref(bytesRead))
                if not ok or not pEnvironment.value:
                    kernel32.CloseHandle(hProcess)
                    continue

                # 读取环境变量块 (最大 64KB)
                ENV_SIZE = 32768 * 2
                env_buf = ctypes.create_string_buffer(ENV_SIZE)
                ok = kernel32.ReadProcessMemory(
                    hProcess, pEnvironment,
                    env_buf, ENV_SIZE, ctypes.byref(bytesRead))
                kernel32.CloseHandle(hProcess)

                if not ok or bytesRead.value < 10:
                    continue

                env_str = env_buf.raw[:bytesRead.value].decode('utf-16le', errors='ignore')
                m = re.search(
                    r'WINDSURF_CSRF_TOKEN=([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-'
                    r'[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})',
                    env_str)
                if m:
                    token = m.group(1)
                    if token not in found_tokens:
                        found_tokens.append(token)
                        print(f"  ✓ PID {pid}: 发现 Token {token[:8]}...")
            except Exception:
                continue

        if found_tokens:
            return found_tokens[0]

        # 3. 回退：尝试运行同目录下的 get_token.exe
        script_dir = os.path.dirname(os.path.abspath(__file__))
        exe_path = os.path.join(script_dir, 'get_token.exe')
        if os.path.exists(exe_path):
            print("  ctypes 方式未找到，尝试 get_token.exe...")
            try:
                res = subprocess.run([exe_path], capture_output=True,
                                     text=True, timeout=15)
                m = re.search(
                    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
                    r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', res.stdout)
                if m:
                    print(f"  ✓ get_token.exe 返回 Token")
                    return m.group(0)
            except Exception:
                pass

    except Exception as e:
        print(f"  自动获取 Token 异常: {e}")

    return None

def _probe_port_http(port, token):
    """探测某个端口是否是正确的 HTTP Connect-protocol API 端口"""
    import socket
    SERVICE = 'exa.language_server_pb.LanguageServerService'
    url = f'http://127.0.0.1:{port}/{SERVICE}/GetUserTrajectoryDescriptions'
    headers = {'Content-Type': 'application/json', 'Connect-Protocol-Version': '1'}
    if token:
        headers['x-codeium-csrf-token'] = token
    req = _ur.Request(url, data=b'{}', headers=headers, method='POST')
    try:
        resp = _ur.urlopen(req, timeout=3)
        return True
    except _ur.HTTPError:
        # HTTP error (400, 500 等) 说明端口确实在服务 HTTP 请求
        return True
    except Exception:
        return False

def find_language_server_port(token=None):
    """自动发现 Windsurf 的 language_server 端口（排除 Antigravity 等其他 IDE）
    
    新版 Windsurf 可能为同一进程开放多个端口（gRPC/H2 + HTTP/Connect），
    需要逐一探测找到真正支持 HTTP/1.1 Connect-protocol 的 API 端口。
    """
    try:
        result = subprocess.run(
            ['powershell', '-Command',
             'Get-CimInstance Win32_Process -Filter "Name=\'language_server_windows_x64.exe\'" | '
             'ForEach-Object { "$($_.ProcessId)|||$($_.ExecutablePath)|||$($_.CommandLine)" }'],
            capture_output=True, text=True, timeout=15
        )
        if not result.stdout.strip(): return None

        windsurf_pid = None
        windsurf_ext_port = None

        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line: continue
            parts = line.split('|||', 2)
            if len(parts) < 3: continue
            pid_str, exe_path, cmdline = [p.strip() for p in parts]

            path_lower = exe_path.lower()
            if '\\windsurf\\' not in path_lower: continue
            if '\\antigravity\\' in path_lower: continue

            windsurf_pid = pid_str
            m = re.search(r'--extension_server_port\s+(\d+)', cmdline)
            windsurf_ext_port = int(m.group(1)) if m else None
            break

        if not windsurf_pid: return None

        ns_result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, timeout=10)
        candidate_ports = []
        pid_pattern = re.compile(r'127\.0\.0\.1:(\d+)\s+\S+\s+LISTENING\s+' + windsurf_pid + r'\b')
        for line in ns_result.stdout.split('\n'):
            m2 = pid_pattern.search(line.strip())
            if m2:
                p = int(m2.group(1))
                if windsurf_ext_port and p == windsurf_ext_port: continue
                candidate_ports.append(p)

        if not candidate_ports:
            return windsurf_ext_port

        # 新版 Windsurf 会开多个端口，需要探测哪个是 HTTP/Connect API 端口
        if len(candidate_ports) == 1:
            return candidate_ports[0]

        print(f"  发现多个候选端口: {candidate_ports}，正在探测...")
        for p in candidate_ports:
            if _probe_port_http(p, token):
                print(f"  ✓ 端口 {p} 响应 HTTP Connect-protocol")
                return p
            else:
                print(f"  ✗ 端口 {p} 无响应")

        # 全部探测失败，返回最后一个（通常较高端口号是 API 端口）
        print(f"  探测均失败，尝试最后一个端口 {candidate_ports[-1]}")
        return candidate_ports[-1]
    except Exception as e:
        print(f"  端口发现异常: {e}")
        return None

class WindsurfAPI:
    SERVICE = 'exa.language_server_pb.LanguageServerService'

    def __init__(self, port=None, token=None):
        self.token = token or get_csrf_token_auto()
        if not self.token:
            raise RuntimeError("未提供 CSRF token 且自动获取失败，请使用 --csrf 手动传入。")
        print(f"成功获取 CSRF Token: {self.token}")

        self.port = port or find_language_server_port(token=self.token)
        if not self.port:
            raise RuntimeError("无法自动找到 language_server 端口。")
        print(f"使用 API 端口: {self.port}")

        import ssl as _ssl
        self._ssl_ctx = _ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = _ssl.CERT_NONE
        self.base_url = self._detect_scheme()
        print(f"API 地址: {self.base_url}")

    def _detect_scheme(self):
        """探测服务器使用 HTTP 还是 HTTPS。优先 HTTP（本地服务大多用 HTTP）。"""
        test_path = f'/{self.SERVICE}/GetUserTrajectoryDescriptions'
        data = b'{}'
        headers = {'Content-Type': 'application/json', 'Connect-Protocol-Version': '1', 'x-codeium-csrf-token': self.token}

        # 优先尝试 HTTP
        http_url = f'http://127.0.0.1:{self.port}{test_path}'
        try:
            req = _ur.Request(http_url, data=data, headers=headers, method='POST')
            resp = _ur.urlopen(req, timeout=5)
            return f'http://127.0.0.1:{self.port}'
        except _ur.HTTPError as e:
            body_text = e.read().decode('utf-8', errors='replace')
            if e.code == 400 and 'HTTPS' in body_text:
                return f'https://127.0.0.1:{self.port}'
            # 其他 HTTP 错误码说明服务器确实在响应 HTTP
            return f'http://127.0.0.1:{self.port}'
        except Exception:
            pass

        # HTTP 不通，尝试 HTTPS
        https_url = f'https://127.0.0.1:{self.port}{test_path}'
        try:
            req = _ur.Request(https_url, data=data, headers=headers, method='POST')
            resp = _ur.urlopen(req, context=self._ssl_ctx, timeout=5)
            return f'https://127.0.0.1:{self.port}'
        except _ur.HTTPError:
            return f'https://127.0.0.1:{self.port}'
        except Exception:
            pass

        # 都不通，默认 HTTP（避免 SSL EOF）
        print(f"  警告: 端口 {self.port} HTTP/HTTPS 探测均失败，默认使用 HTTP")
        return f'http://127.0.0.1:{self.port}'

    def _call(self, method, body=None):
        url = f'{self.base_url}/{self.SERVICE}/{method}'
        data = json.dumps(body or {}).encode('utf-8')
        headers = {'Content-Type': 'application/json', 'Connect-Protocol-Version': '1', 'x-codeium-csrf-token': self.token}
        req = _ur.Request(url, data=data, headers=headers, method='POST')
        try:
            if url.startswith('https://'):
                resp = _ur.urlopen(req, context=self._ssl_ctx, timeout=60)
            else:
                resp = _ur.urlopen(req, timeout=60)
            return json.loads(resp.read().decode('utf-8'))
        except _ur.HTTPError as e:
            err_body = e.read().decode('utf-8', errors='replace')[:300]
            raise RuntimeError(f"API {method} 失败: {e.code} {err_body}")
        except Exception as e:
            raise RuntimeError(f"API {method} 连接失败: {e}")

    def list_trajectories(self): return self._call('GetUserTrajectoryDescriptions')
    def get_cascade_trajectory(self, cascade_id): return self._call('GetCascadeTrajectory', {'cascadeId': cascade_id})
    def get_cascade_steps_page(self, cascade_id, offset=0): return self._call('GetCascadeTrajectorySteps', {'cascadeId': cascade_id, 'stepOffset': offset})

    def get_all_cascade_trajectories(self):
        """新版 API: 一次性获取所有 cascade 的摘要信息（ID、标题、步骤数、工作区等）"""
        return self._call('GetAllCascadeTrajectories')

    def get_all_cascade_steps(self, cascade_id, offset=0):
        all_steps = []
        page = 0
        while True:
            r = self.get_cascade_steps_page(cascade_id, offset)
            batch = r.get('steps', [])
            if not batch: break
            all_steps.extend(batch)
            page += 1
            offset += len(batch)
        return all_steps

    def get_full_cascade(self, cascade_id):
        all_steps = self.get_all_cascade_steps(cascade_id)
        data = {'trajectory': {'cascadeId': cascade_id, 'steps': all_steps, 'metadata': {}}, 'numTotalSteps': len(all_steps)}
        return data


# ============================================================
# DB (bak.db) 相关函数
# ============================================================

def init_db(db_path='bak.db'):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS cascade_backups (
                    cascade_id TEXT PRIMARY KEY,
                    workspace TEXT,
                    title TEXT,
                    total_steps INTEGER,
                    raw_data TEXT,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    return conn

def sync_cascade_to_db(api, cid):
    conn = init_db()
    c = conn.cursor()
    c.execute("SELECT raw_data FROM cascade_backups WHERE cascade_id=?", (cid,))
    row = c.fetchone()
    
    if row:
        try:
            data = json.loads(row[0])
        except json.JSONDecodeError:
            data = None
        if data:
            existing_steps = data.get('trajectory', {}).get('steps', [])
            print(f"本地数据库已有记录，当前步骤数: {len(existing_steps)}。")
        else:
            data = {'trajectory': {'cascadeId': cid, 'steps': [], 'metadata': {}}, 'numTotalSteps': 0}
            existing_steps = []
            print("本地数据库记录损坏，准备全量同步。")
    else:
        data = {'trajectory': {'cascadeId': cid, 'steps': [], 'metadata': {}}, 'numTotalSteps': 0}
        existing_steps = []
        print("本地数据库没有记录，准备全量同步。")
        
    offset = len(existing_steps)
    print(f"正在从步骤 offset={offset} 开始增量获取...")
    try:
        new_steps = api.get_all_cascade_steps(cid, offset=offset)
        if not new_steps:
            print("没有新步骤需要更新。无需操作。")
        else:
            existing_steps.extend(new_steps)
            data['trajectory']['steps'] = existing_steps
            data['numTotalSteps'] = len(existing_steps)
            
            # Simple title / workspace extraction
            title = "未知对话"
            for s in existing_steps:
                if 'userInput' in s:
                    text = s['userInput'].get('userResponse', '') or s['userInput'].get('text', '')
                    if text: title = text[:50].replace('\n', ' '); break
            
            # store to DB
            c.execute("INSERT OR REPLACE INTO cascade_backups (cascade_id, workspace, title, total_steps, raw_data, updated_at) VALUES (?, ?, ?, ?, ?, datetime('now'))", 
                      (cid, "", title, len(existing_steps), json.dumps(data)))
            conn.commit()
            print(f"成功导入 {len(new_steps)} 个新步骤，当前总计 {len(existing_steps)} 步已保存至 bak.db。")
    except Exception as e:
        print(f"同步失败: {e}")
    finally:
        conn.close()

def safe_filename(title, workspace='', max_len=80):
    """将标题和工作目录组合为安全的文件名"""
    # 提取目录最后一级作为简短标识
    ws_short = os.path.basename(workspace.rstrip('/\\')) if workspace else ''
    # 清理标题：只保留中文、字母、数字、空格、连字符
    clean_title = re.sub(r'[^\w\u4e00-\u9fff\s-]', '', title).strip()
    clean_title = re.sub(r'\s+', '_', clean_title)  # 空格转下划线
    if not clean_title:
        clean_title = 'untitled'
    # 组合: 标题_目录
    if ws_short:
        name = f'{clean_title}_{ws_short}'
    else:
        name = clean_title
    # 截断
    if len(name) > max_len:
        name = name[:max_len]
    return name


def export_cascade_from_db(cid, out_dir, title='', workspace=''):
    conn = init_db()
    c = conn.cursor()
    c.execute("SELECT raw_data FROM cascade_backups WHERE cascade_id=?", (cid,))
    row = c.fetchone()
    conn.close()
    
    if row and row[0]:
        print("从数据库成功读取数据，开始导出 HTML...")
        try:
            data = json.loads(row[0])
            os.makedirs(out_dir, exist_ok=True)
            fname = safe_filename(title or f'cascade_{cid[:12]}', workspace)
            html = trajectory_to_html(data, title=title or None)
            html_file = os.path.join(out_dir, f'{fname}.html')
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html)
            print(f"HTML 导出成功: {html_file}")
            print(f"本地文件路径: file:///{os.path.abspath(html_file).replace(chr(92), '/')}")
        except Exception as e:
            print(f"解析或导出失败: {e}")
    else:
        print("数据库中未找到该 Cascade 的数据。请先执行同步操作（选项1）。")


# ============================================================
# SQLite DB 发现 cascade IDs (IDE Storage)
# ============================================================
def get_cascade_ids_from_vsdb():
    """从 state.vscdb 中读取所有 cascade IDs"""
    APPDATA = os.environ.get('APPDATA', '')
    DB_PATH = os.path.join(APPDATA, r'Windsurf\User\globalStorage\state.vscdb')
    if not os.path.exists(DB_PATH): return []

    def decode_varint(data, pos):
        result = 0; shift = 0
        while pos < len(data):
            b = data[pos]; result |= (b & 0x7f) << shift; pos += 1
            if not (b & 0x80): break
            shift += 7
        return result, pos

    def decode_pb(data):
        pos = 0; fields = []
        while pos < len(data):
            try:
                tag, new_pos = decode_varint(data, pos)
                if tag == 0: break
                fn = tag >> 3; wt = tag & 0x7; pos = new_pos
                if wt == 0: val, pos = decode_varint(data, pos); fields.append((fn, 0, val))
                elif wt == 2:
                    length, pos = decode_varint(data, pos)
                    if length < 0 or length > len(data) - pos: break
                    fields.append((fn, 2, data[pos:pos+length])); pos += length
                elif wt == 1: fields.append((fn, 1, data[pos:pos+8])); pos += 8
                elif wt == 5: fields.append((fn, 5, data[pos:pos+4])); pos += 4
                else: break
            except: break
        return fields

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT value FROM ItemTable WHERE key='codeium.windsurf'")
        row = c.fetchone()
        conn.close()
        if not row: return []
        raw = row[0]
        if isinstance(raw, bytes): raw = raw.decode('utf-8', errors='replace')
        j = json.loads(raw)
    except Exception:
        return []

    import base64
    cascade_ids = []

    for k, v in j.items():
        if 'cachedTrajectorySummaries:' in k and isinstance(v, str) and len(v) > 10:
            try:
                data = base64.b64decode(v)
                top = decode_pb(data)
                for fn, wt, fv in top:
                    if wt == 2:
                        sub = decode_pb(fv)
                        for sfn, swt, sv in sub:
                            if sfn == 1 and swt == 2:
                                try:
                                    cid = sv.decode('utf-8')
                                    if len(cid) > 10 and cid not in cascade_ids:
                                        cascade_ids.append(cid)
                                except: pass
            except: pass

    for k, v in j.items():
        if 'cachedActiveTrajectory:' in k and isinstance(v, str) and len(v) > 10:
            try:
                text = base64.b64decode(v).decode('utf-8', errors='replace')
                uuids = re.findall(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', text)
                for u in uuids:
                    if u not in cascade_ids:
                        cascade_ids.append(u)
            except: pass

    return cascade_ids


def verify_cascade_ids(api, candidate_ids):
    """验证哪些 UUID 是真正可用的 cascade ID（通过 API 检查）"""
    valid = []
    for cid in candidate_ids:
        try:
            r = api.get_cascade_steps_page(cid, 0)
            steps = r.get('steps', [])
            if steps:
                valid.append(cid)
        except Exception:
            pass
    return valid


# ============================================================
# 工具与渲染函数
# ============================================================
def ts_format(iso_str):
    if not iso_str: return ''
    try:
        dt = datetime.datetime.fromisoformat(iso_str.replace('Z', '+00:00'))
        return dt.astimezone().strftime('%Y-%m-%d %H:%M:%S')
    except: return iso_str

def get_step_ts(step):
    return ts_format(step.get('metadata', {}).get('createdAt', ''))

def file_ext(path):
    if path and '.' in os.path.basename(path): return os.path.splitext(path)[1].lstrip('.')
    return ''

def uri_to_path(uri):
    if not uri: return ''
    p = uri
    for prefix in ('file:///', 'file://'):
        if p.startswith(prefix): p = p[len(prefix):]
    return p.replace('%20', ' ').replace('%3A', ':')

def render_content_html(text):
    """渲染内容为 HTML，支持处理 Markdown 表格转换为 HTML <table>"""
    if not text: return ""
    lines = text.split('\n')
    out_lines = []
    
    in_table = False
    table_lines = []

    def flush_table():
        if not table_lines: return ""
        html = ['<div class="table-container"><table class="md-table">']
        for i, row in enumerate(table_lines):
            # Split row by | and filter empty edge columns
            cols = [c.strip() for c in row.strip().strip('|').split('|')]
            if not cols or (len(cols) == 1 and not cols[0]): continue
            
            # Check for header separator line (e.g. |---|---|)
            if i == 1 and all(not c.replace('-', '').replace(':', '').strip() for c in cols):
                continue
            
            tag = 'th' if i == 0 else 'td'
            row_html = '<tr>' + ''.join(f'<{tag}>{html_escape(c)}</{tag}>' for c in cols) + '</tr>'
            html.append(row_html)
        html.append('</table></div>')
        return '\n'.join(html)

    for line in lines:
        stripped = line.strip()
        # Basic check for markdown table line
        if stripped.startswith('|') and stripped.endswith('|') and len(stripped.split('|')) > 2:
            in_table = True
            table_lines.append(stripped)
        else:
            if in_table:
                # Flush table block
                out_lines.append(flush_table())
                table_lines = []
                in_table = False
            # Normal text block
            escaped_line = html_escape(line).replace('  ', '&nbsp;&nbsp;')
            out_lines.append(escaped_line)
            
    if in_table:
        out_lines.append(flush_table())
        
    return '<br/>\n'.join(out_lines)


# ============================================================
# HTML 输出模板与生成
# ============================================================

HTML_TEMPLATE_HEAD = Template(r'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>$title</title>
<style>
:root {
  --bg: #1e1e2e; --bg2: #181825; --surface: #313244; --overlay: #45475a;
  --text: #cdd6f4; --subtext: #a6adc8; --blue: #89b4fa; --green: #a6e3a1;
  --red: #f38ba8; --yellow: #f9e2af; --mauve: #cba6f7; --teal: #94e2d5;
  --peach: #fab387; --sidebar-w: 600px;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background:var(--bg); color:var(--text); display:flex; min-height:100vh; }

/* Sidebar */
#sidebar { width:var(--sidebar-w); background:var(--bg2); border-right:1px solid var(--surface); position:fixed; top:0; left:0; bottom:0; overflow-y:auto; z-index:10; transition:transform .3s; }
#sidebar.hidden { transform:translateX(-100%); }
#sidebar h2 { padding:16px 16px 8px; font-size:14px; color:var(--subtext); text-transform:uppercase; letter-spacing:1px; }
#sidebar .meta { padding:4px 16px; font-size:12px; color:var(--overlay); }
#nav-tree { list-style:none; padding:8px 0; }
#nav-tree li { border-left:3px solid transparent; }
#nav-tree li:hover { background:var(--surface); }
#nav-tree li.active { border-left-color:var(--blue); background:var(--surface); }
#nav-tree a { display:block; padding:8px 16px; color:var(--text); text-decoration:none; font-size:13px; line-height:1.4; }
#nav-tree .ts { display:block; font-size:11px; color:var(--subtext); margin-top:2px; }

/* Resizer handle */
#resizer { position:fixed; top:0; bottom:0; width:6px; left:var(--sidebar-w); cursor:col-resize; z-index:15; background:transparent; }
#resizer:hover, #resizer.active { background:var(--blue); opacity:0.5; }

/* Toggle button */
#toggle-sidebar { position:fixed; top:12px; left:12px; z-index:20; background:var(--surface); border:none; color:var(--text); width:36px; height:36px; border-radius:8px; cursor:pointer; font-size:18px; display:flex; align-items:center; justify-content:center; }
#toggle-sidebar:hover { background:var(--overlay); }
.sidebar-visible #toggle-sidebar { left: calc(var(--sidebar-w) + 16px); }

/* Main content — contain:content isolates internal layout from sidebar resize */
#main { margin-left:calc(var(--sidebar-w) + 6px); flex:1; padding:32px 48px; min-width:0; overflow-wrap:break-word; contain:content; }
body.sidebar-hidden #main { margin-left:0; }
body.sidebar-hidden #resizer { display:none; }

/* Blocks */
.step { margin-bottom:24px; padding:16px 20px; border-radius:10px; border-left:4px solid var(--surface); }
.step-user { background:linear-gradient(135deg, #1a3a5c 0%, #1e2a3e 100%); border-left-color:var(--blue); }
.step-assistant { background:var(--bg2); border-left-color:var(--mauve); }
.step-tool { background:var(--bg2); border-left-color:var(--green); opacity:0.92; }

.step h2 { font-size:16px; margin-bottom:8px; display:flex; align-items:center; gap:8px; }
.step h3 { font-size:14px; margin-bottom:6px; display:flex; align-items:center; gap:6px; }
.step .ts-badge { font-size:11px; color:var(--subtext); background:var(--surface); padding:2px 8px; border-radius:4px; font-weight:normal; white-space:nowrap; }

/* Content */
.step .content { font-size:14px; line-height:1.7; word-break:break-word; }

/* Collapsible */
details { margin:8px 0; border:1px solid var(--surface); border-radius:8px; overflow:hidden; }
details summary { cursor:pointer; padding:8px 12px; background:var(--surface); font-size:13px; font-weight:600; color:var(--subtext); user-select:none; }
details summary:hover { background:var(--overlay); }
details .detail-body { padding:12px; font-size:13px; line-height:1.6; max-height:80vh; overflow:auto; }

/* Code blocks */
pre, code { font-family: 'Consolas', 'Monaco', monospace; }
pre { background:var(--bg); border:1px solid var(--surface); border-radius:6px; padding:12px; overflow-x:auto; font-size:13px; line-height:1.5; margin:8px 0; white-space:pre-wrap; word-break:break-all; }
.inline-code { background:var(--surface); color:var(--peach); padding:2px 6px; border-radius:4px; font-size:12px; }

/* Markdown Table */
.table-container { overflow-x: auto; margin: 12px 0; border-radius: 6px; border: 1px solid var(--surface); }
.md-table { width: 100%; border-collapse: collapse; font-size: 13px; margin: 0; }
.md-table th, .md-table td { padding: 10px 14px; border-bottom: 1px solid var(--surface); text-align: left; }
.md-table th { background: var(--bg); font-weight: 600; color: var(--blue); }
.md-table tr:last-child td { border-bottom: none; }
.md-table tr:hover td { background: rgba(255, 255, 255, 0.05); }

</style>
</head>
<body class="sidebar-visible">
<button id="toggle-sidebar" onclick="document.body.classList.toggle('sidebar-hidden');document.getElementById('sidebar').classList.toggle('hidden')">☰</button>
<aside id="sidebar">
  <h2>$title_short</h2>
  <div class="meta">ID: $cascade_id_short</div>
  <div class="meta">Created: $created</div>
  <div class="meta">Steps: $n_steps / $n_total_steps</div>
  <ul id="nav-tree">
$nav_items
  </ul>
</aside>
<div id="resizer"></div>
<main id="main">
''')

HTML_TEMPLATE_TAIL = Template(r'''
</main>
<script>
// Pre-build nav lookup for O(1) access
const navMap = {};
document.querySelectorAll('#nav-tree li[data-id]').forEach(li => { navMap[li.dataset.id] = li; });
let activeNav = null;

// Scroll spy
const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      if (activeNav) activeNav.classList.remove('active');
      const nav = navMap[entry.target.id];
      if (nav) { nav.classList.add('active'); activeNav = nav; }
    }
  });
}, { rootMargin: '-20% 0px -70% 0px' });
// Only observe steps that have nav entries (user messages) — not all thousands of steps
document.querySelectorAll('.step[id]').forEach(s => { if (navMap[s.id]) observer.observe(s); });

// Draggable sidebar resizer
(function() {
  const resizer = document.getElementById('resizer');
  let isResizing = false;

  resizer.addEventListener('mousedown', (e) => {
    isResizing = true;
    resizer.classList.add('active');
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    e.preventDefault();
  });

  document.addEventListener('mousemove', (e) => {
    if (!isResizing) return;
    let newWidth = Math.max(180, Math.min(e.clientX, window.innerWidth - 300));
    document.documentElement.style.setProperty('--sidebar-w', newWidth + 'px');
  });

  document.addEventListener('mouseup', () => {
    if (isResizing) {
      isResizing = false;
      resizer.classList.remove('active');
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    }
  });
})();
</script>
</body>
</html>
''')

def format_step_html(step, step_idx):
    status = step.get('status', '')
    if status == 'CORTEX_STEP_STATUS_CLEARED': return '', None

    ts = get_step_ts(step)
    ts_badge = f'<span class="ts-badge">{html_escape(ts)}</span>' if ts else ''
    step_id = f'step-{step_idx}'
    nav_item = None

    if 'userInput' in step:
        ui = step['userInput']
        text = ui.get('userResponse', '') or ui.get('text', '') or ui.get('query', '')
        preview = text[:60] + '...' if len(text) > 60 else text
        nav_item = {'id': step_id, 'label': f'👤 {preview}', 'ts': ts}

        html = f'<div class="step step-user" id="{step_id}">\n  <h2>👤 User {ts_badge}</h2>\n'
        if text: html += f'  <div class="content">{render_content_html(text)}</div>\n'
        html += '</div>\n'
        return html, nav_item

    if 'plannerResponse' in step:
        pr = step['plannerResponse']
        thinking = pr.get('thinking', '')
        response = pr.get('response', '')
        
        html = f'<div class="step step-assistant" id="{step_id}">\n  <h2>🤖 Assistant {ts_badge}</h2>\n'
        if thinking:
            html += f'  <details>\n    <summary>💭 Thinking</summary>\n    <div class="detail-body"><pre>{html_escape(thinking)}</pre></div>\n  </details>\n'
        if response:
            html += f'  <div class="content">{render_content_html(response)}</div>\n'
        html += '</div>\n'
        return html, nav_item

    if 'runCommand' in step:
        cmd = step['runCommand'].get('commandLine', '')
        stdout = step['runCommand'].get('output', '') or step['runCommand'].get('combinedOutput', {}).get('full', '')
        html = f'<div class="step step-tool" id="{step_id}">\n  <h3>▶ Run Command {ts_badge}</h3>\n'
        html += f'  <pre>{html_escape(cmd)}</pre>\n'
        if stdout:
            html += f'  <details>\n    <summary>Output</summary>\n    <div class="detail-body"><pre>{html_escape(stdout)}</pre></div>\n  </details>\n'
        html += '</div>\n'
        return html, nav_item

    # Simplify other tools to avoid excessive code
    if 'codeAction' in step or 'viewFile' in step or 'grapSearch' in step:
        html = f'<div class="step step-tool" id="{step_id}">\n  <h3>⚙ Tool / File Operation {ts_badge}</h3>\n'
        html += f'  <div style="font-size:12px;color:gray;">(See internal data)</div>\n</div>\n'
        return html, nav_item

    return '', None

def trajectory_to_html(traj_data, title=None):
    traj = traj_data.get('trajectory', {})
    cascade_id = traj.get('cascadeId', '')
    steps = traj.get('steps', [])
    metadata = traj.get('metadata', {})
    
    if not title: title = f"Cascade - {cascade_id[:12]}"
    
    body_parts = []
    nav_items = []
    for i, step in enumerate(steps):
        step_html, nav = format_step_html(step, i)
        if step_html: body_parts.append(step_html)
        if nav: nav_items.append(
            f'    <li data-id="{nav["id"]}"><a href="#{nav["id"]}">{html_escape(nav["label"])}'
            f'<span class="ts">{html_escape(nav["ts"])}</span></a></li>'
        )

    head = HTML_TEMPLATE_HEAD.safe_substitute(
        title=html_escape(title),
        title_short=html_escape(title[:40]),
        cascade_id_short=cascade_id[:12],
        created=ts_format(metadata.get('createdAt', '')),
        n_steps=len(steps),
        n_total_steps=traj_data.get('numTotalSteps', len(steps)),
        nav_items='\n'.join(nav_items),
    )
    return head + '\n'.join(body_parts) + HTML_TEMPLATE_TAIL.safe_substitute()


# ============================================================
# CLI 命令处理逻辑
# ============================================================

def enhanced_list(cascade_summaries):
    """显示增强的列表输出：使用 GetAllCascadeTrajectories 返回的元数据"""
    print(f"\n找到 {len(cascade_summaries)} 个 Cascade 对话:\n")
    for i, (cid, info) in enumerate(cascade_summaries.items()):
        summary = info.get('summary', '(无标题)')
        steps = info.get('stepCount', 0)
        created = info.get('createdTime', '')[:19].replace('T', ' ')
        modified = info.get('lastModifiedTime', '')[:19].replace('T', ' ')
        model = info.get('lastGeneratorModelUid', '')
        ws_list = info.get('workspaces', [])
        ws = ws_list[0].get('workspaceFolderAbsoluteUri', '').replace('file:///', '') if ws_list else '(unknown)'
        status = info.get('status', '').replace('CASCADE_RUN_STATUS_', '')

        print(f"  [{i+1}] {summary}")
        print(f"      Steps: {steps}  |  Model: {model}  |  Status: {status}")
        print(f"      [DIR] {ws}")
        print(f"      [ID]  {cid}")
        print(f"      Created: {created}  Modified: {modified}")
        print()

def handle_menu_for_id(api, cid, out_dir, cascade_summaries=None):
    # 从 summaries 中获取元数据
    info = (cascade_summaries or {}).get(cid, {})
    title = info.get('summary', '')
    ws_list = info.get('workspaces', [])
    workspace = ws_list[0].get('workspaceFolderAbsoluteUri', '').replace('file:///', '') if ws_list else ''

    print(f"\n已选择 Cascade: {title or cid}")
    if workspace:
        print(f"工作目录: {workspace}")
    print(f"ID: {cid}")
    print("\n选择操作:")
    print("  [a] 同步到本地数据库 (增量更新 bak.db，老数据不动)")
    print("  [b] 从数据库备份导出 HTML")
    print("  [c] 直接从 API 获取并导出 HTML (不存数据库)")
    
    choice = input("请输入 a, b, 或 c: ").lower().strip()
    
    if choice == 'a':
        sync_cascade_to_db(api, cid)
    elif choice == 'b':
        export_cascade_from_db(cid, out_dir, title=title, workspace=workspace)
    elif choice == 'c':
        print("\n正在获取对话...")
        data = api.get_full_cascade(cid)
        os.makedirs(out_dir, exist_ok=True)
        fname = safe_filename(title or f'cascade_{cid[:12]}', workspace)
        html = trajectory_to_html(data, title=title or None)
        out_path = os.path.join(out_dir, f'{fname}.html')
        with open(out_path, 'w', encoding='utf-8') as f: f.write(html)
        print(f"导出成功: {out_path}")
    else:
        print("无效输入，退出。")


def main():
    parser = argparse.ArgumentParser(description='Windsurf Cascade 对话导出工具 v4')
    parser.add_argument('--csrf', type=str, help='如果自动获取失败，请手动传入 CSRF token')
    parser.add_argument('--list', action='store_true', help='列出所有可用对话，显示标题和目录')
    parser.add_argument('--id', type=str, help='指定 cascade ID 并进入操作菜单')
    parser.add_argument('--out', type=str, default='.', help='输出目录（默认当前目录）')
    args = parser.parse_args()

    print("Windsurf Cascade 导出工具 v4")
    print("=" * 40)

    try:
        api = WindsurfAPI(token=args.csrf)
    except RuntimeError as e:
        print(f"启动错误: {e}")
        sys.exit(1)

    # 使用新版 API 获取所有 cascade 的完整摘要
    cascade_summaries = {}
    try:
        r = api.get_all_cascade_trajectories()
        cascade_summaries = r.get('trajectorySummaries', {})
        print(f"API 返回 {len(cascade_summaries)} 个 cascade 对话。")
    except Exception as e:
        print(f"GetAllCascadeTrajectories 失败: {e}")
        print("回退到旧版本发现方式...")
        # Fallback: 用旧方式
        cascade_ids_fallback = get_cascade_ids_from_vsdb()
        if not cascade_ids_fallback:
            desc = api.list_trajectories()
            for t in desc.get('trajectories', []):
                tid = t.get('trajectoryId')
                if tid: cascade_ids_fallback.append(tid)
        cascade_ids_fallback = verify_cascade_ids(api, cascade_ids_fallback)
        for cid in cascade_ids_fallback:
            cascade_summaries[cid] = {'summary': '(旧版发现)', 'stepCount': 0}

    if args.list:
        enhanced_list(cascade_summaries)
        return

    if args.id:
        handle_menu_for_id(api, args.id, args.out, cascade_summaries)
        return

    print("\n请指定 --list 或 --id CASCADE_ID。")
    print("例如：python windsurf_export_v4.py --list")

if __name__ == '__main__':
    main()
