# Apollyon V45 - ELITE C2

<p align="center">
  <img src="https://img.shields.io/badge/Red_Team-ELITE-red" alt="Red Team">
  <img src="https://img.shields.io/badge/Version-45.0-ff0000" alt="Version">
</p>

---

## ⚠️ WARNING

> This software is a **highly capable Red Team simulation tool**.

**Never run on production or personal systems.**
Use **isolated virtual machines (VM)** or sandbox environments.
Some features (`set_persistence`, `scorch_earth`) can modify or delete system data.

<p align="center">
  <img src="https://img.icons8.com/fluency/48/000000/skull.png" alt="Danger">
</p>

---

## 🛠 Features

### Apollyon Agent
- AES-style encryption with dynamic key rotation
- HMAC integrity for secure comms
- Sandbox detection & evasion
- System metrics collection

### C2 Server
- Flask-based dark-themed web UI
- Agent monitoring and live decision feed
- Manual objective injection (`PERSIST`, `EXFIL`, `PIVOT`, `MASQUERADE`, `SCORCH`)
- Beacon endpoint for autonomous agent check-ins

### Offensive Engine
- Lateral scan simulation
- Exploit simulation
- Linux process masquerade
- Mock loot exfiltration

### Database
- SQLite in-memory database
- Tracks agents, network assets, decisions, loot
- Logs operator & system actions

---

## 💻 Setup & Execution (Safe Mode)

1. **Clone the repo:**
```bash
git clone https://github.com/your-repo/apollyon-v45.git
cd apollyon-v45
```

2. **Install dependencies:**
```bash
pip install flask
```

3. **Run in Safe Mode:**
- Disable destructive features by commenting out:
```python
# agent.set_persistence()
# agent.scorch_earth()
```
- Start server:
```bash
python apollyon_c2.py
```

4. **Access UI:**
```
http://127.0.0.1:<random_port>/access
```

Default admin password (hashed in config): `mehran_dominance_2026`

---

## 🧪 Testing / Red Team Simulation

- **Agents**: Simulated via `/v45/beacon`
- **Offensive Operations**: Inject objectives via UI
- **Lateral Movement**: Mock scan/exploit results in DB
- **Loot Exfiltration**: In-memory only, no real system data

> Always test in VM or container environment.

---

## 🔐 OPSEC / Security Notes

- Active only during **working hours** (08:00–20:00)
- AES + HMAC for agent-server communication
- Nonce reuse and timestamp validation for integrity
- Logs written to memory by default

---


## 🧩 Notes

- Customize `Config` for lab environment
- Use `OffensiveEngine` methods in **mock mode** to avoid system changes
- UI & API are for **training/simulation**, not real attacks

<p align="center">
  <img src="https://img.icons8.com/fluency/48/000000/ghost.png" alt="Stealth">
</p>

---

## ⚖️ Legal Disclaimer

**Author: MehranTurk (M.T)**


This tool is intended **strictly for educational purposes** and authorized professional penetration testing. Attacking targets without prior written consent is illegal and punishable by law. The developer assumes no liability for any misuse, damage, or legal consequences resulting from the use of this framework. Use responsibly and legally.

## 💰 Donate


| Currency | Address |
|-----------|----------|
| **USDT / TRX** | `TSVd8USqUv1B1dz6Hw3bUCQhLkSz1cLE1v` |
| **BTC** | `32Sxd8UJav7pERtL9QbAStWuFJ4aMHaZ9g` |
| **ETH** | `0xb2ba6B8CbB433Cb7120127474aEF3B1281C796a6` |
| **LTC** | `MEUoFAYLqrwxnUBkT4sBB63wAypKEdyewy` |

---

