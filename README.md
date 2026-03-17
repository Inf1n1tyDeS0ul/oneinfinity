# 🚀 One&Infinity

### Autonomous Penetration Testing Assistant

<p align="center">
  <b>AI-powered offensive security system that discovers, prioritizes, and exploits vulnerabilities autonomously.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/AI-Autonomous-red">
  <img src="https://img.shields.io/badge/Security-Offensive-black">
  <img src="https://img.shields.io/badge/License-MIT-green">
  <img src="https://img.shields.io/badge/Status-Active-blue">
</p>

---

## ⚡ Why One&Infinity?

Most tools **scan**.
Some tools **exploit**.

👉 **One&Infinity thinks.**

It simulates a real attacker:

* Maps attack surface
* Prioritizes high-value targets
* Executes multi-step exploit chains
* Learns from success & failure

---

## 🧠 Core Capabilities

### 🔗 Autonomous Exploit Chaining

* Multi-step attack execution
* Token/credential reuse across nodes
* Real-world attack path simulation

```
Insecure Storage → Extract JWT → API Access → Privilege Escalation
```

---

### 🧠 AI Decision Engine

* Graph-based prioritization
* Dynamic agent routing (XSS / SQLi / API / Mobile)
* Context-aware attack selection

---

### 🕸️ Adaptive Recon Engine

* Subdomain + API discovery
* JS endpoint extraction
* Cloud asset intelligence

---

### 🛡️ Intelligent WAF Bypass

* Detects WAF (Cloudflare, Akamai, etc.)
* Applies mutation strategies automatically
* Retries attacks with adaptive payloads

---

### 📱 Mobile Security Engine

* Static + dynamic analysis
* Secret extraction (API keys, tokens)
* Frida script generation
* API reverse engineering

---

### 📡 Traffic Capture & Replay

* Full HTTP interception
* Replay + fuzz requests
* Business logic flaw detection

---

### 🧬 Learning System

* Tracks successful attack patterns
* Improves future scans
* Prioritizes high-yield vulnerabilities

---

## 🖥️ Control Panel (Web UI)

| Module         | Description                        |
| -------------- | ---------------------------------- |
| 🧠 Brain       | AI decision + attack orchestration |
| ⚡ Intelligence | Live event stream                  |
| 🐝 Swarm       | Multi-agent execution              |
| 🔗 Chains      | Exploit chain visualization        |
| 📡 Traffic     | HTTP capture & replay              |
| 📱 Mobile      | APK/IPA analysis                   |
| 🧬 Evolution   | Learning insights                  |
| 🏆 Hunter      | Bug bounty automation              |

---

## 🎥 Demo

<p align="center">
  <img src="docs/demo.gif" width="900">
</p>

---

## ⚙️ Architecture

```text
Target → Recon → Attack Graph → AI Decision Engine
        ↓
   Agent Swarm (XSS / SQLi / API / Mobile)
        ↓
   Exploit Chain Engine → Validation → Reporting
        ↓
   Learning System → Improves next scan
```

---

## 🚀 Quick Start

### Clone

```bash
git clone https://github.com/Inf1n1tyDeS0ul/oneinfinity.git
cd oneinfinity
```

---

### Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

### Run Backend

```bash
python3 oneinfinity.py
```

---

### Run UI

```bash
cd web/frontend
npm install
npm run dev
```

---

## 🧪 Example

```bash
python3 oneinfinity.py scan --target example.com
```

---

## 🔥 What Makes This Different?

| Capability   | Traditional Tools | One&Infinity |
| ------------ | ----------------- | ------------ |
| Scanning     | Static            | Adaptive     |
| Exploitation | Manual            | Autonomous   |
| Chaining     | ❌                 | ✅            |
| AI Decision  | ❌                 | ✅            |
| Learning     | ❌                 | ✅            |

---

## 🔐 Safety

* Scope validation enforced
* Rate limiting built-in
* Safe execution guardrails
* Controlled exploitation

---

## 📊 Output

* Structured findings
* Exploit chains
* Risk scoring
* Bug bounty-ready reports

---

## 🏆 Built For

* Bug bounty hunters
* Red teamers
* Security researchers
* Offensive engineers

---

## 📜 License

MIT License

---

## ⭐ Support

If you like this project:

👉 Star the repo
👉 Share with the community

---

## 🧠 Philosophy

> "Automation finds bugs.
> Intelligence finds impact."
