<h1 align="center">
  <img src="https://img.shields.io/badge/NetSentinel-v4-blue?style=for-the-badge&logo=windows&logoColor=white" alt="NetSentinel v4"/>
</h1>

<p align="center">
  <b>Real-time AI-powered network security dashboard for Windows</b><br/>
  Monitor active connections, classify threats, and investigate unknown traffic — all in one dark-mode desktop app.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows%2010%2B-0078D4?logo=windows&logoColor=white"/>
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/GUI-PyQt6-41CD52?logo=qt&logoColor=white"/>
  <img src="https://img.shields.io/badge/AI-Gemini%202.0%20Flash-4285F4?logo=google&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-lightgrey"/>
</p>

---

## What Is NetSentinel?

NetSentinel v4 is a local Windows security auditing tool. It gives you a live view of every process and network connection on your machine, automatically classifies each one, and surfaces **unknown or unrecognised traffic** so you can investigate it — without the noise of traditional alerts.

It is **not** an antivirus. It does not block anything automatically. Every action requires your explicit approval.

---

## Key Features

### 🔍 4-Tier Connection Classification

Every connection is evaluated in real time and labelled with one of four tiers:

| Tier | Colour | When Applied |
|------|--------|--------------|
| 🟢 **TRUSTED** | Green | Known Windows system processes (svchost, lsass, etc.) or user-verified |
| 🔵 **NORMAL** | Blue | Recognised software (browsers, IDEs, cloud sync) or LAN-only traffic |
| 🟡 **UNKNOWN** | Orange | First time this process has connected to this IP — no baseline match |
| 🔴 **SUSPICIOUS** | Red | Known malicious port, unsafe execution path with external traffic |

### 🚨 UNKNOWN Panel (Primary Feature)

A dedicated **`! UNKNOWN`** tab shows only unclassified connections — always visible, never buried in logs. This is the main attention area: new software phoning home, unexpected destinations, anything that hasn't been seen before.

### 🧠 AI Analysis (Gemini 2.0 Flash)

Click **Run AI Threat Explanation** on any selected process. The AI engine:
- Only analyses **UNKNOWN** and **SUSPICIOUS** connections (ignores safe traffic)
- Is instructed to **reason from evidence only** — it does not assume guilt or innocence
- Falls back gracefully to local heuristics if no API key is set

### 🛡️ Threat Detection Rules

- **Suspicious port detection** — flags outbound connections to ports like 4444, 31337, 3389, 23, 5900
- **Unsafe execution path** — alerts when a process runs from `Temp`, `Downloads`, `Desktop`, or `AppData\Local\Temp`
- **Volume anomaly** — flags processes with connections far exceeding the system-wide average
- **First-seen IP tracking** — marks any new remote IP as UNKNOWN until classified

### 🧪 Baseline Learning

- **Create Baseline** — snapshots all current connections as NORMAL so you can focus on new activity
- **Mark Process as Safe** — permanently trusts a process for the session
- **Mark Remote IP as Safe** — classifies a specific destination as trusted

### 🔧 Containment Controls

Guarded by confirmation dialogs — no accidental actions:
- **Terminate Process** — kills a selected PID via `taskkill`
- **Block Remote IP** — adds a Windows Firewall outbound block rule via `netsh`

### 📋 Monitoring & Logs

- Auto-refresh at configurable intervals (1 / 2 / 3 / 5 seconds)
- Thread-safe colour-coded event log panel
- JSON log export
- HTML security report generation

---

## Screenshots

> *Dark-mode dashboard with classification-coloured connection rows, UNKNOWN panel, and process tree.*

---

## Installation & Usage

### Requirements

```
Python 3.10+
Windows 10 or later
```

### Install Dependencies

```powershell
pip install PyQt6 psutil google-genai
```

### Run

```powershell
cd netsentinel_v4
python main.py
```

> ⚠️ **Run as Administrator** for full functionality. Features like firewall blocking and process termination require elevated privileges.

---

## AI Setup (Optional)

1. Get a free API key from [Google AI Studio](https://aistudio.google.com/app/apikey)
2. Launch NetSentinel
3. Click the **`API Key`** button in the header bar
4. Paste your key → **Save Key**

Without a key the app works fully — AI analysis falls back to the built-in local heuristics engine.

---

## Project Structure

```
netsentinel_v4/
├── main.py                     # Entry point
│
├── core/
│   ├── process_monitor.py      # psutil-based process discovery & resource metrics
│   ├── network_monitor.py      # TCP/UDP socket enumeration
│   ├── threat_engine.py        # 4-tier classifier, first-seen tracking, alert rules
│   └── ai_engine.py            # Gemini 2.0 Flash wrapper + local heuristic fallback
│
├── ui/
│   ├── dashboard.py            # Main window: tables, filters, inspector, threads, dialogs
│   └── log_panel.py            # Thread-safe colour-coded console log widget
│
└── utils/
    ├── formatters.py           # Byte / IP address / percentage formatters
    └── logger.py               # Thread-safe JSON event logger (singleton)
```

---

## Security Design Principles

| Principle | Implementation |
|---|---|
| **No silent actions** | Kill / block operations require QMessageBox confirmation |
| **No network calls by default** | AI engine is opt-in via key dialog |
| **No data sent externally** | Only the selected process telemetry is sent to Gemini on demand |
| **Graceful degradation** | Gemini quota/auth errors fall back to local rules silently |
| **Read-only monitoring** | Background scan threads never modify system state |

---

## License

MIT — use freely, modify freely, no warranty.
