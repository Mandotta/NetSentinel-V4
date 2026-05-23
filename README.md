# NetSentinel v4 — AI Network Security Analyzer

A real-time Windows desktop security monitoring dashboard built with Python 3.13 + PyQt6.

![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![PyQt6](https://img.shields.io/badge/GUI-PyQt6-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Features

- **4-Tier Connection Classification** — TRUSTED / NORMAL / UNKNOWN / SUSPICIOUS with colour-coded rows
- **UNKNOWN Panel** — dedicated tab that surfaces first-seen or unclassified connections immediately
- **Real-time Process Monitor** — PID, name, CPU, memory, user, and parent-child tree view
- **Threat Engine** — heuristic rules: suspicious ports, unsafe execution paths, connection volume spikes
- **AI Explainer** — Google Gemini 2.0 Flash analyses UNKNOWN + SUSPICIOUS connections on demand
- **Baseline Learning** — "Create Baseline" and "Mark as Safe" buttons to teach the tool your environment
- **Containment Controls** — terminate processes and block IPs via Windows Firewall (admin elevation required)
- **Log Export** — JSON log export and HTML report generation

---

## Tech Stack

| Layer | Library |
|---|---|
| GUI | PyQt6 |
| Process / Socket data | psutil |
| AI analysis | google-genai (Gemini 2.0 Flash) |
| Build | PyInstaller |

---

## Running from Source

```powershell
# 1. Install dependencies
pip install PyQt6 psutil google-genai

# 2. Launch
cd netsentinel_v4
python main.py
```

> **Note:** Some features (firewall block, process kill) require the terminal to be run as Administrator.

---

## AI Setup

1. Get a free Gemini API key from [Google AI Studio](https://aistudio.google.com)
2. Launch NetSentinel and click the **API Key** button in the header
3. Paste your key and click **Save Key**

The AI engine only analyses **UNKNOWN** and **SUSPICIOUS** connections — it never assumes, only reasons from evidence.

---

## Project Structure

```
netsentinel_v4/
├── main.py                    # Entry point
├── core/
│   ├── process_monitor.py     # psutil process discovery
│   ├── network_monitor.py     # TCP socket tracking
│   ├── threat_engine.py       # 4-tier classification + alert rules
│   └── ai_engine.py           # Gemini API wrapper + local fallback
├── ui/
│   ├── dashboard.py           # Main window, tables, threads, dialogs
│   └── log_panel.py           # Thread-safe colour-coded log panel
└── utils/
    ├── formatters.py           # Byte / address formatters
    └── logger.py               # Thread-safe JSON logger
```

---

## Security Notice

This is a **diagnostic tool** — not an antivirus. All active actions (kill process, block IP) require explicit user confirmation via dialog prompts.
