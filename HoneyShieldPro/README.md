# HoneyShield Pro 🛡️

HoneyShield Pro is an advanced, modular SSH honeypot with dynamic threat detection capabilities. It detects complex network scanning behaviors and brute force attempts in real-time.

## 🚀 Features

- **Multi-Vector Detection**:
    - **ICMP Ping Sweep** (Simulated via connection flood patterns).
    - **Nmap Scan Detection** (Identifies rapid connect/disconnect probing).
    - **TCP SYN Scan Detection** (Detects incomplete/rapid handshake floods).
    - **SSH Brute Force** (Blocks and logs rapid login failures).
- **Dynamic Configuration**: Select specific detection modules at runtime.
- **Real-Time Alerts**: CLI alerts for high-severity threats.
- **Structured JSON Logging**: Detailed event logs for analysis.

## 🛠️ Installation

```bash
git clone <repository_url>
cd HoneyShieldPro
```

## 🏃 How to Run

1. Start the tool:
   ```bash
   python main.py
   ```

2. Select detection modes (e.g., `1,3` or `5` for All).
3. Choose a port (default `2222`).

## 🧪 Simulation Guide

### 1. Simulating Brute Force
Attempt multiple logins rapidly:
```bash
ssh -p 2222 root@localhost
# Repeat 5+ times quickly
```
*Expected Alert:* `[ALERT DETECTED] Attack Type: Brute Force`

### 2. Simulating Nmap/Port Scan
Use netcat to connect and immediately exit (simulates port check):
```bash
nc localhost 2222
# Press Ctrl+C immediately
```
*Expected Alert:* `[ALERT DETECTED] Attack Type: Nmap Scan Behavior`

### 3. Simulating TCP SYN Flood
Use a loop to open many connections:
```bash
for i in {1..20}; do nc -z -w 1 localhost 2222; done
```
*Expected Alert:* `[ALERT DETECTED] Attack Type: TCP SYN Scan / Flood`

## 📂 Logs
Logs are saved in `logs/honeypot_log.json`.

---
**Disclaimer**: For educational use only.
