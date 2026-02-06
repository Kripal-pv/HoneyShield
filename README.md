# HoneyShield 🛡️

HoneyShield is a modular Python-based CLI honeypot tool designed to simulate a basic SSH server. It captures attacker behavior, detects brute force attempts, and logs structured attack data for analysis.

## 🚀 Features

- **SSH Simulation**: Displays a realistic fake SSH banner and login prompt.
- **Brute Force Detection**: Automatically detects rapid login attempts (default: >5 attempts in 10s).
- **Risk Classification**: Assigns risk scores to IP addresses based on their behavior.
- **Structured Logging**: Saves all attempts to `logs/honeypot_log.json` in detailed JSON format.
- **Real-Time Alerts**: Displays CLI alerts when high-severity attacks are detected.
- **Threaded Architecture**: Handles multiple concurrent connections.

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone <repository_url>
   cd HoneyShield
   ```

2. **Requirements**:
   - Python 3.x
   - No external dependencies required (uses standard library only).

## 🏃 How to Run

1. Navigate to the project directory:
   ```bash
   cd HoneyShield
   ```

2. Start the honeypot:
   ```bash
   python main.py
   ```

3. Follow the CLI prompts:
   - Type `Y` to confirm.
   - Enter a port number (default `2222`).
   - The server will start listening.

## 🧪 Example Attack Simulation

To test the honeypot, you can use `netcat` or `ssh` from another terminal or machine.

**Using Netcat (Recommended for testing text prompts):**
```bash
nc localhost 2222
```
*Note: You will see the banner, then "login:" and "password:" prompts.*

**Using SSH:**
```bash
ssh -p 2222 root@localhost
```
*Note: Real SSH clients may fail the handshake or hang because this is a basic socket simulation, but the connection will still be logged.*

## 📂 Log Output Example

The log file (`logs/honeypot_log.json`) contains structured data:

```json
[
    {
        "timestamp": "2026-02-06 10:45:21",
        "source_ip": "127.0.0.1",
        "source_port": 52341,
        "destination_port": 2222,
        "username": "root",
        "password": "password123",
        "attempt_count": 6,
        "attack_type": "Brute Force",
        "severity": "High",
        "risk_score": 60
    }
]
```

## 🛡️ Security Note

This tool is for **educational and lab use only**.
- Do not run this on a production server without proper isolation.
- It is a low-interaction honeypot and does not actually execute commands.
