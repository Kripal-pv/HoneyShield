import json
import socket
import sys
import threading
from core.server import HoneyServer

CONFIG_FILE = "config.json"

def load_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {
            "port": 2222,
            "host": "0.0.0.0",
            "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu",
            "log_file": "logs/honeypot_log.json",
            "brute_force_threshold": 5,
            "time_window": 10
        }

def main():
    print("\n" + "="*40)
    print("      Welcome to HoneyShield")
    print("="*40 + "\n")

    ready = input("Are you ready to create a honeypot? (Y/N): ").strip().lower()
    if ready != 'y':
        print("Exiting...")
        sys.exit(0)

    config = load_config()

    try:
        port_input = input(f"Enter port number (default: {config['port']}): ").strip()
        port = int(port_input) if port_input else config['port']
    except ValueError:
        print("Invalid port. Using default.")
        port = config['port']

    print(f"Confirm service type: SSH simulation only")
    
    server = HoneyServer(config['host'], port, config['banner'], config)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nStopping HoneyShield...")
        sys.exit(0)

if __name__ == "__main__":
    main()
