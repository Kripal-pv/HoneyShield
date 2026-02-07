import sys
import threading
import time
from core.server import HoneyServerPro
from core.ftp_server import FTPServer
from core.logger import HoneyLogger
from core.detection_engine import DetectionEngine

def main():
    print("\n" + "="*50)
    print("      Welcome to HoneyShield Pro")
    print("      SSH & FTP Honeypot / IDS")
    print("="*50 + "\n")

    print("[*] Configuration Setup")
    
    # 1. Configure Detection Modes
    print("\nSelect detection types to enable:")
    print("1) ICMP Ping Sweep Detection")
    print("2) Nmap Scan Detection")
    print("3) TCP SYN Scan Detection")
    print("4) SSH/FTP Brute Force Detection")
    print("5) All")

    choices_input = input("\nEnter choices separated by comma (example: 1,3,4) [Default: 5]: ").strip()
    
    try:
        if not choices_input:
            active_modes = [5]
        else:
            active_modes = [int(c.strip()) for c in choices_input.split(',')]
    except ValueError:
        print("Invalid choices. Enabling default (All).")
        active_modes = [5]

    # Initialize shared components
    logger = HoneyLogger("honeypot_log.json")
    detector = DetectionEngine(active_modes)

    # 2. Configure SSH
    try:
        ssh_port_input = input("Enter SSH port (Default: 2222): ").strip()
        ssh_port = int(ssh_port_input) if ssh_port_input else 2222
    except ValueError:
        print("Invalid port. Using default 2222.")
        ssh_port = 2222

    # 3. Configure FTP
    try:
        ftp_port_input = input("Enter FTP port (Default: 2121) or 0 to disable: ").strip()
        ftp_port = int(ftp_port_input) if ftp_port_input else 2121
    except ValueError:
        print("Invalid port. Using default 2121.")
        ftp_port = 2121

    servers = []

    # Start SSH
    print(f"\n[*] Starting SSH Honeypot on Port {ssh_port}...")
    ssh_server = HoneyServerPro("0.0.0.0", ssh_port, detector, logger)
    ssh_thread = threading.Thread(target=ssh_server.start)
    ssh_thread.daemon = True
    ssh_thread.start()
    servers.append(ssh_thread)

    # Start FTP
    if ftp_port > 0:
        print(f"[*] Starting FTP Honeypot on Port {ftp_port}...")
        ftp_server = FTPServer("0.0.0.0", ftp_port, detector, logger)
        ftp_thread = threading.Thread(target=ftp_server.start)
        ftp_thread.daemon = True
        ftp_thread.start()
        servers.append(ftp_thread)

    print("\n[+] HoneyShield is running! Press Ctrl+C to stop.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping HoneyShield...")
        sys.exit(0)

if __name__ == "__main__":
    main()
