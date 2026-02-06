import sys
from core.server import HoneyServerPro

def main():
    print("\n" + "="*40)
    print("      Welcome to HoneyShield Pro")
    print("="*40 + "\n")

    print("Select detection types to enable:")
    print("1) ICMP Ping Sweep Detection")
    print("2) Nmap Scan Detection")
    print("3) TCP SYN Scan Detection")
    print("4) SSH Brute Force Detection")
    print("5) All")

    choices_input = input("\nEnter choices separated by comma (example: 1,3,4): ").strip()
    
    try:
        active_modes = [int(c.strip()) for c in choices_input.split(',')]
    except ValueError:
        print("Invalid choices. Enabling default (All).")
        active_modes = [5]

    try:
        port_input = input("\nEnter port number to open for honeypot service (Default: 2222): ").strip()
        port = int(port_input) if port_input else 2222
    except ValueError:
        print("Invalid port. Using default 2222.")
        port = 2222

    print(f"\n[*] Starting HoneyShield Pro on Port {port}...")
    print(f"[*] Enabled Detection Modes: {active_modes}")
    
    server = HoneyServerPro("0.0.0.0", port, active_modes)
    server.start()

if __name__ == "__main__":
    main()
