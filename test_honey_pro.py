import socket
import time
import sys
import threading

HOST = 'localhost'
PORT = 2222

def test_nmap_scan_behavior():
    print(f"\n[TEST] Simulating Nmap Scan Behavior (Quick Disconnects)...")
    for i in range(3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((HOST, PORT))
            # Just connect and immediately close
            sock.close()
            time.sleep(0.1) 
        except Exception as e:
            print(f"Error in Nmap sim: {e}")

def test_syn_flood_sim():
    print(f"\n[TEST] Simulating TCP SYN Flood (Rapid Connections)...")
    threads = []
    
    def spam_connect():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((HOST, PORT))
            sock.close()
        except: pass

    for i in range(15):
        t = threading.Thread(target=spam_connect)
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()

def test_brute_force():
    print(f"\n[TEST] Simulating SSH Brute Force...")
    for i in range(6):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((HOST, PORT))
            sock.recv(1024) # banner
            
            sock.sendall(b"SSH-2.0-Test\r\n")
            
            time.sleep(0.1)
            sock.sendall(f"user{i}\n".encode()) # username
            time.sleep(0.1)
            sock.sendall(f"pass{i}\n".encode()) # password
            
            sock.recv(1024)
            sock.close()
        except Exception as e:
            print(f"Error in Brute Force sim: {e}")

if __name__ == "__main__":
    time.sleep(2) # Wait for server to start if running via script
    test_nmap_scan_behavior()
    time.sleep(1)
    test_syn_flood_sim()
    time.sleep(1)
    test_brute_force()
    print("\n[TEST] All simulations complete.")
