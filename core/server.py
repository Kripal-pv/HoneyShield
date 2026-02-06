import socket
import threading
import time
from .logger import HoneyLogger
from .analyzer import Analyzer

class HoneyServer:
    def __init__(self, host, port, banner, config):
        self.host = host
        self.port = port
        self.banner = banner
        self.config = config
        self.logger = HoneyLogger(config.get("log_file", "logs/honeypot_log.json"))
        self.analyzer = Analyzer(
            brute_force_threshold=config.get("brute_force_threshold", 5),
            time_window=config.get("time_window", 10)
        )
        self.processing_delay = config.get("processing_delay", 1.0)
        self.running = False

    def start(self):
        self.running = True
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            
            print(f"[*] HoneyShield Active on {self.host}:{self.port}")
            print(f"[*] Banner: {self.banner}")
            
            while self.running:
                client_sock, addr = server_socket.accept()
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, addr)
                )
                client_handler.daemon = True
                client_handler.start()
                
        except Exception as e:
            print(f"[!] Server Error: {e}")
        finally:
            server_socket.close()

    def handle_client(self, client_sock, addr):
        ip, port = addr
        self.analyzer.record_connection(ip)
        
        try:
            client_sock.settimeout(10) # 10s timeout
            
            # 1. Send Banner
            client_sock.sendall(f"{self.banner}\r\n".encode('utf-8'))
            
            # 2. Receive Client Version (Fake Handshake)
            # Just read, we don't care what it is for this basic simulation
            try:
                client_sock.recv(1024)
            except socket.timeout:
                pass

            # 3. Simulate Login Prompt
            # Note: Real SSH clients won't see this text interactive mode immediately,
            # but netcat/telnet users will. 
            client_sock.sendall(b"login: ")
            username = self._receive_line(client_sock)
            
            client_sock.sendall(b"password: ")
            password = self._receive_line(client_sock)
            
            # 4. Analyze & Log
            if username or password: # Only log if we got something
                analysis = self.analyzer.analyze_attempt(ip, username, password)
                
                log_data = {
                    "source_ip": ip,
                    "source_port": port,
                    "destination_port": self.port,
                    "username": username,
                    "password": password,
                    "attempt_count": analysis["attempt_count"],
                    "attack_type": analysis["attack_type"],
                    "severity": analysis["severity"],
                    "risk_score": analysis["risk_score"]
                }
                
                self.logger.log_attempt(log_data)
                
                # Alerts
                if analysis["attack_type"] == "Brute Force" or analysis["severity"] == "High":
                    print(f"\n[ALERT] Possible Brute Force Detected")
                    print(f"Source IP: {ip}")
                    print(f"Attempts: {analysis['attempt_count']}")
                    print(f"Severity: {analysis['severity']}\n")

            # 5. Deny Access
            if self.processing_delay > 0:
                time.sleep(self.processing_delay) # Fake processing delay
            client_sock.sendall(b"\r\nLogin incorrect\r\n")
            client_sock.close()
            
        except BrokenPipeError:
            pass # Client disconnected
        except ConnectionResetError:
            pass
        except Exception as e:
            # print(f"[DEBUG] Error handling client {ip}: {e}")
            pass
        finally:
            try:
                client_sock.close()
            except:
                pass

    def _receive_line(self, sock):
        """Reads a line from socket until \n or \r"""
        buffer = b""
        while len(buffer) < 256: # Limit length
            try:
                chunk = sock.recv(1)
                if not chunk:
                    break
                if chunk == b'\n' or chunk == b'\r':
                    break
                buffer += chunk
            except:
                break
        return buffer.decode('utf-8', errors='ignore').strip()
