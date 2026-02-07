import socket
import threading
import time

class HoneyServerPro:
    def __init__(self, host, port, detector, logger):
        self.host = host
        self.port = port
        self.banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu"
        self.logger = logger
        self.detector = detector
        self.running = False

    def start(self):
        self.running = True
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            
            print(f"[*] HoneyShield Pro Active on {self.host}:{self.port}")
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
        except KeyboardInterrupt:
            print("\nShutting down server...")
        finally:
            try:
                server_socket.close()
            except:
                pass

    def handle_client(self, client_sock, addr):
        ip, port = addr
        start_time = time.time()
        
        # 1. Register Connection (Checks for Syn Scan / Flood)
        alert = self.detector.register_connection(ip)
        if alert:
             self.logger.log_event({
                "source_ip": ip,
                "source_port": port,
                "destination_port": self.port,
                **alert
            })

        try:
            client_sock.settimeout(10)
            
            # 2. Send Banner
            try:
                client_sock.sendall(f"{self.banner}\r\n".encode('utf-8'))
                banner_sent = True
            except:
                banner_sent = False

            # 3. Wait/Read (Detect Logic)
            # Give client a moment to respond or disconnect
            # Nmap often disconnects immediately after banner
            try:
                client_sock.recv(1024)
            except socket.timeout:
                pass
            
            # Check for immediate disconnect (Nmap behavior)
            duration = time.time() - start_time
            alert = self.detector.analyze_behavior(ip, duration, banner_sent)
            if alert:
                 self.logger.log_event({
                    "source_ip": ip,
                    "source_port": port,
                    "destination_port": self.port,
                    **alert
                })

            # 4. Login Simulation
            client_sock.sendall(b"login: ")
            username = self._receive_line(client_sock)
            
            client_sock.sendall(b"password: ")
            password = self._receive_line(client_sock)
            
            # 5. Brute Force Analysis
            if username or password:
                alert = self.detector.analyze_login(ip, username, password)
                if alert:
                     self.logger.log_event({
                        "source_ip": ip,
                        "source_port": port,
                        "destination_port": self.port,
                         "username": username,
                         "password": password,
                        **alert
                    })
                else:
                    # Log normal attempt even if not alert
                    self.logger.log_event({
                        "source_ip": ip,
                        "source_port": port,
                        "destination_port": self.port,
                        "username": username,
                        "password": password,
                        "detection_type": "Login Attempt",
                        "severity": "Low",
                        "attempt_count": 1
                    })

            # 6. Deny & Close
            time.sleep(1)
            client_sock.sendall(b"\r\nLogin incorrect\r\n")
            
        except BrokenPipeError:
            pass 
        except Exception as e:
            # print(f"[DEBUG] Error {e}")
            pass
        finally:
            try:
                client_sock.close()
            except:
                pass

    def _receive_line(self, sock):
        buffer = b""
        while len(buffer) < 256:
            try:
                chunk = sock.recv(1)
                if not chunk: break
                if chunk == b'\n' or chunk == b'\r': break
                buffer += chunk
            except: break
        return buffer.decode('utf-8', errors='ignore').strip()
