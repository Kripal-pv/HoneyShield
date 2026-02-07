import socket
import threading
import time

class FTPServer:
    def __init__(self, host, port, detector, logger):
        self.host = host
        self.port = port
        self.detector = detector
        self.logger = logger
        self.running = False
        self.banner = "220 (vsFTPd 3.0.3)"

    def start(self):
        self.running = True
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            
            print(f"[*] FTP Server Active on {self.host}:{self.port}")
            
            while self.running:
                client_sock, addr = server_socket.accept()
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, addr)
                )
                client_handler.daemon = True
                client_handler.start()
                
        except Exception as e:
            print(f"[!] FTP Server Error: {e}")
        finally:
            try:
                server_socket.close()
            except:
                pass

    def handle_client(self, client_sock, addr):
        ip, port = addr
        start_time = time.time()
        
        # Register connection
        alert = self.detector.register_connection(ip)
        if alert:
            self.logger.log_event({
                "source_ip": ip,
                "source_port": port,
                "destination_port": self.port,
                "protocol": "FTP",
                **alert
            })

        try:
            client_sock.settimeout(10)
            client_sock.sendall(f"{self.banner}\r\n".encode('utf-8'))
            
            # Simple FTP interaction
            while True:
                data = self._receive_line(client_sock)
                if not data:
                    break
                    
                cmd = data.split(' ')[0].upper()
                
                if cmd == "USER":
                    client_sock.sendall(b"331 Please specify the password.\r\n")
                    username = data.split(' ', 1)[1] if len(data.split(' ')) > 1 else ""
                    
                    # Log attempt
                    self.logger.log_event({
                         "source_ip": ip,
                         "source_port": port,
                         "destination_port": self.port,
                         "protocol": "FTP",
                         "username": username,
                         "detection_type": "Login Attempt",
                         "severity": "Low"
                    })

                elif cmd == "PASS":
                     client_sock.sendall(b"530 Login incorrect.\r\n")
                     # We can alert on brute force here if we want, using detector
                     password = data.split(' ', 1)[1] if len(data.split(' ')) > 1 else ""
                     
                     alert = self.detector.analyze_login(ip, "ftp_user", password) # Using placeholder user for aggregate tracking
                     if alert:
                         self.logger.log_event({
                            "source_ip": ip,
                            "source_port": port,
                            "destination_port": self.port,
                            "protocol": "FTP",
                            "password": password,
                            **alert
                        })
                     break # Close after failed login
                
                elif cmd == "QUIT":
                    client_sock.sendall(b"221 Goodbye.\r\n")
                    break
                else:
                    client_sock.sendall(b"500 Unknown command.\r\n")

        except Exception as e:
            pass
        finally:
            client_sock.close()
            # Analyze behavior on close (scan detection)
            duration = time.time() - start_time
            alert = self.detector.analyze_behavior(ip, duration, True)
            if alert:
                 self.logger.log_event({
                    "source_ip": ip,
                    "source_port": port,
                    "destination_port": self.port,
                    "protocol": "FTP",
                    **alert
                })

    def _receive_line(self, sock):
        buffer = b""
        while len(buffer) < 256:
            try:
                chunk = sock.recv(1)
                if not chunk: break
                if chunk == b'\n': break
                buffer += chunk
            except: break
        return buffer.decode('utf-8', errors='ignore').strip()
