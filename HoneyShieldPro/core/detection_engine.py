import time
from datetime import datetime
import threading

class DetectionEngine:
    def __init__(self, enabled_modes):
        """
        enabled_modes: list of integers representing selected modes.
        1: ICMP Ping Sweep (Simulated via connection flood checks)
        2: Nmap Scan
        3: TCP SYN Scan
        4: SSH Brute Force
        5: All
        """
        self.modes = enabled_modes
        if 5 in self.modes:
            self.modes = [1, 2, 3, 4]

        # IP History Structure:
        # {
        #   '192.168.1.1': {
        #       'attempts': [timestamp1, timestamp2],
        #       'connections': [{'start': ts, 'duration': float}, ...],
        #       'severity': 'Low'
        #   }
        # }
        self.ip_history = {}
        self.lock = threading.Lock()

    def _get_ip_record(self, ip):
        if ip not in self.ip_history:
            self.ip_history[ip] = {
                'login_attempts': [],
                'connections': [], # List of (timestamp, duration)
                'alerts_triggered': set() # To avoid spamming same alert
            }
        return self.ip_history[ip]

    def _alert(self, detection_type, ip, attempts, severity):
        # Basic debounce - don't alert same thing multiple times for same IP in short window
        # For simplicity in this lab, we just print always but maybe mark severity
        print("\n" + "="*30)
        print(f"[ALERT DETECTED]")
        print(f"Attack Type: {detection_type}")
        print(f"Source IP: {ip}")
        print(f"Attempts: {attempts}")
        print(f"Severity: {severity}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*30 + "\n")
        return {
            "detection_type": detection_type,
            "severity": severity,
            "attempt_count": attempts
        }

    def register_connection(self, ip):
        """Called when a client connects"""
        with self.lock:
            record = self._get_ip_record(ip)
            now = datetime.now()
            
            # Record connection start
            # We store provisional record, duration will be updated on close or assume 0 for SYN check
            record['connections'].append({'start': now, 'duration': 0})
            
            # Prune old connections (keep last 60 seconds)
            record['connections'] = [c for c in record['connections'] if (now - c['start']).total_seconds() < 60]

            conn_count = len(record['connections'])

            # 3) TCP SYN Scan Detection & 1) ICMP/Ping Sweep (Simulated)
            # Both characterized by rapid connections
            if 3 in self.modes or 1 in self.modes:
                # If we have many connections in very short time
                recent_conns = [c for c in record['connections'] if (now - c['start']).total_seconds() < 5]
                if len(recent_conns) > 10:
                    if 3 in self.modes:
                        return self._alert("TCP SYN Scan / Flood", ip, len(recent_conns), "High")
                    elif 1 in self.modes:
                         return self._alert("Possible Network Scan", ip, len(recent_conns), "Medium")
        return None

    def analyze_behavior(self, ip, duration, banner_sent):
        """Called when connection closes"""
        with self.lock:
            record = self._get_ip_record(ip)
            if not record['connections']:
                return None
            
            # Update last connection duration
            last_conn = record['connections'][-1]
            last_conn['duration'] = duration
            
            # 2) Nmap Scan Detection
            # Nmap (esp -sS or -sT) often connects and disconnects immediately upon receiving banner or just checking open
            if 2 in self.modes:
                if duration < 0.5 and banner_sent:
                    # Check if this happened multiple times? Or just once is suspicious?
                    # For lab, 2+ quick drops is suspicious
                    short_conns = [c for c in record['connections'] if c['duration'] < 0.5]
                    if len(short_conns) >= 2:
                         return self._alert("Nmap Scan Behavior", ip, len(short_conns), "High")
            
        return None

    def analyze_login(self, ip, username, password):
        """Called on login attempt"""
        if 4 not in self.modes:
            return None

        with self.lock:
            record = self._get_ip_record(ip)
            now = datetime.now()
            record['login_attempts'].append(now)
            
            # Prune old login attempts (keep last 30s)
            record['login_attempts'] = [t for t in record['login_attempts'] if (now - t).total_seconds() < 30]
            
            count = len(record['login_attempts'])
            
            if count >= 5:
                 return self._alert("Brute Force", ip, count, "High")
            
        return None
