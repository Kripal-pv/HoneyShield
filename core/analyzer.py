from datetime import datetime
import threading

class Analyzer:
    def __init__(self, brute_force_threshold=5, time_window=10):
        self.brute_force_threshold = brute_force_threshold
        self.time_window = time_window
        
        # Structure: {ip_address: { 'attempts': [], 'connection_count': 0, 'total_logins': 0 }}
        self.ip_history = {}
        self.lock = threading.Lock()

    def analyze_attempt(self, ip_address, username, password):
        """
        Analyzes the login attempt and returns detection results.
        Returns: (attack_type, severity, risk_score)
        """
        with self.lock:
            if ip_address not in self.ip_history:
                self.ip_history[ip_address] = {
                    'attempts': [],
                    'connection_count': 0,
                    'total_logins': 0,
                    'risk_score': 0
                }
            
            history = self.ip_history[ip_address]
            now = datetime.now()
            
            # Update stats
            history['total_logins'] += 1
            history['attempts'].append(now)
            
            # Prune old attempts outside time window for rate limiting check
            history['attempts'] = [
                t for t in history['attempts'] 
                if (now - t).total_seconds() <= self.time_window
            ]
            
            attempt_count = len(history['attempts'])
            
            # Determine Attack Type & Severity
            attack_type = "Login Attempt"
            severity = "Low"
            
            # Brute Force Detection
            if attempt_count > self.brute_force_threshold:
                attack_type = "Brute Force"
                severity = "High"
            elif attempt_count >= 3:
                severity = "Medium"
            
            # Calculate Risk Score
            # Base score for detecting brute force
            if attack_type == "Brute Force":
                history['risk_score'] += 50
            else:
                history['risk_score'] += 10 # Base cost per attempt
                
            current_risk_score = history['risk_score']
            
            return {
                "attack_type": attack_type,
                "severity": severity,
                "risk_score": current_risk_score,
                "attempt_count": attempt_count
            }

    def record_connection(self, ip_address):
        with self.lock:
            if ip_address not in self.ip_history:
                 self.ip_history[ip_address] = {
                    'attempts': [],
                    'connection_count': 0,
                    'total_logins': 0,
                    'risk_score': 0
                }
            self.ip_history[ip_address]['connection_count'] += 1
