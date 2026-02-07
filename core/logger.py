import json
import os
from datetime import datetime
import threading

class HoneyLogger:
    def __init__(self, log_filename="honeypot_log.json"):
        # Determine absolute path to HoneyShieldPro/logs/
        # This file is in core/ so we go up one level
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.log_dir = os.path.join(self.base_dir, 'logs')
        self.log_file = os.path.join(self.log_dir, log_filename)
        self.lock = threading.Lock()
        self._ensure_log_dir()

    def _ensure_log_dir(self):
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        
        # Initialize file if it doesn't exist
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w') as f:
                json.dump([], f)

    def log_event(self, data):
        """
        Logs an event to the JSON file.
        data: dict containing event details
        """
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            **data
        }

        with self.lock:
            try:
                # Read existing logs
                logs = []
                if os.path.exists(self.log_file) and os.path.getsize(self.log_file) > 0:
                    with open(self.log_file, 'r') as f:
                        try:
                            logs = json.load(f)
                            if not isinstance(logs, list):
                                logs = []
                        except json.JSONDecodeError:
                            logs = []
                
                logs.append(entry)

                with open(self.log_file, 'w') as f:
                    json.dump(logs, f, indent=4)
            except Exception as e:
                print(f"[ERROR] Failed to write log: {e}")
