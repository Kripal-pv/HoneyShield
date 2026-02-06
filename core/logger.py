import json
import os
from datetime import datetime
import threading

class HoneyLogger:
    def __init__(self, log_file="logs/honeypot_log.json"):
        self.log_file = log_file
        self.lock = threading.Lock()
        self._ensure_log_dir()

    def _ensure_log_dir(self):
        log_dir = os.path.dirname(self.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Initialize file if it doesn't exist
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w') as f:
                json.dump([], f)

    def log_attempt(self, data):
        """
        Logs an attack attempt to the JSON file.
        data: dict containing attack details
        """
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            **data
        }

        with self.lock:
            try:
                # Read existing logs (inefficient for huge files but fine for lab)
                if os.path.exists(self.log_file) and os.path.getsize(self.log_file) > 0:
                    with open(self.log_file, 'r') as f:
                        try:
                            logs = json.load(f)
                            if not isinstance(logs, list):
                                logs = []
                        except json.JSONDecodeError:
                            logs = []
                else:
                    logs = []

                logs.append(entry)

                with open(self.log_file, 'w') as f:
                    json.dump(logs, f, indent=4)
            except Exception as e:
                print(f"[ERROR] Failed to write log: {e}")
