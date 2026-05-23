# logger.py - Thread-safe logging engine for NetSentinel v4

import json
import datetime
import threading

class SecurityLogger:
    """Thread-safe event logging system with JSON export capabilities."""
    def __init__(self):
        self._lock = threading.Lock()
        self._logs = []
        self._listeners = []

    def log(self, severity, message):
        """Creates a log entry and dispatches it to registered listeners."""
        entry = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "severity": severity.upper(), # INFO, WARNING, CRITICAL
            "message": message
        }
        with self._lock:
            self._logs.append(entry)
            # Limit memory footprint to last 5000 entries
            if len(self._logs) > 5000:
                self._logs.pop(0)
            
            listeners_snapshot = list(self._listeners)

        for callback in listeners_snapshot:
            try:
                callback(entry)
            except Exception:
                pass

    def add_listener(self, callback):
        """Registers a callback function to receive live log updates."""
        with self._lock:
            if callback not in self._listeners:
                self._listeners.append(callback)

    def remove_listener(self, callback):
        """Unregisters a callback listener."""
        with self._lock:
            if callback in self._listeners:
                self._listeners.remove(callback)

    def get_logs(self):
        """Returns a snapshot copy of the current log buffer."""
        with self._lock:
            return list(self._logs)

    def clear(self):
        """Clears all stored logs."""
        with self._lock:
            self._logs.clear()

    def export_json(self, file_path):
        """Saves current logs to a structured JSON file."""
        with self._lock:
            logs_to_save = list(self._logs)
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(logs_to_save, f, indent=4, ensure_ascii=False)
            return True, None
        except Exception as e:
            return False, str(e)

# Global singleton instance
app_logger = SecurityLogger()
