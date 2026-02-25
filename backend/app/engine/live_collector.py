import os
import time
import requests
import json
import win32evtlog
import win32evtlogutil
import win32con
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8000"
POLL_INTERVAL = 5 # seconds
FILES_TO_WATCH = [
    # Add actual paths here, e.g., "C:/inetpub/logs/LogFiles/W3SVC1/u_ex210101.log"
]

class LiveCollector:
    def __init__(self):
        self.server = 'localhost'
        self.last_security_index = self.get_last_event_index('Security')
        self.last_system_index = self.get_last_event_index('System')

    def get_last_event_index(self, log_type):
        try:
            hand = win32evtlog.OpenEventLog(self.server, log_type)
            count = win32evtlog.GetNumberOfEventLogRecords(hand)
            # Start from the current end to avoid backlog flood
            return count
        except Exception as e:
            print(f"Error opening {log_type} log: {e}")
            return 0

    def poll_windows_events(self, log_type, last_index):
        try:
            hand = win32evtlog.OpenEventLog(self.server, log_type)
            flags = win32con.EVENTLOG_FORWARDS_READ | win32con.EVENTLOG_SEQUENTIAL_READ
            
            # Read from the last index
            events = win32evtlog.ReadEventLog(hand, flags, last_index)
            new_last_index = last_index
            
            for event in events:
                new_last_index += 1
                msg = win32evtlogutil.SafeFormatMessage(event, log_type)
                timestamp = event.TimeGenerated.Format()
                
                # Normalize type
                source = event.SourceName
                event_id = event.EventID & 0xFFFF
                
                raw_log = f"Time: {timestamp} | Source: {source} | ID: {event_id} | Message: {msg}"
                self.ingest_log(raw_log, "windows")
                
            return new_last_index
        except Exception as e:
            print(f"Error polling {log_type}: {e}")
            return last_index

    def ingest_log(self, raw_log, log_type="auto"):
        try:
            print(f"Ingesting: {raw_log[:100]}...")
            requests.post(
                f"{BASE_URL}/ingest/raw", 
                params={"raw_log": raw_log, "log_type": log_type},
                timeout=5
            )
        except Exception as e:
            print(f"Failed to ingest: {e}")

    def run(self):
        print(f"Live Collector started. Monitoring Windows Events and {len(FILES_TO_WATCH)} files...")
        while True:
            # Poll Windows Security Log (logins, access)
            self.last_security_index = self.poll_windows_events('Security', self.last_security_index)
            
            # Poll Windows System Log (process changes, errors)
            self.last_system_index = self.poll_windows_events('System', self.last_system_index)
            
            # TODO: Add local file tailing here if needed
            
            time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    collector = LiveCollector()
    collector.run()
