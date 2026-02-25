import os
import time
import requests
import socket
import win32evtlog
import win32evtlogutil
import win32con
import sys

# Configuration - Change BASE_URL to the ATDH Server IP in an organization
BASE_URL = "http://localhost:8000" 
POLL_INTERVAL = 10 

class ATDHAgent:
    def __init__(self):
        self.hostname = socket.gethostname()
        self.server = 'localhost'
        self.last_security_index = self.get_last_event_index('Security')
        self.last_system_index = self.get_last_event_index('System')

    def get_last_event_index(self, log_type):
        try:
            hand = win32evtlog.OpenEventLog(self.server, log_type)
            oldest = win32evtlog.GetOldestEventLogRecord(hand)
            count = win32evtlog.GetNumberOfEventLogRecords(hand)
            return oldest + count - 1
        except Exception:
            return 0

    def poll_logs(self, log_type, last_index):
        try:
            hand = win32evtlog.OpenEventLog(self.server, log_type)
            flags = win32con.EVENTLOG_FORWARDS_READ | win32con.EVENTLOG_SEEK_READ
            events = win32evtlog.ReadEventLog(hand, flags, last_index)
            
            new_last_index = last_index
            for event in events:
                if event.RecordNumber > new_last_index:
                    new_last_index = event.RecordNumber
                
                msg = win32evtlogutil.SafeFormatMessage(event, log_type)
                timestamp = event.TimeGenerated.Format()
                raw_log = f"Time: {timestamp} | Source: {event.SourceName} | ID: {event.EventID & 0xFFFF} | Message: {msg}"
                self.send_to_server(raw_log, "windows")
                
            return new_last_index
        except Exception:
            return last_index

    def send_to_server(self, raw_log, log_type):
        try:
            requests.post(
                f"{BASE_URL}/ingest/raw", 
                params={"raw_log": raw_log, "log_type": log_type, "hostname": self.hostname},
                timeout=5
            )
        except Exception as e:
            print(f"Server unreachable: {e}")

    def run(self):
        print(f"ATDH Agent running on {self.hostname}...")
        while True:
            self.last_security_index = self.poll_logs('Security', self.last_security_index)
            self.last_system_index = self.poll_logs('System', self.last_system_index)
            time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    agent = ATDHAgent()
    agent.run()
