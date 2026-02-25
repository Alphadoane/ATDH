import re
from datetime import datetime
from typing import Optional, Dict
from ..models import NormalizedLog

class Normalizer:
    def parse_windows_sysmon(self, raw: str) -> Optional[NormalizedLog]:
        """
        Parses Windows Event and Sysmon logs using structured regex patterns.
        """
        try:
            timestamp_match = re.search(r'Time: ([\d\-: ]+)', raw)
            user_match = re.search(r'User: ([\w\\]+)', raw)
            ip_match = re.search(r'Source: ([\d\.]+)', raw)
            proc_match = re.search(r'Process: ([\w\.]+)', raw)
            
            return NormalizedLog(
                timestamp=datetime.strptime(timestamp_match.group(1), "%Y-%m-%d %H:%M:%S") if timestamp_match else datetime.utcnow(),
                source_ip=ip_match.group(1) if ip_match else None,
                event_type="Process Creation" if "creation" in raw.lower() else "General",
                username=user_match.group(1) if user_match else None,
                process_name=proc_match.group(1) if proc_match else None,
                raw_log=raw
            )
        except Exception:
            return None

    def parse_auth_log(self, raw: str) -> Optional[NormalizedLog]:
        # Example: Feb 26 01:10:01 server sshd[123]: Failed password for invalid user admin from 192.168.1.50 port 54321 ssh2
        try:
            ip_match = re.search(r'from ([\d\.]+)', raw)
            user_match = re.search(r'for (?:invalid user )?(\w+)', raw)
            event_type = "Failed Login" if "failed password" in raw.lower() else "Auth Event"
            
            return NormalizedLog(
                event_type=event_type,
                source_ip=ip_match.group(1) if ip_match else None,
                username=user_match.group(1) if user_match else None,
                raw_log=raw
            )
        except Exception:
            return None

    def normalize(self, raw: str, log_type: str = "auto") -> Optional[NormalizedLog]:
        if log_type == "windows" or "sysmon" in raw.lower():
            return self.parse_windows_sysmon(raw)
        elif log_type == "linux" or "sshd" in raw.lower():
            return self.parse_auth_log(raw)
        
        # Default behavior
        return NormalizedLog(event_type="Unknown", raw_log=raw)
