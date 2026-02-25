import requests
import time
import random

BASE_URL = "http://localhost:8000"

def ingest(log, log_type="auto"):
    try:
        requests.post(f"{BASE_URL}/ingest/raw", params={"raw_log": log, "log_type": log_type})
    except:
        print("Backend not reachable. Start the backend first!")

def simulate_brute_force(ip="192.168.1.50", user="admin"):
    print(f"Simulating Brute Force from {ip}...")
    for _ in range(6):
        log = f"Feb 26 01:20:01 server sshd[123]: Failed password for {user} from {ip} port {random.randint(1024, 65535)} ssh2"
        ingest(log, "linux")
        time.sleep(0.5)

def simulate_port_scan(ip="10.0.0.99"):
    print(f"Simulating Port Scan from {ip}...")
    for i in range(12):
        log = f"Firewall: Blocked inbound connection from {ip} to port {i*100}"
        ingest(log)
        time.sleep(0.2)

def simulate_suspicious_proc(user="maldev"):
    print("Simulating Suspicious Process...")
    log = f"Time: 2026-02-26 01:25:30 User: {user} Process: powershell.exe Command: powershell -enc ZWNobyAiSGVsbG8gV29ybGQi"
    ingest(log, "windows")

if __name__ == "__main__":
    print("Starting simulation...")
    simulate_brute_force()
    simulate_port_scan()
    simulate_suspicious_proc()
    print("Simulation complete.")
