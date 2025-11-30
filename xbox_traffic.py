#!/usr/bin/env python3
import subprocess
import time
import csv
from datetime import datetime

INTERFACE = "enp2s0"
XBOX_IP = "10.0.0.39"
DURATION = 60 # seconds

def capture_traffic():
    cmd = [
        "tshark",
        "-i", INTERFACE,
        "-f", f"host {XBOX_IP}",
        "-T", "fields",
        "-e", "frame.len"
    ]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    start = time.time()
    total_bytes = 0

    while time.time() - start < DURATION:
        line = proc.stdout.readline()
        if not line:
            continue
        try:
            total_bytes += int(line.strip())
        except ValueError:
            pass

    proc.terminate()
    return total_bytes

def save_to_csv(total_bytes):
    with open("xbox_traffic.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([datetime.now().isoformat(), total_bytes])

if __name__ == "__main__":
    bytes_1min = capture_traffic()
    save_to_csv(bytes_1min)
    print(f"{bytes_1min} bytes in last 1 minute")