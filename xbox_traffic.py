import subprocess
from time import sleep
from collections import defaultdict
from prometheus_client import start_http_server, Gauge
from datetime import datetime

INTERFACE = "enp2s0"
IPS = ["10.0.0.39", "10.0.0.170"]
DURATION = 30
SLEEP_BETWEEN_ROUNDS = 270
DEBUG = True

network_bytes = Gauge("bytes_last_minute", "Network usage over last minute", ["ip"])

def capture_traffic():
    capture_filter = " or ".join(f"host {ip}" for ip in IPS)
    cmd = [
        "tshark",
        "-i", INTERFACE,
        "-f", capture_filter,
        "-a", f"duration:{DURATION}",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "frame.len",
        "-E", "separator=\\t",
        "-l",  # line buffered stdout
        "-n",  # no name resolution
    ]

    if DEBUG:
        print(f"[{datetime.now().isoformat()}] Command: {' '.join(cmd)}", flush=True)

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        print("tshark not found: install Wireshark/tshark or adjust PATH.", flush=True)
        return defaultdict(int)

    totals = defaultdict(int)

    total_lines = 0
    parsed_lines = 0
    skipped_lines = 0
    invalid_flen = 0

    for line in proc.stdout:
        total_lines += 1
        parts = line.strip().split("\t")

        if len(parts) < 3:
            skipped_lines += 1
            if DEBUG and total_lines <= 5:
                # show the first few skipped lines to help debugging
                print(f"[{datetime.now().isoformat()}] Skipped line (too few fields): '{line.strip()}'", flush=True)
            continue
        src, dst, flen = parts[0], parts[1], parts[2]

        if not flen.isdigit():
            invalid_flen += 1
            if DEBUG and invalid_flen <= 5:
                print(f"[{datetime.now().isoformat()}] Invalid frame.len: '{flen}' from line: '{line.strip()}'", flush=True)
            continue
        length = int(flen)
        parsed_lines += 1

        if src in IPS:
            totals[src] += length

        if dst in IPS:
            totals[dst] += length

    proc.wait()
    stderr = proc.stderr.read()
    if proc.returncode != 0:
        print(f"tshark exited with code {proc.returncode}; stderr:\n{stderr}", flush=True)

    # summary logs
    if DEBUG:
        print(f"[{datetime.now().isoformat()}] Capture summary: total_lines={total_lines}, parsed_lines={parsed_lines}, skipped_lines={skipped_lines}, invalid_flen={invalid_flen}", flush=True)
        for ip in IPS:
            print(f"[{datetime.now().isoformat()}] Total bytes for {ip}: {totals.get(ip, 0)}", flush=True)

    return totals

if __name__ == "__main__":
    print("Starting Prometheus exporter on port 9108…", flush=True)
    start_http_server(9108)

    while True:
        totals = capture_traffic()
        for ip in IPS:
            network_bytes.labels(ip=ip).set(totals.get(ip, 0))
            print(f"{ip}: {totals.get(ip, 0)} bytes", flush=True)
        sleep(SLEEP_BETWEEN_ROUNDS)