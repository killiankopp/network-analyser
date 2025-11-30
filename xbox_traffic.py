import subprocess
from time import sleep
from collections import defaultdict
from prometheus_client import start_http_server, Gauge

INTERFACE = "enp2s0"
IPS = ["10.0.0.39", "10.0.0.170"]
DURATION = 30
SLEEP_BETWEEN_ROUNDS = 270

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

    print(f"Starting capture for {DURATION} seconds...")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    totals = defaultdict(int)

    for line in proc.stdout:
        parts = line.strip().split("\t")

        if len(parts) < 3:
            continue
        src, dst, flen = parts[0], parts[1], parts[2]

        if not flen.isdigit():
            continue
        length = int(flen)

        if src in IPS:
            totals[src] += length

        if dst in IPS:
            totals[dst] += length

    proc.wait()
    stderr = proc.stderr.read()
    if proc.returncode != 0:
        print(f"tshark exited with code {proc.returncode}; stderr:\n{stderr}")
    return totals

if __name__ == "__main__":
    print("Starting Prometheus exporter on port 9108…")
    start_http_server(9108)

    while True:
        totals = capture_traffic()
        for ip in IPS:
            network_bytes.labels(ip=ip).set(totals.get(ip, 0))
            print(f"{ip}: {totals.get(ip, 0)} bytes")
        sleep(SLEEP_BETWEEN_ROUNDS)