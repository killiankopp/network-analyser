import subprocess

INTERFACE = "enp2s0"
XBOX_IP = "10.0.0.170"
DURATION = 10

def capture_traffic():
    cmd = [
        "tshark",
        "-i", INTERFACE,
        "-f", f"host {XBOX_IP}",
        "-a", f"duration:{DURATION}",
        "-T", "fields",
        "-e", "frame.len"
    ]

    print(f"Starting capture for {DURATION} seconds...")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    total_bytes = 0

    for line in proc.stdout:
        line = line.strip()
        if line.isdigit():
            total_bytes += int(line)

    proc.wait()
    return total_bytes

if __name__ == "__main__":
    bytes_period = capture_traffic()
    print(f"{bytes_period} bytes in last {DURATION} seconds for {XBOX_IP}")