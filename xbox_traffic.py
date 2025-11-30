import subprocess

XBOX_IP = "10.0.0.39"
INTERFACE = "enp2s0"

def capture_traffic():
    cmd = [
        "tshark",
        "-i", INTERFACE,
        "-f", f"host {XBOX_IP}",
        "-a", "duration:60",
        "-T", "fields",
        "-e", "frame.len"
    ]

    print("Starting capture for 60 seconds...")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    total_bytes = 0

    for line in proc.stdout:
        line = line.strip()
        if line.isdigit():
            total_bytes += int(line)

    proc.wait()
    return total_bytes

if __name__ == "__main__":
    bytes_1min = capture_traffic()
    print(f"{bytes_1min} bytes in last 1 minute")