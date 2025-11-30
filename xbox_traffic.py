import subprocess
from time import sleep
from collections import defaultdict
from prometheus_client import start_http_server, Gauge
from datetime import datetime
import re
import tempfile
import os

INTERFACE = "enp2s0"
IPS = ["10.0.0.39", "10.0.0.170"]
DURATION = 30
SLEEP_BETWEEN_ROUNDS = 270
DEBUG = True

network_bytes = Gauge("bytes_last_minute", "Network usage over last minute", ["ip"])

IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


def _parse_tshark_fields_output(output):
    totals = defaultdict(int)
    parsed = 0
    for i, line in enumerate(output.splitlines(), start=1):
        parts = line.strip().split("\t")
        if len(parts) < 3:
            if DEBUG and i <= 5:
                print(f"[{datetime.now().isoformat()}] fallback: skipped malformed line: '{line}'", flush=True)
            continue
        src, dst, flen = parts[0], parts[1], parts[2]
        if not flen.isdigit():
            m = re.search(r"(\d+)", flen)
            if m:
                flen = m.group(1)
        if not flen.isdigit():
            continue
        length = int(flen)
        parsed += 1
        if src in IPS:
            totals[src] += length
        if dst in IPS:
            totals[dst] += length
    return totals, parsed


def _pcap_fallback(capture_filter):
    # write to temp pcap using tshark -w, then read back with tshark -r to get consistent field output
    fd, pcap_path = tempfile.mkstemp(prefix="na_capture_", suffix=".pcap")
    os.close(fd)
    cmd_write = [
        "tshark",
        "-i", INTERFACE,
        "-f", capture_filter,
        "-a", f"duration:{DURATION}",
        "-w", pcap_path,
        "-n",
    ]
    if DEBUG:
        print(f"[{datetime.now().isoformat()}] Fallback: writing pcap to {pcap_path} using: {' '.join(cmd_write)}", flush=True)
    try:
        r = subprocess.run(cmd_write, capture_output=True, text=True)
    except FileNotFoundError:
        print("tshark not found for fallback: install tshark.", flush=True)
        return defaultdict(int), 0
    if r.returncode != 0:
        print(f"Fallback capture failed (code {r.returncode}): {r.stderr}", flush=True)
        try:
            os.remove(pcap_path)
        except Exception:
            pass
        return defaultdict(int), 0

    # now read pcap and parse fields
    cmd_read = [
        "tshark",
        "-r", pcap_path,
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "frame.len",
        "-E", "separator=\t",
        "-n",
    ]
    if DEBUG:
        print(f"[{datetime.now().isoformat()}] Fallback: reading pcap with: {' '.join(cmd_read)}", flush=True)
    try:
        r2 = subprocess.run(cmd_read, capture_output=True, text=True)
    except FileNotFoundError:
        print("tshark not found for fallback read: install tshark.", flush=True)
        try:
            os.remove(pcap_path)
        except Exception:
            pass
        return defaultdict(int), 0

    if r2.returncode != 0:
        print(f"Fallback read failed (code {r2.returncode}): {r2.stderr}", flush=True)
        try:
            os.remove(pcap_path)
        except Exception:
            pass
        return defaultdict(int), 0

    totals, parsed = _parse_tshark_fields_output(r2.stdout)
    try:
        os.remove(pcap_path)
    except Exception:
        pass
    return totals, parsed


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
    raw_preview = []

    try:
        for line in proc.stdout:
            total_lines += 1
            raw = line.rstrip('\n')
            if len(raw_preview) < 10:
                raw_preview.append(raw)

            # Split on backslash, tab or other whitespace (robust to weird separators)
            parts = [p for p in re.split(r"[\\\t\s]+", raw) if p]
            if DEBUG and total_lines <= 20:
                print(f"[{datetime.now().isoformat()}] Raw line {total_lines}: '{raw}' -> parts={parts}", flush=True)

            heuristic_used = False
            # If we don't have three fields, try a few heuristics to recover
            if len(parts) < 3:
                # Case: second part could be "<ip><digits>" like '10.0.0.200102'
                if len(parts) == 2:
                    m = re.match(r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?P<flen>\d+)$", parts[1])
                    if m:
                        parts = [parts[0], m.group('ip'), m.group('flen')]
                        heuristic_used = True

                # More general fallback: extract IPs and final integer from the raw line
                if not heuristic_used:
                    ips = IP_RE.findall(raw)
                    nums = re.findall(r"(\d+)", raw)
                    if len(ips) >= 2 and len(nums) >= 1:
                        # take first two IPs and the last number as frame length
                        parts = [ips[0], ips[1], nums[-1]]
                        heuristic_used = True

                if heuristic_used and DEBUG and total_lines <= 20:
                    print(f"[{datetime.now().isoformat()}] Heuristic applied to line {total_lines}: parts={parts}", flush=True)

            if len(parts) < 3:
                skipped_lines += 1
                if DEBUG and total_lines <= 20:
                    print(f"[{datetime.now().isoformat()}] Skipped line (too few fields): '{raw}'", flush=True)
                continue

            src, dst, flen = parts[0], parts[1], parts[2]

            # frame.len may include non-digit chars; extract the first integer-looking token
            if not flen.isdigit():
                m = re.search(r"(\d+)", flen)
                if m:
                    flen = m.group(1)

            if not flen.isdigit():
                invalid_flen += 1
                if DEBUG and invalid_flen <= 10:
                    print(f"[{datetime.now().isoformat()}] Invalid frame.len: '{flen}' from line: '{raw}'", flush=True)
                continue

            length = int(flen)
            parsed_lines += 1

            if src in IPS:
                totals[src] += length

            if dst in IPS:
                totals[dst] += length

    except KeyboardInterrupt:
        # User interrupted; ensure tshark is terminated cleanly
        if DEBUG:
            print(f"[{datetime.now().isoformat()}] KeyboardInterrupt received, terminating tshark...", flush=True)
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            pass
        # propagate to allow program to exit
        raise

    proc.wait()
    stderr = proc.stderr.read()
    if proc.returncode != 0:
        print(f"tshark exited with code {proc.returncode}; stderr:\n{stderr}", flush=True)

    # if nothing parsed but we saw lines, try pcap fallback
    if parsed_lines == 0 and total_lines > 0:
        if DEBUG:
            print(f"[{datetime.now().isoformat()}] No lines parsed from live output (total_lines={total_lines}), trying pcap fallback...", flush=True)
        fb_totals, fb_parsed = _pcap_fallback(capture_filter)
        if fb_parsed > 0:
            if DEBUG:
                print(f"[{datetime.now().isoformat()}] Fallback parsed {fb_parsed} lines; using fallback totals.", flush=True)
            return fb_totals
        else:
            if DEBUG:
                print(f"[{datetime.now().isoformat()}] Fallback did not parse any lines.", flush=True)

    # summary logs
    if DEBUG:
        print(f"[{datetime.now().isoformat()}] Capture raw preview (first {len(raw_preview)} lines):", flush=True)
        for r in raw_preview:
            print(f"  {r}", flush=True)
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