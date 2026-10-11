#!/usr/bin/env python3
"""Reads Suricata alerts and blocks repeat offenders with nftables."""
import ipaddress, json, subprocess, sys, time
from collections import defaultdict, deque

EVE = sys.argv[1] if len(sys.argv) > 1 else "/var/log/suricata/eve.json"
THRESHOLD = 3          # alerts from one IP...
WINDOW = 60            # ...within this many seconds triggers a block
BAN_SECONDS = 60      # how long the block lasts
WHITELIST = {"127.0.0.1", "10.124.190.222"}  # me and my gateway

hits = defaultdict(deque)   # ip -> timestamps of recent alerts

def nft(*args):
    subprocess.run(["nft", *args], check=False)

def setup_firewall():
    nft("add", "table", "inet", "nids")
    nft("add", "set", "inet", "nids", "blocklist", "{ type ipv4_addr; flags timeout; }")
    nft("add", "chain", "inet", "nids", "input",
        "{ type filter hook input priority -10; policy accept; }")
    nft("flush", "chain", "inet", "nids", "input")
    nft("add", "rule", "inet", "nids", "input", "ip", "saddr", "@blocklist", "drop")

def block(ip):
    nft("add", "element", "inet", "nids", "blocklist", f"{{ {ip} timeout {BAN_SECONDS}s }}")
    print(f"[BLOCKED] {ip} for {BAN_SECONDS}s", flush=True)

def follow(path):
    with open(path) as f:
        f.seek(0, 2)                      # start at the end: only new alerts
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(0.5)

def main():
    setup_firewall()
    print(f"watching {EVE}", flush=True)
    for line in follow(EVE):
        try:
            ev = json.loads(line)
            if ev.get("event_type") != "alert":
                continue
            ip = str(ipaddress.ip_address(ev["src_ip"]))   # rejects anything that isn't an IP
        except (ValueError, KeyError):
            continue
        if ip in WHITELIST:
            continue
        now = time.time()
        q = hits[ip]
        q.append(now)
        while q and q[0] < now - WINDOW:
            q.popleft()
        print(f"[alert] {ip}: {len(q)}/{THRESHOLD}", flush=True)
        if len(q) >= THRESHOLD:
            block(ip)
            q.clear()

if __name__ == "__main__":
    main()
