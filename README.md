# Network Intrusion Detection System (Suricata)

CodeAlpha Cyber Security Internship, Task 4.

A network IDS built on Suricata with custom detection rules and an automated
response script that blocks attackers using nftables.

## How it works
Network traffic -> Suricata (custom rules) -> eve.json alerts -> responder.py -> nftables blocklist

## Detection rules (rules/local.rules)
| SID | Detects |
|---|---|
| 1000001 | ICMP ping |
| 1000002 | TCP SYN port scan (20 SYNs in 10 s) |
| 1000003 | SSH brute-force pattern (5 SYNs in 60 s) |
| 1000004 | SQL injection (UNION SELECT) |
| 1000005 | Cross-site scripting (script tag) |
| 1000006 | Directory traversal (matched on the raw URI) |

## Automatic response (responder/responder.py)
Reads Suricata alerts, and blocks any source IP that triggers 3 alerts within 60 s,
using an nftables set with a timeout. A whitelist protects trusted hosts.

## Setup
    sudo apt install suricata
    sudo cp rules/local.rules /var/lib/suricata/rules/local.rules
    # set HOME_NET and the interface in /etc/suricata/suricata.yaml, add local.rules to rule-files
    sudo suricata -c /etc/suricata/suricata.yaml -i wlan0
    sudo python3 responder/responder.py

## Testing
Attacks were generated with curl and nmap against a local web server, and from a second
device (a phone). See the screenshots/ folder.

## Lessons learned
- Suricata normalises URI paths, so traversal detection uses http.uri.raw.
- Running several Suricata instances on one interface splits traffic between them.
- Whitelists must not contain the attacker; blocking by IP is risky behind NAT.

Only test against systems you own.
