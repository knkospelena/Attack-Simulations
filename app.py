#!/usr/bin/env python3
"""
SOC Attack Simulation Tool - Backend
BN301 - Security Operations Center Project
Supports: nmap scanning + hydra brute force + custom attacks
"""

import nmap
import os
import re
import time
import threading
import subprocess
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────────────────────
# In-memory store
# ─────────────────────────────────────────────────────────────
scan_results  = {}
running_scans = {}

# ─────────────────────────────────────────────────────────────
# Attack Catalogue  (grouped by category)
# ─────────────────────────────────────────────────────────────
ATTACK_TYPES = {

    # ── RECONNAISSANCE ──────────────────────────────────────
    "port_scan_basic": {
        "name": "Basic Port Scan",
        "description": "Scans the most common 1000 TCP ports. Fast and lightweight.",
        "icon": "scan-search",
        "group": "Reconnaissance",
        "risk": "Low",
        "tool": "nmap",
        "nmap_args": "-T4 -F",
        "estimated_time": "10-30 seconds",
    },
    "port_scan_full": {
        "name": "Full TCP Port Scan",
        "description": "Scans all 65535 TCP ports. Comprehensive but slower.",
        "icon": "search-check",
        "group": "Reconnaissance",
        "risk": "Low",
        "tool": "nmap",
        "nmap_args": "-T4 -p-",
        "estimated_time": "2-10 minutes",
    },
    "service_version": {
        "name": "Service & Version Detection",
        "description": "Identifies services and software versions on open ports.",
        "icon": "wrench",
        "group": "Reconnaissance",
        "risk": "Medium",
        "tool": "nmap",
        "nmap_args": "-T4 -sV -F",
        "estimated_time": "30-60 seconds",
    },
    "os_detection": {
        "name": "OS Fingerprinting",
        "description": "Attempts to identify the target operating system via TCP/IP stack analysis.",
        "icon": "monitor",
        "group": "Reconnaissance",
        "risk": "Medium",
        "tool": "nmap",
        "nmap_args": "-T4 -O -F",
        "estimated_time": "30-60 seconds",
    },
    "aggressive_scan": {
        "name": "Aggressive Scan",
        "description": "OS detection + version + NSE scripts + traceroute combined.",
        "icon": "zap",
        "group": "Reconnaissance",
        "risk": "High",
        "tool": "nmap",
        "nmap_args": "-T4 -A -F",
        "estimated_time": "1-3 minutes",
    },
    "ping_sweep": {
        "name": "Ping Sweep (Host Discovery)",
        "description": "Discovers live hosts in a network range without port scanning.",
        "icon": "wifi",
        "group": "Reconnaissance",
        "risk": "Low",
        "tool": "nmap",
        "nmap_args": "-sn",
        "estimated_time": "5-20 seconds",
    },
    "udp_scan": {
        "name": "UDP Port Scan",
        "description": "Scans top 100 UDP ports. Useful for DNS/SNMP/TFTP discovery.",
        "icon": "radio",
        "group": "Reconnaissance",
        "risk": "Low",
        "tool": "nmap",
        "nmap_args": "-T4 -sU --top-ports 100",
        "estimated_time": "2-5 minutes",
    },
    "netbios_enum": {
        "name": "NetBIOS / SMB Enumeration",
        "description": "Enumerates NetBIOS names, shares, and SMB information.",
        "icon": "folder-open",
        "group": "Reconnaissance",
        "risk": "Medium",
        "tool": "nmap",
        "nmap_args": "-T4 --script smb-enum-shares,smb-enum-users,nbstat -p 137,139,445",
        "estimated_time": "30-90 seconds",
    },
    "http_enum": {
        "name": "HTTP Service Enumeration",
        "description": "Enumerates web directories, headers, and server info via nmap HTTP scripts.",
        "icon": "globe",
        "group": "Reconnaissance",
        "risk": "Medium",
        "tool": "nmap",
        "nmap_args": "-T4 --script http-enum,http-headers,http-methods -p 80,443,8080,8443",
        "estimated_time": "30-60 seconds",
    },
    "dns_enum": {
        "name": "DNS Enumeration",
        "description": "Attempts DNS zone transfer and hostname brute-force via nmap scripts.",
        "icon": "network",
        "group": "Reconnaissance",
        "risk": "Low",
        "tool": "nmap",
        "nmap_args": "-T4 --script dns-brute,dns-zone-transfer -p 53",
        "estimated_time": "30-120 seconds",
    },

    # ── EVASION ──────────────────────────────────────────────
    "syn_stealth": {
        "name": "SYN Stealth Scan",
        "description": "Half-open TCP SYN scan. Does not complete handshake. Harder to detect.",
        "icon": "ghost",
        "group": "Evasion",
        "risk": "Medium",
        "tool": "nmap",
        "nmap_args": "-T4 -sS -F",
        "estimated_time": "15-45 seconds",
    },
    "firewall_evasion": {
        "name": "Firewall Evasion (Fragmented PKT)",
        "description": "Sends fragmented IP packets to bypass simple packet filters and firewalls.",
        "icon": "shield-off",
        "group": "Evasion",
        "risk": "High",
        "tool": "nmap",
        "nmap_args": "-T4 -f -F",
        "estimated_time": "20-60 seconds",
    },
    "decoy_scan": {
        "name": "Decoy Scan",
        "description": "Spoofs multiple decoy source IPs to confuse IDS/firewall attribution.",
        "icon": "eye-off",
        "group": "Evasion",
        "risk": "High",
        "tool": "nmap",
        "nmap_args": "-T4 -D RND:5 -F",
        "estimated_time": "20-60 seconds",
    },
    "idle_zombie": {
        "name": "Idle / Zombie Scan",
        "description": "Uses a zombie host to scan target — attacker IP never appears in logs.",
        "icon": "skull",
        "group": "Evasion",
        "risk": "High",
        "tool": "nmap",
        "nmap_args": "-T2 -sI localhost -F",
        "estimated_time": "1-3 minutes",
    },
    "slow_scan": {
        "name": "Slow Paranoid Scan",
        "description": "Extremely slow scan (timing T0/T1) designed to evade IDS rate limits.",
        "icon": "timer",
        "group": "Evasion",
        "risk": "Medium",
        "tool": "nmap",
        "nmap_args": "-T1 -F",
        "estimated_time": "5-20 minutes",
    },

    # ── VULNERABILITY ASSESSMENT ─────────────────────────────
    "vuln_scan": {
        "name": "NSE Vulnerability Scan",
        "description": "Runs nmap's built-in vuln scripts against open ports.",
        "icon": "crosshair",
        "group": "Vulnerability",
        "risk": "High",
        "tool": "nmap",
        "nmap_args": "-T4 --script vuln -F",
        "estimated_time": "2-5 minutes",
    },
    "ftp_anon": {
        "name": "FTP Anonymous Login Check",
        "description": "Tests whether FTP anonymous login is allowed on port 21.",
        "icon": "folder-lock",
        "group": "Vulnerability",
        "risk": "Medium",
        "tool": "nmap",
        "nmap_args": "-T4 --script ftp-anon -p 21",
        "estimated_time": "10-30 seconds",
    },
    "ssl_check": {
        "name": "SSL/TLS Vulnerability Scan",
        "description": "Checks for weak ciphers, POODLE, Heartbleed, expired certs on HTTPS.",
        "icon": "lock-keyhole",
        "group": "Vulnerability",
        "risk": "Medium",
        "tool": "nmap",
        "nmap_args": "-T4 --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-cert -p 443,8443",
        "estimated_time": "30-90 seconds",
    },
    "smb_vuln": {
        "name": "SMB Vulnerability Scan (EternalBlue)",
        "description": "Tests for MS17-010 (EternalBlue/WannaCry) and other SMB vulnerabilities.",
        "icon": "biohazard",
        "group": "Vulnerability",
        "risk": "Critical",
        "tool": "nmap",
        "nmap_args": "-T4 --script smb-vuln-ms17-010,smb-vuln-ms08-067,smb-security-mode -p 445",
        "estimated_time": "30-60 seconds",
    },
    "default_creds_nmap": {
        "name": "Default Credential Check (NSE)",
        "description": "Uses nmap scripts to test default/common credentials on common services.",
        "icon": "key-round",
        "group": "Vulnerability",
        "risk": "High",
        "tool": "nmap",
        "nmap_args": "-T4 --script http-default-accounts,ssh-auth-methods -F",
        "estimated_time": "1-3 minutes",
    },

    # ── BRUTE FORCE ──────────────────────────────────────────
    "brute_ssh": {
        "name": "SSH Brute Force",
        "description": "Dictionary attack against SSH (port 22) using hydra with common credentials.",
        "icon": "hammer",
        "group": "Brute Force",
        "risk": "Critical",
        "tool": "hydra",
        "hydra_service": "ssh",
        "hydra_port": 22,
        "estimated_time": "1-5 minutes",
        "requires_creds": True,
    },
    "brute_ftp": {
        "name": "FTP Brute Force",
        "description": "Dictionary attack against FTP (port 21) using hydra.",
        "icon": "folder",
        "group": "Brute Force",
        "risk": "Critical",
        "tool": "hydra",
        "hydra_service": "ftp",
        "hydra_port": 21,
        "estimated_time": "1-5 minutes",
        "requires_creds": True,
    },
    "brute_telnet": {
        "name": "Telnet Brute Force",
        "description": "Dictionary attack against Telnet (port 23) using hydra.",
        "icon": "terminal",
        "group": "Brute Force",
        "risk": "Critical",
        "tool": "hydra",
        "hydra_service": "telnet",
        "hydra_port": 23,
        "estimated_time": "2-5 minutes",
        "requires_creds": True,
    },
    "brute_http_basic": {
        "name": "HTTP Basic Auth Brute Force",
        "description": "Dictionary attack against HTTP Basic Authentication using hydra.",
        "icon": "globe-2",
        "group": "Brute Force",
        "risk": "High",
        "tool": "hydra",
        "hydra_service": "http-get",
        "hydra_port": 80,
        "estimated_time": "1-3 minutes",
        "requires_creds": True,
        "requires_path": True,
    },
    "brute_smb": {
        "name": "SMB / Windows Brute Force",
        "description": "Dictionary attack against SMB (port 445) — Windows file sharing.",
        "icon": "server",
        "group": "Brute Force",
        "risk": "Critical",
        "tool": "hydra",
        "hydra_service": "smb",
        "hydra_port": 445,
        "estimated_time": "1-5 minutes",
        "requires_creds": True,
    },
    "brute_rdp": {
        "name": "RDP Brute Force",
        "description": "Dictionary attack against Remote Desktop Protocol (port 3389) using hydra.",
        "icon": "monitor-cog",
        "group": "Brute Force",
        "risk": "Critical",
        "tool": "hydra",
        "hydra_service": "rdp",
        "hydra_port": 3389,
        "estimated_time": "2-5 minutes",
        "requires_creds": True,
    },
    "brute_mysql": {
        "name": "MySQL Brute Force",
        "description": "Dictionary attack against MySQL database (port 3306) using hydra.",
        "icon": "database",
        "group": "Brute Force",
        "risk": "Critical",
        "tool": "hydra",
        "hydra_service": "mysql",
        "hydra_port": 3306,
        "estimated_time": "1-3 minutes",
        "requires_creds": True,
    },
    "brute_postgres": {
        "name": "PostgreSQL Brute Force",
        "description": "Dictionary attack against PostgreSQL (port 5432) using hydra.",
        "icon": "database-zap",
        "group": "Brute Force",
        "risk": "Critical",
        "tool": "hydra",
        "hydra_service": "postgres",
        "hydra_port": 5432,
        "estimated_time": "1-3 minutes",
        "requires_creds": True,
    },
    "brute_ssh_nmap": {
        "name": "SSH Brute Force (nmap NSE)",
        "description": "Uses nmap ssh-brute script to brute-force SSH with a small built-in wordlist.",
        "icon": "lock-open",
        "group": "Brute Force",
        "risk": "High",
        "tool": "nmap",
        "nmap_args": "-T4 --script ssh-brute -p 22",
        "estimated_time": "1-3 minutes",
        "requires_creds": False,
    },
    "brute_ftp_nmap": {
        "name": "FTP Brute Force (nmap NSE)",
        "description": "Uses nmap ftp-brute script to brute-force FTP with built-in wordlists.",
        "icon": "package-open",
        "group": "Brute Force",
        "risk": "High",
        "tool": "nmap",
        "nmap_args": "-T4 --script ftp-brute -p 21",
        "estimated_time": "1-3 minutes",
        "requires_creds": False,
    },
}

# ─────────────────────────────────────────────────────────────
# Built-in wordlists (for when no custom list is provided)
# ─────────────────────────────────────────────────────────────
DEFAULT_USERNAMES = ["admin", "root", "user", "administrator", "test", "guest",
                     "kali", "pi", "oracle", "postgres", "mysql", "ftp", "www"]
DEFAULT_PASSWORDS = ["password", "123456", "admin", "root", "toor", "pass",
                     "1234", "test", "guest", "raspberry", "changeme",
                     "password123", "letmein", "qwerty", "12345678", "abc123"]


def _write_wordlist(items, prefix):
    """Write a list to a temp file and return its path."""
    path = f"/tmp/soc_wl_{prefix}_{int(time.time())}.txt"
    with open(path, "w") as f:
        f.write("\n".join(items))
    return path


# ─────────────────────────────────────────────────────────────
# nmap scan runner
# ─────────────────────────────────────────────────────────────
def run_nmap_scan(scan_id, target_ip, attack_type):
    try:
        atk = ATTACK_TYPES[attack_type]
        _log(scan_id, f"Initializing {atk['name']}...")
        _log(scan_id, f"Target: {target_ip}")
        _log(scan_id, f"Command: nmap {atk['nmap_args']} {target_ip}")
        _progress(scan_id, 15)

        nm = nmap.PortScanner()
        _progress(scan_id, 20)
        _log(scan_id, "Running scan... (this may take a while)")

        nm.scan(hosts=target_ip, arguments=atk["nmap_args"])

        _progress(scan_id, 80)
        _log(scan_id, "Parsing results...")

        parsed_hosts = _parse_nmap(nm)

        open_count = sum(
            1 for h in parsed_hosts
            for p in h["protocols"]
            for port in p["ports"]
            if port["state"] == "open"
        )

        scan_results[scan_id] = {
            "scan_id": scan_id,
            "target": target_ip,
            "attack_type": attack_type,
            "attack_name": atk["name"],
            "group": atk["group"],
            "timestamp": datetime.now().isoformat(),
            "hosts": parsed_hosts,
            "total_hosts": len(parsed_hosts),
            "open_ports": open_count,
            "scan_info": nm.scaninfo(),
            "command": nm.command_line(),
            "type": "nmap",
        }

        _progress(scan_id, 100, "completed")
        _log(scan_id, f"✅ Done! Hosts: {len(parsed_hosts)}, Open ports: {open_count}", "success")

    except Exception as e:
        _progress(scan_id, 0, "error")
        running_scans[scan_id]["error"] = str(e)
        _log(scan_id, f"❌ Error: {e}", "error")


def _parse_nmap(nm):
    parsed = []
    for host in nm.all_hosts():
        h = {
            "ip": host,
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "protocols": [],
        }
        for proto in nm[host].all_protocols():
            pd = {"protocol": proto, "ports": []}
            for port in sorted(nm[host][proto].keys()):
                pi = nm[host][proto][port]
                pd["ports"].append({
                    "port": port,
                    "state": pi.get("state", "?"),
                    "name": pi.get("name", "?"),
                    "product": pi.get("product", ""),
                    "version": pi.get("version", ""),
                    "extrainfo": pi.get("extrainfo", ""),
                    "cpe": pi.get("cpe", ""),
                    "script": pi.get("script", {}),
                })
            h["protocols"].append(pd)
        if "osmatch" in nm[host]:
            h["os_matches"] = [
                {"name": o["name"], "accuracy": o["accuracy"]}
                for o in nm[host]["osmatch"][:3]
            ]
        if hasattr(nm[host], "get"):
            h["hostscript"] = nm[host].get("hostscript", [])
        parsed.append(h)
    return parsed


# ─────────────────────────────────────────────────────────────
# hydra brute force runner
# ─────────────────────────────────────────────────────────────
def run_hydra_attack(scan_id, target_ip, attack_type, username, password,
                     userlist, passlist, port_override, http_path):
    try:
        atk = ATTACK_TYPES[attack_type]
        service = atk["hydra_service"]
        port    = port_override or atk.get("hydra_port", "")

        _log(scan_id, f"Initializing {atk['name']}...")
        _log(scan_id, f"Target: {target_ip}:{port}  Service: {service}")
        _progress(scan_id, 10)

        # Check hydra is available
        if subprocess.run(["which", "hydra"], capture_output=True).returncode != 0:
            raise RuntimeError("hydra is not installed. On Kali: sudo apt install hydra")

        # Build wordlist files
        if userlist:
            ufile = userlist
        elif username:
            ufile = _write_wordlist([username], "u")
        else:
            ufile = _write_wordlist(DEFAULT_USERNAMES, "u")

        if passlist:
            pfile = passlist
        elif password:
            pfile = _write_wordlist([password], "p")
        else:
            pfile = _write_wordlist(DEFAULT_PASSWORDS, "p")

        # Build hydra command
        cmd = ["hydra", "-L", ufile, "-P", pfile, "-t", "4",
               "-f", "-V", target_ip]

        if port:
            cmd += ["-s", str(port)]

        if service == "http-get" and http_path:
            cmd += ["http-get", http_path]
        else:
            cmd.append(service)

        _log(scan_id, f"Command: {' '.join(cmd)}")
        _progress(scan_id, 20)
        _log(scan_id, "Brute force started. Watch live output below...")

        found_credentials = []
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )

        progress = 20
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            _log(scan_id, line)

            # Detect success lines
            if "[" in line and "] login:" in line.lower():
                found_credentials.append(line)
                _log(scan_id, f"🎯 CREDENTIAL FOUND: {line}", "success")

            # Increment progress slowly
            if progress < 90:
                progress += 1
                _progress(scan_id, progress)

        proc.wait()
        _progress(scan_id, 100, "completed")

        scan_results[scan_id] = {
            "scan_id": scan_id,
            "target": target_ip,
            "attack_type": attack_type,
            "attack_name": atk["name"],
            "group": atk["group"],
            "timestamp": datetime.now().isoformat(),
            "service": service,
            "port": port,
            "found_credentials": found_credentials,
            "total_found": len(found_credentials),
            "command": " ".join(cmd),
            "type": "hydra",
        }

        if found_credentials:
            _log(scan_id, f"✅ Attack complete! Found {len(found_credentials)} credential(s).", "success")
        else:
            _log(scan_id, "✅ Attack complete. No valid credentials found.", "info")

    except Exception as e:
        _progress(scan_id, 0, "error")
        running_scans[scan_id]["error"] = str(e)
        _log(scan_id, f"❌ Error: {e}", "error")


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────
def _log(scan_id, msg, kind=""):
    ts = datetime.now().strftime("%H:%M:%S")
    running_scans[scan_id].setdefault("log", []).append({
        "time": ts, "msg": msg, "kind": kind
    })


def _progress(scan_id, pct, status=None):
    running_scans[scan_id]["progress"] = pct
    if status:
        running_scans[scan_id]["status"] = status


def _init_scan(scan_id, target_ip, attack_type):
    running_scans[scan_id] = {
        "scan_id": scan_id,
        "target": target_ip,
        "attack_type": attack_type,
        "status": "running",
        "progress": 0,
        "log": [],
        "started_at": datetime.now().isoformat(),
    }


# ─────────────────────────────────────────────────────────────
# Flask Routes
# ─────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/attack-types")
def get_attack_types():
    return jsonify(ATTACK_TYPES)


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data        = request.get_json()
    target_ip   = data.get("target_ip", "").strip()
    attack_type = data.get("attack_type", "")

    # Brute force extras
    username      = data.get("username", "").strip()
    password      = data.get("password", "").strip()
    userlist      = data.get("userlist", "").strip()   # file path on server
    passlist      = data.get("passlist", "").strip()
    port_override = data.get("port", "")
    http_path     = data.get("http_path", "/").strip()

    if not target_ip:
        return jsonify({"error": "Target IP is required"}), 400
    if not attack_type or attack_type not in ATTACK_TYPES:
        return jsonify({"error": "Invalid attack type"}), 400

    scan_id = f"scan_{int(time.time() * 1000)}"
    _init_scan(scan_id, target_ip, attack_type)

    atk = ATTACK_TYPES[attack_type]

    if atk["tool"] == "hydra":
        t = threading.Thread(
            target=run_hydra_attack,
            args=(scan_id, target_ip, attack_type, username, password,
                  userlist or None, passlist or None, port_override or None, http_path),
            daemon=True,
        )
    else:
        t = threading.Thread(
            target=run_nmap_scan,
            args=(scan_id, target_ip, attack_type),
            daemon=True,
        )

    t.start()
    return jsonify({"scan_id": scan_id, "message": "Simulation started"}), 202


@app.route("/api/scan/<scan_id>/status")
def get_scan_status(scan_id):
    if scan_id not in running_scans:
        return jsonify({"error": "Not found"}), 404
    return jsonify(running_scans[scan_id])


@app.route("/api/scan/<scan_id>/results")
def get_scan_results(scan_id):
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id])
    if scan_id in running_scans:
        return jsonify({"error": "Still running", "status": running_scans[scan_id]["status"]}), 202
    return jsonify({"error": "Not found"}), 404


@app.route("/api/scans/history")
def get_history():
    history = []
    for sid, r in scan_results.items():
        history.append({
            "scan_id": sid,
            "target": r["target"],
            "attack_name": r["attack_name"],
            "group": r.get("group", ""),
            "timestamp": r["timestamp"],
            "total_hosts": r.get("total_hosts", 0),
            "total_found": r.get("total_found", 0),
            "type": r.get("type", "nmap"),
        })
    return jsonify(sorted(history, key=lambda x: x["timestamp"], reverse=True))


@app.route("/api/scans/clear", methods=["DELETE"])
def clear_history():
    scan_results.clear()
    running_scans.clear()
    return jsonify({"message": "Cleared"})


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  SOC Attack Simulation Tool — BN301")
    print("  http://localhost:5050")
    print("=" * 60 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5050)
