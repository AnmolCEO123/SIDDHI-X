import re
import os
import socket
import requests
import ipaddress
import webbrowser
from urllib.parse import urlparse
from threading import Timer
from collections import defaultdict
from flask import Flask, render_template, jsonify, request, redirect, url_for

app = Flask(__name__)

API_KEY = (
    "55f735f237b3efa59aae54dfa5c0468c0fd4261eeb448f4aa7fe203830fcf45b433df719bb64e365"
)
LOG_FILE = "server.log"


class ThreatIntelEngine:
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, key):
        self.key = key
        self.headers = {"Accept": "application/json", "Key": self.key}
        self.cache = {}

    def get_reputation(self, ip):
        if ip in self.cache:
            return self.cache[ip]

        try:
            if ipaddress.ip_address(ip).is_private:
                data = {"score": 0, "country": "LAN", "verdict": "BENIGN"}
                self.cache[ip] = data
                return data
        except ValueError:
            return {"score": 0, "country": "UNKNOWN", "verdict": "UNKNOWN"}

        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        try:
            res = requests.get(
                self.BASE_URL, headers=self.headers, params=params, timeout=4
            )
            if res.status_code == 200:
                body = res.json().get("data", {})
                score = body.get("abuseConfidenceScore", 0)
                verdict = (
                    "MALICIOUS"
                    if score >= 50
                    else ("SUSPICIOUS" if score > 15 else "CLEAN")
                )
                result = {
                    "score": score,
                    "country": body.get("countryCode", "N/A"),
                    "verdict": verdict,
                }
                self.cache[ip] = result
                return result
        except Exception:
            pass

        return {"score": 0, "country": "N/A", "verdict": "UNVERIFIED"}


intel_engine = ThreatIntelEngine(API_KEY)


def analyze_target(raw_input):
    target_ip = None
    domain = None
    server_tech = "Masked / Cloudflare"
    powered_by = "Hidden"
    open_ports = []
    passed_headers = []
    missing_headers = []

    cleaned = (
        raw_input
        if raw_input.startswith(("http://", "https://"))
        else f"http://{raw_input}"
    )
    parsed = urlparse(cleaned)
    domain_candidate = (
        parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
    )

    try:
        target_ip = socket.gethostbyname(domain_candidate)
        domain = domain_candidate
    except Exception:
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_input)
        target_ip = ip_match.group(0) if ip_match else "Unknown Target"

    if domain:
        for port in [80, 443]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((target_ip, port)) == 0:
                open_ports.append(f"Port {port}")
            s.close()

        try:
            target_url = f"https://{domain}"
            resp = requests.get(
                target_url,
                timeout=3,
                allow_redirects=True,
                headers={"User-Agent": "SIDDHI-X/2.4"},
            )
            headers = resp.headers
            server_tech = headers.get("Server", "Masked / CDN")
            powered_by = headers.get("X-Powered-By", "None Disclosed")

            if "Strict-Transport-Security" in headers:
                passed_headers.append("HSTS")
            else:
                missing_headers.append("HSTS")

            if "Content-Security-Policy" in headers:
                passed_headers.append("CSP")
            else:
                missing_headers.append("CSP")

            if "X-Frame-Options" in headers:
                passed_headers.append("X-Frame-Options")
            else:
                missing_headers.append("X-Frame-Options")

            if "X-Content-Type-Options" in headers:
                passed_headers.append("X-Content-Type-Options")
            else:
                missing_headers.append("X-Content-Type-Options")
        except Exception:
            server_tech = "Port 443 Filtered"

    intel = {"score": 0, "country": "N/A", "verdict": "CLEAN"}
    if target_ip and "Unknown" not in target_ip:
        intel = intel_engine.get_reputation(target_ip)

    detected_attack = "Passive Recon & Audit"
    severity = "LOW"
    payload_lower = raw_input.lower()

    if any(
        sig in payload_lower
        for sig in ["' or '1'='1", "union select", "admin' --", "sleep("]
    ):
        detected_attack = "SQL Injection Payload"
        severity = "CRITICAL"
    elif any(sig in payload_lower for sig in ["/etc/passwd", "/.env", "../"]):
        detected_attack = "Path Traversal / LFI"
        severity = "HIGH"
    elif len(missing_headers) >= 3:
        detected_attack = "Weak Defensive Posture"
        severity = "MEDIUM"

    return {
        "raw_input": raw_input,
        "domain": domain,
        "target_ip": target_ip,
        "server_tech": server_tech,
        "powered_by": powered_by,
        "open_ports": open_ports,
        "intel": intel,
        "attack_type": detected_attack,
        "severity": severity,
        "security_headers": {"passed": passed_headers, "missing": missing_headers},
    }


def parse_server_logs():
    failed_logins = defaultdict(int)
    incidents = []
    total_logs = 0

    if not os.path.exists(LOG_FILE):
        return incidents, 0

    pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+).*?"(?:GET|POST) (.*?) HTTP.*?" (\d+)')

    with open(LOG_FILE, "r") as f:
        for line in f:
            total_logs += 1
            match = pattern.search(line)
            if not match:
                continue

            ip, endpoint, status = match.groups()

            if status == "401":
                failed_logins[ip] += 1
                if failed_logins[ip] >= 3:
                    intel = intel_engine.get_reputation(ip)
                    incidents.append(
                        {
                            "ip": ip,
                            "attack_type": "Brute-Force Authentication",
                            "endpoint": endpoint,
                            "score": intel["score"],
                            "country": intel["country"],
                            "verdict": intel["verdict"],
                            "severity": "High" if intel["score"] >= 50 else "Medium",
                        }
                    )

            sqli_signatures = ["' OR '1'='1", "UNION SELECT", "/etc/passwd"]
            if any(sig in endpoint for sig in sqli_signatures):
                intel = intel_engine.get_reputation(ip)
                incidents.append(
                    {
                        "ip": ip,
                        "attack_type": "Web Exploitation (SQLi / Traversal)",
                        "endpoint": endpoint,
                        "score": intel["score"],
                        "country": intel["country"],
                        "verdict": intel["verdict"],
                        "severity": "Critical" if intel["score"] >= 50 else "High",
                    }
                )

    return incidents, total_logs


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/report")
def report_page():
    query = request.args.get("target", "").strip()
    if not query:
        return redirect("/")
    report_data = analyze_target(query)
    return render_template("report.html", report=report_data)


@app.route("/api/incidents")
def get_incidents():
    incidents, total_logs = parse_server_logs()
    total = len(incidents)
    malicious = sum(1 for i in incidents if i["score"] > 0)
    unique_ips = len(set(i["ip"] for i in incidents))

    return jsonify(
        {
            "metrics": {
                "total_logs": total_logs,
                "total_incidents": total,
                "malicious_actors": malicious,
                "unique_ips": unique_ips,
            },
            "incidents": incidents,
        }
    )


def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000/")


if __name__ == "__main__":
    Timer(1.2, open_browser).start()
    app.run(port=5000, debug=False)
