import re
import os
import requests
import ipaddress
import webbrowser
from threading import Timer
from collections import defaultdict
from flask import Flask, render_template, jsonify

app = Flask(__name__)

# Aapki verified AbuseIPDB Key
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


def parse_server_logs():
    failed_logins = defaultdict(int)
    incidents = []

    if not os.path.exists(LOG_FILE):
        return incidents

    pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+).*?"(?:GET|POST) (.*?) HTTP.*?" (\d+)')

    with open(LOG_FILE, "r") as f:
        for line in f:
            match = pattern.search(line)
            if not match:
                continue

            ip, endpoint, status = match.groups()

            # Rule 1: Brute Force (401 status code)
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

            # Rule 2: SQL Injection & Path Traversal
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

    return incidents


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/api/incidents")
def get_incidents():
    incidents = parse_server_logs()
    total = len(incidents)
    malicious = sum(1 for i in incidents if i["verdict"] == "MALICIOUS")
    unique_ips = len(set(i["ip"] for i in incidents))

    return jsonify(
        {
            "stats": {
                "total_threats": total,
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
