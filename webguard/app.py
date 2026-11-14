import socket
import ssl
import re
from datetime import datetime, timezone
from urllib.parse import urlparse
import whois
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

def normalize_domain(raw_url):
    raw_url = raw_url.strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    domain = parsed.netloc.split(":")[0].lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain, raw_url

def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (not_after - datetime.now(timezone.utc)).days
                issuer = dict(x[0] for x in cert.get("issuer", []))
                org = issuer.get("organizationName", "Unknown CA")
                return {
                    "valid": days_left > 0,
                    "days_left": days_left,
                    "issuer": org,
                    "message": f"Valid HTTPS certificate issued by {org} ({days_left} days remaining)."
                }
    except Exception as e:
        return {
            "valid": False,
            "days_left": 0,
            "issuer": None,
            "message": "No valid SSL/TLS certificate found. Connection is unencrypted or untrusted."
        }

def check_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation_date).days
            return {
                "found": True,
                "age_days": age_days,
                "created": creation_date.strftime("%Y-%m-%d"),
                "registrar": w.registrar or "Unknown",
                "message": f"Registered {age_days} days ago ({creation_date.strftime('%Y-%m-%d')})."
            }
    except Exception:
        pass
    return {
        "found": False,
        "age_days": None,
        "created": "Unknown",
        "registrar": "Unknown",
        "message": "WHOIS creation date hidden or unavailable."
    }

def check_heuristics(full_url, domain):
    flags = []
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        flags.append("Uses raw IP address instead of a domain name")
    if "@" in full_url:
        flags.append("Contains '@' symbol (classic URL redirection trick)")
    if domain.count("-") >= 3:
        flags.append("Excessive hyphens in domain name")
    suspicious_words = ["login", "verify", "secure", "account", "update", "banking", "free-gift", "kyc"]
    matched = [word for word in suspicious_words if word in full_url.lower()]
    if matched:
        flags.append(f"Contains high-risk keywords: {', '.join(matched)}")
    if len(full_url) > 85:
        flags.append("Unusually long URL structure")
    return flags

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    raw_url = data.get("url", "").strip()
    if not raw_url:
        return jsonify({"error": "Please enter a valid URL or domain."}), 400

    domain, full_url = normalize_domain(raw_url)
    if not domain or "." not in domain:
        return jsonify({"error": "Invalid domain format."}), 400

    # 1. DNS Check
    try:
        ip_address = socket.gethostbyname(domain)
    except socket.gaierror:
        return jsonify({"error": f"Domain '{domain}' does not resolve to an active server."}), 404

    # 2. Run Security Checks
    ssl_info = check_ssl(domain)
    whois_info = check_domain_age(domain)
    heuristic_flags = check_heuristics(full_url, domain)

    # 3. Calculate Risk Score (0 = Safe, 100 = High Risk)
    risk_score = 0
    reasons = []

    if not ssl_info["valid"]:
        risk_score += 40
        reasons.append("Missing or invalid HTTPS encryption.")
    if whois_info["found"] and whois_info["age_days"] is not None:
        if whois_info["age_days"] < 30:
            risk_score += 45
            reasons.append("Domain is less than 30 days old (common in phishing campaigns).")
        elif whois_info["age_days"] < 180:
            risk_score += 15
            reasons.append("Domain is relatively new (under 6 months old).")
    if heuristic_flags:
        risk_score += 15 * len(heuristic_flags)
        reasons.extend(heuristic_flags)

    risk_score = min(risk_score, 100)

    if risk_score >= 50:
        verdict = "Dangerous"
        level = "danger"
        summary = "High risk detected. Avoid entering passwords, OTPs, or payment details on this site."
    elif risk_score >= 20:
        verdict = "Caution"
        level = "warning"
        summary = "Some suspicious indicators found. Double-check the sender before trusting this link."
    else:
        verdict = "Likely Safe"
        level = "safe"
        summary = "No major red flags found in SSL, domain age, or URL structure."

    return jsonify({
        "domain": domain,
        "ip": ip_address,
        "risk_score": risk_score,
        "verdict": verdict,
        "level": level,
        "summary": summary,
        "reasons": reasons,
        "ssl": ssl_info,
        "whois": whois_info
    })

if __name__ == "__main__":
    app.run(debug=True, port=5000)