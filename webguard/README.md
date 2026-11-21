# 🛡️ WebGuard — Real-Time URL & Phishing Security Scanner

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-000000?style=for-the-badge&logo=flask&logoColor=white)
![Security](https://img.shields.io/badge/Focus-Application%20Security-00C853?style=for-the-badge)

**WebGuard** is a lightweight, public-facing URL security analysis tool built with Python and Flask. It inspects target domains across multiple network and application layers to detect potential phishing links, unencrypted connections, and newly registered malicious domains—returning an instant, human-readable risk score.

🔗 **Live Demo:** [https://webguard.onrender.com](https://[your-live-link].onrender.com)

---

## 🔍 Key Security Checks

WebGuard evaluates every submitted URL through four independent inspection layers:

1. **SSL/TLS Certificate Validation:** Verifies HTTPS enforcement, checks certificate validity, and flags expired or missing encryption.
2. **WHOIS Domain Age Analysis:** Queries registration metadata to flag newly registered domains (common indicators of disposable phishing infrastructure).
3. **DNS & Socket Resolution:** Resolves target hostnames to IP addresses to verify active infrastructure and catch dead or sinkholed domains.
4. **Heuristic Phishing Pattern Detection:** Scans URL structure for suspicious keywords, excessive subdomains, IP-based URLs, URL shorteners, and obfuscation tactics.

---

## 🛠️ Tech Stack

* **Backend:** Python 3, Flask
* **Security & Networking Libraries:** `ssl`, `socket`, `python-whois`, `urllib.parse`, `requests`
* **Frontend:** HTML5, CSS3, Vanilla JavaScript (Responsive Dark UI)
* **Deployment:** Render / Gunicorn

---

## 📂 Project Structure

```text
webguard/
├── app.py               # Main Flask server & multi-layered security analysis engine
├── templates/
│   └── index.html       # Frontend dashboard UI & risk score display
├── requirements.txt     # Python dependencies
├── Procfile             # Production web server configuration (Gunicorn)
└── README.md            # Project documentation