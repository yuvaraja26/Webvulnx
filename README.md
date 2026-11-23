# WebVulnX

**Automated Web Application Vulnerability Assessment & Reporting Platform with Burp Suite Community Edition Integration**

WebVulnX is a modular, localhost-first web application security assessment and reporting workbench built with **Python (Flask)**, **SQLite**, **Chart.js**, **ReportLab**, and the **Burp Suite Montoya API**. It receives user-selected HTTP requests and responses from Burp Suite Community Edition over an authenticated local REST API, redacts sensitive credentials, runs passive vulnerability checks, manages manual analyst validation workflows, and exports professional **PDF** and **HTML** VAPT reports.

---

## Architecture

```
OWASP Juice Shop (Local Docker :3000)
          │
          ▼
   Burp Suite Community Edition (Proxy)
          │
          ▼
   WebVulnX Montoya Java Extension (Right-click -> Send to WebVulnX)
          │  HTTP POST + X-WebVulnX-Key
          ▼
   Flask REST API (127.0.0.1:5000/api/v1/traffic)
          │
          ├──► Scope Validator (Strict localhost / authorized prefix)
          ├──► Traffic Processor & Credential Redaction
          └──► Passive Vulnerability Detection Engine
                     │
                     ▼
               SQLite Database (Targets, Assessments, Traffic, Findings)
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
   Web Dashboard           Report Generator
  (Red & Black UI)         (PDF & HTML VAPT)
```

---

## Key Features

* **Burp Suite Community Integration**: Custom Java extension (Montoya API) that transmits selected HTTP history items to WebVulnX without requiring Burp Suite Professional.
* **Strict Scope Enforcement**: Restricts ingestion and assessment targets to explicitly authorized local lab hosts (`127.0.0.1`, `localhost`).
* **Automatic Credential Redaction**: Redacts `Authorization`, `Cookie`, `X-API-Key`, and cookie values in `Set-Cookie` headers before database storage while preserving cookie security flags for analysis.
* **Modular Passive Detection Engine**:
  * Missing Security Headers (`CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`)
  * Cookie Security Attributes (`HttpOnly`, `SameSite`, `Secure`)
  * Information Disclosure (Verbose `Server`/`X-Powered-By` banners and unhandled error/debug traces)
* **Manual Validation Workflow**: Analysts can review captured evidence and transition findings across `New`, `Needs Validation`, `Confirmed`, `False Positive`, `Fixed`, and `Retested`.
* **Automated VAPT Reporting**: One-click export of formatted **PDF** (ReportLab) and standalone **HTML** security assessment reports.

---

## Installation & Quick Start (Kali Linux)

### 1. Start the Target Application (OWASP Juice Shop)
```bash
sudo systemctl start docker
sudo docker run --rm -d -p 127.0.0.1:3000:3000 --name juice-shop bkimminich/juice-shop
```

### 2. Set Up WebVulnX
```bash
git clone <your-repo-url> WebVulnX
cd WebVulnX
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 run.py
```
Access the dashboard at `http://127.0.0.1:5000`.

### 3. Build & Load the Burp Suite Extension
```bash
sudo apt update && sudo apt install -y maven default-jdk
cd burp_extension
mvn clean package
```
1. Open **Burp Suite Community Edition** -> **Extensions** -> **Installed** -> **Add**.
2. Set **Extension type** to **Java** and select `burp_extension/target/webvulnx-burp-extension-1.0.0.jar`.
3. Browse `http://127.0.0.1:3000` through Burp's browser, right-click any request in **Proxy -> HTTP history**, and select **Extensions -> WebVulnX Connector -> Send to WebVulnX**.

---

## Running Integration Tests
```bash
source venv/bin/activate
python3 -m unittest discover -s tests -v
```

---

## Known Limitations & Future Roadmap
* **Passive-First Analysis**: Current detectors focus on passive HTTP response analysis and require manual analyst validation for complex access-control or business-logic issues.
* **Localhost Only**: Designed strictly for local lab environments (e.g., OWASP Juice Shop) and bound to `127.0.0.1` by default.
* **Planned Enhancements**: Assessment comparison views, CVSS v4.0 calculator integration, and additional modular analyzers (CORS misconfiguration, JWT header/claim inspection, and Open Redirect checks).
