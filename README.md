#  Web Scraper for Security Analysis

A Python-based web scraper designed for security researchers to analyze websites for potential vulnerabilities. It fetches HTTP response headers, performs WHOIS lookups, scans common ports, extracts internal links, checks security headers, and attempts CVE-based fingerprinting.

![License](https://img.shields.io/github/license/techie-varun404/web-scraper-security)
![Language](https://img.shields.io/github/languages/top/techie-varun404/web-scraper-security)
![Last Commit](https://img.shields.io/github/last-commit/techie-varun404/web-scraper-security)

---

## Features
-  HTTP Header Analysis
-  Internal Link Extraction
-  WHOIS Lookup
-  Security Headers Check
-  CVE Matching from JSON DB
-  Common Port Scanner
-  Report Output in Text Format

---

## Installation

```bash
git clone https://github.com/techie-varun404/web-scraper-security.git
cd web-scraper-security
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

 Usage
```bash
cd web-scraper-security
python3 main.py
```
You'll be prompted to enter the target URL.
The scan report will be saved in the reports/ folder.


---

Project Structure

web-scraper-security/
├── cve_database.json
├── main.py
├── reports/
│   └── <generated_report>.txt
├── src/
├── venv/

---

Sample Output
pgsql
[+] Target: https://zero.webappsecurity.com
[+] Ports Open: 80 (HTTP), 443 (HTTPS)
[+] Server: nginx
[+] Security Headers: Content-Security-Policy, X-Frame-Options, etc.
[+] Links Extracted: /login, /about, /support

---

👤 Author
Varun Sharma
