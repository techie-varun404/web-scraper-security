import requests
from bs4 import BeautifulSoup
import whois
import socket
import json
import os
from urllib.parse import urljoin, urlparse
from datetime import datetime

# Common ports and services
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}

# Load CVE indicators from file
def load_cve_database(path="cve_database.json"):
    if os.path.exists(path):
        with open(path, "r") as file:
            return json.load(file)
    return []

# Match headers with known CVEs
def match_cves(headers, cve_list):
    matched = []
    for cve in cve_list:
        for indicator in cve.get("indicators", []):
            for header, value in headers.items():
                if indicator.lower() in value.lower():
                    matched.append({
                        "cve_id": cve["id"],
                        "description": cve["description"],
                        "matched_on": header
                    })
                    break
    return matched

# Scan open ports
def scan_ports(host, ports=None, timeout=1):
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    open_ports = []
    print(f"\n[+] Scanning Ports on {host}...")
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((host, port)) == 0:
                    print(f"   [OPEN] Port {port} ({COMMON_PORTS.get(port, 'Unknown')})")
                    open_ports.append(port)
        except Exception as e:
            print(f"   [!] Error on port {port}: {e}")
    return open_ports

# Prioritize and score links from the webpage
def extract_important_links(url, html):
    soup = BeautifulSoup(html, "lxml")
    base = urlparse(url).netloc
    all_links = [urljoin(url, a['href']) for a in soup.find_all('a', href=True)]
    keywords = ['admin', 'login', 'dashboard', 'account', 'panel', 'secure', 'signup', 'signin', 'cpanel']
    
    scored_links = []
    for link in all_links:
        score = 0
        if link.startswith("https://"):
            score += 2
        if urlparse(link).netloc == base:
            score += 1
        if any(kw in link.lower() for kw in keywords):
            score += 3
        scored_links.append((link, score))
    
    return sorted(scored_links, key=lambda x: x[1], reverse=True)[:10]

# Perform WHOIS lookup
def get_whois_info(domain):
    try:
        info = whois.whois(domain)
        creation = info.creation_date[0] if isinstance(info.creation_date, list) else info.creation_date
        expiration = info.expiration_date[0] if isinstance(info.expiration_date, list) else info.expiration_date
        age_days = (datetime.now() - creation).days if creation else "Unknown"
        return info, creation, expiration, age_days
    except Exception as e:
        print(f"   WHOIS Lookup Failed: {e}")
        return {}, "Unknown", "Unknown", "Unknown"

# Check for missing security headers and fingerprinting
def analyze_security_headers(headers):
    required = [
        "X-Content-Type-Options", "Strict-Transport-Security",
        "Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection"
    ]
    missing = [h for h in required if h not in headers]
    
    warnings = []
    server = headers.get("Server", "")
    powered_by = headers.get("X-Powered-By", "")
    
    if "Apache" in server:
        try:
            version = int(server.split("/")[1].split(".")[0])
            if version < 2:
                warnings.append(f"Outdated Apache version: {server}")
        except:
            pass
    if powered_by:
        warnings.append(f"Powered by: {powered_by} (reveals tech stack)")
    
    return missing, warnings

# Main function
def main():
    url = input("Enter the URL (e.g., https://example.com): ").strip()
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        print(f"\n[+] Status Code: {response.status_code}")
        for k, v in headers.items():
            print(f"   {k}: {v}")
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return

    # CVE Matching
    cves = load_cve_database()
    matched_cves = match_cves(headers, cves)
    if matched_cves:
        print("\n[!] CVEs Matched:")
        for cve in matched_cves:
            print(f"   - {cve['cve_id']}: {cve['description']} (matched on {cve['matched_on']})")
    else:
        print("\n[+] No CVEs matched.")

    # Page Title
    soup = BeautifulSoup(response.text, "lxml")
    title = soup.title.string.strip() if soup.title else "No title found"
    print(f"\n[+] Page Title: {title}")

    # Important Links
    top_links = extract_important_links(url, response.text)
    print("\n[+] Top 10 Important Links:")
    for link, _ in top_links:
        print(f"   - {link}")

    # WHOIS Info
    print("\n[+] WHOIS Info:")
    domain = urlparse(url).netloc
    whois_info, creation, expiration, age_days = get_whois_info(domain)
    print(f"   - Domain: {whois_info.get('domain_name', 'Unknown')}")
    print(f"   - Registrar: {whois_info.get('registrar', 'Unknown')}")
    print(f"   - Creation: {creation}")
    print(f"   - Expiration: {expiration}")
    print(f"   - Domain Age: {age_days} days")

    # Port Scan
    host = urlparse(url).hostname
    open_ports = scan_ports(host)

    # Security Header & Fingerprinting
    missing_headers, fingerprint_warnings = analyze_security_headers(headers)
    print(f"\n[+] Missing Headers: {missing_headers if missing_headers else 'None'}")
    for warn in fingerprint_warnings:
        print(f"   [!] {warn}")

    # Save Report
    report_dir = "./reports"
    os.makedirs(report_dir, exist_ok=True)
    clean_domain = domain.replace("www.", "").replace(".", "_")
    report_path = os.path.join(report_dir, f"{clean_domain}_report.txt")

    try:
        with open(report_path, "w") as rpt:
            rpt.write("===============================================\n")
            rpt.write("Website Security Scanner Report\n")
            rpt.write("===============================================\n\n")
            rpt.write(f"URL: {url}\n")
            rpt.write(f"Status Code: {response.status_code}\n\n")

            rpt.write("Matched CVEs:\n")
            if matched_cves:
                for cve in matched_cves:
                    rpt.write(f"- {cve['cve_id']}: {cve['description']} (matched on {cve['matched_on']})\n")
            else:
                rpt.write("- None\n")

            rpt.write("\nPage Title:\n")
            rpt.write(f"- {title}\n\n")

            rpt.write("Top 10 Important Links:\n")
            for link, _ in top_links:
                rpt.write(f"- {link}\n")

            rpt.write("\nWHOIS Info:\n")
            rpt.write(f"- Domain: {whois_info.get('domain_name', 'Unknown')}\n")
            rpt.write(f"- Registrar: {whois_info.get('registrar', 'Unknown')}\n")
            rpt.write(f"- Creation: {creation}\n")
            rpt.write(f"- Expiration: {expiration}\n")
            rpt.write(f"- Domain Age: {age_days} days\n")

            rpt.write("\nOpen Ports:\n")
            if open_ports:
                for port in open_ports:
                    rpt.write(f"- Port {port} ({COMMON_PORTS.get(port, 'Unknown')}) is OPEN\n")
            else:
                rpt.write("- No common ports open.\n")

            rpt.write("\nMissing Security Headers:\n")
            for h in missing_headers:
                rpt.write(f"- {h}\n")

            rpt.write("\nFingerprint Warnings:\n")
            for warn in fingerprint_warnings:
                rpt.write(f"- {warn}\n")

            rpt.write("\n===============================================\n")
            rpt.write("End of Report\n")
            rpt.write("===============================================\n")
        print(f"\n[+] Report saved to: {report_path}")
    except Exception as e:
        print(f"[-] Error writing report: {e}")

if __name__ == "__main__":
   main()
