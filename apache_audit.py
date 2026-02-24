#!/usr/bin/env python3
"""
Apache Hardening Audit Tool
Red Team / Blue Team Portfolio Project
Author: Tanzz1337 - Security Audit Tools
"""

import os
import re
import json
import sys
import socket
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path


# COLOR OUTPUT
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def c(color, text): return f"{color}{text}{Colors.RESET}"


class ApacheAuditor:
    def __init__(self, config_path=None, target_url=None):
        self.config_path = config_path
        self.target_url = target_url
        self.findings = []
        self.score = 0
        self.max_score = 0

    def add_finding(self, check_id, title, status, severity, description, recommendation, mitre=None, reference=None):
        finding = {
            "id": check_id,
            "title": title,
            "status": status,
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
            "mitre": mitre or "",
            "reference": reference or "",
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)
        weight = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 0}
        self.max_score += weight.get(severity, 0)
        if status == "PASS":
            self.score += weight.get(severity, 0)
        icon = {"PASS": "OK", "FAIL": "FAIL", "WARN": "WARN", "INFO": "INFO"}.get(status, "?")
        color = {"PASS": Colors.GREEN, "FAIL": Colors.RED, "WARN": Colors.YELLOW, "INFO": Colors.CYAN}.get(status, Colors.WHITE)
        sev_color = {"CRITICAL": Colors.RED, "HIGH": Colors.RED, "MEDIUM": Colors.YELLOW, "LOW": Colors.CYAN, "INFO": Colors.BLUE}.get(severity, Colors.WHITE)
        print(f"  [{c(color, icon)}] [{c(sev_color, severity[:4])}] {title}")
        if status != "PASS":
            print(f"       -> {c(Colors.WHITE, description)}")

    def read_config(self):
        content = ""
        if self.config_path and os.path.exists(self.config_path):
            with open(self.config_path, 'r', errors='ignore') as f:
                content = f.read()
        return content

    def find_config_files(self):
        common_paths = [
            "/etc/apache2/apache2.conf",
            "/etc/httpd/conf/httpd.conf",
            "/etc/httpd/httpd.conf",
            "/usr/local/apache2/conf/httpd.conf",
        ]
        found = []
        for p in common_paths:
            if os.path.exists(p):
                found.append(p)
        return found

    def check_server_tokens(self, config):
        if re.search(r'ServerTokens\s+Prod', config, re.I):
            self.add_finding("APT-001", "ServerTokens set to Prod", "PASS", "HIGH",
                "Server version info is minimal.", "Keep ServerTokens Prod")
        elif re.search(r'ServerTokens', config, re.I):
            self.add_finding("APT-001", "ServerTokens misconfigured", "FAIL", "HIGH",
                "ServerTokens exposes server version. Attackers can fingerprint and target known CVEs.",
                "Set 'ServerTokens Prod' in httpd.conf",
                mitre="T1592.002", reference="CIS Apache 2.4 - 2.1")
        else:
            self.add_finding("APT-001", "ServerTokens not configured", "WARN", "HIGH",
                "Default ServerTokens may expose full version info.",
                "Add 'ServerTokens Prod' to config", mitre="T1592.002")

    def check_server_signature(self, config):
        if re.search(r'ServerSignature\s+Off', config, re.I):
            self.add_finding("APT-002", "ServerSignature Off", "PASS", "MEDIUM",
                "Server signature disabled.", "Keep ServerSignature Off")
        else:
            self.add_finding("APT-002", "ServerSignature not disabled", "FAIL", "MEDIUM",
                "Error pages may expose Apache version and OS info.",
                "Add 'ServerSignature Off' to config",
                mitre="T1592.002", reference="CIS Apache 2.4 - 2.2")

    def check_directory_listing(self, config):
        if re.search(r'Options\s+.*-Indexes', config, re.I):
            self.add_finding("APT-003", "Directory listing disabled", "PASS", "HIGH",
                "Indexes option is disabled.", "")
        elif re.search(r'Options\s+.*Indexes', config, re.I):
            self.add_finding("APT-003", "Directory listing ENABLED", "FAIL", "HIGH",
                "Options +Indexes allows attackers to browse directory contents.",
                "Use 'Options -Indexes'", mitre="T1083",
                reference="OWASP Security Misconfiguration")
        else:
            self.add_finding("APT-003", "Directory listing status unclear", "WARN", "MEDIUM",
                "Could not confirm directory listing is disabled.",
                "Explicitly set 'Options -Indexes'")

    def check_trace_method(self, config):
        if re.search(r'TraceEnable\s+Off', config, re.I):
            self.add_finding("APT-004", "TraceEnable Off", "PASS", "MEDIUM",
                "HTTP TRACE method is disabled.", "")
        else:
            self.add_finding("APT-004", "TRACE method not disabled", "FAIL", "MEDIUM",
                "HTTP TRACE enables Cross-Site Tracing (XST) to steal cookies.",
                "Add 'TraceEnable Off'", mitre="T1059", reference="CVE-2004-2320")

    def check_etag(self, config):
        if re.search(r'FileETag\s+None', config, re.I):
            self.add_finding("APT-005", "ETag disabled", "PASS", "LOW",
                "ETag won't leak inode info.", "")
        else:
            self.add_finding("APT-005", "ETag may leak inode info", "WARN", "LOW",
                "Default ETag includes inode numbers which aid attacker recon.",
                "Add 'FileETag None'", mitre="T1592")

    def check_timeout(self, config):
        match = re.search(r'Timeout\s+(\d+)', config, re.I)
        if match:
            timeout = int(match.group(1))
            if timeout <= 60:
                self.add_finding("APT-006", f"Timeout set to {timeout}s (OK)", "PASS", "MEDIUM",
                    "Timeout value is reasonable.", "")
            else:
                self.add_finding("APT-006", f"Timeout too high ({timeout}s)", "WARN", "MEDIUM",
                    f"High timeout ({timeout}s) increases Slowloris DoS exposure.",
                    "Set 'Timeout 60'", mitre="T1499")
        else:
            self.add_finding("APT-006", "Timeout not configured", "WARN", "MEDIUM",
                "Default timeout (300s) may enable Slowloris-style attacks.",
                "Set 'Timeout 60' explicitly", mitre="T1499")

    def check_limit_request(self, config):
        if re.search(r'LimitRequestBody\s+\d+', config, re.I):
            self.add_finding("APT-007", "LimitRequestBody configured", "PASS", "MEDIUM",
                "Request body size is limited.", "")
        else:
            self.add_finding("APT-007", "LimitRequestBody not set", "FAIL", "MEDIUM",
                "No request body limit allows large payload attacks and potential DoS.",
                "Add 'LimitRequestBody 10485760' (10MB)", mitre="T1499")

    def check_symlinks(self, config):
        if re.search(r'Options\s+.*-FollowSymLinks', config, re.I):
            self.add_finding("APT-008", "FollowSymLinks disabled", "PASS", "HIGH",
                "Symlink following is disabled.", "")
        elif re.search(r'Options\s+.*FollowSymLinks', config, re.I):
            self.add_finding("APT-008", "FollowSymLinks ENABLED", "WARN", "HIGH",
                "FollowSymLinks can allow traversal outside web root if misconfigured.",
                "Use 'Options -FollowSymLinks'", mitre="T1083")
        else:
            self.add_finding("APT-008", "FollowSymLinks status unclear", "INFO", "LOW",
                "Could not determine FollowSymLinks setting.", "Review Options directives")

    def check_htaccess(self, config):
        if re.search(r'AllowOverride\s+None', config, re.I):
            self.add_finding("APT-009", "AllowOverride None", "PASS", "MEDIUM",
                ".htaccess overrides are disabled.", "")
        elif re.search(r'AllowOverride\s+All', config, re.I):
            self.add_finding("APT-009", "AllowOverride All is dangerous", "FAIL", "MEDIUM",
                "AllowOverride All lets .htaccess override security settings.",
                "Use 'AllowOverride None'", mitre="T1574")
        else:
            self.add_finding("APT-009", "AllowOverride partially set", "INFO", "LOW",
                "Review AllowOverride for each directory.", "Prefer AllowOverride None")

    def check_mod_security(self, config):
        if re.search(r'SecRuleEngine\s+On', config, re.I) or re.search(r'mod_security', config, re.I):
            self.add_finding("APT-010", "ModSecurity WAF active", "PASS", "CRITICAL",
                "Web Application Firewall is enabled.", "")
        else:
            self.add_finding("APT-010", "ModSecurity WAF not detected", "FAIL", "CRITICAL",
                "No WAF detected. SQLi, XSS, and other attacks are unfiltered.",
                "Install mod_security with OWASP CRS ruleset",
                mitre="T1190", reference="OWASP ModSecurity CRS")

    def check_ssl_config(self, config):
        if re.search(r'SSLProtocol.*TLSv1\.2|SSLProtocol.*TLSv1\.3', config, re.I):
            self.add_finding("APT-011", "Modern TLS protocol configured", "PASS", "CRITICAL",
                "TLS 1.2/1.3 is enforced.", "")
        elif re.search(r'SSLProtocol', config, re.I):
            self.add_finding("APT-011", "SSL/TLS protocol may be weak", "WARN", "CRITICAL",
                "SSL config exists but may allow deprecated protocols (SSLv3, TLS 1.0/1.1).",
                "Set 'SSLProtocol -All +TLSv1.2 +TLSv1.3'",
                mitre="T1557", reference="CVE-2014-3566 POODLE")
        else:
            self.add_finding("APT-011", "SSL/TLS not configured in config", "INFO", "CRITICAL",
                "No SSL config found. Verify HTTPS is implemented.",
                "Implement SSL/TLS with valid certificate")

    def check_hsts(self, config):
        if re.search(r'Strict-Transport-Security', config, re.I):
            self.add_finding("APT-012", "HSTS header configured", "PASS", "HIGH",
                "HTTP Strict Transport Security is enabled.", "")
        else:
            self.add_finding("APT-012", "HSTS not configured", "FAIL", "HIGH",
                "Without HSTS, users can be downgraded to HTTP via MITM attacks.",
                'Add: Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
                mitre="T1557")

    def check_security_headers(self, config):
        headers = {
            "X-Frame-Options": "T1185",
            "X-Content-Type-Options": "T1059",
            "X-XSS-Protection": "T1059.007",
            "Content-Security-Policy": "T1059.007",
            "Referrer-Policy": "T1592",
        }
        missing = [h for h in headers if not re.search(h, config, re.I)]
        if not missing:
            self.add_finding("APT-013", "All security headers configured", "PASS", "HIGH",
                "Key security headers are present.", "")
        else:
            self.add_finding("APT-013", f"Missing headers: {', '.join(missing)}", "FAIL", "HIGH",
                f"Missing: {', '.join(missing)}. These protect against XSS, clickjacking, MIME attacks.",
                'Add via mod_headers: Header always set X-Frame-Options "SAMEORIGIN"',
                mitre="T1059.007", reference="OWASP Secure Headers Project")

    def check_mod_status(self, config):
        if re.search(r'<Location\s+/server-status', config, re.I):
            if re.search(r'Require\s+local|Require\s+ip\s+127', config, re.I):
                self.add_finding("APT-014", "server-status restricted to localhost", "PASS", "HIGH",
                    "Status page is access-controlled.", "")
            else:
                self.add_finding("APT-014", "server-status publicly accessible!", "FAIL", "HIGH",
                    "/server-status exposes worker stats and request info to everyone.",
                    "Add: Require local inside the Location block", mitre="T1046")
        else:
            self.add_finding("APT-014", "server-status config not found", "INFO", "MEDIUM",
                "Verify /server-status is disabled or properly restricted.",
                "Disable: a2dismod status")

    def check_expose_php(self, config):
        if re.search(r'expose_php\s*=\s*Off', config, re.I):
            self.add_finding("APT-015", "PHP version exposure disabled", "PASS", "MEDIUM",
                "PHP version not exposed in headers.", "")
        elif re.search(r'expose_php\s*=\s*On', config, re.I):
            self.add_finding("APT-015", "PHP version exposed!", "FAIL", "MEDIUM",
                "X-Powered-By reveals PHP version, aiding targeted attacks.",
                "Set 'expose_php = Off' in php.ini", mitre="T1592.002")
        else:
            self.add_finding("APT-015", "PHP config not found in Apache config", "INFO", "LOW",
                "Check php.ini separately.", "Set expose_php = Off in php.ini")

    def check_http_methods(self, url):
        try:
            req = urllib.request.Request(url, method='OPTIONS')
            req.add_header('User-Agent', 'ApacheAuditTool/1.0')
            with urllib.request.urlopen(req, timeout=5) as resp:
                allow = resp.getheader('Allow', '')
                dangerous = [m for m in ['PUT', 'DELETE', 'CONNECT'] if m in allow]
                if dangerous:
                    self.add_finding("APT-016", f"Dangerous HTTP methods: {', '.join(dangerous)}", "FAIL", "HIGH",
                        f"Methods {dangerous} should be disabled.",
                        "Use <LimitExcept GET POST HEAD> Require all denied </LimitExcept>",
                        mitre="T1190")
                else:
                    self.add_finding("APT-016", "HTTP methods appear restricted", "PASS", "HIGH",
                        f"Allowed: {allow}", "")
        except Exception as e:
            self.add_finding("APT-016", "HTTP methods check skipped", "INFO", "HIGH",
                f"Could not connect: {e}", "Run: curl -X OPTIONS -v <url>")

    def check_server_header(self, url):
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'ApacheAuditTool/1.0')
            with urllib.request.urlopen(req, timeout=5) as resp:
                server = resp.getheader('Server', '')
                if server and len(server) > 7:
                    self.add_finding("APT-017", f"Server header leaks version: '{server}'", "FAIL", "HIGH",
                        "Detailed server header helps attackers find applicable CVEs.",
                        "Set ServerTokens Prod", mitre="T1592.002")
                elif server:
                    self.add_finding("APT-017", f"Server header minimal: '{server}'", "PASS", "HIGH",
                        "Server header is minimal.", "")
                else:
                    self.add_finding("APT-017", "Server header suppressed", "PASS", "HIGH",
                        "No Server header -- excellent!", "")
        except Exception as e:
            self.add_finding("APT-017", "Server header check skipped", "INFO", "HIGH",
                f"Could not connect: {e}", "Run: curl -I <url>")

    def check_directory_listing_http(self, url):
        test_paths = ['/icons/', '/manual/', '/cgi-bin/']
        for path in test_paths:
            try:
                req = urllib.request.Request(url.rstrip('/') + path)
                req.add_header('User-Agent', 'ApacheAuditTool/1.0')
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = resp.read(2000).decode('utf-8', errors='ignore')
                    if 'Index of' in body or 'Directory listing' in body:
                        self.add_finding("APT-018", f"Directory listing ACTIVE at {path}", "FAIL", "HIGH",
                            f"Directory browsing enabled at {path}.",
                            "Add 'Options -Indexes'", mitre="T1083")
                        return
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    pass
            except Exception:
                pass
        self.add_finding("APT-018", "Directory listing not detected via HTTP", "PASS", "HIGH",
            "Common directories return 403/404.", "")

    def check_clickjacking(self, url):
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'ApacheAuditTool/1.0')
            with urllib.request.urlopen(req, timeout=5) as resp:
                xfo = resp.getheader('X-Frame-Options', '')
                csp = resp.getheader('Content-Security-Policy', '')
                if xfo or 'frame-ancestors' in csp:
                    self.add_finding("APT-019", "Clickjacking protection present", "PASS", "MEDIUM",
                        f"X-Frame-Options: {xfo or 'via CSP'}", "")
                else:
                    self.add_finding("APT-019", "No clickjacking protection", "FAIL", "MEDIUM",
                        "Missing X-Frame-Options allows iframe embedding (clickjacking).",
                        'Add: Header always set X-Frame-Options "SAMEORIGIN"', mitre="T1185")
        except Exception as e:
            self.add_finding("APT-019", "Clickjacking check skipped", "INFO", "MEDIUM",
                f"Could not connect: {e}", "")

    def check_ssl_live(self, url):
        if not url.startswith('https'):
            self.add_finding("APT-020", "Target not using HTTPS!", "FAIL", "CRITICAL",
                "HTTP is unencrypted. All traffic can be intercepted.",
                "Implement HTTPS with a valid TLS certificate", mitre="T1557")
        else:
            import ssl
            try:
                hostname = url.split('//')[1].split('/')[0]
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                    s.settimeout(5)
                    s.connect((hostname, 443))
                    proto = s.version()
                    if proto in ['TLSv1', 'SSLv3']:
                        self.add_finding("APT-020", f"Weak TLS version: {proto}", "FAIL", "CRITICAL",
                            f"Server negotiated {proto} which has known vulnerabilities.",
                            "Enforce: SSLProtocol -All +TLSv1.2 +TLSv1.3", mitre="T1557")
                    else:
                        self.add_finding("APT-020", f"TLS version OK: {proto}", "PASS", "CRITICAL",
                            f"Negotiated: {proto}", "")
            except Exception as e:
                self.add_finding("APT-020", "SSL live check failed", "WARN", "CRITICAL",
                    f"Error: {e}", "Verify SSL cert and TLS config manually")

    def check_default_pages(self, url):
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'ApacheAuditTool/1.0')
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read(3000).decode('utf-8', errors='ignore')
                if 'Apache2 Ubuntu Default Page' in body or 'It works!' in body or 'Apache HTTP Server Test Page' in body:
                    self.add_finding("APT-021", "Default Apache page still active!", "FAIL", "MEDIUM",
                        "Default page reveals Apache is running and OS type.",
                        "Remove: rm /var/www/html/index.html", mitre="T1592")
                else:
                    self.add_finding("APT-021", "Default page replaced", "PASS", "MEDIUM",
                        "No default Apache page detected.", "")
        except Exception as e:
            self.add_finding("APT-021", "Default page check skipped", "INFO", "MEDIUM",
                f"Could not connect: {e}", "")

    def check_file_permissions(self):
        paths_to_check = [
            ("/etc/apache2/apache2.conf", 0o644),
            ("/etc/apache2/", 0o755),
            ("/var/www/html/", 0o755),
            ("/etc/httpd/conf/httpd.conf", 0o644),
        ]
        issues = []
        checked = False
        for path, expected_max in paths_to_check:
            if os.path.exists(path):
                checked = True
                stat = os.stat(path)
                mode = stat.st_mode & 0o777
                if mode > expected_max:
                    issues.append(f"{path} mode {oct(mode)} (expected max {oct(expected_max)})")
        if not checked:
            self.add_finding("APT-022", "File permission check skipped", "INFO", "HIGH",
                "No standard Apache paths found on this system.",
                "Manually check: ls -la /etc/apache2/ or /etc/httpd/")
        elif not issues:
            self.add_finding("APT-022", "File permissions appear OK", "PASS", "HIGH",
                "Checked paths have reasonable permissions.", "")
        else:
            self.add_finding("APT-022", "Insecure file permissions detected", "FAIL", "HIGH",
                "; ".join(issues),
                "chmod 644 /etc/apache2/apache2.conf", mitre="T1222")

    def _get_demo_config(self):
        return """
# Demo Apache Config - Intentionally misconfigured for testing
ServerTokens Full
ServerSignature On
Options +Indexes +FollowSymLinks
TraceEnable On
AllowOverride All
Timeout 300
"""

    def run_audit(self):
        print(f"\n{c(Colors.BOLD, c(Colors.CYAN, '================================================'))}")
        print(f"{c(Colors.CYAN, '  APACHE HARDENING AUDIT TOOL v1.0')}")
        print(f"{c(Colors.CYAN, '  Red Team / Blue Team Portfolio Project')}")
        print(f"{c(Colors.CYAN, '================================================')}\n")

        config_content = ""

        print(c(Colors.BOLD, "--- [1/3] CONFIG FILE ANALYSIS ---"))
        if self.config_path:
            if os.path.exists(self.config_path):
                config_content = self.read_config()
                print(f"  -> Reading: {self.config_path}\n")
            else:
                print(f"  Config not found: {self.config_path}")
        else:
            auto_found = self.find_config_files()
            if auto_found:
                print(f"  -> Auto-detected: {', '.join(auto_found)}\n")
                for cf in auto_found:
                    with open(cf, 'r', errors='ignore') as f:
                        config_content += f.read() + "\n"
            else:
                print(f"  No Apache config found - using demo config for demonstration\n")
                config_content = self._get_demo_config()

        self.check_server_tokens(config_content)
        self.check_server_signature(config_content)
        self.check_directory_listing(config_content)
        self.check_trace_method(config_content)
        self.check_etag(config_content)
        self.check_timeout(config_content)
        self.check_limit_request(config_content)
        self.check_symlinks(config_content)
        self.check_htaccess(config_content)
        self.check_mod_security(config_content)
        self.check_ssl_config(config_content)
        self.check_hsts(config_content)
        self.check_security_headers(config_content)
        self.check_mod_status(config_content)
        self.check_expose_php(config_content)

        print(f"\n{c(Colors.BOLD, '--- [2/3] FILESYSTEM CHECKS ---')}")
        self.check_file_permissions()

        print(f"\n{c(Colors.BOLD, '--- [3/3] NETWORK / HTTP CHECKS ---')}")
        if self.target_url:
            print(f"  -> Target: {self.target_url}\n")
            self.check_server_header(self.target_url)
            self.check_http_methods(self.target_url)
            self.check_directory_listing_http(self.target_url)
            self.check_clickjacking(self.target_url)
            self.check_ssl_live(self.target_url)
            self.check_default_pages(self.target_url)
        else:
            print(f"  No target URL provided. Skipping HTTP checks.")
            print(f"  Run with --url http://your-server to enable.\n")

        self._print_summary()
        return self.findings

    def _print_summary(self):
        counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "INFO": 0}
        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": []}
        for f in self.findings:
            counts[f["status"]] = counts.get(f["status"], 0) + 1
            if f["status"] in ("FAIL", "WARN") and f["severity"] in by_severity:
                by_severity[f["severity"]].append(f)

        pct = int((self.score / self.max_score * 100)) if self.max_score > 0 else 0
        if pct >= 80:
            grade, grade_color = "A - HARDENED", Colors.GREEN
        elif pct >= 60:
            grade, grade_color = "B - MODERATE", Colors.YELLOW
        elif pct >= 40:
            grade, grade_color = "C - NEEDS WORK", Colors.YELLOW
        else:
            grade, grade_color = "D - VULNERABLE", Colors.RED

        print(f"\n{c(Colors.BOLD, c(Colors.CYAN, '--- AUDIT SUMMARY ---'))}")
        print(f"  Score  : {c(Colors.BOLD, str(self.score))}/{self.max_score} ({pct}%)")
        print(f"  Grade  : {c(grade_color, c(Colors.BOLD, grade))}")
        print(f"  PASS:{counts['PASS']}  FAIL:{counts['FAIL']}  WARN:{counts['WARN']}  INFO:{counts['INFO']}")

        if by_severity["CRITICAL"]:
            print(f"\n  CRITICAL ISSUES:")
            for f in by_severity["CRITICAL"]:
                print(f"    [!] {f['title']}")
        if by_severity["HIGH"]:
            print(f"\n  HIGH ISSUES:")
            for f in by_severity["HIGH"]:
                print(f"    [!] {f['title']}")

    def export_json(self, output_path="apache_audit_report.json"):
        pct = int((self.score / self.max_score * 100)) if self.max_score > 0 else 0
        report = {
            "tool": "Apache Hardening Audit Tool v1.0",
            "generated": datetime.now().isoformat(),
            "target_url": self.target_url or "N/A",
            "config_path": self.config_path or "auto-detected",
            "score": self.score,
            "max_score": self.max_score,
            "percentage": pct,
            "findings": self.findings
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        return report


    def export_html(self, output_path="apache_audit_report.html"):
        pct = int((self.score / self.max_score * 100)) if self.max_score > 0 else 0
        now = datetime.now().strftime("%d %B %Y, %H:%M")

        if pct >= 80:
            grade, grade_cls = "HARDENED", "grade-a"
        elif pct >= 60:
            grade, grade_cls = "MODERATE", "grade-b"
        elif pct >= 40:
            grade, grade_cls = "NEEDS WORK", "grade-c"
        else:
            grade, grade_cls = "VULNERABLE", "grade-d"

        counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "INFO": 0}
        sev_fail = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            counts[f["status"]] = counts.get(f["status"], 0) + 1
            if f["status"] in ("FAIL", "WARN"):
                sev_fail[f["severity"]] = sev_fail.get(f["severity"], 0) + 1

        def row(f):
            status_cls = f["status"].lower()
            sev_cls    = f["severity"].lower()
            rec = f["recommendation"].replace("\n", "<br>")
            mitre = f'<span class="tag">{f["mitre"]}</span>' if f["mitre"] else ""
            return (
                f'<tr class="r-{status_cls}">'
                f'<td class="td-id">{f["id"]}</td>'
                f'<td class="td-title">{f["title"]}{mitre}</td>'
                f'<td><span class="sev sev-{sev_cls}">{f["severity"]}</span></td>'
                f'<td><span class="st st-{status_cls}">{f["status"]}</span></td>'
                f'<td class="td-desc">{f["description"]}</td>'
                f'<td class="td-rec">{rec}</td>'
                f'</tr>'
            )

        rows_html = "\n".join(row(f) for f in self.findings)
        config_display = self.config_path or "auto-detected"
        url_display    = self.target_url or "N/A"

        r = 52
        circ = 2 * 3.14159 * r
        dash = circ * pct / 100
        gap  = circ - dash
        ring_color = "#2a6e3f" if pct >= 80 else "#c0392b" if pct < 40 else "#9a6b00"

        html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Apache Hardening Audit Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:        #1e2025;
  --surface:   #272b33;
  --surface2:  #2e333d;
  --border:    #363c47;
  --border2:   #424956;
  --text:      #d4d8e2;
  --text-dim:  #7f8899;
  --text-head: #eaecf0;
  --pass:   #3a8f58;
  --fail:   #c0392b;
  --warn:   #c47c1a;
  --info:   #4a7abf;
  --c-crit: #c0392b;
  --c-high: #c0622b;
  --c-med:  #a07820;
  --c-low:  #2e6ea6;
}

html { font-size: 15px; }

body {
  font-family: 'Inter', system-ui, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
  min-height: 100vh;
}

/* ── Page Layout ───────────────────── */
.page { max-width: 1280px; margin: 0 auto; padding: 28px 28px 60px; }

/* ── Header ────────────────────────── */
.header {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 28px 32px;
  display: flex;
  align-items: flex-start;
  gap: 36px;
  margin-bottom: 16px;
}
.header-text { flex: 1; min-width: 0; }
.header-eyebrow {
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--text-dim);
  margin-bottom: 6px;
}
.header-title {
  font-size: 22px;
  font-weight: 700;
  color: var(--text-head);
  letter-spacing: -0.02em;
  margin-bottom: 18px;
}
.meta-grid { display: flex; gap: 28px; flex-wrap: wrap; }
.meta-item { display: flex; flex-direction: column; gap: 2px; }
.meta-label {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--text-dim);
}
.meta-value {
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px;
  color: var(--text);
}

/* ── Score Ring ─────────────────────── */
.score-block {
  display: flex; flex-direction: column;
  align-items: center; gap: 8px; flex-shrink: 0;
}
.score-ring { position: relative; width: 116px; height: 116px; }
.score-ring svg { width: 100%; height: 100%; transform: rotate(-90deg); }
.ring-bg  { fill: none; stroke: var(--border2); stroke-width: 9; }
.ring-val { fill: none; stroke-width: 9; stroke-linecap: round; }
.ring-center {
  position: absolute; top: 50%; left: 50%;
  transform: translate(-50%,-50%);
  text-align: center; line-height: 1.1;
}
.ring-pct {
  font-size: 26px; font-weight: 700;
  font-variant-numeric: tabular-nums;
}
.ring-sub {
  font-size: 10px; font-weight: 500;
  text-transform: uppercase; letter-spacing: 0.1em;
  color: var(--text-dim);
}
.grade-pill {
  font-size: 11px; font-weight: 600;
  letter-spacing: 0.1em; text-transform: uppercase;
  padding: 4px 14px; border-radius: 4px;
  border: 1px solid var(--border2);
  color: var(--text-dim); background: var(--surface2);
}
.grade-a { background:#1a3326; color:#4caf7d; border-color:#2a5240; }
.grade-b { background:#2e2510; color:#c9a03a; border-color:#4a3a18; }
.grade-c { background:#2e1f10; color:#d0843a; border-color:#4a3020; }
.grade-d { background:#2e1515; color:#e05050; border-color:#4a2222; }

/* ── Stat + Severity Grid ───────────── */
.cards-row {
  display: grid;
  grid-template-columns: repeat(4,1fr);
  gap: 12px;
  margin-bottom: 16px;
}
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 18px 20px;
  border-left: 4px solid var(--border2);
}
.card.c-pass { border-left-color: var(--pass); }
.card.c-fail { border-left-color: var(--fail); }
.card.c-warn { border-left-color: var(--warn); }
.card.c-total{ border-left-color: var(--info); }
.card.c-crit { border-left-color: var(--c-crit); }
.card.c-high { border-left-color: var(--c-high); }
.card.c-med  { border-left-color: var(--c-med);  }
.card.c-low  { border-left-color: var(--c-low);  }

.card-num {
  font-size: 34px; font-weight: 700; line-height: 1;
  font-variant-numeric: tabular-nums;
}
.c-pass  .card-num { color: var(--pass); }
.c-fail  .card-num { color: var(--fail); }
.c-warn  .card-num { color: var(--warn); }
.c-total .card-num { color: var(--info); }
.c-crit  .card-num { color: var(--c-crit); }
.c-high  .card-num { color: var(--c-high); }
.c-med   .card-num { color: var(--c-med);  }
.c-low   .card-num { color: var(--c-low);  }

.card-lbl {
  font-size: 11px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.1em;
  color: var(--text-dim); margin-top: 5px;
}
.card-sub { font-size: 11px; color: var(--text-dim); margin-top: 2px; }

/* ── Table Section ──────────────────── */
.section {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}
.section-head {
  padding: 16px 20px;
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center;
  justify-content: space-between; gap: 12px; flex-wrap: wrap;
}
.section-title {
  font-size: 14px; font-weight: 600;
  color: var(--text-head);
}
.filter-bar { display: flex; gap: 6px; }
.fbtn {
  font-size: 12px; font-weight: 500;
  padding: 5px 14px; border-radius: 5px;
  border: 1px solid var(--border2);
  background: transparent; color: var(--text-dim);
  cursor: pointer; transition: all .12s;
  font-family: 'Inter', sans-serif;
}
.fbtn:hover { border-color: var(--border2); color: var(--text); background: var(--surface2); }
.fbtn.active { border-color: #4a7abf; color: #7aaddf; background: #1a2a3d; }

/* ── Table ──────────────────────────── */
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }

thead { background: var(--surface2); }
thead th {
  padding: 11px 16px;
  text-align: left;
  font-size: 11px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.1em;
  color: var(--text-dim);
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
tbody tr { border-bottom: 1px solid var(--border); transition: background .08s; }
tbody tr:last-child { border-bottom: none; }
tbody tr:hover { background: var(--surface2); }

td { padding: 12px 16px; vertical-align: top; }

.r-fail td:first-child { border-left: 3px solid var(--fail); }
.r-warn td:first-child { border-left: 3px solid var(--warn); }
.r-pass td:first-child { border-left: 3px solid var(--pass); }
.r-info td:first-child { border-left: 3px solid #555; }

.td-id {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px; color: var(--text-dim);
  white-space: nowrap;
}
.td-title { font-size: 13px; font-weight: 500; color: var(--text-head); }
.td-desc  { font-size: 12px; color: var(--text-dim); max-width: 260px; }
.td-rec   {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11.5px; color: var(--text);
  max-width: 220px; line-height: 1.75;
}
.tag {
  display: inline-block; margin-left: 7px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px; font-weight: 500;
  padding: 1px 7px; border-radius: 3px;
  background: #1a2a3d; color: #7aaddf;
  border: 1px solid #2a3f5a;
  vertical-align: middle;
}

/* ── Severity badges ─────────────────── */
.sev {
  display: inline-block; font-size: 11px; font-weight: 600;
  letter-spacing: 0.07em; text-transform: uppercase;
  padding: 2px 9px; border-radius: 4px;
}
.sev-critical { background:#3a1515; color:#e05050; border:1px solid #5a2222; }
.sev-high     { background:#3a2010; color:#d87040; border:1px solid #5a3418; }
.sev-medium   { background:#352a08; color:#c9a03a; border:1px solid #52400e; }
.sev-low      { background:#102035; color:#5b9ad4; border:1px solid #1e3852; }
.sev-info     { background:#22262e; color:#7f8899; border:1px solid #363c47; }

/* ── Status badges ───────────────────── */
.st {
  display: inline-block; font-size: 11px; font-weight: 600;
  letter-spacing: 0.07em; text-transform: uppercase;
  padding: 2px 9px; border-radius: 4px;
}
.st-pass { background:#1a3326; color:#4caf7d; border:1px solid #2a5240; }
.st-fail { background:#2e1515; color:#e05050; border:1px solid #4a2222; }
.st-warn { background:#2e2205; color:#c9a03a; border:1px solid #4a3808; }
.st-info { background:#22262e; color:#7f8899; border:1px solid #363c47; }

/* ── Footer ──────────────────────────── */
.footer {
  margin-top: 20px; text-align: center;
  font-size: 11px; color: var(--text-dim);
  letter-spacing: 0.06em;
}

/* ── Responsive ──────────────────────── */
@media (max-width: 720px) {
  .cards-row { grid-template-columns: repeat(2,1fr); }
  .header { flex-direction: column; }
}
</style>
</head>
<body>
<div class="page">
"""
        html += f"""
  <!-- HEADER -->
  <div class="header">
    <div class="header-text">
      <div class="header-eyebrow">Security Assessment Report</div>
      <div class="header-title">Apache HTTP Server &mdash; Hardening Audit</div>
      <div class="meta-grid">
        <div class="meta-item">
          <span class="meta-label">Config Path</span>
          <span class="meta-value">{config_display}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Target URL</span>
          <span class="meta-value">{url_display}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Generated</span>
          <span class="meta-value">{now}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">Tool Version</span>
          <span class="meta-value">apache_audit v1.0</span>
        </div>
      </div>
    </div>
    <div class="score-block">
      <div class="score-ring">
        <svg viewBox="0 0 120 120">
          <circle class="ring-bg" cx="60" cy="60" r="{r}"/>
          <circle class="ring-val" cx="60" cy="60" r="{r}"
            style="stroke:{ring_color};stroke-dasharray:{dash:.2f} {gap:.2f}"/>
        </svg>
        <div class="ring-center">
          <div class="ring-pct" style="color:{ring_color}">{pct}</div>
          <div class="ring-sub">Score</div>
        </div>
      </div>
      <div class="grade-pill {grade_cls}">{grade}</div>
    </div>
  </div>

  <!-- STAT CARDS -->
  <div class="cards-row">
    <div class="card c-total">
      <div class="card-num">{len(self.findings)}</div>
      <div class="card-lbl">Total Checks</div>
    </div>
    <div class="card c-pass">
      <div class="card-num">{counts["PASS"]}</div>
      <div class="card-lbl">Passed</div>
    </div>
    <div class="card c-fail">
      <div class="card-num">{counts["FAIL"]}</div>
      <div class="card-lbl">Failed</div>
    </div>
    <div class="card c-warn">
      <div class="card-num">{counts["WARN"]}</div>
      <div class="card-lbl">Warnings</div>
    </div>
  </div>

  <!-- SEVERITY BREAKDOWN -->
  <div class="cards-row">
    <div class="card c-crit">
      <div class="card-num">{sev_fail["CRITICAL"]}</div>
      <div class="card-lbl">Critical</div>
      <div class="card-sub">Remediate immediately</div>
    </div>
    <div class="card c-high">
      <div class="card-num">{sev_fail["HIGH"]}</div>
      <div class="card-lbl">High</div>
      <div class="card-sub">Fix within 48 hours</div>
    </div>
    <div class="card c-med">
      <div class="card-num">{sev_fail["MEDIUM"]}</div>
      <div class="card-lbl">Medium</div>
      <div class="card-sub">Fix within 1 week</div>
    </div>
    <div class="card c-low">
      <div class="card-num">{sev_fail["LOW"]}</div>
      <div class="card-lbl">Low</div>
      <div class="card-sub">Next maintenance window</div>
    </div>
  </div>

  <!-- FINDINGS TABLE -->
  <div class="section">
    <div class="section-head">
      <div class="section-title">Findings &mdash; {len(self.findings)} checks</div>
      <div class="filter-bar">
        <button class="fbtn active" onclick="doFilter(this,'all')">All</button>
        <button class="fbtn" onclick="doFilter(this,'fail')">Failed</button>
        <button class="fbtn" onclick="doFilter(this,'warn')">Warning</button>
        <button class="fbtn" onclick="doFilter(this,'pass')">Passed</button>
      </div>
    </div>
    <div class="table-wrap">
      <table id="tbl">
        <thead>
          <tr>
            <th>ID</th>
            <th>Check</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Description</th>
            <th>Recommendation</th>
          </tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
    </div>
  </div>

  <div class="footer">
    Apache Hardening Audit Tool v1.0 &nbsp;&mdash;&nbsp; {now}
    &nbsp;&mdash;&nbsp; CIS Apache 2.4 Benchmark &middot; OWASP &middot; NIST SP 800-52
  </div>
</div>
<script>
function doFilter(btn, status) {{
  document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('#tbl tbody tr').forEach(tr => {{
    tr.style.display = (status === 'all' || tr.classList.contains('r-' + status)) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

        with open(output_path, 'w', encoding='utf-8') as fh:
            fh.write(html)
        return html


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description='Apache Hardening Audit Tool',
        epilog="""
Examples:
  python apache_audit.py -c demo_apache.conf -o hasil_audit.html
  python apache_audit.py -c /etc/apache2/apache2.conf -o laporan.html
  python apache_audit.py -c /etc/apache2/apache2.conf -u http://myserver.com -o full_report.html
        """
    )
    parser.add_argument('--config', '-c', help='Path to Apache config file')
    parser.add_argument('--url', '-u', help='Target URL for HTTP checks')
    parser.add_argument('--output', '-o', default='apache_audit_report.html',
                        help='Output filename. Use .html for dashboard, .json for raw data (default: apache_audit_report.html)')
    args = parser.parse_args()

    auditor = ApacheAuditor(config_path=args.config, target_url=args.url)
    auditor.run_audit()

    out = args.output
    if out.endswith('.json'):
        auditor.export_json(out)
        print(f"\n  JSON saved : {out}")
    else:
        # Ensure .html extension
        if not out.endswith('.html'):
            out = out + '.html'
        auditor.export_html(out)
        print(f"\n  Report saved : {out}")


if __name__ == "__main__":
    main()
