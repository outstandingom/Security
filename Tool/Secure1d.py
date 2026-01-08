#!/usr/bin/env python3
import requests
import time
import json
import sys
import ssl
import socket
from enum import Enum
from urllib.parse import urljoin
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# =========================
# SECURITY STATES
# =========================
class TestStatus(Enum):
    VULNERABLE = "VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    NOT_TESTED = "NOT_TESTED"
    BLOCKED = "BLOCKED_BY_WAF"
    ERROR = "ERROR"

# =========================
# MAIN TOOL
# =========================
class SecurityValidator:

    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.findings = []
        self.timeout = 10

    # ---------- Utility ----------
    def log(self, msg, level="INFO"):
        print(f"[{level}] {msg}")

    def add_finding(self, name, severity, status, evidence=None):
        self.findings.append({
            "name": name,
            "severity": severity,
            "status": status.value,
            "evidence": evidence,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        })

    # =========================
    # EDGE / WAF CHECK
    # =========================
    def detect_waf(self, response):
        text = response.text.lower()
        if "access denied" in text or "edgesuite" in text or response.status_code == 403:
            return True
        return False

    # =========================
    # SQL INJECTION (VERIFIED)
    # =========================
    def test_sql_injection(self):
        self.log("Testing SQL Injection (verified logic)...")
        test_url = f"{self.base_url}/api/search"

        payload_fast = "' AND SLEEP(1)--"
        payload_slow = "' AND SLEEP(5)--"

        try:
            t1 = time.time()
            r1 = self.session.get(test_url, params={"q": payload_fast}, timeout=self.timeout)
            d1 = time.time() - t1

            if self.detect_waf(r1):
                self.add_finding("SQL Injection", "HIGH", TestStatus.BLOCKED,
                                 "Blocked by WAF/CDN")
                return

            t2 = time.time()
            r2 = self.session.get(test_url, params={"q": payload_slow}, timeout=self.timeout)
            d2 = time.time() - t2

            if d2 - d1 >= 3:
                self.add_finding(
                    "SQL Injection (Time-Based)",
                    "CRITICAL",
                    TestStatus.VULNERABLE,
                    f"Delay difference: {d2:.2f}s vs {d1:.2f}s"
                )
            else:
                self.add_finding(
                    "SQL Injection",
                    "INFO",
                    TestStatus.NOT_VULNERABLE,
                    "No timing difference detected"
                )

        except Exception as e:
            self.add_finding("SQL Injection", "ERROR", TestStatus.ERROR, str(e))

    # =========================
    # SECURITY HEADERS
    # =========================
    def test_security_headers(self):
        self.log("Testing Security Headers...")
        try:
            r = self.session.get(self.base_url, timeout=self.timeout)
            headers = r.headers

            missing = []
            required = [
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Strict-Transport-Security",
                "Referrer-Policy"
            ]

            for h in required:
                if h not in headers:
                    missing.append(h)

            if missing:
                self.add_finding(
                    "Missing Security Headers",
                    "LOW",
                    TestStatus.VULNERABLE,
                    f"Missing: {', '.join(missing)}"
                )
            else:
                self.add_finding(
                    "Security Headers",
                    "INFO",
                    TestStatus.NOT_VULNERABLE,
                    "All recommended headers present"
                )

        except Exception as e:
            self.add_finding("Security Headers", "ERROR", TestStatus.ERROR, str(e))

    # =========================
    # SSL / TLS
    # =========================
    def test_ssl_tls(self):
        self.log("Testing SSL/TLS...")
        if not self.base_url.startswith("https://"):
            self.add_finding(
                "SSL/TLS",
                "CRITICAL",
                TestStatus.VULNERABLE,
                "HTTPS not enforced"
            )
            return

        try:
            hostname = self.base_url.replace("https://", "").split("/")[0]
            ctx = ssl.create_default_context()

            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(cert, default_backend())

                    if x509_cert.not_valid_after < x509_cert.not_valid_before:
                        self.add_finding(
                            "SSL Certificate",
                            "CRITICAL",
                            TestStatus.VULNERABLE,
                            "Invalid certificate validity"
                        )
                        return

                    tls_version = ssock.version()
                    if tls_version in ["TLSv1", "TLSv1.1"]:
                        self.add_finding(
                            "Outdated TLS",
                            "HIGH",
                            TestStatus.VULNERABLE,
                            tls_version
                        )
                    else:
                        self.add_finding(
                            "SSL/TLS",
                            "INFO",
                            TestStatus.NOT_VULNERABLE,
                            f"TLS version: {tls_version}"
                        )

        except Exception as e:
            self.add_finding("SSL/TLS", "ERROR", TestStatus.ERROR, str(e))

    # =========================
    # BUSINESS LOGIC / STATE BYPASS
    # =========================
    def test_business_logic_state_bypass(self):
        self.log("Testing Business Logic / State Transition...")
        endpoint = f"{self.base_url}/api/order/complete"

        try:
            r = self.session.post(endpoint, json={"order_id": 123})
            if r.status_code == 200:
                self.add_finding(
                    "Business Logic Flaw – Illegal State Transition",
                    "CRITICAL",
                    TestStatus.VULNERABLE,
                    "Order completed without payment verification"
                )
            else:
                self.add_finding(
                    "Business Logic State Validation",
                    "INFO",
                    TestStatus.NOT_VULNERABLE,
                    "State transition enforced"
                )
        except Exception as e:
            self.add_finding("Business Logic Check", "ERROR", TestStatus.ERROR, str(e))

    # =========================
    # MASS ASSIGNMENT
    # =========================
    def test_mass_assignment(self):
        self.log("Testing Mass Assignment...")
        endpoint = f"{self.base_url}/api/profile/update"

        payload = {
            "name": "Test",
            "role": "admin",
            "is_admin": True,
            "balance": 999999
        }

        try:
            r = self.session.post(endpoint, json=payload)
            if r.status_code == 200 and "admin" in r.text.lower():
                self.add_finding(
                    "Mass Assignment Vulnerability",
                    "HIGH",
                    TestStatus.VULNERABLE,
                    "Unauthorized fields accepted"
                )
            else:
                self.add_finding(
                    "Mass Assignment Protection",
                    "INFO",
                    TestStatus.NOT_VULNERABLE,
                    "Unauthorized fields ignored"
                )
        except Exception as e:
            self.add_finding("Mass Assignment", "ERROR", TestStatus.ERROR, str(e))

    # =========================
    # RATE LIMITING
    # =========================
    def test_rate_limiting(self):
        self.log("Testing Rate Limiting...")
        endpoint = f"{self.base_url}/api/login"
        blocked = False

        try:
            for _ in range(30):
                r = self.session.post(endpoint, json={
                    "email": "test@example.com",
                    "password": "wrong"
                }, timeout=self.timeout)
                if r.status_code == 429:
                    blocked = True
                    break

            if not blocked:
                self.add_finding(
                    "Missing Rate Limiting",
                    "HIGH",
                    TestStatus.VULNERABLE,
                    "No 429 after repeated attempts"
                )
            else:
                self.add_finding(
                    "Rate Limiting",
                    "INFO",
                    TestStatus.NOT_VULNERABLE,
                    "Brute-force blocked"
                )
        except Exception as e:
            self.add_finding("Rate Limiting", "ERROR", TestStatus.ERROR, str(e))

    # =========================
    # TOKEN REUSE
    # =========================
    def test_token_reuse(self):
        self.log("Testing Token Reuse...")
        if not self.session.headers.get("Authorization"):
            self.add_finding(
                "Session Token Reuse",
                "INFO",
                TestStatus.NOT_TESTED,
                "No Authorization header present"
            )
            return

        try:
            r = self.session.get(f"{self.base_url}/api/profile", timeout=self.timeout)
            if r.status_code == 200:
                self.add_finding(
                    "Session Token Reuse",
                    "HIGH",
                    TestStatus.VULNERABLE,
                    "Token valid without re-authentication"
                )
            else:
                self.add_finding(
                    "Session Token Validation",
                    "INFO",
                    TestStatus.NOT_VULNERABLE,
                    "Token requires re-authentication"
                )
        except Exception as e:
            self.add_finding("Token Reuse", "ERROR", TestStatus.ERROR, str(e))

    # =========================
    # FILE UPLOAD
    # =========================
    def test_file_upload(self):
        self.log("Testing File Upload Security...")
        endpoint = f"{self.base_url}/api/upload"

        try:
            files = {"file": ("shell.php", b"<?php echo 1; ?>")}
            r = self.session.post(endpoint, files=files, timeout=self.timeout)

            if r.status_code == 200:
                self.add_finding(
                    "Insecure File Upload",
                    "CRITICAL",
                    TestStatus.VULNERABLE,
                    "Executable file accepted"
                )
            else:
                self.add_finding(
                    "File Upload Security",
                    "INFO",
                    TestStatus.NOT_VULNERABLE,
                    "Executable file rejected"
                )
        except Exception as e:
            self.add_finding("File Upload", "ERROR", TestStatus.ERROR, str(e))

    # =========================
    # WEBHOOK VALIDATION
    # =========================
    def test_webhook_validation(self):
        self.log("Testing Webhook Signature Validation...")
        endpoint = f"{self.base_url}/api/payment/webhook"

        try:
            fake_payload = {"status": "PAID", "order_id": 1}
            r = self.session.post(endpoint, json=fake_payload, timeout=self.timeout)

            if r.status_code == 200:
                self.add_finding(
                    "Unverified Webhook Acceptance",
                    "CRITICAL",
                    TestStatus.VULNERABLE,
                    "Webhook accepted without signature"
                )
            else:
                self.add_finding(
                    "Webhook Signature Validation",
                    "INFO",
                    TestStatus.NOT_VULNERABLE,
                    "Webhook requires validation"
                )
        except Exception as e:
            self.add_finding("Webhook Validation", "ERROR", TestStatus.ERROR, str(e))

    # =========================
    # OBJECT ENUMERATION
    # =========================
    def test_object_enumeration(self):
        self.log("Testing API Object Enumeration...")
        endpoint = f"{self.base_url}/api/invoices/"
        found = False

        try:
            for i in range(1, 10):
                r = self.session.get(endpoint + str(i), timeout=self.timeout)
                if r.status_code == 200:
                    found = True
                    self.add_finding(
                        "Object Enumeration",
                        "HIGH",
                        TestStatus.VULNERABLE,
                        f"Accessed object ID {i}"
                    )
                    break
            
            if not found:
                self.add_finding(
                    "Object Enumeration Protection",
                    "INFO",
                    TestStatus.NOT_VULNERABLE,
                    "No sequential object access detected"
                )
        except Exception as e:
            self.add_finding("Object Enumeration", "ERROR", TestStatus.ERROR, str(e))

    # =========================
    # DEBUG ENDPOINTS
    # =========================
    def test_debug_endpoints(self):
        self.log("Testing Debug / Admin Endpoints...")
        paths = ["/debug", "/admin", "/actuator", "/health", "/env", "/metrics"]
        exposed = []

        try:
            for p in paths:
                r = self.session.get(self.base_url + p, timeout=self.timeout)
                if r.status_code == 200:
                    exposed.append(p)

            if exposed:
                self.add_finding(
                    "Exposed Debug Endpoint",
                    "MEDIUM",
                    TestStatus.VULNERABLE,
                    f"Found: {', '.join(exposed)}"
                )
            else:
                self.add_finding(
                    "Debug Endpoint Security",
                    "INFO",
                    TestStatus.NOT_VULNERABLE,
                    "No exposed debug endpoints found"
                )
        except Exception as e:
            self.add_finding("Debug Endpoints", "ERROR", TestStatus.ERROR, str(e))

    # =========================
    # RUN ALL TESTS
    # =========================
    def run(self):
        self.log(f"Starting validation for {self.base_url}")
        self.log("=" * 60)

        # Core tests
        self.test_sql_injection()
        self.test_security_headers()
        self.test_ssl_tls()
        
        # API/Logic tests
        self.test_business_logic_state_bypass()
        self.test_mass_assignment()
        self.test_rate_limiting()
        self.test_token_reuse()
        self.test_file_upload()
        self.test_webhook_validation()
        self.test_object_enumeration()
        self.test_debug_endpoints()

        self.log("=" * 60)
        self.log("ASSESSMENT COMPLETE")

        self.save_report()

    # =========================
    # REPORT
    # =========================
    def save_report(self):
        report = {
            "target": self.base_url,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "findings": self.findings
        }

        with open("security_report.json", "w") as f:
            json.dump(report, f, indent=2)

        self.log("Report saved to security_report.json")

# =========================
# ENTRY POINT
# =========================
if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python asvt_security_tool.py https://example.com")
        sys.exit(1)

    url = sys.argv[1]
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print("\n⚠️ LEGAL WARNING")
    print("Use ONLY on systems you own or have written permission for.\n")

    confirm = input("Type YES to continue: ")
    if confirm != "YES":
        sys.exit(0)

    tool = SecurityValidator(url)
    tool.run()
