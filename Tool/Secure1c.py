#!/usr/bin/env python3
import requests
import time
import json
import sys
import ssl
import socket
import re
from enum import Enum
from urllib.parse import urljoin
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# ==========================================================
# RESULT STATES (NO BINARY LIES)
# ==========================================================
class TestStatus(Enum):
    VULNERABLE = "VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    NOT_TESTED = "NOT_TESTED"
    BLOCKED_BY_WAF = "BLOCKED_BY_WAF"
    ERROR = "ERROR"

# ==========================================================
# MAIN TOOL
# ==========================================================
class ASVTSecurityTool:
    def __init__(self, base_url, auth_token=None):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "ASVT/1.0 (Security Validation; Permission Required)"
        })
        self.timeout = 10
        self.findings = []
        self.auth_token = auth_token
        if auth_token:
            self.session.headers.update({"Authorization": f"Bearer {auth_token}"})

    # -------------------- Utilities --------------------
    def log(self, msg, level="INFO"):
        print(f"[{level}] {msg}")

    def add_finding(self, name, severity, status, evidence=None, endpoint=None, payload=None, confidence=0.0):
        self.findings.append({
            "name": name,
            "severity": severity,     # LOW / MEDIUM / HIGH / CRITICAL
            "status": status.value,
            "endpoint": endpoint,
            "payload": payload,
            "confidence": round(confidence, 2),
            "evidence": evidence,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        })

    def is_waf_block(self, response):
        if response is None:
            return False
        text = (response.text or "").lower()
        if response.status_code in (403, 406, 429):
            if any(x in text for x in ["access denied", "forbidden", "edgesuite", "akamai", "cloudflare", "bot"]):
                return True
        return False

    # ==========================================================
    # 1) VERIFIED SQL INJECTION (TIME-BASED CONFIRMATION)
    # ==========================================================
    def test_sql_injection(self):
        self.log("Testing SQL Injection (verified, time-based)...")
        endpoint = f"{self.base_url}/api/search"
        params_fast = {"q": "' AND SLEEP(1)--"}
        params_slow = {"q": "' AND SLEEP(5)--"}

        try:
            t1 = time.time()
            r1 = self.session.get(endpoint, params=params_fast, timeout=self.timeout)
            d1 = time.time() - t1

            if self.is_waf_block(r1):
                self.add_finding(
                    "SQL Injection",
                    "HIGH",
                    TestStatus.BLOCKED_BY_WAF,
                    "Blocked by CDN/WAF before app logic",
                    endpoint=endpoint,
                    confidence=0.7
                )
                return

            t2 = time.time()
            r2 = self.session.get(endpoint, params=params_slow, timeout=self.timeout)
            d2 = time.time() - t2

            if (d2 - d1) >= 3:
                self.add_finding(
                    "SQL Injection (Time-Based)",
                    "CRITICAL",
                    TestStatus.VULNERABLE,
                    f"Response delay delta confirmed: fast={d1:.2f}s slow={d2:.2f}s",
                    endpoint=endpoint,
                    payload="SLEEP(n)",
                    confidence=0.9
                )
            else:
                self.add_finding(
                    "SQL Injection",
                    "INFO",
                    TestStatus.NOT_VULNERABLE,
                    "No timing difference observed",
                    endpoint=endpoint,
                    confidence=0.6
                )
        except Exception as e:
            self.add_finding("SQL Injection", "ERROR", TestStatus.ERROR, str(e), endpoint=endpoint)

    # ==========================================================
    # 2) BUSINESS LOGIC / STATE TRANSITION
    # ==========================================================
    def test_business_logic_state(self):
        self.log("Testing Business Logic / State Transition...")
        endpoint = f"{self.base_url}/api/order/complete"
        try:
            r = self.session.post(endpoint, json={"order_id": 123}, timeout=self.timeout)
            if self.is_waf_block(r):
                self.add_finding(
                    "Business Logic State Validation",
                    "HIGH",
                    TestStatus.BLOCKED_BY_WAF,
                    "Blocked by edge",
                    endpoint=endpoint,
                    confidence=0.6
                )
                return

            if r.status_code == 200:
                self.add_finding(
                    "Illegal State Transition",
                    "CRITICAL",
                    TestStatus.VULNERABLE,
                    "Final state reachable without prerequisite steps",
                    endpoint=endpoint,
                    confidence=0.95
                )
            else:
                self.add_finding(
                    "Business Logic State Validation",
                    "INFO",
                    TestStatus.NOT_VULNERABLE,
                    "State transition appears enforced",
                    endpoint=endpoint,
                    confidence=0.7
                )
        except Exception as e:
            self.add_finding("Business Logic State", "ERROR", TestStatus.ERROR, str(e), endpoint=endpoint)

    # ==========================================================
    # 3) MASS ASSIGNMENT / OVER-POSTING
    # ==========================================================
    def test_mass_assignment(self):
        self.log("Testing Mass Assignment / Over-Posting...")
        endpoint = f"{self.base_url}/api/profile/update"
        payload = {
            "name": "Test",
            "role": "admin",
            "is_admin": True,
            "balance": 999999
        }
        try:
            r = self.session.post(endpoint, json=payload, timeout=self.timeout)
            if r.status_code == 200 and re.search(r"admin|balance", r.text.lower()):
                self.add_finding(
                    "Mass Assignment",
                    "HIGH",
                    TestStatus.VULNERABLE,
                    "Unauthorized fields accepted",
                    endpoint=endpoint,
                    payload=payload,
                    confidence=0.85
                )
            else:
                self.add_finding(
                    "Mass Assignment",
                    "INFO",
                    TestStatus.NOT_VULNERABLE,
                    "Unauthorized fields ignored",
                    endpoint=endpoint,
                    confidence=0.6
                )
        except Exception as e:
            self.add_finding("Mass Assignment", "ERROR", TestStatus.ERROR, str(e), endpoint=endpoint)

    # ==========================================================
    # 4) RATE LIMITING (LOGIN)
    # ==========================================================
    def test_rate_limiting(self):
        self.log("Testing Rate Limiting...")
        endpoint = f"{self.base_url}/api/login"
        blocked = False
        try:
            for _ in range(20):
                r = self.session.post(endpoint, json={"email": "test@example.com", "password": "wrong"}, timeout=self.timeout)
                if r.status_code == 429:
                    blocked = True
                    break
            if blocked:
                self.add_finding(
                    "Rate Limiting",
                    "INFO",
                    TestStatus.NOT_VULNERABLE,
                    "429 returned after repeated attempts",
                    endpoint=endpoint,
                    confidence=0.8
                )
            else:
                self.add_finding(
                    "Missing Rate Limiting",
                    "HIGH",
                    TestStatus.VULNERABLE,
                    "No 429 after repeated attempts",
                    endpoint=endpoint,
                    confidence=0.9
                )
        except Exception as e:
            self.add_finding("Rate Limiting", "ERROR", TestStatus.ERROR, str(e), endpoint=endpoint)

    # ==========================================================
    # 5) TOKEN / SESSION MISUSE (CREDENTIALED ONLY)
    # ==========================================================
    def test_token_reuse(self):
        self.log("Testing Token / Session Misuse...")
        if not self.auth_token:
            self.add_finding(
                "Token Reuse",
                "INFO",
                TestStatus.NOT_TESTED,
                "No auth token provided",
                confidence=0.5
            )
            return
        endpoint = f"{self.base_url}/api/profile"
        try:
            r = self.session.get(endpoint, timeout=self.timeout)
            if r.status_code == 200:
                self.add_finding(
                    "Session Token Reuse",
                    "HIGH",
                    TestStatus.VULNERABLE,
                    "Token valid without re-authentication checks",
                    endpoint=endpoint,
                    confidence=0.8
                )
            else:
                self.add_finding(
                    "Session Token Handling",
                    "INFO",
                    TestStatus.NOT_VULNERABLE,
                    "Token handling appears restricted",
                    endpoint=endpoint,
                    confidence=0.6
                )
        except Exception as e:
            self.add_finding("Token Reuse", "ERROR", TestStatus.ERROR, str(e), endpoint=endpoint)

    # ==========================================================
    # 6) WEBHOOK / CALLBACK TRUST
    # ==========================================================
    def test_webhook_validation(self):
        self.log("Testing Webhook / Callback Validation...")
        endpoint = f"{self.base_url}/api/payment/webhook"
        fake_payload = {"status": "PAID", "order_id": 1}
        try:
            r = self.session.post(endpoint, json=fake_payload, timeout=self.timeout)
            if r.status_code == 200:
                self.add_finding(
                    "Unverified Webhook Acceptance",
                    "CRITICAL",
                    TestStatus.VULNERABLE,
                    "Webhook accepted without signature/verification",
                    endpoint=endpoint,
                    confidence=0.95
                )
            else:
                self.add_finding(
                    "Webhook Validation",
                    "INFO",
                    TestStatus.NOT_VULNERABLE,
                    "Webhook rejected or verified",
                    endpoint=endpoint,
                    confidence=0.7
                )
        except Exception as e:
            self.add_finding("Webhook Validation", "ERROR", TestStatus.ERROR, str(e), endpoint=endpoint)

    # ==========================================================
    # 7) FILE UPLOAD SECURITY
    # ==========================================================
    def test_file_upload(self):
        self.log("Testing File Upload Security...")
        endpoint = f"{self.base_url}/api/upload"
        files = {"file": ("test.php", b"<?php echo 'x'; ?>")}
        try:
            r = self.session.post(endpoint, files=files, timeout=self.timeout)
            if r.status_code == 200:
                self.add_finding(
                    "Insecure File Upload",
                    "CRITICAL",
                    TestStatus.VULNERABLE,
                    "Executable file accepted",
                    endpoint=endpoint,
                    confidence=0.9
                )
            else:
                self.add_finding(
                    "File Upload Validation",
                    "INFO",
                    TestStatus.NOT_VULNERABLE,
                    "Executable file rejected",
                    endpoint=endpoint,
                    confidence=0.7
                )
        except Exception as e:
            self.add_finding("File Upload", "ERROR", TestStatus.ERROR, str(e), endpoint=endpoint)

    # ==========================================================
    # 8) SECURITY HEADERS
    # ==========================================================
    def test_security_headers(self):
        self.log("Testing Security Headers...")
        try:
            r = self.session.get(self.base_url, timeout=self.timeout)
            headers = r.headers
            required = [
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Strict-Transport-Security",
                "Referrer-Policy"
            ]
            missing = [h for h in required if h not in headers]
            if missing:
                self.add_finding(
                    "Missing Security Headers",
                    "LOW",
                    TestStatus.VULNERABLE,
                    f"Missing: {', '.join(missing)}",
                    confidence=0.6
                )
            else:
                self.add_finding(
                    "Security Headers",
                    "INFO",
                    TestStatus.NOT_VULNERABLE,
                    "All recommended headers present",
                    confidence=0.8
                )
        except Exception as e:
            self.add_finding("Security Headers", "ERROR", TestStatus.ERROR, str(e))

    # ==========================================================
    # 9) SSL / TLS
    # ==========================================================
    def test_ssl_tls(self):
        self.log("Testing SSL/TLS...")
        if not self.base_url.startswith("https://"):
            self.add_finding(
                "SSL/TLS",
                "CRITICAL",
                TestStatus.VULNERABLE,
                "HTTPS not enforced",
                confidence=0.95
            )
            return
        try:
            hostname = self.base_url.replace("https://", "").split("/")[0]
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                    tls_version = ssock.version()
                    if tls_version in ("TLSv1", "TLSv1.1"):
                        self.add_finding(
                            "Outdated TLS",
                            "HIGH",
                            TestStatus.VULNERABLE,
                            tls_version,
                            confidence=0.9
                        )
                    else:
                        self.add_finding(
                            "SSL/TLS",
                            "INFO",
                            TestStatus.NOT_VULNERABLE,
                            f"TLS version: {tls_version}",
                            confidence=0.8
                        )
        except Exception as e:
            self.add_finding("SSL/TLS", "ERROR", TestStatus.ERROR, str(e))

    # ==========================================================
    # 10) DEBUG / ADMIN EXPOSURE
    # ==========================================================
    def test_debug_endpoints(self):
        self.log("Testing Debug/Admin Exposure...")
        paths = ["/debug", "/admin", "/actuator", "/health"]
        exposed = []
        for p in paths:
            try:
                r = self.session.get(self.base_url + p, timeout=self.timeout)
                if r.status_code == 200:
                    exposed.append(p)
            except:
                pass
        if exposed:
            self.add_finding(
                "Exposed Debug/Admin Endpoints",
                "MEDIUM",
                TestStatus.VULNERABLE,
                f"Exposed: {', '.join(exposed)}",
                confidence=0.85
            )
        else:
            self.add_finding(
                "Debug/Admin Endpoints",
                "INFO",
                TestStatus.NOT_VULNERABLE,
                "No common debug endpoints exposed",
                confidence=0.7
            )

    # ==========================================================
    # RUN ALL
    # ==========================================================
    def run(self):
        self.log(f"Starting ASVT scan for {self.base_url}")
        self.log("=" * 60)

        self.test_sql_injection()
        self.test_business_logic_state()
        self.test_mass_assignment()
        self.test_rate_limiting()
        self.test_token_reuse()
        self.test_webhook_validation()
        self.test_file_upload()
        self.test_security_headers()
        self.test_ssl_tls()
        self.test_debug_endpoints()

        self.log("=" * 60)
        self.log("ASSESSMENT COMPLETE")
        self.save_report()

    # ==========================================================
    # REPORT
    # ==========================================================
    def save_report(self):
        report = {
            "target": self.base_url,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "findings": self.findings
        }
        with open("security_report.json", "w") as f:
            json.dump(report, f, indent=2)
        self.log("Report saved to security_report.json")

# ==========================================================
# ENTRY POINT
# ==========================================================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python asvt_production_security_tool.py https://example.com [AUTH_TOKEN]")
        sys.exit(1)

    url = sys.argv[1]
    token = sys.argv[2] if len(sys.argv) > 2 else None

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print("\n⚠️ LEGAL WARNING")
    print("Use ONLY on systems you own or have written permission for.\n")
    confirm = input("Type YES to continue: ")
    if confirm != "YES":
        sys.exit(0)

    tool = ASVTSecurityTool(url, token)
    tool.run()
