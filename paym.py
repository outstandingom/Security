#!/usr/bin/env python3

import requests
import time
import random
import json
import argparse
import re
from abc import ABC, abstractmethod
from urllib.parse import urljoin
from urllib3.util.retry import Retry

# ─── CONFIG ──────────────────────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0",
]

TIMEOUT = 15
DELAY = (1.5, 4.0)
RETRY_TIMES = 3
RETRY_BACKOFF = 2

# Expanded tampering payloads
TAMPERING_TESTS = [
    {"name": "Negative amount", "data": {"amount": -500, "fee": 100, "total": -400}},
    {"name": "Zero amount", "data": {"amount": 0, "fee": 0, "total": 0}},
    {"name": "Type juggling string amount", "data": {"amount": "100.00", "fee": 100, "total": "200.00"}},
    {"name": "Type juggling int amount", "data": {"amount": 100, "fee": 100, "total": 200}},
    {"name": "Rounding error", "data": {"amount": 0.0000001, "fee": 0.0000001, "total": 0.0000002}},
    {"name": "Array injection", "data": {"amount": [1, 100], "fee": [1, 100], "total": [2, 200]}},
    {"name": "Currency swapping", "data": {"amount": 10, "currency": "JPY", "total": 10}},  # USD vs JPY
    {"name": "Huge amount", "data": {"amount": 999999999, "fee": 999999999, "total": 1999999998}},
    {"name": "Negative quantity", "data": {"quantity": -10, "price": 1000, "total": -10000}},
]

# Payment flow steps (customize as needed)
FLOW_STEPS = [
    {"endpoint": "/init", "data": {"user": "test", "amount": 100}, "desc": "Initialize payment"},
    {"endpoint": "/pay", "data": {"token": "fake_token", "amount": 100}, "desc": "Process payment"},
    {"endpoint": "/callback", "data": {"status": "success", "tx_id": "fake_tx"}, "desc": "Callback webhook"}
]

# Compliance mapping
COMPLIANCE_MAP = {
    "tampering": "PCI DSS 4.0 Req 6.2.4: Parameter tampering | GDPR Art 25: Data protection by design",
    "logic_flaw": "PCI DSS 4.0 Req 6.2.4: Insufficient protection against manipulation | GDPR Art 32: Security of processing",
    "signature_issue": "PCI DSS 4.0 Req 6.2.2: Insecure signatures | GDPR Art 5(1)(f): Integrity/confidentiality"
}

class BaseScanner(ABC):
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
        retry = Retry(total=RETRY_TIMES, backoff_factor=RETRY_BACKOFF)
        adapter = requests.adapters.HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.results = []
        self.csrf_token = None

    def log(self, msg: str, level: str = "INFO"):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        colors = {"DANGER": "\033[91m", "WARNING": "\033[93m", "INFO": "\033[94m", "OK": "\033[92m", "RESET": "\033[0m"}
        print(f"{colors.get(level, '')}[{ts}] [{level}] {msg}{colors['RESET']}")

    @abstractmethod
    def run(self):
        pass

    def get_initial_state(self):
        """Fetch page to grab CSRF tokens and cookies."""
        try:
            r = self.session.get(self.base_url, timeout=TIMEOUT)
            match = re.search(r'(?i)<input.*name=.*(csrf|token).*value="([^"]+)"', r.text)
            if match:
                self.csrf_token = match.group(2)
                self.log(f"CSRF token extracted: {self.csrf_token[:10]}...", "OK")
            return r.status_code == 200
        except Exception as e:
            self.log(f"Initial state fetch failed: {e}", "WARNING")
            return False

class PayloadScanner(BaseScanner):
    def run(self):
        self.log("Running PayloadScanner (tampering detection)...")
        self.get_initial_state()  # Fetch CSRF

        for test in TAMPERING_TESTS:
            time.sleep(random.uniform(*DELAY))
            data = test["data"]
            if self.csrf_token:
                data["csrf_token"] = self.csrf_token  # Include if found

            headers = {"User-Agent": random.choice(USER_AGENTS), "Content-Type": "application/x-www-form-urlencoded"}
            success, resp, err = self._send_post(data, form_urlencoded=True)

            result = {
                "scenario": test["name"],
                "data_sent": data,
                "success": success,
                "status": resp.status_code if resp else 0,
                "response_time": resp.elapsed.total_seconds() if resp else 0,
                "content_length": len(resp.content) if resp else 0,
                "error": err,
                "accepted": False,
                "potential_issue": False,
                "compliance": COMPLIANCE_MAP["tampering"]
            }

            if not success:
                self.log(f"Request failed: {err}", "WARNING")
            elif resp.status_code < 400 and "success" in resp.text.lower():
                result["accepted"] = True
                result["potential_issue"] = True
                self.log(f"!!! Possible tampering accepted: {test['name']} !!!", "DANGER")
            else:
                self.log(f"OK - Rejected: {test['name']}", "OK")

            self.results.append(result)

    def _send_post(self, data: dict, form_urlencoded: bool = False):
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            if form_urlencoded:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                data_str = urlencode(data)
                r = self.session.post(self.base_url, data=data_str, headers=headers, timeout=TIMEOUT)
            else:
                r = self.session.post(self.base_url, json=data, headers=headers, timeout=TIMEOUT)
            return True, r, ""
        except Exception as e:
            return False, None, str(e)

class LogicScanner(BaseScanner):
    def run(self):
        self.log("Running LogicScanner (sequential flow & skip-step testing)...")
        self.get_initial_state()  # CSRF & cookies

        flow_success = True
        for step in FLOW_STEPS:
            time.sleep(random.uniform(*DELAY))
            data = step["data"]
            if self.csrf_token:
                data["csrf_token"] = self.csrf_token

            success, resp, err = self._send_post(data, form_urlencoded=random.choice([True, False]))
            if not success or resp.status_code >= 400:
                self.log(f"Flow break at {step['desc']}: {err or resp.text[:100]}", "WARNING")
                flow_success = False
                break

        # Test skipping steps
        if flow_success:
            self.log("Testing skip-step logic...")
            skip_data = FLOW_STEPS[-1]["data"]  # Jump to last step
            success, resp, err = self._send_post(skip_data)
            if success and resp.status_code < 400:
                self.log("!!! Possible skip-step vulnerability !!!", "DANGER")
                self.results.append({
                    "scenario": "Skip-step",
                    "vulnerability": "Logic bypass",
                    "reason": "Direct access to callback succeeded",
                    "compliance": COMPLIANCE_MAP["logic_flaw"]
                })

class SignatureScanner(BaseScanner):
    def run(self):
        self.log("Running SignatureScanner (hash/signature analysis)...")

        # Assume valid request first to get signature
        valid_data = {"amount": 100, "total": 100}
        success, resp, err = self._send_post(valid_data)
        if not success or resp.status_code >= 400:
            self.log("Cannot get valid signature - skipping", "WARNING")
            return

        sig_match = re.search(r'"(hash|signature|mac)": "([^"]+)"', resp.text)
        if not sig_match:
            self.log("No signature/hash found in response", "WARNING")
            return
        valid_sig = sig_match.group(2)

        # 1. Stripping: Send without signature
        stripped_data = valid_data.copy()
        self.log("Testing signature stripping...")
        success, resp, err = self._send_post(stripped_data)
        if success and resp.status_code < 400:
            self.log("!!! Request accepted without signature !!!", "DANGER")
            self.results.append({
                "scenario": "Signature stripping",
                "vulnerability": "Missing signature validation",
                "compliance": COMPLIANCE_MAP["signature_issue"]
            })

        # 2. Replay: Reuse valid sig on tampered data
        tampered_data = {"amount": 1, "total": 1, "hash": valid_sig}
        self.log("Testing signature replay...")
        success, resp, err = self._send_post(tampered_data)
        if success and resp.status_code < 400:
            self.log("!!! Replay accepted on tampered data !!!", "DANGER")
            self.results.append({
                "scenario": "Signature replay",
                "vulnerability": "Weak signature validation",
                "compliance": COMPLIANCE_MAP["signature_issue"]
            })

    def _send_post(self, data: dict):
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            r = self.session.post(self.base_url, json=data, headers=headers, timeout=TIMEOUT)
            return True, r, ""
        except Exception as e:
            return False, None, str(e)

class PaymentSafeDetector:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.scanners = [
            PayloadScanner(base_url),
            LogicScanner(base_url),
            SignatureScanner(base_url)
        ]
        self.results = []

    def run(self):
        for scanner in self.scanners:
            scanner.run()
            self.results.extend(scanner.results)

        self._generate_report()

    def _generate_report(self):
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": self.base_url,
            "findings": self.results
        }
        with open("payment_detect_report.json", "w") as f:
            json.dump(report, f, indent=4)
        scanner.log("Report saved → payment_detect_report.json", "OK")

def main():
    parser = argparse.ArgumentParser(description="SAFE Payment Vuln Detection Tool")
    parser.add_argument("url", help="Payment endpoint URL")
    args = parser.parse_args()

    if not args.url.startswith(("http://", "https://")):
        args.url = "https://" + args.url

    detector = PaymentSafeDetector(args.url)
    detector.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception as e:
        print(f"\nError: {e}")
