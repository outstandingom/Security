#!/usr/bin/env python3
"""
paym.py - SAFE Payment Endpoint Detection Tool (Detection Only)
===============================================================

Usage:
    python paym.py "https://www.feepayr.com/FeePayerOnlinePay/Index"

THIS SCRIPT IS FOR **AUTHORIZED TESTING ONLY**.
It performs **non-destructive detection checks** only.

Features:
- Tests for obvious client-side price/amount tampering acceptance
- Checks zero/negative value handling
- Checks quantity manipulation
- Checks basic parameter tampering
- Saves simple JSON report

WARNING:
- Do NOT use on any live system without **explicit written permission**
- Even detection can trigger fraud detection, IP ban, or legal action
- Positive result = **needs manual verification**
- Negative result = **does NOT mean secure**
"""

import requests
import time
import random
import json
import argparse
from urllib.parse import urljoin

# ─── CONFIG ──────────────────────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0",
]

TIMEOUT = 15
DELAY = 1.2

# Simulated tampering scenarios (detection only)
TAMPERING_TESTS = [
    {"name": "Negative amount", "data": {"amount": -500, "fee": 100, "total": -400}},
    {"name": "Zero amount", "data": {"amount": 0, "fee": 0, "total": 0}},
    {"name": "Very low amount", "data": {"amount": 1, "fee": 1, "total": 2}},
    {"name": "Huge amount", "data": {"amount": 999999999, "fee": 999999999, "total": 1999999998}},
    {"name": "Negative quantity", "data": {"quantity": -10, "price": 1000, "total": -10000}},
]

class PaymentSafeDetector:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = requests.Session()
        self.results = []

    def log(self, msg: str, level: str = "INFO"):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        colors = {"DANGER": "\033[91m", "WARNING": "\033[93m", "INFO": "\033[94m", "OK": "\033[92m", "RESET": "\033[0m"}
        print(f"{colors.get(level, '')}[{ts}] [{level}] {msg}{colors['RESET']}")

    def _send(self, data: dict) -> tuple[bool, requests.Response | None, str]:
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            r = self.session.post(self.base_url, json=data, headers=headers, timeout=TIMEOUT)
            return True, r, ""
        except Exception as e:
            return False, None, str(e)

    def run_tests(self):
        self.log(f"SAFE Payment detection started → {self.base_url}")
        self.log("Sending only obviously tampered values (detection only)")

        for test in TAMPERING_TESTS:
            time.sleep(DELAY)
            self.log(f"Testing: {test['name']}")

            success, resp, err = self._send(test["data"])

            result = {
                "scenario": test["name"],
                "data_sent": test["data"],
                "success": success,
                "status": resp.status_code if resp else 0,
                "response_snippet": resp.text[:200] if resp else "",
                "error": err,
                "accepted": False,
                "potential_issue": False
            }

            if not success:
                result["error"] = err
                self.log(f"  Request failed: {err}", "WARNING")
            elif resp.status_code < 400 and ("success" in resp.text.lower() or "processed" in resp.text.lower()):
                result["accepted"] = True
                result["potential_issue"] = True
                self.log("  !!! SERVER ACCEPTED OBVIOUSLY INVALID VALUE !!!", "DANGER")
            else:
                self.log("  Server rejected the invalid value (good behavior)", "OK")

            self.results.append(result)

        self._save_report()

    def _save_report(self):
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": self.base_url,
            "tests_performed": len(TAMPERING_TESTS),
            "potential_issues": sum(1 for r in self.results if r["potential_issue"]),
            "findings": self.results
        }
        with open("payment_detection_report.json", "w") as f:
            json.dump(report, f, indent=4)
        self.log("Report saved → payment_detection_report.json")


def main():
    parser = argparse.ArgumentParser(description="SAFE Payment Endpoint Detection Tool")
    parser.add_argument("url", help="Payment endpoint URL")
    args = parser.parse_args()

    if not args.url.startswith(("http://", "https://")):
        args.url = "https://" + args.url

    detector = PaymentSafeDetector(args.url)
    detector.run_tests()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception as e:
        print(f"\nError: {e}")
