```python
#!/usr/bin/env python3
import requests
import json
import sys
import time
import random
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
]

COMMON_TOKEN_NAMES = [
    'csrf_token', '_csrf', 'CSRFToken', 'csrf-token', 'X-CSRF-Token', 'X-XSRF-Token',
    'authenticity_token', 'anti-csrf', 'xsrf_token', 'csrf'
]

class CSRFValidator:
    def __init__(self, base_url, action_endpoint='/api/action', method='POST', form_page='', token_names=None):
        self.base_url = base_url.rstrip('/')
        self.action_endpoint = action_endpoint
        self.method = method.upper()
        self.form_page = form_page or self.base_url
        self.token_names = token_names or COMMON_TOKEN_NAMES
        self.session = requests.Session()
        self.results = []
        self.token = None
        self.token_location = None
        self.valid_response = None

    def log(self, message, status="INFO"):
        print(f"[{status}] {message}")

    def get_random_user_agent(self):
        return random.choice(USER_AGENTS)

    def fetch_page(self, url):
        try:
            headers = {'User-Agent': self.get_random_user_agent()}
            response = self.session.get(url, headers=headers, timeout=10)
            return response
        except Exception as e:
            self.log(f"Error fetching page: {e}", "ERROR")
            return None

    def extract_token_from_html(self, soup):
        # Hidden input fields
        for name in self.token_names:
            input_tag = soup.find('input', {'name': name, 'type': 'hidden'})
            if input_tag and input_tag.get('value'):
                return input_tag['value'], 'html_form', name
        # Meta tags
        meta_tag = soup.find('meta', {'name': 'csrf-token'})
        if meta_tag and meta_tag.get('content'):
            return meta_tag['content'], 'meta_tag', 'csrf-token'
        return None, None, None

    def extract_token_from_js(self, text):
        # Simple regex for JS variables like var csrf_token = "...";
        for name in self.token_names:
            pattern = r'var\s+{}\s*=\s*["\']([^"\']+)["\']'.format(re.escape(name))
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1), 'js_variable', name
        # Or const csrf = ...
        pattern = r'(var|const|let)\s+(csrf\S*)\s*=\s*["\']([^"\']+)["\']'
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(3), 'js_variable', match.group(2)
        return None, None, None

    def extract_token_from_cookies(self):
        for name in self.token_names:
            token = self.session.cookies.get(name)
            if token:
                return token, 'cookie', name
        return None, None, None

    def extract_token_from_headers(self, response):
        for name in self.token_names:
            token = response.headers.get(name)
            if token:
                return token, 'header', name
        return None, None, None

    def get_csrf_token(self):
        """Attempt to fetch CSRF token from various locations"""
        self.log("Fetching potential form page for CSRF token...")
        response = self.fetch_page(self.form_page)
        if not response:
            return False

        soup = BeautifulSoup(response.text, 'html.parser')

        # Try HTML
        token, location, name = self.extract_token_from_html(soup)
        if token:
            self.log(f"Found token in {location} with name {name}")
            self.token = token
            self.token_location = location
            self.token_name = name
            return True

        # Try JS
        token, location, name = self.extract_token_from_js(response.text)
        if token:
            self.log(f"Found token in {location} with name {name}")
            self.token = token
            self.token_location = location
            self.token_name = name
            return True

        # Try cookies (double submit)
        token, location, name = self.extract_token_from_cookies()
        if token:
            self.log(f"Found token in {location} with name {name}")
            self.token = token
            self.token_location = location
            self.token_name = name
            return True

        # Try headers
        token, location, name = self.extract_token_from_headers(response)
        if token:
            self.log(f"Found token in {location} with name {name}")
            self.token = token
            self.token_location = location
            self.token_name = name
            return True

        self.log("No CSRF token found. Site may not use token-based protection or uses undetected method.", "WARNING")
        return False

    def perform_request(self, data=None, headers=None, include_token=True, token_value=None):
        action_url = urljoin(self.base_url, self.action_endpoint)
        req_headers = {'User-Agent': self.get_random_user_agent()}
        if headers:
            req_headers.update(headers)

        payload = data.copy() if data else {}
        if include_token and self.token_name:
            if self.token_location in ['header', 'custom_header']:
                req_headers[self.token_name] = token_value or self.token
            else:
                payload[self.token_name] = token_value or self.token

        try:
            if self.method == 'POST':
                response = self.session.post(action_url, data=payload, headers=req_headers, timeout=10)
            elif self.method == 'GET':
                params = payload
                response = self.session.get(action_url, params=params, headers=req_headers, timeout=10)
            elif self.method == 'PUT':
                response = self.session.put(action_url, data=payload, headers=req_headers, timeout=10)
            elif self.method == 'DELETE':
                response = self.session.delete(action_url, data=payload, headers=req_headers, timeout=10)
            elif self.method == 'PATCH':
                response = self.session.patch(action_url, data=payload, headers=req_headers, timeout=10)
            else:
                self.log(f"Unsupported method: {self.method}", "ERROR")
                return None
            return response
        except Exception as e:
            self.log(f"Error performing request: {e}", "ERROR")
            return None

    def test_valid_request(self, data):
        self.log("Performing valid request to establish baseline...")
        response = self.perform_request(data=data)
        if response and response.status_code in [200, 201, 204]:
            self.valid_response = {
                'status': response.status_code,
                'content_length': len(response.text),
                'text_snippet': response.text[:200]
            }
            return True
        self.log("Valid request failed. Check endpoint and data.", "ERROR")
        return False

    def is_response_successful(self, response):
        if not self.valid_response or not response:
            return False
        # Compare status, content length, similarity
        if response.status_code != self.valid_response['status']:
            return False
        if abs(len(response.text) - self.valid_response['content_length']) > 50:  # Arbitrary threshold
            return False
        # Simple check if similar
        if self.valid_response['text_snippet'] in response.text:
            return True
        return False

    def test_csrf(self):
        self.log("Testing CSRF protections...")
        if not self.get_csrf_token():
            self.results.append({
                "vulnerability": "CSRF - No Token Detected",
                "details": "Possibly no protection or undetected. Manual review needed. Consider SameSite, Origin checks."
            })
            return True  # Assume vulnerable if no token

        # Assume some test data - customize as needed
        test_data = {"some_key": "test_value"}

        # Valid request baseline
        if not self.test_valid_request(test_data):
            return False

        vulnerable = False

        # Test without token
        self.log("Testing without token...")
        resp_no_token = self.perform_request(data=test_data, include_token=False)
        if self.is_response_successful(resp_no_token):
            self.log("⚠️ Action succeeded without CSRF token!", "WARNING")
            vulnerable = True
            self.results.append({
                "vulnerability": "CSRF - No Token Validation",
                "details": "Request succeeded without token"
            })

        # Test with invalid token
        self.log("Testing with invalid token...")
        invalid_token = self.token + "invalid"
        resp_invalid = self.perform_request(data=test_data, token_value=invalid_token)
        if self.is_response_successful(resp_invalid):
            self.log("⚠️ Action succeeded with invalid CSRF token!", "WARNING")
            vulnerable = True
            self.results.append({
                "vulnerability": "CSRF - Invalid Token Accepted",
                "details": "Request succeeded with modified token"
            })

        # Test token reusability (submit twice with same token)
        self.log("Testing token reusability...")
        resp_reuse = self.perform_request(data=test_data)
        if self.is_response_successful(resp_reuse):
            self.log("⚠️ Token reusable - possible session-fixed token weakness!", "WARNING")
            vulnerable = True
            self.results.append({
                "vulnerability": "CSRF - Reusable Token",
                "details": "Same token worked multiple times - should be per-request"
            })

        # Test wrong Origin/Referer
        self.log("Testing with wrong Origin/Referer...")
        wrong_headers = {
            'Origin': 'http://evil.com',
            'Referer': 'http://evil.com'
        }
        resp_wrong_origin = self.perform_request(data=test_data, headers=wrong_headers)
        if self.is_response_successful(resp_wrong_origin):
            self.log("⚠️ Action succeeded with wrong Origin/Referer!", "WARNING")
            vulnerable = True
            self.results.append({
                "vulnerability": "CSRF - No Origin/Referer Validation",
                "details": "Request from wrong origin succeeded"
            })

        # Note on untestable aspects
        self.log("\nNote: This script cannot fully test browser-enforced protections like SameSite cookies or CORS misconfigs.", "IMPORTANT")
        self.log("For those, use a browser automation tool like Playwright or manual testing with tools like Burp Suite.")
        self.log("Also, for expiration, manually test after delay. For file uploads/JSON/multi-step, customize script.")

        return vulnerable

    def run_csrf_test(self):
        self.log(f"Starting CSRF tests for {self.base_url} (method: {self.method}, action: {self.action_endpoint})")
        self.log("=" * 60)
        vulnerable = self.test_csrf()
        status = "POTENTIAL VULNERABILITIES ⚠️" if vulnerable else "SECURE ✅"
        self.log(f"CSRF: {status}")
        # Summary and report
        self.save_report()

    def save_report(self):
        report = {
            "base_url": self.base_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": self.results
        }
        try:
            with open("csrf_report.json", "w") as f:
                json.dump(report, f, indent=2)
            self.log("Detailed report saved to 'csrf_report.json'")
        except Exception as e:
            self.log(f"Error saving report: {e}", "ERROR")

def main():
    if len(sys.argv) < 2:
        print("Usage: python csrf_test.py <base_url> [action_endpoint] [method] [form_page]")
        sys.exit(1)
    base_url = sys.argv[1]
    action_endpoint = sys.argv[2] if len(sys.argv) > 2 else '/api/action'
    method = sys.argv[3] if len(sys.argv) > 3 else 'POST'
    form_page = sys.argv[4] if len(sys.argv) > 4 else ''
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'https://' + base_url
    validator = CSRFValidator(base_url, action_endpoint, method, form_page)
    validator.run_csrf_test()

if __name__ == "__main__":
    main()
```
