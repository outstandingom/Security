```python
🧪 What happens when you do this right

If you do:

Permission proof ✔

Scope control ✔

Throttling ✔

Clear disclaimers ✔

Then your SaaS becomes:

✅ Legit
✅ Sellable
✅ Insurable (important later)
✅ Acceptable for enterprises'''
#!/usr/bin/env python3
import requests
import json
import sys
import time
import random
import argparse
import re

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
]

class SecurityTester:
    def __init__(self, base_url, user1_email=None, user1_password=None, user2_email=None, user2_password=None,
                 register_endpoint='/api/register', login_endpoint='/api/login', profile_endpoint='/api/profile',
                 profile_id_template='/api/profile/{id}', logout_endpoint='/api/logout',
                 admin_endpoint='/api/admin', id_param='id', use_existing=False):
        self.base_url = base_url.rstrip('/')
        self.user1_email = user1_email or f"test1_{random.randint(1000,9999)}@example.com"
        self.user2_email = user2_email or f"test2_{random.randint(1000,9999)}@example.com"
        self.user1_password = user1_password or "Test123!"
        self.user2_password = user2_password or "Test123!"
        self.register_endpoint = register_endpoint
        self.login_endpoint = login_endpoint
        self.profile_endpoint = profile_endpoint
        self.profile_id_template = profile_id_template
        self.logout_endpoint = logout_endpoint
        self.admin_endpoint = admin_endpoint
        self.id_param = id_param
        self.use_existing = use_existing  # Flag to use existing users without registration
        self.session = requests.Session()
        self.results = []
        self.user1_token = None
        self.user2_token = None
        self.user1_id = None
        self.user2_id = None
        self.additional_endpoints = []  # To store additionally discovered endpoints for broader testing

    def log(self, message, status="INFO"):
        print(f"[{status}] {message}")

    def get_random_user_agent(self):
        return random.choice(USER_AGENTS)

    def discover_openapi(self):
        """Attempt to discover and parse OpenAPI spec from common locations"""
        suffixes = ['/openapi.json', '/swagger.json', '/v2/api-docs', '/api/openapi.json', '/docs/openapi.json']
        for suffix in suffixes:
            url = self.base_url + suffix
            try:
                headers = {'User-Agent': self.get_random_user_agent()}
                r = requests.get(url, headers=headers, timeout=5)
                if r.status_code == 200:
                    try:
                        data = r.json()
                        if 'openapi' in data or 'swagger' in data:
                            self.discover_endpoints(data)
                            self.log(f"Discovered and parsed OpenAPI at {url}")
                            return True
                    except:
                        pass
            except:
                pass
        self.log("No OpenAPI spec discovered in common locations", "WARNING")
        return False

    def discover_endpoints(self, openapi_data):
        """Heuristically map endpoints from OpenAPI data and collect additional endpoints"""
        paths = openapi_data.get('paths', {})
        for path, methods in paths.items():
            lower_path = path.lower()
            if 'post' in methods:
                if any(k in lower_path for k in ['register', 'signup', 'createuser', 'user/create']):
                    self.register_endpoint = path
                    self.log(f"Mapped register_endpoint to {path}")
                elif any(k in lower_path for k in ['login', 'signin', 'authenticate', 'auth/login']):
                    self.login_endpoint = path
                    self.log(f"Mapped login_endpoint to {path}")
                elif any(k in lower_path for k in ['logout', 'signout', 'auth/logout']):
                    self.logout_endpoint = path
                    self.log(f"Mapped logout_endpoint to {path}")
                else:
                    self.additional_endpoints.append((path, 'post'))
            if 'get' in methods:
                if any(k in lower_path for k in ['profile', 'user', 'me', 'account']) and '{' not in path:
                    self.profile_endpoint = path
                    self.log(f"Mapped profile_endpoint to {path}")
                elif 'admin' in lower_path:
                    self.admin_endpoint = path
                    self.log(f"Mapped admin_endpoint to {path}")
                elif '{' in path and any(k in lower_path for k in ['profile', 'user', 'account']):
                    self.profile_id_template = path
                    self.log(f"Mapped profile_id_template to {path}")
                    match = re.search(r'{([^}]+)}', path)
                    if match:
                        self.id_param = match.group(1)
                        self.log(f"Detected id_param as {self.id_param}")
                else:
                    self.additional_endpoints.append((path, 'get'))
            # Add other methods if relevant
            if 'put' in methods or 'delete' in methods:
                self.additional_endpoints.append((path, 'put' if 'put' in methods else 'delete'))

    def register_user(self, email, password, extra_payload=None):
        """Register a new user"""
        if self.use_existing:
            self.log("Skipping registration as --use-existing flag is set", "INFO")
            return None
        endpoint = self.base_url + self.register_endpoint
        try:
            payload = {"email": email, "password": password}
            if extra_payload:
                payload.update(extra_payload)
            headers = {'User-Agent': self.get_random_user_agent()}
            time.sleep(random.uniform(0.5, 2))  # Jitter for WAF evasion
            response = self.session.post(endpoint, json=payload, headers=headers, timeout=10)
            return response
        except Exception as e:
            self.log(f"Error registering user {email} at {endpoint}: {e}", "ERROR")
            return None

    def login_user(self, email, password):
        """Login a user and return token"""
        endpoint = self.base_url + self.login_endpoint
        try:
            payload = {"email": email, "password": password}
            headers = {'User-Agent': self.get_random_user_agent()}
            time.sleep(random.uniform(0.5, 2))
            response = self.session.post(endpoint, json=payload, headers=headers, timeout=10)
            if response.status_code in [200, 201]:
                try:
                    data = response.json()
                    possible_token_keys = ['token', 'access_token', 'jwt', 'session_id']
                    for key in possible_token_keys:
                        if key in data:
                            return data[key]
                except:
                    pass
            self.log(f"Login failed for {email}: {response.status_code} {response.text[:100]}", "WARNING")
            return None
        except Exception as e:
            self.log(f"Error logging in user {email} at {endpoint}: {e}", "ERROR")
            return None

    def get_profile(self, token, user_id=None):
        """Get profile, optionally for a specific user_id"""
        if user_id:
            endpoint = self.base_url + self.profile_id_template.replace('{' + self.id_param + '}', str(user_id))
        else:
            endpoint = self.base_url + self.profile_endpoint
        try:
            headers = {
                'User-Agent': self.get_random_user_agent(),
                'Authorization': f"Bearer {token}"
            }
            time.sleep(random.uniform(0.5, 2))
            response = self.session.get(endpoint, headers=headers, timeout=10)
            return response
        except Exception as e:
            self.log(f"Error getting profile at {endpoint}: {e}", "ERROR")
            return None

    def extract_user_id(self, response):
        """Extract user ID from profile response"""
        if response and response.status_code == 200:
            try:
                data = response.json()
                possible_keys = ['id', 'user_id', 'uuid', 'userId', 'UID', 'accountId']
                for key in possible_keys:
                    if key in data:
                        return data[key]
            except:
                pass
        return None

    def test_idor_authorization(self):
        """Test for IDOR / Authorization issues"""
        if not self.user1_id or not self.profile_id_template:
            self.log("Skipping IDOR test: Missing user ID or profile ID template", "WARNING")
            return False
        self.log("Testing IDOR / Authorization...")
        vulnerable = False
        response = self.get_profile(self.user2_token, self.user1_id)
        if not response:
            return False
        context = {
            "auth_required": True,
            "public_endpoint": False,
            "user_controlled_input": True
        }
        finding_id = f"AC-{len(self.results) + 1}"
        if response.status_code == 200:
            try:
                data = response.json()
                if "email" in data and data["email"] == self.user1_email:
                    self.log("⚠️ Potential IDOR vulnerability: User2 can access User1's profile!", "WARNING")
                    vulnerable = True
                    self.results.append({
                        "finding_id": finding_id,
                        "vulnerability": "IDOR / Broken Authorization",
                        "endpoint": self.profile_id_template.replace('{' + self.id_param + '}', str(self.user1_id)),
                        "details": "User2 accessed User1's private data",
                        "context": context,
                        "status": "NOT_CONFIRMED"
                    })
            except:
                pass
        elif response.status_code == 404:
            self.log("Profile ID endpoint returned 404, may not exist", "INFO")
        # Additional IDOR test on discovered endpoints
        for path, method in self.additional_endpoints:
            if '{' in path and self.id_param in path:
                test_endpoint = self.base_url + path.replace('{' + self.id_param + '}', str(self.user1_id))
                try:
                    headers = {
                        'User-Agent': self.get_random_user_agent(),
                        'Authorization': f"Bearer {self.user2_token}"
                    }
                    if method == 'get':
                        resp = self.session.get(test_endpoint, headers=headers, timeout=10)
                    elif method == 'post':
                        resp = self.session.post(test_endpoint, headers=headers, timeout=10)
                    # Check if access granted
                    if resp.status_code == 200:
                        self.log(f"⚠️ Potential IDOR on additional endpoint {path}", "WARNING")
                        vulnerable = True
                        self.results.append({
                            "finding_id": f"AC-{len(self.results) + 1}",
                            "vulnerability": "IDOR / Broken Authorization",
                            "endpoint": path,
                            "details": "User2 accessed resource with User1's ID on additional endpoint",
                            "context": context,
                            "status": "NOT_CONFIRMED"
                        })
                except:
                    pass
        return vulnerable

    def test_session_token_misuse(self):
        """Test for session / token misuse (e.g., no revocation)"""
        self.log("Testing Session / Token Misuse...")
        vulnerable = False
        endpoint = self.base_url + self.logout_endpoint
        try:
            headers = {
                'User-Agent': self.get_random_user_agent(),
                'Authorization': f"Bearer {self.user1_token}"
            }
            time.sleep(random.uniform(0.5, 2))
            logout_response = self.session.post(endpoint, headers=headers, timeout=10)
            if logout_response.status_code not in [200, 204, 401]:
                self.log(f"Logout endpoint {self.logout_endpoint} may not exist or failed ({logout_response.status_code}), skipping test", "WARNING")
                return False
        except:
            self.log(f"Error accessing logout endpoint {self.logout_endpoint}, skipping test", "ERROR")
            return False

        # Try to access profile with "revoked" token
        response = self.get_profile(self.user1_token)
        if not response:
            return False
        context = {
            "auth_required": True,
            "public_endpoint": False,
            "user_controlled_input": False
        }
        finding_id = f"AC-{len(self.results) + 1}"
        if response.status_code == 200:
            self.log("⚠️ Potential Session Misuse: Token still valid after logout!", "WARNING")
            vulnerable = True
            self.results.append({
                "finding_id": finding_id,
                "vulnerability": "Session / Token Misuse",
                "endpoint": self.profile_endpoint,
                "details": "Token usable after logout",
                "context": context,
                "status": "NOT_CONFIRMED"
            })
        return vulnerable

    def test_admin_exposure(self):
        """Test for admin endpoint exposure"""
        self.log("Testing Admin Exposure...")
        vulnerable = False
        endpoint = self.base_url + self.admin_endpoint
        try:
            headers = {
                'User-Agent': self.get_random_user_agent(),
                'Authorization': f"Bearer {self.user2_token}"
            }
            time.sleep(random.uniform(0.5, 2))
            response = self.session.get(endpoint, headers=headers, timeout=10)
            context = {
                "auth_required": True,
                "public_endpoint": False,
                "user_controlled_input": False
            }
            finding_id = f"AC-{len(self.results) + 1}"
            if response.status_code == 200:
                self.log("⚠️ Potential Admin Exposure: Normal user can access admin endpoint!", "WARNING")
                vulnerable = True
                self.results.append({
                    "finding_id": finding_id,
                    "vulnerability": "Admin Exposure",
                    "endpoint": self.admin_endpoint,
                    "details": "Accessible without admin privileges",
                    "context": context,
                    "status": "NOT_CONFIRMED"
                })
            elif response.status_code == 404:
                self.log("Admin endpoint returned 404, may not exist", "INFO")
        except Exception as e:
            self.log(f"Error testing admin exposure at {endpoint}: {e}", "ERROR")
        return vulnerable

    def test_mass_assignment(self):
        """Test for mass assignment vulnerability"""
        if self.use_existing:
            self.log("Skipping Mass Assignment test as using existing users (cannot register new)", "INFO")
            return False
        self.log("Testing Mass Assignment...")
        vulnerable = False
        test_email_mass = f"mass_{random.randint(1000,9999)}@example.com"
        extra_payload = {"role": "admin", "is_admin": True, "admin": True, "privileges": "admin", "is_superuser": True}
        reg_response = self.register_user(test_email_mass, "Test123!", extra_payload)
        if not reg_response or reg_response.status_code not in [200, 201]:
            self.log("Failed to register for mass assignment test", "ERROR")
            return False

        token_mass = self.login_user(test_email_mass, "Test123!")
        if not token_mass:
            self.log("Failed to login for mass assignment test", "ERROR")
            return False

        profile_response = self.get_profile(token_mass)
        if not profile_response:
            return False
        context = {
            "auth_required": False,
            "public_endpoint": True,
            "user_controlled_input": True
        }
        finding_id = f"AC-{len(self.results) + 1}"
        if profile_response.status_code == 200:
            try:
                data = profile_response.json()
                privileged_fields = ["role", "is_admin", "admin", "privileges", "is_superuser"]
                for field in privileged_fields:
                    if data.get(field) in ["admin", True]:
                        self.log(f"⚠️ Potential Mass Assignment: Privileged field '{field}' was assigned!", "WARNING")
                        vulnerable = True
                        self.results.append({
                            "finding_id": finding_id,
                            "vulnerability": "Mass Assignment",
                            "endpoint": self.register_endpoint,
                            "details": f"Unauthorized field '{field}' bound to object",
                            "context": context,
                            "status": "NOT_CONFIRMED"
                        })
                        break
            except:
                pass
        return vulnerable

    def test_rate_limiting(self):
        """Test for rate limiting by sending multiple requests"""
        self.log("Testing Rate Limiting...")
        vulnerable = False
        max_attempts = 20  # Safe number to avoid abuse
        failed_logins = 0
        endpoint = self.base_url + self.login_endpoint
        # Use a generic email if no users created
        test_email = self.user1_email if self.user1_email else "test@example.com"

        for i in range(max_attempts):
            time.sleep(random.uniform(1, 5))  # Increased jitter for better evasion
            login_response = self.perform_normal_request(endpoint, {"email": test_email, "password": "wrongpass" + str(i)})
            if login_response:
                if login_response.status_code == 429:  # Too Many Requests
                    self.log("Rate limiting detected (429 status)", "INFO")
                    return False
                resp_text = login_response.text.lower()
                if any(keyword in resp_text for keyword in ["rate limit", "too many", "slow down", "try again later"]):
                    self.log("Rate limiting detected in response body", "INFO")
                    return False
            failed_logins += 1

        if failed_logins == max_attempts:
            self.log("⚠️ No rate limiting detected after multiple failed attempts!", "WARNING")
            vulnerable = True
            context = {
                "auth_required": False,
                "public_endpoint": True,
                "user_controlled_input": True
            }
            finding_id = f"AC-{len(self.results) + 1}"
            self.results.append({
                "finding_id": finding_id,
                "vulnerability": "Missing Rate Limiting",
                "endpoint": self.login_endpoint,
                "details": f"No limiting after {max_attempts} attempts",
                "context": context,
                "status": "NOT_CONFIRMED"
            })
        return vulnerable

    def perform_normal_request(self, endpoint, data):
        """Perform a normal request"""
        try:
            headers = {'User-Agent': self.get_random_user_agent()}
            response = self.session.post(endpoint, json=data, headers=headers, timeout=10)
            return response
        except Exception:
            return None

    def setup_users(self):
        """Setup two test users - register if not using existing, always attempt login"""
        self.log("Setting up test users...")
        setup_success = True

        # User1
        if not self.use_existing:
            reg1 = self.register_user(self.user1_email, self.user1_password)
            if not reg1 or reg1.status_code not in [200, 201]:
                self.log(f"Failed to register user1 at {self.register_endpoint}. Falling back to login-only mode.", "WARNING")
                self.use_existing = True  # Fallback to existing mode if registration fails

        self.user1_token = self.login_user(self.user1_email, self.user1_password)
        if not self.user1_token:
            self.log(f"Failed to login user1 at {self.login_endpoint}", "ERROR")
            setup_success = False

        if self.user1_token:
            profile1 = self.get_profile(self.user1_token)
            if not profile1 or profile1.status_code != 200:
                self.log(f"Failed to get user1 profile at {self.profile_endpoint}", "WARNING")
            else:
                self.user1_id = self.extract_user_id(profile1)
                if not self.user1_id:
                    self.log("Failed to extract user1 ID from profile response", "WARNING")

        # User2
        if not self.use_existing:
            reg2 = self.register_user(self.user2_email, self.user2_password)
            if not reg2 or reg2.status_code not in [200, 201]:
                self.log(f"Failed to register user2 at {self.register_endpoint}. Falling back to login-only mode.", "WARNING")
                self.use_existing = True

        self.user2_token = self.login_user(self.user2_email, self.user2_password)
        if not self.user2_token:
            self.log(f"Failed to login user2 at {self.login_endpoint}", "ERROR")
            setup_success = False

        if self.user2_token:
            profile2 = self.get_profile(self.user2_token)
            if not profile2 or profile2.status_code != 200:
                self.log(f"Failed to get user2 profile at {self.profile_endpoint}", "WARNING")
            else:
                self.user2_id = self.extract_user_id(profile2)
                if not self.user2_id:
                    self.log("Failed to extract user2 ID from profile response", "WARNING")

        if not setup_success:
            self.log("User setup partially failed. Some tests will be skipped.", "WARNING")
        return setup_success

    def run_access_control_test(self):
        """Run the access control integrity test"""
        self.log(f"Starting Access Control Integrity tests for {self.base_url}")
        self.log("=" * 60)
        self.log(f"Using endpoints: register={self.register_endpoint}, login={self.login_endpoint}, "
                 f"profile={self.profile_endpoint}, profile_id={self.profile_id_template}, "
                 f"logout={self.logout_endpoint}, admin={self.admin_endpoint}")
        self.log("Note: This is a black-box test and does not understand business logic. "
                 "It cannot detect conditional auth bugs, role hierarchies, or logic flaws. "
                 "It may produce false negatives for complex vulnerabilities. "
                 "For deeper analysis, use white-box testing, source code review, or manual pentesting.")
        self.log("Warning: This tool is not audit-grade and may miss vulnerabilities or produce false positives. "
                 "It is easy for WAFs to block and carries legal risks if used without permission.")
        if self.use_existing:
            self.log("Using existing users mode: Skipping registration and mass assignment test.", "INFO")
        else:
            self.log("Attempting to register new users. If fails, falls back to login-only.", "INFO")

        setup_success = self.setup_users()
        if not setup_success and not (self.user1_token or self.user2_token):
            self.log("Critical: No users could be set up. Only running independent tests like rate limiting.", "ERROR")

        vulnerable = False
        if self.user1_token and self.user2_token and self.user1_id and self.user2_id:
            if self.test_idor_authorization():
                vulnerable = True
            if self.test_session_token_misuse():
                vulnerable = True
            if self.test_admin_exposure():
                vulnerable = True
        else:
            self.log("Skipping user-dependent tests (IDOR, session misuse, admin exposure) due to setup issues.", "WARNING")

        if not self.use_existing:
            if self.test_mass_assignment():
                vulnerable = True
        else:
            self.log("Skipping mass assignment as using existing users.", "INFO")

        if self.test_rate_limiting():
            vulnerable = True

        status = "POTENTIAL VULNERABILITIES ⚠️" if vulnerable else "SECURE ✅"
        self.log(f"Access Control Integrity: {status}")
        self.log("Note: Results may have false negatives due to limited coverage and black-box nature.")

        # Print summary
        self.log("\n" + "=" * 60)
        self.log("ACCESS CONTROL INTEGRITY TEST SUMMARY")
        self.log("=" * 60)
        if vulnerable:
            self.log("⚠️ POTENTIAL VULNERABILITIES FOUND - REQUIRES MANUAL CONFIRMATION", "WARNING")
        else:
            self.log("✅ No vulnerabilities found! (But may miss some due to limitations)")

        # Save detailed report
        self.save_report()

        # Perform analysis
        self.analyze_with_rules()

    def save_report(self):
        """Save detailed vulnerability report"""
        report = {
            "base_url": self.base_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "endpoints_used": {
                "register": self.register_endpoint,
                "login": self.login_endpoint,
                "profile": self.profile_endpoint,
                "profile_id": self.profile_id_template,
                "logout": self.logout_endpoint,
                "admin": self.admin_endpoint
            },
            "additional_endpoints": self.additional_endpoints,
            "use_existing": self.use_existing,
            "vulnerabilities": self.results
        }
        try:
            with open("access_control_report.json", "w") as f:
                json.dump(report, f, indent=2)
            self.log("Detailed report saved to 'access_control_report.json'")
        except Exception as e:
            self.log(f"Error saving report: {e}", "ERROR")

    def analyze_with_rules(self):
        """Perform rule-based analysis on findings for suggestions and confirmations"""
        self.log("Performing rule-based analysis on findings...")
        try:
            with open("access_control_report.json") as f:
                report = json.load(f)
            analysis_results = self.analyze_findings(report["vulnerabilities"])
            with open("analysis.json", "w") as f:
                json.dump(analysis_results, f, indent=2)
            self.log("Analysis saved to 'analysis.json'")
            # Print analysis results summary
            for result in analysis_results:
                self.log(f"Finding {result['finding_id']}: {result['vulnerability']}", "ANALYSIS")
                self.log(f"Confirmed: {'Yes' if result['confirmed'] else 'No'}", "ANALYSIS")
                self.log(f"Why: {result['why']}", "ANALYSIS")
                self.log(f"What: {result['what']}", "ANALYSIS")
                self.log(f"How: {result['how']}", "ANALYSIS")
                self.log("Suggestions:", "ANALYSIS")
                for sug in result['suggestions']:
                    self.log(f"- {sug}", "ANALYSIS")
                self.log("")
        except Exception as e:
            self.log(f"Error in analysis: {e}", "ERROR")

    def analyze_findings(self, findings):
        """Rule-based analysis function with logic for access control types"""
        suggestion_map = {
            "IDOR / Broken Authorization": {
                "suggestions": ["Implement proper access controls", "Use indirect references or GUIDs", "Validate user ownership on every request", "Use RBAC frameworks", "Consider attribute-based access control (ABAC) for complex logic"],
                "why": "The application allows one user to access another's resources directly, potentially exposing sensitive data. This could be due to missing checks in business logic.",
                "what": "User2 retrieved User1's profile data using direct ID reference.",
                "how": "An attacker can guess or enumerate IDs to access unauthorized data, leading to data breaches. In complex systems, this might involve second-order issues.",
                "confirmed": False,  # Changed to False to encourage manual confirmation
                "risk_level": "High",
                "potential_false_negative": "May miss IDOR in non-profile endpoints or with complex IDs."
            },
            "Session / Token Misuse": {
                "suggestions": ["Implement token revocation on logout", "Use short-lived tokens with refresh", "Validate tokens server-side on every request", "Use secure session management libraries", "Monitor for token reuse patterns"],
                "why": "Sessions or tokens remain valid after actions that should invalidate them, like logout.",
                "what": "Token still usable after logout attempt.",
                "how": "Attackers can continue using stolen or hijacked tokens even after user logs out.",
                "confirmed": False,
                "risk_level": "Medium",
                "potential_false_negative": "May not detect misuse in distributed systems or with custom token handling."
            },
            "Admin Exposure": {
                "suggestions": ["Implement Role-based access control (RBAC)", "Hide admin endpoints from non-admins", "Use IP whitelisting or VPN for admin access", "Regularly audit admin permissions", "Use multi-factor auth for admin"],
                "why": "Administrative functionalities are exposed to non-privileged users.",
                "what": "Normal user accessed /api/admin endpoint successfully.",
                "how": "Attackers can exploit admin features without proper privileges, leading to full system compromise.",
                "confirmed": False,
                "risk_level": "Critical",
                "potential_false_negative": "May miss hidden admin features or those behind feature flags."
            },
            "Mass Assignment": {
                "suggestions": ["Whitelist allowed fields in binding", "Use Data Transfer Objects (DTOs)", "Avoid auto-binding sensitive fields like roles", "Validate input against expected schema", "Use explicit property setting"],
                "why": "Application binds user-controlled input to object properties without validation, allowing privilege escalation.",
                "what": "Extra fields like 'role: admin' were set during registration and reflected in profile.",
                "how": "Attackers can escalate privileges by submitting hidden or additional fields in requests.",
                "confirmed": False,
                "risk_level": "High",
                "potential_false_negative": "May miss mass assignment in update endpoints or with nested objects."
            },
            "Missing Rate Limiting": {
                "suggestions": ["Implement rate limiting on sensitive endpoints like login", "Use CAPTCHA after multiple failures", "Monitor and block abusive IPs", "Use libraries like Flask-Limiter or nginx configs", "Apply to all critical endpoints"],
                "why": "No limits on repeated actions, allowing brute-force attacks or DoS.",
                "what": "Multiple failed logins without any blocking or delay.",
                "how": "Attackers can brute-force passwords, enumerate users, or overwhelm the system with requests.",
                "confirmed": False,
                "risk_level": "Medium",
                "potential_false_negative": "May not detect account-specific limiting or delayed bans."
            }
        }
        analysis_results = []
        for finding in findings:
            vuln_type = finding["vulnerability"]
            if vuln_type in suggestion_map:
                entry = {
                    "finding_id": finding["finding_id"],
                    "vulnerability": vuln_type,
                    "confirmed": suggestion_map[vuln_type]["confirmed"],
                    "why": suggestion_map[vuln_type]["why"],
                    "what": suggestion_map[vuln_type]["what"],
                    "how": suggestion_map[vuln_type]["how"],
                    "suggestions": suggestion_map[vuln_type]["suggestions"],
                    "risk_level": suggestion_map[vuln_type]["risk_level"],
                    "potential_false_negative": suggestion_map[vuln_type].get("potential_false_negative", "")
                }
                if len(findings) > 1:
                    entry["combined_risk"] = "Multiple access control issues increase risk of unauthorized access, escalation, and potential full compromise."
                analysis_results.append(entry)
            else:
                analysis_results.append({
                    "finding_id": finding["finding_id"],
                    "vulnerability": vuln_type,
                    "confirmed": False,
                    "why": "Unknown vulnerability type.",
                    "what": "N/A",
                    "how": "N/A",
                    "suggestions": ["Investigate further manually", "Consider professional audit"],
                    "risk_level": "Unknown",
                    "potential_false_negative": "Limited coverage may miss this type."
                })
        return analysis_results

def main():
    print("""
    █████╗  ██████╗ ██████╗███████╗███████╗███████╗    ███████╗ ██████╗ ███╗   ██╗████████╗██████╗  ██████╗ ██╗     
   ██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝    ██╔════╝██╔═══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔═══██╗██║     
   ███████║██║     ██║     █████╗  ███████╗███████╗    ██║     ██║   ██║██╔██╗ ██║   ██║   ██████╔╝██║   ██║██║     
   ██╔══██║██║     ██║     ██╔══╝  ╚════██║╚════██║    ██║     ██║   ██║██║╚██╗██║   ██║   ██╔══██╗██║   ██║██║     
   ██║  ██║╚██████╗╚██████╗███████╗███████║███████║    ╚██████╗╚██████╔╝██║ ╚████║   ██║   ██║  ██║╚██████╔╝███████╗
   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚══════╝╚══════╝╚══════╝     ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
    Access Control Integrity Testing Tool v1.3 - Enhanced with Broader Endpoint Testing, Improved Evasion, Rule-Based Analysis, and Explicit Limitations
    For educational purposes only! Includes tests that could trigger alerts.
    WARNING: Only use on sites you own or have explicit permission. No destructive actions, but can lock test accounts or trigger bans.
    This is a black-box tool: It cannot inspect code, queries, or business logic, leading to potential false negatives.
    Analysis is rule-based, not AI-driven. Results require manual confirmation.
    Tool may be blocked by WAFs; use with caution to avoid legal risks.
    Not suitable for production audits—use professional tools for comprehensive coverage.
    Use --use-existing for closed systems; provide credentials.
    In real pentesting, for complex issues, combine with white-box review.
    """)
    parser = argparse.ArgumentParser(description="Access Control Integrity Tester")
    parser.add_argument('base_url', help="Base URL of the API (e.g., https://example.com)")
    parser.add_argument('--user1-email', default=None, help="Email for user 1 (required for --use-existing)")
    parser.add_argument('--user1-password', default=None, help="Password for user 1 (required for --use-existing)")
    parser.add_argument('--user2-email', default=None, help="Email for user 2 (required for --use-existing)")
    parser.add_argument('--user2-password', default=None, help="Password for user 2 (required for --use-existing)")
    parser.add_argument('--use-existing', action='store_true', help="Use existing users (skip registration)")
    parser.add_argument('--register-endpoint', default='/api/register', help="Register endpoint")
    parser.add_argument('--login-endpoint', default='/api/login', help="Login endpoint")
    parser.add_argument('--profile-endpoint', default='/api/profile', help="Profile endpoint (self)")
    parser.add_argument('--profile-id-template', default='/api/profile/{id}', help="Profile by ID template")
    parser.add_argument('--logout-endpoint', default='/api/logout', help="Logout endpoint")
    parser.add_argument('--admin-endpoint', default='/api/admin', help="Admin endpoint")
    parser.add_argument('--id-param', default='id', help="ID parameter name in paths")
    parser.add_argument('--discover', action='store_true', help="Attempt to discover OpenAPI spec and map endpoints")
    parser.add_argument('--openapi-url', default=None, help="Direct URL to OpenAPI spec")

    args = parser.parse_args()

    base_url = args.base_url
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'https://' + base_url

    if args.use_existing:
        if not (args.user1_email and args.user1_password and args.user2_email and args.user2_password):
            print("Error: For --use-existing, provide --user1-email, --user1-password, --user2-email, --user2-password")
            sys.exit(1)

    print(f"\nTarget URL: {base_url}")
    confirm = input("\n⚠️ WARNING: This tool will attempt logins, unauthorized actions, and may trigger security alerts or account locks. \n"
                    "It is black-box only and assumes no business logic knowledge. Use only on staging or with permission. \n"
                    "Continue? (y/N): ")
    if confirm.lower() != 'y':
        print("Aborted.")
        sys.exit(0)

    tester = SecurityTester(base_url, args.user1_email, args.user1_password, args.user2_email, args.user2_password,
                            args.register_endpoint, args.login_endpoint, args.profile_endpoint, args.profile_id_template,
                            args.logout_endpoint, args.admin_endpoint, args.id_param, args.use_existing)

    if args.openapi_url:
        try:
            headers = {'User-Agent': tester.get_random_user_agent()}
            r = requests.get(args.openapi_url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                tester.discover_endpoints(data)
                tester.log(f"Parsed provided OpenAPI from {args.openapi_url}")
        except Exception as e:
            tester.log(f"Failed to fetch or parse provided OpenAPI: {e}", "ERROR")
    elif args.discover:
        tester.discover_openapi()

    tester.run_access_control_test()
    print("\n" + "=" * 60)
    print("IMPORTANT:")
    print("- This tool tests for access control issues like IDOR, session misuse, admin exposure, mass assignment, rate limiting")
    print("- Supports existing users for closed registration systems")
    print("- Falls back to partial testing if setup fails")
    print("- Endpoints are configurable or discoverable via OpenAPI for flexibility")
    print("- Broader testing on discovered endpoints to reduce false negatives")
    print("- Still black-box: Cannot detect complex logic flaws; manual confirmation required")
    print("- Rule-based analysis provides basic suggestions; not true AI")
    print("- Running on production can cause issues: account locks, IP bans, compliance violations")
    print("- Always test in STAGING; professional pentest recommended for thorough analysis")
    print("=" * 60)

if __name__ == "__main__":
    main()
```
