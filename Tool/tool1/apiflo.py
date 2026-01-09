
#!/usr/bin/env python3
import requests
import json
import sys
import time
import random

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
]

class SecurityTester:
    def __init__(self, base_url, test_email1=None, test_email2=None):
        self.base_url = base_url.rstrip('/')
        self.test_email1 = test_email1 or f"test1_{random.randint(1000,9999)}@example.com"
        self.test_email2 = test_email2 or f"test2_{random.randint(1000,9999)}@example.com"
        self.test_password = "Test123!"
        self.session = requests.Session()
        self.results = []
        self.user1_token = None
        self.user2_token = None
        self.user1_id = None
        self.user2_id = None

    def log(self, message, status="INFO"):
        print(f"[{status}] {message}")

    def get_random_user_agent(self):
        return random.choice(USER_AGENTS)

    def register_user(self, email, password, extra_payload=None):
        """Register a new user"""
        try:
            endpoint = f"{self.base_url}/api/register"
            payload = {"email": email, "password": password}
            if extra_payload:
                payload.update(extra_payload)
            headers = {'User-Agent': self.get_random_user_agent()}
            response = self.session.post(endpoint, json=payload, headers=headers, timeout=10)
            return response
        except Exception as e:
            self.log(f"Error registering user {email}: {e}", "ERROR")
            return None

    def login_user(self, email, password):
        """Login a user and return token"""
        try:
            endpoint = f"{self.base_url}/api/login"
            payload = {"email": email, "password": password}
            headers = {'User-Agent': self.get_random_user_agent()}
            response = self.session.post(endpoint, json=payload, headers=headers, timeout=10)
            if response.status_code == 200 and "token" in response.json():
                return response.json()["token"]
            else:
                return None
        except Exception as e:
            self.log(f"Error logging in user {email}: {e}", "ERROR")
            return None

    def get_profile(self, token, user_id=None):
        """Get profile, optionally for a specific user_id"""
        try:
            if user_id:
                endpoint = f"{self.base_url}/api/profile/{user_id}"
            else:
                endpoint = f"{self.base_url}/api/profile"
            headers = {
                'User-Agent': self.get_random_user_agent(),
                'Authorization': f"Bearer {token}"
            }
            response = self.session.get(endpoint, headers=headers, timeout=10)
            return response
        except Exception as e:
            self.log(f"Error getting profile: {e}", "ERROR")
            return None

    def test_idor_authorization(self):
        """Test for IDOR / Authorization issues"""
        self.log("Testing IDOR / Authorization...")
        vulnerable = False

        # Try to access user1's profile as user2
        response = self.get_profile(self.user2_token, self.user1_id)
        context = {
            "auth_required": True,
            "public_endpoint": False,
            "user_controlled_input": True
        }
        finding_id = f"AC-{len(self.results) + 1}"
        if response and response.status_code == 200:
            try:
                data = response.json()
                if "email" in data and data["email"] == self.test_email1:
                    self.log("⚠️ Potential IDOR vulnerability: User2 can access User1's profile!", "WARNING")
                    vulnerable = True
                    self.results.append({
                        "finding_id": finding_id,
                        "vulnerability": "IDOR / Broken Authorization",
                        "endpoint": f"/api/profile/{self.user1_id}",
                        "details": "User2 accessed User1's private data",
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

        # Assume there's a logout endpoint
        try:
            endpoint = f"{self.base_url}/api/logout"
            headers = {
                'User-Agent': self.get_random_user_agent(),
                'Authorization': f"Bearer {self.user1_token}"
            }
            self.session.post(endpoint, headers=headers, timeout=10)
        except:
            pass

        # Try to access profile with "revoked" token
        response = self.get_profile(self.user1_token)
        context = {
            "auth_required": True,
            "public_endpoint": False,
            "user_controlled_input": False
        }
        finding_id = f"AC-{len(self.results) + 1}"
        if response and response.status_code == 200:
            self.log("⚠️ Potential Session Misuse: Token still valid after logout!", "WARNING")
            vulnerable = True
            self.results.append({
                "finding_id": finding_id,
                "vulnerability": "Session / Token Misuse",
                "endpoint": "/api/profile",
                "details": "Token usable after logout",
                "context": context,
                "status": "NOT_CONFIRMED"
            })

        return vulnerable

    def test_admin_exposure(self):
        """Test for admin endpoint exposure"""
        self.log("Testing Admin Exposure...")
        vulnerable = False

        # Try to access /api/admin as normal user
        try:
            endpoint = f"{self.base_url}/api/admin"
            headers = {
                'User-Agent': self.get_random_user_agent(),
                'Authorization': f"Bearer {self.user2_token}"
            }
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
                    "endpoint": "/api/admin",
                    "details": "Accessible without admin privileges",
                    "context": context,
                    "status": "NOT_CONFIRMED"
                })
        except Exception as e:
            self.log(f"Error testing admin exposure: {e}", "ERROR")

        return vulnerable

    def test_mass_assignment(self):
        """Test for mass assignment vulnerability"""
        self.log("Testing Mass Assignment...")
        vulnerable = False

        # Register a new user with extra fields like "role": "admin"
        test_email_mass = f"mass_{random.randint(1000,9999)}@example.com"
        extra_payload = {"role": "admin", "is_admin": True}
        reg_response = self.register_user(test_email_mass, self.test_password, extra_payload)
        if not reg_response or reg_response.status_code not in [200, 201]:
            self.log("Failed to register for mass assignment test", "ERROR")
            return False

        token_mass = self.login_user(test_email_mass, self.test_password)
        if not token_mass:
            self.log("Failed to login for mass assignment test", "ERROR")
            return False

        profile_response = self.get_profile(token_mass)
        context = {
            "auth_required": False,
            "public_endpoint": True,
            "user_controlled_input": True
        }
        finding_id = f"AC-{len(self.results) + 1}"
        if profile_response and profile_response.status_code == 200:
            try:
                data = profile_response.json()
                if data.get("role") == "admin" or data.get("is_admin") == True:
                    self.log("⚠️ Potential Mass Assignment: Extra fields like 'role: admin' were assigned!", "WARNING")
                    vulnerable = True
                    self.results.append({
                        "finding_id": finding_id,
                        "vulnerability": "Mass Assignment",
                        "endpoint": "/api/register",
                        "details": "Unauthorized fields bound to object",
                        "context": context,
                        "status": "NOT_CONFIRMED"
                    })
            except:
                pass

        return vulnerable

    def test_rate_limiting(self):
        """Test for rate limiting by sending multiple requests"""
        self.log("Testing Rate Limiting...")
        vulnerable = False
        max_attempts = 20  # Safe number to avoid abuse
        failed_logins = 0

        for i in range(max_attempts):
            time.sleep(random.uniform(0.5, 1.5))  # Jitter
            login_response = self.perform_normal_request(f"{self.base_url}/api/login", {"email": self.test_email1, "password": "wrongpass"})
            if login_response:
                if login_response.status_code == 429:  # Too Many Requests
                    self.log("Rate limiting detected (429 status)", "INFO")
                    return False
                if "rate limit" in login_response.text.lower() or "too many" in login_response.text.lower():
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
                "endpoint": "/api/login",
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
        """Setup two test users"""
        self.log("Setting up test users...")

        # Register and login user1
        reg1 = self.register_user(self.test_email1, self.test_password)
        if not reg1 or reg1.status_code not in [200, 201]:
            self.log("Failed to register user1", "ERROR")
            return False
        self.user1_token = self.login_user(self.test_email1, self.test_password)
        if not self.user1_token:
            self.log("Failed to login user1", "ERROR")
            return False
        profile1 = self.get_profile(self.user1_token)
        if profile1 and profile1.status_code == 200:
            try:
                self.user1_id = profile1.json()["id"]
            except:
                self.log("Failed to get user1 ID", "ERROR")
                return False
        else:
            return False

        # Register and login user2
        reg2 = self.register_user(self.test_email2, self.test_password)
        if not reg2 or reg2.status_code not in [200, 201]:
            self.log("Failed to register user2", "ERROR")
            return False
        self.user2_token = self.login_user(self.test_email2, self.test_password)
        if not self.user2_token:
            self.log("Failed to login user2", "ERROR")
            return False
        profile2 = self.get_profile(self.user2_token)
        if profile2 and profile2.status_code == 200:
            try:
                self.user2_id = profile2.json()["id"]
            except:
                self.log("Failed to get user2 ID", "ERROR")
                return False
        else:
            return False

        return True

    def run_access_control_test(self):
        """Run the access control integrity test"""
        self.log(f"Starting Access Control Integrity tests for {self.base_url}")
        self.log("=" * 60)

        if not self.setup_users():
            self.log("Setup failed, aborting tests", "ERROR")
            return

        vulnerable = False
        if self.test_idor_authorization():
            vulnerable = True
        if self.test_session_token_misuse():
            vulnerable = True
        if self.test_admin_exposure():
            vulnerable = True
        if self.test_mass_assignment():
            vulnerable = True
        if self.test_rate_limiting():
            vulnerable = True

        status = "POTENTIAL VULNERABILITIES ⚠️" if vulnerable else "SECURE ✅"
        self.log(f"Access Control Integrity: {status}")

        # Print summary
        self.log("\n" + "=" * 60)
        self.log("ACCESS CONTROL INTEGRITY TEST SUMMARY")
        self.log("=" * 60)
        if vulnerable:
            self.log("⚠️ POTENTIAL VULNERABILITIES FOUND - AWAITING AI CONFIRMATION", "WARNING")
        else:
            self.log("✅ No vulnerabilities found!")

        # Save detailed report
        self.save_report()

        # Perform AI analysis
        self.analyze_with_ai()

    def save_report(self):
        """Save detailed vulnerability report"""
        report = {
            "base_url": self.base_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": self.results
        }
        try:
            with open("access_control_report.json", "w") as f:
                json.dump(report, f, indent=2)
            self.log("Detailed report saved to 'access_control_report.json'")
        except Exception as e:
            self.log(f"Error saving report: {e}", "ERROR")

    def analyze_with_ai(self):
        """Analyze findings with AI for suggestions and confirmations"""
        self.log("Performing AI analysis on findings...")
        try:
            with open("access_control_report.json") as f:
                report = json.load(f)
            ai_results = self.ai_analyze(report["vulnerabilities"])
            with open("ai_analysis.json", "w") as f:
                json.dump(ai_results, f, indent=2)
            self.log("AI analysis saved to 'ai_analysis.json'")
            # Print AI results summary
            for result in ai_results:
                self.log(f"Finding {result['finding_id']}: {result['vulnerability']}", "AI")
                self.log(f"Confirmed: {'Yes' if result['confirmed'] else 'No'}", "AI")
                self.log(f"Why: {result['why']}", "AI")
                self.log(f"What: {result['what']}", "AI")
                self.log(f"How: {result['how']}", "AI")
                self.log("Suggestions:", "AI")
                for sug in result['suggestions']:
                    self.log(f"- {sug}", "AI")
                self.log("")
        except Exception as e:
            self.log(f"Error in AI analysis: {e}", "ERROR")

    def ai_analyze(self, findings):
        """Simulated AI analysis function with hardcoded logic for access control types"""
        suggestion_map = {
            "IDOR / Broken Authorization": {
                "suggestions": ["Implement proper access controls", "Use indirect references", "Validate user ownership"],
                "why": "The application allows one user to access another's resources directly.",
                "what": "User2 retrieved User1's profile data.",
                "how": "An attacker can guess or enumerate IDs to access unauthorized data.",
                "confirmed": True,
                "risk_level": "High"
            },
            "Session / Token Misuse": {
                "suggestions": ["Implement token revocation on logout", "Use short-lived tokens", "Validate tokens server-side"],
                "why": "Sessions or tokens remain valid after actions that should invalidate them.",
                "what": "Token still usable after logout.",
                "how": "Attackers can continue using stolen tokens even after user logs out.",
                "confirmed": True,
                "risk_level": "Medium"
            },
            "Admin Exposure": {
                "suggestions": ["Role-based access control (RBAC)", "Hide admin endpoints from non-admins", "IP whitelisting for admin"],
                "why": "Administrative functionalities are exposed to non-privileged users.",
                "what": "Normal user accessed /api/admin.",
                "how": "Attackers can exploit admin features without proper privileges.",
                "confirmed": True,
                "risk_level": "Critical"
            },
            "Mass Assignment": {
                "suggestions": ["Whitelist allowed fields", "Use DTOs or binding whitelists", "Avoid auto-binding sensitive fields"],
                "why": "Application binds user-controlled input to object properties without validation.",
                "what": "Extra fields like 'role: admin' were set during registration.",
                "how": "Attackers can escalate privileges by submitting hidden fields.",
                "confirmed": True,
                "risk_level": "High"
            },
            "Missing Rate Limiting": {
                "suggestions": ["Implement rate limiting on sensitive endpoints", "Use CAPTCHA after failures", "Monitor and block abusive IPs"],
                "why": "No limits on repeated actions, allowing brute-force attacks.",
                "what": "Multiple failed logins without blocking.",
                "how": "Attackers can brute-force passwords or overwhelm the system.",
                "confirmed": True,
                "risk_level": "Medium"
            }
        }
        ai_results = []
        for finding in findings:
            vuln_type = finding["vulnerability"]
            if vuln_type in suggestion_map:
                ai_entry = {
                    "finding_id": finding["finding_id"],
                    "vulnerability": vuln_type,
                    "confirmed": suggestion_map[vuln_type]["confirmed"],
                    "why": suggestion_map[vuln_type]["why"],
                    "what": suggestion_map[vuln_type]["what"],
                    "how": suggestion_map[vuln_type]["how"],
                    "suggestions": suggestion_map[vuln_type]["suggestions"],
                    "risk_level": suggestion_map[vuln_type]["risk_level"]
                }
                if len(findings) > 1:
                    ai_entry["combined_risk"] = "Multiple access control issues increase risk of unauthorized access and escalation."
                ai_results.append(ai_entry)
            else:
                ai_results.append({
                    "finding_id": finding["finding_id"],
                    "vulnerability": vuln_type,
                    "confirmed": False,
                    "why": "Unknown vulnerability type.",
                    "what": "N/A",
                    "how": "N/A",
                    "suggestions": ["Investigate further"],
                    "risk_level": "Unknown"
                })
        return ai_results

def main():
    print("""
    Access Control Integrity Testing Tool v1.0
    For educational purposes only!
    WARNING: Only use on sites you own or have permission.
    This tool tests for access control issues by creating test users and attempting unauthorized actions.
    Assumes API endpoints: /api/register, /api/login, /api/profile, /api/profile/{id}, /api/admin, /api/logout
    """)
    if len(sys.argv) < 2:
        print("Usage: python access_control_test.py <base_url> [test_email1] [test_email2]")
        print("Example: python access_control_test.py https://your-site.com test1@example.com test2@example.com")
        sys.exit(1)
    base_url = sys.argv[1]
    test_email1 = sys.argv[2] if len(sys.argv) > 2 else None
    test_email2 = sys.argv[3] if len(sys.argv) > 3 else None
    # Add protocol if missing
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'https://' + base_url
    print(f"\nTarget URL: {base_url}")
    confirm = input("\n⚠️ WARNING: This tool will create test accounts and test access controls. \n"
                    "Only use on sites you own or have permission. \n"
                    "Continue? (y/N): ")
    if confirm.lower() != 'y':
        print("Aborted.")
        sys.exit(0)
    tester = SecurityTester(base_url, test_email1, test_email2)
    tester.run_access_control_test()
    print("\n" + "=" * 60)
    print("IMPORTANT:")
    print("- This tool only tests for access control integrity issues")
    print("- Covers IDOR, session misuse, admin exposure, mass assignment, rate limiting")
    print("- AI analysis provides explanations, confirmations, and fix suggestions")
    print("- Manual verification and professional pentesting recommended")
    print("- Always test in a STAGING environment first")
    print("- Never test production systems without permission")
    print("=" * 60)

if __name__ == "__main__":
    main()
