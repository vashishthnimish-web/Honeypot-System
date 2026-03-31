#!/usr/bin/env python3
"""
Test script to demonstrate where login attempts are logged
"""
import requests
import time

def test_web_login():
    """Test web dashboard login attempts"""
    print("🕷️ Testing Web Dashboard Login Attempts...")

    # Test URLs
    login_url = 'http://localhost:5000/login'

    # Test cases
    test_cases = [
        {'username': 'admin', 'password': 'wrongpass'},
        {'username': 'hacker', 'password': 'password123'},
        {'username': 'root', 'password': 'admin'},
    ]

    for i, creds in enumerate(test_cases, 1):
        try:
            print(f"  Attempt {i}: {creds['username']}/{creds['password']}")
            response = requests.post(login_url, data=creds, allow_redirects=False)
            print(f"    Response: {response.status_code}")
        except Exception as e:
            print(f"    Error: {e}")

        time.sleep(1)  # Brief pause

    print("✅ Web login attempts completed")

def show_log_locations():
    """Show where different login attempts are logged"""
    print("\n📍 LOGIN ATTEMPT LOGGING LOCATIONS:")
    print("=" * 50)

    print("1. SSH Honeypot Login Attempts:")
    print("   📁 File: logs/auth.log")
    print("   📝 Format: syslog-style SSH authentication logs")
    print("   🔍 Example: 'Feb 03 12:05:36 hostname sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2'")
    print()

    print("2. Web Dashboard Login Attempts:")
    print("   📁 File: logs/auth.log (same file)")
    print("   📝 Format: 'Feb 03 12:05:36 hostname httpd[8080]: Failed web login for hacker from 127.0.0.1'")
    print("   📝 Also logged to: Console output of web_dashboard.py")
    print()

    print("3. Commands Executed in SSH Shell:")
    print("   📁 File: logs/commands.log")
    print("   📝 Format: '2026-02-03 12:05:38 - 192.168.1.100 - command - ls'")
    print()

    print("4. Connection Metadata:")
    print("   📁 File: logs/connections.log")
    print("   📝 Format: Standard logging with timestamps")
    print()

    print("5. Error Logs:")
    print("   📁 File: logs/errors.log")
    print("   📝 Format: Full Python tracebacks for debugging")
    print()

if __name__ == '__main__':
    show_log_locations()

    print("🧪 Testing login attempts...")
    try:
        test_web_login()
    except ImportError:
        print("❌ requests module not available - install with: pip install requests")
        print("   Manual testing: Visit http://localhost:5000 and try wrong login credentials")

    print("\n📊 Check your logs after testing:")
    print("   tail -f logs/auth.log")
    print("   Visit: http://localhost:5000 (admin/honeypot2024)")