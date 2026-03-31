#!/usr/bin/env python3
"""
Combined runner for SSH Honeypot and Web Dashboard
Runs both services simultaneously
"""
import subprocess
import sys
import os
import signal
import time
from threading import Thread

def run_ssh_honeypot():
    """Run the SSH honeypot in a separate process"""
    try:
        print("Starting SSH Honeypot on port 2222...")
        subprocess.run([sys.executable, 'ssh_honeypot.py', '--bind', '127.0.0.1', '--port', '2222'])
    except KeyboardInterrupt:
        print("SSH Honeypot stopped")

def run_web_dashboard():
    """Run the web dashboard in a separate process"""
    try:
        print("Starting Web Dashboard on port 5000...")
        subprocess.run([sys.executable, 'web_dashboard.py'])
    except KeyboardInterrupt:
        print("Web Dashboard stopped")

if __name__ == '__main__':
    print("SSH Honeypot System with Web Dashboard")
    print("=" * 40)
    print("SSH Honeypot will run on: http://localhost:2222 (SSH)")
    print("Web Dashboard will run on: http://localhost:5000 (Web)")
    print("Web Dashboard login: admin / honeypot2024")
    print("Press Ctrl+C to stop both services")
    print("=" * 40)

    # Start both services in separate threads
    ssh_thread = Thread(target=run_ssh_honeypot, daemon=True)
    web_thread = Thread(target=run_web_dashboard, daemon=True)

    try:
        ssh_thread.start()
        web_thread.start()

        # Keep the main thread alive
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nShutting down services...")
        sys.exit(0)