#!/usr/bin/env python3
"""
SSH Honeypot Connection Demonstrator
Shows how to connect to the honeypot and what happens
"""
import socket
import time
import paramiko
import threading

def demonstrate_ssh_connection():
    """Demonstrate connecting to the SSH honeypot"""
    print("🔗 SSH Honeypot Connection Demonstration")
    print("=" * 50)

    # Test 1: Basic connection attempt
    print("\n1. Testing basic connection to honeypot...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(('127.0.0.1', 2222))
        if result == 0:
            print("✅ Honeypot is listening on port 2222")
        else:
            print("❌ Cannot connect to honeypot")
        sock.close()
    except Exception as e:
        print(f"❌ Connection error: {e}")

    # Test 2: Paramiko SSH client connection
    print("\n2. Attempting SSH authentication with Paramiko...")

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        print("   Connecting with username: 'admin', password: 'wrongpass'")
        client.connect('127.0.0.1', port=2222, username='admin', password='wrongpass', timeout=10)

        print("✅ Authentication successful (unexpected!)")
        client.close()

    except paramiko.AuthenticationException:
        print("✅ Authentication failed as expected (honeypot logged this attempt)")

    except paramiko.SSHException as e:
        print(f"✅ SSH connection established but auth failed: {e}")

    except Exception as e:
        print(f"❌ Connection error: {e}")

    # Test 3: Multiple rapid connection attempts
    print("\n3. Simulating multiple attacker attempts...")

    usernames = ['root', 'admin', 'user', 'test', 'ubuntu']
    passwords = ['password', '123456', 'admin', 'root', 'letmein']

    for i, (user, pwd) in enumerate(zip(usernames, passwords), 1):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            print(f"   Attempt {i}: {user}/{pwd}")
            client.connect('127.0.0.1', port=2222, username=user, password=pwd, timeout=5)

            # If we get here, authentication succeeded
            print("   ✅ Auth successful - executing commands...")

            # Try to execute a command
            stdin, stdout, stderr = client.exec_command('whoami')
            output = stdout.read().decode().strip()
            print(f"   Command output: {output}")

            client.close()
            break  # Stop after first successful auth

        except paramiko.AuthenticationException:
            print("   ❌ Auth failed (logged)")
        except Exception as e:
            print(f"   ❌ Connection error: {e}")
        finally:
            try:
                client.close()
            except:
                pass

        time.sleep(0.5)  # Brief pause between attempts

    print("\n4. Checking generated logs...")
    try:
        with open('logs/auth.log', 'r') as f:
            lines = f.readlines()[-5:]  # Last 5 lines
            print("   Recent auth.log entries:")
            for line in lines:
                print(f"   {line.strip()}")
    except FileNotFoundError:
        print("   No auth.log found yet")
    except Exception as e:
        print(f"   Error reading logs: {e}")

    print("\n" + "=" * 50)
    print("🎯 Demonstration Complete!")
    print("\n📊 Check your web dashboard at http://localhost:5000")
    print("   Login: admin / honeypot2024")
    print("   You'll see all these connection attempts logged!")

if __name__ == '__main__':
    demonstrate_ssh_connection()