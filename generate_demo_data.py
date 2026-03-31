#!/usr/bin/env python3
"""
Demo script to generate sample log data for the honeypot dashboard
"""
import os
import datetime
import random

# Sample data
usernames = ['admin', 'root', 'user', 'test', 'ubuntu', 'centos', 'debian', 'pi', 'oracle', 'mysql']
passwords = ['password', '123456', 'admin', 'root', 'letmein', 'qwerty', 'password123', 'admin123']
ips = ['192.168.1.100', '10.0.0.50', '172.16.1.25', '203.0.113.45', '198.51.100.78']
commands = ['ls', 'pwd', 'whoami', 'ps aux', 'cat /etc/passwd', 'uname -a', 'id', 'w', 'top', 'df -h']

def generate_sample_logs():
    """Generate sample log entries"""
    hostname = 'HoneypotServer'
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)

    # Generate auth.log entries
    with open(os.path.join(log_dir, 'auth.log'), 'a') as f:
        for i in range(20):
            timestamp = datetime.datetime.now() - datetime.timedelta(minutes=random.randint(0, 60))
            time_str = timestamp.strftime('%b %d %H:%M:%S')

            if random.choice([True, False]):
                # Connection attempt
                ip = random.choice(ips)
                f.write(f'{time_str} {hostname} sshd[1234]: Connection from {ip} port {random.randint(20000, 60000)}\n')
            else:
                # Auth attempt
                username = random.choice(usernames)
                ip = random.choice(ips)
                f.write(f'{time_str} {hostname} sshd[1234]: Failed password for invalid user {username} from {ip} port {random.randint(20000, 60000)} ssh2\n')

    # Generate commands.log entries
    with open(os.path.join(log_dir, 'commands.log'), 'a') as f:
        for i in range(15):
            timestamp = datetime.datetime.now() - datetime.timedelta(minutes=random.randint(0, 30))
            time_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            ip = random.choice(ips)
            command = random.choice(commands)
            f.write(f'{time_str} - {ip} - command - {command}\n')

    print("Sample log data generated!")
    print("Run 'python web_dashboard.py' to view the dashboard")

if __name__ == '__main__':
    generate_sample_logs()