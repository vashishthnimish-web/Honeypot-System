#!/usr/bin/env python3
"""
Lightweight SSH honeypot using Paramiko.

Features:
"""
# Libraries
import logging
from logging.handlers import RotatingFileHandler
import paramiko
import socket
import threading
import os
import argparse
import traceback
import datetime

# Constants
logging_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"

# Loggers & Logging Files
auth_logger = logging.getLogger("AuthLogger")
auth_logger.setLevel(logging.INFO)
auth_handler = RotatingFileHandler('logs/auth.log', maxBytes=5000000, backupCount=5)
auth_handler.setFormatter(logging.Formatter('%(message)s'))
auth_logger.addHandler(auth_handler)

cmd_logger = logging.getLogger("CmdLogger")
cmd_logger.setLevel(logging.INFO)
cmd_handler = RotatingFileHandler('logs/commands.log', maxBytes=5000000, backupCount=5)
cmd_handler.setFormatter(logging_format)
cmd_logger.addHandler(cmd_handler)

conn_logger = logging.getLogger("ConnLogger")
conn_logger.setLevel(logging.INFO)
conn_handler = RotatingFileHandler('logs/connections.log', maxBytes=5000000, backupCount=5)
conn_handler.setFormatter(logging_format)
conn_logger.addHandler(conn_handler)

err_logger = logging.getLogger("ErrorLogger")
err_logger.setLevel(logging.INFO)
err_handler = RotatingFileHandler('logs/errors.log', maxBytes=5000000, backupCount=5)
err_handler.setFormatter(logging_format)
err_logger.addHandler(err_handler)


# SSH Server Class
class HoneypotServer(paramiko.ServerInterface):

    def __init__(self, client_addr, allowed_username=None, allowed_password=None):
        self.event = threading.Event()
        self.client_addr = client_addr
        self.allowed_username = allowed_username
        self.allowed_password = allowed_password

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Log the attempt in standard auth.log format
        import datetime
        timestamp = datetime.datetime.now().strftime("%b %d %H:%M:%S")
        hostname = socket.gethostname()
        
        if self.allowed_username is not None and self.allowed_password is not None:
            if username == self.allowed_username and password == self.allowed_password:
                auth_logger.info(f"{timestamp} {hostname} sshd[1234]: Accepted password for {username} from {self.client_addr} port 22 ssh2")
                return paramiko.AUTH_SUCCESSFUL
            else:
                auth_logger.info(f"{timestamp} {hostname} sshd[1234]: Failed password for {username} from {self.client_addr} port 22 ssh2")
                return paramiko.AUTH_FAILED
        else:
            # Honeypot mode - accept any credentials but log them
            auth_logger.info(f"{timestamp} {hostname} sshd[1234]: Failed password for invalid user {username} from {self.client_addr} port 22 ssh2")
            return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True


def emulated_shell(channel, client_addr):
    """A very small pseudo-shell that echoes input and supports a few builtins."""
    try:
        prompt = 'corp-jumpbox$ '
        channel.send(prompt)
        buf = b''
        while True:
            data = channel.recv(1024)
            if not data:
                break
            # echo back
            channel.send(data)
            buf += data
            # check for line ending
            if b"\r" in buf or b"\n" in buf:
                line = buf.replace(b"\r", b"").replace(b"\n", b"").strip()
                try:
                    text = line.decode('utf-8', errors='ignore')
                except Exception:
                    text = repr(line)
                if text:
                    cmd_logger.info(f"{client_addr} - command - {text}")
                # simple responses
                if text == 'exit':
                    channel.send('\nGoodbye\n')
                    break
                elif text == 'pwd':
                    channel.send('\n/home/corpuser\n')
                elif text == 'whoami':
                    channel.send('\ncorpuser\n')
                elif text == 'ls':
                    channel.send('\njumpbox.conf\n')
                elif text.startswith('cat '):
                    channel.send('\n' + text.encode() + b'\n')
                else:
                    channel.send('\n' + text + '\n')
                buf = b''
                channel.send(prompt)
    except Exception:
        err_logger.error('Shell error:\n' + traceback.format_exc())
    finally:
        try:
            channel.close()
        except Exception:
            pass


def handle_client(client_sock, addr, args):
    client_ip = addr[0]
    timestamp = datetime.datetime.now().strftime("%b %d %H:%M:%S")
    hostname = socket.gethostname()
    
    # Log connection attempt
    auth_logger.info(f"{timestamp} {hostname} sshd[1234]: Connection from {client_ip} port {addr[1]}")
    conn_logger.info(f"Connection from {client_ip}:{addr[1]}")
    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = SSH_BANNER
        # load host key
        try:
            host_key = paramiko.RSAKey(filename=args.host_key)
        except Exception as e:
            err_logger.error(f"Unable to load host key from {args.host_key}: {e}")
            # generate an ephemeral key
            host_key = paramiko.RSAKey.generate(2048)
            err_logger.error("Using ephemeral host key")

        transport.add_server_key(host_key)
        server = HoneypotServer(client_ip, allowed_username=args.username, allowed_password=args.password)
        transport.start_server(server=server)

        chan = transport.accept(20)
        if chan is None:
            timestamp = datetime.datetime.now().strftime("%b %d %H:%M:%S")
            hostname = socket.gethostname()
            auth_logger.info(f"{timestamp} {hostname} sshd[1234]: Connection closed by {client_ip} port {addr[1]} [preauth]")
            conn_logger.info(f"{client_ip} - no channel opened (timeout)")
            return

        timestamp = datetime.datetime.now().strftime("%b %d %H:%M:%S")
        hostname = socket.gethostname()
        auth_logger.info(f"{timestamp} {hostname} sshd[1234]: Opened session for user from {client_ip} port {addr[1]}")
        
        chan.send("Welcome to Corporate SSH\n")
        # wait for shell request
        server.event.wait(10)
        emulated_shell(chan, client_ip)

    except Exception:
        err_logger.error('Handler error:\n' + traceback.format_exc())
    finally:
        try:
            if transport is not None:
                transport.close()
        except Exception:
            pass
        try:
            client_sock.close()
        except Exception:
            pass


def serve(bind_addr: str, bind_port: int, args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_addr, bind_port))
    sock.listen(100)
    print(f"Honeypot listening on {bind_addr}:{bind_port}")
    while True:
        try:
            client, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(client, addr, args), daemon=True)
            t.start()
        except KeyboardInterrupt:
            print('Shutting down')
            break
        except Exception:
            err_logger.error('Accept loop error:\n' + traceback.format_exc())


def parse_args():
    p = argparse.ArgumentParser(description='Simple Paramiko-based SSH honeypot')
    p.add_argument('--bind', default='0.0.0.0', help='Bind address (default 0.0.0.0)')
    p.add_argument('--port', type=int, default=2222, help='Port to listen on (default 2222)')
    p.add_argument('--host-key', default=os.path.join(os.path.dirname(__file__), '..', 'server.key'), help='Path to host RSA key')
    p.add_argument('--username', default=None, help='Optional allowed username (if set, only this username will authenticate)')
    p.add_argument('--password', default=None, help='Optional allowed password (if set, only this password will authenticate)')
    return p.parse_args()


if __name__ == '__main__':
    args = parse_args()
    # normalize host key path
    args.host_key = os.path.abspath(args.host_key)
    serve(args.bind, args.port, args)
