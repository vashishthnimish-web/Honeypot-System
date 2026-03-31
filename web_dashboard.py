#!/usr/bin/env python3
"""
Fixed & Enhanced SSH Honeypot Web Dashboard
Stable, secure, production-ready backend
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
import os, json, re, io, csv, socket
from datetime import datetime, timedelta
import logging
from logging.handlers import RotatingFileHandler

# Optional deps
try:
    from flask_socketio import SocketIO  # type: ignore
    socketio_available = True
except ImportError:
    socketio_available = False

try:
    import pandas as pd
    import plotly.graph_objs as go
    import plotly.express as px
    charts_available = True
except ImportError:
    charts_available = False

try:
    import bcrypt
    bcrypt_available = True
except ImportError:
    bcrypt_available = False

# ------------------- App Setup -------------------
app = Flask(__name__)
app.secret_key = os.environ.get("HONEYPOT_SECRET", os.urandom(32))

socketio = SocketIO(app, cors_allowed_origins="*") if socketio_available else None

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "honeypot2024"

# ------------------- Logging -------------------
auth_logger = logging.getLogger("WebAuth")
auth_logger.setLevel(logging.INFO)
handler = RotatingFileHandler(f"{LOG_DIR}/auth.log", maxBytes=5_000_000, backupCount=5)
handler.setFormatter(logging.Formatter('%(message)s'))
auth_logger.addHandler(handler)

# ------------------- Auth Helpers -------------------
if bcrypt_available:
    HASHED_ADMIN_PASS = bcrypt.hashpw(
        DEFAULT_ADMIN_PASS.encode(), bcrypt.gensalt()
    )
else:
    HASHED_ADMIN_PASS = DEFAULT_ADMIN_PASS

def check_password(password):
    if bcrypt_available:
        return bcrypt.checkpw(password.encode(), HASHED_ADMIN_PASS)
    return password == HASHED_ADMIN_PASS

# ------------------- Log Parsers -------------------
def parse_auth_log():
    path = f"{LOG_DIR}/auth.log"
    results = []

    if not os.path.exists(path):
        return results

    with open(path, "r", errors="ignore") as f:
        for line in f:
            ip = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            user = re.search(r'for (?:invalid user )?(\w+)', line)

            event = "other"
            if "Failed password" in line:
                event = "failed_auth"
            elif "Accepted password" in line:
                event = "successful_auth"
            elif "Invalid user" in line:
                event = "invalid_user"
            elif "Connection" in line:
                event = "connection"

            results.append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": ip.group(1) if ip else "unknown",
                "username": user.group(1) if user else "unknown",
                "type": event,
                "message": line.strip()
            })
    return results[::-1]

def parse_command_log():
    path = f"{LOG_DIR}/commands.log"
    results = []

    if not os.path.exists(path):
        return results

    with open(path, "r", errors="ignore") as f:
        for line in f:
            if "command -" in line:
                ip = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                results.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": ip.group(1) if ip else "unknown",
                    "command": line.strip()
                })
    return results[::-1]

# ------------------- Stats Engine -------------------
def get_enhanced_stats():
    auth = parse_auth_log()
    cmds = parse_command_log()

    ips = {a["ip"] for a in auth if a["ip"] != "unknown"}

    ip_fail = {}
    user_count = {}

    for a in auth:
        if a["type"] in ("failed_auth", "invalid_user"):
            ip_fail[a["ip"]] = ip_fail.get(a["ip"], 0) + 1
        user_count[a["username"]] = user_count.get(a["username"], 0) + 1

    return {
        "total_connections": sum(1 for a in auth if a["type"] == "connection"),
        "failed_auth_attempts": sum(1 for a in auth if a["type"] == "failed_auth"),
        "successful_auth_attempts": sum(1 for a in auth if a["type"] == "successful_auth"),
        "invalid_user_attempts": sum(1 for a in auth if a["type"] == "invalid_user"),
        "unique_ips": len(ips),
        "total_commands": len(cmds),
        "top_attackers": sorted(ip_fail.items(), key=lambda x: x[1], reverse=True)[:10],
        "common_usernames": sorted(user_count.items(), key=lambda x: x[1], reverse=True)[:10],
        "recent_activity": auth[:20]
    }

# ------------------- Charts -------------------
def create_charts():
    if not charts_available:
        return {}

    stats = get_enhanced_stats()

    fig = px.pie(
        values=[
            stats["failed_auth_attempts"],
            stats["successful_auth_attempts"],
            stats["invalid_user_attempts"],
            stats["total_connections"]
        ],
        names=["Failed Auth", "Success", "Invalid User", "Connections"],
        title="Event Distribution"
    )

    return {
        "event_chart": fig.to_dict()
    }

# ------------------- Routes -------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard")) if session.get("logged_in") else redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["username"] == DEFAULT_ADMIN_USER and check_password(request.form["password"]):
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        auth_logger.info(f"Failed login from {request.remote_addr}")
        flash("Invalid credentials", "danger")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("dashboard.html",
        stats=get_enhanced_stats(),
        charts=create_charts()
    )

@app.route("/api/stats")
def api_stats():
    return jsonify(get_enhanced_stats())

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ------------------- Socket.IO -------------------
if socketio_available:
    @socketio.on("request_update")
    def update():
        socketio.emit("stats_update", {
            "stats": get_enhanced_stats(),
            "charts": create_charts()
        })

# ------------------- Run -------------------
if __name__ == "__main__":
    print("🚀 Honeypot Dashboard running on http://localhost:5000")
    if socketio_available:
        socketio.run(app, host="0.0.0.0", port=5000, debug=True)
    else:
        app.run(host="0.0.0.0", port=5000, debug=True)