# Python SSH Honeypot

This is a comprehensive SSH honeypot system implemented with Paramiko, featuring advanced monitoring, logging, and a modern web dashboard for real-time security analysis.

## Features

### SSH Honeypot
- SSH honeypot with configurable authentication
- Comprehensive logging (authentication, commands, connections, errors)
- Tiny emulated shell for interaction capture
- Configurable bind address and port

### Enhanced Web Dashboard
- **Modern Responsive UI**: Beautiful, mobile-friendly interface with Bootstrap 5
- **Real-time Updates**: Live data updates using WebSocket (optional)
- **Interactive Charts**: Data visualization with Plotly (optional)
- **Advanced Analytics**: Top attackers, common usernames, activity patterns
- **Security Features**: Enhanced authentication with bcrypt hashing (optional)
- **Data Export**: CSV export functionality for logs and reports
- **Settings Management**: System configuration and monitoring

### Core Files
- `ssh_honeypot.py` - Main SSH server script
- `web_dashboard.py` - Enhanced web dashboard application
- `requirements.txt` - Python dependencies
- `server.key` - Host private key
- `templates/` - HTML templates for the web interface
- `static/` - Static assets (CSS, JS, images)

## Quick Start

### 1. Install Dependencies

```powershell
# Create virtual environment (optional)
python -m venv .venv; .\.venv\Scripts\Activate.ps1

# Install basic requirements
pip install -r requirements.txt

# Install optional enhanced features
pip install flask-socketio python-socketio plotly pandas bcrypt
```

### 2. Run the SSH Honeypot

```powershell
# Run honeypot on port 2222 (default)
python ssh_honeypot.py

# Or specify custom port and bind address
python ssh_honeypot.py --bind 127.0.0.1 --port 2223
```

### 3. Access the Web Dashboard

```powershell
# Run the web dashboard
python web_dashboard.py
```

Then open http://localhost:5000 and login with:
- **Username**: admin
- **Password**: honeypot2024

### 4. Run Both Services Together

```powershell
# Run both SSH honeypot and web dashboard simultaneously
python run_both.py
```

### 5. Generate Demo Data (Optional)

```powershell
# Generate sample log data to see the dashboard in action
python generate_demo_data.py
```

## Web Dashboard Features

### Core Features (Always Available)
- **Secure Login Page**: Modern authentication with honeypot-themed design
- **Dashboard**: Comprehensive statistics and recent activity monitoring
- **Logs Viewer**: Detailed view of authentication and command logs with export functionality
- **Settings Page**: System configuration and information
- **Responsive Design**: Works seamlessly on desktop and mobile devices

### Enhanced Features (Optional Dependencies)
- **Real-time Updates**: Live data updates using WebSocket technology
- **Interactive Charts**: Data visualization with Plotly for activity trends and distributions
- **Advanced Analytics**:
  - Top attacking IP addresses
  - Most common attempted usernames
  - Hourly activity patterns
  - Event type distribution
- **Secure Authentication**: Bcrypt password hashing for enhanced security
- **Data Export**: CSV export functionality for logs and reports

### Dashboard Statistics
- Total connections and unique IPs
- Failed vs successful authentication attempts
- Commands executed
- Recent activity feed (last 24 hours)
- Top attackers and common usernames

**Default Login Credentials:**
- Username: `admin`
- Password: `honeypot2024`

## Logs

Logs are written to the `logs/` directory as rotating files:
- `logs/connections.log` - connection metadata
- `logs/auth.log` - authentication attempts (username/password)
- `logs/commands.log` - commands typed in emulated shell
- `logs/errors.log` - error traces

## Security Considerations

- Do not expose this to the public internet without proper safeguards
- Run in an isolated environment and monitor resource usage
- Consider log shipping and secure storage for collected data
- All login attempts to the web dashboard are logged
- Use strong passwords and consider enabling bcrypt hashing

## Future Improvements

- Add JSON structured logs and timestamps in ISO 8601
- Capture full TCP stream and attempted uploads
- Add service wrapper for Windows and systemd unit for Linux
- Implement user management and role-based access
- Add alerting and notification system
- Integrate with SIEM systems for advanced analysis
