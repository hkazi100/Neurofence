# Neurofence Implementation Guide for Raspberry Pi

> **Complete deployment guide for beginners!**
> This guide will help you set up your own network security monitoring system.

## What You'll Build

By the end of this guide, you'll have:
- A Raspberry Pi that monitors network traffic
- Real-time threat detection dashboard
- Cloud storage for attack history
- Skills in network security and ML!

## Hardware Requirements

## Hardware Requirements

| Component | Specification | Notes |
|-----------|--------------|-------|
| Raspberry Pi | Pi 4 (4GB+ recommended) | Pi 3B+ works but slower |
| SD Card | 32GB+ Class 10 | Samsung or Sandisk recommended |
| Power Supply | 5V 3A USB-C | Official Pi 4 power adapter |
| Case | With cooling | Prevents thermal throttling |
| Network Cable | Cat 6 | For reliable packet capture |

## Software Setup

### 1. Install Raspberry Pi OS

```bash
# Download Raspberry Pi Imager from https://www.raspberrypi.com/software/
# Or use command line:
sudo apt-get update
sudo apt-get install raspberrypi-kernel-headers
```

### 2. Initial Setup

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Enable SSH (headless setup)
sudo raspi-config
# → Interface Options → SSH → Enable
```

### 3. Install Python Dependencies

```bash
# Install system dependencies
sudo apt-get install -y python3-pip libpcap0.8-dev git

# Create virtual environment (recommended)
python3 -m venv rnids-env
source rnids-env/bin/activate

# Install Python packages
pip3 install --upgrade pip
pip3 install flask flask-socketio flask-cors firebase-admin
pip3 install scikit-learn scapy psutil pandas numpy scipy joblib
pip3 install plotly lime dill keras
```

### 4. Configure Network Monitoring

```bash
# Allow packet capture (run as root or use setcap)
sudo setcap cap_net_raw+ep $(readlink -f $(which python3))

# Alternative: Run with sudo for development
sudo python3 application.py
```

## Firebase Configuration

### 1. Create Firebase Project

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Click "Add project"
3. Name: `rnids` (or your choice)
4. Disable Google Analytics (for simplicity)
5. Click "Create project"

### 2. Enable Firestore

1. In Firebase console, click "Build" → "Firestore Database"
2. Click "Create database"
3. Select location closest to you
4. **Important**: Start in "Test mode" (allows all reads/writes for 30 days)
5. Click "Enable"

### 3. Get Service Account Key

1. Click project settings (gear icon)
2. Go to "Service Accounts"
3. Click "Generate New Private Key"
4. Save as `firebase-adminsdk.json`
5. Upload to your Raspberry Pi at `/home/pi/rnids/firebase-adminsdk.json`

## Deployment Steps

### 1. Clone and Setup

```bash
# Login via SSH
ssh pi@raspberrypi.local

# Clone repository
git clone https://github.com/Noel9812/RNIDS.git
cd RNIDS

# Upload firebase credentials
# (use scp or filezilla)
scp firebase-adminsdk.json pi@raspberrypi.local:~/RNIDS/

# Install dependencies
pip3 install -r requirements.txt
```

### 2. Configure Application

```bash
# Edit application.py to disable test mode
nano application.py
# Change: TEST_MODE = True  →  TEST_MODE = False
```

### 3. Run the Application

```bash
# Run with sudo (required for packet capture)
sudo python3 application.py

# Or run as service
sudo cp rnids.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable rnids
sudo systemctl start rnids
```

## Service Configuration (Optional)

Create `/etc/systemd/system/rnids.service`:

```ini
[Unit]
Description=RNIDS - Real-Time Network Intrusion Detection System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/pi/RNIDS
ExecStart=/usr/bin/python3 /home/pi/RNIDS/application.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Network Tap Setup

### Option 1: Mirror Port (Recommended)

Configure your network switch to mirror all traffic to a specific port:

```
Network Switch → Mirror Port → Raspberry Pi Ethernet
```

### Option 2: Network Tap

Build a passive network tap:

```
[Internet] ────► [Tap] ────► [Router]
              │
              └───────────► [Raspberry Pi]
```

### Option 3: WiFi Monitor (Limited)

```bash
# Enable monitor mode (limited capability)
sudo airmon-ng start wlan0
```

## Security Hardening

### 1. Firewall Rules

```bash
# Allow only necessary ports
sudo ufw allow 8080/tcp
sudo ufw allow ssh
sudo ufw enable
```

### 2. Fail2Ban Installation

```bash
sudo apt-get install fail2ban
sudo cp fail2ban/jail.local /etc/fail2ban/
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### 3. SSL Configuration

```bash
# Install certbot
sudo apt-get install certbot python3-certbot-nginx

# Generate certificate
sudo certbot --nginx -d yourdomain.com

# Configure nginx reverse proxy
```

## Performance Optimization

### 1. Reduce Logging

In `application.py`:

```python
import logging
logging.basicConfig(level=logging.WARNING)
```

### 2. Optimize Models

```python
# Use smaller models for Raspberry Pi
# Convert .hdf5 to .tflite if needed
```

### 3. Memory Management

```bash
# Increase swap size
sudo dphys-swapfile setup
sudo dphys-swapfile swapon
```

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Permission denied | Run with `sudo python3 application.py` |
| Firebase error | Check `firebase-adminsdk.json` path |
| Port in use | Change port in application.py |
| No packets captured | Check network connection / mirror port |
| Memory error | Reduce buffer size / add swap |

### Check Logs

```bash
# Application logs
tail -f /var/log/syslog

# Service status
sudo systemctl status rnids
```

### Test Packet Capture

```bash
# Test as root
sudo python3 -c "from scapy.all import *; sniff(count=1)"
```

## Remote Access

### 1. Ngrok (Quick)

```bash
# Download ngrok
wget https://bin.equinox.io/c/4WmRwT51iqQ/ngrok-stable-linux-arm.zip
unzip ngrok-stable-linux-arm.zip
sudo mv ngrok /usr/local/bin/

# Start tunnel
sudo ./ngrok tcp 8080
```

### 2. Private Network (Recommended)

Access via local network:
```
http://raspberrypi.local:8080
```

### 3. VPN (Most Secure)

Setup WireGuard or OpenVPN for secure remote access.

## Maintenance

### Regular Tasks

```bash
# Update system weekly
sudo apt-get update && sudo apt-get upgrade -y

# Check disk space
df -h

# Monitor memory
free -h

# Check temperatures
vcgencmd measure_temp
```

### Backup

```bash
# Backup Firestore data
# Use Firebase console or gcloud CLI

# Backup local logs
tar -czf rnids-logs-$(date +%Y%m%d).tar.gz *.csv
```

## Cost Estimate

| Item | One-Time Cost |
|------|---------------|
| Raspberry Pi 4 (4GB) | $55 |
| Case + Power Supply | $20 |
| 32GB SD Card | $10 |
| Network Cable | $5 |
| **Total** | **~$90** |

Monthly costs:
- Firebase: Free tier (up to 50K reads/writes/day)
- Electricity: ~$3/month

## Quick Reference Commands

```bash
# Start RNIDS
sudo python3 application.py

# Check status
systemctl status rnids

# Stop RNIDS
systemctl stop rnids

# View logs
journalctl -u rnids -f

# Update
cd ~/RNIDS && git pull

# Restart
systemctl restart rnids
```

## Support

- Issues: https://github.com/Noel9812/RNIDS/issues
- Documentation: https://github.com/Noel9812/RNIDS#readme