# Neurofence - Network Intrusion Detection System

<p align="center">
  <img src="https://img.shields.io/badge/Hackathon-First Place-blue" alt="Hackathon">
  <img src="https://img.shields.io/badge/Python-3.8+-green" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
  <img src="https://img.shields.io/badge/Raspberry%20Pi-Supported-red" alt="Raspberry Pi">
</p>

A modern network intrusion detection system that uses machine learning to detect malicious network traffic in real-time. Built for educational purposes and deployed on Raspberry Pi for hands-on cybersecurity learning.

> Perfect for beginners and enthusiasts wanting to learn about network security, packet analysis, and ML-based threat detection.

## Why Neurofence?

- **Learn by Doing**: Real-time packet capture and analysis
- **Open Source**: Fully customizable and transparent
- **Beginner Friendly**: Designed for students and hobbyists
- **Low Cost**: Runs on Raspberry Pi (~$90 one-time)
- **Practical Skills**: Gain experience with tools used in the industry

## Features

- **Real-Time Traffic Analysis**: Captures and analyzes network packets using Scapy
- **Machine Learning Detection**: Uses Random Forest classifier with LIME explainability
- **Autoencoder Anomaly Detection**: Reconstruction error analysis for unknown threats
- **Live Dashboard**: Real-time visualization with Chart.js and SocketIO
- **Cloud Storage**: Firebase Firestore for persistent storage and analytics
- **Multi-Platform**: Works on Raspberry Pi, Linux, and macOS

## What You'll Learn

| Skill | Description |
|-------|-------------|
| Packet Analysis | Understanding network protocols (TCP/IP, UDP) |
| Network Security | Identifying threats and attack patterns |
| Machine Learning | ML concepts for anomaly detection |
| Real-time Systems | Building live data pipelines |
| Cloud Integration | Firebase Firestore for data storage |
| IoT Deployment | Running ML on edge devices |

## Tech Stack

- **Backend**: Python 3, Flask, Flask-SocketIO
- **Database**: Firebase Firestore (free tier)
- **ML/AI**: scikit-learn, Keras, LIME, Plotly
- **Frontend**: Bootstrap 5, Chart.js, Socket.IO
- **Packet Capture**: Scapy
- **Deployment**: Raspberry Pi 4 / Linux server

## Quick Start (5 Minutes)

### Step 1: Get the Code

```bash
git clone https://github.com/hkazi100/Neurofence.git
cd Neurofence
```

### Step 2: Install Dependencies

```bash
# Install everything at once
pip3 install -r requirements.txt
```

### Step 3: Setup Firebase (Free!)

1. Go to [firebase.google.com](https://firebase.google.com) and sign in
2. Click "Go to Console" → "Add Project"
3. Follow the wizard (disable Google Analytics for simplicity)
4. **Build → Firestore Database → Create Database → Test Mode**
5. **Project Settings → Service Accounts → Generate Key**
6. Rename downloaded file to `firebase-adminsdk.json`

### Step 4: Run It!

```bash
# Run the application
sudo python3 application.py
```

Open http://localhost:8080 in your browser!

### Installation

```bash
# Clone the repository
git clone https://github.com/hkazi100/Neurofence.git
cd Neurofence

# Install Python dependencies
pip3 install -r requirements.txt
```

### Firebase Setup (Crucial Step)

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Create a new project (name it anything you like)
3. **Enable Firestore Database**:
   - Build → Firestore Database → Create Database
   - Start in **Test Mode** (allows all reads/writes for 30 days)
   - Select your nearest location
4. **Get Credentials**:
   - Project Settings (gear icon) → Service Accounts
   - Generate New Private Key → Download JSON
   - Rename the file to `firebase-adminsdk.json`
   - Place it in the project root folder

> **Don't worry about the complex setup!** The code handles most errors gracefully. If Firebase isn't configured, the app will still run in demo mode.

### Firebase Setup

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Create a new project
3. Enable **Firestore Database** (start in test mode)
4. Generate service account key:
   - Project Settings → Service Accounts → Generate New Private Key
   - Save as `firebase-adminsdk.json` in project root
5. Update Firebase config in `firebase_config.py` if needed

### Running the Application

```bash
# Run with sudo for packet sniffing (required)
sudo python3 application.py

# Access the web interface
# http://localhost:8080
```

### Production Deployment

```bash
# Set TEST_MODE = False in application.py for real packet capture

# Run behind nginx with gunicorn
pip3 install gunicorn eventlet
gunicorn -k eventlet -w 4 application:app &
```

## Project Structure

```
RNIDS/
├── application.py          # Main Flask application
├── firebase_config.py     # Firebase configuration
├── firebase-adminsdk.json  # Firebase credentials
├── output_logs.csv     # Output flow logs
├── input_logs.csv    # Input flow logs
├── models/           # ML models
│   ├── model.pkl
│   ├── preprocess_pipeline_AE_39ft.save
│   ├── autoencoder_39ft.hdf5
│   └── explainer
├── flow/              # Packet processing
│   ├── Flow.py
│   └── PacketInfo.py
├── templates/         # HTML templates
│   ├── index.html     # Dashboard
│   ├── landing.html  # Home page
│   ├── signup.html   # Registration
│   ├── profile.html # User profile
│   ├── detail.html  # Flow details
│   └── about.html   # About page
├── static/            # Static assets
│   ├── css/
│   ├── js/
│   └── images/
└── README.md
```

## Usage

### Login/Registration

1. Open `http://localhost:8080`
2. Click "Get Started" or "Signup"
3. Create an account (stored in Firestore)
4. Login with credentials

### Dashboard

- View real-time traffic chart
- See statistics (Total Flows, Benign, Threats)
- Click flows to view details

### Flow Details

- View feature values
- See LIME explanation
- View autoencoder reconstruction errors

## Raspberry Pi Setup

See [IMPLEMENTATION.md](IMPLEMENTATION.md) for detailed Raspberry Pi deployment instructions.

## License

MIT License - See LICENSE file for details

## Credits

- Original author: Noel9812
- ML models: Trained on CICIDS2017 dataset
- Built with open-source tools