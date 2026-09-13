"""
SentinelSOC - Configuration Module
Defines settings, threat detection parameters, and risk scoring thresholds.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

# Base project directory
BASE_DIR = Path(__file__).resolve().parent

# Ensure required runtime directories exist
DATABASE_DIR = BASE_DIR / 'database'
DATABASE_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_LOGS_DIR = BASE_DIR / 'sample_logs'
SAMPLE_LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Database file path
DB_FILE = DATABASE_DIR / 'security.db'

# Flask Configuration
DEBUG = os.getenv('DEBUG', 'False').lower() in ('true', '1', 't')
SECRET_KEY = os.getenv('SECRET_KEY', 'sentinelsoc-dev-secret-key-change-in-production-2026')

# SQLite Database URI
SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', f"sqlite:///{str(DB_FILE).replace(os.sep, '/')}")
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Application Identity
APP_NAME = 'SentinelSOC'
APP_VERSION = '1.0.0'
APP_DESCRIPTION = 'Real-Time Security Operations Center & Threat Intelligence'

# Threat Detection Rules Configuration
THREAT_CONFIG = {
    # Rule A: Brute Force
    'brute_force': {
        'failed_attempts': 5,
        'time_window_minutes': 5,
        'critical_threshold': 10,
        'severity': 'HIGH'
    },
    
    # Rule B: Password Spraying
    'password_spraying': {
        'unique_users': 3,
        'time_window_minutes': 10,
        'severity': 'MEDIUM',
        'high_threshold_users': 5
    },
    
    # Rule C: Successful Login After Multiple Failures
    'login_after_failures': {
        'failed_attempts': 3,
        'time_window_minutes': 5,
        'severity': 'HIGH'
    },
    
    # Rule D: Account Enumeration
    'account_enumeration': {
        'unique_users': 4,
        'time_window_minutes': 15,
        'severity': 'MEDIUM'
    },
    
    # Rule E: Suspicious Access (Access Denied / Privilege Escalation)
    'suspicious_access': {
        'access_denied_threshold': 3,
        'time_window_minutes': 10,
        'severity': 'MEDIUM',
        'critical_threshold': 7
    },
    
    # Rule F: Unusual Login Time
    'unusual_login': {
        'normal_hours_start': 8,   # 08:00 AM
        'normal_hours_end': 20,    # 08:00 PM
        'severity': 'LOW'
    }
}

# Risk Scoring Thresholds (0-100 Scale)
RISK_THRESHOLDS = {
    'LOW': (0, 29),
    'MEDIUM': (30, 59),
    'HIGH': (60, 79),
    'CRITICAL': (80, 100)
}

# HTTP Security Headers
SECURITY_HEADERS = {
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
}
