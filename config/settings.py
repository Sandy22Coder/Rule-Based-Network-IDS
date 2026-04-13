"""
config/settings.py — Central configuration for the Rule-Based Network IDS.
"""
import os

# ── Project root (auto-detected) ─────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── Data paths ────────────────────────────────────────────────────────────
RAW_DATA_DIR = os.path.join(PROJECT_ROOT, "data")
PROCESSED_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")

# ── Rule Engine Settings ─────────────────────────────────────────────────
RULE_TIME_WINDOW_SEC = 10.0          # sliding window for per-IP correlation
IP_BLOCK_COOLDOWN_SEC = 60.0         # 60-second cooldown before re-blocking an IP

# ── Real-time capture ────────────────────────────────────────────────────
FLOW_TIMEOUT_SEC = 2.0               # aggregate packets into flows every N sec
CAPTURE_INTERFACE = None             # None = default interface

# ── Dashboard ─────────────────────────────────────────────────────────────
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5000
MAX_ALERTS_STORED = 500              # keep last N alerts in memory

# ── Alert thresholds ──────────────────────────────────────────────────────
ALERT_LOG_FILE = os.path.join(LOGS_DIR, "alerts.log")

# ── Ensure directories exist ─────────────────────────────────────────────
for d in [PROCESSED_DATA_DIR, MODELS_DIR, LOGS_DIR]:
    os.makedirs(d, exist_ok=True)
