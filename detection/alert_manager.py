"""
detection/alert_manager.py — Alert system with forensics and explanations.

Features:
  - Severity levels (critical / high / medium / low)
  - Human-readable rule explanations per alert
  - Structured JSON forensics log (logs/forensics.jsonl)
  - Top attacker IP tracking
  - Thread-safe with deque storage
"""
import os
import sys
import json
import datetime
import threading
from collections import deque, Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import ALERT_LOG_FILE, MAX_ALERTS_STORED, LOGS_DIR


class AlertManager:
    """Thread-safe alert manager with console + file + forensics logging."""

    def __init__(self):
        self._alerts = deque(maxlen=MAX_ALERTS_STORED)
        self._lock = threading.Lock()
        self._alert_count = 0
        self._attacker_counter = Counter()

        os.makedirs(os.path.dirname(ALERT_LOG_FILE), exist_ok=True)
        self._forensics_path = os.path.join(LOGS_DIR, "forensics.jsonl")

    def raise_alert(self, label: str, src_ip: str, dst_ip: str,
                    rule_triggered: str, severity: str = "medium",
                    action_taken: str = "Logged",
                    explanation: str = ""):
        """Generate an alert with full context and rule explanation."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        alert = {
            "id": self._alert_count + 1,
            "timestamp": timestamp,
            "label": str(label),
            "src_ip": str(src_ip),
            "dst_ip": str(dst_ip),
            "rule_triggered": str(rule_triggered),
            "action_taken": str(action_taken),
            "severity": str(severity),
            "explanation": str(explanation),
        }

        with self._lock:
            self._alerts.append(alert)
            self._alert_count += 1
            self._attacker_counter[src_ip] += 1

        self._print_alert(alert)
        self._log_alert(alert)
        self._log_forensics(alert)

    def _print_alert(self, alert: dict):
        """Print a formatted alert to console."""
        severity_icons = {
            "critical": "!!", "high": "! ",
            "medium": "* ", "low": "- ", "none": "  ",
        }
        sev_icon = severity_icons.get(alert["severity"], "  ")
        action_icon = "BLOCK" if "Blocked" in alert["action_taken"] else "LOG"

        print(f"\n  [{sev_icon}] ALERT #{alert['id']}  |  {alert['timestamp']}  |  {alert['severity'].upper()}")
        print(f"      Attack    : {alert['label']}")
        print(f"      Source    : {alert['src_ip']}  ->  {alert['dst_ip']}")
        print(f"      Rule      : {alert['rule_triggered']}")
        print(f"      Action    : [{action_icon}] {alert['action_taken']}")
        if alert["explanation"]:
            print(f"      Reason    : {alert['explanation'][:90]}")
        print(f"  {'_' * 55}")

    def _log_alert(self, alert: dict):
        """Append alert to plain-text log file."""
        try:
            with open(ALERT_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(
                    f"[{alert['timestamp']}] [{alert['severity'].upper()}] "
                    f"{alert['label']} | "
                    f"{alert['src_ip']} -> {alert['dst_ip']} | "
                    f"rule={alert['rule_triggered']} | "
                    f"action={alert['action_taken']} | "
                    f"reason={alert['explanation']}\n"
                )
        except OSError:
            pass

    def _log_forensics(self, alert: dict):
        """Append structured JSON to forensics log."""
        try:
            with open(self._forensics_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def get_recent_alerts(self, n: int = 50) -> list:
        """Return the most recent *n* alerts (newest first)."""
        with self._lock:
            return list(reversed(list(self._alerts)))[:n]

    @property
    def total_alerts(self) -> int:
        return self._alert_count

    def get_attack_stats(self) -> dict:
        """Return a count of each attack type seen."""
        stats = {}
        with self._lock:
            for alert in self._alerts:
                lbl = alert["label"]
                stats[lbl] = stats.get(lbl, 0) + 1
        return stats

    def get_top_attackers(self, n: int = 10) -> list:
        """Return the top N attacker IPs by frequency."""
        with self._lock:
            return [{"ip": ip, "count": count}
                    for ip, count in self._attacker_counter.most_common(n)]
