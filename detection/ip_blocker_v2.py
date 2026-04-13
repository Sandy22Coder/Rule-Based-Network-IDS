"""
detection/ip_blocker_v2.py — IP blocking with cooldown and firewall support.

Blocks ONLY confirmed attack types (Port Scan, DoS/DDoS, SYN Flood,
Web Attack). Does NOT block Suspicious Activity or Normal traffic.

Cooldown: 60 seconds per IP to prevent repeated blocking actions.
"""
from __future__ import annotations

import datetime
import json
import os
import platform
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import LOGS_DIR


# Attack types that warrant automatic blocking
BLOCKABLE_ATTACKS = {"Port Scan", "DoS/DDoS", "SYN Flood", "Brute Force", "Web Attack"}


class IPBlocker:
    """Manage blocked IPs with cooldown and firewall enforcement."""

    def __init__(self, cooldown_seconds: float = 60.0):
        """
        Args:
            cooldown_seconds: after blocking an IP, ignore repeat block
                              requests for this many seconds (default 60s).
        """
        self._blocked: dict[str, dict] = {}
        self._cooldowns: dict[str, float] = {}
        self._lock = threading.Lock()
        self.cooldown_seconds = cooldown_seconds
        self._is_linux = platform.system() == "Linux"
        self._is_windows = platform.system() == "Windows"
        self._block_count = 0
        self._state_path = os.path.join(LOGS_DIR, "blocked_ips.json")
        self.whitelist = {
            "127.0.0.1",
            "0.0.0.0",
            "localhost",
            "192.168.1.1",
            "10.0.0.1",
        }

    def should_block(self, attack_type: str) -> bool:
        """Only block confirmed attack types, never Suspicious or Normal."""
        return attack_type in BLOCKABLE_ATTACKS

    def _is_cooled_down_unlocked(self, ip: str) -> bool:
        """Check cooldown WITHOUT acquiring the lock (caller must hold it)."""
        last_block = self._cooldowns.get(ip, 0.0)
        return (time.time() - last_block) < self.cooldown_seconds

    def is_cooled_down(self, ip: str) -> bool:
        """Check if an IP is still in cooldown (recently blocked). Thread-safe."""
        with self._lock:
            return self._is_cooled_down_unlocked(ip)

    def block_ip(self, ip: str, attack_type: str) -> dict:
        if ip in self.whitelist:
            return {"status": "whitelisted", "ip": ip}

        with self._lock:
            if ip in self._blocked:
                self._blocked[ip]["hit_count"] += 1
                if self._is_cooled_down_unlocked(ip):
                    self._persist_blocklist()
                    return {
                        "status": "cooldown",
                        "ip": ip,
                        "message": f"Cooldown active ({self.cooldown_seconds:.0f}s)",
                        **self._blocked[ip],
                    }
                self._persist_blocklist()
                return {"status": "already_blocked", "ip": ip, **self._blocked[ip]}

            entry = {
                "ip": ip,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "attack_type": attack_type,
                "hit_count": 1,
                "enforced": False,
                "mode": "app_containment",
                "details": "",
            }
            self._blocked[ip] = entry
            self._cooldowns[ip] = time.time()
            self._block_count += 1

        enforced, mode, details = self._enforce_block(ip)
        with self._lock:
            self._blocked[ip]["enforced"] = enforced
            self._blocked[ip]["mode"] = mode
            self._blocked[ip]["details"] = details
            self._persist_blocklist()

        action = "BLOCKED (Firewall Rule Applied)" if enforced else "BLOCKED (App Containment)"
        print(f"  BLOCK {action}: {ip} [{attack_type}]")

        return {
            "status": "blocked",
            "ip": ip,
            "enforced": enforced,
            "attack_type": attack_type,
            "mode": mode,
            "details": details,
        }

    def _enforce_block(self, ip: str) -> tuple[bool, str, str]:
        if self._is_linux:
            try:
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True, capture_output=True, timeout=5,
                )
                return True, "firewall", "iptables INPUT DROP rule created"
            except (subprocess.CalledProcessError, FileNotFoundError,
                    subprocess.TimeoutExpired) as exc:
                return False, "app_containment", f"iptables unavailable: {type(exc).__name__}"

        if self._is_windows:
            rule_base = f"IDS_BLOCK_{ip}"
            commands = [
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_base}_IN", "dir=in", "action=block",
                    f"remoteip={ip}",
                ],
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_base}_OUT", "dir=out", "action=block",
                    f"remoteip={ip}",
                ],
            ]
            try:
                for cmd in commands:
                    subprocess.run(cmd, check=True, capture_output=True, timeout=5)
                return True, "firewall", "Windows Defender Firewall rules added"
            except (subprocess.CalledProcessError, FileNotFoundError,
                    subprocess.TimeoutExpired) as exc:
                return False, "app_containment", f"Firewall rule failed: {type(exc).__name__}"

        return False, "app_containment", "Platform firewall not configured"

    def unblock_ip(self, ip: str) -> bool:
        with self._lock:
            if ip in self._blocked:
                del self._blocked[ip]
                self._cooldowns.pop(ip, None)
                self._persist_blocklist()
                return True
        return False

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked

    def get_blocked_list(self) -> list:
        with self._lock:
            return sorted(self._blocked.values(),
                          key=lambda x: x["timestamp"], reverse=True)

    @property
    def blocked_count(self) -> int:
        with self._lock:
            return len(self._blocked)

    @property
    def total_blocks(self) -> int:
        return self._block_count

    def _persist_blocklist(self):
        try:
            with open(self._state_path, "w", encoding="utf-8") as f:
                json.dump(list(self._blocked.values()), f,
                          ensure_ascii=False, indent=2)
        except OSError:
            pass
