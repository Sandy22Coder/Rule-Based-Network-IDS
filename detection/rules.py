"""
detection/rules.py — Rule-Based Intrusion Detection Engine.

Deterministic, signature-based detection using raw traffic features.
Each rule inspects per-source-IP flow statistics within a sliding
time window and applies threshold-based conditions.

Detection Rules:
  1. SYN Flood       — Excess SYN packets without ACK responses
  2. DoS / DDoS      — Extremely high packet rate detected
  3. Port Scan       — Multiple ports accessed in short time
  4. Brute Force     — Repeated auth-service connection attempts
  5. Web Attack      — Abnormal HTTP/HTTPS request pattern detected
  6. Suspicious      — Deviates from normal but no specific match
"""
from __future__ import annotations

import os
import sys
import time
import threading
import numpy as np
from collections import defaultdict, deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from features.feature_config import FEATURE_NAMES


# ── Rule Explanations (human-readable) ───────────────────────────────────
RULE_EXPLANATIONS = {
    "Port Scan": "Multiple ports accessed in short time — network reconnaissance detected",
    "DoS/DDoS": "Extremely high packet rate detected — denial-of-service attempt",
    "SYN Flood": "Excess SYN packets without ACK responses — connection resource exhaustion",
    "Brute Force": "Repeated authentication service connections — credential guessing attempt",
    "Web Attack": "Abnormal HTTP/HTTPS request pattern detected — possible exploitation",
    "Suspicious Activity (Needs Monitoring)": "Traffic deviates from normal baselines — manual review recommended",
    "Normal": "Standard traffic pattern — no threat indicators",
}


class _IPTracker:
    """Per-source-IP sliding-window tracker for time-based rule conditions.

    Maintains:
        flow_stats[src_ip] = {
            packets_per_second,
            unique_ports,
            syn_count,
            ack_count,
            timestamps
        }
    """

    def __init__(self, window_seconds: float = 10.0):
        self.window = window_seconds
        self._events: deque = deque()

    def record(self, timestamp: float, port: int, signals: dict):
        """Record a flow event and prune entries older than the window."""
        self._events.append({
            "time": timestamp,
            "port": port,
            "signals": signals,
        })
        self._prune(timestamp)

    def _prune(self, now: float):
        while self._events and now - self._events[0]["time"] > self.window:
            self._events.popleft()

    @property
    def unique_ports(self) -> set:
        """Distinct destination ports seen within the window."""
        return {e["port"] for e in self._events if e["port"] > 0}

    @property
    def flow_count(self) -> int:
        """Number of flows within the window."""
        return len(self._events)

    @property
    def total_syn_count(self) -> int:
        """Aggregate SYN flag count across all flows in window."""
        return sum(int(round(e["signals"].get("syn_flag_count", 0)))
                   for e in self._events)

    @property
    def total_ack_count(self) -> int:
        """Aggregate ACK flag count across all flows in window."""
        return sum(int(round(e["signals"].get("ack_flag_count", 0)))
                   for e in self._events)

    @property
    def avg_packets_per_second(self) -> float:
        """Average packets/s across flows in window."""
        rates = [float(e["signals"].get("flow_pkts_per_s", 0))
                 for e in self._events]
        return sum(rates) / len(rates) if rates else 0.0

    @property
    def total_fwd_packets(self) -> int:
        """Total forward packets across all flows in window."""
        return sum(int(round(e["signals"].get("total_fwd_packets", 0)))
                   for e in self._events)

    @property
    def auth_port_hits(self) -> int:
        return sum(1 for e in self._events
                   if e["port"] in {21, 22, 25, 110, 143, 3389})

    @property
    def web_port_hits(self) -> int:
        return sum(1 for e in self._events
                   if e["port"] in {80, 443, 8080, 8000})

    @property
    def recent_signals(self) -> list[dict]:
        return [e["signals"] for e in self._events]


class RuleEngine:
    """
    Deterministic rule-based intrusion detection engine.

    Processes raw (unscaled) 20-feature vectors and applies a prioritized
    chain of rules. Per-IP history is maintained for time-window conditions.

    Thresholds (per-IP, within 10s window):
        Port Scan:  unique_ports > 5  (per-flow) or > 50 (aggregate)
        DoS/DDoS:   packets_per_second > 1000 (aggregate)
        SYN Flood:  syn_count > 100 AND ack_count < 10 (aggregate)
        Suspicious: packets_per_second > 300 AND unique_ports > 20
    """

    def __init__(self, time_window: float = 10.0):
        self._ip_trackers: dict[str, _IPTracker] = defaultdict(
            lambda: _IPTracker(window_seconds=time_window)
        )
        self._lock = threading.Lock()
        self.time_window = time_window

        print(f"  Rule engine initialized (time-window={time_window}s)")
        print(f"  {len(self._get_rules())} detection rules loaded")

    # ── Public API ────────────────────────────────────────────────────────

    def evaluate(self, features: np.ndarray, src_ip: str = "unknown") -> dict:
        """
        Evaluate a feature vector against all rules.

        Args:
            features:  (1, 20) numpy array of RAW traffic features
            src_ip:    source IP for per-IP tracking

        Returns:
            dict with keys: label, is_attack, rule_triggered, severity,
                            explanation, signals, action_recommended
        """
        signals = self._extract_signals(features)
        now = time.time()
        port = int(signals.get("destination_port", 0))

        # Record in per-IP tracker
        with self._lock:
            tracker = self._ip_trackers[src_ip]
            tracker.record(now, port, signals)

        # Build result skeleton
        result = {
            "label": "Normal",
            "is_attack": False,
            "rule_triggered": "None",
            "severity": "none",
            "explanation": RULE_EXPLANATIONS["Normal"],
            "signals": signals,
            "action_recommended": "Allow",
        }

        # Evaluate rules in priority order (first match wins)
        for rule_fn in self._get_rules():
            match = rule_fn(signals, tracker)
            if match is not None:
                result["label"] = match["label"]
                result["is_attack"] = True
                result["rule_triggered"] = match["rule_triggered"]
                result["severity"] = match["severity"]
                result["explanation"] = match["explanation"]
                result["action_recommended"] = match.get("action", "Block")
                break

        return result

    # ── Signal extraction ────────────────────────────────────────────────

    @staticmethod
    def _extract_signals(features: np.ndarray) -> dict:
        """Map the 20-element feature array to a named dict."""
        row = features[0] if features.ndim == 2 else features
        return {name: float(row[idx]) for idx, name in enumerate(FEATURE_NAMES)}

    # ── Rule chain (ordered by priority) ─────────────────────────────────

    def _get_rules(self):
        """Return the ordered list of rule functions."""
        return [
            self._rule_syn_flood,
            self._rule_dos_ddos,
            self._rule_port_scan,
            self._rule_brute_force,
            self._rule_web_attack,
            self._rule_suspicious,
        ]

    # ── Individual Rules ─────────────────────────────────────────────────

    def _rule_syn_flood(self, signals: dict, tracker: _IPTracker) -> dict | None:
        """
        SYN Flood Detection
        Single-flow: SYN >= 10, ACK <= 15% of SYN, high packet rate
        Aggregate:   Total SYN > 100, Total ACK < 10 (within 10s window)
        """
        syn = int(round(signals.get("syn_flag_count", 0)))
        ack = int(round(signals.get("ack_flag_count", 0)))
        pkts_per_s = float(signals.get("flow_pkts_per_s", 0))

        # Single-flow detection
        if syn >= 10 and ack <= max(2, int(syn * 0.15)) and pkts_per_s >= 200:
            return {
                "label": "SYN Flood",
                "rule_triggered": "SYN Flood — Single Flow",
                "severity": "critical",
                "explanation": (
                    f"{RULE_EXPLANATIONS['SYN Flood']} | "
                    f"SYN={syn}, ACK={ack}, Rate={pkts_per_s:.0f} pkt/s"
                ),
                "action": "Block",
            }

        # Aggregate time-window detection
        total_syn = tracker.total_syn_count
        total_ack = tracker.total_ack_count
        if total_syn > 100 and total_ack < 10:
            return {
                "label": "SYN Flood",
                "rule_triggered": "SYN Flood — Time-Window Aggregate",
                "severity": "critical",
                "explanation": (
                    f"{RULE_EXPLANATIONS['SYN Flood']} | "
                    f"Aggregate: {total_syn} SYN, {total_ack} ACK across "
                    f"{tracker.flow_count} flows in {self.time_window}s"
                ),
                "action": "Block",
            }
        return None

    def _rule_dos_ddos(self, signals: dict, tracker: _IPTracker) -> dict | None:
        """
        DoS/DDoS Detection
        Single-flow: pkt/s >= 250, fwd >= 30, asymmetric traffic
        Aggregate:   avg packets/s > 1000 across window
        """
        pkts_per_s = float(signals.get("flow_pkts_per_s", 0))
        bytes_per_s = float(signals.get("flow_bytes_per_s", 0))
        fwd = int(round(signals.get("total_fwd_packets", 0)))
        bwd = int(round(signals.get("total_bwd_packets", 0)))

        # Single-flow: high-rate flood
        if (
            ((pkts_per_s >= 250 and fwd >= 30) or bytes_per_s >= 180_000)
            and bwd <= max(4, int(fwd * 0.25))
        ):
            return {
                "label": "DoS/DDoS",
                "rule_triggered": "DoS/DDoS — High Rate Flood",
                "severity": "critical",
                "explanation": (
                    f"{RULE_EXPLANATIONS['DoS/DDoS']} | "
                    f"Rate={pkts_per_s:.0f} pkt/s, Fwd={fwd}, Bwd={bwd}"
                ),
                "action": "Block",
            }

        # Aggregate time-window: sustained high rate
        avg_pps = tracker.avg_packets_per_second
        if avg_pps > 1000 and tracker.flow_count >= 3:
            return {
                "label": "DoS/DDoS",
                "rule_triggered": "DoS/DDoS — Sustained High Rate",
                "severity": "critical",
                "explanation": (
                    f"{RULE_EXPLANATIONS['DoS/DDoS']} | "
                    f"Aggregate avg={avg_pps:.0f} pkt/s across "
                    f"{tracker.flow_count} flows in {self.time_window}s"
                ),
                "action": "Block",
            }

        # Sustained burst (multiple high-rate flows)
        flood_hits = sum(
            1 for s in tracker.recent_signals
            if float(s.get("flow_pkts_per_s", 0)) > 200
            or int(round(s.get("total_fwd_packets", 0))) >= 25
        )
        if flood_hits >= 4 and tracker.flow_count >= 5:
            return {
                "label": "DoS/DDoS",
                "rule_triggered": "DoS/DDoS — Burst Pattern",
                "severity": "critical",
                "explanation": (
                    f"{RULE_EXPLANATIONS['DoS/DDoS']} | "
                    f"{flood_hits} high-rate flows from same source "
                    f"within {self.time_window}s"
                ),
                "action": "Block",
            }
        return None

    def _rule_port_scan(self, signals: dict, tracker: _IPTracker) -> dict | None:
        """
        Port Scan Detection
        Single-flow: Short SYN probe (fwd<=4, bwd<=1, SYN>=1, duration<=0.35s)
        Aggregate:   unique_ports > 5 from same IP within window
        """
        fwd = int(round(signals.get("total_fwd_packets", 0)))
        bwd = int(round(signals.get("total_bwd_packets", 0)))
        syn = int(round(signals.get("syn_flag_count", 0)))
        ack = int(round(signals.get("ack_flag_count", 0)))
        rst = int(round(signals.get("rst_flag_count", 0)))
        duration_us = float(signals.get("flow_duration", 0))
        duration_s = max(duration_us / 1e6, 0.0)
        avg_size = float(signals.get("avg_packet_size", 0))

        distinct_ports = tracker.unique_ports

        # Single-flow SYN probe signature
        if (fwd <= 4 and bwd <= 1 and syn >= 1 and ack <= 1
                and duration_s <= 0.35 and avg_size <= 120):
            return {
                "label": "Port Scan",
                "rule_triggered": "Port Scan — SYN Probe",
                "severity": "high",
                "explanation": (
                    f"{RULE_EXPLANATIONS['Port Scan']} | "
                    f"{len(distinct_ports)} unique ports probed in "
                    f"{self.time_window}s window"
                ),
                "action": "Block",
            }

        # Aggregate: many distinct ports from same IP
        if len(distinct_ports) >= 6:
            syn_present = any(
                int(round(s.get("syn_flag_count", 0))) >= 1
                for s in tracker.recent_signals
            )
            if syn_present:
                return {
                    "label": "Port Scan",
                    "rule_triggered": "Port Scan — Multi-Port Sweep",
                    "severity": "high",
                    "explanation": (
                        f"{RULE_EXPLANATIONS['Port Scan']} | "
                        f"{len(distinct_ports)} distinct ports from same IP "
                        f"within {self.time_window}s"
                    ),
                    "action": "Block",
                }
        return None

    def _rule_brute_force(self, signals: dict, tracker: _IPTracker) -> dict | None:
        """
        Brute Force Detection
        Single-flow: Auth port, short exchange with RST
        Aggregate:   5+ auth-port connections within window
        """
        port = int(signals.get("destination_port", 0))
        fwd = int(round(signals.get("total_fwd_packets", 0)))
        syn = int(round(signals.get("syn_flag_count", 0)))
        rst = int(round(signals.get("rst_flag_count", 0)))
        bwd = int(round(signals.get("total_bwd_packets", 0)))
        duration_us = float(signals.get("flow_duration", 0))
        duration_s = max(duration_us / 1e6, 0.0)

        AUTH_PORTS = {21, 22, 25, 110, 143, 3389}

        # Single-flow signature
        if (port in AUTH_PORTS and fwd >= 3 and syn >= 1
                and duration_s <= 2.0 and (rst >= 1 or bwd <= 2)):
            return {
                "label": "Brute Force",
                "rule_triggered": "Brute Force — Auth Service Attack",
                "severity": "high",
                "explanation": (
                    f"{RULE_EXPLANATIONS['Brute Force']} | "
                    f"Target port: {port}, Fwd={fwd}, RST={rst}"
                ),
                "action": "Block",
            }

        # Aggregate: repeated auth-port connections
        auth_hits = tracker.auth_port_hits
        if auth_hits >= 5:
            return {
                "label": "Brute Force",
                "rule_triggered": "Brute Force — Repeated Auth Attempts",
                "severity": "high",
                "explanation": (
                    f"{RULE_EXPLANATIONS['Brute Force']} | "
                    f"{auth_hits} auth-port connections within {self.time_window}s"
                ),
                "action": "Block",
            }
        return None

    def _rule_web_attack(self, signals: dict, tracker: _IPTracker) -> dict | None:
        """
        Web Attack Detection
        Single-flow: Web port, many PSH flags, small payloads
        Aggregate:   4+ suspicious web flows within window
        """
        port = int(signals.get("destination_port", 0))
        fwd = int(round(signals.get("total_fwd_packets", 0)))
        bwd = int(round(signals.get("total_bwd_packets", 0)))
        psh = int(round(signals.get("fwd_psh_flags", 0)))
        duration_us = float(signals.get("flow_duration", 0))
        duration_s = max(duration_us / 1e6, 0.0)
        avg_size = float(signals.get("avg_packet_size", 0))

        WEB_PORTS = {80, 443, 8080, 8000}

        # Single-flow exploit pattern
        if (port in WEB_PORTS and fwd >= 5 and bwd >= 2
                and psh >= 2 and duration_s <= 4.0 and avg_size <= 500):
            return {
                "label": "Web Attack",
                "rule_triggered": "Web Attack — Exploit Pattern",
                "severity": "high",
                "explanation": (
                    f"{RULE_EXPLANATIONS['Web Attack']} | "
                    f"Port={port}, PSH flags={psh}, Avg size={avg_size:.0f}B"
                ),
                "action": "Block",
            }

        # Aggregate: repeated suspicious web flows
        web_hits = tracker.web_port_hits
        psh_flows = sum(
            1 for s in tracker.recent_signals
            if int(round(s.get("fwd_psh_flags", 0))) >= 1
            and int(s.get("destination_port", 0)) in WEB_PORTS
        )
        if psh_flows >= 4:
            return {
                "label": "Web Attack",
                "rule_triggered": "Web Attack — Repeated Probes",
                "severity": "high",
                "explanation": (
                    f"{RULE_EXPLANATIONS['Web Attack']} | "
                    f"{psh_flows} suspicious web requests within {self.time_window}s"
                ),
                "action": "Block",
            }
        return None

    def _rule_suspicious(self, signals: dict, tracker: _IPTracker) -> dict | None:
        """
        Suspicious Activity (Needs Monitoring)
        Catch-all for traffic that deviates from normal but doesn't
        match a specific attack signature.
        """
        fwd = int(round(signals.get("total_fwd_packets", 0)))
        bwd = int(round(signals.get("total_bwd_packets", 0)))
        syn = int(round(signals.get("syn_flag_count", 0)))
        pkts_per_s = float(signals.get("flow_pkts_per_s", 0))
        avg_size = float(signals.get("avg_packet_size", 0))
        duration_us = float(signals.get("flow_duration", 0))
        duration_s = max(duration_us / 1e6, 0.0)

        reasons = []

        # Asymmetric traffic
        if fwd >= 8 and bwd <= 1 and syn <= 2:
            reasons.append(f"Asymmetric traffic ({fwd} fwd / {bwd} bwd)")

        # Elevated packet rate (above 300 pps but below DoS threshold)
        if pkts_per_s > 300 and len(tracker.unique_ports) > 20:
            reasons.append(
                f"High rate + many ports ({pkts_per_s:.0f} pps, "
                f"{len(tracker.unique_ports)} ports)"
            )

        # Elevated packet rate alone
        if 120 <= pkts_per_s < 250 and fwd >= 10:
            reasons.append(f"Elevated packet rate ({pkts_per_s:.0f} pkt/s)")

        # Burst of SYNs
        if duration_s <= 0.1 and syn >= 3:
            reasons.append(f"Burst of {syn} SYNs in {duration_s*1000:.0f}ms")

        # Tiny packets (possible tunneling)
        if 0 < avg_size <= 60 and fwd >= 5:
            reasons.append(f"Tiny packets (avg {avg_size:.0f} bytes)")

        # High flow rate from same IP
        if tracker.flow_count >= 8:
            reasons.append(
                f"High flow rate: {tracker.flow_count} flows in {self.time_window}s"
            )

        if reasons:
            return {
                "label": "Suspicious Activity (Needs Monitoring)",
                "rule_triggered": "Suspicious Activity — Threshold Exceeded",
                "severity": "medium" if len(reasons) >= 2 else "low",
                "explanation": (
                    f"{RULE_EXPLANATIONS['Suspicious Activity (Needs Monitoring)']} | "
                    f"Triggers: {'; '.join(reasons)}"
                ),
                "action": "Monitor",
            }
        return None
