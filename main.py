"""
main.py — Entry point for the Rule-Based Network IDS.

Modes:
    python main.py                      # live capture (admin + Npcap required)
    python main.py --demo               # demo with synthetic traffic
    python main.py --dashboard-only     # just the dashboard
"""
import os
import sys
import time
import argparse
import threading
import random
import numpy as np
from queue import Queue, Empty

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import (
    FLOW_TIMEOUT_SEC, RULE_TIME_WINDOW_SEC,
    IP_BLOCK_COOLDOWN_SEC,
)
from features.feature_extractor import FeatureExtractor
from detection.rules import RuleEngine
from detection.alert_manager import AlertManager
from detection.ip_blocker_v2 import IPBlocker
from dashboard.app import DashboardState, start_dashboard


def parse_args():
    parser = argparse.ArgumentParser(
        description="Rule-Based Network Intrusion Detection & Prevention System"
    )
    parser.add_argument("--demo", action="store_true",
                        help="Run in demo mode with simulated traffic")
    parser.add_argument("--dashboard-only", action="store_true",
                        help="Start only the dashboard (no capture)")
    parser.add_argument("--interface", type=str, default=None,
                        help="Network interface to capture on")
    parser.add_argument("--no-block", action="store_true",
                        help="Disable auto IP blocking")
    return parser.parse_args()


def detection_loop(flow_queue: Queue, extractor: FeatureExtractor,
                   rule_engine: RuleEngine, alert_mgr: AlertManager,
                   ip_blocker: IPBlocker, dash_state: DashboardState,
                   running: threading.Event, auto_block: bool):
    """
    Main detection loop — rule-based evaluation and auto-response.

    Processes raw flows from live capture or demo traffic generator.
    Each flow is feature-extracted and evaluated against the rule engine.
    """
    while running.is_set():
        try:
            flow = flow_queue.get(timeout=1.0)
        except Empty:
            continue

        try:
            src_ip = flow.get("src_ip", "unknown")
            dst_ip = flow.get("dst_ip", "unknown")

            # Skip if IP already blocked
            if ip_blocker.is_blocked(src_ip):
                dash_state.update_flow(is_attack=True, label="Blocked IP",
                                       src_ip=src_ip)
                continue

            # Extract features from raw packets
            features = extractor.extract(flow)

            # Rule-based evaluation
            result = rule_engine.evaluate(features, src_ip=src_ip)

            # Update dashboard state
            dash_state.update_flow(
                is_attack=result["is_attack"],
                label=result["label"],
                src_ip=src_ip,
            )

            # Handle attacks
            if result["is_attack"]:
                action_taken = "Logged"

                # Auto-block confirmed attacks only (not Suspicious)
                is_blockable = ip_blocker.should_block(result["label"])
                is_on_cooldown = ip_blocker.is_cooled_down(src_ip)

                if auto_block and is_blockable and not is_on_cooldown:
                    block_result = ip_blocker.block_ip(
                        ip=src_ip,
                        attack_type=result["label"],
                    )
                    if block_result["status"] == "blocked":
                        action_taken = (
                            "IP Blocked (Firewall Rule Applied)"
                            if block_result.get("enforced")
                            else "IP Blocked (App Containment)"
                        )
                        dash_state.set_blocked_ips(ip_blocker.get_blocked_list())

                # Raise alert with rule explanation
                alert_mgr.raise_alert(
                    label=result["label"],
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    rule_triggered=result.get("rule_triggered", ""),
                    action_taken=action_taken,
                    severity=result.get("severity", "medium"),
                    explanation=result.get("explanation", ""),
                )
                dash_state.add_alert(alert_mgr.get_recent_alerts(1)[0])

        except Exception as e:
            print(f"  [!] Detection error: {e}")


def demo_traffic_loop(flow_queue: Queue, running: threading.Event):
    """Demo traffic generator using realistic synthetic flows."""
    from capture.demo_traffic import DemoTrafficGenerator

    generator = DemoTrafficGenerator()
    print("  Demo generator ready")

    while running.is_set():
        time.sleep(generator.next_sleep_interval())
        flow_queue.put(generator.next_flow())


def traffic_stats_loop(dash_state: DashboardState, packet_counter,
                       running: threading.Event):
    """Periodically update traffic history for dashboard charts."""
    while running.is_set():
        time.sleep(2.0)
        if packet_counter:
            dash_state.set_packet_count(packet_counter())
        dash_state.record_traffic_point()


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    args = parse_args()

    print("=" * 60)
    print("  Rule-Based Network Intrusion Detection & Prevention")
    print("  Detection + Classification + Auto-Response")
    print("=" * 60)

    # Shared state
    dash_state = DashboardState()
    running = threading.Event()
    running.set()

    # Start dashboard
    print("\n[1/5] Starting dashboard ...")
    start_dashboard(dash_state)

    if args.dashboard_only:
        print("\n  Dashboard-only mode. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n  Shutting down ...")
            return

    # Initialize rule engine
    print("\n[2/5] Loading rule-based detection engine ...")
    extractor = FeatureExtractor()
    rule_engine = RuleEngine(time_window=RULE_TIME_WINDOW_SEC)

    # Initialize alert manager + IP blocker
    print("\n[3/5] Initializing alert manager & IP blocker ...")
    alert_mgr = AlertManager()
    ip_blocker = IPBlocker(cooldown_seconds=IP_BLOCK_COOLDOWN_SEC)
    auto_block = not args.no_block
    if auto_block:
        print(f"  Auto-block enabled (cooldown: {ip_blocker.cooldown_seconds:.0f}s)")
        print(f"  Blocks: Port Scan, DoS/DDoS, SYN Flood, Brute Force, Web Attack")
        print(f"  Does NOT block: Suspicious Activity, Normal traffic")
    else:
        print("  Auto-block disabled")

    flow_queue = Queue(maxsize=1000)

    # Start packet capture or demo mode
    packet_counter = None

    if args.demo:
        print("\n[4/5] Starting DEMO traffic generator ...")
        demo_thread = threading.Thread(
            target=demo_traffic_loop,
            args=(flow_queue, running),
            daemon=True,
        )
        demo_thread.start()
        packet_counter_val = [0]

        def _fake_counter():
            packet_counter_val[0] += random.randint(10, 50)
            return packet_counter_val[0]
        packet_counter = _fake_counter
    else:
        print("\n[4/5] Starting live packet capture ...")
        try:
            from capture.packet_capture import PacketCapture
            capture = PacketCapture(
                flow_queue=flow_queue,
                interface=args.interface,
            )
            capture.start()
            packet_counter = lambda: capture.packet_count
        except Exception as e:
            print(f"\n  Failed to start capture: {e}")
            print("  Try running as Administrator, or use --demo mode")
            running.clear()
            return

    # Start detection loop
    print("\n[5/5] Starting rule-based detection engine ...")
    det_thread = threading.Thread(
        target=detection_loop,
        args=(flow_queue, extractor, rule_engine, alert_mgr, ip_blocker,
              dash_state, running, auto_block),
        daemon=True,
    )
    det_thread.start()

    # Traffic stats updater
    stats_thread = threading.Thread(
        target=traffic_stats_loop,
        args=(dash_state, packet_counter, running),
        daemon=True,
    )
    stats_thread.start()

    # Ready
    print("\n" + "=" * 60)
    print("  System is LIVE!")
    print(f"  Dashboard -> http://localhost:5000")
    print(f"  Detection: Rule-based engine ({RULE_TIME_WINDOW_SEC}s window)")
    if auto_block:
        print(f"  Auto-response: blocking attacker IPs (cooldown: {IP_BLOCK_COOLDOWN_SEC:.0f}s)")
    print("  Press Ctrl+C to stop.")
    print("=" * 60 + "\n")

    try:
        while running.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n\n  Shutting down gracefully ...")
        running.clear()
        if not args.demo and 'capture' in locals():
            capture.stop()

        # Print summary
        print(f"\n  Session Summary:")
        print(f"     Alerts raised : {alert_mgr.total_alerts}")
        print(f"     IPs blocked   : {ip_blocker.blocked_count}")
        top = alert_mgr.get_top_attackers(3)
        if top:
            print(f"     Top attackers : {top}")
        print("  System stopped.")


if __name__ == "__main__":
    main()
