"""
PassiveShield AI Cyber Range — Interactive Demonstration Menu
Provides an interactive menu [1]-[9] to execute threat scenarios in Docker lab and run PassiveShield detection pipeline.
"""

import os
import sys
import time
import subprocess

# Add repo root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from cyber_range.scripts.validate_results import validate_cyber_range_captures


SCENARIOS = [
    ("1", "Normal Traffic (Benign TCP/DNS)", "benign_tcp"),
    ("2", "SYN Flood Simulation", "syn_flood"),
    ("3", "UDP Flood Simulation", "udp_flood"),
    ("4", "Slow HTTP Simulation", "slow_http"),
    ("5", "DNS Tunnel Simulation", "dns_tunnel"),
    ("6", "DGA Domain Simulation", "dga"),
    ("7", "C2 Beaconing Simulation", "c2_beacon"),
    ("8", "Mixed Threat Scenario (Simultaneous)", "mixed"),
    ("9", "Run Full Automated Validation Suite", "full_suite"),
    ("0", "Exit Cyber Range Menu", "exit")
]


def display_menu():
    print("\n==========================================================")
    print("      PASSIVESHIELD AI — DOCKER CYBER RANGE DEMO          ")
    print("  SIH 26145: Passive Threat Detection in Unidirectional IP ")
    print("==========================================================")
    for key, label, _ in SCENARIOS:
        print(f"  [{key}] {label}")
    print("==========================================================")


def main():
    while True:
        display_menu()
        choice = input("Select an option [0-9]: ").strip()
        if choice == "0":
            print("[INFO] Exiting Cyber Range Menu.")
            break

        selected = next((item for item in SCENARIOS if item[0] == choice), None)
        if not selected:
            print("[WARN] Invalid selection. Please choose between 0 and 9.")
            continue

        key, label, scenario_key = selected
        print(f"\n[DEMO] Selected Option [{key}]: {label}")

        if scenario_key == "full_suite":
            validate_cyber_range_captures()
        else:
            print(f"[DEMO] Executing scenario '{scenario_key}' inside isolated lab network...")
            # Run simulation & capture via Docker Compose
            cmd = ["docker", "compose", "exec", "traffic-generator", "python3", "-u", "simulator/generator_cli.py", "--scenario", scenario_key, "--duration", "10"]
            print(f"[CMD] {' '.join(cmd)}")
            try:
                subprocess.run(cmd, cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
            except Exception as e:
                print(f"[INFO] Docker Compose execution fallback: {e}")

            # Run PassiveShield Validation
            validate_cyber_range_captures()

        input("\nPress Enter to return to menu...")


if __name__ == "__main__":
    main()
