"""
PassiveShield AI Cyber Range — Traffic Generator CLI
Command-line interface to execute isolated threat simulation scenarios inside threat-lab-network.
"""

import sys
import argparse
from scenarios import ScenarioSimulator


def main():
    parser = argparse.ArgumentParser(description="PassiveShield Cyber Range Traffic Generator CLI")
    parser.add_argument(
        "--scenario",
        default="mixed",
        choices=["benign_tcp", "benign_dns", "syn_flood", "udp_flood", "slow_http", "dns_tunnel", "dga", "c2_beacon", "mixed"],
        help="Scenario to simulate inside isolated lab network"
    )
    parser.add_argument("--duration", type=int, default=10, help="Simulation duration in seconds")

    args = parser.parse_args()

    scenario_map = {
        "benign_tcp": ScenarioSimulator.run_benign_tcp,
        "benign_dns": ScenarioSimulator.run_benign_dns,
        "syn_flood": ScenarioSimulator.run_syn_flood,
        "udp_flood": ScenarioSimulator.run_udp_flood,
        "slow_http": ScenarioSimulator.run_slow_http,
        "dns_tunnel": ScenarioSimulator.run_dns_tunnel,
        "dga": ScenarioSimulator.run_dga,
        "c2_beacon": ScenarioSimulator.run_c2_beacon,
        "mixed": ScenarioSimulator.run_mixed
    }

    fn = scenario_map.get(args.scenario, ScenarioSimulator.run_mixed)
    fn(duration_sec=args.duration)


if __name__ == "__main__":
    main()
