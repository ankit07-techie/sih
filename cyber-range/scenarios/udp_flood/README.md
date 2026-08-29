# Scenario: UDP Flood Simulation
Generates high-rate UDP packet streams against local UDP service (`172.28.0.10:9999`) inside `threat-lab-network`.
Expected PassiveShield Result: `UDP_FLOOD` / `DDoSDetector` alert (`VOLUMETRIC_SURGE` & high `udp_pps` evidence).
