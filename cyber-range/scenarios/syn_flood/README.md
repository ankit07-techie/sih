# Scenario: SYN Flood Volumetric Simulation
Generates high-rate unacknowledged TCP SYN connection attempts against victim container (`172.28.0.10:80`) inside `threat-lab-network`.
Expected PassiveShield Result: `SYN_FLOOD` / `DDoSDetector` alert (`VOLUMETRIC_SURGE` & `SYN_FLOOD_SIGNAL` evidence).
