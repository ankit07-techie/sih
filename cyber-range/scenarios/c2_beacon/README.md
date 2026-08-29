# Scenario: Periodic C2 Beaconing Simulation
Establishes periodic outbound TCP TLS connections at fixed 2-second intervals to HTTPS service (`172.28.0.10:443`) inside `threat-lab-network`.
Expected PassiveShield Result: `C2_BEACONING` / `C2BeaconDetector` alert (`PERIODIC_BEACONING_SIGNAL` & `PERIODIC_BEACONING_FALLBACK` evidence).
