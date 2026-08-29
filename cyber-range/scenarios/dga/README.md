# Scenario: DGA Algorithmic Domain Simulation
Generates high-entropy pseudo-random domain queries returning NXDOMAIN responses against lab DNS service (`172.28.0.10:53`) inside `threat-lab-network`.
Expected PassiveShield Result: `DGA_SUSPICIOUS` / `DNSAnomalyDetector` alert (`DGA_HIGH_DIGIT_RATIO` & `HIGH_DOM_ENTROPY` evidence).
