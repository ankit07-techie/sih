# Scenario: Slow HTTP Connection Exhaustion Simulation
Creates multiple controlled long-lived low-rate HTTP header streams against victim (`172.28.0.10:80`) inside `threat-lab-network`.
Expected PassiveShield Result: `DDoSDetector` alert (`SLOW_HTTP_EXHAUSTION_DETECTED` evidence).
