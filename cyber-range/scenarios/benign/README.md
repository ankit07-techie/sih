# Scenario: Benign Web & DNS Traffic
Generates ordinary TCP/HTTP GET & POST traffic and standard DNS domain resolution queries between generator (`172.28.0.20`) and victim (`172.28.0.10`) containers inside the isolated `threat-lab-network`.
Expected PassiveShield Result: `BENIGN` (0 alerts, 0.00 confidence, INFO severity).
