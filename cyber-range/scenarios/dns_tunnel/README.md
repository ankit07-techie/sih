# Scenario: DNS Subdomain Tunneling Simulation
Generates high-entropy TXT DNS queries containing long encoded payload subdomains against lab DNS service (`172.28.0.10:53`) inside `threat-lab-network`.
Expected PassiveShield Result: `DNS_TUNNEL` / `DNSAnomalyDetector` alert (`DNS_TUNNELING_EXFIL` & `HIGH_DOM_ENTROPY` evidence).
