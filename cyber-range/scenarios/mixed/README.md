# Scenario: Mixed Threat Simulation
Simultaneously generates benign TCP web traffic, benign DNS lookups, SYN flood simulation, UDP flood simulation, Slow HTTP exhaustion, DNS subdomain tunneling, DGA domain generation, and C2 periodic beaconing inside the isolated Docker lab network.
Target: `VICTIM_IP` (172.28.0.10)
Expected PassiveShield Result: Multi-vector threat alerts (`SYN_FLOOD`, `UDP_FLOOD`, `SLOW_HTTP`, `DNS_TUNNEL`, `DGA_SUSPICIOUS`, `C2_BEACONING`) with preserved benign flow context.
