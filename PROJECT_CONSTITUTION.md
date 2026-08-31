# PassiveShield AI — Project Constitution

## 1. Mission
Build a modular, explainable cyber-threat detection platform for passive, unidirectional IP traffic.

Core principle:

**Observe Everything. Touch Nothing. Detect Intelligently. Explain Clearly.**

## 2. Priority scope
P0:
1. DDoS / SYN or UDP Flood
2. Reconnaissance / Port Scanning
3. Botnet C2 Beaconing
4. DNS anomalies including DGA-like behavior and DNS tunnelling

P1: Data Exfiltration
P2: Encrypted-malware metadata detection when reliable metadata exists.

## 3. Non-negotiable passive boundary
The monitored network is read-only from PassiveShield's perspective.

Never:
- actively probe monitored assets
- perform port scanning
- inject packets
- initiate monitored-network handshakes
- modify or block monitored traffic
- assume a return path
- require payload decryption merely to enable detection

Internal application communication outside the monitored boundary is allowed.

## 4. Architecture principles
1. One clear responsibility per module.
2. Explicit, versioned contracts between modules.
3. Detectors consume stable feature inputs.
4. Detectors do not directly depend on UI or persistence.
5. Frontend changes do not change detection logic.
6. Storage changes do not change detector algorithms.
7. State must be bounded and observable.
8. Every alert must expose structured evidence.
9. Deterministic replay is required for demonstration and debugging.
10. Never claim measurements that were not actually measured.

## 5. Change principles
Prefer the smallest safe change.
Do not hide unrelated refactors inside feature work.
Do not silently introduce breaking contract changes.
Breaking changes require impact analysis and migration planning.

## 6. Task protocol
Before a task:
- inspect git status and branch
- read relevant docs
- inspect recent relevant commits
- identify scope and affected files

During:
- stay inside approved scope
- preserve unrelated work
- add tests when behavior changes

Before commit:
- run relevant tests
- inspect git diff and diff stat
- verify no secrets/debug artifacts
- verify documentation impact

After:
- create one logical descriptive commit
- push without force
- verify working tree
- report commit hash and results
- stop

## 7. Approval gates
Explicit human approval is required before:
- deleting repositories, databases, or large datasets
- force pushing
- changing credentials
- publishing externally
- deploying externally
- changing firewall or production-network settings

## 8. Definition of done
Code alone is not done.

A task is complete only when relevant implementation, tests, verification, documentation impact, Git commit, and push are complete.
