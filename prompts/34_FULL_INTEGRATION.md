# Prompt 34 — Controlled Full Integration

Integrate approved modules incrementally.

For each integration:
- validate contracts
- run deterministic replay
- verify alert evidence
- verify downstream delivery

Do not hide unrelated fixes.

Use separate logical commits when integration reveals independent fixes.

Push each verified commit without force.
Stop after reporting all commits.
