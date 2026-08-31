# Debugging Guide

## Required sequence
1. reproduce
2. identify module boundary
3. inspect relevant logs
4. trace input → transformation → state → output
5. identify root cause
6. propose smallest safe fix
7. add regression test
8. run affected tests
9. inspect diff
10. commit and push

Do not rewrite an entire subsystem before reproducing and isolating the problem.

Useful debugging artifacts:
- deterministic fixtures
- replay scenarios
- structured logs
- feature snapshots
- alert evidence
- commit history
