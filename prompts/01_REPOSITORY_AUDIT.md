# Prompt 01 — Repository Audit

Perform a read-only repository inspection first.

Inspect:
- structure
- code
- services
- dependencies
- contracts
- tests
- configuration
- Docker/infrastructure
- placeholders/incomplete code

Create docs/PROJECT_STATE_AUDIT.md containing:
- current functional state
- incomplete areas
- dependency observations
- debugging risks
- documented requirement gaps

Do not fix code.

Before commit:
- inspect diff
- ensure only intended audit documentation changed

Commit:
docs: add project state audit

Push without force.
Verify clean status.
Report files changed, commit hash, and push result.
Stop.
