# Prompt 37 — Bug Fix

BUG:
<INSERT ERROR OR BEHAVIOR>

Do not rewrite immediately.

1. inspect Git state/recent commits
2. read relevant docs
3. reproduce
4. isolate module
5. trace input → transformation → state → output
6. identify root cause
7. propose smallest safe fix

Then:
- implement fix
- add regression test
- run regression + affected tests
- inspect diff
- commit: fix(<module>): <specific issue>
- push without force
- verify clean status

Report reproduction, root cause, fix, tests, commit hash, and rollback reference.
Stop.
