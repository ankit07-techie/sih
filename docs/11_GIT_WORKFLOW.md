# Git Workflow

## Core rule
One meaningful task should normally create one logical commit.

## Before work
- inspect status
- inspect branch
- inspect relevant recent commits
- never overwrite uncommitted user work

## Commit style
Examples:
- docs: add architecture audit
- feat(contracts): add normalized flow event
- feat(ingest): add pcap replay adapter
- test(ddos): add syn flood scenarios
- fix(dns): handle missing query metadata
- refactor(features): isolate window calculation

Avoid vague messages such as:
- updates
- changes
- fixes

## Push
Push verified logical commits to the configured branch.
Never force push unless explicitly approved.

## Rollback
Use commit history to identify the smallest responsible change.
Prefer revert/fix commits over destructive history rewriting.
