# Product Requirements Document

## Product goal
Accept passive network telemetry, analyze behavior, detect prioritized cyber threats, and present evidence-rich alerts.

## Primary user outcome
An operator can observe system activity, receive an alert, inspect why it was generated, and understand the evidence.

## Functional requirements
- FR-01: accept PCAP replay, Zeek-style logs, or normalized events
- FR-02: validate and normalize observations
- FR-03: maintain configurable bounded observation windows
- FR-04: extract reusable detector features
- FR-05: run independent P0 detectors
- FR-06: fuse compatible results transparently
- FR-07: generate structured alerts
- FR-08: expose alerts, evidence, health, and metrics
- FR-09: support deterministic replay for demonstrations

## Non-goals
Inline blocking, active probing, packet injection, universal threat detection, and mandatory payload decryption.
