# Data Contract Design

## Required contracts
1. NormalizedFlowEvent
2. DNSObservation
3. TLSObservation
4. FeatureSnapshot
5. DetectionResult
6. ThreatEvidence
7. ThreatAlert
8. SystemMetrics
9. ReplayControlEvent

## Contract change rule
Before changing a contract:
1. identify producers
2. identify consumers
3. classify compatibility
4. define migration/version behavior if breaking
5. add regression tests

Each contract implementation should be independently testable.
