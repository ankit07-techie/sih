# Data Architecture

Core conceptual lifecycle:

Raw Observation
→ NormalizedFlowEvent / DNSObservation / TLSObservation
→ FeatureSnapshot
→ DetectionResult
→ ThreatEvidence
→ ThreatAlert

Public contracts must:
- contain a version
- document required and optional fields
- define producers and consumers
- support compatibility analysis

Detector-specific fields belong in detector outputs/evidence rather than unrelated base events.
