# System Architecture

## Logical data flow

Passive Input
→ Ingestion
→ Normalization
→ Bounded State
→ Feature Extraction
→ Specialized Detectors
→ Threat Fusion
→ Alert Service
→ Persistence / Real-Time Distribution
→ SOC Dashboard

## Dependency rule

Dependencies flow in the direction of the pipeline or through stable shared contracts.

Modules must not reach into another module's private implementation.

Examples:
- detector → shared contracts/features: allowed
- detector → frontend: forbidden
- frontend → detector internals: forbidden
- persistence implementation → detector algorithm: forbidden

## Major modules
1. input adapters
2. normalization
3. state management
4. feature engine
5. independent detectors
6. threat fusion
7. alert management
8. persistence
9. API/realtime transport
10. dashboard
11. replay control
