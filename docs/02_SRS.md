# Software Requirements Specification

## Functional behavior
The system shall:
1. ingest passive observations incrementally
2. preserve timestamps and provenance where available
3. validate observations
4. normalize data into versioned contracts
5. maintain bounded time-window state
6. generate reusable features
7. execute specialized detectors independently
8. generate explainable detection results
9. create standardized alerts
10. expose history, metrics, health, and real-time updates
11. replay deterministic scenarios

## Non-functional requirements
### Maintainability
Module boundaries and contracts must limit change propagation.

### Reliability
Malformed input should be handled safely without crashing the entire pipeline.

### Explainability
Confidence without evidence is insufficient.

### Reproducibility
Demo and debugging scenarios should be replayable.

### Observability
Important services expose logs and measurable metrics.

### Performance
Only measured performance may be claimed.
