# UI/UX Specification

Primary views:
- system overview
- live threat feed
- alert detail/evidence
- traffic timeline
- detector insights
- metrics
- replay controls

Alert detail should expose:
- threat class
- severity
- confidence/risk
- affected context
- observation window
- contributing detectors
- key feature values
- baseline/current comparison where available
- human-readable explanation

Frontend code must not contain detector logic.
