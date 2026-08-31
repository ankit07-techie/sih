# Module Boundaries

Every module owns one responsibility.

## Ingestion
Owns reading external passive inputs.
Output: validated raw/normalized boundary.

## Normalization
Owns conversion into common internal contracts.

## State
Owns bounded temporal observations.

## Features
Own reusable feature calculations.
Output: FeatureSnapshot or equivalent stable feature contract.

## Detectors
Each detector owns only its threat logic and evidence generation.
No UI, database, or transport dependencies.

## Threat Fusion
Owns combination of compatible detection results.

## Alert Service
Owns alert identifiers, validation, persistence coordination, and delivery.

## Persistence
Owns storage implementation behind a stable interface.

## API/Realtime
Owns external application transport.

## Dashboard
Owns presentation and user interaction only.

## Replay
Owns deterministic input control for demo/testing.

Any cross-boundary dependency must be documented.
