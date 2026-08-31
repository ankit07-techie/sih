# Test Strategy

## Unit
Contracts, validation, features, scoring, evidence, edge cases.

## Integration
Contract compatibility and component boundaries.

## End-to-end
Replay → processing → detector → alert → delivery → dashboard where applicable.

## Required detector scenarios
- benign traffic
- obvious attack
- boundary condition
- incomplete/missing metadata
- deterministic replay

Every fixed reproducible bug receives a regression test.
