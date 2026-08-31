# Threat Detection Specification

## Common detector output
Every detector should return:
- detector identity/version
- classification
- score/confidence
- severity recommendation
- observation window
- affected entity/flow context
- structured evidence
- limitations or data-quality notes where relevant

## DDoS / Flood
Signals may include traffic-rate surge, packet-rate surge, SYN/ACK imbalance, source distribution/entropy shift, destination concentration, and baseline deviation.

## Port Scanning
Signals may include unique ports, unique destinations, fan-out, growth rate, and connection characteristics when available.

## C2 Beaconing
Signals may include inter-arrival intervals, variance, coefficient of variation, periodicity, autocorrelation, and spectral evidence only when enough observations exist.

## DNS anomalies
DGA-like behavior: length, entropy, digit ratio, character characteristics.
Tunnelling: subdomain entropy, depth, frequency, and unique-query growth.

Every alert must explain contributing signals.
