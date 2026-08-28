# Passive TLS JA3/JA4 Metadata Analysis Specification

## Executive Summary
This document specifies the design, fingerprint signature lookup mechanisms, passive protocol anomaly checks, non-decryption passivity boundaries, and test verification results for the `TLSMetadataAnalyzer` component ([`services/analytics/tls_analyzer.py`](file:///d:/sih%20project/PassiveShield_AI_v2/services/analytics/tls_analyzer.py)).

---

## 1. Passive Monitoring & Non-Decryption Boundary

PassiveShield AI operates under strict passive network security principles:
1. **0% Decryption**: No payload decryption, SSL stripping, or MITM certificate re-signing is performed.
2. **0% Active Probing**: No active TLS handshakes or network port probes are initiated.
3. **Metadata-Only Analysis**: Analyzes unencrypted Client Hello / Server Hello handshake metadata parameters (JA3 hash, JA4 fingerprint, SNI hostname, negotiated TLS version, and cipher suite) extracted passively by Zeek security monitoring (`ssl.log`).

---

## 2. Threat Signature & Anomaly Detection Logic

### A. JA3 / JA4 Threat Signature Lookup
Queries client JA3 hashes (`observation.ja3`) and JA4 fingerprints (`observation.ja4`) against local threat intelligence signature databases ([`fixtures/tls_signatures.json`](file:///d:/sih%20project/PassiveShield_AI_v2/fixtures/tls_signatures.json)):
- **Cobalt Strike HTTPS Beacon**: `JA3: e7ed94cc5e470845a0b4b2941f15e32a`, `JA4: t13d151600_8da5c1b52b28_0123456789ab` -> `CRITICAL` severity ($S = 0.95$).
- **Metasploit Meterpreter**: `JA3: 51c64c77e60f3980eea40869b68c58a8` -> `CRITICAL` severity ($S = 0.95$).
- **AsyncRAT / Sliver C2**: Known RAT / C2 hashes -> `HIGH` / `CRITICAL` severity.

### B. Protocol & Cipher Anomaly Rules
- **Outdated TLS Protocol**: Detects `SSLv2`, `SSLv3`, `TLSv1.0`, or `TLSv1.1` protocol usage (`OUTDATED_TLS_VERSION` evidence).
- **Weak Cipher Suite**: Detects deprecated or insecure ciphers (`RC4`, `DES`, `3DES`, `NULL`, `EXPORT`, `MD5`) (`WEAK_CIPHER_SUITE` evidence).
- **Missing SNI Hostname**: Flags completed TLS flows missing Server Name Indication headers (`MISSING_SNI_HOSTNAME` evidence).

---

## 3. Test Verification Results

Unit tests are implemented in [`tests/test_tls_analyzer.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_tls_analyzer.py).

### Execution Command:
```bash
py -3 -m unittest discover tests
```

### Verified Test Cases:
- `test_benign_tls_flow`: Verified benign `TLSv1.3` flow produces `INFO` severity ($S=0.0$, `is_threat=False`).
- `test_ja3_cobalt_strike_match`: Verified Cobalt Strike JA3 hash match triggers `CRITICAL` severity ($S=0.95$, `JA3_MALWARE_SIGNATURE_MATCH`).
- `test_ja4_cobalt_strike_match`: Verified Cobalt Strike JA4 fingerprint match triggers `CRITICAL` severity ($S=0.95$, `JA4_MALWARE_SIGNATURE_MATCH`).
- `test_outdated_tls_and_weak_cipher`: Verified `TLSv1.0` and `RC4` cipher trigger `LOW` severity ($S=0.50$, `OUTDATED_TLS_VERSION`, `WEAK_CIPHER_SUITE`).
- `test_missing_sni_hostname`: Verified established flow without SNI triggers `MISSING_SNI_HOSTNAME` evidence.
- Total Test Suite Status: **70 tests passed, 0 failures, 0 errors** (`OK`).
