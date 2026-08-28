# Reusable DNS Feature Set Specification

## Executive Summary
This document specifies the design, feature definitions, and verification results for the `DNSFeatureExtractor` module ([`services/features/dns_features.py`](file:///d:/sih%20project/PassiveShield_AI_v2/services/features/dns_features.py)).

---

## 1. Feature Extractor Architecture & Scope

The `DNSFeatureExtractor` computes domain length, Shannon entropy, character statistics (digits, vowels, consonants, hyphens), n-gram metrics, subdomain depth, query frequency, and NXDOMAIN growth for DGA / DNS Tunneling analysis.

- **Location**: `services/features/dns_features.py`
- **Output Contract**: `shared.contracts.FeatureSnapshot` (`entity_type: "domain"`, `version: "1.0"`)
- **Isolation**: Contains **zero classification, threshold scoring, or detector decision code**. Computes objective mathematical features for downstream consumption by independent DNS anomaly threat detectors.

---

## 2. Feature Signals & Metrics Table

| Feature Key | Category | Mathematical Definition | Target Threat Signal |
|---|---|---|---|
| `domain_length` | Lexical Size | Character count of domain string | Long domain names common in DGA & DNS tunneling |
| `subdomain_length` | Lexical Size | Character count of subdomain prefix | Tunneling payload encoded in subdomain labels |
| `subdomain_depth` | Structure | Label dot count (`domain.count('.')`) | Deep nested subdomain structures |
| `entropy` | Randomness | Shannon entropy of domain string | Randomly generated DGA domain strings |
| `bigram_entropy` | N-gram Entropy | Entropy of 2-character n-grams | Artificial character distributions |
| `digit_count` / `digit_ratio` | Character Stats | Digit frequency & ratio | High numeric density in hex/base64 encoded queries |
| `vowel_ratio` / `consonant_ratio` | Character Stats | Vowel and consonant ratios | Unnatural pronounceability ratios in DGA strings |
| `max_consecutive_consonants` | Character Stats | Max sequence of consecutive consonants | Random consonant clusters in DGA strings |
| `is_nxdomain` | Protocol Flag | Flag `1` if response code is `NXDOMAIN` | Failed DGA domain resolution attempts |
| `is_txt_query` | Protocol Flag | Flag `1` if query type is `TXT` | DNS TXT record tunneling exfiltration |
| `domain_growth_rate` | Frequency Growth | `(current_domains - prev) / max(1, prev)` | Rapid surge in unique domain queries |

---

## 3. Test Verification Results

Unit tests are implemented in [`tests/test_dns_features.py`](file:///d:/sih%20project/PassiveShield_AI_v2/tests/test_dns_features.py).

### Execution Command:
```bash
py -3 -m unittest discover tests
```

### Verified Test Cases:
- `test_benign_domain_features`: Verified benign `google.com` produces low entropy (< 3.0), zero digits, and depth 1.
- `test_dga_domain_features`: Verified DGA domain produces high entropy (> 3.5), high digit ratio (> 0.20), and `is_nxdomain = 1`.
- `test_dns_tunneling_txt_query`: Verified tunneling payload produces `is_txt_query = 1` and subdomain depth 3.
- `test_consecutive_consonants_and_bigram_entropy`: Verified `max_consecutive_consonants` and `bigram_entropy` calculations.
- Total Test Suite Status: **62 tests passed, 0 failures, 0 errors** (`OK`).
