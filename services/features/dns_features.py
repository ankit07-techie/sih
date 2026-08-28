"""
PassiveShield AI — Reusable DNS Feature Extractor
Extracts domain length, Shannon entropy, character statistics (digits, vowels, consonants, hyphens),
n-gram metrics, subdomain depth, query frequency, and NXDOMAIN growth for DGA / DNS Tunneling analysis.
"""

import math
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

from shared.contracts import FeatureSnapshot
from services.state import RedisStateManager
from .feature_engine import compute_shannon_entropy


def compute_bigram_entropy(s: str) -> float:
    """Calculates Shannon entropy of 2-character n-grams in string s."""
    if len(s) < 2:
        return 0.0
    bigrams = [s[i:i + 2] for i in range(len(s) - 1)]
    total = len(bigrams)
    counts = {}
    for bg in bigrams:
        counts[bg] = counts.get(bg, 0) + 1
    return -sum((c / float(total)) * math.log2(c / float(total)) for c in counts.values())


def max_consecutive_consonants(s: str) -> int:
    """Calculates the maximum count of consecutive consonants in string s."""
    consonants = set("bcdfghjklmnpqrstvwxyz")
    max_c = 0
    curr_c = 0
    for char in s.lower():
        if char in consonants:
            curr_c += 1
            if curr_c > max_c:
                max_c = curr_c
        else:
            curr_c = 0
    return max_c


class DNSFeatureExtractor:
    """
    Computes reusable DNS features for domain query entities.
    Outputs FeatureSnapshot contract objects.
    Contains 0% detector classification or threat scoring logic.
    """

    def __init__(self, state_manager: Optional[RedisStateManager] = None):
        self.state_mgr = state_manager

    def compute_dns_features(
        self,
        domain: str,
        query_type: str = "A",
        response_code: str = "NOERROR",
        window_seconds: int = 60,
        prev_unique_domains: int = 0,
        current_unique_domains: int = 1,
        timestamp: Optional[str] = None
    ) -> FeatureSnapshot:
        """
        Calculates lexical, character, n-gram, and frequency signals for a queried domain.
        """
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        domain_str = domain.strip().lower()

        length = len(domain_str)
        subdomain_depth = domain_str.count('.')

        # Extract subdomain prefix (everything except last 2 labels)
        parts = domain_str.split('.')
        subdomain_prefix = ".".join(parts[:-2]) if len(parts) > 2 else parts[0] if len(parts) > 0 else ""
        subdomain_length = len(subdomain_prefix)

        # Entropy metrics
        entropy = round(compute_shannon_entropy(domain_str), 4)
        bigram_entropy = round(compute_bigram_entropy(domain_str), 4)

        # Character statistics
        digits = sum(c.isdigit() for c in domain_str)
        digit_ratio = round(digits / float(length), 4) if length > 0 else 0.0

        vowels_set = set("aeiou")
        vowels = sum(1 for c in domain_str if c in vowels_set)
        vowel_ratio = round(vowels / float(length), 4) if length > 0 else 0.0

        consonants_set = set("bcdfghjklmnpqrstvwxyz")
        consonants = sum(1 for c in domain_str if c in consonants_set)
        consonant_ratio = round(consonants / float(length), 4) if length > 0 else 0.0

        hyphens = domain_str.count('-')
        max_cons_seq = max_consecutive_consonants(domain_str)

        # Protocol flags
        is_nxdomain = 1 if response_code.upper() == "NXDOMAIN" else 0
        is_txt_query = 1 if query_type.upper() == "TXT" else 0

        # Frequency growth metric
        denom = max(1, prev_unique_domains)
        domain_growth_rate = round((current_unique_domains - prev_unique_domains) / float(denom), 2)

        features = {
            "domain_length": length,
            "subdomain_length": subdomain_length,
            "subdomain_depth": subdomain_depth,
            "entropy": entropy,
            "bigram_entropy": bigram_entropy,
            "digit_count": digits,
            "digit_ratio": digit_ratio,
            "vowel_ratio": vowel_ratio,
            "consonant_ratio": consonant_ratio,
            "hyphen_count": hyphens,
            "max_consecutive_consonants": max_cons_seq,
            "is_nxdomain": is_nxdomain,
            "is_txt_query": is_txt_query,
            "domain_growth_rate": domain_growth_rate
        }

        return FeatureSnapshot(
            timestamp=ts,
            entity_type="domain",
            entity_id=domain_str,
            window_seconds=window_seconds,
            features=features
        )
