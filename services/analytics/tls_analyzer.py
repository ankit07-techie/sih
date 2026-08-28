"""
PassiveShield AI — Passive TLS JA3/JA4 Metadata Analyzer
Evaluates passive TLSObservation contracts against known C2/malware JA3/JA4 fingerprint signatures,
outdated TLS versions, weak ciphers, and SNI anomalies.
Strictly passive: performs 0% packet decryption and 0% active TLS network probing.
"""

import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from shared.contracts import (
    TLSObservation,
    DetectionResult,
    ThreatEvidence
)

logger = logging.getLogger(__name__)

ANALYZER_NAME = "TLSMetadataAnalyzer"

WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "NULL", "EXPORT", "3DES", "RC2", "MD5"]
OUTDATED_TLS_VERSIONS = {"sslv2", "sslv3", "tlsv1.0", "tlsv1.1", "tlsv1", "sslv23"}


class TLSMetadataAnalyzer:
    """
    Passively analyzes TLSObservation metadata contracts for JA3/JA4 threat signatures and TLS anomalies.
    Does NOT perform decryption or active probing.
    """

    def __init__(self, signature_db: Optional[Dict[str, Any]] = None):
        self.signatures = signature_db or {
            "ja3_signatures": {
                "e7ed94cc5e470845a0b4b2941f15e32a": {"malware": "Cobalt Strike Beacon", "severity": "CRITICAL"},
                "51c64c77e60f3980eea40869b68c58a8": {"malware": "Metasploit Meterpreter", "severity": "CRITICAL"},
                "6734f37d90595b6002bf7061704940a6": {"malware": "AsyncRAT", "severity": "HIGH"},
                "17f54070a2489e5a8efb7a2d4805e718": {"malware": "Sliver C2", "severity": "CRITICAL"}
            },
            "ja4_signatures": {
                "t13d151600_8da5c1b52b28_0123456789ab": {"malware": "Cobalt Strike HTTPS Beacon", "severity": "CRITICAL"},
                "t12d140800_b990a1c2d3e4_112233445566": {"malware": "TrickBot Loader", "severity": "HIGH"}
            }
        }

    @classmethod
    def from_signature_file(cls, filepath: str) -> 'TLSMetadataAnalyzer':
        """Loads JA3/JA4 signature database from a JSON file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                sig_db = json.load(f)
            return cls(signature_db=sig_db)
        except Exception as e:
            logger.warning(f"Failed to load TLS signature file {filepath}: {e}")
            return cls()

    def analyze_tls_observation(self, observation: TLSObservation) -> DetectionResult:
        """Analyzes a TLSObservation contract passively and outputs DetectionResult."""
        timestamp = observation.timestamp or datetime.now(timezone.utc).isoformat()
        entity_id = f"{observation.client_ip}->{observation.server_ip}"

        evidence_list: List[Dict[str, Any]] = []
        threat_score = 0.0

        ja3 = observation.ja3.strip().lower() if observation.ja3 else ""
        ja4 = observation.ja4.strip().lower() if observation.ja4 else ""
        tls_version = observation.tls_version.strip()
        cipher = observation.cipher_suite.strip()
        sni = observation.sni_hostname.strip()

        # 1. Check JA3 Threat Signatures
        ja3_sigs = self.signatures.get("ja3_signatures", {})
        if ja3 and ja3 in ja3_sigs:
            match = ja3_sigs[ja3]
            threat_score = max(threat_score, 0.95 if match.get("severity") == "CRITICAL" else 0.80)
            evidence_list.append(ThreatEvidence(
                code="JA3_MALWARE_SIGNATURE_MATCH",
                message=f"JA3 hash matched known threat signature: {match.get('malware', 'Unknown C2')}.",
                value=ja3,
                threshold=match.get("malware")
            ).to_dict())

        # 2. Check JA4 Threat Signatures
        ja4_sigs = self.signatures.get("ja4_signatures", {})
        if ja4 and ja4 in ja4_sigs:
            match = ja4_sigs[ja4]
            threat_score = max(threat_score, 0.95 if match.get("severity") == "CRITICAL" else 0.80)
            evidence_list.append(ThreatEvidence(
                code="JA4_MALWARE_SIGNATURE_MATCH",
                message=f"JA4 hash matched known threat signature: {match.get('malware', 'Unknown C2')}.",
                value=ja4,
                threshold=match.get("malware")
            ).to_dict())

        # 3. Check Outdated / Deprecated TLS Version
        if tls_version.lower() in OUTDATED_TLS_VERSIONS:
            threat_score = max(threat_score, 0.45)
            evidence_list.append(ThreatEvidence(
                code="OUTDATED_TLS_VERSION",
                message=f"Deprecated/insecure TLS protocol version used: {tls_version}.",
                value=tls_version,
                threshold="TLSv1.2+"
            ).to_dict())

        # 4. Check Weak Cipher Suite
        cipher_upper = cipher.upper()
        if any(weak in cipher_upper for weak in WEAK_CIPHER_KEYWORDS):
            threat_score = max(threat_score, 0.50)
            evidence_list.append(ThreatEvidence(
                code="WEAK_CIPHER_SUITE",
                message=f"Weak/deprecated cipher suite negotiated: {cipher}.",
                value=cipher,
                threshold="Modern Ciphers"
            ).to_dict())

        # 5. Missing SNI on non-established IP flow
        if not sni and observation.established:
            threat_score = max(threat_score, 0.35)
            evidence_list.append(ThreatEvidence(
                code="MISSING_SNI_HOSTNAME",
                message="TLS handshake completed without Server Name Indication (SNI) header.",
                value="",
                threshold="Valid SNI"
            ).to_dict())

        confidence_score = round(min(1.0, max(0.0, threat_score)), 2)

        if confidence_score < 0.35:
            severity = "INFO"
            is_threat = False
            rec = "NO_ACTION"
        elif confidence_score < 0.60:
            severity = "LOW"
            is_threat = True
            rec = "MONITOR_TLS_FLOW"
        elif confidence_score < 0.85:
            severity = "MEDIUM"
            is_threat = True
            rec = "FLAG_SUSPECT_TLS_CLIENT"
        elif confidence_score < 0.95:
            severity = "HIGH"
            is_threat = True
            rec = "BLOCK_TLS_CLIENT"
        else:
            severity = "CRITICAL"
            is_threat = True
            rec = "APPLY_PASSIVE_SHIELD_FILTERS"

        return DetectionResult(
            timestamp=timestamp,
            detector_name=ANALYZER_NAME,
            entity_type="flow_pair",
            entity_id=entity_id,
            severity=severity,
            confidence_score=confidence_score,
            is_threat=is_threat,
            evidence=evidence_list,
            mitigation_recommendation=rec
        )
