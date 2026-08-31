/**
 * PassiveShield AI — Static Analytical & Demonstration Data
 * Cleanly separated from live backend telemetry. Used exclusively for analytical and architecture visualizations.
 */

export const mockInitialIncidents = [
  {
    id: 'INC-2026-0817',
    title: 'Sustained DNS Tunneling Activity',
    rawClassification: 'DNS_TUNNEL',
    source: 'Unidirectional Flow / 192.168.1.100',
    entityId: '192.168.1.100',
    detector: 'DNSAnomalyDetector',
    severity: 'HIGH',
    score: 88,
    confidence: 0.88,
    age: '02m 14s ago',
    timestamp: '2026-08-31T14:30:00Z',
    status: 'Active Threat',
    mitigation: 'BLOCK_DOMAIN_RESOLUTION',
    evidence: [
      { code: 'TUNNEL_SUBDOMAIN_LENGTH', message: 'Subdomain length (50 chars) exceeds tunneling threshold.', value: 50, threshold: 20, detector_source: 'DNSAnomalyDetector' },
      { code: 'TUNNEL_TXT_QUERY', message: 'High volume TXT query payload carrying base32 encoded data.', value: 'TXT', threshold: 'A/AAAA', detector_source: 'DNSAnomalyDetector' }
    ]
  },
  {
    id: 'INC-2026-0815',
    title: 'High-Rate TCP SYN Flood Surge',
    rawClassification: 'SYN_FLOOD',
    source: 'Subnet Tap / 10.10.1.0/24',
    entityId: '10.10.1.55',
    detector: 'DDoSDetector',
    severity: 'CRITICAL',
    score: 95,
    confidence: 0.95,
    age: '08m 40s ago',
    timestamp: '2026-08-31T14:24:00Z',
    status: 'Active Threat',
    mitigation: 'APPLY_PASSIVE_SHIELD_FILTERS',
    evidence: [
      { code: 'SYN_FLOOD_SIGNAL', message: 'SYN-only ratio dominates (98% unacknowledged SYNs).', value: 0.98, threshold: 0.40, detector_source: 'DDoSDetector' },
      { code: 'VOLUMETRIC_SURGE', message: 'Packet rate surge ratio 15.2x above baseline.', value: 15.2, threshold: 3.0, detector_source: 'DDoSDetector' }
    ]
  },
  {
    id: 'INC-2026-0814',
    title: 'Periodic C2 Beaconing (Cobalt Strike)',
    rawClassification: 'C2_BEACONING',
    source: 'Isolated VLAN / 172.16.4.12',
    entityId: '172.16.4.12',
    detector: 'C2BeaconDetector',
    severity: 'CRITICAL',
    score: 100,
    confidence: 1.00,
    age: '15m 12s ago',
    timestamp: '2026-08-31T14:17:00Z',
    status: 'Active Threat',
    mitigation: 'BLOCK_C2_HOST',
    evidence: [
      { code: 'SPECTRAL_PEAK_DETECTED', message: 'SciPy FFT peak power ratio (0.84) indicates rigid automated beaconing.', value: 0.84, threshold: 0.50, detector_source: 'C2BeaconDetector' },
      { code: 'JA3_MALWARE_SIGNATURE_MATCH', message: 'JA3 fingerprint matched Cobalt Strike HTTPS Beacon signature.', value: 'e7ed94cc5e470845a0b4b2941f15e32a', threshold: 'Cobalt Strike', detector_source: 'TLSMetadataAnalyzer' }
    ]
  },
  {
    id: 'INC-2026-0811',
    title: 'Algorithmic DGA Domain Query Burst',
    rawClassification: 'DGA_SUSPICIOUS',
    source: 'Workstation / 10.0.4.88',
    entityId: '10.0.4.88',
    detector: 'DNSAnomalyDetector',
    severity: 'MEDIUM',
    score: 60,
    confidence: 0.60,
    age: '42m 05s ago',
    timestamp: '2026-08-31T13:50:00Z',
    status: 'Observed',
    mitigation: 'FLAG_SUSPECT_DOMAIN',
    evidence: [
      { code: 'DGA_HIGH_ENTROPY', message: 'Shannon character entropy (4.12 bits) exceeds natural domain threshold.', value: 4.12, threshold: 3.80, detector_source: 'DNSAnomalyDetector' },
      { code: 'DGA_DIGIT_DENSITY', message: 'Digit ratio in query string is 32% (abnormal lexical density).', value: 0.32, threshold: 0.25, detector_source: 'DNSAnomalyDetector' }
    ]
  }
];

export const mockThreatIntelligence = {
  signatures: [
    { hash: 'e7ed94cc5e470845a0b4b2941f15e32a', type: 'JA3 MD5', family: 'Cobalt Strike HTTPS Beacon', severity: 'CRITICAL', status: 'ACTIVE' },
    { hash: '51c64c77e60f3980eea40869b68c58a8', type: 'JA3 MD5', family: 'Metasploit Meterpreter Reverse HTTPS', severity: 'CRITICAL', status: 'ACTIVE' },
    { hash: '6734f37d90595b6002bf7061704940a6', type: 'JA3 MD5', family: 'AsyncRAT C2 Client', severity: 'HIGH', status: 'ACTIVE' },
    { hash: '17f54070a2489e5a8efb7a2d4805e718', type: 'JA3 MD5', family: 'Sliver C2 Implant', severity: 'CRITICAL', status: 'ACTIVE' },
    { hash: 't13d151600_8da5c1b52b28_0123456789ab', type: 'JA4 Raw', family: 'Cobalt Strike TLS 1.3 Profile', severity: 'CRITICAL', status: 'ACTIVE' },
    { hash: 't12d140800_b990a1c2d3e4_112233445566', type: 'JA4 Raw', family: 'TrickBot Banking Trojan Loader', severity: 'HIGH', status: 'ACTIVE' }
  ]
};

export const mockDetectorEngineSpecs = [
  { name: 'DDoSDetector', category: 'Volumetric & Exhaustion', math: 'Surge ratio + SYN/ACK asymmetry + Slowloris heuristic', status: 'ONLINE', rate: '100%' },
  { name: 'PortScanDetector', category: 'Reconnaissance', math: 'Vertical target ports + Horizontal IP dispersion + Port entropy', status: 'ONLINE', rate: '100%' },
  { name: 'C2BeaconDetector', category: 'Temporal Heartbeats', math: 'SciPy FFT spectral peak power ratio (E_peak) + CV_IAT', status: 'ONLINE', rate: '100%' },
  { name: 'DNSAnomalyDetector', category: 'Tunneling & DGAs', math: 'Shannon info entropy + Bigram transition + TXT length', status: 'ONLINE', rate: '100%' },
  { name: 'ExfiltrationDetector', category: 'Directional Asymmetry', math: 'Orig/Resp byte ratio + Burst volume + MAD Robust Z-score', status: 'ONLINE', rate: '100%' },
  { name: 'TLSMetadataAnalyzer', category: 'Encrypted Traffic', math: 'Passive JA3/JA4 cryptographic hash matching + Cipher audit', status: 'ONLINE', rate: '100%' }
];
