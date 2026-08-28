/**
 * PassiveShield AI — Node.js Express Application Gateway
 * Standardized REST API endpoints for health, alerts, alert detail, metrics, and detector insights.
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());

// In-memory standardized threat alerts repository
const alertStore = [
  {
    alert_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    timestamp: "2026-08-28T16:55:00Z",
    threat_classification: "CORRELATED_MULTI_VECTOR",
    severity: "CRITICAL",
    confidence_score: 0.98,
    affected_context: {
      entity_type: "ip",
      entity_id: "192.168.1.200",
      src_ip: "192.168.1.200",
      dst_ip: "198.51.100.99"
    },
    observation_window_seconds: 300,
    contributing_detectors: ["PortScanDetector", "ExfiltrationDetector", "TLSMetadataAnalyzer"],
    structured_evidence: [
      { code: "VERTICAL_PORT_SCAN", message: "Vertical port scan detected: 50 distinct ports probed.", value: 50, threshold: 15, detector_source: "PortScanDetector" },
      { code: "EXFIL_HIGH_BURST_VOLUME", message: "Large single-flow outbound data transfer (15.0 MB).", value: 15000000, threshold: 10000000, detector_source: "ExfiltrationDetector" },
      { code: "JA3_MALWARE_SIGNATURE_MATCH", message: "JA3 hash matched known threat signature: Cobalt Strike Beacon.", value: "e7ed94cc5e470845a0b4b2941f15e32a", threshold: "Cobalt Strike Beacon", detector_source: "TLSMetadataAnalyzer" }
    ],
    mitigation_recommendation: "APPLY_PASSIVE_SHIELD_FILTERS",
    event_type: "ThreatAlert",
    version: "1.0"
  },
  {
    alert_id: "b2c3d4e5-f6a7-8901-bcde-f23456789012",
    timestamp: "2026-08-28T16:40:00Z",
    threat_classification: "DDOS_ATTACK",
    severity: "HIGH",
    confidence_score: 0.92,
    affected_context: {
      entity_type: "ip",
      entity_id: "192.168.1.100",
      src_ip: "192.168.1.100"
    },
    observation_window_seconds: 60,
    contributing_detectors: ["DDoSDetector"],
    structured_evidence: [
      { code: "SYN_FLOOD_DETECTED", message: "High SYN packet rate: 800 pps", value: 800, threshold: 500, detector_source: "DDoSDetector" }
    ],
    mitigation_recommendation: "APPLY_PASSIVE_SHIELD_FILTERS",
    event_type: "ThreatAlert",
    version: "1.0"
  },
  {
    alert_id: "c3d4e5f6-a7b8-9012-cdef-345678901234",
    timestamp: "2026-08-28T16:45:00Z",
    threat_classification: "DNS_ANOMALY",
    severity: "HIGH",
    confidence_score: 0.89,
    affected_context: {
      entity_type: "domain",
      entity_id: "chunk998877665544.tunnel.exfil.org"
    },
    observation_window_seconds: 60,
    contributing_detectors: ["DNSAnomalyDetector"],
    structured_evidence: [
      { code: "TUNNEL_SUBDOMAIN_LENGTH", message: "Excessive subdomain payload length (45 characters).", value: 45, threshold: 20, detector_source: "DNSAnomalyDetector" },
      { code: "TUNNEL_TXT_QUERY", message: "DNS TXT record query used.", value: 1, threshold: 1, detector_source: "DNSAnomalyDetector" }
    ],
    mitigation_recommendation: "BLOCK_DOMAIN_RESOLUTION",
    event_type: "ThreatAlert",
    version: "1.0"
  }
];

// Helper: Response Envelope Formatter
function successResponse(res, data, meta = null, code = 200) {
  return res.status(code).json({
    status: 'success',
    data,
    meta
  });
}

function errorResponse(res, message, errorCode = 'NOT_FOUND', code = 404) {
  return res.status(code).json({
    status: 'error',
    error: {
      code: errorCode,
      message
    }
  });
}

// 1. GET /health & /api/v1/health
app.get(['/health', '/api/v1/health'], (req, res) => {
  return successResponse(res, {
    health: 'ok',
    service: 'PassiveShield AI Express API Gateway',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    uptime_seconds: Math.floor(process.uptime())
  });
});

// 2. GET /api/v1/alerts — Paginated/filtered alert list query
app.get('/api/v1/alerts', (req, res) => {
  const { severity, threat_classification, limit = 50, offset = 0 } = req.query;

  let filtered = alertStore;

  if (severity) {
    filtered = filtered.filter(a => a.severity.toUpperCase() === severity.toUpperCase());
  }

  if (threat_classification) {
    filtered = filtered.filter(a => a.threat_classification.toUpperCase() === threat_classification.toUpperCase());
  }

  const limitNum = Math.max(1, parseInt(limit, 10) || 50);
  const offsetNum = Math.max(0, parseInt(offset, 10) || 0);
  const paginated = filtered.slice(offsetNum, offsetNum + limitNum);

  return successResponse(res, paginated, {
    total: filtered.length,
    limit: limitNum,
    offset: offsetNum
  });
});

// 3. GET /api/v1/alerts/:id — Alert Detail View
app.get('/api/v1/alerts/:id', (req, res) => {
  const alertId = req.params.id;
  const alert = alertStore.find(a => a.alert_id === alertId);

  if (!alert) {
    return errorResponse(res, `ThreatAlert with ID '${alertId}' not found`, 'ALERT_NOT_FOUND', 404);
  }

  return successResponse(res, alert);
});

// 4. GET /api/v1/metrics — Operational Summary Metrics
app.get('/api/v1/metrics', (req, res) => {
  const total = alertStore.length;
  const bySeverity = { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  const byClassification = {};
  const affectedEntities = new Set();

  alertStore.forEach(a => {
    bySeverity[a.severity] = (bySeverity[a.severity] || 0) + 1;
    byClassification[a.threat_classification] = (byClassification[a.threat_classification] || 0) + 1;
    if (a.affected_context && a.affected_context.entity_id) {
      affectedEntities.add(a.affected_context.entity_id);
    }
  });

  return successResponse(res, {
    total_alerts: total,
    by_severity: bySeverity,
    by_classification: byClassification,
    unique_affected_entities: affectedEntities.size
  });
});

// 5. GET /api/v1/detectors/insights — Detector Insights
app.get('/api/v1/detectors/insights', (req, res) => {
  const detectors = [
    { name: "DDoSDetector", category: "Volumetric / Flood", status: "active", total_detections: 1 },
    { name: "PortScanDetector", category: "Reconnaissance", status: "active", total_detections: 1 },
    { name: "C2BeaconDetector", category: "Command & Control", status: "active", total_detections: 0 },
    { name: "DNSAnomalyDetector", category: "DGA / Tunneling", status: "active", total_detections: 1 },
    { name: "ExfiltrationDetector", category: "Data Exfiltration", status: "active", total_detections: 1 },
    { name: "TLSMetadataAnalyzer", category: "JA3/JA4 Cryptographic", status: "active", total_detections: 1 }
  ];

  return successResponse(res, detectors, { count: detectors.length });
});

// 404 Handler
app.use((req, res) => {
  return errorResponse(res, `Endpoint '${req.originalUrl}' not found`, 'ENDPOINT_NOT_FOUND', 404);
});

module.exports = app;
