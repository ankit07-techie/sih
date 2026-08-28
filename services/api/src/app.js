/**
 * PassiveShield AI — Node.js Express Application Gateway
 * Connects through approved module boundaries to alert/state/query services.
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());

// In-memory alert buffer / cache for API query service
const cachedAlerts = [
  {
    alert_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    timestamp: new Date().toISOString(),
    threat_classification: "CORRELATED_MULTI_VECTOR",
    severity: "CRITICAL",
    confidence_score: 0.98,
    affected_context: {
      entity_type: "ip",
      entity_id: "192.168.1.200",
      src_ip: "192.168.1.200"
    },
    observation_window_seconds: 300,
    contributing_detectors: ["PortScanDetector", "ExfiltrationDetector"],
    structured_evidence: [
      { code: "VERTICAL_PORT_SCAN", message: "Probed 50 ports", detector_source: "PortScanDetector" },
      { code: "EXFIL_HIGH_BURST_VOLUME", message: "Uploaded 15 MB", detector_source: "ExfiltrationDetector" }
    ],
    mitigation_recommendation: "APPLY_PASSIVE_SHIELD_FILTERS",
    event_type: "ThreatAlert",
    version: "1.0"
  }
];

// Health Check Endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'PassiveShield AI Express API Gateway',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    uptime_seconds: Math.floor(process.uptime())
  });
});

// GET /api/v1/health
app.get('/api/v1/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'PassiveShield AI Express API Gateway',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// GET /api/v1/alerts — Query standardized threat alerts
app.get('/api/v1/alerts', (req, res) => {
  res.status(200).json({
    status: 'success',
    count: cachedAlerts.length,
    alerts: cachedAlerts
  });
});

// GET /api/v1/stats — Pipeline summary statistics
app.get('/api/v1/stats', (req, res) => {
  res.status(200).json({
    status: 'success',
    active_detectors: 6,
    monitored_topics: ['raw_conn', 'raw_dns', 'raw_ssl', 'threat-alerts'],
    total_alerts: cachedAlerts.length
  });
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

module.exports = app;
