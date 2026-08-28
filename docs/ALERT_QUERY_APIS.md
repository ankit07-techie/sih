# Alert Query REST API Specification

## Executive Summary
This document specifies the design, endpoint definitions, stable response envelope formats, query parameter filtering, and test verification results for the Alert Query REST APIs ([`services/api/src/app.js`](file:///d:/sih%20project/PassiveShield_AI_v2/services/api/src/app.js)).

---

## 1. Response Envelope Standard

All API endpoints return consistent, versioned JSON response envelopes.

### Success Response Envelope Format:
```json
{
  "status": "success",
  "data": { ... },
  "meta": {
    "total": 3,
    "limit": 50,
    "offset": 0
  }
}
```

### Error Response Envelope Format:
```json
{
  "status": "error",
  "error": {
    "code": "ALERT_NOT_FOUND",
    "message": "ThreatAlert with ID 'xyz' not found"
  }
}
```

---

## 2. API Endpoints

### A. Health Check (`GET /api/v1/health`)
Returns gateway operational health, version, and server uptime.

### B. Query Threat Alerts (`GET /api/v1/alerts`)
Queries standardized `ThreatAlert` records with optional URL parameters:
- `severity` (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`): Filters by severity level.
- `threat_classification` (`DDOS_ATTACK`, `PORT_SCAN`, etc.): Filters by threat category.
- `limit` (default `50`): Maximum records to return.
- `offset` (default `0`): Pagination offset.

### C. Alert Detail View (`GET /api/v1/alerts/:id`)
Returns detailed JSON contract representation for a single `ThreatAlert` by `alert_id`. Returns HTTP 404 if not found.

### D. Operational Metrics (`GET /api/v1/metrics`)
Returns total alert count, severity breakdown (`by_severity`), threat category breakdown (`by_classification`), and unique high-risk entity count.

### E. Detector Insights (`GET /api/v1/detectors/insights`)
Returns active status, detection category, and historical detection counts for all 6 active threat detectors (`DDoSDetector`, `PortScanDetector`, `C2BeaconDetector`, `DNSAnomalyDetector`, `ExfiltrationDetector`, `TLSMetadataAnalyzer`).

---

## 3. Test Verification Results

Unit tests are implemented in [`services/api/tests/app.test.js`](file:///d:/sih%20project/PassiveShield_AI_v2/services/api/tests/app.test.js).

### Execution Command:
```bash
npm test  # inside services/api/
```

### Verified Test Cases:
- `GET /health`: Verified status 200 OK and envelope response.
- `GET /api/v1/alerts`: Verified status 200 OK and standardized `ThreatAlert` array payload.
- `GET /api/v1/alerts?severity=CRITICAL`: Verified query parameter filtering.
- `GET /api/v1/alerts/:id`: Verified single alert detail retrieval by `alert_id`.
- `GET /api/v1/alerts/nonexistent-id`: Verified 404 error response envelope (`code: "ALERT_NOT_FOUND"`).
- `GET /api/v1/metrics`: Verified summary metrics and severity breakdown.
- `GET /api/v1/detectors/insights`: Verified active detector insights.
- Total Test Status: **8 Node.js tests passed, 0 failures** (`duration: ~721ms`).
