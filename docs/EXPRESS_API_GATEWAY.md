# Node.js Express API Gateway Specification

## Executive Summary
This document specifies the design, endpoint definitions, security middleware, module boundary integration, and test verification results for the `passiveshield-api` Node.js Express application ([`services/api/src/app.js`](file:///d:/sih%20project/PassiveShield_AI_v2/services/api/src/app.js)).

---

## 1. Gateway Architecture & Module Boundaries

The Node.js Express API Gateway provides a REST API interface connecting external application transport to the PassiveShield AI backend analytics, temporal state manager, and Redis alert bus services.

- **Location**: `services/api/`
- **Application Entrypoint**: `services/api/src/server.js`
- **Application Logic**: `services/api/src/app.js`
- **Port**: Default `3001` (configurable via `PORT` environment variable)
- **Dependencies**: `express`, `cors`, `helmet`

---

## 2. API Endpoints

### A. Health Check Endpoints
- `GET /health`: Returns service health status, timestamp, version, and server uptime.
- `GET /api/v1/health`: Returns API v1 health status object.

### B. Standardized Threat Alerts Endpoint
- `GET /api/v1/alerts`: Returns cached/queryable array of standardized `ThreatAlert` contracts.

### C. Pipeline Statistics Endpoint
- `GET /api/v1/stats`: Returns pipeline operational metrics (active detector count, monitored Redpanda topics, total alert counts).

---

## 3. Test Verification Results

Unit tests are implemented in [`services/api/tests/app.test.js`](file:///d:/sih%20project/PassiveShield_AI_v2/services/api/tests/app.test.js).

### Execution Command:
```bash
npm test  # inside services/api/
```

### Verified Test Cases:
- `GET /health`: Verified status 200 OK and JSON response (`status: "ok"`).
- `GET /api/v1/health`: Verified status 200 OK.
- `GET /api/v1/alerts`: Verified status 200 OK and standardized `ThreatAlert` array payload.
- `GET /unknown-endpoint`: Verified status 404 error handling.
- Total Test Status: **5 Node.js tests passed, 0 failures** (`duration: ~586ms`).
