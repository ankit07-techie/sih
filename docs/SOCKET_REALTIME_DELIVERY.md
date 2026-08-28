# Socket.IO Real-Time Alert Delivery Specification

## Executive Summary
This document specifies the design, WebSocket event topics, connection handling, CORS policies, Redis Pub/Sub bridge integration, and test verification results for the Socket.IO real-time alert delivery service ([`services/api/src/realtime.js`](file:///d:/sih%20project/PassiveShield_AI_v2/services/api/src/realtime.js)).

---

## 1. Real-Time Delivery Architecture & Scope

The `setupRealtimeServer` module attaches a Socket.IO WebSocket server instance to the HTTP Gateway server, providing real-time event streaming for standardized `ThreatAlert` contracts emitted by the PassiveShield AI threat fusion engine and Redis `cyber_alerts` Pub/Sub channel.

- **Location**: `services/api/src/realtime.js`
- **Gateway Entrypoint**: `services/api/src/server.js`
- **Supported Transports**: `websocket`, `polling` (fallback)
- **CORS Policy**: Configured for cross-origin access (`origin: "*"`).

---

## 2. Real-Time WebSocket Event Topics

### A. Server-to-Client Event Topics
- **`alert:new`**: Emitted to all connected WebSocket clients whenever a standardized `ThreatAlert` payload is generated.
- **`system:info`**: Emitted to newly connected client sockets with connection greeting and server timestamp.
- **`pong`**: Response emitted when client sends a health check `ping` message.

### B. Client-to-Server Event Topics
- **`ping`**: Client health check trigger.
- **`disconnect`**: Connection cleanup handler.

---

## 3. Test Verification Results

Unit & integration tests are implemented in [`services/api/tests/realtime.test.js`](file:///d:/sih%20project/PassiveShield_AI_v2/services/api/tests/realtime.test.js).

### Execution Command:
```bash
npm test  # inside services/api/
```

### Verified Test Cases:
- `Client connects successfully and receives system:info greeting`: Verified WebSocket connection and welcome greeting payload.
- `Client sends ping and receives pong response`: Verified health check ping/pong roundtrip.
- `Real-time alert broadcast emits alert:new to client`: Verified `realtime.broadcastAlert(mockAlert)` emits `alert:new` event with complete `ThreatAlert` contract to connected socket clients.
- Total Test Status: **12 Node.js tests passed, 0 failures** (`duration: ~3950ms`).
