/**
 * PassiveShield AI — Real-Time Socket.IO Endpoint & Event Delivery Tests
 */

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { io: ioc } = require('socket.io-client');

const app = require('../src/app');
const setupRealtimeServer = require('../src/realtime');

test('Socket.IO Real-Time Alert Delivery Tests', async (t) => {
  let server;
  let realtime;
  let clientSocket;
  let port;

  t.before(async () => {
    await new Promise((resolve) => {
      server = http.createServer(app);
      realtime = setupRealtimeServer(server);
      server.listen(0, () => {
        port = server.address().port;
        resolve();
      });
    });
  });

  t.after(async () => {
    if (clientSocket && clientSocket.connected) {
      clientSocket.disconnect();
    }
    await new Promise((resolve) => {
      realtime.io.close();
      server.close(resolve);
    });
  });

  await t.test('Client connects successfully and receives system:info greeting', async () => {
    clientSocket = ioc(`http://127.0.0.1:${port}`, { transports: ['websocket'] });

    const greeting = await new Promise((resolve) => {
      clientSocket.on('system:info', (data) => {
        resolve(data);
      });
    });

    assert.ok(greeting);
    assert.strictEqual(greeting.message, 'Connected to PassiveShield AI Real-Time Alert Stream');
    assert.ok(greeting.socket_id);
  });

  await t.test('Client sends ping and receives pong response', async () => {
    const pongData = await new Promise((resolve) => {
      clientSocket.on('pong', (data) => {
        resolve(data);
      });
      clientSocket.emit('ping');
    });

    assert.ok(pongData);
    assert.ok(pongData.timestamp);
  });

  await t.test('Real-time alert broadcast emits alert:new to client', async () => {
    const mockAlert = {
      alert_id: "rt-alert-001",
      timestamp: new Date().toISOString(),
      threat_classification: "DDOS_ATTACK",
      severity: "CRITICAL",
      confidence_score: 0.96,
      affected_context: { entity_type: "ip", entity_id: "192.168.1.100" },
      observation_window_seconds: 60,
      contributing_detectors: ["DDoSDetector"],
      structured_evidence: [{ code: "SYN_FLOOD", message: "SYN flood attack detected" }],
      mitigation_recommendation: "APPLY_PASSIVE_SHIELD_FILTERS",
      event_type: "ThreatAlert",
      version: "1.0"
    };

    const receivedAlert = await new Promise((resolve) => {
      clientSocket.on('alert:new', (alert) => {
        resolve(alert);
      });
      realtime.broadcastAlert(mockAlert);
    });

    assert.strictEqual(receivedAlert.alert_id, "rt-alert-001");
    assert.strictEqual(receivedAlert.severity, "CRITICAL");
    assert.strictEqual(receivedAlert.threat_classification, "DDOS_ATTACK");
  });
});
