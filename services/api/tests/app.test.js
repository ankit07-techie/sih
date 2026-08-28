/**
 * PassiveShield AI — Focused API Endpoint Tests for Alert Query APIs
 */

const test = require('node:test');
const assert = require('node:assert');

const app = require('../src/app');

test('Express API Gateway Alert Query Endpoints', async (t) => {
  let server;

  t.before(async () => {
    await new Promise((resolve) => {
      server = app.listen(0, resolve);
    });
  });

  t.after(async () => {
    await new Promise((resolve) => {
      server.close(resolve);
    });
  });

  await t.test('GET /health returns status 200 OK', async () => {
    const port = server.address().port;
    const res = await fetch(`http://127.0.0.1:${port}/health`);
    assert.strictEqual(res.status, 200);

    const body = await res.json();
    assert.strictEqual(body.status, 'success');
    assert.strictEqual(body.data.health, 'ok');
  });

  await t.test('GET /api/v1/alerts returns standardized alerts array', async () => {
    const port = server.address().port;
    const res = await fetch(`http://127.0.0.1:${port}/api/v1/alerts`);
    assert.strictEqual(res.status, 200);

    const body = await res.json();
    assert.strictEqual(body.status, 'success');
    assert.ok(Array.isArray(body.data));
    assert.strictEqual(body.meta.total, 3);
  });

  await t.test('GET /api/v1/alerts?severity=CRITICAL filters correctly', async () => {
    const port = server.address().port;
    const res = await fetch(`http://127.0.0.1:${port}/api/v1/alerts?severity=CRITICAL`);
    assert.strictEqual(res.status, 200);

    const body = await res.json();
    assert.strictEqual(body.status, 'success');
    assert.strictEqual(body.meta.total, 1);
    assert.strictEqual(body.data[0].severity, 'CRITICAL');
  });

  await t.test('GET /api/v1/alerts/:id returns single alert detail', async () => {
    const port = server.address().port;
    const validId = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';
    const res = await fetch(`http://127.0.0.1:${port}/api/v1/alerts/${validId}`);
    assert.strictEqual(res.status, 200);

    const body = await res.json();
    assert.strictEqual(body.status, 'success');
    assert.strictEqual(body.data.alert_id, validId);
  });

  await t.test('GET /api/v1/alerts/:id with invalid ID returns 404', async () => {
    const port = server.address().port;
    const res = await fetch(`http://127.0.0.1:${port}/api/v1/alerts/nonexistent-id`);
    assert.strictEqual(res.status, 404);

    const body = await res.json();
    assert.strictEqual(body.status, 'error');
    assert.strictEqual(body.error.code, 'ALERT_NOT_FOUND');
  });

  await t.test('GET /api/v1/metrics returns operational summary metrics', async () => {
    const port = server.address().port;
    const res = await fetch(`http://127.0.0.1:${port}/api/v1/metrics`);
    assert.strictEqual(res.status, 200);

    const body = await res.json();
    assert.strictEqual(body.status, 'success');
    assert.strictEqual(body.data.total_alerts, 3);
    assert.ok(body.data.by_severity);
  });

  await t.test('GET /api/v1/detectors/insights returns active detector list', async () => {
    const port = server.address().port;
    const res = await fetch(`http://127.0.0.1:${port}/api/v1/detectors/insights`);
    assert.strictEqual(res.status, 200);

    const body = await res.json();
    assert.strictEqual(body.status, 'success');
    assert.strictEqual(body.meta.count, 6);
  });
});
