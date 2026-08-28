/**
 * PassiveShield AI — Focused API Endpoint Tests
 */

const test = require('node:test');
const assert = require('node:assert');

const app = require('../src/app');

test('Express API Gateway Unit Tests', async (t) => {
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
    assert.strictEqual(body.status, 'ok');
    assert.strictEqual(body.service, 'PassiveShield AI Express API Gateway');
  });

  await t.test('GET /api/v1/health returns status 200 OK', async () => {
    const port = server.address().port;
    const res = await fetch(`http://127.0.0.1:${port}/api/v1/health`);
    assert.strictEqual(res.status, 200);

    const body = await res.json();
    assert.strictEqual(body.status, 'ok');
  });

  await t.test('GET /api/v1/alerts returns cached standardized alerts', async () => {
    const port = server.address().port;
    const res = await fetch(`http://127.0.0.1:${port}/api/v1/alerts`);
    assert.strictEqual(res.status, 200);

    const body = await res.json();
    assert.strictEqual(body.status, 'success');
    assert.ok(Array.isArray(body.alerts));
    assert.strictEqual(body.alerts[0].event_type, 'ThreatAlert');
  });

  await t.test('GET /unknown-endpoint returns status 404', async () => {
    const port = server.address().port;
    const res = await fetch(`http://127.0.0.1:${port}/unknown-endpoint`);
    assert.strictEqual(res.status, 404);
  });
});
