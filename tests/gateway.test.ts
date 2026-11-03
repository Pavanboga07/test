// ============================================================================
// ai-nexus-gateway — tests/gateway.test.ts
// Comprehensive Production Readiness, Render Compatibility, Security,
// TLS/WSS Reverse Proxy, and Durable SQLite Persistence Test Suite
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import net from 'node:net';
import { execSync } from 'node:child_process';
import { WebSocket } from 'ws';
import {
  CapabilityType,
  computeDeterministicSignature,
  createSignedMessageEnvelope,
  EnvelopeMessageType,
  ExecutionMode,
  GatewayErrorCode,
  generateIdentityKeyBundle,
  InvocationRequestPayload,
  InvocationState,
  PublicAIIdentity,
  signEd25519Canonical,
} from '../src/protocol/index.ts';
import { createGatewayServer } from '../src/server/gatewayMain.ts';

function buildTestIdentity(
  aiId: string,
  handle: string,
  displayName: string
): { identity: PublicAIIdentity; privateKeyPem: string } {
  const bundle = generateIdentityKeyBundle();
  return {
    privateKeyPem: bundle.signingPrivateKeyPem,
    identity: {
      aiId,
      handle,
      displayName,
      ownerId: `owner_${aiId}`,
      ownerDisplayName: `${displayName} Owner`,
      nodeId: `node_${aiId}_01`,
      deviceId: `dev_${aiId}_01`,
      publicKeyPem: bundle.signingPublicKeyPem,
      encryptionPublicKeyPem: bundle.encryptionPublicKeyPem,
      encryptionKeyFingerprint: bundle.encryptionKeyFingerprint,
      keyFingerprint: bundle.signingKeyFingerprint,
      registrationState: 'REGISTERED',
      verificationState: 'VERIFIED',
      executionMode: ExecutionMode.LOCAL,
      online: false,
      killSwitchActive: false,
      supportedProtocolVersions: ['1.0'],
      configuredProvider: 'gemini',
      configuredModel: 'gemini-3.8-flash',
      createdAt: new Date().toISOString(),
      lastHeartbeatAt: new Date().toISOString(),
    },
  };
}

test('1. Gateway binds to process.env.PORT on 0.0.0.0 and serves /api/health, /api/ready, /health, and /ready', async () => {
  const prevPort = process.env.PORT;
  // Find a free ephemeral port first, then pass it via process.env.PORT
  const freePort = await new Promise<number>((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });

  process.env.PORT = String(freePort);
  const gw = await createGatewayServer({ dbPath: ':memory:' });
  try {
    assert.equal(gw.port, freePort, 'Gateway must bind to process.env.PORT');
    assert.equal(gw.host, '0.0.0.0', 'Gateway must bind to 0.0.0.0 by default');

    // Verify /api/health and /health
    for (const healthPath of ['/api/health', '/health']) {
      const healthRes = await fetch(`http://127.0.0.1:${gw.port}${healthPath}`, {
        headers: { 'X-Forwarded-Proto': 'https' },
      });
      assert.equal(healthRes.status, 200);
      const health = await healthRes.json();
      assert.equal(health.service, 'ai-nexus-gateway');
      assert.equal(health.status, 'OK');
      assert.equal(health.databaseReady, true);
      assert.equal(health.wsPath, '/ws/node');
      assert.equal(
        health.transportScheme,
        'wss',
        'Gateway must respect X-Forwarded-Proto: https behind Render TLS proxy'
      );
    }

    // Verify /api/ready and /ready
    for (const readyPath of ['/api/ready', '/ready']) {
      const readyRes = await fetch(`http://127.0.0.1:${gw.port}${readyPath}`);
      assert.equal(readyRes.status, 200);
      const ready = await readyRes.json();
      assert.equal(ready.ready, true);
      assert.equal(ready.checks.sqliteStorage, 'READY');
      assert.equal(ready.checks.identityRegistry, 'READY');
      assert.equal(ready.checks.messageRouter, 'READY');
      assert.equal(ready.checks.offlineQueue, 'READY');
      assert.equal(ready.checks.webSocketTransport, 'READY');
    }
  } finally {
    if (prevPort === undefined) {
      delete process.env.PORT;
    } else {
      process.env.PORT = prevPort;
    }
    await gw.close();
  }
});

test('2. Gateway enforces Ed25519 challenge-response pairing, invalid auth rejection, origin validation, and rate limiting', async () => {
  const gw = await createGatewayServer({
    port: 0,
    dbPath: ':memory:',
    allowedOrigins: 'https://trusted-client.example.com',
    rateLimitPerMinute: 2,
  });

  try {
    const baseUrl = `http://127.0.0.1:${gw.port}`;

    // A. Origin validation on HTTP
    const blockedOriginRes = await fetch(`${baseUrl}/api/health`, {
      headers: { Origin: 'https://malicious-site.example.com' },
    });
    assert.equal(blockedOriginRes.status, 403);

    const allowedOriginRes = await fetch(`${baseUrl}/api/health`, {
      headers: { Origin: 'https://trusted-client.example.com' },
    });
    assert.equal(allowedOriginRes.status, 200);
    assert.equal(
      allowedOriginRes.headers.get('access-control-allow-origin'),
      'https://trusted-client.example.com'
    );

    // B. Pairing challenge & verification
    const aliceBundle = buildTestIdentity('ai_alice', '@alice', 'Alice AI');
    const bobBundle = buildTestIdentity('ai_bob', '@bob', 'Bob AI');
    const aliceIdentity = aliceBundle.identity;
    const bobIdentity = bobBundle.identity;

    for (const item of [aliceBundle, bobBundle]) {
      const id = item.identity;
      const chalRes = await fetch(`${baseUrl}/api/v1/pairing/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ aiId: id.aiId, nodeId: id.nodeId, identity: id }),
      });
      const { challenge } = await chalRes.json();
      const validSig = signEd25519Canonical(
        `${challenge.challengeId}:${challenge.nonce}:${challenge.aiId}`,
        item.privateKeyPem
      );

      // Invalid signature must fail
      const badVerRes = await fetch(`${baseUrl}/api/v1/pairing/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeId: challenge.challengeId,
          aiId: id.aiId,
          keyFingerprint: id.keyFingerprint,
          signature: 'ed25519_sig_tampered',
        }),
      });
      assert.equal((await badVerRes.json()).verified, false);

      // Valid signature succeeds
      const verRes = await fetch(`${baseUrl}/api/v1/pairing/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeId: challenge.challengeId,
          aiId: id.aiId,
          keyFingerprint: id.keyFingerprint,
          signature: validSig,
        }),
      });
      assert.equal((await verRes.json()).verified, true);
    }

    // C. WebSocket invalid authentication rejection
    await new Promise<void>((resolve, reject) => {
      const ws = new WebSocket(`ws://127.0.0.1:${gw.port}/ws/node`, {
        headers: { Origin: 'https://trusted-client.example.com' },
      });
      ws.on('open', () => {
        ws.send(
          JSON.stringify({
            type: 'node.authenticate',
            aiId: 'ai_alice',
            nodeId: 'node_alice_01',
            nonce: 'bad_nonce',
            keyFingerprint: aliceIdentity.keyFingerprint,
            signature: 'invalid_ws_signature',
          })
        );
      });
      ws.on('message', (raw) => {
        const msg = JSON.parse(raw.toString());
        if (msg.type === 'node.auth_failed') {
          ws.close();
          resolve();
        }
      });
      ws.on('error', reject);
    });

    // D. Rate limiting enforcement (max 2 requests per minute configured)
    const makeInvocationEnvelope = (idx: number) =>
      createSignedMessageEnvelope<InvocationRequestPayload>({
        correlationId: `corr_rl_${idx}`,
        idempotencyKey: `idem_rl_${idx}`,
        senderAiId: 'ai_alice',
        recipientAiId: 'ai_bob',
        type: EnvelopeMessageType.INVOCATION_REQUEST,
        keyFingerprint: aliceIdentity.keyFingerprint,
        signingPrivateKeyPem: aliceBundle.privateKeyPem,
        payload: {
          requestId: `req_rl_${idx}`,
          capability: 'calendar.availability',
          question: `Rate limit test ${idx}`,
          purpose: 'Scheduling sync',
          maxResponseChars: 400,
          maxFollowUpTurns: 2,
          currentTurn: 1,
          maxBudgetUsd: 0.05,
          queueIfOffline: true,
        },
      });

    const r1 = await (
      await fetch(`${baseUrl}/api/v1/invocations`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ envelope: makeInvocationEnvelope(1) }),
      })
    ).json();
    assert.equal(r1.accepted, true);

    const r2 = await (
      await fetch(`${baseUrl}/api/v1/invocations`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ envelope: makeInvocationEnvelope(2) }),
      })
    ).json();
    assert.equal(r2.accepted, true);

    const r3 = await (
      await fetch(`${baseUrl}/api/v1/invocations`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ envelope: makeInvocationEnvelope(3) }),
      })
    ).json();
    assert.equal(r3.accepted, false);
    assert.equal(r3.error.code, GatewayErrorCode.RATE_LIMITED);
  } finally {
    await gw.close();
  }
});

test('3. Durable Gateway SQLite Persistence: Identities, offline queue, replay nonces, and backups survive Gateway restart without duplicate delivery', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-nexus-gw-persist-'));
  const dbPath = path.join(tmpDir, 'gateway.sqlite');

  const aliceBundle = buildTestIdentity('ai_alice', '@alice', 'Alice AI');
  const bobBundle = buildTestIdentity('ai_bob', '@bob', 'Bob AI');
  const alice = aliceBundle.identity;
  const bob = bobBundle.identity;

  const validQueuedEnvelope = createSignedMessageEnvelope<InvocationRequestPayload>({
    correlationId: 'corr_persist_valid',
    idempotencyKey: 'idem_persist_valid',
    senderAiId: 'ai_alice',
    recipientAiId: 'ai_bob',
    type: EnvelopeMessageType.INVOCATION_REQUEST,
    keyFingerprint: alice.keyFingerprint,
    signingPrivateKeyPem: aliceBundle.privateKeyPem,
    payload: {
      requestId: 'req_persist_valid',
      capability: 'calendar.availability',
      question: 'Are you available at 3 PM after Gateway restart?',
      purpose: 'Meeting coordination',
      maxResponseChars: 400,
      maxFollowUpTurns: 2,
      currentTurn: 1,
      maxBudgetUsd: 0.05,
      queueIfOffline: true,
    },
  });

  // --- GATEWAY INSTANCE 1 ---
  const gw1 = await createGatewayServer({ port: 0, dbPath });
  try {
    const url1 = `http://127.0.0.1:${gw1.port}`;
    gw1.identities.register(alice);
    gw1.identities.register(bob);

    // Enqueue invocation while Bob is offline
    const invRes = await fetch(`${url1}/api/v1/invocations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ envelope: validQueuedEnvelope }),
    });
    const invData = await invRes.json();
    assert.equal(invData.accepted, true);
    assert.equal(invData.queued, true);

    // Also enqueue an already-expiring record directly to verify expiration cleanup on restart
    const expiringEnv = createSignedMessageEnvelope<InvocationRequestPayload>({
      correlationId: 'corr_expiring',
      idempotencyKey: 'idem_expiring',
      senderAiId: 'ai_alice',
      recipientAiId: 'ai_bob',
      type: EnvelopeMessageType.INVOCATION_REQUEST,
      keyFingerprint: alice.keyFingerprint,
      signingPrivateKeyPem: aliceBundle.privateKeyPem,
      ttlSeconds: -10,
      payload: {
        requestId: 'req_expiring',
        capability: 'calendar.availability',
        question: 'Expired request',
        purpose: 'Expiration test',
        maxResponseChars: 400,
        maxFollowUpTurns: 1,
        currentTurn: 1,
        maxBudgetUsd: 0.01,
        queueIfOffline: true,
      },
    });
    const expRecord = gw1.invocations.createRecord(expiringEnv, 'ai_bob');
    expRecord.queuedOffline = true;
    gw1.offlineQueue.enqueue('ai_bob', expRecord);

    // Create atomic SQLite backup via API
    const backupRes = await fetch(`${url1}/api/v1/admin/backup`, {
      method: 'POST',
    });
    assert.equal(backupRes.status, 200);
    const backupData = await backupRes.json();
    assert.equal(backupData.backupCreated, true);
    assert.ok(fs.existsSync(backupData.backupPath));
  } finally {
    await gw1.close();
  }

  // --- GATEWAY INSTANCE 2 (Restarted on the same /var/data-style SQLite file) ---
  const gw2 = await createGatewayServer({ port: 0, dbPath });
  try {
    const url2 = `http://127.0.0.1:${gw2.port}`;

    // 1. Verify registered identities survived restart (and online reset to false until WS reconnect)
    const idRes = await fetch(`${url2}/api/v1/identities`);
    const idData = await idRes.json();
    assert.equal(idData.identities.length, 2);

    // 2. Verify expired offline queue item was automatically cleaned on startup while valid item remains
    const queuedForBob = gw2.offlineQueue.getQueuedFor('ai_bob');
    assert.equal(queuedForBob.length, 1);
    assert.equal(queuedForBob[0].requestId, 'req_persist_valid');

    // 3. Verify replay protection persisted across restart (reusing the same signed envelope nonce with a new idempotencyKey is rejected)
    const replayEnvelope = {
      ...validQueuedEnvelope,
      idempotencyKey: 'idem_replay_after_restart',
    };
    const replayRes = await fetch(`${url2}/api/v1/invocations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ envelope: replayEnvelope }),
    });
    const replayData = await replayRes.json();
    assert.equal(replayData.accepted, false);
    assert.equal(replayData.error.code, GatewayErrorCode.DUPLICATE_REQUEST);

    // 4. Connect Bob over WebSocket -> verify queued message is drained exactly once, and not re-delivered on second reconnect
    const deliveredToBob: string[] = [];
    const connectBobOnce = () =>
      new Promise<number>((resolve, reject) => {
        const ws = new WebSocket(`ws://127.0.0.1:${gw2.port}/ws/node`);
        const nonce = `ws_nonce_${Date.now()}_${Math.random()}`;
        const sig = signEd25519Canonical(
          `ws_auth:ai_bob:${bob.nodeId}:${nonce}`,
          bobBundle.privateKeyPem
        );
        let drainedCount = 0;

        ws.on('open', () => {
          ws.send(
            JSON.stringify({
              type: 'node.authenticate',
              aiId: 'ai_bob',
              nodeId: bob.nodeId,
              nonce,
              keyFingerprint: bob.keyFingerprint,
              signature: sig,
            })
          );
        });

        ws.on('message', (raw) => {
          const frame = JSON.parse(raw.toString());
          if (frame.type === 'node.authenticated') {
            drainedCount = frame.drainedQueueCount;
            setTimeout(() => {
              ws.close();
              resolve(drainedCount);
            }, 40);
          }
          if (frame.type === 'invocation.deliver') {
            deliveredToBob.push(frame.requestId);
          }
        });
        ws.on('error', reject);
      });

    const firstDrainCount = await connectBobOnce();
    assert.equal(firstDrainCount, 1);
    assert.deepEqual(deliveredToBob, ['req_persist_valid']);

    // Reconnect Bob a second time -> queue must now be empty (zero duplicate deliveries)
    const secondDrainCount = await connectBobOnce();
    assert.equal(secondDrainCount, 0);
    assert.equal(deliveredToBob.length, 1);
  } finally {
    await gw2.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('4. WSS Compatibility through TLS Reverse Proxy (Render TLS Termination Simulation)', async () => {
  const gw = await createGatewayServer({ port: 0, dbPath: ':memory:' });
  const tmpCertDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-nexus-tls-'));
  const keyPath = path.join(tmpCertDir, 'key.pem');
  const certPath = path.join(tmpCertDir, 'cert.pem');

  // Generate ephemeral self-signed TLS cert using openssl for local HTTPS/WSS termination proxy
  execSync(
    `openssl req -x509 -newkey rsa:2048 -nodes -keyout "${keyPath}" -out "${certPath}" -days 1 -subj "/CN=127.0.0.1"`,
    { stdio: 'ignore' }
  );

  const tlsProxy = https.createServer(
    {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
    },
    async (req, res) => {
      // Forward HTTPS request to Gateway HTTP server with X-Forwarded-Proto: https
      const targetUrl = `http://127.0.0.1:${gw.port}${req.url}`;
      const proxyRes = await fetch(targetUrl, {
        method: req.method,
        headers: {
          ...Object.fromEntries(
            Object.entries(req.headers).filter(
              ([, v]) => typeof v === 'string'
            ) as Array<[string, string]>
          ),
          'x-forwarded-proto': 'https',
        },
      });
      res.writeHead(proxyRes.status, { 'content-type': 'application/json' });
      res.end(await proxyRes.text());
    }
  );

  // Forward WSS upgrade frames at TCP level to Gateway HTTP server
  tlsProxy.on('upgrade', (req, clientSocket, head) => {
    const upstream = net.connect(gw.port, '127.0.0.1', () => {
      const headers = [
        `${req.method} ${req.url} HTTP/${req.httpVersion}`,
        ...Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`),
        'X-Forwarded-Proto: https',
        '',
        '',
      ].join('\r\n');
      upstream.write(headers);
      if (head && head.length > 0) upstream.write(head);
      clientSocket.pipe(upstream).pipe(clientSocket);
    });
    upstream.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
  });

  await new Promise<void>((resolve) => tlsProxy.listen(0, '127.0.0.1', resolve));
  const proxyAddr = tlsProxy.address();
  const tlsPort = typeof proxyAddr === 'object' && proxyAddr ? proxyAddr.port : 0;

  try {
    const aliceBundle = buildTestIdentity('ai_alice', '@alice', 'Alice AI');
    const alice = aliceBundle.identity;
    gw.identities.register(alice);

    // Connect over real WSS (wss://127.0.0.1:<tlsPort>/ws/node) through the TLS proxy
    await new Promise<void>((resolve, reject) => {
      const wssClient = new WebSocket(`wss://127.0.0.1:${tlsPort}/ws/node`, {
        rejectUnauthorized: false,
      });
      const nonce = `wss_nonce_${Date.now()}`;
      const sig = signEd25519Canonical(
        `ws_auth:ai_alice:${alice.nodeId}:${nonce}`,
        aliceBundle.privateKeyPem
      );

      wssClient.on('open', () => {
        wssClient.send(
          JSON.stringify({
            type: 'node.authenticate',
            aiId: 'ai_alice',
            nodeId: alice.nodeId,
            nonce,
            keyFingerprint: alice.keyFingerprint,
            signature: sig,
          })
        );
      });

      wssClient.on('message', (raw) => {
        const frame = JSON.parse(raw.toString());
        if (frame.type === 'node.authenticated') {
          assert.equal(frame.aiId, 'ai_alice');
          wssClient.close();
          resolve();
        }
      });

      wssClient.on('error', reject);
    });
  } finally {
    await new Promise<void>((resolve) => tlsProxy.close(() => resolve()));
    await gw.close();
    fs.rmSync(tmpCertDir, { recursive: true, force: true });
  }
});
