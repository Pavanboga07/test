// ============================================================================
// APPLICATION B: AI NEXUS GATEWAY
// Entrypoint: `ai-nexus-gateway/src/server/gatewayMain.ts`
// Render Production Web Service + Local Development Support
// HTTP/HTTPS: `process.env.PORT` (default 4000) | WebSocket/WSS: `/ws/node`
// Zero Chatbot imports, zero frontend hosting, zero LLM providers,
// zero access to local Chatbot SQLite conversations or memories.
// ============================================================================

import express from 'express';
import { createServer as createHttpServer, Server as HttpServer } from 'node:http';
import dotenv from 'dotenv';
import {
  ExecutionMode,
  SUPPORTED_PROTOCOL_VERSIONS,
} from '../protocol/index.ts';
import { IdentityRegistry } from '../identity/IdentityRegistry.ts';
import { AuthenticationService } from '../auth/AuthenticationService.ts';
import {
  isOriginAllowed,
  RateLimiter,
  ReplayAndIdempotencyGuard,
} from '../security/SecurityGuards.ts';
import { GatewayAuditService } from '../audit/AuditService.ts';
import { OfflineQueueManager } from '../queue/OfflineQueueManager.ts';
import { InvocationManager } from '../invocation/InvocationManager.ts';
import { WebSocketNodeTransport } from '../transport/WebSocketNodeTransport.ts';
import { MessageRouter } from '../routing/MessageRouter.ts';
import { GatewayDatabase } from '../storage/gatewayDatabase.ts';

dotenv.config();

export interface GatewayServerConfig {
  port?: number;
  host?: string;
  allowedOrigins?: string;
  wsPath?: string;
  dbPath?: string;
  rateLimitPerMinute?: number;
  publicUrl?: string;
  wsPublicUrl?: string;
}

export interface GatewayServerInstance {
  httpServer: HttpServer;
  port: number;
  host: string;
  db: GatewayDatabase;
  close: () => Promise<void>;
  identities: IdentityRegistry;
  invocations: InvocationManager;
  offlineQueue: OfflineQueueManager;
}

export function createGatewayServer(
  config?: GatewayServerConfig
): Promise<GatewayServerInstance> {
  const isProd = process.env.NODE_ENV === 'production';
  const PORT =
    config?.port !== undefined
      ? config.port
      : Number(process.env.PORT || process.env.GATEWAY_PORT || 4000);
  const HOST =
    config?.host ?? (process.env.GATEWAY_HOST || process.env.HOST || '0.0.0.0');

  const NODE_WS_PATH = config?.wsPath ?? (process.env.NODE_WS_PATH || '/ws/node');
  const GATEWAY_PUBLIC_URL =
    config?.publicUrl ??
    process.env.GATEWAY_PUBLIC_URL ??
    process.env.RENDER_EXTERNAL_URL ??
    (isProd ? '' : `http://localhost:${PORT || 4000}`);
  const GATEWAY_WS_URL =
    config?.wsPublicUrl ??
    process.env.GATEWAY_WS_URL ??
    (GATEWAY_PUBLIC_URL
      ? `${GATEWAY_PUBLIC_URL.replace(/^http/, 'ws')}${NODE_WS_PATH}`
      : isProd
      ? ''
      : `ws://localhost:${PORT || 4000}${NODE_WS_PATH}`);

  const defaultAllowedOrigins = isProd
    ? [GATEWAY_PUBLIC_URL, '*'].filter(Boolean).join(',')
    : 'http://localhost:3000,http://127.0.0.1:3000,*';
  const ALLOWED_ORIGINS =
    config?.allowedOrigins ??
    (process.env.ALLOWED_ORIGINS || defaultAllowedOrigins);

  const RATE_LIMIT_PER_MIN =
    config?.rateLimitPerMinute ??
    Number(process.env.GATEWAY_RATE_LIMIT_PER_MINUTE || 60);

  // Use in-memory SQLite by default when ephemeral test port 0 is requested without explicit dbPath
  const effectiveDbPath =
    config?.dbPath ?? (config?.port === 0 && !process.env.GATEWAY_DB_PATH ? ':memory:' : undefined);

  const db = new GatewayDatabase(effectiveDbPath);
  const identities = new IdentityRegistry(db);
  const auth = new AuthenticationService(identities, db);
  const rateLimiter = new RateLimiter(RATE_LIMIT_PER_MIN);
  const replayGuard = new ReplayAndIdempotencyGuard(db);
  const offlineQueue = new OfflineQueueManager(db);
  const invocations = new InvocationManager(db);
  const audit = new GatewayAuditService(db);
  const router = new MessageRouter(
    identities,
    auth,
    rateLimiter,
    replayGuard,
    invocations,
    offlineQueue,
    audit
  );

  // Periodic background cleanup of expired offline queue entries
  const cleanupTimer = setInterval(() => {
    try {
      offlineQueue.cleanExpired();
    } catch {
      // Ignore background maintenance error
    }
  }, 60_000);
  cleanupTimer.unref?.();

  const app = express();
  // Safely trust Render's reverse proxy (single hop TLS termination)
  app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use(express.json({ limit: '256kb' }));

  // Explicit CORS & Origin validation
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin) {
      if (isOriginAllowed(origin, ALLOWED_ORIGINS)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
      } else {
        res.status(403).json({
          error: 'Origin not allowed by AI Nexus Gateway CORS policy',
        });
        return;
      }
    } else if (ALLOWED_ORIGINS.includes('*')) {
      res.setHeader('Access-Control-Allow-Origin', '*');
    }
    res.setHeader(
      'Access-Control-Allow-Methods',
      'GET, POST, PATCH, DELETE, OPTIONS'
    );
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, X-Correlation-Id'
    );
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  });

  const httpServer = createHttpServer(app);
  const wsTransport = new WebSocketNodeTransport(
    httpServer,
    NODE_WS_PATH,
    ALLOWED_ORIGINS,
    identities,
    invocations,
    offlineQueue,
    audit
  );
  router.setWebSocketTransport(wsTransport);

  const buildHealthPayload = (req?: express.Request) => {
    const allIds = identities.listAll();
    const connectedAiIds = wsTransport.getConnectedAiIds();
    const queuedCount = offlineQueue.getAllQueued().length;
    const integrity = db.checkIntegrity();
    const forwardedProto =
      (req?.headers['x-forwarded-proto'] as string | undefined)
        ?.split(',')[0]
        ?.trim() ||
      req?.protocol ||
      (isProd ? 'https' : 'http');

    return {
      status: integrity.ok ? ('OK' as const) : ('DEGRADED' as const),
      service: 'ai-nexus-gateway' as const,
      version: '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      uptimeSeconds: Math.round(process.uptime()),
      protocolVersion: '1.0',
      supportedProtocolVersions: [...SUPPORTED_PROTOCOL_VERSIONS],
      databaseReady: integrity.ok,
      databaseStatus: integrity.ok ? 'READY' : 'UNHEALTHY',
      journalMode: integrity.journalMode,
      wsTransportActive: true,
      wsPath: NODE_WS_PATH,
      transportScheme: forwardedProto === 'https' ? 'wss' : 'ws',
      publicUrl: GATEWAY_PUBLIC_URL || undefined,
      wsPublicUrl: GATEWAY_WS_URL || undefined,
      registeredIdentities: allIds.length,
      registeredIdentitiesCount: allIds.length,
      activeNodeConnections: connectedAiIds.length,
      connectedNodesCount: connectedAiIds.length,
      connectedNodeAiIds: connectedAiIds,
      queuedMessagesCount: queuedCount,
      queueStatus: queuedCount > 0 ? `${queuedCount}_QUEUED` : 'IDLE',
      activeInvocationsCount: invocations.listAll().length,
      timestamp: new Date().toISOString(),
    };
  };

  // Health Check Endpoints (Both /api/health and /health supported)
  const handleHealth: express.RequestHandler = (req, res) => {
    res.status(200).json(buildHealthPayload(req));
  };
  app.get('/api/health', handleHealth);
  app.get('/health', handleHealth);

  // Readiness Check Endpoints (Both /api/ready and /ready supported for Render healthCheckPath)
  const handleReady: express.RequestHandler = (req, res) => {
    const integrity = db.checkIntegrity();
    const payload = buildHealthPayload(req);
    const isReady = Boolean(integrity.ok);

    res.status(isReady ? 200 : 503).json({
      ready: isReady,
      ...payload,
      checks: {
        sqliteStorage: integrity.ok ? 'READY' : 'FAILED',
        identityRegistry: 'READY',
        messageRouter: 'READY',
        offlineQueue: 'READY',
        webSocketTransport: 'READY',
      },
    });
  };
  app.get('/api/ready', handleReady);
  app.get('/ready', handleReady);

  // Pairing & Proof-of-Possession Registration
  app.post('/api/v1/pairing/challenge', (req, res) => {
    const { aiId, nodeId, identity } = req.body ?? {};
    if (!aiId || !nodeId) {
      res.status(400).json({ error: 'aiId and nodeId are required' });
      return;
    }
    const challenge = identities.createPairingChallenge(aiId, nodeId, identity);
    res.json({ challenge });
  });

  app.post('/api/v1/pairing/verify', (req, res) => {
    const { challengeId, signature, keyFingerprint, aiId } = req.body ?? {};
    const result = identities.verifyPairingChallenge(
      challengeId,
      signature,
      keyFingerprint
    );
    audit.record({
      repository: 'ai-nexus-gateway',
      module: 'PairingService',
      eventType: result.verified
        ? 'IDENTITY_PROOF_OF_POSSESSION_VERIFIED'
        : 'PAIRING_CHALLENGE_FAILED',
      actorAiId: aiId ?? 'unknown',
      outcome: result.verified ? 'SUCCESS' : 'DENIED',
      summary: result.verified
        ? `Verified Ed25519 challenge-response signature for ${aiId} (${challengeId}).`
        : `Failed proof-of-possession challenge ${challengeId}: ${result.reason}`,
    });
    res.json(result);
  });

  // Identity Registry Endpoints
  app.get('/api/v1/identities', (_req, res) => {
    res.json({ identities: identities.listAll() });
  });

  app.get('/api/v1/identities/:aiId', (req, res) => {
    const found = identities.get(req.params.aiId);
    if (!found) {
      res.status(404).json({ error: 'Identity not found' });
      return;
    }
    res.json({ identity: found });
  });

  app.post('/api/v1/identities/:aiId/rotate-key', (req, res) => {
    const { aiId } = req.params;
    const { certificate } = req.body ?? {};
    if (certificate) {
      const certResult = identities.rotateKeyWithCertificate(aiId, certificate);
      if (!certResult.rotated || !certResult.identity) {
        audit.record({
          repository: 'ai-nexus-gateway',
          module: 'IdentityRegistry',
          eventType: 'PUBLIC_KEY_ROTATION_REJECTED',
          actorAiId: aiId,
          outcome: 'DENIED',
          summary: `Rejected key rotation for ${aiId}: ${certResult.reason}`,
        });
        res.status(403).json({ error: certResult.reason || 'Key rotation verification failed' });
        return;
      }
      audit.record({
        repository: 'ai-nexus-gateway',
        module: 'IdentityRegistry',
        eventType: 'PUBLIC_KEY_ROTATED',
        actorAiId: aiId,
        outcome: 'SUCCESS',
        summary: `Verified dual-signed rotation certificate and rotated Ed25519+X25519 keys for ${aiId} -> fingerprint ${certResult.identity.keyFingerprint}.`,
      });
      res.json({ identity: certResult.identity, verifiedCertificate: true });
      return;
    }

    const newFp = `ed25519:${Math.random().toString(16).slice(2, 10)}${Date.now()
      .toString(16)
      .slice(-8)}`;
    const newPem = `-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA${Buffer.from(
      `${aiId}:${newFp}`
    ).toString('base64')}\n-----END PUBLIC KEY-----`;
    const updated = identities.rotateKey(aiId, newPem, newFp);
    if (!updated) {
      res.status(404).json({ error: 'Identity not found or revoked' });
      return;
    }
    audit.record({
      repository: 'ai-nexus-gateway',
      module: 'IdentityRegistry',
      eventType: 'PUBLIC_KEY_ROTATED',
      actorAiId: aiId,
      outcome: 'SUCCESS',
      summary: `Rotated Ed25519 public key for ${aiId} -> fingerprint ${newFp}.`,
    });
    res.json({ identity: updated });
  });

  app.post('/api/v1/identities/:aiId/revoke', (req, res) => {
    const { aiId } = req.params;
    const revoked = identities.revoke(aiId);
    if (!revoked) {
      res.status(404).json({ error: 'Identity not found' });
      return;
    }
    audit.record({
      repository: 'ai-nexus-gateway',
      module: 'IdentityRegistry',
      eventType: 'IDENTITY_REVOKED',
      actorAiId: aiId,
      outcome: 'REVOKED',
      summary: `Revoked AI identity ${aiId}.`,
    });
    res.json({ identity: revoked });
  });

  app.patch('/api/v1/identities/:aiId/status', (req, res) => {
    const { aiId } = req.params;
    const {
      online,
      executionMode,
      killSwitchActive,
      configuredProvider,
      configuredModel,
    } = req.body ?? {};
    const updated = identities.updateStatus(aiId, {
      online,
      executionMode: executionMode as ExecutionMode | undefined,
      killSwitchActive,
      configuredProvider,
      configuredModel,
    });
    if (!updated) {
      res.status(404).json({ error: 'Identity not found' });
      return;
    }
    let deliveredRecords: unknown[] = [];
    if (online === true) {
      deliveredRecords = wsTransport.drainOfflineQueueForNode(aiId);
    }
    audit.record({
      repository: 'ai-nexus-gateway',
      module: 'PresenceService',
      eventType: 'IDENTITY_STATUS_UPDATED',
      actorAiId: aiId,
      outcome: 'SUCCESS',
      summary: `Updated ${aiId} status (online=${updated.online}, mode=${updated.executionMode}, killSwitch=${updated.killSwitchActive}, drained=${deliveredRecords.length}).`,
    });
    res.json({ identity: updated, deliveredRecords });
  });

  // Permissions Reference Revocation
  app.post('/api/v1/permissions/:refId/revoke', (req, res) => {
    const { refId } = req.params;
    auth.revokePermissionReference(refId);
    res.json({ revoked: true, permissionReference: refId });
  });

  // Connection Events Routing over Gateway WebSocket
  app.post('/api/v1/connections/events', (req, res) => {
    const envelope = req.body?.envelope;
    const payload = envelope?.payload ?? req.body?.payload ?? req.body;
    if (!payload || !payload.initiatorAiId || !payload.targetAiId) {
      res.status(400).json({ error: 'initiatorAiId and targetAiId are required' });
      return;
    }
    const delivered = wsTransport.deliverConnectionEvent(envelope ?? payload);
    res.json({ accepted: true, deliveredLive: delivered });
  });

  // Invocations Routing & Status
  app.post('/api/v1/invocations', async (req, res) => {
    const { envelope } = req.body ?? {};
    if (!envelope) {
      res.status(400).json({ error: 'Missing envelope in request body' });
      return;
    }
    const result = await router.routeInvocation(envelope);
    res.json(result);
  });

  // Async/Deferred Invocation Response Delivery (e.g. after Recipient Owner ASK Approval)
  app.post('/api/v1/invocations/:requestId/response', (req, res) => {
    const { requestId } = req.params;
    const { responseEnvelope } = req.body ?? {};
    if (!responseEnvelope) {
      res.status(400).json({ error: 'Missing responseEnvelope' });
      return;
    }
    const authCheck = auth.authenticateEnvelope(responseEnvelope);
    if (!authCheck.authenticated) {
      res.status(403).json({
        delivered: false,
        error: authCheck.error,
      });
      return;
    }
    const completed = wsTransport.handleIncomingNodeResponse(
      requestId,
      responseEnvelope
    );
    res.json({
      delivered: Boolean(completed),
      record: completed,
    });
  });

  app.get('/api/v1/invocations', (_req, res) => {
    res.json({
      invocations: invocations.listAll(),
      queuedOffline: offlineQueue.getAllQueued(),
    });
  });

  // Audit Events
  app.get('/api/v1/audit', (_req, res) => {
    res.json({ events: audit.list() });
  });

  // Gateway Storage Backup & Maintenance Endpoints
  app.post('/api/v1/admin/backup', (_req, res) => {
    try {
      const backup = db.createBackup();
      audit.record({
        repository: 'ai-nexus-gateway',
        module: 'StorageMaintenance',
        eventType: 'DATABASE_BACKUP_CREATED',
        actorAiId: 'system',
        outcome: 'SUCCESS',
        summary: `Created atomic Gateway SQLite backup at ${backup.backupPath}.`,
      });
      res.json(backup);
    } catch (err) {
      res.status(500).json({
        backupCreated: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  });

  app.post('/api/v1/admin/cleanup-expired', (_req, res) => {
    const expired = offlineQueue.cleanExpired();
    res.json({
      cleanedCount: expired.length,
      expiredRequestIds: expired.map((r) => r.requestId),
    });
  });

  let closed = false;
  const closeServer = async (): Promise<void> => {
    if (closed) return;
    closed = true;
    clearInterval(cleanupTimer);
    await wsTransport.close();
    await new Promise<void>((r) => {
      if (!httpServer.listening) {
        r();
        return;
      }
      httpServer.close(() => r());
    });
    db.close();
  };

  return new Promise((resolve, reject) => {
    httpServer.once('error', (err) => reject(err));
    httpServer.listen(PORT, HOST, () => {
      const address = httpServer.address();
      const actualPort =
        typeof address === 'object' && address ? address.port : PORT;
      console.log(
        `[ai-nexus-gateway] Listening on http://${HOST}:${actualPort} (WS: ws://${HOST}:${actualPort}${NODE_WS_PATH}, DB: ${db.dbPath}) [PID: ${process.pid}]`
      );
      resolve({
        httpServer,
        port: actualPort,
        host: HOST,
        db,
        identities,
        invocations,
        offlineQueue,
        close: closeServer,
      });
    });
  });
}

// Run directly when invoked as `tsx src/server/gatewayMain.ts` or `node --import tsx src/server/gatewayMain.ts`
const isDirectExecution =
  process.argv[1]?.endsWith('gatewayMain.ts') ||
  process.argv[1]?.endsWith('gatewayMain.js');

if (isDirectExecution) {
  createGatewayServer()
    .then((instance) => {
      const handleSignal = async (signal: string) => {
        console.log(
          `[ai-nexus-gateway] Received ${signal}. Starting graceful shutdown...`
        );
        try {
          await instance.close();
          console.log('[ai-nexus-gateway] Graceful shutdown complete.');
          process.exit(0);
        } catch (err) {
          console.error('[ai-nexus-gateway] Error during graceful shutdown:', err);
          process.exit(1);
        }
      };

      process.once('SIGTERM', () => void handleSignal('SIGTERM'));
      process.once('SIGINT', () => void handleSignal('SIGINT'));
    })
    .catch((err) => {
      console.error('[ai-nexus-gateway] Fatal startup error:', err);
      process.exit(1);
    });
}
