// ============================================================================
// ai-nexus-gateway — src/routing/MessageRouter.ts
// Validates, authenticates, rate-limits, and routes AI-to-AI invocations
// ============================================================================

import {
  GatewayErrorCode,
  InvocationRecord,
  InvocationRequestPayload,
  InvocationState,
  MessageEnvelope,
  NexusProtocolError,
  validateMessageEnvelope,
} from '../protocol/index.ts';
import { IdentityRegistry } from '../identity/IdentityRegistry.ts';
import { AuthenticationService } from '../auth/AuthenticationService.ts';
import { RateLimiter, ReplayAndIdempotencyGuard } from '../security/SecurityGuards.ts';
import { InvocationManager } from '../invocation/InvocationManager.ts';
import { OfflineQueueManager } from '../queue/OfflineQueueManager.ts';
import { GatewayAuditService } from '../audit/AuditService.ts';
import { WebSocketNodeTransport } from '../transport/WebSocketNodeTransport.ts';

export class MessageRouter {
  constructor(
    private identities: IdentityRegistry,
    private auth: AuthenticationService,
    private rateLimiter: RateLimiter,
    private replayGuard: ReplayAndIdempotencyGuard,
    private invocations: InvocationManager,
    private offlineQueue: OfflineQueueManager,
    private audit: GatewayAuditService,
    private wsTransport?: WebSocketNodeTransport
  ) {}

  setWebSocketTransport(wsTransport: WebSocketNodeTransport): void {
    this.wsTransport = wsTransport;
  }

  async routeInvocation(
    envelope: MessageEnvelope<InvocationRequestPayload>,
    nowMs: number = Date.now()
  ): Promise<{
    accepted: boolean;
    queued: boolean;
    duplicate: boolean;
    record?: InvocationRecord;
    error?: NexusProtocolError;
  }> {
    // 1. Idempotency check
    const existingRecord = this.replayGuard.getIdempotentRecord(envelope.idempotencyKey);
    if (existingRecord) {
      return {
        accepted: true,
        queued: existingRecord.queuedOffline,
        duplicate: true,
        record: existingRecord,
      };
    }

    // 2. Envelope structural, protocol version, size & expiration validation
    const validation = validateMessageEnvelope(envelope, nowMs);
    if (!validation.valid) {
      this.audit.record({
        repository: 'ai-nexus-gateway',
        module: 'MessageRouter',
        eventType: 'ENVELOPE_REJECTED',
        actorAiId: envelope.senderAiId,
        targetAiId: envelope.recipientAiId,
        correlationId: envelope.correlationId,
        outcome: 'DENIED',
        summary: validation.error?.message ?? 'Invalid envelope',
      });
      return { accepted: false, queued: false, duplicate: false, error: validation.error };
    }

    // 3. Rate limit check
    if (!this.rateLimiter.checkAndIncrement(envelope.senderAiId, nowMs)) {
      return {
        accepted: false,
        queued: false,
        duplicate: false,
        error: {
          code: GatewayErrorCode.RATE_LIMITED,
          message: `Rate limit exceeded for sender '${envelope.senderAiId}'.`,
          correlationId: envelope.correlationId,
          retryable: true,
        },
      };
    }

    // 4. Cryptographic sender authentication
    const authResult = this.auth.authenticateEnvelope(envelope);
    if (!authResult.authenticated) {
      this.audit.record({
        repository: 'ai-nexus-gateway',
        module: 'AuthenticationService',
        eventType: 'AUTH_FAILED',
        actorAiId: envelope.senderAiId,
        targetAiId: envelope.recipientAiId,
        correlationId: envelope.correlationId,
        outcome: 'DENIED',
        summary: authResult.error?.message ?? 'Sender authentication failed',
      });
      return { accepted: false, queued: false, duplicate: false, error: authResult.error };
    }

    // 5. Replay protection (nonce uniqueness)
    if (!this.replayGuard.checkAndRecordNonce(envelope.senderAiId, envelope.security.nonce)) {
      const error: NexusProtocolError = {
        code: GatewayErrorCode.DUPLICATE_REQUEST,
        message: 'Replay protection triggered: cryptographic nonce has already been used.',
        correlationId: envelope.correlationId,
        retryable: false,
      };
      this.audit.record({
        repository: 'ai-nexus-gateway',
        module: 'ReplayProtection',
        eventType: 'REPLAY_BLOCKED',
        actorAiId: envelope.senderAiId,
        targetAiId: envelope.recipientAiId,
        correlationId: envelope.correlationId,
        outcome: 'DENIED',
        summary: error.message,
      });
      return { accepted: false, queued: false, duplicate: false, error };
    }

    // 6. Validate recipient identity
    const recipient = this.identities.get(envelope.recipientAiId);
    if (!recipient) {
      return {
        accepted: false,
        queued: false,
        duplicate: false,
        error: {
          code: GatewayErrorCode.IDENTITY_NOT_FOUND,
          message: `Recipient AI identity '${envelope.recipientAiId}' not found in Gateway registry.`,
          correlationId: envelope.correlationId,
          retryable: false,
        },
      };
    }

    if (recipient.registrationState === 'REVOKED') {
      return {
        accepted: false,
        queued: false,
        duplicate: false,
        error: {
          code: GatewayErrorCode.IDENTITY_REVOKED,
          message: `Recipient AI identity '${recipient.aiId}' has been revoked.`,
          correlationId: envelope.correlationId,
          retryable: false,
        },
      };
    }

    // 7. Permission reference revocation check
    if (this.auth.isPermissionReferenceRevoked(envelope.permissionReference)) {
      return {
        accepted: false,
        queued: false,
        duplicate: false,
        error: {
          code: GatewayErrorCode.PERMISSION_EXPIRED,
          message: `Permission reference '${envelope.permissionReference}' has been revoked.`,
          correlationId: envelope.correlationId,
          retryable: false,
        },
      };
    }

    // 8. Create InvocationRecord
    const record = this.invocations.createRecord(envelope, recipient.aiId, nowMs);
    this.replayGuard.saveIdempotentRecord(envelope.idempotencyKey, record);

    // 9. Check if recipient node is connected & online over WebSocket
    const isConnected =
      recipient.online &&
      (this.wsTransport ? this.wsTransport.isNodeSocketConnected(recipient.aiId) : false);

    if (!isConnected) {
      if (envelope.payload.queueIfOffline) {
        record.queuedOffline = true;
        record.transitions.push({
          state: InvocationState.SENT,
          timestamp: new Date(nowMs).toISOString(),
          summary: `Recipient node ${recipient.aiId} (${recipient.executionMode}) is currently offline. Request queued in OfflineQueueManager until WebSocket reconnection or expiry.`,
          actor: 'GATEWAY',
        });
        this.invocations.saveRecord(record);
        this.offlineQueue.enqueue(recipient.aiId, record);
        this.audit.record({
          repository: 'ai-nexus-gateway',
          module: 'OfflineQueueManager',
          eventType: 'INVOCATION_QUEUED_OFFLINE',
          actorAiId: envelope.senderAiId,
          targetAiId: recipient.aiId,
          correlationId: envelope.correlationId,
          outcome: 'QUEUED',
          summary: `Queued invocation ${record.requestId} for offline node ${recipient.aiId}.`,
        });
        return { accepted: true, queued: true, duplicate: false, record };
      } else {
        this.invocations.transition(
          record.requestId,
          InvocationState.FAILED,
          `Recipient node ${recipient.aiId} is offline and queueIfOffline=false.`,
          'GATEWAY',
          nowMs
        );
        return {
          accepted: false,
          queued: false,
          duplicate: false,
          record,
          error: {
            code: GatewayErrorCode.NODE_OFFLINE,
            message: `${recipient.displayName} (${recipient.handle}) is currently offline.`,
            correlationId: envelope.correlationId,
            retryable: true,
          },
        };
      }
    }

    // 10. Dispatch over live WebSocket to recipient node and await recipient node's response!
    this.wsTransport!.deliverInvocationToNode(recipient.aiId, record);
    const completedRecord = await this.invocations.waitForCompletion(record.requestId, 20000);

    return {
      accepted: true,
      queued: false,
      duplicate: false,
      record: completedRecord,
      error: completedRecord.responseEnvelope?.payload.error,
    };
  }
}
