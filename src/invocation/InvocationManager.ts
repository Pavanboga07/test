// ============================================================================
// ai-nexus-gateway — src/invocation/InvocationManager.ts
// Tracks the 13-state AI-to-AI invocation lifecycle & correlates responses
// Backed by GatewayDatabase (SQLite WAL) for durable delivery acknowledgements
// ============================================================================

import {
  canTransitionInvocationState,
  InvocationRecord,
  InvocationRequestPayload,
  InvocationResponsePayload,
  InvocationState,
  MessageEnvelope,
} from '../protocol/index.ts';
import { GatewayDatabase } from '../storage/gatewayDatabase.ts';

export class InvocationManager {
  private invocations = new Map<string, InvocationRecord>();
  private pendingWaiters = new Map<
    string,
    {
      resolve: (record: InvocationRecord) => void;
      timer: NodeJS.Timeout;
    }
  >();

  constructor(private db?: GatewayDatabase) {
    if (this.db) {
      for (const rec of this.db.loadAllInvocations()) {
        this.invocations.set(rec.requestId, rec);
      }
    }
  }

  createRecord(
    envelope: MessageEnvelope<InvocationRequestPayload>,
    recipientAiId: string,
    nowMs: number = Date.now()
  ): InvocationRecord {
    const nowIso = new Date(nowMs).toISOString();
    const record: InvocationRecord = {
      requestId: envelope.payload.requestId ?? envelope.messageId,
      correlationId: envelope.correlationId,
      idempotencyKey: envelope.idempotencyKey,
      senderAiId: envelope.senderAiId,
      recipientAiId,
      capability: envelope.payload.capability,
      question: envelope.payload.question,
      state: InvocationState.SENT,
      transitions: [
        {
          state: InvocationState.CREATED,
          timestamp: envelope.timestamp,
          summary: `${envelope.senderAiId} created invocation request (${envelope.payload.capability}).`,
          actor: 'SENDER_NODE',
        },
        {
          state: InvocationState.SENT,
          timestamp: nowIso,
          summary: `Verified Ed25519 signature (${envelope.security.keyFingerprint.slice(0, 12)}…) and accepted by AI Nexus Gateway.`,
          actor: 'GATEWAY',
        },
      ],
      envelope,
      createdAt: nowIso,
      updatedAt: nowIso,
      expiresAt: envelope.expiresAt,
      queuedOffline: false,
    };
    this.invocations.set(record.requestId, record);
    this.db?.upsertInvocation(record);
    return record;
  }

  saveRecord(record: InvocationRecord): void {
    this.invocations.set(record.requestId, record);
    this.db?.upsertInvocation(record);
  }

  transition(
    requestId: string,
    nextState: InvocationState,
    summary: string,
    actor: 'SENDER_NODE' | 'GATEWAY' | 'RECIPIENT_NODE' | 'POLICY_ENGINE',
    nowMs: number = Date.now()
  ): InvocationRecord | undefined {
    const record = this.invocations.get(requestId);
    if (!record) return undefined;
    if (record.state !== nextState && canTransitionInvocationState(record.state, nextState)) {
      record.state = nextState;
    } else if (record.state !== nextState) {
      record.state = nextState;
    }
    record.updatedAt = new Date(nowMs).toISOString();
    record.transitions.push({
      state: nextState,
      timestamp: record.updatedAt,
      summary,
      actor,
    });
    this.db?.upsertInvocation(record);
    return record;
  }

  completeWithResponse(
    requestId: string,
    responseEnvelope: MessageEnvelope<InvocationResponsePayload>,
    nowMs: number = Date.now()
  ): InvocationRecord | undefined {
    const record = this.invocations.get(requestId);
    if (!record) return undefined;
    record.responseEnvelope = responseEnvelope;
    record.queuedOffline = false;
    const targetState = responseEnvelope.payload.status;

    if (targetState === InvocationState.REQUIRES_APPROVAL) {
      record.approvalRequiredReason = responseEnvelope.payload.approvalRequiredReason;
    }

    this.transition(
      requestId,
      targetState,
      targetState === InvocationState.COMPLETED
        ? `Gateway verified ${responseEnvelope.senderAiId} response signature and routed result to ${responseEnvelope.recipientAiId}.`
        : responseEnvelope.payload.error?.message ||
          responseEnvelope.payload.approvalRequiredReason ||
          `Terminal state: ${targetState}`,
      'GATEWAY',
      nowMs
    );

    const waiter = this.pendingWaiters.get(requestId);
    if (waiter) {
      clearTimeout(waiter.timer);
      this.pendingWaiters.delete(requestId);
      waiter.resolve(record);
    }
    return record;
  }

  waitForCompletion(requestId: string, timeoutMs: number = 9000): Promise<InvocationRecord> {
    const existing = this.invocations.get(requestId);
    if (
      existing &&
      (existing.state === InvocationState.COMPLETED ||
        existing.state === InvocationState.REJECTED ||
        existing.state === InvocationState.REQUIRES_APPROVAL ||
        existing.state === InvocationState.FAILED ||
        existing.state === InvocationState.EXPIRED)
    ) {
      return Promise.resolve(existing);
    }

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pendingWaiters.delete(requestId);
        const current = this.invocations.get(requestId)!;
        resolve(current);
      }, timeoutMs);

      this.pendingWaiters.set(requestId, { resolve, timer });
    });
  }

  get(requestId: string): InvocationRecord | undefined {
    return this.invocations.get(requestId);
  }

  listAll(): InvocationRecord[] {
    if (this.db) {
      const persisted = this.db.loadAllInvocations();
      for (const p of persisted) {
        this.invocations.set(p.requestId, p);
      }
    }
    return Array.from(this.invocations.values()).sort(
      (a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt)
    );
  }
}
