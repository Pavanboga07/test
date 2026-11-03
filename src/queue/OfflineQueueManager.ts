// ============================================================================
// ai-nexus-gateway — src/queue/OfflineQueueManager.ts
// Queues eligible invocations when recipient Personal AI node is offline
// Durable SQLite persistence prevents message loss across restarts & prevents
// duplicate delivery via idempotency tracking.
// ============================================================================

import {
  InvocationRecord,
  InvocationState,
} from '../protocol/index.ts';
import { GatewayDatabase } from '../storage/gatewayDatabase.ts';

export class OfflineQueueManager {
  private queues = new Map<string, InvocationRecord[]>();

  constructor(private db?: GatewayDatabase) {
    if (this.db) {
      for (const rec of this.db.getAllPendingOfflineQueue()) {
        const list = this.queues.get(rec.recipientAiId) ?? [];
        list.push(rec);
        this.queues.set(rec.recipientAiId, list);
      }
    }
  }

  enqueue(recipientAiId: string, record: InvocationRecord): void {
    if (this.db) {
      const inserted = this.db.enqueueOffline(recipientAiId, record);
      if (!inserted) return;
    }
    const list = this.queues.get(recipientAiId) ?? [];
    if (!list.some((item) => item.idempotencyKey === record.idempotencyKey)) {
      list.push(record);
      this.queues.set(recipientAiId, list);
    }
  }

  drainEligible(recipientAiId: string, nowMs: number = Date.now()): {
    validRecords: InvocationRecord[];
    expiredRecords: InvocationRecord[];
  } {
    if (this.db) {
      const drained = this.db.drainOfflineQueueForRecipient(recipientAiId, nowMs);
      this.queues.delete(recipientAiId);
      return drained;
    }

    const list = this.queues.get(recipientAiId) ?? [];
    this.queues.delete(recipientAiId);
    const validRecords: InvocationRecord[] = [];
    const expiredRecords: InvocationRecord[] = [];

    for (const rec of list) {
      if (Date.parse(rec.expiresAt) <= nowMs) {
        rec.state = InvocationState.EXPIRED;
        rec.queuedOffline = false;
        rec.transitions.push({
          state: InvocationState.EXPIRED,
          timestamp: new Date(nowMs).toISOString(),
          summary: 'Queued request expired while recipient node was offline.',
          actor: 'GATEWAY',
        });
        expiredRecords.push(rec);
      } else {
        rec.queuedOffline = false;
        validRecords.push(rec);
      }
    }
    return { validRecords, expiredRecords };
  }

  cleanExpired(nowMs: number = Date.now()): InvocationRecord[] {
    if (this.db) {
      const expired = this.db.cleanExpiredQueueEntries(nowMs);
      for (const [aiId, list] of this.queues.entries()) {
        const remaining = list.filter((r) => Date.parse(r.expiresAt) > nowMs);
        if (remaining.length === 0) {
          this.queues.delete(aiId);
        } else {
          this.queues.set(aiId, remaining);
        }
      }
      return expired;
    }
    const allExpired: InvocationRecord[] = [];
    for (const [aiId, list] of this.queues.entries()) {
      const remaining: InvocationRecord[] = [];
      for (const rec of list) {
        if (Date.parse(rec.expiresAt) <= nowMs) {
          rec.state = InvocationState.EXPIRED;
          rec.queuedOffline = false;
          allExpired.push(rec);
        } else {
          remaining.push(rec);
        }
      }
      if (remaining.length === 0) {
        this.queues.delete(aiId);
      } else {
        this.queues.set(aiId, remaining);
      }
    }
    return allExpired;
  }

  getQueuedFor(recipientAiId: string): InvocationRecord[] {
    if (this.db) {
      return this.db.getPendingOfflineQueueFor(recipientAiId);
    }
    return [...(this.queues.get(recipientAiId) ?? [])];
  }

  getAllQueued(): InvocationRecord[] {
    if (this.db) {
      return this.db.getAllPendingOfflineQueue();
    }
    const all: InvocationRecord[] = [];
    for (const list of this.queues.values()) {
      all.push(...list);
    }
    return all;
  }
}
