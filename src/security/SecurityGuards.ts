// ============================================================================
// ai-nexus-gateway — src/security/SecurityGuards.ts
// RateLimiter, ReplayProtection, IdempotencyService & Origin Validation
// ============================================================================

import { InvocationRecord } from '../protocol/index.ts';
import { GatewayDatabase } from '../storage/gatewayDatabase.ts';

export class RateLimiter {
  private counters = new Map<string, { count: number; windowStartMs: number }>();
  constructor(private maxPerMinute: number = 60) {}

  checkAndIncrement(aiId: string, nowMs: number = Date.now()): boolean {
    const entry = this.counters.get(aiId);
    if (!entry || nowMs - entry.windowStartMs >= 60_000) {
      this.counters.set(aiId, { count: 1, windowStartMs: nowMs });
      return true;
    }
    if (entry.count >= this.maxPerMinute) {
      return false;
    }
    entry.count += 1;
    return true;
  }
}

export class ReplayAndIdempotencyGuard {
  private seenNonces = new Set<string>();
  private idempotencyResults = new Map<string, InvocationRecord>();

  constructor(private db?: GatewayDatabase) {
    if (this.db) {
      for (const rec of this.db.loadAllInvocations()) {
        this.idempotencyResults.set(rec.idempotencyKey, rec);
      }
    }
  }

  checkAndRecordNonce(senderAiId: string, nonce: string): boolean {
    if (this.db) {
      const ok = this.db.checkAndRecordNonce(senderAiId, nonce);
      if (!ok) return false;
      this.seenNonces.add(`${senderAiId}:${nonce}`);
      return true;
    }
    const key = `${senderAiId}:${nonce}`;
    if (this.seenNonces.has(key)) return false;
    this.seenNonces.add(key);
    return true;
  }

  getIdempotentRecord(idempotencyKey: string): InvocationRecord | undefined {
    const cached = this.idempotencyResults.get(idempotencyKey);
    if (cached) return cached;
    if (this.db) {
      const found = this.db
        .loadAllInvocations()
        .find((r) => r.idempotencyKey === idempotencyKey);
      if (found) {
        this.idempotencyResults.set(idempotencyKey, found);
        return found;
      }
    }
    return undefined;
  }

  saveIdempotentRecord(idempotencyKey: string, record: InvocationRecord): void {
    this.idempotencyResults.set(idempotencyKey, record);
  }
}

export function isOriginAllowed(origin: string | undefined, allowedOriginsCsv: string): boolean {
  if (!origin) return true; // Node-to-Node backend/CLI WebSocket connections omit browser Origin header
  const allowedList = allowedOriginsCsv
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (allowedList.includes('*') || allowedList.includes(origin)) {
    return true;
  }
  return false;
}
