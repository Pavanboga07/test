// ============================================================================
// ai-nexus-gateway — src/audit/AuditService.ts
// Gateway Operational & Security Audit Logger
// ============================================================================

import { AuditEventRecord } from '../protocol/index.ts';
import { GatewayDatabase } from '../storage/gatewayDatabase.ts';

export class GatewayAuditService {
  private events: AuditEventRecord[] = [];

  constructor(private db?: GatewayDatabase) {
    if (this.db) {
      this.events = this.db.listAuditEvents(300);
    }
  }

  record(event: Omit<AuditEventRecord, 'eventId' | 'timestamp'>): AuditEventRecord {
    const full: AuditEventRecord = {
      ...event,
      eventId: `aud_gw_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      timestamp: new Date().toISOString(),
    };
    this.events.unshift(full);
    if (this.events.length > 300) {
      this.events.length = 300;
    }
    this.db?.insertAuditEvent(full);
    return full;
  }

  list(): AuditEventRecord[] {
    if (this.db) {
      return this.db.listAuditEvents(300);
    }
    return [...this.events];
  }
}
