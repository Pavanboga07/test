// ============================================================================
// ai-nexus-gateway — src/storage/gatewayDatabase.ts
// Durable SQLite Storage for Public AI Nexus Gateway Infrastructure
//
// Stores ONLY public Gateway routing & security state:
//   1. Registered PublicAIIdentity records & Pairing Challenges
//   2. Offline Queue entries (with idempotency & expiration tracking)
//   3. Invocation routing records & delivery acknowledgements
//   4. Consumed cryptographic nonces (replay protection across restarts)
//   5. Revoked permission reference IDs
//   6. Gateway operational & security audit log
//
// NEVER stores private Chatbot conversations, user messages, private memories,
// owner datasets, node private keys, or LLM API keys.
// ============================================================================

import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  AuditEventRecord,
  InvocationRecord,
  InvocationState,
  PairingChallenge,
  PublicAIIdentity,
} from '../protocol/index.ts';

const GATEWAY_MIGRATIONS: Array<{ version: number; name: string; sql: string }> = [
  {
    version: 1,
    name: '001_gateway_durable_infrastructure_schema',
    sql: `
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS gateway_identities (
        ai_id TEXT PRIMARY KEY,
        handle TEXT NOT NULL,
        node_id TEXT NOT NULL,
        key_fingerprint TEXT NOT NULL,
        registration_state TEXT NOT NULL,
        verification_state TEXT NOT NULL,
        identity_json TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_gateway_identities_handle
        ON gateway_identities(handle);

      CREATE TABLE IF NOT EXISTS pairing_challenges (
        challenge_id TEXT PRIMARY KEY,
        ai_id TEXT NOT NULL,
        node_id TEXT NOT NULL,
        nonce TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        verified INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS invocations (
        request_id TEXT PRIMARY KEY,
        idempotency_key TEXT NOT NULL UNIQUE,
        correlation_id TEXT NOT NULL,
        sender_ai_id TEXT NOT NULL,
        recipient_ai_id TEXT NOT NULL,
        state TEXT NOT NULL,
        queued_offline INTEGER NOT NULL DEFAULT 0,
        record_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_invocations_recipient_state
        ON invocations(recipient_ai_id, state, queued_offline);

      CREATE TABLE IF NOT EXISTS offline_queue (
        request_id TEXT PRIMARY KEY,
        idempotency_key TEXT NOT NULL UNIQUE,
        recipient_ai_id TEXT NOT NULL,
        sender_ai_id TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        record_json TEXT NOT NULL,
        queued_at TEXT NOT NULL,
        delivered_at TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_offline_queue_recipient_pending
        ON offline_queue(recipient_ai_id, delivered_at, expires_at);

      CREATE TABLE IF NOT EXISTS consumed_nonces (
        nonce_key TEXT PRIMARY KEY,
        sender_ai_id TEXT NOT NULL,
        recorded_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS revoked_permissions (
        ref_id TEXT PRIMARY KEY,
        revoked_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS gateway_audit_log (
        event_id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        event_json TEXT NOT NULL
      );
    `,
  },
];

export function resolveDefaultGatewayDbPath(customDbPath?: string): string {
  if (customDbPath) {
    return customDbPath;
  }
  if (process.env.GATEWAY_DB_PATH) {
    return process.env.GATEWAY_DB_PATH;
  }
  const configuredDataDir = process.env.GATEWAY_DATA_DIR;
  if (configuredDataDir) {
    return path.resolve(configuredDataDir, 'gateway.sqlite');
  }
  // In production on Render with a persistent disk mounted at /var/data, use /var/data/gateway.sqlite
  if (process.env.NODE_ENV === 'production') {
    try {
      if (fs.existsSync('/var/data')) {
        fs.accessSync('/var/data', fs.constants.W_OK);
        return '/var/data/gateway.sqlite';
      }
    } catch {
      // Fallback to local ./data directory if /var/data is not mounted
    }
  }
  return path.resolve(process.cwd(), 'data/gateway.sqlite');
}

export class GatewayDatabase {
  public readonly db: DatabaseSync;
  public readonly dbPath: string;
  private closed = false;

  constructor(customDbPath?: string) {
    this.dbPath = resolveDefaultGatewayDbPath(customDbPath);

    if (this.dbPath !== ':memory:') {
      const dir = path.dirname(this.dbPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    }

    this.db = new DatabaseSync(this.dbPath);
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA synchronous = NORMAL;');
    this.db.exec('PRAGMA busy_timeout = 5000;');
    this.db.exec('PRAGMA foreign_keys = ON;');

    this.runMigrations();
    this.recoverOnStartup();
  }

  public runMigrations(): { applied: number; totalVersions: number } {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL
      );
    `);

    let applied = 0;
    for (const migration of GATEWAY_MIGRATIONS) {
      const exists = this.db
        .prepare('SELECT version FROM schema_migrations WHERE version = ?')
        .get(migration.version) as { version: number } | undefined;

      if (!exists) {
        this.db.exec('BEGIN TRANSACTION;');
        try {
          this.db.exec(migration.sql);
          this.db
            .prepare(
              'INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)'
            )
            .run(migration.version, migration.name, new Date().toISOString());
          this.db.exec('COMMIT;');
          applied++;
        } catch (err) {
          this.db.exec('ROLLBACK;');
          throw err;
        }
      }
    }
    return { applied, totalVersions: GATEWAY_MIGRATIONS.length };
  }

  /**
   * Startup recovery:
   * 1. Marks all persisted identities as `online: false` until their WebSocket nodes reconnect.
   * 2. Cleans up any expired offline queue entries.
   */
  public recoverOnStartup(nowMs: number = Date.now()): void {
    const rows = this.db
      .prepare('SELECT ai_id, identity_json FROM gateway_identities')
      .all() as Array<{ ai_id: string; identity_json: string }>;

    const updateStmt = this.db.prepare(
      'UPDATE gateway_identities SET identity_json = ?, updated_at = ? WHERE ai_id = ?'
    );
    const nowIso = new Date(nowMs).toISOString();

    for (const row of rows) {
      try {
        const parsed = JSON.parse(row.identity_json) as PublicAIIdentity;
        if (parsed.online) {
          parsed.online = false;
          updateStmt.run(JSON.stringify(parsed), nowIso, row.ai_id);
        }
      } catch {
        // Ignore malformed legacy row
      }
    }

    this.cleanExpiredQueueEntries(nowMs);
  }

  // --- Identity Registry Persistence ---

  public upsertIdentity(identity: PublicAIIdentity): void {
    const nowIso = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO gateway_identities (
          ai_id, handle, node_id, key_fingerprint, registration_state, verification_state, identity_json, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ai_id) DO UPDATE SET
          handle = excluded.handle,
          node_id = excluded.node_id,
          key_fingerprint = excluded.key_fingerprint,
          registration_state = excluded.registration_state,
          verification_state = excluded.verification_state,
          identity_json = excluded.identity_json,
          updated_at = excluded.updated_at`
      )
      .run(
        identity.aiId,
        identity.handle.toLowerCase(),
        identity.nodeId,
        identity.keyFingerprint,
        identity.registrationState,
        identity.verificationState,
        JSON.stringify(identity),
        nowIso
      );
  }

  public loadAllIdentities(): PublicAIIdentity[] {
    const rows = this.db
      .prepare('SELECT identity_json FROM gateway_identities ORDER BY ai_id ASC')
      .all() as Array<{ identity_json: string }>;
    return rows.map((r) => JSON.parse(r.identity_json) as PublicAIIdentity);
  }

  public savePairingChallenge(challenge: PairingChallenge): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO pairing_challenges (
          challenge_id, ai_id, node_id, nonce, issued_at, expires_at, verified
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        challenge.challengeId,
        challenge.aiId,
        challenge.nodeId,
        challenge.nonce,
        challenge.issuedAt,
        challenge.expiresAt,
        challenge.verified ? 1 : 0
      );
  }

  public getPairingChallenge(challengeId: string): PairingChallenge | undefined {
    const row = this.db
      .prepare(
        `SELECT challenge_id, ai_id, node_id, nonce, issued_at, expires_at, verified
         FROM pairing_challenges WHERE challenge_id = ?`
      )
      .get(challengeId) as
      | {
          challenge_id: string;
          ai_id: string;
          node_id: string;
          nonce: string;
          issued_at: string;
          expires_at: string;
          verified: number;
        }
      | undefined;

    if (!row) return undefined;
    return {
      challengeId: row.challenge_id,
      aiId: row.ai_id,
      nodeId: row.node_id,
      nonce: row.nonce,
      issuedAt: row.issued_at,
      expiresAt: row.expires_at,
      verified: Boolean(row.verified),
    };
  }

  // --- Invocations & Delivery Acknowledgements ---

  public upsertInvocation(record: InvocationRecord): void {
    this.db
      .prepare(
        `INSERT INTO invocations (
          request_id, idempotency_key, correlation_id, sender_ai_id, recipient_ai_id,
          state, queued_offline, record_json, created_at, updated_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(request_id) DO UPDATE SET
          state = excluded.state,
          queued_offline = excluded.queued_offline,
          record_json = excluded.record_json,
          updated_at = excluded.updated_at`
      )
      .run(
        record.requestId,
        record.idempotencyKey,
        record.correlationId,
        record.senderAiId,
        record.recipientAiId,
        record.state,
        record.queuedOffline ? 1 : 0,
        JSON.stringify(record),
        record.createdAt,
        record.updatedAt,
        record.expiresAt
      );
  }

  public loadAllInvocations(): InvocationRecord[] {
    const rows = this.db
      .prepare('SELECT record_json FROM invocations ORDER BY created_at DESC')
      .all() as Array<{ record_json: string }>;
    return rows.map((r) => JSON.parse(r.record_json) as InvocationRecord);
  }

  // --- Durable Offline Queue ---

  public enqueueOffline(recipientAiId: string, record: InvocationRecord): boolean {
    const existing = this.db
      .prepare(
        'SELECT request_id, delivered_at FROM offline_queue WHERE idempotency_key = ?'
      )
      .get(record.idempotencyKey) as
      | { request_id: string; delivered_at: string | null }
      | undefined;

    if (existing) {
      return false; // Duplicate prevented
    }

    const nowIso = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO offline_queue (
          request_id, idempotency_key, recipient_ai_id, sender_ai_id,
          expires_at, record_json, queued_at, delivered_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`
      )
      .run(
        record.requestId,
        record.idempotencyKey,
        recipientAiId,
        record.senderAiId,
        record.expiresAt,
        JSON.stringify(record),
        nowIso
      );
    this.upsertInvocation(record);
    return true;
  }

  public drainOfflineQueueForRecipient(
    recipientAiId: string,
    nowMs: number = Date.now()
  ): {
    validRecords: InvocationRecord[];
    expiredRecords: InvocationRecord[];
  } {
    const rows = this.db
      .prepare(
        `SELECT request_id, record_json, expires_at
         FROM offline_queue
         WHERE recipient_ai_id = ? AND delivered_at IS NULL
         ORDER BY queued_at ASC`
      )
      .all(recipientAiId) as Array<{
      request_id: string;
      record_json: string;
      expires_at: string;
    }>;

    const validRecords: InvocationRecord[] = [];
    const expiredRecords: InvocationRecord[] = [];
    const nowIso = new Date(nowMs).toISOString();

    const markDeliveredStmt = this.db.prepare(
      'UPDATE offline_queue SET delivered_at = ?, record_json = ? WHERE request_id = ?'
    );
    const deleteExpiredStmt = this.db.prepare(
      'DELETE FROM offline_queue WHERE request_id = ?'
    );

    this.db.exec('BEGIN TRANSACTION;');
    try {
      for (const row of rows) {
        const rec = JSON.parse(row.record_json) as InvocationRecord;
        if (Date.parse(row.expires_at) <= nowMs) {
          rec.state = InvocationState.EXPIRED;
          rec.queuedOffline = false;
          rec.updatedAt = nowIso;
          rec.transitions.push({
            state: InvocationState.EXPIRED,
            timestamp: nowIso,
            summary: 'Queued request expired while recipient node was offline.',
            actor: 'GATEWAY',
          });
          deleteExpiredStmt.run(row.request_id);
          this.upsertInvocation(rec);
          expiredRecords.push(rec);
        } else {
          rec.queuedOffline = false;
          rec.updatedAt = nowIso;
          markDeliveredStmt.run(nowIso, JSON.stringify(rec), row.request_id);
          this.upsertInvocation(rec);
          validRecords.push(rec);
        }
      }
      this.db.exec('COMMIT;');
    } catch (err) {
      this.db.exec('ROLLBACK;');
      throw err;
    }

    return { validRecords, expiredRecords };
  }

  public cleanExpiredQueueEntries(nowMs: number = Date.now()): InvocationRecord[] {
    const rows = this.db
      .prepare(
        `SELECT request_id, record_json, expires_at
         FROM offline_queue
         WHERE delivered_at IS NULL`
      )
      .all() as Array<{
      request_id: string;
      record_json: string;
      expires_at: string;
    }>;

    const expired: InvocationRecord[] = [];
    const nowIso = new Date(nowMs).toISOString();
    const deleteStmt = this.db.prepare(
      'DELETE FROM offline_queue WHERE request_id = ?'
    );

    for (const row of rows) {
      if (Date.parse(row.expires_at) <= nowMs) {
        const rec = JSON.parse(row.record_json) as InvocationRecord;
        rec.state = InvocationState.EXPIRED;
        rec.queuedOffline = false;
        rec.updatedAt = nowIso;
        rec.transitions.push({
          state: InvocationState.EXPIRED,
          timestamp: nowIso,
          summary: 'Queued request expired and was cleaned by Gateway maintenance.',
          actor: 'GATEWAY',
        });
        deleteStmt.run(row.request_id);
        this.upsertInvocation(rec);
        expired.push(rec);
      }
    }
    return expired;
  }

  public getPendingOfflineQueueFor(recipientAiId: string): InvocationRecord[] {
    const rows = this.db
      .prepare(
        `SELECT record_json FROM offline_queue
         WHERE recipient_ai_id = ? AND delivered_at IS NULL
         ORDER BY queued_at ASC`
      )
      .all(recipientAiId) as Array<{ record_json: string }>;
    return rows.map((r) => JSON.parse(r.record_json) as InvocationRecord);
  }

  public getAllPendingOfflineQueue(): InvocationRecord[] {
    const rows = this.db
      .prepare(
        `SELECT record_json FROM offline_queue
         WHERE delivered_at IS NULL
         ORDER BY queued_at ASC`
      )
      .all() as Array<{ record_json: string }>;
    return rows.map((r) => JSON.parse(r.record_json) as InvocationRecord);
  }

  // --- Replay Nonces & Revoked Permission References ---

  public checkAndRecordNonce(senderAiId: string, nonce: string): boolean {
    const nonceKey = `${senderAiId}:${nonce}`;
    const existing = this.db
      .prepare('SELECT nonce_key FROM consumed_nonces WHERE nonce_key = ?')
      .get(nonceKey) as { nonce_key: string } | undefined;
    if (existing) {
      return false;
    }
    this.db
      .prepare(
        'INSERT INTO consumed_nonces (nonce_key, sender_ai_id, recorded_at) VALUES (?, ?, ?)'
      )
      .run(nonceKey, senderAiId, new Date().toISOString());
    return true;
  }

  public revokePermissionReference(refId: string): void {
    this.db
      .prepare(
        'INSERT OR IGNORE INTO revoked_permissions (ref_id, revoked_at) VALUES (?, ?)'
      )
      .run(refId, new Date().toISOString());
  }

  public isPermissionReferenceRevoked(refId?: string): boolean {
    if (!refId) return false;
    const row = this.db
      .prepare('SELECT ref_id FROM revoked_permissions WHERE ref_id = ?')
      .get(refId) as { ref_id: string } | undefined;
    return Boolean(row);
  }

  // --- Gateway Audit Log ---

  public insertAuditEvent(event: AuditEventRecord): void {
    this.db
      .prepare(
        'INSERT OR REPLACE INTO gateway_audit_log (event_id, timestamp, event_json) VALUES (?, ?, ?)'
      )
      .run(event.eventId, event.timestamp, JSON.stringify(event));
  }

  public listAuditEvents(limit: number = 300): AuditEventRecord[] {
    const rows = this.db
      .prepare(
        'SELECT event_json FROM gateway_audit_log ORDER BY timestamp DESC LIMIT ?'
      )
      .all(limit) as Array<{ event_json: string }>;
    return rows.map((r) => JSON.parse(r.event_json) as AuditEventRecord);
  }

  // --- Integrity Check, Atomic Backup & Graceful Close ---

  public checkIntegrity(): { ok: boolean; journalMode: string; details: string } {
    if (this.closed) {
      return { ok: false, journalMode: 'closed', details: 'Database connection is closed' };
    }
    try {
      const checkRow = this.db.prepare('PRAGMA quick_check;').get() as
        | { quick_check?: string }
        | undefined;
      const journalRow = this.db.prepare('PRAGMA journal_mode;').get() as
        | { journal_mode?: string }
        | undefined;
      const status = checkRow?.quick_check ?? 'ok';
      return {
        ok: status.toLowerCase() === 'ok',
        journalMode: journalRow?.journal_mode ?? 'wal',
        details: status,
      };
    } catch (err) {
      return {
        ok: false,
        journalMode: 'error',
        details: err instanceof Error ? err.message : String(err),
      };
    }
  }

  public createBackup(customBackupPath?: string): {
    backupCreated: boolean;
    backupPath: string;
    timestamp: string;
  } {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const baseDir =
      this.dbPath === ':memory:'
        ? path.resolve(process.cwd(), 'data/backups')
        : path.resolve(path.dirname(this.dbPath), 'backups');

    const targetPath =
      customBackupPath ??
      path.resolve(baseDir, `gateway-backup-${timestamp}.sqlite`);

    const targetDir = path.dirname(targetPath);
    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true });
    }
    if (fs.existsSync(targetPath)) {
      fs.unlinkSync(targetPath);
    }

    const escaped = targetPath.replace(/'/g, "''");
    this.db.exec(`VACUUM INTO '${escaped}';`);

    return {
      backupCreated: true,
      backupPath: targetPath,
      timestamp: new Date().toISOString(),
    };
  }

  public close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      if (this.dbPath !== ':memory:') {
        this.db.exec('PRAGMA wal_checkpoint(TRUNCATE);');
      }
    } catch {
      // Ignore checkpoint error on close
    }
    try {
      this.db.close();
    } catch {
      // Ignore close error
    }
  }
}
