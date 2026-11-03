// ============================================================================
// ai-nexus-gateway — src/identity/IdentityRegistry.ts
// Manages PublicAIIdentity registration, Node heartbeats, Pairing Challenges,
// and Dual-Signed Key Rotation Certificates
// Backed by GatewayDatabase (SQLite WAL) for durability across restarts
// ============================================================================

import {
  ExecutionMode,
  KeyRotationCertificate,
  PairingChallenge,
  PublicAIIdentity,
  verifyDeterministicSignature,
  verifyKeyRotationCertificate,
} from '../protocol/index.ts';
import { GatewayDatabase } from '../storage/gatewayDatabase.ts';

export class IdentityRegistry {
  private identities = new Map<string, PublicAIIdentity>();
  private heartbeats = new Map<string, number>();
  private challenges = new Map<string, PairingChallenge>();

  constructor(private db?: GatewayDatabase) {
    if (this.db) {
      for (const persisted of this.db.loadAllIdentities()) {
        this.identities.set(persisted.aiId, persisted);
      }
    }
  }

  register(identity: PublicAIIdentity): PublicAIIdentity {
    const copy = { ...identity };
    this.identities.set(identity.aiId, copy);
    this.heartbeats.set(identity.aiId, Date.now());
    this.db?.upsertIdentity(copy);
    return { ...copy };
  }

  get(aiIdOrHandle: string): PublicAIIdentity | undefined {
    const direct = this.identities.get(aiIdOrHandle);
    if (direct) return { ...direct };
    const normalized = aiIdOrHandle.startsWith('@')
      ? aiIdOrHandle.toLowerCase()
      : `@${aiIdOrHandle.toLowerCase()}`;
    for (const item of this.identities.values()) {
      if (item.handle.toLowerCase() === normalized) {
        return { ...item };
      }
    }
    return undefined;
  }

  listAll(): PublicAIIdentity[] {
    return Array.from(this.identities.values()).map((i) => ({ ...i }));
  }

  recordHeartbeat(aiId: string, nowMs: number = Date.now()): void {
    this.heartbeats.set(aiId, nowMs);
    const existing = this.identities.get(aiId);
    if (existing) {
      existing.lastHeartbeatAt = new Date(nowMs).toISOString();
      this.db?.upsertIdentity(existing);
    }
  }

  rotateKey(
    aiId: string,
    newPublicKeyPem: string,
    newKeyFingerprint: string,
    newEncryptionPublicKeyPem?: string,
    newEncryptionKeyFingerprint?: string
  ): PublicAIIdentity | undefined {
    const existing = this.identities.get(aiId);
    if (!existing || existing.registrationState === 'REVOKED') return undefined;
    existing.publicKeyPem = newPublicKeyPem;
    existing.keyFingerprint = newKeyFingerprint;
    if (newEncryptionPublicKeyPem) {
      existing.encryptionPublicKeyPem = newEncryptionPublicKeyPem;
    }
    if (newEncryptionKeyFingerprint) {
      existing.encryptionKeyFingerprint = newEncryptionKeyFingerprint;
    }
    existing.lastHeartbeatAt = new Date().toISOString();
    this.db?.upsertIdentity(existing);
    return { ...existing };
  }

  rotateKeyWithCertificate(
    aiId: string,
    certificate: KeyRotationCertificate
  ): { rotated: boolean; identity?: PublicAIIdentity; reason?: string } {
    const existing = this.identities.get(aiId);
    if (!existing || existing.registrationState === 'REVOKED') {
      return { rotated: false, reason: 'Identity not found or revoked' };
    }
    if (certificate.aiId !== aiId) {
      return { rotated: false, reason: 'Certificate aiId mismatch' };
    }
    const check = verifyKeyRotationCertificate(
      certificate,
      existing.publicKeyPem
    );
    if (!check.valid) {
      return { rotated: false, reason: check.reason };
    }

    const updated = this.rotateKey(
      aiId,
      certificate.newPublicKeyPem,
      certificate.newKeyFingerprint,
      certificate.newEncryptionPublicKeyPem,
      certificate.newEncryptionKeyFingerprint
    );
    return { rotated: true, identity: updated };
  }

  revoke(aiId: string): PublicAIIdentity | undefined {
    const existing = this.identities.get(aiId);
    if (!existing) return undefined;
    existing.registrationState = 'REVOKED';
    existing.verificationState = 'REVOKED';
    existing.online = false;
    existing.revokedAt = new Date().toISOString();
    this.db?.upsertIdentity(existing);
    return { ...existing };
  }

  updateStatus(
    aiId: string,
    updates: {
      online?: boolean;
      executionMode?: ExecutionMode;
      killSwitchActive?: boolean;
      configuredProvider?: PublicAIIdentity['configuredProvider'];
      configuredModel?: string;
    }
  ): PublicAIIdentity | undefined {
    const existing = this.identities.get(aiId);
    if (!existing || existing.registrationState === 'REVOKED') return undefined;
    if (typeof updates.online === 'boolean') existing.online = updates.online;
    if (updates.executionMode) existing.executionMode = updates.executionMode;
    if (typeof updates.killSwitchActive === 'boolean') {
      existing.killSwitchActive = updates.killSwitchActive;
    }
    if (updates.configuredProvider) {
      existing.configuredProvider = updates.configuredProvider;
    }
    if (updates.configuredModel) {
      existing.configuredModel = updates.configuredModel;
    }
    existing.lastHeartbeatAt = new Date().toISOString();
    this.db?.upsertIdentity(existing);
    return { ...existing };
  }

  createPairingChallenge(
    aiId: string,
    nodeId: string,
    pendingIdentity?: PublicAIIdentity,
    nowMs: number = Date.now()
  ): PairingChallenge {
    if (pendingIdentity) {
      const existing = this.identities.get(aiId);
      const registered: PublicAIIdentity = {
        ...(existing ?? {}),
        ...pendingIdentity,
        registrationState: 'REGISTERED',
      };
      this.identities.set(aiId, registered);
      this.db?.upsertIdentity(registered);
    }
    const challengeId = `chal_${aiId}_${nowMs}_${Math.random()
      .toString(36)
      .slice(2, 6)}`;
    const nonce = `nonce_${Math.random().toString(36).slice(2, 10)}_${nowMs}`;
    const challenge: PairingChallenge = {
      challengeId,
      aiId,
      nodeId,
      nonce,
      issuedAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(nowMs + 5 * 60 * 1000).toISOString(),
      verified: false,
    };
    this.challenges.set(challengeId, challenge);
    this.db?.savePairingChallenge(challenge);
    return challenge;
  }

  verifyPairingChallenge(
    challengeId: string,
    signature: string,
    keyFingerprint: string,
    nowMs: number = Date.now()
  ): { verified: boolean; identity?: PublicAIIdentity; reason?: string } {
    const challenge =
      this.challenges.get(challengeId) ??
      this.db?.getPairingChallenge(challengeId);
    if (!challenge) return { verified: false, reason: 'Challenge not found' };
    if (challenge.verified) {
      return { verified: false, reason: 'Challenge already consumed' };
    }
    if (Date.parse(challenge.expiresAt) <= nowMs) {
      return { verified: false, reason: 'Challenge expired' };
    }

    const identity = this.identities.get(challenge.aiId);
    const canonical = `${challenge.challengeId}:${challenge.nonce}:${challenge.aiId}`;
    const isValid = verifyDeterministicSignature(
      canonical,
      keyFingerprint,
      signature,
      identity?.publicKeyPem
    );

    if (!isValid) {
      return {
        verified: false,
        reason: 'Invalid Ed25519 proof-of-possession signature',
      };
    }

    challenge.verified = true;
    this.challenges.set(challengeId, challenge);
    this.db?.savePairingChallenge(challenge);

    if (identity) {
      identity.registrationState = 'REGISTERED';
      identity.verificationState = 'VERIFIED';
      identity.lastHeartbeatAt = new Date(nowMs).toISOString();
      this.db?.upsertIdentity(identity);
    }
    return { verified: true, identity: identity ? { ...identity } : undefined };
  }
}
