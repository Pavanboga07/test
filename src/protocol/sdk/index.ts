// ============================================================================
// ai-nexus-chatbot — src/protocol/sdk/index.ts
// Protocol Client SDK: Signed + E2EE Encrypted Envelope Builder & Gateway HTTP Client (v1.0)
// ============================================================================

import {
  AuditEventRecord,
  CURRENT_PROTOCOL_VERSION,
  DEFAULT_TTL_SECONDS,
  EncryptedEnvelopePayload,
  EnvelopeMessageType,
  ExecutionMode,
  GatewayErrorCode,
  InvocationRecord,
  InvocationRequestPayload,
  InvocationResponsePayload,
  KeyRotationCertificate,
  MessageEnvelope,
  PairingChallenge,
  PublicAIIdentity,
} from '../types/index.ts';
import {
  buildEnvelopeCanonicalString,
  computeDeterministicSignature,
} from '../validators/index.ts';
import {
  computeKeyFingerprint,
  decryptEnvelopePayloadE2EE,
  encryptEnvelopePayloadE2EE,
} from '../crypto/index.ts';

export function createSignedMessageEnvelope<TPayload>(params: {
  messageId?: string;
  correlationId: string;
  idempotencyKey: string;
  senderAiId: string;
  recipientAiId: string;
  groupId?: string;
  type: EnvelopeMessageType;
  ttlSeconds?: number;
  permissionReference?: string;
  payload: TPayload;
  keyFingerprint: string;
  signingPrivateKeyPem?: string;
  recipientEncryptionPublicKeyPem?: string;
  recipientEncryptionKeyFingerprint?: string;
  nowMs?: number;
}): MessageEnvelope<TPayload> {
  const nowMs = params.nowMs ?? Date.now();
  const messageId =
    params.messageId ??
    `msg_${nowMs}_${Math.random().toString(36).slice(2, 8)}`;
  const ttlSeconds = params.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  const timestamp = new Date(nowMs).toISOString();
  const expiresAt = new Date(nowMs + ttlSeconds * 1000).toISOString();
  const nonce = `nonce_${Math.random().toString(36).slice(2, 10)}_${nowMs}`;

  let wirePayload: TPayload = params.payload;
  let encryptedPayload: EncryptedEnvelopePayload | undefined;

  if (params.recipientEncryptionPublicKeyPem) {
    const recipientEncFp =
      params.recipientEncryptionKeyFingerprint ??
      computeKeyFingerprint(params.recipientEncryptionPublicKeyPem, 'x25519');
    encryptedPayload = encryptEnvelopePayloadE2EE({
      plaintextPayload: params.payload,
      messageId,
      correlationId: params.correlationId,
      senderAiId: params.senderAiId,
      recipientAiId: params.recipientAiId,
      senderSigningKeyFingerprint: params.keyFingerprint,
      recipientEncryptionPublicKeyPem: params.recipientEncryptionPublicKeyPem,
      recipientEncryptionKeyFingerprint: recipientEncFp,
    });

    // Redact sensitive content on the wire so the Gateway only sees minimal routing metadata!
    const p = params.payload as Record<string, unknown>;
    if (p && typeof p === 'object') {
      if ('question' in p) {
        wirePayload = {
          requestId: p.requestId,
          capability: p.capability,
          question: '[ENCRYPTED_E2EE_PAYLOAD]',
          purpose: '[ENCRYPTED_E2EE_PAYLOAD]',
          maxResponseChars: p.maxResponseChars ?? 800,
          maxFollowUpTurns: p.maxFollowUpTurns ?? 5,
          currentTurn: p.currentTurn ?? 1,
          maxBudgetUsd: p.maxBudgetUsd ?? 0.05,
          queueIfOffline: Boolean(p.queueIfOffline),
        } as unknown as TPayload;
      } else if ('minimizedDisclosures' in p || 'answer' in p) {
        wirePayload = {
          requestId: p.requestId,
          status: p.status,
          answer: p.answer ? '[ENCRYPTED_E2EE_PAYLOAD]' : undefined,
          minimizedDisclosures: {},
          withheldReasonSummary: p.withheldReasonSummary
            ? '[ENCRYPTED_E2EE_PAYLOAD]'
            : undefined,
          provenance: p.provenance
            ? {
                ...(p.provenance as Record<string, unknown>),
                disclosedFields: [],
                withheldFields: [],
              }
            : undefined,
          error: p.error,
          approvalRequiredReason: p.approvalRequiredReason,
          pendingApprovalId: p.pendingApprovalId,
          turnNumber: p.turnNumber ?? 1,
          estimatedCostUsd: p.estimatedCostUsd ?? 0,
        } as unknown as TPayload;
      }
    }
  }

  const canonical = buildEnvelopeCanonicalString({
    messageId,
    correlationId: params.correlationId,
    senderAiId: params.senderAiId,
    recipientAiId: params.recipientAiId,
    nonce,
    encryptedPayload,
  });

  const signature = computeDeterministicSignature(
    canonical,
    params.keyFingerprint,
    params.signingPrivateKeyPem
  );

  return {
    protocolVersion: CURRENT_PROTOCOL_VERSION,
    messageId,
    correlationId: params.correlationId,
    idempotencyKey: params.idempotencyKey,
    senderAiId: params.senderAiId,
    recipientAiId: params.recipientAiId,
    groupId: params.groupId,
    type: params.type,
    timestamp,
    expiresAt,
    ttlSeconds,
    permissionReference: params.permissionReference,
    payload: wirePayload,
    encryptedPayload,
    security: {
      signatureAlgorithm: 'Ed25519',
      keyFingerprint: params.keyFingerprint,
      signature,
      nonce,
      signedAt: timestamp,
      e2eeEncrypted: Boolean(encryptedPayload),
    },
  };
}

/**
 * Opens an incoming MessageEnvelope: if `encryptedPayload` is present, decrypts and
 * authenticates it using the recipient's X25519 private key.
 */
export function openEnvelopePayload<TPayload>(
  envelope: MessageEnvelope<TPayload>,
  recipientEncryptionPrivateKeyPem?: string
): TPayload {
  if (!envelope.encryptedPayload) {
    return envelope.payload;
  }
  if (!recipientEncryptionPrivateKeyPem) {
    throw new Error(
      `Envelope ${envelope.messageId} is E2EE encrypted (${envelope.encryptedPayload.algorithm}) but no X25519 private key was provided to decrypt it.`
    );
  }
  return decryptEnvelopePayloadE2EE<TPayload>({
    encryptedPayload: envelope.encryptedPayload,
    messageId: envelope.messageId,
    correlationId: envelope.correlationId,
    expectedSenderAiId: envelope.senderAiId,
    expectedRecipientAiId: envelope.recipientAiId,
    recipientEncryptionPrivateKeyPem,
  });
}

export interface GatewayHealthResponse {
  status: 'OK' | 'DEGRADED';
  service: 'ai-nexus-gateway';
  protocolVersion: '1.0';
  supportedProtocolVersions: string[];
  databaseReady: boolean;
  wsTransportActive: boolean;
  wsPath: string;
  registeredIdentitiesCount: number;
  connectedNodesCount: number;
  connectedNodeAiIds: string[];
  queuedMessagesCount: number;
  activeInvocationsCount: number;
  timestamp: string;
}

export class GatewayProtocolHttpClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  getBaseUrl(): string {
    return this.baseUrl;
  }

  async checkHealth(timeoutMs: number = 2000): Promise<{
    reachable: boolean;
    health?: GatewayHealthResponse;
    error?: string;
  }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(`${this.baseUrl}/health`, {
        signal: controller.signal,
      });
      if (!res.ok) {
        return {
          reachable: false,
          error: `Gateway returned HTTP ${res.status}`,
        };
      }
      const health = (await res.json()) as GatewayHealthResponse;
      return { reachable: true, health };
    } catch (err) {
      return {
        reachable: false,
        error: err instanceof Error ? err.message : 'Gateway unreachable',
      };
    } finally {
      clearTimeout(timer);
    }
  }

  async registerAndVerifyIdentity(
    identity: PublicAIIdentity,
    signingPrivateKeyPem?: string
  ): Promise<{
    verified: boolean;
    challenge?: PairingChallenge;
    identity?: PublicAIIdentity;
    error?: string;
  }> {
    const chalRes = await fetch(`${this.baseUrl}/api/v1/pairing/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        aiId: identity.aiId,
        nodeId: identity.nodeId,
        identity,
      }),
    });
    if (!chalRes.ok) {
      const text = await chalRes.text();
      return { verified: false, error: `Challenge creation failed: ${text}` };
    }
    const { challenge } = (await chalRes.json()) as {
      challenge: PairingChallenge;
    };

    const signature = computeDeterministicSignature(
      `${challenge.challengeId}:${challenge.nonce}:${challenge.aiId}`,
      identity.keyFingerprint,
      signingPrivateKeyPem
    );

    const verRes = await fetch(`${this.baseUrl}/api/v1/pairing/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challengeId: challenge.challengeId,
        aiId: identity.aiId,
        keyFingerprint: identity.keyFingerprint,
        signature,
      }),
    });
    const verData = (await verRes.json()) as {
      verified?: boolean;
      identity?: PublicAIIdentity;
      reason?: string;
    };
    return {
      verified: Boolean(verData.verified),
      challenge,
      identity: verData.identity,
      error: verData.reason,
    };
  }

  async listIdentities(): Promise<PublicAIIdentity[]> {
    const res = await fetch(`${this.baseUrl}/api/v1/identities`);
    if (!res.ok) throw new Error(`Gateway HTTP ${res.status}`);
    const data = (await res.json()) as { identities?: PublicAIIdentity[] };
    return data.identities ?? [];
  }

  async rotateKey(
    aiId: string,
    certificate?: KeyRotationCertificate
  ): Promise<PublicAIIdentity> {
    const res = await fetch(
      `${this.baseUrl}/api/v1/identities/${encodeURIComponent(
        aiId
      )}/rotate-key`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ certificate }),
      }
    );
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Key rotation failed: HTTP ${res.status} ${errText}`);
    }
    const data = (await res.json()) as { identity: PublicAIIdentity };
    return data.identity;
  }

  async updateIdentityConfig(
    aiId: string,
    updates: {
      online?: boolean;
      executionMode?: ExecutionMode;
      killSwitchActive?: boolean;
      configuredProvider?: PublicAIIdentity['configuredProvider'];
      configuredModel?: string;
    }
  ): Promise<{
    identity: PublicAIIdentity;
    deliveredRecords?: InvocationRecord[];
  }> {
    const res = await fetch(
      `${this.baseUrl}/api/v1/identities/${encodeURIComponent(aiId)}/status`,
      {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates),
      }
    );
    if (!res.ok) throw new Error(`Status update failed: HTTP ${res.status}`);
    return (await res.json()) as {
      identity: PublicAIIdentity;
      deliveredRecords?: InvocationRecord[];
    };
  }

  async sendInvocation(
    envelope: MessageEnvelope<InvocationRequestPayload>,
    timeoutMs: number = 12000
  ): Promise<{
    accepted: boolean;
    queued: boolean;
    duplicate: boolean;
    record?: InvocationRecord;
    error?: { code: GatewayErrorCode; message: string };
  }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(`${this.baseUrl}/api/v1/invocations`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ envelope }),
        signal: controller.signal,
      });
      return (await res.json()) as {
        accepted: boolean;
        queued: boolean;
        duplicate: boolean;
        record?: InvocationRecord;
        error?: { code: GatewayErrorCode; message: string };
      };
    } catch (err) {
      return {
        accepted: false,
        queued: false,
        duplicate: false,
        error: {
          code: GatewayErrorCode.INTERNAL_ERROR,
          message: `Cannot reach AI Nexus Gateway at ${this.baseUrl}: ${
            err instanceof Error ? err.message : 'Network error'
          }`,
        },
      };
    } finally {
      clearTimeout(timer);
    }
  }

  async deliverAsyncResponse(
    requestId: string,
    responseEnvelope: MessageEnvelope<InvocationResponsePayload>
  ): Promise<{ delivered: boolean }> {
    const res = await fetch(
      `${this.baseUrl}/api/v1/invocations/${encodeURIComponent(
        requestId
      )}/response`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ responseEnvelope }),
      }
    );
    if (!res.ok) return { delivered: false };
    return (await res.json()) as { delivered: boolean };
  }

  async listInvocations(): Promise<{
    invocations: InvocationRecord[];
    queuedOffline: InvocationRecord[];
  }> {
    const res = await fetch(`${this.baseUrl}/api/v1/invocations`);
    if (!res.ok) throw new Error(`Gateway HTTP ${res.status}`);
    return (await res.json()) as {
      invocations: InvocationRecord[];
      queuedOffline: InvocationRecord[];
    };
  }

  async listAuditEvents(): Promise<AuditEventRecord[]> {
    const res = await fetch(`${this.baseUrl}/api/v1/audit`);
    if (!res.ok) throw new Error(`Gateway HTTP ${res.status}`);
    const data = (await res.json()) as { events?: AuditEventRecord[] };
    return data.events ?? [];
  }
}
