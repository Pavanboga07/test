// ============================================================================
// ai-nexus-gateway — src/auth/AuthenticationService.ts
// Cryptographic envelope authentication (Ed25519 + E2EE binding) & permission reference validation
// ============================================================================

import {
  buildEnvelopeCanonicalString,
  GatewayErrorCode,
  MessageEnvelope,
  NexusProtocolError,
  PublicAIIdentity,
  verifyDeterministicSignature,
} from '../protocol/index.ts';
import { IdentityRegistry } from '../identity/IdentityRegistry.ts';
import { GatewayDatabase } from '../storage/gatewayDatabase.ts';

export class AuthenticationService {
  private revokedReferences = new Set<string>();

  constructor(
    private identityRegistry: IdentityRegistry,
    private db?: GatewayDatabase
  ) {}

  revokePermissionReference(refId: string): void {
    this.revokedReferences.add(refId);
    this.db?.revokePermissionReference(refId);
  }

  isPermissionReferenceRevoked(refId?: string): boolean {
    if (!refId) return false;
    if (this.revokedReferences.has(refId)) return true;
    return Boolean(this.db?.isPermissionReferenceRevoked(refId));
  }

  authenticateEnvelope(envelope: MessageEnvelope<unknown>): {
    authenticated: boolean;
    sender?: PublicAIIdentity;
    error?: NexusProtocolError;
  } {
    const sender = this.identityRegistry.get(envelope.senderAiId);
    if (!sender) {
      return {
        authenticated: false,
        error: {
          code: GatewayErrorCode.IDENTITY_NOT_FOUND,
          message: `Sender identity '${envelope.senderAiId}' is not registered with AI Nexus Gateway.`,
          correlationId: envelope.correlationId,
          retryable: false,
        },
      };
    }

    if (
      sender.registrationState === 'REVOKED' ||
      sender.verificationState === 'REVOKED'
    ) {
      return {
        authenticated: false,
        error: {
          code: GatewayErrorCode.IDENTITY_REVOKED,
          message: `Sender identity '${envelope.senderAiId}' has been revoked.`,
          correlationId: envelope.correlationId,
          retryable: false,
        },
      };
    }

    if (envelope.security.keyFingerprint !== sender.keyFingerprint) {
      return {
        authenticated: false,
        error: {
          code: GatewayErrorCode.AUTHENTICATION_FAILED,
          message: `Envelope key fingerprint mismatch for '${envelope.senderAiId}'.`,
          correlationId: envelope.correlationId,
          retryable: false,
        },
      };
    }

    const canonical = buildEnvelopeCanonicalString({
      messageId: envelope.messageId,
      correlationId: envelope.correlationId,
      senderAiId: envelope.senderAiId,
      recipientAiId: envelope.recipientAiId,
      nonce: envelope.security.nonce,
      encryptedPayload: envelope.encryptedPayload,
    });

    const isSignatureValid = verifyDeterministicSignature(
      canonical,
      sender.keyFingerprint,
      envelope.security.signature,
      sender.publicKeyPem
    );

    if (!isSignatureValid) {
      return {
        authenticated: false,
        error: {
          code: GatewayErrorCode.AUTHENTICATION_FAILED,
          message:
            'Cryptographic Ed25519 signature verification failed on message envelope.',
          correlationId: envelope.correlationId,
          retryable: false,
        },
      };
    }

    return { authenticated: true, sender };
  }
}
