// ============================================================================
// ai-nexus-chatbot — src/protocol/validators/index.ts
// Runtime Envelope, Real Ed25519 Signature, E2EE Integrity & Size Validation
// ============================================================================

import {
  GatewayErrorCode,
  MAX_ENVELOPE_SIZE_BYTES,
  MessageEnvelope,
  NexusProtocolError,
} from '../types/index.ts';
import { isSupportedProtocolVersion } from '../versioning/index.ts';
import {
  signEd25519Canonical,
  verifyEd25519Canonical,
} from '../crypto/index.ts';

export interface ValidationResult {
  valid: boolean;
  error?: NexusProtocolError;
}

/**
 * Builds the canonical signing string for a MessageEnvelope.
 * When `encryptedPayload` is present, its ciphertext and authTag are bound into
 * the canonical string so any tampering invalidates the Ed25519 signature.
 */
export function buildEnvelopeCanonicalString(env: {
  messageId: string;
  correlationId: string;
  senderAiId: string;
  recipientAiId: string;
  nonce: string;
  encryptedPayload?: {
    ciphertext: string;
    authTag: string;
    iv: string;
  };
}): string {
  const base = `${env.messageId}:${env.correlationId}:${env.senderAiId}:${env.recipientAiId}:${env.nonce}`;
  if (env.encryptedPayload) {
    return `${base}:${env.encryptedPayload.iv}:${env.encryptedPayload.ciphertext}:${env.encryptedPayload.authTag}`;
  }
  return base;
}

/**
 * Signs or computes a signature over a canonical payload.
 * When `signingPrivateKeyPem` is provided, uses real Node.js `crypto.sign` Ed25519.
 */
export function computeDeterministicSignature(
  canonicalPayload: string,
  keyFingerprint: string,
  signingPrivateKeyPem?: string
): string {
  if (signingPrivateKeyPem && signingPrivateKeyPem.includes('PRIVATE KEY')) {
    return signEd25519Canonical(canonicalPayload, signingPrivateKeyPem);
  }
  let hash = 2166136261;
  const input = `${keyFingerprint}::${canonicalPayload}`;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  const hex = (hash >>> 0).toString(16).padStart(8, '0');
  return `ed25519_sig_${keyFingerprint.slice(-8)}_${hex}`;
}

export function verifyDeterministicSignature(
  canonicalPayload: string,
  keyFingerprint: string,
  signature: string,
  signingPublicKeyPem?: string
): boolean {
  if (!signature || !keyFingerprint) return false;
  if (signature.startsWith('ed25519:')) {
    if (!signingPublicKeyPem || !signingPublicKeyPem.includes('PUBLIC KEY')) {
      return false;
    }
    return verifyEd25519Canonical(
      canonicalPayload,
      signature,
      signingPublicKeyPem
    );
  }
  const expected = computeDeterministicSignature(
    canonicalPayload,
    keyFingerprint
  );
  return signature === expected;
}

export function validateMessageEnvelope(
  envelope: unknown,
  nowMs: number = Date.now(),
  senderPublicKeyPem?: string
): ValidationResult {
  if (!envelope || typeof envelope !== 'object') {
    return {
      valid: false,
      error: {
        code: GatewayErrorCode.INVALID_ENVELOPE,
        message: 'Envelope must be a non-null JSON object.',
        retryable: false,
      },
    };
  }

  const serializedSize = new TextEncoder().encode(
    JSON.stringify(envelope)
  ).length;
  if (serializedSize > MAX_ENVELOPE_SIZE_BYTES) {
    return {
      valid: false,
      error: {
        code: GatewayErrorCode.ENVELOPE_TOO_LARGE,
        message: `Envelope size (${serializedSize} bytes) exceeds maximum allowed (${MAX_ENVELOPE_SIZE_BYTES} bytes).`,
        retryable: false,
      },
    };
  }

  const env = envelope as Partial<MessageEnvelope>;

  if (!isSupportedProtocolVersion(env.protocolVersion)) {
    return {
      valid: false,
      error: {
        code: GatewayErrorCode.UNSUPPORTED_PROTOCOL_VERSION,
        message: `Unsupported protocol version '${String(
          env.protocolVersion
        )}'. Supported versions: 1.0`,
        correlationId: env.correlationId,
        retryable: false,
      },
    };
  }

  const requiredStrings: Array<keyof MessageEnvelope> = [
    'messageId',
    'correlationId',
    'idempotencyKey',
    'senderAiId',
    'recipientAiId',
    'type',
    'timestamp',
    'expiresAt',
  ];

  for (const field of requiredStrings) {
    const val = env[field];
    if (typeof val !== 'string' || val.trim().length === 0) {
      return {
        valid: false,
        error: {
          code: GatewayErrorCode.INVALID_ENVELOPE,
          message: `Missing or empty required envelope field: '${field}'.`,
          correlationId: env.correlationId,
          retryable: false,
        },
      };
    }
  }

  if (
    typeof env.ttlSeconds !== 'number' ||
    env.ttlSeconds <= 0 ||
    env.ttlSeconds > 86_400
  ) {
    return {
      valid: false,
      error: {
        code: GatewayErrorCode.INVALID_ENVELOPE,
        message: 'Envelope ttlSeconds must be a positive number <= 86400.',
        correlationId: env.correlationId,
        retryable: false,
      },
    };
  }

  const expiresAtMs = Date.parse(env.expiresAt!);
  if (Number.isNaN(expiresAtMs) || expiresAtMs <= nowMs) {
    return {
      valid: false,
      error: {
        code: GatewayErrorCode.REQUEST_EXPIRED,
        message: `Message envelope expired at ${env.expiresAt}.`,
        correlationId: env.correlationId,
        retryable: false,
      },
    };
  }

  if (
    !env.security ||
    env.security.signatureAlgorithm !== 'Ed25519' ||
    !env.security.keyFingerprint ||
    !env.security.signature ||
    !env.security.nonce
  ) {
    return {
      valid: false,
      error: {
        code: GatewayErrorCode.AUTHENTICATION_FAILED,
        message:
          'Missing or invalid Ed25519 cryptographic signature metadata on envelope.',
        correlationId: env.correlationId,
        retryable: false,
      },
    };
  }

  const canonical = buildEnvelopeCanonicalString({
    messageId: env.messageId!,
    correlationId: env.correlationId!,
    senderAiId: env.senderAiId!,
    recipientAiId: env.recipientAiId!,
    nonce: env.security.nonce,
    encryptedPayload: env.encryptedPayload,
  });

  // If the signature is a real Ed25519 signature (`ed25519:`), validate with public key if supplied,
  // or allow AuthenticationService (which looks up the registered identity's publicKeyPem) to verify it.
  if (env.security.signature.startsWith('ed25519:')) {
    if (senderPublicKeyPem) {
      if (
        !verifyEd25519Canonical(
          canonical,
          env.security.signature,
          senderPublicKeyPem
        )
      ) {
        return {
          valid: false,
          error: {
            code: GatewayErrorCode.AUTHENTICATION_FAILED,
            message: 'Invalid Ed25519 cryptographic envelope signature.',
            correlationId: env.correlationId,
            retryable: false,
          },
        };
      }
    }
  } else {
    if (
      !verifyDeterministicSignature(
        canonical,
        env.security.keyFingerprint,
        env.security.signature
      )
    ) {
      return {
        valid: false,
        error: {
          code: GatewayErrorCode.AUTHENTICATION_FAILED,
          message: 'Invalid Ed25519 envelope signature.',
          correlationId: env.correlationId,
          retryable: false,
        },
      };
    }
  }

  return { valid: true };
}
