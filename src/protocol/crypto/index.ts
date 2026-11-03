// ============================================================================
// ai-nexus-chatbot — src/protocol/crypto/index.ts
// Audited Cryptographic Primitives for AI Nexus Protocol:
//   1. Ed25519 Digital Signatures (Identity Proof-of-Possession, Envelope Signing,
//      Key Rotation Authorization, Key Revocation)
//   2. X25519 Key Agreement + HKDF-SHA256 + AES-256-GCM End-to-End Encryption (E2EE)
//      with Ephemeral Forward Secrecy and Authenticated Sender/Recipient Binding (AAD)
// ============================================================================

import crypto from 'node:crypto';

export interface GeneratedIdentityKeyBundle {
  signingPublicKeyPem: string;
  signingPrivateKeyPem: string;
  signingKeyFingerprint: string;
  encryptionPublicKeyPem: string;
  encryptionPrivateKeyPem: string;
  encryptionKeyFingerprint: string;
}

export interface EncryptedEnvelopePayload {
  algorithm: 'X25519-HKDF-AES256GCM';
  ephemeralPublicKeyPem: string;
  senderAiId: string;
  recipientAiId: string;
  senderSigningKeyFingerprint: string;
  recipientEncryptionKeyFingerprint: string;
  iv: string; // base64 (12 bytes)
  salt: string; // base64 (16 bytes)
  ciphertext: string; // base64
  authTag: string; // base64 (16 bytes)
}

export interface KeyRotationCertificate {
  aiId: string;
  oldPublicKeyPem?: string;
  oldKeyFingerprint: string;
  newPublicKeyPem: string;
  newKeyFingerprint: string;
  newEncryptionPublicKeyPem: string;
  newEncryptionKeyFingerprint: string;
  timestamp: string;
  nonce: string;
  /** Signature by the previous Ed25519 private key authorizing the rotation */
  oldKeySignature: string;
  /** Proof-of-possession signature by the new Ed25519 private key */
  newKeySignature: string;
}

/**
 * Computes a deterministic SHA-256 fingerprint of a SPKI PEM public key.
 */
export function computeKeyFingerprint(
  publicKeyPem: string,
  prefix: 'ed25519' | 'x25519' = 'ed25519'
): string {
  const normalized = publicKeyPem.trim();
  const digest = crypto
    .createHash('sha256')
    .update(normalized, 'utf8')
    .digest('hex');
  return `${prefix}:${digest.slice(0, 24)}`;
}

/**
 * Generates a fresh Ed25519 signing keypair and X25519 key-agreement keypair.
 */
export function generateIdentityKeyBundle(): GeneratedIdentityKeyBundle {
  const signing = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const encryption = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  return {
    signingPublicKeyPem: signing.publicKey,
    signingPrivateKeyPem: signing.privateKey,
    signingKeyFingerprint: computeKeyFingerprint(signing.publicKey, 'ed25519'),
    encryptionPublicKeyPem: encryption.publicKey,
    encryptionPrivateKeyPem: encryption.privateKey,
    encryptionKeyFingerprint: computeKeyFingerprint(
      encryption.publicKey,
      'x25519'
    ),
  };
}

/**
 * Signs a canonical string using an Ed25519 private key (PKCS8 PEM).
 */
export function signEd25519Canonical(
  canonicalPayload: string,
  signingPrivateKeyPem: string
): string {
  const privKey = crypto.createPrivateKey(signingPrivateKeyPem);
  const sig = crypto.sign(
    null,
    Buffer.from(canonicalPayload, 'utf8'),
    privKey
  );
  return `ed25519:${sig.toString('base64')}`;
}

/**
 * Verifies an Ed25519 signature against a canonical string and SPKI PEM public key.
 */
export function verifyEd25519Canonical(
  canonicalPayload: string,
  signatureWithPrefix: string,
  signingPublicKeyPem: string
): boolean {
  try {
    if (!signatureWithPrefix.startsWith('ed25519:')) {
      return false;
    }
    const rawBase64 = signatureWithPrefix.slice('ed25519:'.length);
    const sigBuf = Buffer.from(rawBase64, 'base64');
    const pubKey = crypto.createPublicKey(signingPublicKeyPem);
    return crypto.verify(
      null,
      Buffer.from(canonicalPayload, 'utf8'),
      pubKey,
      sigBuf
    );
  } catch {
    return false;
  }
}

/**
 * Builds the canonical AAD (Additional Authenticated Data) bound to AES-256-GCM
 * so an encrypted payload cannot be replayed or transplanted into another envelope,
 * sender, or recipient.
 */
export function buildE2EEAad(params: {
  messageId: string;
  correlationId: string;
  senderAiId: string;
  recipientAiId: string;
  senderSigningKeyFingerprint: string;
  recipientEncryptionKeyFingerprint: string;
}): Buffer {
  const aadString = [
    'AI_NEXUS_E2EE_V1',
    params.messageId,
    params.correlationId,
    params.senderAiId,
    params.recipientAiId,
    params.senderSigningKeyFingerprint,
    params.recipientEncryptionKeyFingerprint,
  ].join(':');
  return Buffer.from(aadString, 'utf8');
}

/**
 * Encrypts a structured payload for `recipientEncryptionPublicKeyPem` using:
 *   - Ephemeral X25519 key agreement (Forward Secrecy)
 *   - HKDF-SHA256 key derivation (256-bit key)
 *   - AES-256-GCM authenticated encryption with 96-bit random IV and strict AAD
 */
export function encryptEnvelopePayloadE2EE<TPayload>(params: {
  plaintextPayload: TPayload;
  messageId: string;
  correlationId: string;
  senderAiId: string;
  recipientAiId: string;
  senderSigningKeyFingerprint: string;
  recipientEncryptionPublicKeyPem: string;
  recipientEncryptionKeyFingerprint: string;
}): EncryptedEnvelopePayload {
  // 1. Generate ephemeral X25519 keypair for forward secrecy
  const ephemeral = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const ephemeralPrivKey = crypto.createPrivateKey(ephemeral.privateKey);
  const recipientPubKey = crypto.createPublicKey(
    params.recipientEncryptionPublicKeyPem
  );

  // 2. X25519 ECDH shared secret
  const sharedSecret = crypto.diffieHellman({
    privateKey: ephemeralPrivKey,
    publicKey: recipientPubKey,
  });

  // 3. HKDF-SHA256 to derive 32-byte AES-256 key
  const salt = crypto.randomBytes(16);
  const info = Buffer.from(
    `ai-nexus-e2ee-v1:${params.senderAiId}:${params.recipientAiId}:${params.recipientEncryptionKeyFingerprint}`,
    'utf8'
  );
  const aesKey = Buffer.from(
    crypto.hkdfSync('sha256', sharedSecret, salt, info, 32)
  );

  // 4. AES-256-GCM encryption with 12-byte random nonce (IV) and AAD
  const iv = crypto.randomBytes(12);
  const aad = buildE2EEAad({
    messageId: params.messageId,
    correlationId: params.correlationId,
    senderAiId: params.senderAiId,
    recipientAiId: params.recipientAiId,
    senderSigningKeyFingerprint: params.senderSigningKeyFingerprint,
    recipientEncryptionKeyFingerprint: params.recipientEncryptionKeyFingerprint,
  });

  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv, {
    authTagLength: 16,
  });
  cipher.setAAD(aad);

  const plaintextBytes = Buffer.from(
    JSON.stringify(params.plaintextPayload),
    'utf8'
  );
  const encrypted = Buffer.concat([
    cipher.update(plaintextBytes),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return {
    algorithm: 'X25519-HKDF-AES256GCM',
    ephemeralPublicKeyPem: ephemeral.publicKey,
    senderAiId: params.senderAiId,
    recipientAiId: params.recipientAiId,
    senderSigningKeyFingerprint: params.senderSigningKeyFingerprint,
    recipientEncryptionKeyFingerprint: params.recipientEncryptionKeyFingerprint,
    iv: iv.toString('base64'),
    salt: salt.toString('base64'),
    ciphertext: encrypted.toString('base64'),
    authTag: authTag.toString('base64'),
  };
}

/**
 * Decrypts and authenticates an `EncryptedEnvelopePayload` using the recipient's
 * X25519 private key. Throws if the ciphertext, IV, authTag, or AAD was tampered with.
 */
export function decryptEnvelopePayloadE2EE<TPayload>(params: {
  encryptedPayload: EncryptedEnvelopePayload;
  messageId: string;
  correlationId: string;
  expectedSenderAiId?: string;
  expectedRecipientAiId?: string;
  senderAiId?: string;
  recipientAiId?: string;
  recipientEncryptionPrivateKeyPem: string;
}): TPayload {
  const { encryptedPayload } = params;
  if (encryptedPayload.algorithm !== 'X25519-HKDF-AES256GCM') {
    throw new Error(
      `Unsupported E2EE algorithm: ${String(encryptedPayload.algorithm)}`
    );
  }

  const effectiveSenderAiId =
    params.expectedSenderAiId ?? params.senderAiId ?? encryptedPayload.senderAiId;
  const effectiveRecipientAiId =
    params.expectedRecipientAiId ??
    params.recipientAiId ??
    encryptedPayload.recipientAiId;

  if (encryptedPayload.senderAiId !== effectiveSenderAiId) {
    throw new Error(
      `E2EE sender mismatch: expected ${effectiveSenderAiId}, got ${encryptedPayload.senderAiId}`
    );
  }

  if (encryptedPayload.recipientAiId !== effectiveRecipientAiId) {
    throw new Error(
      `E2EE recipient mismatch: expected ${effectiveRecipientAiId}, got ${encryptedPayload.recipientAiId}`
    );
  }

  const recipientPrivKey = crypto.createPrivateKey(
    params.recipientEncryptionPrivateKeyPem
  );
  const ephemeralPubKey = crypto.createPublicKey(
    encryptedPayload.ephemeralPublicKeyPem
  );

  const sharedSecret = crypto.diffieHellman({
    privateKey: recipientPrivKey,
    publicKey: ephemeralPubKey,
  });

  const salt = Buffer.from(encryptedPayload.salt, 'base64');
  const info = Buffer.from(
    `ai-nexus-e2ee-v1:${effectiveSenderAiId}:${effectiveRecipientAiId}:${encryptedPayload.recipientEncryptionKeyFingerprint}`,
    'utf8'
  );
  const aesKey = Buffer.from(
    crypto.hkdfSync('sha256', sharedSecret, salt, info, 32)
  );

  const iv = Buffer.from(encryptedPayload.iv, 'base64');
  const ciphertext = Buffer.from(encryptedPayload.ciphertext, 'base64');
  const authTag = Buffer.from(encryptedPayload.authTag, 'base64');

  const aad = buildE2EEAad({
    messageId: params.messageId,
    correlationId: params.correlationId,
    senderAiId: effectiveSenderAiId,
    recipientAiId: effectiveRecipientAiId,
    senderSigningKeyFingerprint: encryptedPayload.senderSigningKeyFingerprint,
    recipientEncryptionKeyFingerprint:
      encryptedPayload.recipientEncryptionKeyFingerprint,
  });

  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv, {
    authTagLength: 16,
  });
  decipher.setAAD(aad);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
  return JSON.parse(decrypted.toString('utf8')) as TPayload;
}

/**
 * Creates a dual-signed KeyRotationCertificate authorizing key rotation on the Gateway.
 */
export function createKeyRotationCertificate(params: {
  aiId: string;
  oldPublicKeyPem?: string;
  oldKeyFingerprint: string;
  oldSigningPrivateKeyPem: string;
  newPublicKeyPem: string;
  newKeyFingerprint: string;
  newSigningPrivateKeyPem: string;
  newEncryptionPublicKeyPem: string;
  newEncryptionKeyFingerprint: string;
  nowMs?: number;
}): KeyRotationCertificate {
  const nowMs = params.nowMs ?? Date.now();
  const timestamp = new Date(nowMs).toISOString();
  const nonce = `rot_nonce_${crypto.randomBytes(8).toString('hex')}_${nowMs}`;
  const canonical = `rotate:${params.aiId}:${params.oldKeyFingerprint}:${params.newKeyFingerprint}:${params.newEncryptionKeyFingerprint}:${timestamp}:${nonce}`;

  const oldKeySignature = signEd25519Canonical(
    canonical,
    params.oldSigningPrivateKeyPem
  );
  const newKeySignature = signEd25519Canonical(
    canonical,
    params.newSigningPrivateKeyPem
  );

  return {
    aiId: params.aiId,
    oldPublicKeyPem: params.oldPublicKeyPem,
    oldKeyFingerprint: params.oldKeyFingerprint,
    newPublicKeyPem: params.newPublicKeyPem,
    newKeyFingerprint: params.newKeyFingerprint,
    newEncryptionPublicKeyPem: params.newEncryptionPublicKeyPem,
    newEncryptionKeyFingerprint: params.newEncryptionKeyFingerprint,
    timestamp,
    nonce,
    oldKeySignature,
    newKeySignature,
  };
}

/**
 * Verifies a dual-signed KeyRotationCertificate against the currently registered Ed25519 public key
 * and the new Ed25519 public key.
 */
export function verifyKeyRotationCertificate(
  cert: KeyRotationCertificate,
  currentRegisteredPublicKeyPem?: string
): { valid: boolean; reason?: string } {
  const effectiveOldPublicKeyPem =
    currentRegisteredPublicKeyPem ?? cert.oldPublicKeyPem;
  if (!effectiveOldPublicKeyPem) {
    return {
      valid: false,
      reason: 'Missing previous Ed25519 public key for rotation verification.',
    };
  }
  const computedOldFp = computeKeyFingerprint(effectiveOldPublicKeyPem, 'ed25519');
  if (computedOldFp !== cert.oldKeyFingerprint) {
    return {
      valid: false,
      reason: 'Old Ed25519 key fingerprint does not match oldPublicKeyPem.',
    };
  }
  const computedNewFp = computeKeyFingerprint(cert.newPublicKeyPem, 'ed25519');
  if (computedNewFp !== cert.newKeyFingerprint) {
    return {
      valid: false,
      reason: 'New Ed25519 key fingerprint does not match newPublicKeyPem.',
    };
  }
  const computedEncFp = computeKeyFingerprint(
    cert.newEncryptionPublicKeyPem,
    'x25519'
  );
  if (computedEncFp !== cert.newEncryptionKeyFingerprint) {
    return {
      valid: false,
      reason:
        'New X25519 encryption key fingerprint does not match newEncryptionPublicKeyPem.',
    };
  }

  const canonical = `rotate:${cert.aiId}:${cert.oldKeyFingerprint}:${cert.newKeyFingerprint}:${cert.newEncryptionKeyFingerprint}:${cert.timestamp}:${cert.nonce}`;

  const oldValid = verifyEd25519Canonical(
    canonical,
    cert.oldKeySignature,
    effectiveOldPublicKeyPem
  );
  if (!oldValid) {
    return {
      valid: false,
      reason:
        'Rotation authorization signature by previous Ed25519 key is invalid.',
    };
  }

  const newValid = verifyEd25519Canonical(
    canonical,
    cert.newKeySignature,
    cert.newPublicKeyPem
  );
  if (!newValid) {
    return {
      valid: false,
      reason:
        'Proof-of-possession signature by new Ed25519 key is invalid.',
    };
  }

  return { valid: true };
}
