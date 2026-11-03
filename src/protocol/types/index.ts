// ============================================================================
// ai-nexus-chatbot — src/protocol/types/index.ts
// Authoritative Protocol Types, Enums, Message Envelopes & Security Contracts
// Synchronized with ai-nexus-gateway via scripts/sync-protocol.ts
// ============================================================================

import type {
  EncryptedEnvelopePayload,
  KeyRotationCertificate,
} from '../crypto/index.ts';

export const CURRENT_PROTOCOL_VERSION = '1.0' as const;
export const SUPPORTED_PROTOCOL_VERSIONS = ['1.0'] as const;
export type SupportedProtocolVersion = (typeof SUPPORTED_PROTOCOL_VERSIONS)[number];

export const MAX_ENVELOPE_SIZE_BYTES = 65_536; // 64 KB hard limit per message envelope
export const DEFAULT_TTL_SECONDS = 300; // 5 minutes default TTL

export type IdentityRegistrationState = 'UNREGISTERED' | 'REGISTERED' | 'REVOKED';
export type PairingVerificationState = 'UNVERIFIED' | 'VERIFIED' | 'REVOKED';

export enum ExecutionMode {
  LOCAL = 'LOCAL',
  HYBRID = 'HYBRID',
  CLOUD = 'CLOUD',
}

export type ConfiguredLlmProvider = 'gemini' | 'openai' | 'local';

export interface PublicAIIdentity {
  aiId: string; // e.g. "ai_alice"
  handle: string; // e.g. "@alice"
  displayName: string; // e.g. "Alice AI"
  ownerId: string; // e.g. "user_alice"
  ownerDisplayName: string; // e.g. "Alice Vance"
  description?: string; // Optional Chatbot role/bio
  nodeId: string; // e.g. "node_alice_01"
  deviceId: string; // e.g. "dev_macbook_alice"
  publicKeyPem: string; // Ed25519 SPKI public key PEM
  keyFingerprint: string; // SHA-256 fingerprint of Ed25519 public key
  encryptionPublicKeyPem?: string; // X25519 SPKI public key PEM for E2EE
  encryptionKeyFingerprint?: string; // SHA-256 fingerprint of X25519 public key
  registrationState: IdentityRegistrationState;
  verificationState: PairingVerificationState;
  executionMode: ExecutionMode;
  online: boolean;
  killSwitchActive: boolean;
  supportedProtocolVersions: SupportedProtocolVersion[];
  configuredProvider?: ConfiguredLlmProvider;
  configuredModel?: string;
  createdAt: string;
  lastHeartbeatAt: string;
  revokedAt?: string;
}

export interface PairingChallenge {
  challengeId: string;
  aiId: string;
  nodeId: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  verified: boolean;
}

/**
 * 16 Core Protocol Message Types (Part 7.A of Master Specification)
 */
export enum EnvelopeMessageType {
  // 1-2. Identity lifecycle
  IDENTITY_REGISTER = 'protocol.identity.register',
  IDENTITY_VERIFY = 'protocol.identity.verify',
  // 3-6. Connection lifecycle
  CONNECTION_REQUEST = 'protocol.connection.request',
  CONNECTION_APPROVED = 'protocol.connection.approved',
  CONNECTION_REJECTED = 'protocol.connection.rejected',
  CONNECTION_REVOKED = 'protocol.connection.revoked',
  // 7. Presence & Heartbeat
  PRESENCE_UPDATE = 'protocol.presence.update',
  HEARTBEAT = 'protocol.node.heartbeat',
  // 8-11. AI-to-AI request/response/followup/cancel
  AI_REQUEST = 'protocol.invocation.request',
  INVOCATION_REQUEST = 'protocol.invocation.request',
  AI_RESPONSE = 'protocol.invocation.response',
  INVOCATION_RESPONSE = 'protocol.invocation.response',
  AI_FOLLOWUP = 'protocol.invocation.followup',
  AI_CANCEL = 'protocol.invocation.cancel',
  // 12-14. Memory sharing lifecycle
  MEMORY_SHARE_REQUEST = 'protocol.memory.share.request',
  MEMORY_SHARE_APPROVED = 'protocol.memory.share.approved',
  MEMORY_SHARE_REVOKED = 'protocol.memory.share.revoked',
  // 15-16. Delivery acknowledgement & error
  DELIVERY_ACK = 'protocol.invocation.status',
  INVOCATION_STATUS = 'protocol.invocation.status',
  ERROR = 'protocol.error',
  PROTOCOL_ERROR = 'protocol.error',
}

export type CapabilityType =
  | 'calendar.availability'
  | 'architecture.review'
  | 'code.review'
  | 'document.review'
  | 'task.delegation'
  | 'research.summary'
  | 'memory.share'
  | 'general.question';

export type ConnectionStatus =
  | 'PENDING_INCOMING'
  | 'PENDING_OUTGOING'
  | 'CONNECTED'
  | 'REJECTED'
  | 'DISCONNECTED'
  | 'BLOCKED';

export interface ChatbotConnectionPermissions {
  allowedCapabilities: CapabilityType[];
  allowAutonomousFollowUp: boolean;
  maxFollowUpTurns: number;
  allowMemorySharing: boolean;
  requireHumanApprovalForSensitive: boolean;
}

export interface ChatbotConnectionRecord {
  connectionId: string;
  ownerAiId: string;
  peerAiId: string;
  peerHandle: string;
  peerDisplayName: string;
  peerOwnerName: string;
  status: ConnectionStatus;
  initiatedByAiId: string;
  permissions: ChatbotConnectionPermissions;
  note?: string;
  createdAt: string;
  updatedAt: string;
  lastInteractionAt?: string;
}

export interface ConnectionEventPayload {
  connectionId?: string;
  action?: 'INVITE' | 'APPROVE' | 'REJECT' | 'REVOKE';
  initiatorAiId: string;
  initiatorHandle?: string;
  initiatorDisplayName?: string;
  initiatorOwnerName?: string;
  targetAiId: string;
  targetHandle?: string;
  status?: ConnectionStatus;
  note?: string;
  permissions?: Partial<ChatbotConnectionPermissions>;
  timestamp?: string;
}

export enum InvocationState {
  CREATED = 'CREATED',
  SENT = 'SENT',
  RECEIVED = 'RECEIVED',
  AUTHENTICATED = 'AUTHENTICATED',
  AUTHORIZED = 'AUTHORIZED',
  POLICY_EVALUATED = 'POLICY_EVALUATED',
  REQUIRES_APPROVAL = 'REQUIRES_APPROVAL',
  EXECUTING = 'EXECUTING',
  COMPLETED = 'COMPLETED',
  REJECTED = 'REJECTED',
  EXPIRED = 'EXPIRED',
  FAILED = 'FAILED',
  CANCELLED = 'CANCELLED',
}

export enum GatewayErrorCode {
  INVALID_ENVELOPE = 'INVALID_ENVELOPE',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  UNSUPPORTED_PROTOCOL_VERSION = 'UNSUPPORTED_PROTOCOL_VERSION',
  ENVELOPE_TOO_LARGE = 'ENVELOPE_TOO_LARGE',
  AUTHENTICATION_FAILED = 'AUTHENTICATION_FAILED',
  IDENTITY_NOT_FOUND = 'IDENTITY_NOT_FOUND',
  IDENTITY_REVOKED = 'IDENTITY_REVOKED',
  CONNECTION_REQUIRED = 'CONNECTION_REQUIRED',
  UNAUTHORIZED_SENDER = 'UNAUTHORIZED_SENDER',
  UNAUTHORIZED_CAPABILITY = 'UNAUTHORIZED_CAPABILITY',
  PERMISSION_EXPIRED = 'PERMISSION_EXPIRED',
  REQUIRES_HUMAN_APPROVAL = 'REQUIRES_HUMAN_APPROVAL',
  OWNER_APPROVAL_REQUIRED = 'OWNER_APPROVAL_REQUIRED',
  KILL_SWITCH_ACTIVE = 'KILL_SWITCH_ACTIVE',
  NODE_OFFLINE = 'NODE_OFFLINE',
  REQUEST_EXPIRED = 'REQUEST_EXPIRED',
  RATE_LIMITED = 'RATE_LIMITED',
  DUPLICATE_REQUEST = 'DUPLICATE_REQUEST',
  LOOP_LIMIT_EXCEEDED = 'LOOP_LIMIT_EXCEEDED',
  BUDGET_EXCEEDED = 'BUDGET_EXCEEDED',
  INTERNAL_ERROR = 'INTERNAL_ERROR',
}

export interface NexusProtocolError {
  code: GatewayErrorCode;
  message: string;
  correlationId?: string;
  retryable: boolean;
  details?: Record<string, unknown>;
}

export interface EnvelopeSecurityMetadata {
  signatureAlgorithm: 'Ed25519';
  keyFingerprint: string;
  signature: string;
  nonce: string;
  signedAt: string;
  e2eeEncrypted?: boolean;
}

export interface MessageEnvelope<TPayload = unknown> {
  protocolVersion: SupportedProtocolVersion;
  messageId: string;
  correlationId: string;
  idempotencyKey: string;
  senderAiId: string;
  recipientAiId: string;
  groupId?: string;
  type: EnvelopeMessageType;
  timestamp: string;
  expiresAt: string;
  ttlSeconds: number;
  permissionReference?: string;
  /**
   * When `encryptedPayload` is present, sensitive content inside `payload` is
   * replaced on the wire with `[ENCRYPTED_E2EE]` so the Gateway only sees minimal
   * routing fields (`requestId`, `queueIfOffline`, `currentTurn`, `maxFollowUpTurns`, `status`).
   */
  payload: TPayload;
  encryptedPayload?: EncryptedEnvelopePayload;
  security: EnvelopeSecurityMetadata;
}

export interface InvocationRequestPayload {
  requestId: string;
  capability: CapabilityType;
  question: string;
  purpose: string;
  contextSnippet?: string;
  structuredParams?: Record<string, unknown>;
  maxResponseChars: number;
  maxFollowUpTurns: number;
  currentTurn: number;
  maxBudgetUsd: number;
  queueIfOffline: boolean;
}

export interface ProvenanceMetadata {
  sourceAiId: string;
  sourceHandle: string;
  sourceDisplayName: string;
  ownerDisplayName: string;
  correlationId: string;
  requestId: string;
  permissionReference: string;
  capability: CapabilityType;
  executionMode: ExecutionMode;
  verifiedSignatureFingerprint: string;
  e2eeVerified?: boolean;
  disclosedFields: string[];
  withheldFields: string[];
  trustClassification: 'VERIFIED_EXTERNAL_AI' | 'UNVERIFIED_EXTERNAL_AI';
  executedAt: string;
  expiresAt: string;
}

export interface InvocationResponsePayload {
  requestId: string;
  status: InvocationState;
  answer?: string;
  minimizedDisclosures: Record<string, string>;
  withheldReasonSummary?: string;
  provenance?: ProvenanceMetadata;
  error?: NexusProtocolError;
  approvalRequiredReason?: string;
  pendingApprovalId?: string;
  turnNumber: number;
  estimatedCostUsd: number;
}

export interface InvocationTransitionEvent {
  state: InvocationState;
  timestamp: string;
  summary: string;
  actor: 'SENDER_NODE' | 'GATEWAY' | 'RECIPIENT_NODE' | 'POLICY_ENGINE';
}

export interface InvocationRecord {
  requestId: string;
  correlationId: string;
  idempotencyKey: string;
  senderAiId: string;
  recipientAiId: string;
  capability: CapabilityType;
  question: string;
  state: InvocationState;
  transitions: InvocationTransitionEvent[];
  envelope: MessageEnvelope<InvocationRequestPayload>;
  responseEnvelope?: MessageEnvelope<InvocationResponsePayload>;
  createdAt: string;
  updatedAt: string;
  expiresAt: string;
  queuedOffline: boolean;
  approvalRequiredReason?: string;
}

export type PermissionGrantDecision =
  | 'ALLOW'
  | 'ALLOW_MINIMIZED'
  | 'REQUIRE_APPROVAL'
  | 'DENY';

export type ApprovalResolutionDecision =
  | 'APPROVE_ONCE'
  | 'ALWAYS_ALLOW'
  | 'DENY';

export interface PendingApprovalRecord {
  approvalId: string; // matches requestId
  requestId?: string;
  correlationId?: string;
  ownerAiId: string; // recipient Chatbot owner
  senderAiId: string;
  senderHandle: string;
  senderDisplayName: string;
  capability: CapabilityType;
  question: string;
  purpose: string;
  contextSnippet?: string;
  ruleId?: string;
  allowedFields: string[];
  withheldFields: string[];
  status:
    | 'PENDING'
    | 'APPROVED_ONCE'
    | 'ALWAYS_ALLOWED'
    | 'APPROVED_ALWAYS'
    | 'DENIED'
    | 'EXPIRED';
  decisionByOwner?: ApprovalResolutionDecision;
  createdAt: string;
  expiresAt: string;
  decidedAt?: string;
}

export interface PermissionPolicyRule {
  ruleId: string;
  ownerAiId: string;
  allowedSenderAiIds: string[]; // e.g. ["ai_alice"] or ["*"]
  capability: CapabilityType;
  decision: PermissionGrantDecision;
  allowedFields: string[];
  withheldFields: string[];
  expiresAt: string;
  revoked: boolean;
  maxAutonomousTurns: number;
  maxBudgetUsd: number;
  description: string;
}

export type MemoryCategory =
  | 'owner_private'
  | 'shared_context'
  | 'external_ai'
  | 'system_knowledge';

export interface MemoryItem {
  memoryId: string;
  ownerAiId: string;
  category: MemoryCategory;
  title: string;
  content: string;
  tags: string[];
  sharedWithAiIds: string[];
  createdAt: string;
  updatedAt: string;
  expiresAt?: string;
  revoked: boolean;
  provenance?: {
    sourceAiId: string;
    sourceHandle: string;
    correlationId: string;
    requestId?: string;
    permissionReference?: string;
    verifiedFingerprint: string;
    receivedAt: string;
    expiresAt?: string;
    trustClassification:
      | 'OWNER_AUTHORED'
      | 'VERIFIED_EXTERNAL_AI'
      | 'SYSTEM_DERIVED';
  };
}

export interface AuditEventRecord {
  eventId: string;
  timestamp: string;
  repository: 'ai-nexus-protocol' | 'ai-nexus-gateway' | 'ai-nexus-chatbot';
  module: string;
  eventType: string;
  actorAiId: string;
  targetAiId?: string;
  correlationId?: string;
  outcome: 'SUCCESS' | 'DENIED' | 'REQUIRES_APPROVAL' | 'QUEUED' | 'ERROR' | 'REVOKED';
  summary: string;
  metadata?: Record<string, unknown>;
}

// ============================================================================
// WebSocket Node Transport Wire Frames (`/ws/node`)
// ============================================================================

export type GatewayNodeWsFrame =
  | {
      type: 'node.authenticate';
      aiId: string;
      nodeId: string;
      nonce: string;
      keyFingerprint: string;
      signature: string;
    }
  | {
      type: 'node.authenticated';
      aiId: string;
      nodeId: string;
      timestamp: string;
      drainedQueueCount: number;
    }
  | {
      type: 'node.auth_failed';
      reason: string;
    }
  | {
      type: 'invocation.deliver';
      requestId: string;
      envelope: MessageEnvelope<InvocationRequestPayload>;
    }
  | {
      type: 'invocation.transition';
      requestId: string;
      state: InvocationState;
      summary: string;
      actor: 'RECIPIENT_NODE' | 'POLICY_ENGINE';
    }
  | {
      type: 'invocation.response';
      requestId: string;
      responseEnvelope: MessageEnvelope<InvocationResponsePayload>;
    }
  | {
      /** Pushed by Gateway to Sender Node when an async/deferred response (e.g. after ASK approval or offline queue drain) completes */
      type: 'invocation.response_delivered';
      requestId: string;
      record: InvocationRecord;
      responseEnvelope: MessageEnvelope<InvocationResponsePayload>;
    }
  | {
      type: 'connection.event';
      payload?: ConnectionEventPayload;
      envelope?: MessageEnvelope<ConnectionEventPayload>;
    }
  | {
      type: 'presence.event';
      aiId: string;
      handle: string;
      online: boolean;
      executionMode?: ExecutionMode;
      killSwitchActive?: boolean;
      timestamp: string;
    }
  | {
      type: 'ping';
      aiId?: string;
      timestamp: string;
    }
  | {
      type: 'pong';
      timestamp: string;
    };

export type { EncryptedEnvelopePayload, KeyRotationCertificate };
