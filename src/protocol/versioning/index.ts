// ============================================================================
// ai-nexus-chatbot — src/protocol/versioning/index.ts
// Protocol Versioning & Compatibility Contract
// ============================================================================

import {
  CURRENT_PROTOCOL_VERSION,
  SUPPORTED_PROTOCOL_VERSIONS,
  SupportedProtocolVersion,
} from '../types/index.ts';

export const PROTOCOL_CONTRACT_METADATA = {
  packageName: 'ai-nexus-protocol-embedded',
  protocolVersion: CURRENT_PROTOCOL_VERSION,
  supportedVersions: SUPPORTED_PROTOCOL_VERSIONS,
  updatedAt: '2026-11-02T00:00:00.000Z',
} as const;

export function isSupportedProtocolVersion(
  version: unknown
): version is SupportedProtocolVersion {
  return (
    typeof version === 'string' &&
    (SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(version)
  );
}
