// ============================================================================
// ai-nexus-chatbot — src/protocol/events/index.ts
// Invocation State Machine & Protocol Event Definitions
// ============================================================================

import { InvocationState } from '../types/index.ts';

export const VALID_INVOCATION_TRANSITIONS: Record<InvocationState, InvocationState[]> = {
  [InvocationState.CREATED]: [
    InvocationState.SENT,
    InvocationState.FAILED,
    InvocationState.CANCELLED,
  ],
  [InvocationState.SENT]: [
    InvocationState.RECEIVED,
    InvocationState.EXPIRED,
    InvocationState.FAILED,
    InvocationState.CANCELLED,
  ],
  [InvocationState.RECEIVED]: [
    InvocationState.AUTHENTICATED,
    InvocationState.REJECTED,
    InvocationState.EXPIRED,
    InvocationState.FAILED,
  ],
  [InvocationState.AUTHENTICATED]: [
    InvocationState.AUTHORIZED,
    InvocationState.REJECTED,
    InvocationState.FAILED,
  ],
  [InvocationState.AUTHORIZED]: [
    InvocationState.POLICY_EVALUATED,
    InvocationState.REJECTED,
    InvocationState.FAILED,
  ],
  [InvocationState.POLICY_EVALUATED]: [
    InvocationState.EXECUTING,
    InvocationState.REQUIRES_APPROVAL,
    InvocationState.REJECTED,
  ],
  [InvocationState.REQUIRES_APPROVAL]: [
    InvocationState.EXECUTING,
    InvocationState.REJECTED,
    InvocationState.EXPIRED,
    InvocationState.CANCELLED,
  ],
  [InvocationState.EXECUTING]: [
    InvocationState.COMPLETED,
    InvocationState.FAILED,
    InvocationState.CANCELLED,
  ],
  [InvocationState.COMPLETED]: [],
  [InvocationState.REJECTED]: [],
  [InvocationState.EXPIRED]: [],
  [InvocationState.FAILED]: [],
  [InvocationState.CANCELLED]: [],
};

export function canTransitionInvocationState(
  from: InvocationState,
  to: InvocationState
): boolean {
  return VALID_INVOCATION_TRANSITIONS[from]?.includes(to) ?? false;
}
