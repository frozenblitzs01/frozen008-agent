'use strict';
/**
 * Pure decision logic for Proof Gatekeeper (Agent Games / zkVerify).
 * No I/O, no crypto — fully unit-testable.
 *
 * Task input shape (from the event page):
 *   { registered_vk, proof_vk, minimum, public_balance,
 *     expiry_block, current_block, recipient, condition_recipient,
 *     amount, max_transfer, proof_tx }
 *
 * Trap priority follows the order of the "trap encyclopedia" on the event
 * page. The generator is documented to inject at most one trap per task,
 * so priority only matters for determinism on double-trap inputs.
 */
const REASON = {
  VALID: 'VALID_CONDITION',
  VK: 'VK_SUBSTITUTION',
  THRESHOLD: 'THRESHOLD_MISMATCH',
  REUSED: 'PROOF_REUSED',
  EXPIRED: 'EXPIRED_CONDITION',
  RECIPIENT: 'RECIPIENT_MISMATCH',
  AMOUNT: 'AMOUNT_OVERFLOW',
  INVALID: 'INVALID_INPUT',
};

function toBigInt(value, field) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0) throw new Error(`${field} must be a non-negative integer`);
    return BigInt(value);
  }
  if (typeof value === 'string') {
    const s = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^[0-9]+$/.test(s)) return BigInt(s);
    throw new Error(`${field} is not a valid integer: ${value}`);
  }
  throw new Error(`${field} has unsupported type ${typeof value}`);
}

function normAddress(value, field) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value.trim())) {
    throw new Error(`${field} is not a valid 20-byte address: ${value}`);
  }
  return value.trim().toLowerCase();
}

function normHash(value, field) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value.trim())) {
    throw new Error(`${field} is not a valid 32-byte hash: ${value}`);
  }
  return value.trim().toLowerCase();
}

/**
 * Decide a task.
 * @param {object} input - the task's `input` object.
 * @param {{has:(mode:string, proofTx:string)=>boolean}} seen - proof-reuse store.
 * @param {string} mode - 'competition' | 'practice' (seen-set is scoped per mode).
 * @returns {{decision:'APPROVE'|'REJECT', reason_code:string, needsProof:boolean,
 *            checks:object, detail:string}}
 *   needsProof=false only for PROOF_REUSED (platform docs: those tasks have no
 *   proof to submit) and INVALID_INPUT (no circuit input can be built).
 */
function decide(input, seen, mode = 'competition') {
  if (!input || typeof input !== 'object') {
    return { decision: 'REJECT', reason_code: REASON.INVALID, needsProof: false,
             checks: {}, detail: 'missing input object' };
  }
  let v;
  try {
    v = {
      registeredVk: normHash(input.registered_vk, 'registered_vk'),
      proofVk: normHash(input.proof_vk, 'proof_vk'),
      minimum: toBigInt(input.minimum, 'minimum'),
      publicBalance: toBigInt(input.public_balance, 'public_balance'),
      expiryBlock: toBigInt(input.expiry_block, 'expiry_block'),
      currentBlock: toBigInt(input.current_block, 'current_block'),
      recipient: normAddress(input.recipient, 'recipient'),
      conditionRecipient: normAddress(input.condition_recipient, 'condition_recipient'),
      amount: toBigInt(input.amount, 'amount'),
      maxTransfer: toBigInt(input.max_transfer, 'max_transfer'),
      proofTx: normHash(input.proof_tx, 'proof_tx'),
    };
  } catch (err) {
    return { decision: 'REJECT', reason_code: REASON.INVALID, needsProof: false,
             checks: {}, detail: err.message };
  }

  const checks = {
    vkMatches: v.proofVk === v.registeredVk,
    thresholdOk: v.publicBalance >= v.minimum,
    notReused: !(seen && seen.has(mode, v.proofTx)),
    notExpired: v.currentBlock <= v.expiryBlock,
    recipientMatches: v.recipient === v.conditionRecipient,
    amountOk: v.amount <= v.maxTransfer,
  };

  if (!checks.vkMatches) {
    return { decision: 'REJECT', reason_code: REASON.VK, needsProof: true, checks,
             detail: `proof_vk ${v.proofVk} != registered_vk ${v.registeredVk}` };
  }
  if (!checks.thresholdOk) {
    return { decision: 'REJECT', reason_code: REASON.THRESHOLD, needsProof: true, checks,
             detail: `public_balance ${v.publicBalance} < minimum ${v.minimum}` };
  }
  if (!checks.notReused) {
    return { decision: 'REJECT', reason_code: REASON.REUSED, needsProof: false, checks,
             detail: `proof_tx ${v.proofTx} already accepted in a previous ${mode} task` };
  }
  if (!checks.notExpired) {
    return { decision: 'REJECT', reason_code: REASON.EXPIRED, needsProof: true, checks,
             detail: `current_block ${v.currentBlock} > expiry_block ${v.expiryBlock}` };
  }
  if (!checks.recipientMatches) {
    return { decision: 'REJECT', reason_code: REASON.RECIPIENT, needsProof: true, checks,
             detail: `recipient ${v.recipient} != condition_recipient ${v.conditionRecipient}` };
  }
  if (!checks.amountOk) {
    return { decision: 'REJECT', reason_code: REASON.AMOUNT, needsProof: true, checks,
             detail: `amount ${v.amount} > max_transfer ${v.maxTransfer}` };
  }
  return { decision: 'APPROVE', reason_code: REASON.VALID, needsProof: true, checks,
           detail: 'all checks passed' };
}

module.exports = { decide, REASON, toBigInt, normAddress, normHash };
