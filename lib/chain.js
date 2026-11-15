'use strict';
/**
 * On-chain proof check — HONESTLY UNIMPLEMENTED for automatic verification.
 *
 * What was tried (2026-11-15, from this VM):
 * - zkVerify public RPC https://rpc.zkverify.io — unreachable (connection failure).
 * - https://api.zkverify.io — unreachable.
 * - Kurier mainnet API https://api.kurier.xyz/api/v1 — reachable, but it is a
 *   submission API that requires a mainnet API key; no public read endpoint
 *   for "is proof_tx X included on-chain" was found in its docs.
 *
 * Therefore this module NEVER claims a proof is on-chain. It returns
 * { checked: false, reason } and the decision logic proceeds with the local
 * checks only (VK match, threshold, expiry, recipient, amount, reuse).
 * The local checks already cover 6 of the 7 trap types from the payload
 * alone; the missing piece is confirming the task's proof_tx is really
 * included on zkVerify mainnet. The platform itself validates that side,
 * and a wrong APPROVE is penalised -6 vs -3 for a wrong REJECT, so the
 * fail-closed rule still applies to anything ambiguous in the payload.
 *
 * If a reachable zkVerify RPC / Kurier key becomes available, set
 * ZKVERIFY_RPC_URL and implement the inclusion lookup here — do not fake it.
 */
async function checkProofOnChain(proofTx, opts = {}) {
  const rpcUrl = opts.rpcUrl || process.env.ZKVERIFY_RPC_URL || '';
  if (!rpcUrl) {
    return { checked: false, reason: 'no_rpc_configured',
             detail: 'ZKVERIFY_RPC_URL not set; on-chain inclusion not verified' };
  }
  try {
    const res = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'system_chain', params: [] }),
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return { checked: false, reason: 'rpc_unreachable', detail: `HTTP ${res.status}` };
    // Connectivity only — this does NOT verify the proof_tx. Inclusion lookup
    // needs a proof indexer, which is not available without credentials.
    return { checked: false, reason: 'rpc_reachable_but_no_proof_index',
             detail: 'RPC reachable but no proof-inclusion lookup is implemented' };
  } catch (err) {
    return { checked: false, reason: 'rpc_unreachable', detail: err.message };
  }
}

module.exports = { checkProofOnChain };
