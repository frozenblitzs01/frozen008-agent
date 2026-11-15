'use strict';
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');
const { keccak_256 } = require('js-sha3');

/**
 * Groth16 proof generation / verification for the official gatekeeper circuit.
 *
 * Signal names (13) come from the verified Medium walkthrough
 * (Diki Ardian, 2026-11-14), which probed the compiled wasm:
 *   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
 *   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
 *   decision, taskId, salt
 *
 * ENCODING ASSUMPTIONS (not documented on the build page — flagged as
 * uncertain, see README):
 * - 32-byte hashes (vk hashes) are BigInt(hash) mod p (BN128 scalar field).
 *   snarkjs's witness calculator reduces inputs mod p the same way.
 * - Addresses are uint160 integers (BigInt(address)).
 * - taskId (a string like "gk_24_9d1") is keccak256(taskId) mod p.
 * - salt is a private input, derived deterministically as
 *   keccak256("frozen008-agent-games-salt:" + taskId) mod p.
 * Any of these could differ from the platform's expectation; a locally
 * valid proof would still verify with snarkjs, but the platform may
 * compare public signals against its own encoding. Flagged in README.
 *
 * VERIFIED public-signal layout (probed 2026-11-15, see test/local-test.js):
 *   [0]  Poseidon([salt, taskId])        — replay-binding commitment
 *   [1]  registeredVkHash  [2] proofVkHash  [3] minimum
 *   [4]  publicBalance     [5] expiryBlock  [6] currentBlock
 *   [7]  recipient         [8] conditionRecipient
 *   [9]  amount            [10] maxTransfer
 *   [11] decision          [12] taskId
 */

const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const DEFAULT_WASM = path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm');
const DEFAULT_ZKEY = path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey');
const DEFAULT_VK = path.join(__dirname, '..', 'circuits', 'verification_key.json');

function hashToField(value) {
  // value: hex string '0x...' or utf8 string -> keccak256 -> BigInt mod p
  let hex;
  if (typeof value === 'string' && /^0x[0-9a-fA-F]+$/.test(value)) {
    hex = value.slice(2);
    return BigInt('0x' + hex) % FIELD_P;
  }
  const h = keccak_256(Buffer.from(String(value), 'utf8'));
  return BigInt('0x' + h) % FIELD_P;
}

function taskIdToField(taskId) {
  return hashToField(taskId);
}

function defaultSalt(taskId) {
  return hashToField(`frozen008-agent-games-salt:${taskId}`);
}

/**
 * Build the circuit input object. All values are decimal strings
 * (snarkjs accepts them; BigInts are stringified the same way).
 */
function buildCircuitInput(d) {
  const decision = d.decision === 1 || d.decision === '1' || d.decision === 'APPROVE' ? 1 : 0;
  const taskId = d.taskId || d.task_id || '';
  if (!taskId) throw new Error('taskId is required to build the circuit input');
  const salt = d.salt !== undefined ? (typeof d.salt === 'bigint' ? d.salt : BigInt(d.salt)) : defaultSalt(taskId);
  const input = {
    registeredVkHash: (BigInt(d.registeredVkHash ?? d.registered_vk) % FIELD_P).toString(10),
    proofVkHash: (BigInt(d.proofVkHash ?? d.proof_vk) % FIELD_P).toString(10),
    minimum: BigInt(d.minimum).toString(10),
    publicBalance: BigInt(d.publicBalance ?? d.public_balance).toString(10),
    expiryBlock: BigInt(d.expiryBlock ?? d.expiry_block).toString(10),
    currentBlock: BigInt(d.currentBlock ?? d.current_block).toString(10),
    recipient: BigInt(d.recipient).toString(10),
    conditionRecipient: BigInt(d.conditionRecipient ?? d.condition_recipient).toString(10),
    amount: BigInt(d.amount).toString(10),
    maxTransfer: BigInt(d.maxTransfer ?? d.max_transfer).toString(10),
    decision: decision.toString(10),
    taskId: taskIdToField(taskId).toString(10),
    salt: (salt % FIELD_P).toString(10),
  };
  return input;
}

/**
 * Generate a Groth16 proof for a decision.
 * @returns {Promise<{proof, publicSignals, durationMs}>}
 * Throws if the circuit refuses the decision (wrong decision for the inputs).
 */
async function generateProof(decisionInput, opts = {}) {
  const wasmPath = opts.wasmPath || process.env.CIRCUIT_WASM || DEFAULT_WASM;
  const zkeyPath = opts.zkeyPath || process.env.CIRCUIT_ZKEY || DEFAULT_ZKEY;
  const input = buildCircuitInput(decisionInput);
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
  return { proof, publicSignals, durationMs: Date.now() - t0, input };
}

async function verifyProof(publicSignals, proof, opts = {}) {
  const vkPath = opts.vkPath || process.env.CIRCUIT_VK || DEFAULT_VK;
  const vk = JSON.parse(fs.readFileSync(vkPath, 'utf8'));
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

module.exports = { buildCircuitInput, generateProof, verifyProof, taskIdToField, defaultSalt, hashToField, FIELD_P };
