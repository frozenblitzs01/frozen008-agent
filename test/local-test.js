'use strict';
/**
 * Local integration test for the frozen008 Proof Gatekeeper agent.
 *
 * Starts server.js on a test port, then drives it over HTTP with
 * HMAC-signed tasks (1 VALID case + 1 case per trap + 1 malformed case),
 * verifies every returned Groth16 proof with snarkjs, and checks the
 * circuit's strictness directly (a wrong decision must fail fullProve).
 *
 * Run: npm test
 */
const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { generateProof, verifyProof, taskIdToField, defaultSalt, FIELD_P } = require('../lib/proof');
const { decide } = require('../lib/decision');
const circomlibjs = require('circomlibjs');

const PORT = 3456;
const SECRET = 'test-secret-123';
const BASE_URL = `http://127.0.0.1:${PORT}`;
const ROOT = path.join(__dirname, '..');

const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const ADDR = '0xDe42aBcDeF0123456789aBcDeF0123456789aB01';
const ADDR_OTHER = '0x1111111111111111111111111111111111111111';

let passed = 0;
let failed = 0;
const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok: !!ok, detail });
  if (ok) { passed++; console.log(`  PASS  ${name}${detail ? ' — ' + detail : ''}`); }
  else { failed++; console.log(`  FAIL  ${name}${detail ? ' — ' + detail : ''}`); }
}

function baseInput(overrides = {}) {
  return {
    registered_vk: VK,
    proof_vk: VK,
    minimum: '1000',
    public_balance: '1460',
    expiry_block: 19842201,
    current_block: 19832000,
    recipient: ADDR,
    condition_recipient: ADDR,
    amount: '500',
    max_transfer: '1000',
    proof_tx: '0x' + 'a'.repeat(64),
    ...overrides,
  };
}

function taskEnvelope(input, taskId, mode = 'competition') {
  return { type: 'agent-games.proof-gatekeeper.v1', task_id: taskId, mode, issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60000).toISOString(), input };
}

function hmac(raw) {
  return crypto.createHmac('sha256', SECRET).update(raw).digest('hex');
}

async function postAgent(envelope, { sign = true } = {}) {
  const raw = JSON.stringify(envelope);
  const headers = { 'Content-Type': 'application/json' };
  if (sign) headers['x-agent-games-signature'] = hmac(raw);
  const t0 = Date.now();
  const res = await fetch(`${BASE_URL}/agent`, { method: 'POST', headers, body: raw });
  const resRaw = await res.text();
  let body = null;
  try { body = JSON.parse(resRaw); } catch { /* keep null */ }
  const sigOk = !SECRET ? true : (res.headers.get('x-agent-games-signature') === hmac(resRaw));
  return { status: res.status, body, raw: resRaw, sigOk, ms: Date.now() - t0 };
}

async function waitHealth(timeoutMs = 15000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    try {
      const res = await fetch(`${BASE_URL}/health`);
      if (res.ok) return true;
    } catch { /* retry */ }
    await new Promise((r) => setTimeout(r, 300));
  }
  return false;
}

async function main() {
  // Hermetic seen-set: start from an empty store.
  const seenFile = path.join(ROOT, 'data', 'seen.json');
  try { fs.unlinkSync(seenFile); } catch { /* first run */ }

  console.log('== starting server ==');
  const server = spawn('node', ['server.js'], {
    cwd: ROOT,
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET, NODE_ENV: 'development' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  server.stdout.on('data', (d) => process.stdout.write('[srv] ' + d));
  server.stderr.on('data', (d) => process.stdout.write('[srv:err] ' + d));
  let exitCode = 0;
  try {
    if (!(await waitHealth())) throw new Error('server did not become healthy in time');

    console.log('\n== HTTP decision tests ==');
    // 1. VALID -> APPROVE + valid proof
    let r = await postAgent(taskEnvelope(baseInput(), 'gk_test_valid'));
    check('VALID: status 200', r.status === 200, `status=${r.status}`);
    check('VALID: decision APPROVE', r.body && r.body.decision === 'APPROVE', JSON.stringify(r.body && r.body.decision));
    check('VALID: reason VALID_CONDITION', r.body && r.body.reason_code === 'VALID_CONDITION');
    check('VALID: response HMAC signature verifies', r.sigOk);
    check('VALID: proof present', !!(r.body && r.body.proof && r.body.publicSignals));
    let proofOk = false;
    if (r.body && r.body.proof) {
      proofOk = await verifyProof(r.body.publicSignals, r.body.proof);
      check('VALID: Groth16 proof verifies (snarkjs)', proofOk);
      check('VALID: publicSignals length is 13', r.body.publicSignals.length === 13, `len=${r.body.publicSignals.length}`);
      // Map public signals to expected values for the report.
      // Verified public-signal layout (indices, probed 2026-11-15):
      //   [0] Poseidon([salt, taskId]) — replay-binding commitment
      //   [1] registeredVkHash  [2] proofVkHash  [3] minimum
      //   [4] publicBalance     [5] expiryBlock  [6] currentBlock
      //   [7] recipient         [8] conditionRecipient
      //   [9] amount            [10] maxTransfer
      //   [11] decision         [12] taskId (keccak256(taskId) mod p)
      const ps = r.body.publicSignals;
      const expected = [
        null, // [0] checked via Poseidon below
        (BigInt(VK) % FIELD_P).toString(10),
        (BigInt(VK) % FIELD_P).toString(10),
        '1000', '1460', '19842201', '19832000',
        BigInt(ADDR).toString(10), BigInt(ADDR).toString(10),
        '500', '1000', '1',
        taskIdToField('gk_test_valid').toString(10),
      ];
      let layoutOk = true;
      for (let i = 1; i <= 12; i++) if (ps[i] !== expected[i]) layoutOk = false;
      check('VALID: publicSignals layout [1..12] matches task inputs', layoutOk);
      const poseidon = await circomlibjs.buildPoseidon();
      const commit = poseidon.F.toObject(poseidon([defaultSalt('gk_test_valid'), taskIdToField('gk_test_valid')]));
      check('VALID: publicSignals[0] = Poseidon([salt, taskId])', commit.toString(10) === ps[0]);
      console.log('  publicSignals:', JSON.stringify(ps));
    }
    check('VALID: round-trip < 60s', r.ms < 60000, `${r.ms}ms`);

    // 2. VK_SUBSTITUTION
    r = await postAgent(taskEnvelope(baseInput({ proof_vk: '0x' + 'c'.repeat(64), proof_tx: '0x' + 'b'.repeat(64) }), 'gk_test_vk'));
    check('VK_SUBSTITUTION: REJECT', r.body && r.body.decision === 'REJECT');
    check('VK_SUBSTITUTION: reason_code', r.body && r.body.reason_code === 'VK_SUBSTITUTION');
    check('VK_SUBSTITUTION: proof present and verifies', !!(r.body && r.body.proof) && (await verifyProof(r.body.publicSignals, r.body.proof)));

    // 3. THRESHOLD_MISMATCH
    r = await postAgent(taskEnvelope(baseInput({ public_balance: '500', proof_tx: '0x' + 'd'.repeat(64) }), 'gk_test_threshold'));
    check('THRESHOLD_MISMATCH: REJECT', r.body && r.body.decision === 'REJECT');
    check('THRESHOLD_MISMATCH: reason_code', r.body && r.body.reason_code === 'THRESHOLD_MISMATCH');
    check('THRESHOLD_MISMATCH: proof verifies', !!(r.body && r.body.proof) && (await verifyProof(r.body.publicSignals, r.body.proof)));

    // 4. PROOF_REUSED — same proof_tx as the VALID case (already APPROVEd)
    r = await postAgent(taskEnvelope(baseInput(), 'gk_test_reused'));
    check('PROOF_REUSED: REJECT', r.body && r.body.decision === 'REJECT');
    check('PROOF_REUSED: reason_code', r.body && r.body.reason_code === 'PROOF_REUSED');
    check('PROOF_REUSED: no proof field (per platform docs)', r.body && !r.body.proof);

    // 5. EXPIRED_CONDITION
    r = await postAgent(taskEnvelope(baseInput({ current_block: 19843000, proof_tx: '0x' + 'e'.repeat(64) }), 'gk_test_expired'));
    check('EXPIRED_CONDITION: REJECT', r.body && r.body.decision === 'REJECT');
    check('EXPIRED_CONDITION: reason_code', r.body && r.body.reason_code === 'EXPIRED_CONDITION');
    check('EXPIRED_CONDITION: proof verifies', !!(r.body && r.body.proof) && (await verifyProof(r.body.publicSignals, r.body.proof)));

    // 6. RECIPIENT_MISMATCH
    r = await postAgent(taskEnvelope(baseInput({ recipient: ADDR_OTHER, proof_tx: '0x' + 'f'.repeat(64) }), 'gk_test_recipient'));
    check('RECIPIENT_MISMATCH: REJECT', r.body && r.body.decision === 'REJECT');
    check('RECIPIENT_MISMATCH: reason_code', r.body && r.body.reason_code === 'RECIPIENT_MISMATCH');
    check('RECIPIENT_MISMATCH: proof verifies', !!(r.body && r.body.proof) && (await verifyProof(r.body.publicSignals, r.body.proof)));

    // 7. AMOUNT_OVERFLOW
    r = await postAgent(taskEnvelope(baseInput({ amount: '1500', proof_tx: '0x' + '1'.repeat(64) }), 'gk_test_amount'));
    check('AMOUNT_OVERFLOW: REJECT', r.body && r.body.decision === 'REJECT');
    check('AMOUNT_OVERFLOW: reason_code', r.body && r.body.reason_code === 'AMOUNT_OVERFLOW');
    check('AMOUNT_OVERFLOW: proof verifies', !!(r.body && r.body.proof) && (await verifyProof(r.body.publicSignals, r.body.proof)));

    // 8. Malformed input -> REJECT INVALID_INPUT
    r = await postAgent(taskEnvelope(baseInput({ minimum: 'not-a-number', proof_tx: '0x' + '2'.repeat(64) }), 'gk_test_malformed'));
    check('MALFORMED: REJECT', r.body && r.body.decision === 'REJECT');
    check('MALFORMED: reason INVALID_INPUT', r.body && r.body.reason_code === 'INVALID_INPUT');

    // 9. Bad HMAC -> 401
    r = await postAgent(taskEnvelope(baseInput({ proof_tx: '0x' + '3'.repeat(64) }), 'gk_test_badhMAC'), { sign: false });
    check('BAD HMAC: 401', r.status === 401, `status=${r.status}`);

    // 10. Wrong envelope type -> 400
    const wrongType = taskEnvelope(baseInput({ proof_tx: '0x' + '4'.repeat(64) }), 'gk_test_wrongtype');
    wrongType.type = 'agent-games.something-else.v1';
    r = await postAgent(wrongType);
    check('WRONG TYPE: 400', r.status === 400, `status=${r.status}`);

    console.log('\n== decision.js unit checks (priority) ==');
    const seenStub = { has: () => false };
    const doubleTrap = decide(baseInput({ proof_vk: '0x' + 'c'.repeat(64), public_balance: '1' }), seenStub);
    check('double trap (VK+threshold) -> VK_SUBSTITUTION first', doubleTrap.reason_code === 'VK_SUBSTITUTION', doubleTrap.reason_code);

    console.log('\n== circuit strictness (direct proof.js) ==');
    const t0 = Date.now();
    let threw = false;
    try {
      await generateProof({
        registeredVkHash: VK, proofVkHash: VK, minimum: '1000', publicBalance: '1460',
        expiryBlock: 19842201, currentBlock: 19832000, recipient: ADDR_OTHER,
        conditionRecipient: ADDR, amount: '500', maxTransfer: '1000',
        decision: 1, taskId: 'gk_strict_approve_trap',
      });
    } catch { threw = true; }
    check('circuit refuses APPROVE on recipient-mismatch trap', threw, `took ${Date.now() - t0}ms`);

    threw = false;
    try {
      await generateProof({
        registeredVkHash: VK, proofVkHash: VK, minimum: '1000', publicBalance: '1460',
        expiryBlock: 19842201, currentBlock: 19832000, recipient: ADDR,
        conditionRecipient: ADDR, amount: '500', maxTransfer: '1000',
        decision: 0, taskId: 'gk_strict_reject_valid',
      });
    } catch { threw = true; }
    check('circuit refuses REJECT on fully-valid inputs', threw);

    // Timing benchmark: one full proof
    const bench = await generateProof({
      registeredVkHash: VK, proofVkHash: VK, minimum: '1000', publicBalance: '1460',
      expiryBlock: 19842201, currentBlock: 19832000, recipient: ADDR,
      conditionRecipient: ADDR, amount: '500', maxTransfer: '1000',
      decision: 1, taskId: 'gk_bench',
    });
    console.log(`\n== benchmark ==\n  proof generation: ${bench.durationMs}ms (limit 60000ms)`);
    check('proof generation < 60s', bench.durationMs < 60000, `${bench.durationMs}ms`);
  } catch (err) {
    console.error('TEST ERROR:', err);
    exitCode = 1;
  } finally {
    server.kill();
  }

  console.log(`\n== summary ==\n  ${passed} passed, ${failed} failed`);
  process.exit(failed > 0 || exitCode ? 1 : 0);
}

main();
