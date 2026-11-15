'use strict';
/**
 * frozen008 — Proof Gatekeeper agent for zkVerify Agent Games.
 *
 * Endpoints:
 *   GET  /health     -> {"status":"ok"}            (platform health check)
 *   GET  /           -> {"status":"ok", ...}       (same, in case the check hits root)
 *   POST /agent      -> gatekeeper task endpoint (HMAC-verified, signed response)
 *
 * Env vars (see .env.example):
 *   PORT (default 3000), AGENT_GAMES_HMAC_SECRET (required in production),
 *   CIRCUIT_WASM, CIRCUIT_ZKEY, CIRCUIT_VK, ZKVERIFY_RPC_URL (optional).
 *
 * Security notes:
 * - Incoming tasks are HMAC-verified (sha256 over the RAW body) before parsing.
 *   Header assumed: `x-agent-games-signature` (build page names this header for
 *   responses; the incoming header name is NOT documented — flagged in README).
 * - Every response is signed with the same HMAC over the raw response body.
 * - Fail closed: unknown/malformed tasks are REJECTed (or 400 for a wrong
 *   envelope type); no decision is ever guessed.
 * - The HMAC secret must come from the dashboard ("Rotate Secret"). Never
 *   hardcode it, never commit it (.env is git-ignored).
 */
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { decide } = require('./lib/decision');
const { generateProof } = require('./lib/proof');
const { SeenStore } = require('./lib/store');
const { checkProofOnChain } = require('./lib/chain');

const PORT = parseInt(process.env.PORT || '3000', 10);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const TASK_TYPE = 'agent-games.proof-gatekeeper.v1';
const MAX_TOTAL_MS = 55000; // platform deadline is 60s; leave 5s of margin

if (process.env.NODE_ENV === 'production' && !HMAC_SECRET) {
  console.error('[fatal] AGENT_GAMES_HMAC_SECRET is required in production. Refusing to start.');
  process.exit(1);
}
if (!HMAC_SECRET) {
  console.warn('[warn] AGENT_GAMES_HMAC_SECRET is not set — HMAC verification DISABLED (development only).');
}

const seen = new SeenStore(path.join(__dirname, 'data', 'seen.json'));
const app = express();
app.use(express.raw({ type: 'application/json', limit: '1mb' }));

function hmacHex(secret, raw) {
  return crypto.createHmac('sha256', secret).update(raw).digest('hex');
}

function verifySignature(raw, headerValue) {
  if (!HMAC_SECRET) return true; // dev only; production refuses to start without a secret
  if (!headerValue) return false;
  const clean = String(headerValue).replace(/^sha256=/i, '');
  const expected = hmacHex(HMAC_SECRET, raw);
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(clean, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function sendSigned(res, statusCode, bodyObj) {
  const raw = JSON.stringify(bodyObj);
  if (HMAC_SECRET) res.set('x-agent-games-signature', hmacHex(HMAC_SECRET, raw));
  res.status(statusCode).type('application/json').send(raw);
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok', agent: 'frozen008', service: 'proof-gatekeeper', time: new Date().toISOString() });
});

app.get('/', (req, res) => {
  res.json({ status: 'ok', agent: 'frozen008', service: 'proof-gatekeeper' });
});

async function handlePost(req, res, probeOk) {
  const startedAt = Date.now();
  const raw = req.body; // Buffer (express.raw)
  const log = (msg, extra = {}) => console.log(JSON.stringify({ ts: new Date().toISOString(), ...extra, msg }));

  if (!Buffer.isBuffer(raw) || raw.length === 0) {
    return sendSigned(res, 400, { error: 'empty body' });
  }
  if (!verifySignature(raw, req.get('x-agent-games-signature'))) {
    log('rejected: bad HMAC signature');
    return sendSigned(res, 401, { error: 'invalid signature' });
  }

  let envelope;
  try {
    envelope = JSON.parse(raw.toString('utf8'));
  } catch {
    return sendSigned(res, 400, { error: 'invalid json' });
  }
  if (!envelope || envelope.type !== TASK_TYPE) {
    // The platform probes the registered endpoint root with a signed
    // preflight request whose type is not the task type. A signed 200
    // here is what the health check and preflight require.
    if (probeOk) return sendSigned(res, 200, { status: 'ok', agent: 'frozen008', service: 'proof-gatekeeper' });
    return sendSigned(res, 400, { error: 'unsupported task type', type: envelope && envelope.type });
  }

  const taskId = envelope.task_id || '(no task_id)';
  const mode = envelope.mode || 'competition';
  log('task received', { task_id: taskId, mode });

  const onChain = await checkProofOnChain(envelope.input && envelope.input.proof_tx);
  if (!onChain.checked) log('on-chain check skipped', { task_id: taskId, reason: onChain.reason });

  const result = decide(envelope.input, seen, mode);
  log('decision', { task_id: taskId, decision: result.decision, reason_code: result.reason_code, detail: result.detail });

  // The proof was "accepted" by us only when we APPROVE — that is the
  // literal reading of the PROOF_REUSED rule ("already accepted in a
  // previous task"). Rejected proofs are not added to the seen-set.
  if (result.decision === 'APPROVE' && envelope.input && envelope.input.proof_tx) {
    seen.add(mode, envelope.input.proof_tx, taskId);
  }

  const response = {
    decision: result.decision,
    reason_code: result.reason_code,
    proof_tx: envelope.input && envelope.input.proof_tx,
  };

  if (result.needsProof) {
    if (Date.now() - startedAt > MAX_TOTAL_MS - 10000) {
      log('skipping proof: too close to deadline', { task_id: taskId });
    } else {
      try {
        const { proof, publicSignals, durationMs } = await generateProof({
          registeredVkHash: envelope.input.registered_vk,
          proofVkHash: envelope.input.proof_vk,
          minimum: envelope.input.minimum,
          publicBalance: envelope.input.public_balance,
          expiryBlock: envelope.input.expiry_block,
          currentBlock: envelope.input.current_block,
          recipient: envelope.input.recipient,
          conditionRecipient: envelope.input.condition_recipient,
          amount: envelope.input.amount,
          maxTransfer: envelope.input.max_transfer,
          decision: result.decision === 'APPROVE' ? 1 : 0,
          taskId,
        });
        response.proof = proof;
        response.publicSignals = publicSignals;
        log('proof generated', { task_id: taskId, proof_ms: durationMs });
      } catch (err) {
        // Circuit refuses a proof when the decision contradicts the inputs.
        // That means our decision logic and the circuit disagree — a bug, or
        // an input the circuit cannot prove (e.g. decision 0 on a fully
        // valid task). Still return the decision: a correct decision without
        // a proof scores +12-2, a timeout scores -2 and forfeits the task.
        log('proof generation FAILED', { task_id: taskId, error: String(err && err.message || err).slice(0, 300) });
      }
    }
  }

  log('responding', { task_id: taskId, total_ms: Date.now() - startedAt, with_proof: !!response.proof });
  return sendSigned(res, 200, response);
}

app.post('/agent', (req, res) => handlePost(req, res, false));

// The platform POSTs tasks AND the signed preflight to the registered
// endpoint root, not to /agent. Unknown types at the root are answered
// 200 so the health check / preflight pass.
app.post('/', (req, res) => handlePost(req, res, true));

app.listen(PORT, () => {
  console.log(`[frozen008] proof-gatekeeper listening on :${PORT} (health: /health, tasks: POST / and /agent)`);
});

module.exports = app;
