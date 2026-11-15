'use strict';
const fs = require('fs');
const path = require('path');

/**
 * Persistent seen-set for proof_tx reuse detection (PROOF_REUSED trap).
 * Stored as JSON so it survives restarts. Scoped per mode
 * (competition / practice) because practice tasks must not poison the
 * competition seen-set.
 */
class SeenStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.map = new Map(); // key `${mode}:${proofTxLower}` -> {taskId, firstSeenAt}
    this.load();
  }

  load() {
    try {
      const raw = fs.readFileSync(this.filePath, 'utf8');
      const data = JSON.parse(raw);
      for (const e of data.entries || []) {
        this.map.set(`${e.mode}:${String(e.proofTx).toLowerCase()}`, e);
      }
    } catch (err) {
      if (err.code !== 'ENOENT') console.warn(`[seen] could not load ${this.filePath}: ${err.message}`);
    }
  }

  save() {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const data = { entries: [...this.map.values()] };
    fs.writeFileSync(this.filePath, JSON.stringify(data, null, 2));
  }

  has(mode, proofTx) {
    return this.map.has(`${mode}:${String(proofTx).toLowerCase()}`);
  }

  add(mode, proofTx, taskId) {
    const key = `${mode}:${String(proofTx).toLowerCase()}`;
    if (!this.map.has(key)) {
      this.map.set(key, { mode, proofTx: String(proofTx).toLowerCase(), taskId, firstSeenAt: new Date().toISOString() });
      this.save();
    }
  }

  size() { return this.map.size; }
}

module.exports = { SeenStore };
