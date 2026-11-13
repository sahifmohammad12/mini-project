/**
 * db.js — SQLite database layer using Node's built-in `node:sqlite`
 *         (available from Node 22+, no native compilation required)
 *
 * Tables:
 *   companies      — registered organisations (each has a company_id + password)
 *   blockchain     — immutable chain of blocks; each block records one registered file
 *   uploads        — public uploads awaiting verification (anyone can submit)
 *   verifications  — verification results tied to an upload
 */

"use strict";

const { DatabaseSync } = require("node:sqlite");
const crypto  = require("node:crypto");
const path    = require("node:path");
const fs      = require("node:fs");

const DATA_DIR = path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new DatabaseSync(path.join(DATA_DIR, "deepfake.db"));

// ─── Pragmas ──────────────────────────────────────────────────────────────────

db.exec("PRAGMA journal_mode = WAL;");
db.exec("PRAGMA foreign_keys = ON;");

// ─── Schema ───────────────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS companies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id  TEXT    UNIQUE NOT NULL,
    name        TEXT    NOT NULL,
    password    TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS blockchain (
    block_index   INTEGER PRIMARY KEY AUTOINCREMENT,
    previous_hash TEXT    NOT NULL,
    timestamp     TEXT    NOT NULL DEFAULT (datetime('now')),
    file_hash     TEXT    NOT NULL UNIQUE,
    file_name     TEXT    NOT NULL,
    file_size     INTEGER NOT NULL,
    company_id    TEXT    NOT NULL,
    block_hash    TEXT    NOT NULL,
    nonce         INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS uploads (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    file_hash   TEXT    NOT NULL,
    file_name   TEXT    NOT NULL,
    file_size   INTEGER NOT NULL,
    uploader    TEXT    NOT NULL DEFAULT 'anonymous',
    uploaded_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS verifications (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    upload_id         INTEGER NOT NULL,
    file_hash         TEXT    NOT NULL,
    is_registered     INTEGER NOT NULL,
    block_index       INTEGER,
    registered_by     TEXT,
    registered_at     TEXT,
    ai_deepfake_score REAL,
    verdict           TEXT    NOT NULL,
    verified_at       TEXT    NOT NULL DEFAULT (datetime('now'))
  );
`);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function hashPassword(plain) {
  return crypto.createHash("sha256").update(plain + "DEEPFAKE_SALT_2024").digest("hex");
}

function computeBlockHash(index, previous_hash, file_hash, file_name, file_size, company_id, nonce) {
  const data = `${index}${previous_hash}${file_hash}${file_name}${file_size}${company_id}${nonce}`;
  return crypto.createHash("sha256").update(data).digest("hex");
}

// ─── Genesis block ────────────────────────────────────────────────────────────

const genesisRow = db.prepare("SELECT block_index FROM blockchain WHERE block_index = 1").get();
if (!genesisRow) {
  const prevHash = "0".repeat(64);
  const fileHash = "0".repeat(64);
  let nonce = 0;
  let blockHash;
  do {
    nonce++;
    blockHash = computeBlockHash(1, prevHash, fileHash, "GENESIS", 0, "SYSTEM", nonce);
  } while (!blockHash.startsWith("00"));

  db.prepare(`
    INSERT INTO blockchain (previous_hash, file_hash, file_name, file_size, company_id, block_hash, nonce)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(prevHash, fileHash, "GENESIS", 0, "SYSTEM", blockHash, nonce);
}

// ─── Seed companies ───────────────────────────────────────────────────────────

const demoCompanies = [
  { id: "CORP001", name: "MediaCorp Inc.",   pw: "pass1234"  },
  { id: "CORP002", name: "TrustMedia Ltd.",  pw: "secure99"  },
  { id: "CORP003", name: "VerifyPress Co.",  pw: "verify42"  },
];
const insertComp = db.prepare(
  "INSERT OR IGNORE INTO companies (company_id, name, password) VALUES (?, ?, ?)"
);
for (const c of demoCompanies) {
  insertComp.run(c.id, c.name, hashPassword(c.pw));
}

// ─── Public API ───────────────────────────────────────────────────────────────

function getLastBlock() {
  return db.prepare("SELECT * FROM blockchain ORDER BY block_index DESC LIMIT 1").get();
}

function authenticateCompany(company_id, password) {
  const hashed = hashPassword(password);
  return db.prepare("SELECT * FROM companies WHERE company_id = ? AND password = ?").get(company_id, hashed);
}

function createCompany({ company_id, name, password }) {
  const existing = db.prepare("SELECT company_id FROM companies WHERE company_id = ?").get(company_id);
  if (existing) {
    return { success: false, error: "COMPANY_EXISTS" };
  }
  const hashed = hashPassword(password);
  db.prepare("INSERT INTO companies (company_id, name, password) VALUES (?, ?, ?)").run(company_id, name, hashed);
  return { success: true, company: { company_id, name } };
}

function registerFile({ file_hash, file_name, file_size, company_id }) {
  const existing = db.prepare("SELECT * FROM blockchain WHERE file_hash = ?").get(file_hash);
  if (existing) {
    return { success: false, error: "FILE_ALREADY_REGISTERED", block: existing };
  }

  const last      = getLastBlock();
  const nextIndex = last.block_index + 1;
  const DIFFICULTY = 2;
  const prefix     = "0".repeat(DIFFICULTY);

  let nonce = 0;
  let blockHash;
  do {
    nonce++;
    blockHash = computeBlockHash(nextIndex, last.block_hash, file_hash, file_name, file_size, company_id, nonce);
  } while (!blockHash.startsWith(prefix));

  const result = db.prepare(`
    INSERT INTO blockchain (previous_hash, file_hash, file_name, file_size, company_id, block_hash, nonce)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(last.block_hash, file_hash, file_name, file_size, company_id, blockHash, nonce);

  return {
    success: true,
    block: db.prepare("SELECT * FROM blockchain WHERE block_index = ?").get(result.lastInsertRowid),
  };
}

function verifyFile({ file_hash, file_name, file_size, uploader }) {
  const uploadResult = db.prepare(`
    INSERT INTO uploads (file_hash, file_name, file_size, uploader) VALUES (?, ?, ?, ?)
  `).run(file_hash, file_name, file_size, uploader || "anonymous");

  const upload_id = uploadResult.lastInsertRowid;
  const block     = db.prepare("SELECT * FROM blockchain WHERE file_hash = ?").get(file_hash);
  const is_registered = block ? 1 : 0;

  // Deterministic pseudo-random AI score (seed = file_hash)
  const scoreHex        = crypto.createHash("sha256").update(file_hash + "AI_ADVISORY_SEED").digest("hex");
  const ai_deepfake_score = parseInt(scoreHex.slice(0, 4), 16) / 65535;

  let verdict;
  if (!is_registered) {
    verdict = "UNREGISTERED";
  } else if (ai_deepfake_score > 0.75) {
    verdict = "SUSPICIOUS";
  } else {
    verdict = "AUTHENTIC";
  }

  db.prepare(`
    INSERT INTO verifications
      (upload_id, file_hash, is_registered, block_index, registered_by, registered_at, ai_deepfake_score, verdict)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    upload_id, file_hash, is_registered,
    block ? block.block_index : null,
    block ? block.company_id  : null,
    block ? block.timestamp   : null,
    parseFloat(ai_deepfake_score.toFixed(4)),
    verdict
  );

  return {
    is_registered: !!is_registered,
    block:         block || null,
    ai_deepfake_score: parseFloat(ai_deepfake_score.toFixed(4)),
    verdict,
    upload_id,
  };
}

function getChain(limit = 20, offset = 0) {
  return db.prepare("SELECT * FROM blockchain ORDER BY block_index DESC LIMIT ? OFFSET ?").all(limit, offset);
}

function getChainLength() {
  return db.prepare("SELECT COUNT(*) AS count FROM blockchain").get().count;
}

function validateChain() {
  const blocks = db.prepare("SELECT * FROM blockchain ORDER BY block_index ASC").all();
  for (let i = 1; i < blocks.length; i++) {
    const b    = blocks[i];
    const prev = blocks[i - 1];
    const expected = computeBlockHash(
      b.block_index, b.previous_hash, b.file_hash,
      b.file_name, b.file_size, b.company_id, b.nonce
    );
    if (expected !== b.block_hash)       return { valid: false, bad_index: b.block_index, reason: "hash_mismatch" };
    if (b.previous_hash !== prev.block_hash) return { valid: false, bad_index: b.block_index, reason: "broken_link" };
  }
  return { valid: true, length: blocks.length };
}

function listCompanies() {
  return db.prepare("SELECT company_id, name, created_at FROM companies").all();
}

module.exports = {
  authenticateCompany,
  createCompany,
  registerFile,
  verifyFile,
  getChain,
  getChainLength,
  validateChain,
  listCompanies,
  hashPassword,
};
