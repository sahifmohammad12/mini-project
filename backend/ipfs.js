/**
 * ipfs.js — Local IPFS Content Addressing & Storage Engine
 *
 * Implements standard IPFS CIDv0 (Base58btc multihash starting with Qm...)
 * and content-addressed storage for decentralized media verification.
 */

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const IPFS_STORAGE_DIR = path.join(__dirname, "data", "ipfs_storage");
fs.mkdirSync(IPFS_STORAGE_DIR, { recursive: true });

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(buffer) {
  const digits = [0];
  for (let i = 0; i < buffer.length; i++) {
    for (let j = 0; j < digits.length; j++) digits[j] <<= 8;
    digits[0] += buffer[i];
    let carry = 0;
    for (let j = 0; j < digits.length; ++j) {
      digits[j] += carry;
      carry = (digits[j] / 58) | 0;
      digits[j] %= 58;
    }
    while (carry) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  for (let i = 0; buffer[i] === 0 && i < buffer.length - 1; i++) digits.push(0);
  return digits.reverse().map((d) => BASE58_ALPHABET[d]).join("");
}

/**
 * Calculates standard IPFS CIDv0 (Qm... 46-char Base58btc multihash: 0x12 0x20 <sha256>)
 * @param {Buffer} buffer - File buffer
 * @returns {string} IPFS CIDv0 string
 */
function calculateIpfsCid(buffer) {
  const hash = crypto.createHash("sha256").update(buffer).digest();
  const multihash = Buffer.concat([Buffer.from([0x12, 0x20]), hash]);
  return base58Encode(multihash);
}

/**
 * Stores file in content-addressed IPFS storage directory
 * @param {Buffer} buffer - File buffer
 * @param {string} [cid] - Optional precalculated CID
 * @returns {string} The IPFS CID
 */
function pinToIpfs(buffer, cid) {
  const computedCid = cid || calculateIpfsCid(buffer);
  const filePath = path.join(IPFS_STORAGE_DIR, computedCid);
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, buffer);
  }
  return computedCid;
}

/**
 * Retrieves file from IPFS storage
 * @param {string} cid - IPFS CID
 * @returns {Buffer|null} File buffer if found
 */
function getFromIpfs(cid) {
  const cleanCid = path.basename(cid);
  const filePath = path.join(IPFS_STORAGE_DIR, cleanCid);
  if (fs.existsSync(filePath)) {
    return fs.readFileSync(filePath);
  }
  return null;
}

module.exports = {
  calculateIpfsCid,
  pinToIpfs,
  getFromIpfs,
  IPFS_STORAGE_DIR,
};
