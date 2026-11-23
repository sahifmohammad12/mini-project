/**
 * server.js — Express REST API
 *
 * Routes:
 *   POST /api/company/login       — authenticate a company (returns session token)
 *   GET  /api/company/list        — list companies (public, no passwords)
 *
 *   POST /api/register            — register a file on the blockchain (company only)
 *   POST /api/upload              — upload a file for verification (anyone)
 *   GET  /api/verify/:hash        — verify a SHA-256 hash against the chain
 *
 *   GET  /api/chain               — paginated blockchain explorer
 *   GET  /api/chain/validate      — verify chain integrity
 *   GET  /api/chain/length        — total block count
 */

const express  = require("express");
const cors     = require("cors");
const crypto   = require("crypto");
const multer   = require("multer");
const path     = require("path");
const fs       = require("fs");
const { ethers } = require("ethers");

const db   = require("./db");
const ipfs = require("./ipfs");

const app  = express();
const PORT = process.env.PORT || 4000;

// ─── Middleware ───────────────────────────────────────────────────────────────

app.use(cors({ origin: "*" }));
app.use(express.json());

// Multer: store file in memory so we can hash it without saving to disk
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB max
});

// ─── Tiny in-memory token store (replace with JWT or Redis in production) ────

const sessions = new Map(); // token → { company_id, name, expires }

function createToken(company_id, name) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, {
    company_id,
    name,
    expires: Date.now() + 8 * 60 * 60 * 1000, // 8 hours
  });
  return token;
}

function requireCompany(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  const session = sessions.get(token);
  if (!session || session.expires < Date.now()) {
    return res.status(401).json({ error: "Token expired or invalid" });
  }
  req.company = session;
  next();
}

// ─── Utility ─────────────────────────────────────────────────────────────────

function sha256Buffer(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

// ─── Routes ──────────────────────────────────────────────────────────────────

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", time: new Date().toISOString() });
});

// ── Company auth ─────────────────────────────────────────────────────────────

app.post("/api/company/login", (req, res) => {
  const { company_id, password } = req.body || {};
  if (!company_id || !password) {
    return res.status(400).json({ error: "company_id and password required" });
  }
  const company = db.authenticateCompany(company_id.trim().toUpperCase(), password);
  if (!company) {
    return res.status(401).json({ error: "Invalid company ID or password" });
  }
  const token = createToken(company.company_id, company.name);
  res.json({ token, company_id: company.company_id, name: company.name });
});

app.post("/api/company/register", (req, res) => {
  const { company_id, name, password } = req.body || {};
  if (!company_id || !password) {
    return res.status(400).json({ error: "company_id and password required" });
  }
  const cleanId = company_id.trim().toUpperCase();
  const cleanName = (name && name.trim()) ? name.trim() : cleanId;
  const result = db.createCompany({ company_id: cleanId, name: cleanName, password });
  if (!result.success) {
    return res.status(409).json({ error: "Company ID already exists" });
  }
  const token = createToken(cleanId, cleanName);
  res.status(201).json({ token, company_id: cleanId, name: cleanName });
});

app.post("/api/company/logout", requireCompany, (req, res) => {
  const auth = req.headers.authorization.slice(7);
  sessions.delete(auth);
  res.json({ success: true });
});

app.get("/api/company/list", (req, res) => {
  res.json(db.listCompanies());
});

// ── Register (company only) ──────────────────────────────────────────────────

/**
 * POST /api/register
 * Body: multipart/form-data with field "file"
 * Auth: Authorization: Bearer <token>  OR  fields "company_id" & "password" in body
 *
 * The file is hashed in-memory; only the SHA-256 hash is stored on the chain.
 */
app.post("/api/register", upload.single("file"), (req, res) => {
  let company = null;

  // 1. Check Bearer token if provided
  const auth = req.headers.authorization || "";
  if (auth.startsWith("Bearer ")) {
    const token = auth.slice(7);
    const session = sessions.get(token);
    if (session && session.expires >= Date.now()) {
      company = session;
    }
  }

  // 2. Or check company_id and password directly in the form
  if (!company && req.body && req.body.company_id && req.body.password) {
    const verified = db.authenticateCompany(req.body.company_id.trim().toUpperCase(), req.body.password);
    if (verified) {
      company = { company_id: verified.company_id, name: verified.name };
    } else {
      return res.status(401).json({ error: "Invalid company ID or password" });
    }
  }

  if (!company) {
    return res.status(401).json({ error: "Company authentication required (Company ID and Password)" });
  }

  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  const file_hash = sha256Buffer(req.file.buffer);
  const file_name = req.file.originalname;
  const file_size = req.file.size;
  const company_id = company.company_id;

  // 3. Pin file to IPFS content-addressed storage
  const ipfs_cid = ipfs.pinToIpfs(req.file.buffer);

  // 4. Verify optional MetaMask Web3 wallet signature
  let verifiedSigner = null;
  const claimedWallet = req.body.signer_wallet || null;
  const walletSig = req.body.wallet_signature || null;
  const attestationMsg = req.body.attestation_message || null;

  if (claimedWallet && walletSig && attestationMsg) {
    try {
      const recovered = ethers.verifyMessage(attestationMsg, walletSig);
      if (recovered.toLowerCase() === claimedWallet.toLowerCase()) {
        verifiedSigner = recovered;
      }
    } catch (err) {
      console.warn("Wallet signature verification failed:", err.message);
    }
  }

  const result = db.registerFile({
    file_hash,
    file_name,
    file_size,
    company_id,
    ipfs_cid,
    signer_wallet: verifiedSigner,
    wallet_signature: walletSig,
    attestation_message: attestationMsg,
  });

  if (!result.success) {
    return res.status(409).json({
      error: "File already registered on the blockchain",
      details: result.block,
      file_hash,
      ipfs_cid,
    });
  }

  res.status(201).json({
    message: "File registered on the blockchain and pinned to IPFS",
    file_hash,
    ipfs_cid,
    signer_wallet: verifiedSigner,
    ipfs_gateway: `/api/ipfs/${ipfs_cid}`,
    public_ipfs_url: `https://ipfs.io/ipfs/${ipfs_cid}`,
    block: result.block,
    registered_by: company_id,
  });
});

// ── IPFS Gateway Endpoint ───────────────────────────────────────────────────

/**
 * GET /api/ipfs/:cid
 * Serves content-addressed media directly from the decentralized IPFS node cache
 */
app.get("/api/ipfs/:cid", (req, res) => {
  const cid = req.params.cid;
  const buffer = ipfs.getFromIpfs(cid);
  if (!buffer) {
    return res.status(404).json({ error: `Content ${cid} not found on local IPFS gateway` });
  }

  res.setHeader("Content-Disposition", `inline; filename="${cid}"`);
  res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
  res.send(buffer);
});

// ── Upload & Verify (anyone) ─────────────────────────────────────────────────

/**
 * POST /api/upload
 * Body: multipart/form-data with field "file" and optional "uploader" (name/email)
 */
app.post("/api/upload", upload.single("file"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  const file_hash = sha256Buffer(req.file.buffer);
  const file_name = req.file.originalname;
  const file_size = req.file.size;
  const uploader  = (req.body.uploader || "anonymous").toString().slice(0, 100);

  // Compute IPFS CID of uploaded copy
  const ipfs_cid = ipfs.calculateIpfsCid(req.file.buffer);

  const result = db.verifyFile({ file_hash, file_name, file_size, uploader });

  res.json({
    file_hash,
    ipfs_cid,
    file_name,
    file_size,
    ipfs_gateway: `/api/ipfs/${ipfs_cid}`,
    public_ipfs_url: `https://ipfs.io/ipfs/${ipfs_cid}`,
    ...result,
  });
});

/**
 * GET /api/verify/:hash
 * Quick hash-only lookup (no file upload required).
 */
app.get("/api/verify/:hash", (req, res) => {
  const hash = req.params.hash.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) {
    return res.status(400).json({ error: "Invalid SHA-256 hash" });
  }
  const result = db.verifyFile({
    file_hash: hash,
    file_name: "hash-only-query",
    file_size: 0,
    uploader: "api",
  });
  res.json({ file_hash: hash, ...result });
});

// ── Blockchain explorer ──────────────────────────────────────────────────────

app.get("/api/chain", (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit  || "20"), 100);
  const offset = parseInt(req.query.offset || "0");
  const chain  = db.getChain(limit, offset);
  const total  = db.getChainLength();
  res.json({ total, limit, offset, blocks: chain });
});

app.get("/api/chain/length", (req, res) => {
  res.json({ length: db.getChainLength() });
});

app.get("/api/chain/validate", (req, res) => {
  const result = db.validateChain();
  res.json(result);
});

// ── Serve Frontend Production Build (if dist/ exists) ─────────────────────────

const distPath = path.join(__dirname, "..", "dist");
if (fs.existsSync(distPath)) {
  console.log(`📦 Serving static frontend from ${distPath}`);
  app.use(express.static(distPath));

  // SPA fallback: any GET request not starting with /api returns index.html
  app.get("*", (req, res, next) => {
    if (req.path.startsWith("/api")) return next();
    res.sendFile(path.join(distPath, "index.html"));
  });
}

// ── JSON 404 & Error Handlers (Prevents unhandled HTML responses) ─────────────

app.use("/api/*", (req, res) => {
  res.status(404).json({ error: `API route ${req.method} ${req.originalUrl} not found` });
});

app.use((req, res) => {
  if (fs.existsSync(distPath)) {
    return res.sendFile(path.join(distPath, "index.html"));
  }
  res.status(404).json({ error: `Route ${req.method} ${req.originalUrl} not found` });
});

app.use((err, req, res, next) => {
  console.error("Internal API error:", err);
  res.status(err.status || 500).json({ error: err.message || "Internal server error" });
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n🔗 Deepfake Verification Backend`);
  console.log(`   Running on http://localhost:${PORT}`);
  console.log(`   Demo companies: CORP001/pass1234  CORP002/secure99  CORP003/verify42\n`);
});

