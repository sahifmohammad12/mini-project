/**
 * App.jsx — Blockchain-Based Deepfake Verification System
 *
 * Core Concept:
 *   - Column 1: "Register File" — Company credentials required (ID & Password) to mint records to the blockchain.
 *   - Column 2: "Upload & Verify File" — Public access for everyone else to verify any media against the blockchain.
 *   - End-to-End SHA-256: Hashes are calculated in the browser (Web Crypto API) and independently
 *     on the server (Node crypto), cross-checked in the UI to guarantee cryptographic integrity.
 */

import { lazy, Suspense, useEffect, useState, useRef, useCallback } from "react";

const HashField = lazy(() => import("./HashField.jsx"));

// ─── Resilient API Client & Live Deployment Config ────────────────────────────
// Priority for API Base URL:
//   1. User-customized URL in localStorage (can be set directly in the UI when deployed live)
//   2. Vite environment variable: import.meta.env.VITE_API_URL (set in Vercel/Netlify/Render)
//   3. Default relative path: "/api" (works automatically when full-stack is deployed on Render/Railway/VPS)
//   4. Local fallback: "http://localhost:4000/api" (ONLY on localhost/127.0.0.1)

const isLocalhost =
  typeof window !== "undefined" &&
  (window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1" ||
    window.location.hostname === "[::1]");

function getInitialApiBase() {
  if (typeof window !== "undefined") {
    const saved = localStorage.getItem("deepfake_api_url");
    if (saved && saved.trim()) return saved.trim().replace(/\/+$/, "");
  }

  const envUrl = import.meta.env?.VITE_API_URL;
  if (envUrl && envUrl.trim()) return envUrl.trim().replace(/\/+$/, "");

  return "/api";
}

let activeApiBase = getInitialApiBase();

function setConfiguredApiBase(newUrl) {
  const clean = (newUrl || "").trim().replace(/\/+$/, "");
  activeApiBase = clean || "/api";
  if (typeof window !== "undefined") {
    if (clean) {
      localStorage.setItem("deepfake_api_url", clean);
    } else {
      localStorage.removeItem("deepfake_api_url");
    }
  }
}

async function requestApi(endpoint, options = {}) {
  const path = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;

  const buildUrl = (base) => {
    // If base already ends with /api and path starts with /api, avoid /api/api
    if (base.endsWith("/api") && path.startsWith("/api")) {
      return `${base}${path.slice(4)}`;
    }
    // If base doesn't end with /api and path starts with /api
    return `${base}${path}`;
  };

  let res;
  try {
    res = await fetch(buildUrl(activeApiBase), options);
    const ct = res.headers.get("content-type") || "";

    // If local dev server returned index.html (SPA fallback because Vite proxy wasn't loaded)
    if (isLocalhost && ct.includes("text/html") && activeApiBase === "/api") {
      activeApiBase = "http://localhost:4000/api";
      res = await fetch(buildUrl(activeApiBase), options);
    }
  } catch (err) {
    // If local relative /api failed due to network / connection refusal
    if (isLocalhost && activeApiBase === "/api") {
      activeApiBase = "http://localhost:4000/api";
      res = await fetch(buildUrl(activeApiBase), options);
    } else {
      throw new Error(
        `Cannot connect to backend (${err.message}). ${
          !isLocalhost
            ? "Please verify or update your live backend URL in the connection settings."
            : "Ensure backend is running: cd backend && node server.js"
        }`
      );
    }
  }

  const ct = res.headers.get("content-type") || "";
  if (ct.includes("text/html")) {
    throw new Error(
      `Backend returned HTML instead of JSON (${res.status}). ${
        !isLocalhost
          ? "Please configure your live backend URL in the connection banner."
          : "Make sure the backend server is running on port 4000."
      }`
    );
  }

  let data;
  try {
    data = await res.json();
  } catch {
    throw new Error(`Failed to parse response as JSON (${res.status}).`);
  }

  if (!res.ok) {
    const err = new Error(data.error || `Server error (${res.status})`);
    err.details = data.details;
    err.status = res.status;
    throw err;
  }

  return data;
}

// ─── Style Tokens ─────────────────────────────────────────────────────────────
const btn =
  "inline-flex items-center justify-center gap-2 border border-ink bg-ink px-6 py-[0.95rem] font-medium text-bg no-underline hover:opacity-85 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed transition-all";
const btnAlt =
  "inline-flex items-center justify-center gap-2 border border-ink bg-transparent px-6 py-[0.95rem] font-medium text-ink no-underline hover:opacity-85 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed transition-all";
const sec = "mt-[clamp(5rem,14vw,10rem)] border-t border-rule pt-5";
const h2cls = "mb-4 text-[1.15rem] font-semibold tracking-tight";
const inputCls =
  "w-full border-b border-ink bg-transparent py-2.5 text-ink placeholder:text-mute focus:outline-none font-mono text-sm";
const tagCls =
  "inline-block rounded-sm px-2 py-0.5 text-[0.65rem] font-mono font-semibold uppercase tracking-widest";

const ORIGINAL = "This photo is original.";
const HEX = "0123456789abcdef";

// ─── SHA-256 Helpers ──────────────────────────────────────────────────────────
// Uses the native Web Crypto API (SHA-256) inside the browser.

async function sha256Text(text) {
  if (!window.crypto?.subtle) return "";
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256File(file) {
  const buf = await file.arrayBuffer();
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, "0")).join("");
}

// ─── Sub-Components ───────────────────────────────────────────────────────────

function Spinner({ size = 4 }) {
  return (
    <span
      className={`inline-block h-${size} w-${size} animate-spin rounded-full border-2 border-current border-t-transparent`}
      aria-hidden="true"
    />
  );
}

function Hash({ value, reference, label }) {
  return (
    <div
      aria-label={label}
      className="min-h-[2.6em] w-[32ch] max-w-full break-all font-mono text-[clamp(0.65rem,3.4vw,1.6rem)] leading-[1.3]"
    >
      {Array.from(value).map((c, i) => (
        <span key={i} className={reference && reference[i] !== c ? "opacity-20" : undefined}>
          {c}
        </span>
      ))}
    </div>
  );
}

function Scene({ reg, cur, className }) {
  return (
    <div className={className} aria-hidden="true">
      <Suspense fallback={null}>
        <HashField reg={reg} cur={cur} />
      </Suspense>
    </div>
  );
}

/** Displays SHA-256 hash with copy button and verification flag */
function HashDisplay({ hash, label = "SHA-256", serverHash, className = "" }) {
  const [copied, setCopied] = useState(false);
  if (!hash) return null;

  const mismatch = serverHash && serverHash !== hash;

  async function copy() {
    await navigator.clipboard.writeText(hash).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }

  return (
    <div className={`space-y-1.5 ${className}`}>
      <div className="flex items-center gap-2">
        <span className={`${tagCls} bg-ink text-bg`}>{label}</span>
        {serverHash && !mismatch && (
          <span className={`${tagCls} bg-green-600 text-white`}>✓ server confirmed</span>
        )}
        {mismatch && (
          <span className={`${tagCls} bg-red-600 text-white`}>⚠ hash mismatch</span>
        )}
      </div>
      <div className="flex items-start gap-3 bg-black/5 dark:bg-white/5 p-2.5 rounded-sm">
        <p className="break-all font-mono text-xs text-mute flex-1 leading-relaxed">{hash}</p>
        <button
          type="button"
          onClick={copy}
          className="shrink-0 text-xs font-mono text-mute hover:text-ink underline transition-colors"
          title="Copy hash to clipboard"
        >
          {copied ? "copied" : "copy"}
        </button>
      </div>
    </div>
  );
}

/** Drag-and-drop file upload zone */
function DropZone({ file, onFile, hashing, label = "Choose file" }) {
  const ref = useRef();

  const handleChange = useCallback(
    (e) => {
      const f = e.target.files?.[0];
      if (f) onFile(f);
    },
    [onFile]
  );

  const handleDrop = useCallback(
    (e) => {
      e.preventDefault();
      const f = e.dataTransfer.files?.[0];
      if (f) onFile(f);
    },
    [onFile]
  );

  return (
    <div
      role="button"
      tabIndex={0}
      aria-label="File drop zone"
      className="flex cursor-pointer flex-col items-center justify-center gap-2 border-2 border-dashed border-rule py-8 px-4 hover:border-ink transition-colors focus-visible:outline-2 focus-visible:outline-ink text-center"
      onClick={() => ref.current?.click()}
      onKeyDown={(e) => e.key === "Enter" && ref.current?.click()}
      onDrop={handleDrop}
      onDragOver={(e) => e.preventDefault()}
    >
      <input ref={ref} type="file" className="sr-only" onChange={handleChange} />
      {hashing ? (
        <div className="flex flex-col items-center gap-2 text-mute py-2">
          <Spinner size={6} />
          <p className="text-sm font-mono">Computing SHA-256 fingerprint…</p>
        </div>
      ) : file ? (
        <div className="space-y-1">
          <p className="font-semibold text-sm truncate max-w-[280px]">{file.name}</p>
          <p className="text-xs text-mute font-mono">
            {(file.size / 1024).toFixed(1)} KB · {file.type || "binary"}
          </p>
          <p className="text-[0.7rem] text-mute pt-1">Click to replace file</p>
        </div>
      ) : (
        <div className="space-y-2 text-mute">
          <p className="text-3xl leading-none">↑</p>
          <p className="text-sm font-medium">{label} or drag here</p>
          <p className="text-[0.7rem]">Fingerprint calculated locally with SHA-256</p>
        </div>
      )}
    </div>
  );
}

// ─── COLUMN 1: REGISTER FILE (Company ID & Password) ──────────────────────────

function RegisterColumn({ company, token, onLogin, onLogout }) {
  // Auth state within column
  const [authMode, setAuthMode] = useState("login"); // 'login' | 'new_company'
  const [companyId, setCompanyId] = useState("");
  const [companyName, setCompanyName] = useState("");
  const [password, setPassword] = useState("");
  const [authLoading, setAuthLoading] = useState(false);
  const [authMsg, setAuthMsg] = useState("");

  // File registration state
  const [file, setFile] = useState(null);
  const [clientHash, setClientHash] = useState("");
  const [hashing, setHashing] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [regResult, setRegResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");

  const handleFile = useCallback(async (f) => {
    setFile(f);
    setRegResult(null);
    setErrorMsg("");
    setClientHash("");
    setHashing(true);
    const h = await sha256File(f);
    setClientHash(h);
    setHashing(false);
  }, []);

  // Quick helper to fill demo credentials
  function fillDemo(id, pw) {
    setCompanyId(id);
    setPassword(pw);
    setErrorMsg("");
    setAuthMsg("");
  }

  // Handle explicit sign in or registration of new company
  async function handleCompanyAuth(e) {
    e.preventDefault();
    setAuthLoading(true);
    setAuthMsg("");
    setErrorMsg("");

    try {
      if (authMode === "login") {
        const data = await requestApi("/company/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ company_id: companyId, password }),
        });
        onLogin(data);
        setAuthMsg("✓ Signed in successfully");
      } else {
        const data = await requestApi("/company/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            company_id: companyId,
            name: companyName || companyId,
            password,
          }),
        });
        onLogin(data);
        setAuthMsg("✓ Company account created and signed in");
      }
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setAuthLoading(false);
    }
  }

  // Handle Registering file on blockchain
  async function handleRegisterFile(e) {
    e.preventDefault();
    if (!file) return;

    // Check if company credentials are ready
    if (!company && (!companyId.trim() || !password)) {
      setErrorMsg("Please enter your Company ID and Password to register files.");
      return;
    }

    setSubmitting(true);
    setErrorMsg("");
    setAuthMsg("");

    const form = new FormData();
    form.append("file", file);

    // If not authenticated via token, attach credentials directly to multipart body
    if (!token) {
      form.append("company_id", companyId.trim().toUpperCase());
      form.append("password", password);
    }

    try {
      const headers = {};
      if (token) headers.Authorization = `Bearer ${token}`;

      const data = await requestApi("/register", {
        method: "POST",
        headers,
        body: form,
      });

      setRegResult(data);

      // If registered with inline credentials and not yet logged in, auto-save company
      if (!company && data.registered_by) {
        onLogin({
          token: "",
          company_id: data.registered_by,
          name: data.registered_by,
        });
      }
    } catch (err) {
      if (err.status === 409) {
        setErrorMsg(
          `Already registered — Block #${err.details?.block_index} by ${err.details?.company_id}`
        );
      } else {
        setErrorMsg(err.message);
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="border border-ink bg-bg p-6 lg:p-8 flex flex-col justify-between h-full">
      <div>
        <div className="flex items-center justify-between mb-2">
          <span className={`${tagCls} bg-ink text-bg`}>Company Portal</span>
          <span className="text-xs font-mono text-mute">Mint to Blockchain</span>
        </div>
        <h2 className={h2cls}>Register Original File</h2>
        <p className="text-sm text-mute mb-6">
          Reserved exclusively for verified companies. Enter company credentials to record the
          SHA-256 fingerprint into the immutable ledger.
        </p>

        {/* Company Authentication State / Form */}
        {company ? (
          <div className="mb-6 border border-rule p-4 bg-black/5 dark:bg-white/5 flex items-center justify-between">
            <div>
              <p className="text-xs text-mute uppercase tracking-widest font-mono">Authenticated</p>
              <p className="font-semibold text-sm">
                {company.name}{" "}
                <span className="font-mono text-xs text-mute font-normal">({company.company_id})</span>
              </p>
            </div>
            <button
              type="button"
              onClick={onLogout}
              className="text-xs font-mono text-mute hover:text-ink underline"
            >
              Change ID
            </button>
          </div>
        ) : (
          <div className="mb-6 border border-rule p-4 bg-black/[0.02] dark:bg-white/[0.02]">
            <div className="flex items-center justify-between border-b border-rule pb-2 mb-4">
              <span className="text-xs font-mono font-semibold uppercase tracking-wider">
                {authMode === "login" ? "Company Credentials" : "Create Company ID"}
              </span>
              <button
                type="button"
                className="text-xs text-mute hover:text-ink underline"
                onClick={() => {
                  setAuthMode((m) => (m === "login" ? "new_company" : "login"));
                  setErrorMsg("");
                  setAuthMsg("");
                }}
              >
                {authMode === "login" ? "+ Register New Company" : "Back to Sign In"}
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <label className="block text-[0.65rem] uppercase tracking-widest text-mute mb-1">
                  Company ID
                </label>
                <input
                  className={inputCls}
                  placeholder="e.g. CORP001"
                  value={companyId}
                  onChange={(e) => setCompanyId(e.target.value.toUpperCase())}
                  required
                />
              </div>

              {authMode === "new_company" && (
                <div>
                  <label className="block text-[0.65rem] uppercase tracking-widest text-mute mb-1">
                    Company Name
                  </label>
                  <input
                    className={inputCls}
                    placeholder="e.g. Acme Media Corp"
                    value={companyName}
                    onChange={(e) => setCompanyName(e.target.value)}
                  />
                </div>
              )}

              <div>
                <label className="block text-[0.65rem] uppercase tracking-widest text-mute mb-1">
                  Password
                </label>
                <input
                  type="password"
                  className={inputCls}
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>

              {/* Demo auto-fill helpers */}
              {authMode === "login" && (
                <div className="pt-1 flex flex-wrap items-center gap-1.5 text-[0.7rem] text-mute">
                  <span>Demo IDs:</span>
                  {[
                    ["CORP001", "pass1234"],
                    ["CORP002", "secure99"],
                    ["CORP003", "verify42"],
                  ].map(([id, pw]) => (
                    <button
                      key={id}
                      type="button"
                      onClick={() => fillDemo(id, pw)}
                      className="font-mono underline hover:text-ink"
                    >
                      {id}
                    </button>
                  ))}
                </div>
              )}

              <button
                type="button"
                onClick={handleCompanyAuth}
                disabled={authLoading || !companyId.trim() || !password}
                className={btnAlt + " w-full text-xs py-2 mt-2"}
              >
                {authLoading ? (
                  <Spinner size={3} />
                ) : authMode === "login" ? (
                  "Verify & Sign In"
                ) : (
                  "Create Company Account"
                )}
              </button>
            </div>
          </div>
        )}

        {/* File Dropzone */}
        <form onSubmit={handleRegisterFile} className="space-y-4">
          <DropZone file={file} onFile={handleFile} hashing={hashing} label="Choose original file" />

          {/* Client SHA-256 fingerprint */}
          {clientHash && (
            <HashDisplay
              hash={clientHash}
              label="SHA-256 (client)"
              serverHash={regResult?.file_hash}
            />
          )}

          {authMsg && (
            <p className="text-xs text-green-600 bg-green-50 dark:bg-green-950/30 p-2.5 font-mono">
              {authMsg}
            </p>
          )}

          {errorMsg && (
            <div className="text-xs text-red-600 border border-red-300 bg-red-50 dark:bg-red-950/30 p-3 leading-relaxed">
              {errorMsg}
            </div>
          )}

          {/* Registration Result Card */}
          {regResult && (
            <div className="border border-green-600 bg-green-50 dark:bg-green-950/30 p-4 space-y-2.5 text-xs">
              <p className="font-semibold text-green-700 dark:text-green-400 text-sm">
                ✓ Successfully Minted to Blockchain
              </p>
              <div className="space-y-1 font-mono text-mute">
                <p>
                  <span className="text-ink font-semibold">Block #:</span>{" "}
                  {regResult.block.block_index}
                </p>
                <p>
                  <span className="text-ink">Registered by:</span> {regResult.block.company_id}
                </p>
                <p>
                  <span className="text-ink">Timestamp:</span> {regResult.block.timestamp}
                </p>
                <p>
                  <span className="text-ink">PoW Nonce:</span> {regResult.block.nonce}
                </p>
                <p className="break-all">
                  <span className="text-ink">Block Hash:</span> {regResult.block.block_hash}
                </p>
              </div>
            </div>
          )}

          <button
            type="submit"
            disabled={!file || hashing || submitting}
            className={btn + " w-full mt-4"}
          >
            {submitting ? (
              <>
                <Spinner /> Mining Block (PoW)…
              </>
            ) : (
              "Register File on Blockchain (SHA-256)"
            )}
          </button>
        </form>
      </div>
    </div>
  );
}

// ─── COLUMN 2: UPLOAD & VERIFY (Everyone Else) ────────────────────────────────

function VerifyColumn() {
  const [file, setFile] = useState(null);
  const [uploader, setUploader] = useState("");
  const [clientHash, setClientHash] = useState("");
  const [hashing, setHashing] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verResult, setVerResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");

  const handleFile = useCallback(async (f) => {
    setFile(f);
    setVerResult(null);
    setErrorMsg("");
    setClientHash("");
    setHashing(true);
    const h = await sha256File(f);
    setClientHash(h);
    setHashing(false);
  }, []);

  async function handleVerify(e) {
    e.preventDefault();
    if (!file) return;

    setVerifying(true);
    setErrorMsg("");

    const form = new FormData();
    form.append("file", file);
    if (uploader.trim()) form.append("uploader", uploader.trim());

    try {
      const data = await requestApi("/upload", {
        method: "POST",
        body: form,
      });
      setVerResult(data);
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setVerifying(false);
    }
  }

  const serverHash = verResult?.file_hash ?? null;

  return (
    <div className="border border-rule bg-bg p-6 lg:p-8 flex flex-col justify-between h-full">
      <div>
        <div className="flex items-center justify-between mb-2">
          <span className={`${tagCls} bg-rule text-ink`}>Public Access</span>
          <span className="text-xs font-mono text-mute">Verify Any Copy</span>
        </div>
        <h2 className={h2cls}>Upload & Verify File</h2>
        <p className="text-sm text-mute mb-6">
          Open to everyone. No login or password required. Upload any copy to test whether its
          SHA-256 matches an original registered on the chain.
        </p>

        <form onSubmit={handleVerify} className="space-y-4">
          <div>
            <label className="block text-[0.65rem] uppercase tracking-widest text-mute mb-1">
              Your Name or Reference <span className="normal-case">(optional)</span>
            </label>
            <input
              className={inputCls}
              placeholder="Anonymous Auditor"
              value={uploader}
              onChange={(e) => setUploader(e.target.value)}
            />
          </div>

          <DropZone file={file} onFile={handleFile} hashing={hashing} label="Choose copy to verify" />

          {/* Client SHA-256 fingerprint */}
          {clientHash && (
            <HashDisplay
              hash={clientHash}
              label="SHA-256 (client)"
              serverHash={serverHash}
            />
          )}

          {errorMsg && (
            <div className="text-xs text-red-600 border border-red-300 bg-red-50 dark:bg-red-950/30 p-3">
              {errorMsg}
            </div>
          )}

          {/* Verification Result Breakdown */}
          {verResult && (
            <div className="space-y-3 pt-2">
              <div
                className={`p-4 text-white ${
                  verResult.verdict === "AUTHENTIC"
                    ? "bg-green-700"
                    : verResult.verdict === "SUSPICIOUS"
                    ? "bg-yellow-600"
                    : "bg-red-700"
                }`}
              >
                <div className="flex items-center gap-2 text-base font-semibold">
                  <span>
                    {verResult.verdict === "AUTHENTIC"
                      ? "✓ Authentic & Registered"
                      : verResult.verdict === "SUSPICIOUS"
                      ? "⚠ Registered — AI Flags Manipulation"
                      : "✗ Not Registered on Blockchain"}
                  </span>
                </div>
                <p className="text-xs opacity-90 mt-1">
                  {verResult.is_registered
                    ? `Matching block record found in block #${verResult.block?.block_index} by ${verResult.block?.company_id}.`
                    : "This fingerprint does not match any registered block. The media may be unverified or modified."}
                </p>
              </div>

              {/* SHA-256 Match Confirmation */}
              <div className="bg-black/5 dark:bg-white/5 p-3 text-xs font-mono space-y-1.5">
                <p className="font-sans text-[0.6rem] uppercase tracking-widest text-mute">
                  SHA-256 Cryptographic Match
                </p>
                <div className="flex gap-2">
                  <span className="text-mute shrink-0 w-14">Browser:</span>
                  <span className="break-all">{clientHash}</span>
                </div>
                <div className="flex gap-2">
                  <span className="text-mute shrink-0 w-14">Server:</span>
                  <span className="break-all">{serverHash}</span>
                </div>
                <p
                  className={`font-sans text-[0.65rem] pt-1 ${
                    clientHash === serverHash ? "text-green-600" : "text-red-600"
                  }`}
                >
                  {clientHash === serverHash
                    ? "✓ Client and server SHA-256 match perfectly"
                    : "✗ Hash discrepancy detected"}
                </p>
              </div>

              {/* AI Advisory Score Meter */}
              {verResult.ai_deepfake_score != null && (
                <div className="border border-rule p-3 space-y-1.5">
                  <div className="flex justify-between items-center text-xs">
                    <span className="font-medium">AI Deepfake Advisory Score</span>
                    <span className="font-mono font-semibold">
                      {(verResult.ai_deepfake_score * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="h-1.5 bg-black/10 dark:bg-white/10 rounded-full overflow-hidden">
                    <div
                      className={`h-full transition-all ${
                        verResult.ai_deepfake_score > 0.6
                          ? "bg-red-500"
                          : verResult.ai_deepfake_score > 0.3
                          ? "bg-yellow-500"
                          : "bg-green-500"
                      }`}
                      style={{ width: `${(verResult.ai_deepfake_score * 100).toFixed(1)}%` }}
                    />
                  </div>
                  <p className="text-[0.65rem] text-mute">
                    Advisory statistical probability; does not supersede cryptographic blockchain proof.
                  </p>
                </div>
              )}
            </div>
          )}

          <button
            type="submit"
            disabled={!file || hashing || verifying}
            className={btnAlt + " w-full mt-4"}
          >
            {verifying ? (
              <>
                <Spinner /> Querying Chain…
              </>
            ) : (
              "Verify File (SHA-256)"
            )}
          </button>
        </form>
      </div>
    </div>
  );
}

// ─── Blockchain Explorer ──────────────────────────────────────────────────────

function ChainExplorer() {
  const [blocks, setBlocks] = useState([]);
  const [total, setTotal] = useState(0);
  const [valid, setValid] = useState(null);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [page, setPage] = useState(0);
  const PER_PAGE = 6;

  async function load(p = 0) {
    setLoading(true);
    try {
      const [chainRes, validRes] = await Promise.all([
        requestApi(`/chain?limit=${PER_PAGE}&offset=${p * PER_PAGE}`),
        requestApi("/chain/validate"),
      ]);
      setBlocks(chainRes.blocks || []);
      setTotal(chainRes.total || 0);
      setValid(validRes.valid);
      setPage(p);
    } catch {
      /* ignore if backend offline */
    } finally {
      setLoading(false);
    }
  }

  function toggle() {
    if (!open) load(0);
    setOpen((o) => !o);
  }

  return (
    <section aria-labelledby="chain-h" className={sec}>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 id="chain-h" className={h2cls}>
            Blockchain Explorer
          </h2>
          <p className="text-sm text-mute">
            Live public ledger of registered media fingerprints and proof-of-work hashes.
          </p>
        </div>
        <button onClick={toggle} className={btnAlt + " text-sm py-2 px-4"}>
          {open ? "Hide Chain" : "Explore Chain"}
        </button>
      </div>

      {open && (
        <div className="mt-6 space-y-4">
          {loading && (
            <div className="flex items-center gap-2 text-mute text-sm">
              <Spinner size={4} /> Loading ledger…
            </div>
          )}

          {valid != null && (
            <div
              className={`flex items-center gap-2 text-sm font-medium px-4 py-2 border ${
                valid
                  ? "border-green-600 text-green-700 bg-green-50 dark:bg-green-950/20"
                  : "border-red-600 text-red-700 bg-red-50 dark:bg-red-950/20"
              }`}
            >
              {valid ? "✓" : "✗"}{" "}
              {valid
                ? `Cryptographic chain integrity valid — ${total} block${total !== 1 ? "s" : ""}`
                : "Chain integrity FAILED — block tampering detected"}
            </div>
          )}

          <div className="grid gap-3 md:grid-cols-2">
            {blocks.map((b) => (
              <div key={b.block_index} className="border border-rule p-4 text-xs space-y-1.5 font-mono">
                <div className="flex items-baseline justify-between gap-3 font-sans">
                  <span className="font-semibold text-sm">
                    Block #{b.block_index}
                    {b.file_name === "GENESIS" && (
                      <span className="ml-2 text-xs text-mute font-normal">(Genesis)</span>
                    )}
                  </span>
                  <span className="text-mute text-[0.7rem]">{b.timestamp}</span>
                </div>

                {b.file_name !== "GENESIS" && (
                  <>
                    <p className="text-mute truncate">
                      File: <span className="text-ink">{b.file_name}</span>
                    </p>
                    <p className="text-mute">
                      Company: <span className="text-ink font-semibold">{b.company_id}</span>
                    </p>
                    <p className="break-all text-mute">
                      File SHA-256: <span className="text-ink">{b.file_hash}</span>
                    </p>
                  </>
                )}

                <p className="break-all text-mute">
                  Block Hash: <span className="text-ink">{b.block_hash}</span>
                </p>
                {b.nonce > 0 && <p className="text-mute">PoW Nonce: {b.nonce}</p>}
              </div>
            ))}
          </div>

          {total > PER_PAGE && (
            <div className="flex items-center gap-4 text-sm pt-2">
              <button
                onClick={() => load(page - 1)}
                disabled={page === 0 || loading}
                className={btnAlt + " py-1.5 px-3 text-xs"}
              >
                ← Newer
              </button>
              <span className="text-mute text-xs">
                {page * PER_PAGE + 1}–{Math.min((page + 1) * PER_PAGE, total)} of {total}
              </span>
              <button
                onClick={() => load(page + 1)}
                disabled={(page + 1) * PER_PAGE >= total || loading}
                className={btnAlt + " py-1.5 px-3 text-xs"}
              >
                Older →
              </button>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

// ─── SHA-256 Live Demo ────────────────────────────────────────────────────────

function DemoSection() {
  const [text, setText] = useState(ORIGINAL);
  const [regHash, setRegHash] = useState("");
  const [regShown, setRegShown] = useState("");
  const [curHash, setCurHash] = useState("");
  const [unsupported, setUnsupported] = useState(false);

  useEffect(() => {
    let cancelled = false,
      raf;
    sha256Text(ORIGINAL).then((h) => {
      if (cancelled) return;
      if (!h) {
        setUnsupported(true);
        return;
      }
      setRegHash(h);
      if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
        setRegShown(h);
        return;
      }
      const start = performance.now();
      const tick = (now) => {
        const p = Math.min(1, (now - start) / 900);
        const settled = Math.floor(p * h.length);
        setRegShown(
          h.split("").map((c, i) => (i < settled ? c : HEX[Math.floor(Math.random() * 16)])).join("")
        );
        if (p < 1) raf = requestAnimationFrame(tick);
        else setRegShown(h);
      };
      raf = requestAnimationFrame(tick);
    });
    return () => {
      cancelled = true;
      cancelAnimationFrame(raf);
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    sha256Text(text).then((h) => {
      if (!cancelled) setCurHash(h);
    });
    return () => {
      cancelled = true;
    };
  }, [text]);

  const ready = regHash !== "" && curHash !== "";
  const changed = ready && curHash !== regHash;
  const matching = ready ? Array.from(curHash).filter((c, i) => c === regHash[i]).length : 64;

  return (
    <section id="demo" aria-labelledby="demo-h" className="mt-[clamp(5rem,14vw,10rem)] border-t border-ink pt-5">
      <h2 id="demo-h" className={h2cls}>
        Interactive Demo — SHA-256 Fingerprint
      </h2>
      <div className="grid gap-10 lg:grid-cols-[1fr_minmax(0,400px)]">
        <div>
          <label htmlFor="src" className="mb-2 block text-mute text-sm">
            Edit this text. Notice that changing even a single character alters the entire 64-character SHA-256 hash.
          </label>
          <textarea
            id="src"
            rows={2}
            spellCheck={false}
            value={text}
            onChange={(e) => setText(e.target.value)}
            className="w-full resize-none rounded-none border-b border-ink bg-transparent pb-3 pt-1 text-[clamp(1.4rem,3.4vw,2.25rem)] font-medium leading-[1.15] tracking-[-0.025em] text-ink"
          />

          <div className="mt-8">
            <p className="mb-1 text-mute text-xs uppercase tracking-widest font-mono">
              Registered SHA-256 Fingerprint
            </p>
            {unsupported ? (
              <div className="font-mono text-sm">SHA-256 not supported in this browser.</div>
            ) : (
              <Hash value={regShown} label="Registered fingerprint" />
            )}
          </div>

          <div className="mt-8">
            <p className="mb-1 text-mute text-xs uppercase tracking-widest font-mono">
              Current SHA-256 Fingerprint
            </p>
            <Hash value={curHash} reference={regHash} label="Current fingerprint" />
          </div>

          <div
            role="status"
            aria-live="polite"
            className={`mt-8 flex flex-wrap items-baseline justify-between gap-4 border border-ink px-[1.4rem] py-[1.1rem] text-[clamp(1.5rem,5vw,3rem)] font-medium leading-none tracking-[-0.035em] ${
              changed ? "bg-ink text-bg" : ""
            }`}
          >
            <span>{changed ? "Changed" : "Unchanged"}</span>
            <small className="text-base font-normal tracking-normal">{matching} of 64 hex characters match</small>
          </div>
        </div>

        <div>
          <Scene reg={regHash} cur={curHash} className="h-[340px] lg:sticky lg:top-8 lg:h-[420px]" />
          <p className="mt-2 max-w-[22em] text-mute text-xs">
            Each cube represents one hexadecimal character of the SHA-256 hash. Altered positions drop down.
          </p>
        </div>
      </div>
    </section>
  );
}

// ─── Main App Root ────────────────────────────────────────────────────────────

export default function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem("ctoken") || "");
  const [company, setCompany] = useState(() => {
    try {
      return JSON.parse(sessionStorage.getItem("ccompany") || "null");
    } catch {
      return null;
    }
  });
  const [backendStatus, setBackendStatus] = useState("checking"); // 'checking' | 'online' | 'offline'
  const [customUrl, setCustomUrl] = useState(() => activeApiBase);
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [configTesting, setConfigTesting] = useState(false);
  const [configError, setConfigError] = useState("");

  // Probe backend on mount
  useEffect(() => {
    checkConnection();
  }, []);

  async function checkConnection(urlToTest) {
    if (urlToTest) {
      setConfiguredApiBase(urlToTest);
    }
    setBackendStatus("checking");
    try {
      await requestApi("/health");
      setBackendStatus("online");
      setConfigError("");
      return true;
    } catch (err) {
      setBackendStatus("offline");
      setConfigError(err.message);
      return false;
    }
  }

  async function handleSaveBackendUrl(e) {
    e.preventDefault();
    setConfigTesting(true);
    setConfigError("");
    const ok = await checkConnection(customUrl);
    setConfigTesting(false);
    if (ok) {
      setShowConfigModal(false);
    }
  }

  function handleLogin(data) {
    if (data.token) {
      setToken(data.token);
      sessionStorage.setItem("ctoken", data.token);
    }
    const compObj = { company_id: data.company_id, name: data.name };
    setCompany(compObj);
    sessionStorage.setItem("ccompany", JSON.stringify(compObj));
  }

  function handleLogout() {
    if (token) {
      requestApi("/company/logout", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      }).catch(() => {});
    }
    setToken("");
    setCompany(null);
    sessionStorage.removeItem("ctoken");
    sessionStorage.removeItem("ccompany");
  }

  return (
    <div className="mx-auto max-w-[1180px] px-[clamp(1.25rem,5vw,3rem)] pb-16">
      {/* Live Backend Configuration Modal */}
      {showConfigModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
          onClick={(e) => e.target === e.currentTarget && setShowConfigModal(false)}
        >
          <div className="relative w-full max-w-md border border-ink bg-bg p-6 lg:p-8 shadow-2xl">
            <button
              onClick={() => setShowConfigModal(false)}
              className="absolute right-4 top-4 text-mute hover:text-ink text-xl leading-none"
            >
              ×
            </button>
            <h3 className="text-lg font-semibold mb-1">Live Backend Connection</h3>
            <p className="text-xs text-mute mb-5 leading-relaxed">
              When deployed separately (e.g. frontend on Vercel and backend on Render), specify
              your live backend API URL.
            </p>

            <form onSubmit={handleSaveBackendUrl} className="space-y-4">
              <div>
                <label className="block text-[0.65rem] uppercase tracking-widest text-mute mb-1 font-mono">
                  Backend API URL
                </label>
                <input
                  className={inputCls}
                  placeholder="https://your-backend.onrender.com"
                  value={customUrl}
                  onChange={(e) => setCustomUrl(e.target.value)}
                  autoFocus
                />
                <p className="text-[0.7rem] text-mute mt-1.5 font-mono">
                  Current: <span className="text-ink">{activeApiBase}</span>
                </p>
              </div>

              {configError && (
                <p className="text-xs text-red-600 bg-red-50 dark:bg-red-950/30 p-2.5 leading-relaxed">
                  {configError}
                </p>
              )}

              <div className="flex gap-2 pt-2">
                <button type="submit" disabled={configTesting} className={btn + " flex-1 text-xs py-2.5"}>
                  {configTesting ? <><Spinner size={3} /> Testing Connection…</> : "Connect & Save"}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setCustomUrl("/api");
                    setConfiguredApiBase("/api");
                    checkConnection("/api");
                  }}
                  className={btnAlt + " text-xs py-2.5 px-3"}
                >
                  Reset (/api)
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Backend Connection Alert Banner */}
      {backendStatus === "offline" && (
        <div className="mt-4 border border-red-500 bg-red-50 dark:bg-red-950/30 p-4 text-xs text-red-800 dark:text-red-300">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
            <span className="font-semibold text-sm">
              ⚠ Cannot Connect to Backend API ({activeApiBase})
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => checkConnection()}
                className="underline font-mono px-2 py-1 bg-red-100 dark:bg-red-900/40 rounded hover:opacity-80"
              >
                Retry
              </button>
              <button
                onClick={() => setShowConfigModal(true)}
                className="font-mono px-2.5 py-1 bg-ink text-bg rounded hover:opacity-85 font-semibold"
              >
                Configure Backend URL
              </button>
            </div>
          </div>

          {!isLocalhost ? (
            <p className="leading-relaxed opacity-90">
              Your frontend is running live. If your backend is hosted on Render, Railway, or VPS, click{" "}
              <strong>Configure Backend URL</strong> above and paste your backend link (e.g.{" "}
              <code className="font-mono">https://my-backend.onrender.com</code>).
            </p>
          ) : (
            <p className="leading-relaxed opacity-90">
              Running locally. Ensure the backend server is running in terminal:{" "}
              <code className="font-mono bg-red-100 dark:bg-red-900/40 px-1 py-0.5">cd backend && node server.js</code>
            </p>
          )}
        </div>
      )}

      {/* Navigation Header */}
      <header className="flex flex-wrap justify-between items-center gap-4 py-7 font-medium border-b border-rule">
        <a href="#top" className="text-lg font-semibold tracking-tight hover:opacity-80">
          Media Verification <span className="font-mono text-xs text-mute font-normal">/ SHA-256</span>
        </a>
        <nav className="flex flex-wrap items-center gap-5 text-sm">
          <a href="#demo" className="hover:underline hover:underline-offset-4">
            Interactive Demo
          </a>
          <a href="#portal" className="hover:underline hover:underline-offset-4">
            Verification Portal
          </a>
          <a href="#how" className="hover:underline hover:underline-offset-4">
            Architecture
          </a>

          {/* Connection Status Pill */}
          <button
            onClick={() => setShowConfigModal(true)}
            title="Click to view or change backend API URL"
            className="inline-flex items-center gap-1.5 text-xs font-mono border border-rule px-2.5 py-1 rounded hover:border-ink transition-colors"
          >
            <span
              className={`inline-block h-2 w-2 rounded-full ${
                backendStatus === "online"
                  ? "bg-green-500 animate-pulse"
                  : backendStatus === "checking"
                  ? "bg-yellow-500"
                  : "bg-red-500"
              }`}
            />
            <span>{backendStatus === "online" ? "API Live" : "API Offline"}</span>
          </button>

          {company && (
            <div className="flex items-center gap-3">
              <span className="text-xs font-mono bg-black/5 dark:bg-white/5 px-2.5 py-1">
                {company.company_id}
              </span>
              <button onClick={handleLogout} className="text-xs text-mute hover:text-ink underline">
                Sign Out
              </button>
            </div>
          )}
        </nav>
      </header>

      <main id="top">
        {/* Hero Section */}
        <div className="grid items-center gap-8 lg:grid-cols-[1.2fr_1fr] pt-6">
          <div>
            <h1 className="mb-6 mt-[clamp(2rem,5vw,4.5rem)] text-[clamp(2.5rem,6.5vw,5.5rem)] font-medium leading-[0.96] tracking-[-0.04em]">
              Prove a file hasn't changed.
            </h1>
            <p className="mb-8 max-w-[34em] text-[clamp(1.1rem,2vw,1.4rem)] leading-[1.4] text-mute">
              Register original media with SHA-256 on an immutable blockchain ledger. Anyone can
              verify any copy anywhere in seconds.
            </p>
            <div className="flex flex-wrap gap-3">
              <a className={btn} href="#portal">
                Open Verification Portal
              </a>
              <a className={btnAlt} href="#demo">
                Try Live Hash Demo
              </a>
            </div>
          </div>
          <Scene reg="" cur="" className="h-[300px] lg:h-[460px]" />
        </div>

        {/* Interactive SHA-256 Demo */}
        <DemoSection />

        {/* ─── TWO DEDICATED COLUMNS: REGISTER (Company) vs UPLOAD (Everyone) ─── */}
        <section id="portal" className={sec}>
          <div className="mb-8">
            <span className={`${tagCls} bg-rule text-ink mb-2`}>Dual-Channel Access</span>
            <h2 className="text-[clamp(1.8rem,3.5vw,2.5rem)] font-medium tracking-tight">
              Blockchain Media Portal
            </h2>
            <p className="text-mute max-w-[42em] text-sm">
              Companies mint original file fingerprints using verified credentials. Everyone else
              can upload and verify any copy freely against the distributed ledger.
            </p>
          </div>

          <div className="grid lg:grid-cols-2 gap-8 items-stretch">
            {/* Column 1: Company Only with ID and Password */}
            <RegisterColumn
              company={company}
              token={token}
              onLogin={handleLogin}
              onLogout={handleLogout}
            />

            {/* Column 2: Everyone Else (Public Upload) */}
            <VerifyColumn />
          </div>
        </section>

        {/* How It Works Architecture */}
        <section id="how" className={sec}>
          <h2 className={h2cls}>How It Works</h2>
          <div className="grid gap-8 md:grid-cols-3">
            {[
              [
                "1. SHA-256 Fingerprint",
                "Every file has a unique 256-bit hash. Any edit, compression artifact, or manipulated pixel alters the hash completely.",
              ],
              [
                "2. Company Minting",
                "Authorized companies authenticate with their credentials to write the file hash, timestamp, and metadata into a proof-of-work blockchain block.",
              ],
              [
                "3. Public Verification & AI",
                "Anyone can submit a file. The system checks the blockchain ledger and provides an advisory AI deepfake score without revealing original media.",
              ],
            ].map(([title, desc]) => (
              <div key={title} className="border-t border-rule pt-4">
                <h3 className="font-semibold text-lg mb-2">{title}</h3>
                <p className="text-sm text-mute leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Blockchain Explorer Section */}
        <ChainExplorer />
      </main>

      {/* Footer */}
      <footer className="mt-[clamp(5rem,14vw,8rem)] border-t border-ink pt-6 flex flex-wrap justify-between items-center gap-4 text-xs text-mute">
        <p>Blockchain-Based Anti-Deepfake Authentication & Digital Media Verification System</p>
        <p className="font-mono">Engine: SHA-256 · Consensus: Proof-of-Work</p>
      </footer>
    </div>
  );
}
