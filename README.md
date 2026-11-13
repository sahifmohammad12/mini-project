# Blockchain-Based Deepfake Verification System

A full-stack media authentication platform combining client-side and server-side **SHA-256 fingerprinting**, an append-only **blockchain ledger** with proof-of-work consensus, and advisory **AI deepfake scoring**.

---

## Architecture Overview

```
                      ┌───────────────────────────────────────┐
                      │          React Frontend (Vite)        │
                      │  - SHA-256 Web Crypto API             │
                      │  - Three.js 3D Fingerprint Scene      │
                      └──────────────────┬────────────────────┘
                                         │
                    REST API (Multipart & JSON) / CORS
                                         │
                      ┌──────────────────▼────────────────────┐
                      │        Node.js / Express Backend      │
                      │  - Server-Side SHA-256 Verification   │
                      │  - Proof-of-Work Mining Engine        │
                      │  - SQLite Append-Only Blockchain      │
                      │  - Advisory AI Deepfake Score Engine  │
                      └──────────────────┬────────────────────┘
                                         │
                              node:sqlite Embedded DB
                                         │
                      ┌──────────────────▼────────────────────┐
                      │           deepfake.db                 │
                      │  - blockchain (immutable blocks)      │
                      │  - companies  (authorized minters)    │
                      │  - uploads    (audited files)         │
                      │  - verifications (audit logs)         │
                      └───────────────────────────────────────┘
```

---

## Dual-Channel Access Model

1. **Company Portal (Register Original File):**
   - Protected by **Company ID & Password** (`CORP001 / pass1234`, `CORP002 / secure99`, etc.).
   - Mints a new block to the blockchain with timestamp, company ID, and SHA-256 fingerprint.
2. **Public Access (Upload & Verify Any File):**
   - **No login or password required.** Open to everyone.
   - Compares the file's SHA-256 against the blockchain ledger.
   - Shows cryptographic match confirmation and advisory AI deepfake probability score.

---

## Local Development

```bash
# 1. Install dependencies
npm install

# 2. Run both backend & frontend
./start.sh

# Or run manually in separate terminals:
node backend/server.js   # API & DB on http://localhost:4000
npm run dev              # Web App on http://localhost:5173
```

---

## Live Deployment Guide

### Option A: Deploy Full-Stack as a Single Service (Recommended)
Best for: **Render**, **Railway**, **Fly.io**, **Heroku**, **VPS**, **Docker**

When deployed as a single service, the Express server automatically serves both the API (`/api/*`) and the built React frontend (`dist/`) on the **same domain and port**. No CORS or backend URL configuration needed!

- **Build Command:** `npm install && npm run build`
- **Start Command:** `npm start`
- **Environment Variables:** `PORT=4000` (or platform default)

---

### Option B: Deploy Separately (e.g. Frontend on Vercel, Backend on Render)

1. **Deploy Backend to Render / Railway:**
   - Build command: `cd backend && npm install`
   - Start command: `node backend/server.js`
   - Note your deployed backend URL (e.g. `https://my-backend.onrender.com`).

2. **Deploy Frontend to Vercel / Netlify:**
   - Framework preset: `Vite`
   - Root directory: `./`
   - Build command: `npm run build`
   - Output directory: `dist`
   - Environment variable (optional): `VITE_API_URL=https://my-backend.onrender.com`

3. **In-App Live Backend URL Switcher:**
   - If deployed without setting environment variables, click the **"API Status"** button in the header or the connection banner.
   - Paste your live backend URL (e.g. `https://my-backend.onrender.com`) and click **Connect & Save**.
   - The setting is saved in your browser and connects immediately!
