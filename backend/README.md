# Blockchain-Based Deepfake Verification System — Backend

A Node.js / Express REST API that powers the deepfake verification platform. It simulates a blockchain ledger using SQLite with proof-of-work mining and provides endpoints for company registration, file hashing, and AI-advisory deepfake scoring.

## Architecture

```
backend/
├── server.js    ← Express API (all routes)
├── db.js        ← SQLite layer + blockchain logic
├── data/        ← Auto-created; holds deepfake.db
└── package.json
```

## Quickstart

```bash
cd backend
npm install
npm start        # → http://localhost:4000
```

For development with auto-reload:
```bash
npm run dev      # requires nodemon (installed as devDependency)
```

## Demo Company Credentials

| Company ID | Password  | Name             |
|------------|-----------|------------------|
| CORP001    | pass1234  | MediaCorp Inc.   |
| CORP002    | secure99  | TrustMedia Ltd.  |
| CORP003    | verify42  | VerifyPress Co.  |

## API Reference

### Auth
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/company/login` | Login with `{ company_id, password }` → returns `{ token }` |
| `POST` | `/api/company/logout` | Invalidate token (Bearer auth required) |
| `GET`  | `/api/company/list` | List all registered companies (public) |

### Register (Company Only)
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/register` | Upload a file (multipart `file` field). Bearer token required. Mines a new block. |

### Verify (Anyone)
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/upload` | Upload a file (multipart `file` + optional `uploader`). Returns verdict + AI score. |
| `GET`  | `/api/verify/:hash` | Verify a SHA-256 hash directly (no file needed). |

### Blockchain Explorer
| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/chain` | Paginated block list (`?limit=20&offset=0`) |
| `GET`  | `/api/chain/length` | Total block count |
| `GET`  | `/api/chain/validate` | Verify chain integrity (hash linkage + PoW) |
| `GET`  | `/api/health` | Health check |

## Blockchain Design

- Each registered file creates a new **block** linked to the previous block's hash (SHA-256).
- A simple **Proof of Work** (difficulty = 2 leading zeros) is performed for each block.
- The SQLite `blockchain` table is append-only by design — no UPDATE/DELETE is used.
- Chain integrity is verifiable at any time via `/api/chain/validate`.

## AI Deepfake Score

The advisory score (0.0–1.0) is currently a deterministic pseudo-random value seeded by the file hash. In production, replace this with a call to a real deepfake detection model (e.g., a CNN trained on FaceForensics++).

The score is **always advisory** — it never overrides the blockchain integrity result.

