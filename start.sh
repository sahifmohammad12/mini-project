#!/usr/bin/env bash
# start.sh — start both the backend API and the Vite dev server

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "🔗 Starting backend (http://localhost:4000)..."
cd "$ROOT/backend" && node server.js &
BACKEND_PID=$!

echo "⚡ Starting frontend (http://localhost:5173)..."
cd "$ROOT" && npm run dev &
FRONTEND_PID=$!

echo ""
echo "  Backend  → http://localhost:4000"
echo "  Frontend → http://localhost:5173"
echo ""
echo "Press Ctrl+C to stop both."

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM
wait

