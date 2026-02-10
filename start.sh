#!/bin/bash
# ============================================================
# GhostLedger — Quick Start / Restart
# ============================================================
# Usage:
#   bash start.sh           — Start in background (recommended)
#   bash start.sh --fg      — Start in foreground (see live logs)
#   bash start.sh --stop    — Stop the server
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8081

# --stop flag
if [ "$1" = "--stop" ]; then
    echo "==> Stopping GhostLedger..."
    launchctl bootout "gui/$(id -u)/com.ghostledger.intake" 2>/dev/null
    pkill -f "uvicorn ghostledger_intake" 2>/dev/null
    lsof -ti:$PORT 2>/dev/null | xargs kill -9 2>/dev/null
    sleep 1
    if ! lsof -ti:$PORT > /dev/null 2>&1; then
        echo "✅ Server stopped."
    else
        echo "⚠️  Port $PORT still in use. Try: lsof -i:$PORT"
    fi
    exit 0
fi

# --fg flag (foreground mode)
if [ "$1" = "--fg" ]; then
    echo "==> GhostLedger (foreground mode) — Ctrl+C to stop"
    launchctl bootout "gui/$(id -u)/com.ghostledger.intake" 2>/dev/null
    pkill -f "uvicorn ghostledger_intake" 2>/dev/null
    lsof -ti:$PORT 2>/dev/null | xargs kill -9 2>/dev/null
    sleep 1
    cd "$SCRIPT_DIR"
    python3 -m uvicorn ghostledger_intake:app --host 0.0.0.0 --port $PORT
    exit 0
fi

# Default: background mode
echo "==> GhostLedger Quick Start"

# Already running?
if curl -s --max-time 2 http://localhost:$PORT/health > /dev/null 2>&1; then
    HEALTH=$(curl -s http://localhost:$PORT/health)
    echo "✅ Already running on http://localhost:$PORT"
    echo "   $HEALTH"
    echo "   To restart: bash start.sh --stop && bash start.sh"
    exit 0
fi

# Disable launchd if it's loaded (it fights background starts)
launchctl bootout "gui/$(id -u)/com.ghostledger.intake" 2>/dev/null

# Kill anything holding our port
lsof -ti:$PORT 2>/dev/null | xargs kill -9 2>/dev/null
pkill -f "uvicorn ghostledger_intake" 2>/dev/null
sleep 1

# Double-check port is free
if lsof -ti:$PORT > /dev/null 2>&1; then
    echo "   Port $PORT still busy, waiting..."
    sleep 3
    lsof -ti:$PORT 2>/dev/null | xargs kill -9 2>/dev/null
    sleep 1
fi

# Start the server
cd "$SCRIPT_DIR"
mkdir -p logs

echo "   Starting server on port $PORT..."
nohup python3 -m uvicorn ghostledger_intake:app \
    --host 0.0.0.0 --port $PORT \
    >> logs/intake.log 2>> logs/intake.err &
SERVER_PID=$!

# Wait for health check
for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    if curl -s --max-time 2 http://localhost:$PORT/health > /dev/null 2>&1; then
        HEALTH=$(curl -s http://localhost:$PORT/health)
        echo "✅ GhostLedger running — http://localhost:$PORT (PID $SERVER_PID)"
        echo "   $HEALTH"
        echo ""
        echo "   Dashboard:  http://localhost:$PORT"
        echo "   Portal:     http://localhost:$PORT/portal"
        echo "   How It Works: http://localhost:$PORT/how-it-works"
        echo "   API Docs:   http://localhost:$PORT/docs"
        echo ""
        echo "   Stop:  bash start.sh --stop"
        echo "   Logs:  tail -f logs/intake.log"
        exit 0
    fi
done

# Failed
echo "❌ Server failed to start after 10 seconds."
echo ""
echo "   Last 15 lines of error log:"
echo "   ─────────────────────────────"
tail -15 logs/intake.err 2>/dev/null || echo "   (no error log)"
echo "   ─────────────────────────────"
echo ""
echo "   Try foreground mode to see the full error:"
echo "   bash start.sh --fg"
