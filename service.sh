#!/bin/bash
# ============================================================
# GhostLedger Intake — macOS Service Manager
# ============================================================
# Usage:
#   bash service.sh install    — Install & start the service
#   bash service.sh uninstall  — Stop & remove the service
#   bash service.sh start      — Start the service
#   bash service.sh stop       — Stop the service
#   bash service.sh restart    — Restart the service
#   bash service.sh status     — Check if it's running
#   bash service.sh logs       — Tail the live logs
# ============================================================

LABEL="com.ghostledger.intake"
PLIST_SRC="$(cd "$(dirname "$0")" && pwd)/com.ghostledger.intake.plist"
PLIST_DST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG_DIR="$HOME/GhostLedger/logs"

case "$1" in

install)
    echo "==> Installing GhostLedger service..."
    mkdir -p "$LOG_DIR"
    # Stop if already loaded
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null
    # Copy plist to LaunchAgents
    cp "$PLIST_SRC" "$PLIST_DST"
    # Load and start
    launchctl bootstrap "gui/$(id -u)" "$PLIST_DST"
    sleep 2
    if curl -s http://localhost:8081/health > /dev/null 2>&1; then
        echo "✅ GhostLedger intake server is running on port 8081"
        echo "   Logs: $LOG_DIR/intake.log"
        echo "   It will auto-start on login and restart if it crashes."
    else
        echo "⚠️  Service loaded but health check failed. Check logs:"
        echo "   tail -f $LOG_DIR/intake.err"
    fi
    ;;

uninstall)
    echo "==> Uninstalling GhostLedger service..."
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null
    rm -f "$PLIST_DST"
    echo "✅ Service removed. Server is stopped."
    ;;

start)
    echo "==> Starting GhostLedger service..."
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    mkdir -p "$LOG_DIR"

    # Check if already running
    if curl -s --max-time 2 http://localhost:8081/health > /dev/null 2>&1; then
        echo "✅ Server is already running on port 8081"
        exit 0
    fi

    # Try launchctl
    launchctl kickstart "gui/$(id -u)/$LABEL" 2>/dev/null
    sleep 2
    if curl -s --max-time 2 http://localhost:8081/health > /dev/null 2>&1; then
        echo "✅ Server is running on port 8081"
    else
        # Direct start fallback
        echo "   launchctl unavailable; starting directly..."
        cd "$SCRIPT_DIR"
        nohup python3 -m uvicorn ghostledger_intake:app --host 0.0.0.0 --port 8081 \
            >> "$LOG_DIR/intake.log" 2>> "$LOG_DIR/intake.err" &
        sleep 3
        if curl -s --max-time 2 http://localhost:8081/health > /dev/null 2>&1; then
            echo "✅ Server running on port 8081 (direct mode)"
        else
            echo "⚠️  Failed to start. Check: tail -20 $LOG_DIR/intake.err"
            echo "   Or start manually: cd $SCRIPT_DIR && python3 -m uvicorn ghostledger_intake:app --host 0.0.0.0 --port 8081"
        fi
    fi
    ;;

stop)
    echo "==> Stopping GhostLedger service..."
    launchctl kill SIGTERM "gui/$(id -u)/$LABEL" 2>/dev/null
    echo "✅ Server stopped. (It will restart automatically — use 'uninstall' to fully remove)"
    ;;

restart)
    echo "==> Restarting GhostLedger service..."
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    mkdir -p "$LOG_DIR"

    # Kill any stale processes on port 8081 and by name
    pkill -f "uvicorn ghostledger_intake" 2>/dev/null
    lsof -ti:8081 | xargs kill -9 2>/dev/null
    sleep 2

    # Try launchctl first
    launchctl kickstart -k "gui/$(id -u)/$LABEL" 2>/dev/null
    OK=0
    for i in 1 2 3 4 5; do
        sleep 1
        if curl -s --max-time 2 http://localhost:8081/health > /dev/null 2>&1; then
            OK=1; break
        fi
    done
    if [ "$OK" -eq 1 ]; then
        echo "✅ Server restarted on port 8081"
    else
        # Fallback: start directly
        echo "   launchctl didn't respond; starting directly..."
        cd "$SCRIPT_DIR"
        nohup python3 -m uvicorn ghostledger_intake:app --host 0.0.0.0 --port 8081 \
            >> "$LOG_DIR/intake.log" 2>> "$LOG_DIR/intake.err" &
        DIRECT_PID=$!
        # Wait up to 8 seconds for it to come up
        OK2=0
        for j in 1 2 3 4 5 6 7 8; do
            sleep 1
            if curl -s --max-time 2 http://localhost:8081/health > /dev/null 2>&1; then
                OK2=1; break
            fi
        done
        if [ "$OK2" -eq 1 ]; then
            echo "✅ Server running on port 8081 (direct mode, PID $DIRECT_PID)"
        else
            echo "⚠️  Server failed to start. Check error log:"
            echo "   tail -20 $LOG_DIR/intake.err"
            echo ""
            echo "   Or start manually:"
            echo "   cd $SCRIPT_DIR && python3 -m uvicorn ghostledger_intake:app --host 0.0.0.0 --port 8081"
        fi
    fi
    ;;

status)
    if curl -s http://localhost:8081/health > /dev/null 2>&1; then
        HEALTH=$(curl -s http://localhost:8081/health)
        echo "✅ GhostLedger intake server is RUNNING"
        echo "   $HEALTH"
    else
        echo "❌ Server is NOT responding on port 8081"
        # Check if launchd has it loaded
        if launchctl print "gui/$(id -u)/$LABEL" > /dev/null 2>&1; then
            echo "   (Service is loaded in launchd but not responding)"
            echo "   Check: tail -20 $LOG_DIR/intake.err"
        else
            echo "   (Service is not installed — run: bash service.sh install)"
        fi
    fi
    ;;

logs)
    echo "==> Tailing GhostLedger logs (Ctrl+C to stop)..."
    tail -f "$LOG_DIR/intake.log" "$LOG_DIR/intake.err"
    ;;

*)
    echo "GhostLedger Service Manager"
    echo ""
    echo "Usage: bash service.sh {install|uninstall|start|stop|restart|status|logs}"
    echo ""
    echo "  install    Install & start (runs on login, auto-restarts)"
    echo "  uninstall  Stop & remove completely"
    echo "  start      Start the service"
    echo "  stop       Stop (will auto-restart — use uninstall to fully stop)"
    echo "  restart    Restart the service"
    echo "  status     Check if server is running"
    echo "  logs       Tail live logs"
    ;;

esac
