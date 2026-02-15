#!/bin/bash
# ============================================================
# GhostLedger — Cloud Deployment Script
# ============================================================
# Usage:
#   bash deploy.sh railway   — Deploy to Railway
#   bash deploy.sh fly       — Deploy to Fly.io
#   bash deploy.sh render    — Deploy to Render
#   bash deploy.sh docker    — Build & run locally with Docker
#   bash deploy.sh keygen    — Generate a secure API key
# ============================================================

set -e
cd "$(dirname "$0")"

case "$1" in

keygen)
    KEY="gl_live_sk_$(openssl rand -hex 20)"
    echo "==> Generated API key:"
    echo ""
    echo "    $KEY"
    echo ""
    echo "Set this as INTAKE_API_KEY in your environment."
    echo "To require auth: set REQUIRE_AUTH=true"
    ;;

railway)
    echo "==> Deploying to Railway..."
    if ! command -v railway &>/dev/null; then
        echo "Install Railway CLI: npm install -g @railway/cli"
        echo "Then: railway login"
        exit 1
    fi
    # Initialize git if needed
    if [ ! -d .git ]; then
        git init
        git add ghostledger_intake.py GhostLedger.html requirements.txt Dockerfile .dockerignore railway.json
        git commit -m "GhostLedger deployment"
    fi
    railway up
    echo ""
    echo "==> Deployed! Run 'railway open' to see your live URL."
    echo "    Your dashboard will be at: https://your-app.railway.app"
    ;;

fly)
    echo "==> Deploying to Fly.io..."
    if ! command -v flyctl &>/dev/null; then
        echo "Install Fly CLI: curl -L https://fly.io/install.sh | sh"
        echo "Then: fly auth login"
        exit 1
    fi
    # Create app if first deploy
    if ! fly status &>/dev/null 2>&1; then
        fly launch --no-deploy --name ghostledger --region iad
        fly volumes create gl_data --size 1 --region iad
    fi
    fly deploy
    echo ""
    echo "==> Deployed! Your dashboard is at: https://ghostledger.fly.dev"
    ;;

render)
    echo "==> Render deployment..."
    echo ""
    echo "Render deploys via GitHub. Steps:"
    echo "  1. Push this folder to a GitHub repo"
    echo "  2. Go to https://dashboard.render.com"
    echo "  3. New > Web Service > Connect your repo"
    echo "  4. It will auto-detect render.yaml"
    echo "  5. Click Deploy"
    echo ""
    echo "Or use Render CLI: render deploy"
    ;;

docker)
    echo "==> Building Docker image..."
    docker build -t ghostledger .
    echo "==> Running on port 8081..."
    docker run -d \
        --name ghostledger \
        -p 8081:8081 \
        -v ghostledger-data:/data \
        --restart unless-stopped \
        ghostledger
    echo ""
    echo "==> Running at http://localhost:8081"
    echo "    Data persisted in Docker volume: ghostledger-data"
    echo "    Stop:  docker stop ghostledger"
    echo "    Logs:  docker logs -f ghostledger"
    ;;

*)
    echo "GhostLedger Cloud Deployment"
    echo ""
    echo "Usage: bash deploy.sh {railway|fly|render|docker|keygen}"
    echo ""
    echo "  railway  Deploy to Railway (easiest, free tier)"
    echo "  fly      Deploy to Fly.io (good free tier, persistent disk)"
    echo "  render   Deploy to Render (GitHub-based, auto-deploy)"
    echo "  docker   Build & run locally with Docker"
    echo "  keygen   Generate a secure API key"
    echo ""
    echo "Prerequisites:"
    echo "  railway: npm install -g @railway/cli && railway login"
    echo "  fly:     curl -L https://fly.io/install.sh | sh && fly auth login"
    echo "  docker:  Install Docker Desktop for Mac"
    ;;

esac
