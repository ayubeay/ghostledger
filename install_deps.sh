#!/bin/bash
# Install Python dependencies for GhostLedger
# Run: bash ~/GhostLedger/install_deps.sh

echo "Installing GhostLedger dependencies..."
pip3 install --break-system-packages reportlab fastapi uvicorn "pydantic[email]"
echo ""
echo "✅ Dependencies installed. Restart the service:"
echo "   bash ~/GhostLedger/service.sh restart"
