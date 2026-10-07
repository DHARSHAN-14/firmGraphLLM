#!/usr/bin/env bash
# FirmGraph-LLM — Dashboard Launcher Script
set -e

PORT=${1:-8080}
echo "=========================================================="
echo " Starting FirmGraph-LLM Visualization & Ingestion Dashboard"
echo " Web UI: http://localhost:${PORT}"
echo "=========================================================="

# Check if Neo4j container is running
if ! podman ps | grep -q "neo4j"; then
    echo "[*] Starting Neo4j container..."
    podman start neo4j-firmgraph || true
    sleep 5
fi

python3 -m uvicorn dashboard.app:app --host 0.0.0.0 --port "${PORT}"
