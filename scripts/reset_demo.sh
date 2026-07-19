#!/usr/bin/env bash
# Resets the demo to a clean state: wipes the Postgres volume (all
# submissions, verification results, quarantine entries, activity feed,
# dashboard agent records accumulated from previous sessions) and restarts
# the full docker-compose stack fresh.
#
# Deliberately does NOT touch .agent_keys/ -- those are the 4 demo agents'
# persistent Ed25519 identities and TOFU-pinned trust store. Wiping them
# would regenerate new identities every reset and break key pinning; they
# aren't "stale demo data," they're the agents' actual identity.
#
# Usage: bash scripts/reset_demo.sh
set -e

cd "$(dirname "$0")/.."

echo "Stopping stack and wiping database volume..."
docker compose down -v

echo "Rebuilding and starting fresh..."
docker compose up --build -d

echo ""
echo "Done. Waiting for the API to become healthy..."
until curl -sf http://localhost:8000/health > /dev/null 2>&1; do
    sleep 2
done
echo "API healthy. Dashboard: http://localhost:5173"
echo "Agent network takes ~15-20s after boot to start generating traffic."
