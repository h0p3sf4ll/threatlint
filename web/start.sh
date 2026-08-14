#!/bin/bash
# Threatlint Web UI startup script
export PATH="$HOME/.nvm/versions/node/v22.22.3/bin:$PATH"
cd "$(dirname "$0")"
if [ ! -d node_modules ]; then
  echo "Installing dependencies..."
  npm install
fi
echo ""
echo "  Threatlint Web UI"
echo "  http://localhost:${PORT:-3000}"
echo ""
exec node server.js
