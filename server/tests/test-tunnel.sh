#!/bin/bash

echo "🧪 Testing tunnel connection..."

# Check if server is running
if ! curl -s http://127.0.0.1:$1 > /dev/null; then
    echo "❌ No service found on port $1"
    echo "Make sure the tunnel is active and the port is correct"
    exit 1
fi

echo "✅ Tunnel is working! Service is accessible on port $1"
curl -s http://127.0.0.1:$1 | head -5
