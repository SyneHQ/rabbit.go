#!/bin/bash

# Quick test script to verify the tunnel connection fix

echo "🧪 Testing tunnel connection fix..."

# Check if server and client are built
if [ ! -f "rabbit.go" ]; then
    echo "❌ rabbit.go not found. Run: go build -o rabbit.go"
    exit 1
fi

if [ ! -f "../syne-cli/syne-cli" ]; then
    echo "❌ syne-cli not found. Run: cd ../syne-cli && go build -o syne-cli"
    exit 1
fi

echo "✅ Binaries found"

echo ""
echo "🚀 Test Instructions:"
echo "====================="
echo ""

echo "1. Start the tunnel server (in terminal 1):"
echo "   ./rabbit.go server --port 9999 --tokens ./tokens.txt"
echo ""

echo "2. Start a test HTTP server (in terminal 2):"
echo "   python3 -m http.server 8080"
echo ""

echo "3. Create tunnel (in terminal 3):"
echo "   ../syne-cli/syne-cli tunnel --server localhost:9999 --local-port 8080 --token mytoken123"
echo ""

echo "4. Test the connection (in terminal 4):"
echo "   curl http://127.0.0.1:<tunnel-port>"
echo "   (replace <tunnel-port> with the port shown by the tunnel client)"
echo ""

echo "📋 Expected behavior:"
echo "- No 'connection reset by peer' errors"
echo "- HTTP response from local server"
echo "- Clean connection handling in logs"
echo ""

echo "🔧 Changes made to fix the EOF error:"
echo "- Simplified protocol: server sends 'DATA\\n' instead of 'CONNECT:port\\n'"
echo "- Better error handling with proper defer statements"
echo "- Improved logging to track data transfer"
echo "- Fixed race condition in control connection usage"
echo ""

echo "Happy testing! 🎉" 