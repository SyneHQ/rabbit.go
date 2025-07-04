#!/bin/bash

# Example setup script for rabbit.go
# This demonstrates how to set up and test the tunnel system

echo "🚀 Syne Tunneler Example Setup"
echo "================================"

# Build the server
echo "📦 Building rabbit.go server..."
go build -o rabbit.go

if [ $? -ne 0 ]; then
    echo "❌ Failed to build server"
    exit 1
fi

echo "✅ Server built successfully"

# Build the client (syne-cli)
echo "📦 Building syne-cli client..."
cd ../syne-cli
go build -o syne-cli

if [ $? -ne 0 ]; then
    echo "❌ Failed to build client"
    exit 1
fi

echo "✅ Client built successfully"
cd ../rabbit.go

echo ""
echo "🎯 Setup Complete!"
echo ""
echo "To test the tunnel system:"
echo ""
echo "1. Start the tunnel server:"
echo "   ./rabbit.go server --bind 0.0.0.0 --port 9999 --tokens ./tokens.txt"
echo ""
echo "2. In another terminal, start a test service (e.g., a simple HTTP server):"
echo "   python3 -m http.server 8080"
echo ""
echo "3. In a third terminal, create a tunnel:"
echo "   ../syne-cli/syne-cli tunnel --server localhost:9999 --local-port 8080 --token mytoken123"
echo ""
echo "4. The server will show you the random port (e.g., 49523). Test it:"
echo "   curl http://127.0.0.1:49523"
echo ""
echo "🔥 You should see the HTTP server response through the tunnel!"
echo ""

# Create a simple test script
cat > test-tunnel.sh << 'EOF'
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
EOF

chmod +x test-tunnel.sh

echo "📝 Created test-tunnel.sh script"
echo "Usage: ./test-tunnel.sh <remote-port>"
echo ""
echo "Happy tunneling! 🎉" 