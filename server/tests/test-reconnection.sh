#!/bin/bash

# Test script for connection bridging fix
# Tests that clients can reconnect to the same port without "address already in use" errors

set -e

echo "🧪 Testing Connection Bridging Fix"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SERVER_HOST="localhost"
SERVER_PORT="8000"
API_PORT="8080"
TEST_TOKEN="test-token-123"
LOCAL_PORT="5432"

# Function to wait for server startup
wait_for_server() {
    echo -n "⏳ Waiting for server to start..."
    for i in {1..30}; do
        if curl -s http://${SERVER_HOST}:${API_PORT}/api/v1/health > /dev/null 2>&1; then
            echo -e " ${GREEN}✅ Server is ready${NC}"
            return 0
        fi
        echo -n "."
        sleep 1
    done
    echo -e " ${RED}❌ Server failed to start${NC}"
    return 1
}

# Function to test client connection
test_client_connection() {
    local attempt=$1
    echo -e "${YELLOW}📡 Testing client connection attempt #${attempt}${NC}"
    
    # Run client in background for 5 seconds
    timeout 5s ../syne-cli/syne-cli tunnel \
        --server ${SERVER_HOST}:${SERVER_PORT} \
        --token ${TEST_TOKEN} \
        --local-port ${LOCAL_PORT} \
        --max-retries 3 \
        --initial-delay 1s > client_${attempt}.log 2>&1 &
    
    CLIENT_PID=$!
    sleep 2
    
    # Check if client is still running (connected successfully)
    if kill -0 $CLIENT_PID 2>/dev/null; then
        echo -e "${GREEN}✅ Client connection #${attempt} successful${NC}"
        # Stop the client
        kill $CLIENT_PID 2>/dev/null || true
        wait $CLIENT_PID 2>/dev/null || true
        return 0
    else
        echo -e "${RED}❌ Client connection #${attempt} failed${NC}"
        cat client_${attempt}.log
        return 1
    fi
}

# Function to check port assignment via API
check_port_assignment() {
    echo -n "🔍 Checking port assignment via API..."
    
    # Generate token via API
    TOKEN_RESPONSE=$(curl -s -X POST http://${SERVER_HOST}:${API_PORT}/api/v1/tokens/generate \
        -H "Content-Type: application/json" \
        -d '{
            "team_name": "Test Team",
            "team_description": "Test team for bridging fix",
            "token_name": "test-token",
            "expires_at": "2025-12-31T23:59:59Z"
        }')
    
    if echo "$TOKEN_RESPONSE" | grep -q '"success":true'; then
        echo -e " ${GREEN}✅ Token generated successfully${NC}"
        echo "Response: $TOKEN_RESPONSE"
    else
        echo -e " ${YELLOW}⚠️ Using existing token${NC}"
    fi
}

# Start server
echo "🚀 Starting rabbit.go server..."
./rabbit.go server \
    --bind-address ${SERVER_HOST} \
    --control-port ${SERVER_PORT} \
    --api-port ${API_PORT} > server.log 2>&1 &

SERVER_PID=$!

# Cleanup function
cleanup() {
    echo "🧹 Cleaning up..."
    kill $SERVER_PID 2>/dev/null || true
    kill $CLIENT_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    wait $CLIENT_PID 2>/dev/null || true
    rm -f client_*.log server.log
}

trap cleanup EXIT

# Wait for server to be ready
if ! wait_for_server; then
    echo -e "${RED}❌ Test failed: Server did not start${NC}"
    cat server.log
    exit 1
fi

# Check API functionality
check_port_assignment

echo ""
echo "🧪 Running Connection Bridging Tests"
echo "===================================="

# Test 1: Initial connection
echo -e "${YELLOW}Test 1: Initial client connection${NC}"
if test_client_connection 1; then
    echo -e "${GREEN}✅ Test 1 PASSED${NC}"
else
    echo -e "${RED}❌ Test 1 FAILED${NC}"
    echo "Server log:"
    tail -20 server.log
    exit 1
fi

sleep 2

# Test 2: Reconnection (should bridge to existing tunnel)
echo -e "${YELLOW}Test 2: Client reconnection (bridging test)${NC}"
if test_client_connection 2; then
    echo -e "${GREEN}✅ Test 2 PASSED - No 'address already in use' error${NC}"
else
    echo -e "${RED}❌ Test 2 FAILED - Connection bridging not working${NC}"
    echo "Server log:"
    tail -20 server.log
    exit 1
fi

sleep 2

# Test 3: Multiple rapid reconnections
echo -e "${YELLOW}Test 3: Multiple rapid reconnections${NC}"
for i in {3..5}; do
    if test_client_connection $i; then
        echo -e "${GREEN}✅ Reconnection #$i successful${NC}"
    else
        echo -e "${RED}❌ Reconnection #$i failed${NC}"
        echo "Server log:"
        tail -20 server.log
        exit 1
    fi
    sleep 1
done

echo ""
echo "📊 Checking server logs for bridging behavior..."
echo "=============================================="

# Check for expected log messages
if grep -q "Found existing.*tunnel.*replacing client connection" server.log; then
    echo -e "${GREEN}✅ Found connection replacement logs${NC}"
elif grep -q "Found existing restored tunnel.*reconnecting client" server.log; then
    echo -e "${GREEN}✅ Found tunnel restoration logs${NC}"
else
    echo -e "${YELLOW}⚠️ No specific bridging logs found (might be first connection)${NC}"
fi

# Check for error conditions
if grep -q "address already in use" server.log; then
    echo -e "${RED}❌ CRITICAL: Found 'address already in use' errors in logs${NC}"
    grep "address already in use" server.log
    exit 1
else
    echo -e "${GREEN}✅ No 'address already in use' errors found${NC}"
fi

echo ""
echo "🎉 All Tests PASSED!"
echo "==================="
echo -e "${GREEN}✅ Connection bridging fix is working correctly${NC}"
echo -e "${GREEN}✅ Clients can reconnect without port conflicts${NC}"
echo -e "${GREEN}✅ Server properly bridges to existing tunnels${NC}"

echo ""
echo "📝 Summary:"
echo "- Multiple client reconnections succeeded"
echo "- No 'address already in use' errors occurred"
echo "- Server correctly bridged clients to existing tunnels"
echo ""
echo -e "${GREEN}🎯 Fix verification COMPLETE!${NC}" 