#!/bin/bash

# Test script for rabbit.go API endpoints
# This script demonstrates the token generation API that replaces the CLI generate-token command

echo "🧪 Syne Tunneler API Test Script"
echo "================================"

API_BASE="http://localhost:8080"
API_URL="$API_BASE/api/v1"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to make API calls with error handling
api_call() {
    local method=$1
    local endpoint=$2
    local data=$3
    local description=$4
    
    echo -e "${BLUE}🔗 Testing: $description${NC}"
    echo -e "${YELLOW}$method $API_URL$endpoint${NC}"
    
    if [ "$method" = "POST" ] && [ -n "$data" ]; then
        response=$(curl -s -w "\n%{http_code}" -X "$method" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$API_URL$endpoint")
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$API_URL$endpoint")
    fi
    
    # Split response and status code
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
        echo -e "${GREEN}✅ Success ($http_code)${NC}"
        echo "$body" | jq . 2>/dev/null || echo "$body"
    else
        echo -e "${RED}❌ Failed ($http_code)${NC}"
        echo "$body" | jq . 2>/dev/null || echo "$body"
    fi
    echo
}

# Check if rabbit.go is running
check_server() {
    echo "🔍 Checking if rabbit.go is running..."
    if curl -s "$API_BASE" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Server is running${NC}"
        return 0
    else
        echo -e "${RED}❌ Server is not running${NC}"
        echo "Please start the server first:"
        echo "  ./rabbit.go server --bind 0.0.0.0 --port 9999 --api-port 8080"
        return 1
    fi
}

# Test health endpoint
test_health() {
    api_call "GET" "/health" "" "Health Check"
}

# Test home endpoint
test_home() {
    api_call "GET" "/" "" "API Information" | sed "s|$API_URL|$API_BASE|"
}

# Test token generation
test_generate_token() {
    echo -e "${BLUE}🎯 Testing Token Generation${NC}"
    echo "This endpoint replaces the CLI 'generate-token' command"
    echo
    
    # Sample request - you'll need a real team ID from your database
    local team_id="123e4567-e89b-12d3-a456-426614174000"  # Example UUID
    local token_data='{
        "team_id": "'$team_id'",
        "name": "api-test-token",
        "description": "Token generated via API for testing",
        "expires_in_days": 30
    }'
    
    api_call "POST" "/tokens/generate" "$token_data" "Generate Token"
}

# Test teams list
test_teams() {
    api_call "GET" "/teams" "" "List Teams with Tokens"
}

# Test stats
test_stats() {
    api_call "GET" "/stats" "" "Database Statistics"
}

# Main execution
main() {
    echo "Prerequisites:"
    echo "1. PostgreSQL and Redis should be running"
    echo "2. Database should be migrated"
    echo "3. rabbit.go server should be started with API enabled"
    echo
    
    if ! check_server; then
        exit 1
    fi
    
    echo "🚀 Running API tests..."
    echo
    
    # Test all endpoints
    test_home
    test_health
    test_stats
    test_teams
    test_generate_token
    
    echo -e "${BLUE}📋 Summary:${NC}"
    echo "• The token generation endpoint is: POST $API_URL/tokens/generate"
    echo "• Request body should include: team_id, name, description (optional), expires_in_days (optional)"
    echo "• Response includes: token, assigned_port, team_info, etc."
    echo "• This replaces the CLI generate-token command with a REST API"
    echo
    echo -e "${YELLOW}💡 Example usage:${NC}"
    echo 'curl -X POST http://localhost:8080/api/v1/tokens/generate \'
    echo '  -H "Content-Type: application/json" \'
    echo '  -d "{\"team_id\":\"your-team-id\",\"name\":\"my-token\",\"description\":\"Test token\"}"'
    echo
}

# Check dependencies
if ! command -v curl &> /dev/null; then
    echo -e "${RED}❌ curl is required but not installed${NC}"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}⚠️ jq is not installed - JSON output will not be formatted${NC}"
fi

# Run main function
main "$@" 