#!/bin/bash

# Database Tunnel Setup Script
# This script helps you set up tunnels for common databases

SERVER_ADDRESS=""
SYNE_CLI_PATH="../syne-cli/syne-cli"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}🗄️  Database Tunnel Setup${NC}"
    echo -e "${BLUE}=========================${NC}"
    echo ""
}

check_requirements() {
    if [ ! -f "$SYNE_CLI_PATH" ]; then
        echo -e "${RED}❌ syne-cli not found at $SYNE_CLI_PATH${NC}"
        echo "Please build syne-cli first: cd ../syne-cli && go build -o syne-cli"
        exit 1
    fi

    if [ -z "$SERVER_ADDRESS" ]; then
        echo -e "${YELLOW}⚠️  Server address not set${NC}"
        read -p "Enter your tunnel server address (e.g., your.vps.com:9999): " SERVER_ADDRESS
        if [ -z "$SERVER_ADDRESS" ]; then
            echo -e "${RED}❌ Server address is required${NC}"
            exit 1
        fi
    fi
}

create_tunnel() {
    local service_name=$1
    local port=$2
    local token=$3
    local description=$4

    echo -e "${YELLOW}🔗 Creating tunnel for $service_name ($description)...${NC}"
    echo "   Local port: $port"
    echo "   Token: $token"
    echo "   Command: $SYNE_CLI_PATH tunnel --server $SERVER_ADDRESS --local-port $port --token $token"
    echo ""
    echo -e "${GREEN}➡️  Run this command in a new terminal:${NC}"
    echo -e "${BLUE}$SYNE_CLI_PATH tunnel --server $SERVER_ADDRESS --local-port $port --token $token${NC}"
    echo ""
    read -p "Press Enter to continue to next database..."
    echo ""
}

setup_postgresql() {
    echo -e "${GREEN}🐘 PostgreSQL Setup${NC}"
    echo "Default port: 5432"
    echo "Common Docker command: docker run -d --name postgres -p 5432:5432 -e POSTGRES_PASSWORD=password postgres:15"
    echo ""
    create_tunnel "PostgreSQL" "5432" "postgres-production-db" "PostgreSQL Database"
    
    echo -e "${BLUE}📝 Connection examples after tunnel is active:${NC}"
    echo "psql -h 127.0.0.1 -p <tunnel-port> -U postgres"
    echo "postgresql://postgres:password@127.0.0.1:<tunnel-port>/mydb"
    echo ""
}

setup_mongodb() {
    echo -e "${GREEN}🍃 MongoDB Setup${NC}"
    echo "Default port: 27017"
    echo "Common Docker command: docker run -d --name mongo -p 27017:27017 mongo:7"
    echo ""
    create_tunnel "MongoDB" "27017" "mongodb-analytics-cluster" "MongoDB Database"
    
    echo -e "${BLUE}📝 Connection examples after tunnel is active:${NC}"
    echo "mongosh mongodb://127.0.0.1:<tunnel-port>/mydb"
    echo "mongodb://username:password@127.0.0.1:<tunnel-port>/mydb?authSource=admin"
    echo ""
}

setup_elasticsearch() {
    echo -e "${GREEN}🔍 ElasticSearch Setup${NC}"
    echo "Default port: 9200"
    echo "Common Docker command: docker run -d --name elasticsearch -p 9200:9200 -e discovery.type=single-node elasticsearch:8.8.0"
    echo ""
    create_tunnel "ElasticSearch" "9200" "elasticsearch-search-engine" "ElasticSearch Search Engine"
    
    echo -e "${BLUE}📝 Connection examples after tunnel is active:${NC}"
    echo "curl http://127.0.0.1:<tunnel-port>/_cluster/health"
    echo "curl -X GET '127.0.0.1:<tunnel-port>/myindex/_search'"
    echo ""
}

setup_redis() {
    echo -e "${GREEN}🔴 Redis Setup${NC}"
    echo "Default port: 6379"
    echo "Common Docker command: docker run -d --name redis -p 6379:6379 redis:7-alpine"
    echo ""
    create_tunnel "Redis" "6379" "redis-session-store" "Redis Cache/Session Store"
    
    echo -e "${BLUE}📝 Connection examples after tunnel is active:${NC}"
    echo "redis-cli -h 127.0.0.1 -p <tunnel-port>"
    echo "redis://127.0.0.1:<tunnel-port>"
    echo ""
}

setup_mysql() {
    echo -e "${GREEN}🐬 MySQL Setup${NC}"
    echo "Default port: 3306"
    echo "Common Docker command: docker run -d --name mysql -p 3306:3306 -e MYSQL_ROOT_PASSWORD=password mysql:8"
    echo ""
    create_tunnel "MySQL" "3306" "mysql-legacy-system" "MySQL Database"
    
    echo -e "${BLUE}📝 Connection examples after tunnel is active:${NC}"
    echo "mysql -h 127.0.0.1 -P <tunnel-port> -u root -p"
    echo "mysql://root:password@127.0.0.1:<tunnel-port>/mydb"
    echo ""
}

setup_kibana() {
    echo -e "${GREEN}📊 Kibana Setup${NC}"
    echo "Default port: 5601"
    echo "Note: Typically used with ElasticSearch"
    echo ""
    create_tunnel "Kibana" "5601" "kibana-dashboard" "Kibana Dashboard"
    
    echo -e "${BLUE}📝 Access after tunnel is active:${NC}"
    echo "http://127.0.0.1:<tunnel-port> (in browser on VPS)"
    echo ""
}

show_menu() {
    echo -e "${GREEN}Select databases to set up tunnels for:${NC}"
    echo "1) PostgreSQL (port 5432)"
    echo "2) MongoDB (port 27017)"
    echo "3) ElasticSearch (port 9200)"
    echo "4) Redis (port 6379)"
    echo "5) MySQL (port 3306)"
    echo "6) Kibana (port 5601)"
    echo "7) All databases"
    echo "8) Custom port"
    echo "0) Exit"
    echo ""
}

setup_custom() {
    echo -e "${YELLOW}🔧 Custom Database Setup${NC}"
    read -p "Enter service name: " service_name
    read -p "Enter local port: " port
    read -p "Enter token: " token
    read -p "Enter description: " description
    
    create_tunnel "$service_name" "$port" "$token" "$description"
}

main() {
    print_header
    check_requirements
    
    echo -e "${GREEN}✅ Ready to set up database tunnels!${NC}"
    echo -e "${BLUE}Server: $SERVER_ADDRESS${NC}"
    echo ""
    
    while true; do
        show_menu
        read -p "Enter your choice [0-8]: " choice
        echo ""
        
        case $choice in
            1) setup_postgresql ;;
            2) setup_mongodb ;;
            3) setup_elasticsearch ;;
            4) setup_redis ;;
            5) setup_mysql ;;
            6) setup_kibana ;;
            7) 
                setup_postgresql
                setup_mongodb
                setup_elasticsearch
                setup_redis
                setup_mysql
                ;;
            8) setup_custom ;;
            0) 
                echo -e "${GREEN}👋 Happy tunneling!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}❌ Invalid choice. Please try again.${NC}"
                echo ""
                ;;
        esac
    done
}

# Set server address if provided as argument
if [ $# -eq 1 ]; then
    SERVER_ADDRESS=$1
fi

main 