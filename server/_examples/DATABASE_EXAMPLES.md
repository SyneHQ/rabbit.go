# 🗄️ Database Tunneling Examples

Your rabbit.go system is perfect for securely exposing database connections through your VPS. Here are practical examples for common databases.

## 🚀 Quick Database Tunnel Setup

### 1. Start Your Tunnel Server (VPS)
```bash
# On your VPS server
./rabbit.go server --bind 0.0.0.0 --port 9999 --tokens ./tokens.txt
```

### 2. Create Database Tunnels (Local Machine)

## 🐘 PostgreSQL Tunneling

### Local PostgreSQL → VPS Tunnel
```bash
# Create tunnel for PostgreSQL (default port 5432)
./syne-cli tunnel --server your.vps.com:9999 --local-port 5432 --token db-production

# Output example:
# Tunnel ID: a1b2c3d4
# Local port 5432 is now accessible via tunnel server port 49523
```

### Connect to PostgreSQL via Tunnel
```bash
# From your VPS or applications on the VPS:
psql -h 127.0.0.1 -p 49523 -U postgres -d mydb

# Or using connection string:
postgresql://postgres:password@127.0.0.1:49523/mydb
```

### PostgreSQL Docker Example
```bash
# If PostgreSQL is in Docker locally:
docker run -d --name postgres -p 5432:5432 -e POSTGRES_PASSWORD=password postgres:15

# Create tunnel:
./syne-cli tunnel --server your.vps.com:9999 --local-port 5432 --token postgres-tunnel

# Connect from VPS:
psql -h 127.0.0.1 -p <tunnel-port> -U postgres
```

## 🍃 MongoDB Tunneling

### Local MongoDB → VPS Tunnel
```bash
# Create tunnel for MongoDB (default port 27017)
./syne-cli tunnel --server your.vps.com:9999 --local-port 27017 --token mongo-prod

# Output example:
# Local port 27017 is now accessible via tunnel server port 50124
```

### Connect to MongoDB via Tunnel
```bash
# From your VPS:
mongosh mongodb://127.0.0.1:50124/mydb

# Or with authentication:
mongosh mongodb://username:password@127.0.0.1:50124/mydb?authSource=admin
```

### MongoDB Compass via Tunnel
```
# Connection string for MongoDB Compass (on VPS):
mongodb://127.0.0.1:50124

# Or with auth:
mongodb://admin:password@127.0.0.1:50124/admin
```

## 🔍 ElasticSearch Tunneling

### Local ElasticSearch → VPS Tunnel
```bash
# Create tunnel for ElasticSearch (default port 9200)
./syne-cli tunnel --server your.vps.com:9999 --local-port 9200 --token elastic-search

# Output example:  
# Local port 9200 is now accessible via tunnel server port 51789
```

### Connect to ElasticSearch via Tunnel
```bash
# From your VPS:
curl http://127.0.0.1:51789/_cluster/health

# Index data:
curl -X POST "127.0.0.1:51789/myindex/_doc" -H 'Content-Type: application/json' -d'
{
  "user": "john",
  "message": "Hello World"
}'

# Search:
curl -X GET "127.0.0.1:51789/myindex/_search"
```

### ElasticSearch with Kibana
```bash
# If you have Kibana locally too (port 5601):
./syne-cli tunnel --server your.vps.com:9999 --local-port 5601 --token kibana-tunnel

# Access Kibana from VPS browser:
# http://127.0.0.1:<kibana-tunnel-port>
```

## 🔴 Redis Tunneling

### Local Redis → VPS Tunnel
```bash
# Create tunnel for Redis (default port 6379)
./syne-cli tunnel --server your.vps.com:9999 --local-port 6379 --token redis-cache

# Connect from VPS:
redis-cli -h 127.0.0.1 -p <tunnel-port>

# Test:
127.0.0.1:tunnel-port> SET mykey "Hello Redis"
127.0.0.1:tunnel-port> GET mykey
```

## 🐬 MySQL Tunneling

### Local MySQL → VPS Tunnel
```bash
# Create tunnel for MySQL (default port 3306)
./syne-cli tunnel --server your.vps.com:9999 --local-port 3306 --token mysql-db

# Connect from VPS:
mysql -h 127.0.0.1 -P <tunnel-port> -u root -p

# Or with MySQL Workbench connection:
# Host: 127.0.0.1
# Port: <tunnel-port>
# Username: root
```

## 🚀 Advanced Multi-Database Setup

### Run Multiple Database Tunnels Simultaneously
```bash
# Terminal 1: PostgreSQL tunnel
./syne-cli tunnel --server vps.com:9999 --local-port 5432 --token postgres-prod

# Terminal 2: MongoDB tunnel  
./syne-cli tunnel --server vps.com:9999 --local-port 27017 --token mongo-prod

# Terminal 3: Redis tunnel
./syne-cli tunnel --server vps.com:9999 --local-port 6379 --token redis-prod

# Terminal 4: ElasticSearch tunnel
./syne-cli tunnel --server vps.com:9999 --local-port 9200 --token elastic-prod
```

### Server Output Example:
```
Tunnel server is running on 0.0.0.0:9999
Tunnel created: abc123 (local:5432 -> remote:49523)  # PostgreSQL
Tunnel created: def456 (local:27017 -> remote:49524) # MongoDB  
Tunnel created: ghi789 (local:6379 -> remote:49525)  # Redis
Tunnel created: jkl012 (local:9200 -> remote:49526)  # ElasticSearch
```

## 🔧 Production Database Connection Examples

### Application Configuration
```yaml
# config.yaml on your VPS applications
database:
  postgres:
    host: "127.0.0.1"
    port: 49523  # tunnel port
    user: "postgres"
    password: "your-password"
    database: "production"
    
  mongodb:
    uri: "mongodb://127.0.0.1:49524/myapp"
    
  redis:
    host: "127.0.0.1"
    port: 49525
    
  elasticsearch:
    host: "127.0.0.1"
    port: 49526
```

### Environment Variables
```bash
# .env file on VPS
DATABASE_URL=postgresql://user:pass@127.0.0.1:49523/mydb
MONGODB_URI=mongodb://127.0.0.1:49524/myapp
REDIS_URL=redis://127.0.0.1:49525
ELASTICSEARCH_URL=http://127.0.0.1:49526
```

### Docker Compose on VPS
```yaml
# docker-compose.yml on VPS
version: '3.8'
services:
  web-app:
    image: myapp:latest
    environment:
      - DB_HOST=127.0.0.1
      - DB_PORT=49523  # PostgreSQL tunnel
      - MONGO_HOST=127.0.0.1
      - MONGO_PORT=49524  # MongoDB tunnel
      - REDIS_HOST=127.0.0.1
      - REDIS_PORT=49525  # Redis tunnel
    network_mode: host  # Important: allows access to 127.0.0.1 tunnels
```

## 🔐 Security Best Practices

### Token Management for Databases
```bash
# tokens.txt - use descriptive tokens
postgres-production-db
mongodb-analytics-cluster
elasticsearch-search-engine
redis-session-store
mysql-legacy-system

# Rotate tokens regularly
echo "postgres-prod-$(date +%Y%m%d)" >> tokens.txt
```

### Firewall Rules (VPS)
```bash
# Only allow tunnel connections from your IP
ufw allow from YOUR.CLIENT.IP.ADDRESS to any port 9999
ufw deny 9999  # Block all other access to tunnel control port

# Tunnel ports are on localhost only (secure by default)
# No additional firewall rules needed for tunnel ports
```

## 📊 Monitoring Database Tunnels

### Check Active Tunnels
```bash
# Server logs show active tunnels:
tail -f rabbit.go.log

# Example output:
# Tunnel created: abc123 (local:5432 -> remote:49523)
# New connection to tunnel abc123
# Connection to tunnel abc123 finished
```

### Database Health Checks via Tunnel
```bash
# PostgreSQL health check
pg_isready -h 127.0.0.1 -p 49523

# MongoDB health check  
mongosh --eval "db.adminCommand('ping')" mongodb://127.0.0.1:49524

# Redis health check
redis-cli -h 127.0.0.1 -p 49525 ping

# ElasticSearch health check
curl -s http://127.0.0.1:49526/_cat/health
```

## 🎯 Benefits for Database Access

### ✅ **Advantages Over VPN/SSH**
- **No VPN Setup**: Direct database access without complex VPN configuration
- **Firewall Friendly**: Only one port (9999) needs to be open
- **Per-Database Tokens**: Granular access control per database service
- **Auto Port Assignment**: No port conflicts between databases
- **Simple Client**: Just one command to expose any database

### ✅ **vs Traditional SSH Tunneling**
- **No SSH Keys**: Token-based authentication instead of key management
- **Auto-Reconnect**: Built-in reliability (can be enhanced)
- **Multiple Databases**: Easy concurrent tunneling of multiple services
- **Monitoring**: Centralized logging of all database access

## 🚀 Quick Start Checklist

- [ ] **1. Install**: Build rabbit.go on your VPS
- [ ] **2. Configure**: Set up tokens.txt with database access tokens  
- [ ] **3. Start Server**: `./rabbit.go server --port 9999 --tokens ./tokens.txt`
- [ ] **4. Create Tunnels**: Use syne-cli to tunnel your databases
- [ ] **5. Update Apps**: Point your applications to `127.0.0.1:<tunnel-port>`
- [ ] **6. Test**: Verify database connectivity through tunnels
- [ ] **7. Monitor**: Watch server logs for connection activity

**Your databases are now securely accessible through your VPS!** 🎉 