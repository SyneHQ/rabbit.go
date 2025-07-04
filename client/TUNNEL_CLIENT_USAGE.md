# Tunnel Client Usage Guide

## Overview

The syne-cli tunnel client now includes **automatic reconnection with exponential backoff retry logic**. This ensures your tunnels remain stable and automatically recover from network issues or server restarts.

## Features

✅ **Automatic Reconnection**: Reconnects automatically when connection is lost  
✅ **Exponential Backoff**: Smart retry delays that increase over time  
✅ **Health Monitoring**: Continuously monitors connection health  
✅ **Configurable Timeouts**: Customizable connection and retry parameters  
✅ **Server Restart Recovery**: Automatically reconnects to restored tunnels  
✅ **Graceful Shutdown**: Clean disconnection on Ctrl+C  

## Basic Usage

### Simple Tunnel
```bash
syne-cli tunnel --server tunnel.example.com:8000 --token YOUR_TOKEN --local-port 3000
```

### Advanced Configuration
```bash
syne-cli tunnel \
  --server tunnel.example.com:8000 \
  --token YOUR_TOKEN \
  --local-port 8080 \
  --max-retries 15 \
  --initial-delay 2s \
  --max-delay 30s \
  --health-interval 15s \
  --timeout 15s
```

## Configuration Options

### Connection Settings
| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `tunneler.synehq.com` | Tunnel server address (host:port) |
| `--local-port` | `5432` | Local port to expose through tunnel |
| `--token` | `default` | Authentication token |
| `--timeout` | `10s` | Connection timeout |

### Reconnection Settings
| Flag | Default | Description |
|------|---------|-------------|
| `--max-retries` | `10` | Maximum reconnection attempts (0 = infinite) |
| `--initial-delay` | `1s` | Initial delay between retry attempts |
| `--max-delay` | `60s` | Maximum delay between retry attempts |
| `--health-interval` | `30s` | Health check interval |

## Retry Behavior

The client uses **exponential backoff** for reconnection attempts:

```
Attempt 1: Wait 1s    (initial delay)
Attempt 2: Wait 2s    (2^1 * initial)
Attempt 3: Wait 4s    (2^2 * initial)
Attempt 4: Wait 8s    (2^3 * initial)
...
Attempt N: Wait 60s   (capped at max delay)
```

## Example Scenarios

### Development Server
For local development with frequent restarts:
```bash
syne-cli tunnel \
  --server localhost:8000 \
  --token dev-token-123 \
  --local-port 3000 \
  --max-retries 0 \
  --initial-delay 500ms \
  --max-delay 5s \
  --health-interval 10s
```

### Production Service
For stable production tunneling:
```bash
syne-cli tunnel \
  --server prod-tunnel.example.com:8000 \
  --token prod-token-xyz \
  --local-port 8080 \
  --max-retries 20 \
  --initial-delay 2s \
  --max-delay 60s \
  --health-interval 30s
```

### High-Availability Setup
For critical services requiring maximum uptime:
```bash
syne-cli tunnel \
  --server ha-tunnel.example.com:8000 \
  --token ha-token-abc \
  --local-port 9000 \
  --max-retries 0 \
  --initial-delay 1s \
  --max-delay 30s \
  --health-interval 15s \
  --timeout 5s
```

## Expected Output

### Successful Connection
```
🚀 Starting tunnel client with auto-reconnection...
   Server: tunnel.example.com:8000
   Local Port: 3000
   Max Retries: 10
   Retry Delay: 1s - 60s
   Health Check: 30s

🔄 Connection attempt 1...
🎯 Tunnel established!
   Tunnel ID: abc123
   Local port 3000 → Remote port 12345
   Access via: tunnel.example.com:8000 (remote port 12345)

📡 Tunnel client is running with auto-reconnection.
   Press Ctrl+C to stop.

🔗 New connection conn-456 → local:3000
🌉 Bridging connection conn-456
✅ Connection conn-456 finished (↑1024 ↓2048 bytes)
```

### Connection Failure & Retry
```
🔄 Connection attempt 1...
❌ Connection failed: dial tcp: connection refused
⏳ Waiting 1s before next attempt...

🔄 Connection attempt 2...
❌ Connection failed: dial tcp: connection refused
⏳ Waiting 2s before next attempt...

🔄 Connection attempt 3...
✅ Connected successfully!
🎯 Tunnel established!
   Tunnel ID: def789
   Local port 3000 → Remote port 12346
```

### Server Restart Recovery
```
🚨 Health check failed - connection appears dead
🔌 Connection lost. Attempting to reconnect...

🔄 Connection attempt 1...
🔄 Found existing restored tunnel xyz789, reconnecting client
✅ Reconnected successfully! (reconnection #1)
🎯 Client reconnected to restored tunnel: xyz789
```

## Troubleshooting

### Connection Issues
```bash
# Test server connectivity
nc -zv tunnel.example.com 8000

# Check token validity
curl -s http://tunnel.example.com:8080/api/v1/health
```

### Infinite Retries
```bash
# Use max-retries 0 for infinite attempts
syne-cli tunnel --max-retries 0 --token YOUR_TOKEN --local-port 3000
```

### Fast Reconnection
```bash
# Use shorter delays for local development
syne-cli tunnel \
  --initial-delay 200ms \
  --max-delay 2s \
  --health-interval 5s \
  --token YOUR_TOKEN \
  --local-port 3000
```

### Debug Mode
```bash
# Enable verbose output (if available)
syne-cli tunnel --verbose --token YOUR_TOKEN --local-port 3000
```

## Integration Examples

### Docker Compose
```yaml
version: '3.8'
services:
  app:
    image: myapp:latest
    ports:
      - "3000:3000"
  
  tunnel:
    image: syne-cli:latest
    command: >
      tunnel 
      --server tunnel.example.com:8000
      --token ${TUNNEL_TOKEN}
      --local-port 3000
      --max-retries 0
    environment:
      - TUNNEL_TOKEN=${TUNNEL_TOKEN}
    depends_on:
      - app
    restart: unless-stopped
```

### Systemd Service
```ini
[Unit]
Description=Syne Tunnel Client
After=network.target

[Service]
Type=simple
User=tunnel
WorkingDirectory=/opt/syne-cli
ExecStart=/usr/local/bin/syne-cli tunnel \
  --server tunnel.example.com:8000 \
  --token ${TUNNEL_TOKEN} \
  --local-port 8080 \
  --max-retries 0
Restart=always
RestartSec=5
Environment=TUNNEL_TOKEN=your-token-here

[Install]
WantedBy=multi-user.target
```

### Process Manager (PM2)
```json
{
  "apps": [{
    "name": "tunnel-client",
    "script": "syne-cli",
    "args": [
      "tunnel",
      "--server", "tunnel.example.com:8000",
      "--token", "your-token-here",
      "--local-port", "3000",
      "--max-retries", "0"
    ],
    "restart_delay": 1000,
    "max_restarts": 50,
    "min_uptime": "10s"
  }]
}
```

## Best Practices

1. **Use Token Environment Variables**: Keep tokens out of command history
   ```bash
   export TUNNEL_TOKEN="your-secure-token"
   syne-cli tunnel --token $TUNNEL_TOKEN --local-port 3000
   ```

2. **Set Appropriate Retry Limits**: Use infinite retries for production, limited for testing
   
3. **Monitor Health Check Intervals**: Shorter intervals for critical services, longer for stable environments

4. **Configure Timeouts**: Adjust based on network conditions and server response times

5. **Use Process Managers**: Combine with systemd, PM2, or Docker for additional reliability

6. **Log Output**: Redirect output to logs for monitoring and debugging
   ```bash
   syne-cli tunnel --token $TOKEN --local-port 3000 2>&1 | tee tunnel.log
   ``` 