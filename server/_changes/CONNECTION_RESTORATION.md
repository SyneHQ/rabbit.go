# Connection Restoration Documentation

## Overview

The rabbit.go server now supports **automatic restoration and restart** of tunnel listeners when the server restarts. This ensures that previously assigned ports remain accessible and can resume full functionality when clients reconnect.

## How It Works

### 1. Database Tracking
- All active tunnel connections are tracked in the `connection_sessions` table
- Port assignments are stored in the `port_assignments` table
- Connection logs track individual connections through these tunnels
- Session data is stored in Redis with proper JSON serialization

### 2. Server Startup Process
When the server starts, it automatically:

1. **Cleanup Stale Sessions**: Marks sessions inactive if they haven't been seen for >5 minutes
2. **Query Active Sessions**: Retrieves all sessions marked as 'active' from the database
3. **Restore Listeners**: Creates tunnel listeners on the previously assigned ports
4. **Handle Connections**: Detects client reconnections vs external connections
5. **Restart Tunnels**: Fully restarts tunnel functionality when clients reconnect

### 3. Restored Tunnel Behavior

**For Client Reconnections**:
- Detects tunnel client reconnection by analyzing connection data
- Automatically restarts full tunnel functionality
- Resumes normal tunnel operations (proxying, logging, etc.)
- Updates database session status

**For External Connections**:
- Responds with helpful HTTP 503 status message
- Logs connection attempts for monitoring
- Provides instructions for reconnecting tunnel client

## New Features Added

### Enhanced Restoration Methods
- `acceptRestoredConnections()`: Handles both client reconnections and external connections
- `handleRestoredConnection()`: Determines connection type and routes appropriately  
- `isClientReconnection()`: Detects tunnel client reconnection patterns
- `handleClientReconnection()`: Fully restarts tunnel with reconnected client
- `sendRestoredPortMessage()`: Provides helpful messages to external connections

### Database Service Methods
- `RestoreSession()`: Reactivates a session when tunnel is restored
- `ReactivateRestoredTunnel()`: Marks tunnel as fully active when client reconnects
- `GetRestoredTunnelInfo()`: Gets information about restored tunnel sessions

### Fixed Issues
- **Redis Marshaling**: Fixed "can't marshal *database.ConnectionSession" error with proper JSON serialization
- **WaitGroup Panic**: Fixed "negative WaitGroup counter" by proper goroutine management

## Usage Example

### Before Server Restart
```bash
# Start server
./rabbit.go server --bind 127.0.0.1 --port 8000 --api-port 8080

# Client creates tunnel on port 12345
# Database tracks: session_id, token_id, port_assignment_id, port 12345
```

### During Server Restart
```bash
# Server stops (crash, maintenance, etc.)
# Client connection is lost, but database retains session data
```

### After Server Restart
```bash
# Server starts up again
./rabbit.go server --bind 127.0.0.1 --port 8000 --api-port 8080

# Server logs:
# 🔄 Checking for active connections to restore...
# ✅ Restored tunnel listener on port 12345 (sessions: 1)
# 🎧 Listening for tunnel client reconnections on restored port 12345
```

### Client Reconnection
```bash
# Original tunnel client reconnects
./tunnel-client connect --token abc123... --local-port 3000

# Server logs:
# 🔌 New connection to restored tunnel from 127.0.0.1:54321
# 🔄 Detected tunnel client reconnection on port 12345
# ✅ Tunnel client reconnected to restored port 12345
# 🚀 Restarting tunnel with reconnected client
```

### External Connection (Before Client Reconnects)
```bash
# External client tries to connect to port 12345
curl http://localhost:12345

# Response:
# HTTP/1.1 503 Service Unavailable
# Port 12345 was restored from database after server restart.
# The original tunnel client is not connected.
# To restore functionality, reconnect your tunnel client to this port.
```

### Full Tunnel Functionality (After Client Reconnects)
```bash
# External client connects to port 12345 - normal tunnel operation resumes
curl http://localhost:12345/api/data
# -> Proxied to tunnel client's local port 3000
```

## Benefits

1. **Port Consistency**: Previously assigned ports remain available
2. **Automatic Recovery**: Tunnel functionality automatically resumes when clients reconnect
3. **Client Awareness**: External clients get informed responses before tunnel client reconnects
4. **Monitoring**: All connection attempts and reactivations are logged
5. **Graceful Degradation**: Ports remain accessible even without client connection

## Configuration

The restoration process runs automatically on server startup with these defaults:
- **Stale Threshold**: 5 minutes (sessions older than this are marked inactive)
- **Port Range**: 10000-20000 (configurable in database)
- **Protocol**: TCP (extensible to UDP)
- **Reconnection Timeout**: 5 seconds for client reconnection detection

## Client Reconnection

For tunnel clients to reconnect after server restart:

1. **Detect Server Restart**: Monitor connection status
2. **Reconnect to Same Port**: Use the same token and port assignment
3. **Resume Operations**: Server automatically detects and restarts tunnel

```bash
# Example client reconnection logic
while true; do
    if ! tunnel_client_connected; then
        echo "Reconnecting to tunnel server..."
        ./tunnel-client connect --token $TOKEN --local-port $LOCAL_PORT
    fi
    sleep 10
done
```

## Limitations

1. **Session Timeout**: Sessions >5 minutes old are marked inactive
2. **Token Expiration**: Expired tokens cannot reconnect
3. **Resource Usage**: Restored listeners consume ports until cleanup

## Future Enhancements

1. **Auto-Reconnection**: Built-in client auto-reconnection logic
2. **Load Balancing**: Distribute restored sessions across multiple servers  
3. **Health Monitoring**: Active health checks for restored tunnels
4. **Graceful Shutdown**: Preserve sessions during planned maintenance

## Testing

Run the test script to verify functionality:
```bash
bash test-compilation.sh
```

Or test manually:
1. Start server with database connection
2. Create a tunnel session  
3. Stop server (simulating restart)
4. Restart server (check logs for restoration)
5. Reconnect tunnel client (verify full functionality)
6. Test external connections (before and after client reconnection) 