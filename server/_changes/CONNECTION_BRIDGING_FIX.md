# Connection Bridging Fix

## Problem
When a client tries to reconnect with the same token to the same port, the server was getting this error:
```
Error creating tunnel: error creating tunnel listener on port 10000: listen tcp 127.0.0.1:10000: bind: address already in use
```

## Root Cause
The issue was in the tunnel lookup logic:

1. **Original Logic**: `findRestoredTunnelByToken()` only found tunnels where `tunnel.Client == nil` (restored tunnels)
2. **Problem**: Once a client connected to a restored tunnel, `tunnel.Client` was set, so the tunnel was no longer considered "restored"
3. **Result**: Subsequent connections from the same client didn't find the existing tunnel
4. **Failure**: Server tried to create a new tunnel on the same port → "address already in use" error

## Solution
Modified the server logic to handle both restored and active tunnels for the same token/port combination:

### Changes Made

#### 1. Updated `handleControlConnection()` function
```go
// Before: Only check for restored tunnels
existingTunnel := s.findRestoredTunnelByToken(token, portAssignment.Port)

// After: Check for any tunnel (restored or active)
existingTunnel := s.findTunnelByTokenAndPort(token, portAssignment.Port)
if existingTunnel != nil {
    if existingTunnel.Client == nil {
        log.Printf("🔄 Found existing restored tunnel %s, reconnecting client", existingTunnel.ID)
    } else {
        log.Printf("🔄 Found existing active tunnel %s, replacing client connection", existingTunnel.ID)
    }
    // Bridge to existing tunnel instead of creating new one
}
```

#### 2. Created `findTunnelByTokenAndPort()` function
```go
// New function that finds ANY tunnel for given token/port (not just restored ones)
func (s *Server) findTunnelByTokenAndPort(token string, port int) *Tunnel {
    for _, tunnel := range s.tunnels {
        if tunnel.Token == token && tunnel.RemotePort == strconv.Itoa(port) {
            return tunnel
        }
    }
    return nil
}
```

#### 3. Enhanced `reconnectClientToTunnel()` function
```go
func (s *Server) reconnectClientToTunnel(tunnel *Tunnel, conn net.Conn, ...) {
    // If there's an existing client, close it gracefully
    s.mu.Lock()
    oldClient := tunnel.Client
    if oldClient != nil {
        log.Printf("🔄 Closing existing client connection for tunnel %s", tunnel.ID)
        close(tunnel.stopChan)
        oldClient.Close()
    }

    // Update tunnel with new client connection
    tunnel.Client = conn
    tunnel.LocalPort = localPort
    tunnel.stopChan = make(chan struct{}) // Reset stop channel
    s.mu.Unlock()

    // Send success response and start tunnel operations
    fmt.Fprintf(conn, "SUCCESS:%s:%s\n", tunnel.ID, tunnel.RemotePort)
    tunnel.handleTunnel()
}
```

## Behavior After Fix

### Scenario 1: Client Reconnects to Restored Tunnel
- Server restart occurs
- Tunnel port 10000 is restored (no client connected)
- Client reconnects with same token
- ✅ **Result**: Client bridges to existing restored tunnel

### Scenario 2: Client Reconnects to Active Tunnel
- Tunnel is active with client connected
- Same client reconnects (e.g., after network issue)
- ✅ **Result**: Old client connection is closed gracefully, new client bridges to existing tunnel

### Scenario 3: Different Client, Same Token/Port
- Client A is connected to tunnel on port 10000
- Client B tries to connect with same token
- ✅ **Result**: Client A is disconnected, Client B takes over the tunnel

## Benefits

1. **No Port Conflicts**: Eliminates "address already in use" errors
2. **Seamless Reconnection**: Clients can reconnect without server restart
3. **Resource Efficiency**: Reuses existing tunnel infrastructure
4. **Graceful Handover**: Properly closes old connections before establishing new ones
5. **Database Consistency**: Maintains proper session tracking

## Test Scenarios

### Test 1: Basic Reconnection
```bash
# Start server
./rabbit.go server

# Connect client
syne-cli tunnel --token test123 --local-port 5432

# Disconnect and reconnect same client
# Should bridge to existing tunnel without error
```

### Test 2: Multiple Reconnections
```bash
# Connect client multiple times with same token
# Each reconnection should succeed
syne-cli tunnel --token test123 --local-port 5432  # First connection
# Ctrl+C and restart
syne-cli tunnel --token test123 --local-port 5432  # Should succeed
# Ctrl+C and restart  
syne-cli tunnel --token test123 --local-port 5432  # Should succeed
```

### Test 3: Server Restart Scenario
```bash
# Connect client
syne-cli tunnel --token test123 --local-port 5432

# Restart server (tunnel restored from database)
# Reconnect same client
syne-cli tunnel --token test123 --local-port 5432  # Should bridge to restored tunnel
```

## Log Messages

The fix provides clear logging to understand what's happening:

```
✅ Token authenticated for team: MyTeam
📍 Assigned port: 10000
🔄 Found existing active tunnel abc123, replacing client connection
🔄 Closing existing client connection for tunnel abc123
🎯 Client connection replaced for tunnel: abc123 (team:MyTeam, local:5432 -> remote:10000)
```

## Summary

This fix ensures that clients can reliably reconnect to the same port without encountering "address already in use" errors. The server now intelligently bridges clients to existing tunnels rather than trying to create duplicate listeners on the same port. 