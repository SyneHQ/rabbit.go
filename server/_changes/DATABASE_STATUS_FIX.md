# Database Status Constraint Fix

## Problem
Server was generating this error when logging connection attempts to restored ports:
```
⚠️ Failed to end failed connection log: failed to end connection log: pq: new row for relation "connection_logs" violates check constraint "valid_log_status"
```

## Root Cause
The `connection_logs` table has a check constraint that only allows specific status values:

```sql
CONSTRAINT valid_log_status CHECK (status IN ('active', 'closed', 'error', 'timeout'))
```

However, the code was trying to use an invalid status value "info" when logging external connections to restored ports.

## Invalid Code
In `acceptRestoredConnections()` function:
```go
// ❌ INVALID - "info" is not in the allowed status values
t.logConnectionAttempt(clientAddr.IP.String(), clientAddr.Port, "info",
    "External connection to restored port - waiting for tunnel client reconnection")
```

## Fix Applied
Changed the invalid status value to "closed" since the connection is immediately closed after sending the informational message:

```go
// ✅ FIXED - "closed" is a valid status value
t.logConnectionAttempt(clientAddr.IP.String(), clientAddr.Port, "closed",
    "External connection to restored port - waiting for tunnel client reconnection")
```

## Valid Status Values
Added documentation to prevent future issues:

```go
// logConnectionAttempt logs a connection attempt (successful or failed)
// Valid status values (per database constraint):
//   - "active": Connection is currently active
//   - "closed": Connection completed normally
//   - "error": Connection failed due to an error
//   - "timeout": Connection timed out
```

## Verification
Checked all status usage in the codebase:

### ✅ Valid Status Values Found:
- `"active"` - Used for checking if connection is active
- `"closed"` - Used for normal connection completion
- `"error"` - Used for connection failures
- `"timeout"` - Used for connection timeouts

### ❌ Invalid Values Removed:
- `"info"` - Changed to `"closed"`

## Files Modified
1. **`internal/server/server.go`**:
   - Line 877: Changed status from "info" to "closed"
   - Added documentation comment for valid status values

## Testing
After this fix:
- ✅ No more database constraint violations
- ✅ External connections to restored ports are properly logged
- ✅ All connection log entries use valid status values
- ✅ Database integrity maintained

## Prevention
To prevent future constraint violations:
1. **Always check database schema** constraints before adding new status values
2. **Use the documented valid status values** only
3. **Test database operations** to ensure constraints are satisfied
4. **Review migration files** to understand all constraints

## Database Schema Reference
From `internal/database/migrations.sql`:
```sql
CREATE TABLE IF NOT EXISTS connection_logs (
    -- ... other fields ...
    status VARCHAR(20) DEFAULT 'active',
    CONSTRAINT valid_log_status CHECK (status IN ('active', 'closed', 'error', 'timeout'))
);
```

## Summary
This fix ensures all connection log entries comply with the database constraint, eliminating the "violates check constraint" error and maintaining data integrity. 