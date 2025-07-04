# Syne Tunneler API Endpoints

The rabbit.go server now provides HTTP API endpoints for token management and system administration. This replaces the need for CLI commands like `generate-token`.

## Starting the Server with API

```bash
./rabbit.go server --bind 0.0.0.0 --port 9999 --api-port 8080
```

- `--port 9999`: Tunnel control port (for syne-cli connections)
- `--api-port 8080`: HTTP API port (for management operations)

## API Endpoints

### 1. Generate Token (Replaces CLI `generate-token`)

**POST** `/api/v1/tokens/generate`

Generates a new authentication token for an existing team with automatic port assignment.

**Request Body:**
```json
{
  "team_id": "123e4567-e89b-12d3-a456-426614174000",
  "name": "my-tunnel-token",
  "description": "Token for database access",
  "expires_in_days": 30
}
```

**Response:**
```json
{
  "success": true,
  "message": "Token generated successfully",
  "data": {
    "token_id": "456e7890-e12b-34d5-a678-901234567890",
    "team_id": "123e4567-e89b-12d3-a456-426614174000",
    "team_name": "backend-team",
    "token_name": "my-tunnel-token",
    "token": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6",
    "description": "Token for database access",
    "assigned_port": 12345,
    "protocol": "tcp",
    "created_at": "2024-01-15T10:30:00Z",
    "expires_at": "2024-02-14T10:30:00Z"
  }
}
```

**Example:**
```bash
curl -X POST http://localhost:8080/api/v1/tokens/generate \
  -H "Content-Type: application/json" \
  -d @example-token-request.json
```

### 2. List Teams

**GET** `/api/v1/teams`

Returns all teams with their tokens and port assignments.

**Response:**
```json
{
  "success": true,
  "message": "Teams retrieved successfully",
  "data": [
    {
      "team_id": "123e4567-e89b-12d3-a456-426614174000",
      "team_name": "backend-team",
      "description": "Backend development team",
      "created_at": "2024-01-01T00:00:00Z",
      "tokens": [
        {
          "token_id": "456e7890-e12b-34d5-a678-901234567890",
          "name": "prod-db-access",
          "description": "Production database tunnel",
          "port": 12345,
          "protocol": "tcp",
          "created_at": "2024-01-15T10:30:00Z",
          "last_used_at": "2024-01-15T11:45:00Z",
          "expires_at": "2024-02-14T10:30:00Z"
        }
      ]
    }
  ]
}
```

### 3. Health Check

**GET** `/api/v1/health`

Checks database connectivity and system health.

**Response:**
```json
{
  "success": true,
  "status": "healthy",
  "message": "All systems operational",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

### 4. Database Statistics

**GET** `/api/v1/stats`

Returns database statistics and usage metrics.

**Response:**
```json
{
  "success": true,
  "message": "Statistics retrieved successfully",
  "data": {
    "active_teams": 5,
    "active_tokens": 12,
    "port_assignments": 12,
    "active_sessions": 3,
    "connections_today": 47
  }
}
```

### 5. API Information

**GET** `/`

Returns API service information and available endpoints.

## Usage Examples

### Generate a Token (API way - replaces CLI)

Instead of using the CLI command:
```bash
# OLD WAY (CLI)
./rabbit.go generate-token --team-id "123..." --name "my-token"
```

Use the API endpoint:
```bash
# NEW WAY (API)
curl -X POST http://localhost:8080/api/v1/tokens/generate \
  -H "Content-Type: application/json" \
  -d '{
    "team_id": "123e4567-e89b-12d3-a456-426614174000",
    "name": "my-token",
    "description": "Generated via API",
    "expires_in_days": 30
  }'
```

### Check System Health

```bash
curl http://localhost:8080/api/v1/health
```

### Get Database Statistics

```bash
curl http://localhost:8080/api/v1/stats
```

### List All Teams and Tokens

```bash
curl http://localhost:8080/api/v1/teams
```

## Error Responses

All endpoints return error responses in this format:

```json
{
  "success": false,
  "error": "Error description"
}
```

Common error codes:
- `400`: Bad request (missing or invalid parameters)
- `404`: Resource not found (team not found)
- `500`: Internal server error (database issues)
- `503`: Service unavailable (database connection failed)

## Testing

Use the provided test script to verify all endpoints:

```bash
./test-api.sh
```

This will test all endpoints and show example requests/responses. 