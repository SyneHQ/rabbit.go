FROM golang:1.26.8-alpine AS builder

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o rabbit.go ./

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS connections
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1001 tunnel && \
    adduser -D -u 1001 -G tunnel tunnel

WORKDIR /opt/rabbit.go

# Copy binary from builder stage
COPY --from=builder /app/rabbit.go /usr/local/bin/tunnel

# Make binary executable
RUN chmod +x /usr/local/bin/tunnel

# Switch to non-root user
USER tunnel

# Default command - can be overridden
ENTRYPOINT ["tunnel"]

CMD ["tunnel", "--help"]