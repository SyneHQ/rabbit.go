FROM golang:1.24.0-alpine AS builder

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o rabbit.go main.go

FROM gcr.io/distroless/static-debian12 AS runner

COPY --from=builder /app/rabbit.go /usr/local/bin/rabbit.go
COPY --from=builder /app/internal/database/migrations.sql /usr/local/bin/internal/database/migrations.sql

# 9999 is the tunnel server port
# 3422 is the API port (never expose this port to the internet)
EXPOSE 9999 3422

CMD ["/usr/local/bin/rabbit.go", "server", "--bind", "0.0.0.0", "--port", "9999", "--api-port", "3422"]