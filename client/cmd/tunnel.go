package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"rabbit.go/client/internal/tunnel"

	"github.com/spf13/cobra"
)

var (
	serverAddress        string
	caFile               string
	serverName           string
	insecureLocal        bool
	localPort            string
	token                string
	maxReconnectAttempts int
	initialRetryDelay    time.Duration
	maxRetryDelay        time.Duration
	healthCheckInterval  time.Duration
	connectionTimeout    time.Duration
	maxConnections       int
)

func init() {
	tunnelCmd := &cobra.Command{
		Use:   "tunnel",
		Short: "Connect a local TCP service through a verified tunnel",
		Long: `Expose a local TCP service through the Rabbit server using verified TLS.
Database protocol bytes pass through unchanged. The client reconnects after
transport failures; applications remain responsible for retrying their queries.
Set RABBIT_TOKEN before starting the client.`,
		Example: `
  rabbit.go tunnel \
    --server rabbit.synehq.com \
    --local-port 5432 \
    --max-connections 64 \
    --max-retries 5`,
		RunE: runTunnel,
	}

	// Tunnel connection flags
	tunnelCmd.Flags().StringVar(&serverAddress, "server", "rabbit.synehq.com", "Tunnel server address (host:port)")
	tunnelCmd.Flags().StringVar(&localPort, "local-port", "5432", "Local port to tunnel")
	tunnelCmd.Flags().StringVar(&token, "token", os.Getenv("RABBIT_TOKEN"), "Authentication token (or RABBIT_TOKEN environment variable)")
	tunnelCmd.Flags().StringVar(&caFile, "ca-file", "", "Regular PEM CA file for the tunnel server (max 1 MiB; no symlinks)")
	tunnelCmd.Flags().StringVar(&serverName, "server-name", "", "Expected TLS server hostname (defaults to server address)")
	tunnelCmd.Flags().BoolVar(&insecureLocal, "insecure-local", false, "Allow plaintext to a literal loopback address for local development only")

	// Reconnection configuration flags
	tunnelCmd.Flags().IntVar(&maxReconnectAttempts, "max-retries", 10, "Maximum reconnection attempts (0 = infinite)")
	tunnelCmd.Flags().DurationVar(&initialRetryDelay, "initial-delay", 1*time.Second, "Initial delay between retry attempts")
	tunnelCmd.Flags().DurationVar(&maxRetryDelay, "max-delay", 60*time.Second, "Maximum delay between retry attempts")
	tunnelCmd.Flags().DurationVar(&healthCheckInterval, "health-interval", 30*time.Second, "Health check interval")
	tunnelCmd.Flags().DurationVar(&connectionTimeout, "timeout", 10*time.Second, "Connection timeout")
	tunnelCmd.Flags().IntVar(&maxConnections, "max-connections", 64, "Maximum simultaneous database streams (1-4096)")

	// Required flags
	tunnelCmd.MarkFlagRequired("server")

	rootCmd.AddCommand(tunnelCmd)
}

func runTunnel(cmd *cobra.Command, args []string) error {
	// Create tunnel client configuration
	config := tunnel.TunnelClientConfig{
		ServerAddress:            serverAddress,
		CAFile:                   caFile,
		ServerName:               serverName,
		InsecureLocal:            insecureLocal,
		LocalPort:                localPort,
		Token:                    token,
		MaxReconnectAttempts:     maxReconnectAttempts,
		InitialRetryDelay:        initialRetryDelay,
		MaxRetryDelay:            maxRetryDelay,
		HealthCheckInterval:      healthCheckInterval,
		ConnectionTimeout:        connectionTimeout,
		MaxConcurrentConnections: maxConnections,
	}

	fmt.Printf("Starting tunnel client with automatic reconnection...\n")
	fmt.Printf("   Server: %s\n", config.ServerAddress)
	fmt.Printf("   Local Port: %s\n", config.LocalPort)
	fmt.Printf("   Max Retries: %d\n", config.MaxReconnectAttempts)
	fmt.Printf("   Retry Delay: %v - %v\n", config.InitialRetryDelay, config.MaxRetryDelay)
	fmt.Printf("   Health Check: %v\n", config.HealthCheckInterval)
	fmt.Printf("   Max Connections: %d\n", config.MaxConcurrentConnections)

	// Create and start tunnel client
	client, err := tunnel.NewTunnelClient(config)
	if err != nil {
		return fmt.Errorf("error creating tunnel client: %v", err)
	}

	if err := client.Start(); err != nil {
		return fmt.Errorf("error starting tunnel: %v", err)
	}

	// Handle interrupt signal for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	fmt.Printf("\nTunnel client is running with automatic reconnection.\n")
	fmt.Printf("   Press Ctrl+C to stop.\n\n")

	// Wait for interrupt signal
	<-sigChan

	fmt.Printf("\nStopping tunnel client...\n")
	return client.Stop()
}
