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
	localPort            string
	token                string
	maxReconnectAttempts int
	initialRetryDelay    time.Duration
	maxRetryDelay        time.Duration
	healthCheckInterval  time.Duration
	connectionTimeout    time.Duration
)

func init() {
	tunnelCmd := &cobra.Command{
		Use:   "tunnel",
		Short: "Create a tunnel to the rabbit.go server (hop in, it's bunderful!)",
		Long: `Create a secure tunnel to the rabbit.go server to expose your local services.
This command will establish a tunnel between your local machine and the tunnel server.
The tunnel server will allocate a random port that can be used to access your local service.

The client includes automatic reconnection with exponential backoff retry logic.
If the connection is lost, it will automatically attempt to reconnect.

Why did the rabbit use a tunnel? To get to the other side of the firewall, of course! 🐇

Warning: excessive tunneling may result in finding Wonderland. Proceed with curiosity.
`,
		Example: `
  rabbit.go tunnel \
    --local-port 5432 \
    --token mytoken123 \
    --max-retries 5 \
    --initial-delay 2s \
    --max-delay 30s`,
		RunE: runTunnel,
	}

	// Tunnel connection flags
	tunnelCmd.Flags().StringVar(&serverAddress, "server", "tunneler.rabbit.go", "Tunnel server address (host:port)")
	tunnelCmd.Flags().StringVar(&localPort, "local-port", "5432", "Local port to tunnel")
	tunnelCmd.Flags().StringVar(&token, "token", "default", "Authentication token")

	// Reconnection configuration flags
	tunnelCmd.Flags().IntVar(&maxReconnectAttempts, "max-retries", 10, "Maximum reconnection attempts (0 = infinite)")
	tunnelCmd.Flags().DurationVar(&initialRetryDelay, "initial-delay", 1*time.Second, "Initial delay between retry attempts")
	tunnelCmd.Flags().DurationVar(&maxRetryDelay, "max-delay", 60*time.Second, "Maximum delay between retry attempts")
	tunnelCmd.Flags().DurationVar(&healthCheckInterval, "health-interval", 30*time.Second, "Health check interval")
	tunnelCmd.Flags().DurationVar(&connectionTimeout, "timeout", 10*time.Second, "Connection timeout")

	// Required flags
	tunnelCmd.MarkFlagRequired("server")

	rootCmd.AddCommand(tunnelCmd)
}

func runTunnel(cmd *cobra.Command, args []string) error {
	// Create tunnel client configuration
	config := tunnel.TunnelClientConfig{
		ServerAddress:        serverAddress,
		LocalPort:            localPort,
		Token:                token,
		MaxReconnectAttempts: maxReconnectAttempts,
		InitialRetryDelay:    initialRetryDelay,
		MaxRetryDelay:        maxRetryDelay,
		HealthCheckInterval:  healthCheckInterval,
		ConnectionTimeout:    connectionTimeout,
	}

	fmt.Printf("🚀 Starting tunnel client with auto-reconnection...\n")
	fmt.Printf("   Server: %s\n", config.ServerAddress)
	fmt.Printf("   Local Port: %s\n", config.LocalPort)
	fmt.Printf("   Max Retries: %d\n", config.MaxReconnectAttempts)
	fmt.Printf("   Retry Delay: %v - %v\n", config.InitialRetryDelay, config.MaxRetryDelay)
	fmt.Printf("   Health Check: %v\n", config.HealthCheckInterval)

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

	fmt.Printf("\n📡 Tunnel client is running with auto-reconnection.\n")
	fmt.Printf("   Press Ctrl+C to stop.\n\n")

	// Wait for interrupt signal
	<-sigChan

	fmt.Printf("\n🛑 Received interrupt signal...\n")
	return client.Stop()
}
