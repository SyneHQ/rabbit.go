package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"rabbit.go/internal/server"

	"github.com/spf13/cobra"
)

var (
	bindAddress string
	controlPort string
	logLevel    string
	apiPort     string
)

func init() {
	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Start the tunnel server",
		Long: `Start the tunnel server that accepts client connections and provides TCP tunneling.
The server will bind to the specified address and port to accept control connections from tunnel clients.
Additionally, it provides an HTTP API for token management and system administration.

Examples:
  # Start server with tunnel and API endpoints
  rabbit.go server --bind 0.0.0.0 --port 9999 --api-port 8080
  
  # Generate tokens via API instead of CLI
  curl -X POST http://localhost:8080/api/v1/tokens/generate \
    -H "Content-Type: application/json" \
    -d '{"team_id":"your-team-id","name":"my-token","description":"API generated token"}'`,
		RunE: runServer,
	}

	serverCmd.Flags().StringVar(&bindAddress, "bind", "0.0.0.0", "Address to bind the control server to")
	serverCmd.Flags().StringVar(&controlPort, "port", "9999", "Control port for tunnel connections")
	serverCmd.Flags().StringVar(&apiPort, "api-port", "8080", "HTTP API port for management endpoints")
	serverCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")

	rootCmd.AddCommand(serverCmd)
}

func runServer(cmd *cobra.Command, args []string) error {
	// Create server configuration
	config := server.Config{
		BindAddress: bindAddress,
		ControlPort: controlPort,
		LogLevel:    logLevel,
		APIPort:     apiPort,
	}

	// Create and start server
	srv, err := server.NewServer(config)
	if err != nil {
		return fmt.Errorf("error creating server: %v", err)
	}

	if err := srv.Start(); err != nil {
		return fmt.Errorf("error starting server: %v", err)
	}

	// Handle interrupt signal for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Printf("Tunnel server is running on %s:%s\n", bindAddress, controlPort)
	if apiPort != "" {
		fmt.Printf("API server is running on %s:%s\n", bindAddress, apiPort)
		fmt.Printf("API endpoints:\n")
		fmt.Printf("  POST http://%s:%s/api/v1/tokens/generate - Generate new token\n", bindAddress, apiPort)
		fmt.Printf("  GET  http://%s:%s/api/v1/teams/:teamId/tokens - Get token details\n", bindAddress, apiPort)
		fmt.Printf("  GET  http://%s:%s/api/v1/teams - List teams with tokens\n", bindAddress, apiPort)
		fmt.Printf("  GET  http://%s:%s/api/v1/health - Health check\n", bindAddress, apiPort)
		fmt.Printf("  GET  http://%s:%s/api/v1/stats - Database statistics\n", bindAddress, apiPort)
	}
	fmt.Printf("Press Ctrl+C to stop.\n")

	// Wait for interrupt signal
	<-sigChan

	fmt.Printf("\nStopping server...\n")
	return srv.Stop()
}
