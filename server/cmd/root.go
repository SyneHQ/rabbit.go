package cmd

import (
	"github.com/spf13/cobra"
	"rabbit.go/internal/secrets"
)

var (
	version string
	rootCmd = &cobra.Command{
		Use:     "rabbit.go",
		Short:   "A private TCP tunnel server",
		Long:    `A private TCP tunnel server that provides ngrok-style tunneling for internal infrastructure.`,
		Version: version,
	}
)

func SetVersion(v string) {
	version = v
}

func Execute() error {
	if err := secrets.Load(); err != nil {
		return err
	}
	return rootCmd.Execute()
}

func init() {
	// Commands will be added by their respective init() functions
}
