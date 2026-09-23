//go:build linux || darwin

package cmd

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"rabbit.go/client/internal/launcher"
)

func init() {
	var path string
	command := &cobra.Command{Use: "runtime-start", Short: "Supervise an enrolled local notebook runtime", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		err := launcher.Start(ctx, path, cmd.OutOrStdout())
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}}
	command.Flags().StringVar(&path, "config", "", "Private enrolled runtime configuration file (mode 0600)")
	_ = command.MarkFlagRequired("config")
	rootCmd.AddCommand(command)
}
