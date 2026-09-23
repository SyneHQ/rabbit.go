//go:build linux || darwin

package cmd

import (
	"encoding/json"
	"github.com/spf13/cobra"
	"rabbit.go/client/internal/launcher"
)

func provisioningSummary(cmd *cobra.Command, c launcher.Config) error {
	scope := c.Registration.RuntimeScope
	return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"version": 2, "status": "provisioned", "runtimeId": scope.RuntimeID, "teamId": scope.TeamID,
		"installationId": scope.InstallationID, "credentialGeneration": scope.CredentialGeneration, "policyRevision": scope.PolicyRevision,
		"capabilityKeyVersion": c.CapabilityKeyVersion, "ledgerGeneration": scope.LedgerGeneration, "environmentSha256": scope.EnvironmentSHA256,
		"credentialExpiresAt": c.CredentialExpiresAt})
}

func init() {
	var requestPath, statePath string
	var recover bool
	enroll := &cobra.Command{Use: "runtime-enroll", Short: "Enroll a private local notebook installation", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		config, err := launcher.Enroll(cmd.Context(), requestPath, statePath, recover)
		if err != nil {
			return err
		}
		return provisioningSummary(cmd, config)
	}}
	enroll.Flags().StringVar(&requestPath, "request-file", "", "Private enrollment request JSON including the one-time token")
	enroll.Flags().StringVar(&statePath, "config", "", "Private durable launcher state file")
	enroll.Flags().BoolVar(&recover, "recover", false, "Recover this same installation using a fresh administrator-issued enrollment token; preserves its ledger and environment identity")
	_ = enroll.MarkFlagRequired("request-file")
	_ = enroll.MarkFlagRequired("config")
	rootCmd.AddCommand(enroll)
	for _, name := range []string{"bootstrap", "rotate"} {
		name := name
		var path string
		command := &cobra.Command{Use: "runtime-" + name, Short: map[string]string{"bootstrap": "Refresh private notebook runtime provisioning while stopped", "rotate": "Rotate this installation's runtime credential while stopped"}[name], Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
			var config launcher.Config
			var err error
			if name == "bootstrap" {
				config, err = launcher.Bootstrap(cmd.Context(), path)
			} else {
				config, err = launcher.Rotate(cmd.Context(), path)
			}
			if err != nil {
				return err
			}
			return provisioningSummary(cmd, config)
		}}
		command.Flags().StringVar(&path, "config", "", "Private enrolled runtime configuration file")
		_ = command.MarkFlagRequired("config")
		rootCmd.AddCommand(command)
	}
}
