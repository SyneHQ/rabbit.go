package cmd

import (
	"github.com/spf13/cobra"
)

var (
	version string
	rootCmd = &cobra.Command{
		Use:   "rabbit.go",
		Short: "🐇🚀 Rabbit.go CLI: Tunnel your way to fun and productivity!",
		Long: `Welcome to Rabbit.go! 🐇✨

A playful and powerful CLI tool for running tunnels with Rabbit.go. 
Easily expose your local services to the world, hop through firewalls, and enjoy seamless connectivity! 
Requires authentication. Ready to tunnel? Let's hop in! 🕳️🌍

Example:
  rabbit.go tunnel --local-port 5432 --token mytoken123

Happy tunneling! 🥕`,
		Version: version,
	}
)

func SetVersion(v string) {
	version = v
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringP("username", "u", "", "Username for authentication")
	rootCmd.PersistentFlags().StringP("password", "p", "", "Password for authentication")
}
