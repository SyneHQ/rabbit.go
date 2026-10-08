package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"rabbit.go/internal/database"
)

var databaseCmd = &cobra.Command{
	Use:   "database",
	Short: "Database management commands",
	Long:  `Commands for managing the database, teams, tokens, and statistics.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var migrateCmd = &cobra.Command{
	Use:   "migrate <path>",
	Short: "Run database migrations",
	Long:  `Create database tables and run migrations.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		config := database.GetConfigFromEnv()
		db, err := database.NewDatabase(config)
		if err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}
		defer db.Close()

		fmt.Println("Running database migrations...")

		// // Clean up the database
		// fmt.Println("Cleaning up the database...")
		// if err := db.CleanUp(); err != nil {
		// 	return fmt.Errorf("failed to clean up database: %w", err)
		// }

		if err := db.RunMigrations(args[0]); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}

		fmt.Println("Database migrations completed successfully!")
		return nil
	},
}

var listTeamsCmd = &cobra.Command{
	Use:   "list-teams",
	Short: "List all teams with their tokens and ports",
	Long:  `Display all teams along with their associated tokens and port assignments.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		config := database.GetConfigFromEnv()
		db, err := database.NewDatabase(config)
		if err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}
		defer db.Close()

		ctx := context.Background()

		records, err := database.NewService(db).ListTeamsWithTokens(ctx)
		if err != nil {
			return err
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TEAM NAME\tTEAM ID\tTOKEN NAME\tPORT\tPROTOCOL\tCREATED\tLAST USED\tEXPIRES")

		for _, record := range records {
			teamID, teamName, teamCreated := record.TeamID, record.TeamName, record.TeamCreated
			tokenName, tokenCreated, tokenExpires, tokenLastUsed := record.TokenName, record.TokenCreated, record.TokenExpires, record.TokenLastUsed
			port, protocol := record.Port, record.Protocol

			// Format output
			portStr := "N/A"
			protocolStr := "N/A"
			tokenNameStr := "No tokens"
			lastUsedStr := "Never"
			expiresStr := "Never"

			if tokenName != nil {
				tokenNameStr = *tokenName
			}
			if port != nil {
				portStr = strconv.Itoa(*port)
			}
			if protocol != nil {
				protocolStr = *protocol
			}
			if tokenLastUsed != nil {
				if lastUsedTime, err := time.Parse(time.RFC3339, *tokenLastUsed); err == nil {
					lastUsedStr = lastUsedTime.Format("2006-01-02 15:04")
				}
			}
			if tokenExpires != nil {
				if expiresTime, err := time.Parse(time.RFC3339, *tokenExpires); err == nil {
					expiresStr = expiresTime.Format("2006-01-02 15:04")
				}
			}

			createdTime, _ := time.Parse(time.RFC3339, teamCreated)
			if tokenCreated != nil {
				if t, err := time.Parse(time.RFC3339, *tokenCreated); err == nil {
					createdTime = t
				}
			}

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				teamName,
				teamID,
				tokenNameStr,
				portStr,
				protocolStr,
				createdTime.Format("2006-01-02 15:04"),
				lastUsedStr,
				expiresStr,
			)
		}

		w.Flush()
		return nil
	},
}

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show database statistics",
	Long:  `Display statistics about teams, tokens, connections, and system health.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		config := database.GetConfigFromEnv()
		db, err := database.NewDatabase(config)
		if err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}
		defer db.Close()

		service := database.NewService(db)
		ctx := context.Background()

		// Health check
		fmt.Println("🔍 Running health check...")
		if err := service.HealthCheck(ctx); err != nil {
			fmt.Printf("❌ Health check failed: %v\n", err)
		} else {
			fmt.Println("✅ System healthy")
		}

		// Get statistics
		fmt.Println("\n📊 Database Statistics:")
		stats, err := service.GetDatabaseStats(ctx)
		if err != nil {
			return fmt.Errorf("failed to get database stats: %w", err)
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "METRIC\tVALUE")
		for key, value := range stats {
			fmt.Fprintf(w, "%s\t%v\n", key, value)
		}
		w.Flush()

		return nil
	},
}

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check database health",
	Long:  `Verify connectivity to PostgreSQL and Redis databases.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		config := database.GetConfigFromEnv()
		db, err := database.NewDatabase(config)
		if err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}
		defer db.Close()

		service := database.NewService(db)
		ctx := context.Background()

		fmt.Println("🔍 Checking database health...")

		if err := service.HealthCheck(ctx); err != nil {
			fmt.Printf("❌ Health check failed: %v\n", err)
			return err
		}

		fmt.Println("✅ All database connections are healthy!")
		return nil
	},
}

var bootstrapTeamCmd = &cobra.Command{
	Use:   "bootstrap-team <team-id> <name> <owner-id>",
	Short: "Create a standalone team and its first owner",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := database.NewDatabase(database.GetConfigFromEnv())
		if err != nil {
			return err
		}
		defer db.Close()
		ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
		defer cancel()
		if err := db.BootstrapTeam(ctx, args[0], args[1], args[2]); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Standalone team created.")
		return nil
	},
}

func init() {
	// Add subcommands to database command
	databaseCmd.AddCommand(migrateCmd)
	databaseCmd.AddCommand(bootstrapTeamCmd)
	databaseCmd.AddCommand(listTeamsCmd)
	databaseCmd.AddCommand(statsCmd)
	databaseCmd.AddCommand(healthCmd)
	// Add database command to root
	rootCmd.AddCommand(databaseCmd)
}
