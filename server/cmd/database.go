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
	Use:   "migrate",
	Short: "Run database migrations",
	Long:  `Create database tables and run migrations.`,
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

		if err := db.RunMigrations(); err != nil {
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

		// Query teams with their tokens and port assignments
		query := `
			SELECT 
				t.id, t.name, 
				COALESCE(t.description, '') as description, 
				COALESCE(t."createdAt", NOW()) as created_at,
				tt.id, tt.name, tt.token, tt.created_at, tt.expires_at, tt.last_used_at,
				pa.port, pa.protocol
			FROM public."Team" t
			LEFT JOIN team_tokens tt ON t.id = tt.team_id AND tt.is_active = true
			LEFT JOIN port_assignments pa ON tt.id = pa.token_id
			ORDER BY t.name, tt.created_at`

		rows, err := db.DB.QueryContext(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to query teams: %w", err)
		}
		defer rows.Close()

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TEAM NAME\tTEAM ID\tTOKEN NAME\tPORT\tPROTOCOL\tCREATED\tLAST USED\tEXPIRES")

		for rows.Next() {
			var teamID, teamName, teamDesc, teamCreated string
			var tokenID, tokenName, token, tokenCreated, tokenExpires, tokenLastUsed *string
			var port *int
			var protocol *string

			err := rows.Scan(
				&teamID, &teamName, &teamDesc, &teamCreated,
				&tokenID, &tokenName, &token, &tokenCreated, &tokenExpires, &tokenLastUsed,
				&port, &protocol,
			)
			if err != nil {
				return fmt.Errorf("failed to scan row: %w", err)
			}

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
				teamID[:8]+"...", // Show first 8 chars of UUID
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

func init() {
	// Add subcommands to database command
	databaseCmd.AddCommand(migrateCmd)
	databaseCmd.AddCommand(listTeamsCmd)
	databaseCmd.AddCommand(statsCmd)
	databaseCmd.AddCommand(healthCmd)
	// Add database command to root
	rootCmd.AddCommand(databaseCmd)
}
