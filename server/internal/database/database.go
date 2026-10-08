package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
)

// Database represents the database service with PostgreSQL and Redis
type Database struct {
	DB           *sql.DB
	Redis        *redis.Client
	ctx          context.Context
	IdentityMode string
}

// Config holds database configuration
type Config struct {
	PostgresURL  string
	RedisURL     string
	RedisDB      int
	IdentityMode string
}

// NewDatabase creates a new database instance
func NewDatabase(config Config) (*Database, error) {
	mode, err := normalizeIdentityMode(config.IdentityMode)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Connect to PostgreSQL
	db, err := sql.Open("postgres", config.PostgresURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	configured := false
	defer func() {
		if !configured {
			db.Close()
		}
	}()

	// Test PostgreSQL connection
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Connect to Redis
	opt, err := redis.ParseURL(config.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	if config.RedisDB > 0 {
		opt.DB = config.RedisDB
	}

	opt.ContextTimeoutEnabled = true
	rdb := redis.NewClient(opt)
	defer func() {
		if !configured {
			rdb.Close()
		}
	}()

	// Test Redis connection
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	configured = true
	return &Database{
		DB:           db,
		Redis:        rdb,
		ctx:          context.Background(),
		IdentityMode: mode,
	}, nil
}

// Close closes all database connections
func (d *Database) Close() error {
	var errs []error
	if d.Redis != nil {
		if err := d.Redis.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close Redis connection: %w", err))
		}
	}
	if d.DB != nil {
		if err := d.DB.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close PostgreSQL connection: %w", err))
		}
	}
	return errors.Join(errs...)
}

// CleanUp cleans up the database
func (d *Database) CleanUp() error {
	cleanUpFile := "internal/database/clean-up.sql"

	// Read clean-up file
	cleanUpSQL, err := os.ReadFile(cleanUpFile)
	if err != nil {
		return fmt.Errorf("failed to read clean-up file: %w", err)
	}

	// Execute clean-up SQL
	_, err = d.DB.ExecContext(d.ctx, string(cleanUpSQL))
	if err != nil {
		return fmt.Errorf("failed to clean up database: %w", err)
	}

	return nil
}

// RunMigrations runs the database migrations
func (d *Database) RunMigrations(path string) error {
	migrationFile := path

	// Read migration file
	migrationSQL, err := os.ReadFile(migrationFile)
	if err != nil {
		return fmt.Errorf("failed to read migration file: %w", err)
	}

	// Execute migration
	_, err = d.DB.ExecContext(d.ctx, string(migrationSQL))
	if err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}

// GetConfigFromEnv loads database configuration from environment variables
func GetConfigFromEnv() Config {
	// Load environment variables from .env file (optional - for local development)
	// In Docker containers, environment variables are passed directly
	if err := godotenv.Load(); err != nil {
		// Don't log error - this is expected in Docker containers
		// where environment variables are passed via --env-file or -e flags
	}

	return Config{
		PostgresURL:  getEnvOrDefault("DATABASE_URL", "postgres://localhost/syne_tunneler?sslmode=disable"),
		RedisURL:     getEnvOrDefault("REDIS_URL", "redis://localhost:6379"),
		RedisDB:      0,
		IdentityMode: os.Getenv("RABBIT_IDENTITY_MODE"),
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Utility functions for common database operations

// BeginTx starts a new transaction
func (d *Database) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return d.DB.BeginTx(ctx, nil)
}

// WithTx executes a function within a transaction
func (d *Database) WithTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := d.BeginTx(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("tx error: %v, rollback error: %v", err, rbErr)
		}
		return err
	}

	return tx.Commit()
}

// Redis helper methods

// SetCache sets a value in Redis cache with expiration
func (d *Database) SetCache(key string, value interface{}, expiration time.Duration) error {
	return d.Redis.Set(d.ctx, key, value, expiration).Err()
}

// GetCache gets a value from Redis cache
func (d *Database) GetCache(key string) (string, error) {
	return d.Redis.Get(d.ctx, key).Result()
}

// DeleteCache deletes a key from Redis cache
func (d *Database) DeleteCache(key string) error {
	return d.Redis.Del(d.ctx, key).Err()
}

// SetActiveSession sets an active connection session in Redis
func (d *Database) SetActiveSession(sessionID uuid.UUID, data interface{}) error {
	return d.SetActiveSessionContext(d.ctx, sessionID, data)
}

func (d *Database) SetActiveSessionContext(ctx context.Context, sessionID uuid.UUID, data interface{}) error {
	key := fmt.Sprintf("session:%s", sessionID.String())

	// Serialize data to JSON before storing in Redis
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	return d.Redis.Set(ctx, key, jsonData, 24*time.Hour).Err()
}

// GetActiveSession gets an active connection session from Redis
func (d *Database) GetActiveSession(sessionID uuid.UUID) (string, error) {
	key := fmt.Sprintf("session:%s", sessionID.String())
	return d.Redis.Get(d.ctx, key).Result()
}

// DeleteActiveSession deletes an active session from Redis
func (d *Database) DeleteActiveSession(sessionID uuid.UUID) error {
	return d.DeleteActiveSessionContext(d.ctx, sessionID)
}

func (d *Database) DeleteActiveSessionContext(ctx context.Context, sessionID uuid.UUID) error {
	key := fmt.Sprintf("session:%s", sessionID.String())
	return d.Redis.Del(ctx, key).Err()
}

// IncrementCounter increments a counter in Redis
func (d *Database) IncrementCounter(key string) (int64, error) {
	return d.Redis.Incr(d.ctx, key).Result()
}
