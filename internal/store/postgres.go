package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	entsql "entgo.io/ent/dialect/sql"

	"github.com/dalbodeule/hop-gate/ent"
	"github.com/dalbodeule/hop-gate/internal/logging"

	_ "github.com/lib/pq"
)

// Config holds PostgreSQL connection and pool settings.
type Config struct {
	DSN             string        // PostgreSQL DSN, e.g. postgres://user:pass@host:5432/db?sslmode=disable
	MaxOpenConns    int           // maximum number of open connections
	MaxIdleConns    int           // maximum number of idle connections
	ConnMaxLifetime time.Duration // maximum connection lifetime
}

// defaultConfig returns reasonable defaults for local development.
func defaultConfig() Config {
	return Config{
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: 30 * time.Minute,
	}
}

// ConfigFromEnv builds a Config from environment variables.
//
// Environment variables:
//   - HOP_DB_DSN                : required, PostgreSQL DSN
//   - HOP_DB_MAX_OPEN_CONNS     : optional, int, default 10
//   - HOP_DB_MAX_IDLE_CONNS     : optional, int, default 5
//   - HOP_DB_CONN_MAX_LIFETIME  : optional, duration (e.g. "30m"), default 30m
func ConfigFromEnv() (Config, error) {
	cfg := defaultConfig()

	dsn := strings.TrimSpace(os.Getenv("HOP_DB_DSN"))
	if dsn == "" {
		return Config{}, fmt.Errorf("HOP_DB_DSN is required")
	}
	cfg.DSN = dsn

	if v := strings.TrimSpace(os.Getenv("HOP_DB_MAX_OPEN_CONNS")); v != "" {
		if n, err := parseInt(v); err == nil && n > 0 {
			cfg.MaxOpenConns = n
		}
	}

	if v := strings.TrimSpace(os.Getenv("HOP_DB_MAX_IDLE_CONNS")); v != "" {
		if n, err := parseInt(v); err == nil && n >= 0 {
			cfg.MaxIdleConns = n
		}
	}

	if v := strings.TrimSpace(os.Getenv("HOP_DB_CONN_MAX_LIFETIME")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.ConnMaxLifetime = d
		}
	}

	return cfg, nil
}

func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// OpenPostgres opens an ent.Client backed by PostgreSQL, configures the pool,
// verifies the connection, and runs schema migrations (DB init).
//
// This will create tables if they do not exist, based on ent schema definitions.
func OpenPostgres(ctx context.Context, logger logging.Logger, cfg Config) (*ent.Client, error) {
	if strings.TrimSpace(cfg.DSN) == "" {
		return nil, fmt.Errorf("postgres DSN is empty")
	}

	// Open a *sql.DB using the standard library, then wrap it with ent's SQL driver.
	db, err := sql.Open("postgres", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("open postgres db: %w", err)
	}

	// If anything fails after this, close db explicitly.
	if err := configurePool(db, cfg); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configure db pool: %w", err)
	}

	if err := ping(ctx, db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	// Wrap the *sql.DB with the ent SQL driver and create the ent client.
	//
	// From this point on, ent owns the underlying *sql.DB; callers should close
	// the ent.Client when shutting down.
	entDrv := entsql.OpenDB("postgres", db)
	client := ent.NewClient(ent.Driver(entDrv))

	// Auto-migrate schema: creates tables if they do not exist.
	if err := client.Schema.Create(ctx); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ent schema create: %w", err)
	}

	logger.Info("connected to postgres and applied schema", logging.Fields{
		"dsn_masked": maskDSN(cfg.DSN),
	})

	return client, nil
}

func configurePool(db *sql.DB, cfg Config) error {
	if db == nil {
		return fmt.Errorf("db is nil")
	}
	if cfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns >= 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	}
	return nil
}

func ping(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("db is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return db.PingContext(ctx)
}

// OpenPostgresFromEnv is a convenience helper that reads configuration
// from environment variables and opens a PostgreSQL ent client.
//
// It is intended to be called from the server side at startup.
func OpenPostgresFromEnv(ctx context.Context, logger logging.Logger) (*ent.Client, error) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return OpenPostgres(ctx, logger, cfg)
}

// maskDSN hides password in DSN for safe logging.
func maskDSN(dsn string) string {
	// Very simple masking: do not log full DSN.
	if dsn == "" {
		return ""
	}
	return "***"
}
