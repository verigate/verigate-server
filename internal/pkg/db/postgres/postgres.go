// Package postgres provides PostgreSQL database connection and repository implementations
// for the Verigate Server application.
package postgres

import (
	"database/sql"
	"fmt"

	"github.com/verigate/verigate-server/internal/pkg/config"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
)

// NewConnection establishes a new PostgreSQL database connection using configuration settings.
// It connects to the database, validates the connection with a ping, and runs any pending migrations.
// Returns the database connection pool or an error if the connection or migrations fail.
func NewConnection() (*sql.DB, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		config.AppConfig.PostgresHost,
		config.AppConfig.PostgresPort,
		config.AppConfig.PostgresUser,
		config.AppConfig.PostgresPassword,
		config.AppConfig.PostgresDB,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	if err := runMigrations(db); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return db, nil
}

// runMigrations applies any pending database migrations to ensure
// the database schema is up to date with the expected structure.
// It uses the golang-migrate library to track and apply migrations.
func runMigrations(db *sql.DB) error {
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to create driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations/postgres",
		"postgres",
		driver,
	)
	if err != nil {
		return fmt.Errorf("failed to create migration instance: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}
