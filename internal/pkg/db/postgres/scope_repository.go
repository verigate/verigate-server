// Package postgres provides PostgreSQL implementations of the application's repositories.
package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"
	"github.com/verigate/verigate-server/internal/app/scope"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
)

// scopeRepository implements the scope.Repository interface using PostgreSQL.
type scopeRepository struct {
	db *sql.DB
}

// NewScopeRepository creates a new PostgreSQL-based scope repository.
// It takes a database connection and returns a scope.Repository interface.
func NewScopeRepository(db *sql.DB) scope.Repository {
	return &scopeRepository{db: db}
}

// Save creates a new OAuth scope in the PostgreSQL database.
// It inserts all scope fields and returns the generated ID.
// Returns an error if the insertion fails, such as when a duplicate scope name exists.
func (r *scopeRepository) Save(ctx context.Context, scope *scope.Scope) error {
	query := `
		INSERT INTO scopes (name, description, is_default, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`

	err := r.db.QueryRowContext(ctx, query,
		scope.Name,
		scope.Description,
		scope.IsDefault,
		scope.CreatedAt,
		scope.UpdatedAt,
	).Scan(&scope.ID)

	if err != nil {
		// Check for unique constraint violations
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return errors.Conflict(fmt.Sprintf("Scope with name '%s' already exists", scope.Name))
		}
		return errors.Internal(fmt.Sprintf("Failed to save scope: %s", err.Error()))
	}

	return nil
}

// FindByName retrieves a scope from the PostgreSQL database by its name.
// Returns the scope if found, nil if the scope doesn't exist, or an error if the query fails.
// Scope names are case-sensitive.
func (r *scopeRepository) FindByName(ctx context.Context, name string) (*scope.Scope, error) {
	var s scope.Scope
	query := `
		SELECT id, name, description, is_default, created_at, updated_at
		FROM scopes
		WHERE name = $1
	`

	err := r.db.QueryRowContext(ctx, query, name).Scan(
		&s.ID,
		&s.Name,
		&s.Description,
		&s.IsDefault,
		&s.CreatedAt,
		&s.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Internal(fmt.Sprintf(errors.ErrMsgFailedToFindScopeByName, name, err.Error()))
	}

	return &s, nil
}

// FindByNames retrieves multiple scopes from the PostgreSQL database by their names.
// Returns all found scopes, which may be fewer than the names requested if some don't exist.
// Returns an error if the query fails.
func (r *scopeRepository) FindByNames(ctx context.Context, names []string) ([]scope.Scope, error) {
	query := `
		SELECT id, name, description, is_default, created_at, updated_at
		FROM scopes
		WHERE name = ANY($1)
	`

	rows, err := r.db.QueryContext(ctx, query, pq.Array(names))
	if err != nil {
		return nil, errors.Internal(fmt.Sprintf("Failed to find scopes by names: %s", err.Error()))
	}
	defer rows.Close()

	var scopes []scope.Scope
	for rows.Next() {
		var s scope.Scope
		if err := rows.Scan(
			&s.ID,
			&s.Name,
			&s.Description,
			&s.IsDefault,
			&s.CreatedAt,
			&s.UpdatedAt,
		); err != nil {
			return nil, errors.Internal(fmt.Sprintf("Failed to scan scope data: %s", err.Error()))
		}
		scopes = append(scopes, s)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Internal(fmt.Sprintf("Error iterating scope results: %s", err.Error()))
	}

	return scopes, nil
}

// FindAll retrieves all scopes from the PostgreSQL database.
// Returns all scopes ordered by name, or an error if the query fails.
func (r *scopeRepository) FindAll(ctx context.Context) ([]scope.Scope, error) {
	query := `
		SELECT id, name, description, is_default, created_at, updated_at
		FROM scopes
		ORDER BY name
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, errors.Internal(fmt.Sprintf("Failed to find all scopes: %s", err.Error()))
	}
	defer rows.Close()

	var scopes []scope.Scope
	for rows.Next() {
		var s scope.Scope
		if err := rows.Scan(
			&s.ID,
			&s.Name,
			&s.Description,
			&s.IsDefault,
			&s.CreatedAt,
			&s.UpdatedAt,
		); err != nil {
			return nil, errors.Internal(fmt.Sprintf("Failed to scan scope data: %s", err.Error()))
		}
		scopes = append(scopes, s)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Internal(fmt.Sprintf("Error iterating scope results: %s", err.Error()))
	}

	return scopes, nil
}

// FindDefaults retrieves all default scopes from the PostgreSQL database.
// Default scopes are automatically granted to new clients or users.
// Returns all default scopes ordered by name, or an error if the query fails.
func (r *scopeRepository) FindDefaults(ctx context.Context) ([]scope.Scope, error) {
	query := `
		SELECT id, name, description, is_default, created_at, updated_at
		FROM scopes
		WHERE is_default = true
		ORDER BY name
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, errors.Internal(fmt.Sprintf("Failed to find default scopes: %s", err.Error()))
	}
	defer rows.Close()

	var scopes []scope.Scope
	for rows.Next() {
		var s scope.Scope
		if err := rows.Scan(
			&s.ID,
			&s.Name,
			&s.Description,
			&s.IsDefault,
			&s.CreatedAt,
			&s.UpdatedAt,
		); err != nil {
			return nil, errors.Internal(fmt.Sprintf("Failed to scan default scope data: %s", err.Error()))
		}
		scopes = append(scopes, s)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Internal(fmt.Sprintf("Error iterating default scope results: %s", err.Error()))
	}

	return scopes, nil
}
