package postgres

import (
	"context"
	"database/sql"

	"github.com/lib/pq"
	"github.com/verigate/verigate-server/internal/app/scope"
	"github.com/verigate/verigate-server/internal/pkg/utils/errors"
)

type scopeRepository struct {
	db *sql.DB
}

func NewScopeRepository(db *sql.DB) scope.Repository {
	return &scopeRepository{db: db}
}

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
		return errors.Internal("Failed to save scope")
	}

	return nil
}

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
		return nil, errors.Internal("Failed to find scope by name")
	}

	return &s, nil
}

func (r *scopeRepository) FindByNames(ctx context.Context, names []string) ([]scope.Scope, error) {
	query := `
		SELECT id, name, description, is_default, created_at, updated_at
		FROM scopes
		WHERE name = ANY($1)
	`

	rows, err := r.db.QueryContext(ctx, query, pq.Array(names))
	if err != nil {
		return nil, errors.Internal("Failed to find scopes by names")
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
			return nil, errors.Internal("Failed to scan scope")
		}
		scopes = append(scopes, s)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Internal("Error iterating scopes")
	}

	return scopes, nil
}

func (r *scopeRepository) FindAll(ctx context.Context) ([]scope.Scope, error) {
	query := `
		SELECT id, name, description, is_default, created_at, updated_at
		FROM scopes
		ORDER BY name
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, errors.Internal("Failed to find all scopes")
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
			return nil, errors.Internal("Failed to scan scope")
		}
		scopes = append(scopes, s)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Internal("Error iterating scopes")
	}

	return scopes, nil
}

func (r *scopeRepository) FindDefaults(ctx context.Context) ([]scope.Scope, error) {
	query := `
		SELECT id, name, description, is_default, created_at, updated_at
		FROM scopes
		WHERE is_default = true
		ORDER BY name
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, errors.Internal("Failed to find default scopes")
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
			return nil, errors.Internal("Failed to scan scope")
		}
		scopes = append(scopes, s)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.Internal("Error iterating scopes")
	}

	return scopes, nil
}
