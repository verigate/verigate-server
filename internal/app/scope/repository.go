// Package scope provides functionality for managing OAuth scopes,
// including scope registration, retrieval and validation.
package scope

import (
	"context"
)

// Repository defines the interface for scope data access operations.
// It provides methods for saving, retrieving, and querying OAuth scopes.
type Repository interface {
	// Save persists a scope to the data store
	Save(ctx context.Context, scope *Scope) error

	// FindByName retrieves a scope by its unique name
	FindByName(ctx context.Context, name string) (*Scope, error)

	// FindByNames retrieves multiple scopes by their names
	FindByNames(ctx context.Context, names []string) ([]Scope, error)

	// FindAll retrieves all available scopes
	FindAll(ctx context.Context) ([]Scope, error)

	// FindDefaults retrieves all scopes marked as default
	FindDefaults(ctx context.Context) ([]Scope, error)
}
